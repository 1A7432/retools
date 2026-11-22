"""Models of common imported functions, operating on emulated memory only.

Each stub receives a Call (arguments, memory helpers, the run's heap) and
returns the integer result. Nothing here touches the host: no files, no
network, no processes, no clock beyond a deterministic counter.

kind "c": C runtime (cdecl on x86, the caller cleans the stack)
kind "w": Windows API (stdcall on x86, the callee pops 4 * nargs bytes)
"""

from __future__ import annotations

import re

STUBS = {}
ALIASES = {}

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87


class Stub:
    __slots__ = ("name", "fn", "nargs", "kind", "variadic")

    def __init__(self, name, fn, nargs, kind, variadic=False):
        self.name, self.fn, self.nargs, self.kind, self.variadic = name, fn, nargs, kind, variadic


def stub(names, nargs, kind="c", variadic=False):
    names = names.split()

    def deco(fn):
        s = Stub(names[0], fn, nargs, kind, variadic)
        for n in names:
            STUBS[n] = s
        return fn
    return deco


def lookup(name):
    """Find a stub for an import name, tolerating decoration (_memcpy, __imp_memcpy)."""
    if not name:
        return None
    cands = [name]
    # ELF: "strlen@@GLIBC_2.2.5", sometimes behind a "module!" or PLT "." prefix.
    plain = re.sub(r"@@?[A-Za-z_][\w.]*$", "", name.rsplit("!", 1)[-1]).lstrip(".")
    if plain and plain != name:
        cands.append(plain)
    for prefix in ("__imp__", "__imp_", "_imp__"):
        if name.startswith(prefix):
            cands.append(name[len(prefix):])
    base = re.sub(r"@\d+$", "", cands[-1])        # stdcall decoration _Foo@12
    cands += [base, base.lstrip("_")]
    if base.startswith("_"):
        cands.append(base[1:])
    for c in cands:
        if c in STUBS:
            return STUBS[c]
    return None


# --------------------------------------------------------------------------
# memory and string helpers
# --------------------------------------------------------------------------

def _cmp(a, b):
    return (a > b) - (a < b)


@stub("memcpy memmove", 3)
def _memcpy(c):
    d, s, n = c.args(3)
    c.write(d, c.read(s, n))
    return d


@stub("RtlMoveMemory RtlCopyMemory CopyMemory MoveMemory", 3, "w")
def _rtlmovememory(c):
    d, s, n = c.args(3)
    c.write(d, c.read(s, n))
    return 0


@stub("memcpy_s memmove_s", 4)
def _memcpy_s(c):
    d, dsz, s, n = c.args(4)
    if n > dsz:
        return 34   # ERANGE
    c.write(d, c.read(s, n))
    return 0


@stub("__memcpy_chk __memmove_chk", 4)
def _memcpy_chk(c):
    d, s, n, _ = c.args(4)
    c.write(d, c.read(s, n))
    return d


@stub("memset", 3)
def _memset(c):
    d, v, n = c.args(3)
    c.write(d, bytes([v & 0xFF]) * n)
    return d


@stub("__memset_chk", 4)
def _memset_chk(c):
    d, v, n, _ = c.args(4)
    c.write(d, bytes([v & 0xFF]) * n)
    return d


@stub("bzero explicit_bzero", 2)
def _bzero(c):
    d, n = c.args(2)
    c.write(d, b"\0" * n)
    return 0


@stub("RtlZeroMemory ZeroMemory", 2, "w")
def _rtlzero(c):
    d, n = c.args(2)
    c.write(d, b"\0" * n)
    return 0


@stub("RtlFillMemory FillMemory", 3, "w")
def _rtlfill(c):
    d, n, v = c.args(3)
    c.write(d, bytes([v & 0xFF]) * n)
    return 0


@stub("RtlCompareMemory", 3, "w")
def _rtlcmpmem(c):
    a, b, n = c.args(3)
    x, y = c.read(a, n), c.read(b, n)
    i = 0
    while i < n and x[i] == y[i]:
        i += 1
    return i


@stub("memcmp bcmp", 3)
def _memcmp(c):
    a, b, n = c.args(3)
    x, y = c.read(a, n), c.read(b, n)
    for p, q in zip(x, y):
        if p != q:
            return c.ret_signed(p - q)
    return 0


@stub("memchr", 3)
def _memchr(c):
    p, v, n = c.args(3)
    i = c.read(p, n).find(bytes([v & 0xFF]))
    return 0 if i < 0 else p + i


@stub("strlen", 1)
def _strlen(c):
    return len(c.cstr(c.arg(0)))


@stub("lstrlenA", 1, "w")
def _lstrlena(c):
    p = c.arg(0)
    return 0 if p == 0 else len(c.cstr(p))


@stub("lstrlenW", 1, "w")
def _lstrlenw(c):
    p = c.arg(0)
    return 0 if p == 0 else len(c.wstr(p)) // 2


@stub("wcslen", 1)
def _wcslen(c):
    return len(c.wstr(c.arg(0))) // 2


@stub("strnlen", 2)
def _strnlen(c):
    p, n = c.args(2)
    return len(c.cstr(p, n))


@stub("wcsnlen", 2)
def _wcsnlen(c):
    p, n = c.args(2)
    return len(c.wstr(p, n)) // 2


def _copy_str(c, d, s, wide, limit=None):
    data = c.wstr(s) if wide else c.cstr(s)
    unit = 2 if wide else 1
    if limit is not None:
        data = data[: limit * unit]
    c.write(d, data + b"\0" * unit)
    return d


@stub("strcpy", 2)
def _strcpy(c):
    d, s = c.args(2)
    return _copy_str(c, d, s, False)


@stub("lstrcpyA", 2, "w")
def _lstrcpya(c):
    d, s = c.args(2)
    return _copy_str(c, d, s, False)


@stub("wcscpy", 2)
def _wcscpy(c):
    d, s = c.args(2)
    return _copy_str(c, d, s, True)


@stub("lstrcpyW", 2, "w")
def _lstrcpyw(c):
    d, s = c.args(2)
    return _copy_str(c, d, s, True)


@stub("strcpy_s", 3)
def _strcpy_s(c):
    d, n, s = c.args(3)
    data = c.cstr(s)
    if len(data) + 1 > n:
        return 34
    c.write(d, data + b"\0")
    return 0


@stub("wcscpy_s", 3)
def _wcscpy_s(c):
    d, n, s = c.args(3)
    data = c.wstr(s)
    if len(data) // 2 + 1 > n:
        return 34
    c.write(d, data + b"\0\0")
    return 0


@stub("strncpy", 3)
def _strncpy(c):
    d, s, n = c.args(3)
    data = c.cstr(s, n)
    c.write(d, data + b"\0" * (n - len(data)))
    return d


@stub("wcsncpy", 3)
def _wcsncpy(c):
    d, s, n = c.args(3)
    data = c.wstr(s, n)
    c.write(d, data + b"\0" * (2 * n - len(data)))
    return d


@stub("lstrcpynA", 3, "w")
def _lstrcpyna(c):
    d, s, n = c.args(3)
    if n == 0:
        return d
    return _copy_str(c, d, s, False, n - 1)


@stub("lstrcpynW", 3, "w")
def _lstrcpynw(c):
    d, s, n = c.args(3)
    if n == 0:
        return d
    return _copy_str(c, d, s, True, n - 1)


def _cat(c, d, s, wide, limit=None):
    cur = c.wstr(d) if wide else c.cstr(d)
    add = c.wstr(s) if wide else c.cstr(s)
    unit = 2 if wide else 1
    if limit is not None:
        add = add[: limit * unit]
    c.write(d + len(cur), add + b"\0" * unit)
    return d


@stub("strcat", 2)
def _strcat(c):
    d, s = c.args(2)
    return _cat(c, d, s, False)


@stub("strncat", 3)
def _strncat(c):
    d, s, n = c.args(3)
    return _cat(c, d, s, False, n)


@stub("lstrcatA", 2, "w")
def _lstrcata(c):
    d, s = c.args(2)
    return _cat(c, d, s, False)


@stub("wcscat", 2)
def _wcscat(c):
    d, s = c.args(2)
    return _cat(c, d, s, True)


@stub("lstrcatW", 2, "w")
def _lstrcatw(c):
    d, s = c.args(2)
    return _cat(c, d, s, True)


def _text(c, p, wide, n=None):
    if wide:
        return c.wstr(p, n).decode("utf-16le", errors="surrogatepass")
    return c.cstr(p, n).decode("latin-1")


def _strcmp(c, wide, fold, n=None):
    a, b = c.args(2)
    x, y = _text(c, a, wide, n), _text(c, b, wide, n)
    if fold:
        x, y = x.lower(), y.lower()
    return c.ret_signed(_cmp(x, y))


@stub("strcmp", 2)
def _strcmp_(c):
    return _strcmp(c, False, False)


@stub("lstrcmpA", 2, "w")
def _lstrcmpa(c):
    return _strcmp(c, False, False)


@stub("_stricmp stricmp strcasecmp _strcmpi strcmpi", 2)
def _stricmp(c):
    return _strcmp(c, False, True)


@stub("lstrcmpiA", 2, "w")
def _lstrcmpia(c):
    return _strcmp(c, False, True)


@stub("wcscmp", 2)
def _wcscmp(c):
    return _strcmp(c, True, False)


@stub("lstrcmpW", 2, "w")
def _lstrcmpw(c):
    return _strcmp(c, True, False)


@stub("_wcsicmp wcsicmp wcscasecmp", 2)
def _wcsicmp(c):
    return _strcmp(c, True, True)


@stub("lstrcmpiW", 2, "w")
def _lstrcmpiw(c):
    return _strcmp(c, True, True)


@stub("strncmp", 3)
def _strncmp(c):
    return _strcmp(c, False, False, c.arg(2))


@stub("_strnicmp strnicmp strncasecmp", 3)
def _strnicmp(c):
    return _strcmp(c, False, True, c.arg(2))


@stub("wcsncmp", 3)
def _wcsncmp(c):
    return _strcmp(c, True, False, c.arg(2))


@stub("_wcsnicmp", 3)
def _wcsnicmp(c):
    return _strcmp(c, True, True, c.arg(2))


def _find_char(c, wide, last):
    p, ch = c.args(2)
    data = c.wstr(p) if wide else c.cstr(p)
    unit = 2 if wide else 1
    if (ch & (0xFFFF if wide else 0xFF)) == 0:
        return p + len(data)
    needle = (ch & 0xFFFF).to_bytes(2, "little") if wide else bytes([ch & 0xFF])
    idx = -1
    for i in range(0, len(data), unit):
        if data[i:i + unit] == needle:
            idx = i
            if not last:
                break
    return 0 if idx < 0 else p + idx


@stub("strchr", 2)
def _strchr(c):
    return _find_char(c, False, False)


@stub("strrchr", 2)
def _strrchr(c):
    return _find_char(c, False, True)


@stub("wcschr", 2)
def _wcschr(c):
    return _find_char(c, True, False)


@stub("wcsrchr", 2)
def _wcsrchr(c):
    return _find_char(c, True, True)


@stub("strstr", 2)
def _strstr(c):
    a, b = c.args(2)
    i = c.cstr(a).find(c.cstr(b))
    return 0 if i < 0 else a + i


@stub("wcsstr", 2)
def _wcsstr(c):
    a, b = c.args(2)
    hay, needle = c.wstr(a), c.wstr(b)
    i = hay.find(needle)
    while i >= 0 and i % 2:
        i = hay.find(needle, i + 1)
    return 0 if i < 0 else a + i


@stub("toupper", 1)
def _toupper(c):
    v = c.arg(0)
    return v - 32 if 0x61 <= v <= 0x7A else v


@stub("tolower", 1)
def _tolower(c):
    v = c.arg(0)
    return v + 32 if 0x41 <= v <= 0x5A else v


@stub("towupper", 1)
def _towupper(c):
    v = c.arg(0) & 0xFFFF
    return ord(chr(v).upper()[0]) if len(chr(v).upper()) == 1 else v


@stub("towlower", 1)
def _towlower(c):
    v = c.arg(0) & 0xFFFF
    return ord(chr(v).lower()[0]) if len(chr(v).lower()) == 1 else v


def _parse_int(text, base):
    m = re.match(r"\s*([+-]?)(0[xX])?([0-9a-zA-Z]*)", text)
    sign, pfx, digits = m.groups()
    if base == 0:
        base = 16 if pfx else (8 if digits.startswith("0") and len(digits) > 1 else 10)
    elif base != 16 and pfx:
        digits = "0"
    val, used = 0, 0
    for ch in digits:
        d = int(ch, 36)
        if d >= base:
            break
        val = val * base + d
        used += 1
    return -val if sign == "-" else val


@stub("atoi atol", 1)
def _atoi(c):
    return c.ret_signed(_parse_int(c.cstr(c.arg(0)).decode("latin-1"), 10))


@stub("_wtoi _wtol", 1)
def _wtoi(c):
    return c.ret_signed(_parse_int(_text(c, c.arg(0), True), 10))


@stub("strtol strtoul", 3)
def _strtol(c):
    p, endp, base = c.args(3)
    text = c.cstr(p).decode("latin-1")
    v = _parse_int(text, base)
    if endp:
        c.wptr(endp, p + len(text))  # approximation: end of string
    return c.ret_signed(v)


@stub("abs labs", 1)
def _abs(c):
    v = c.signed(c.arg(0), 32)
    return abs(v)


# --------------------------------------------------------------------------
# heap
# --------------------------------------------------------------------------

@stub("malloc ??2@YAPAXI@Z ??_U@YAPAXI@Z ??2@YAPEAX_K@Z ??_U@YAPEAX_K@Z _Znwm _Znwj _Znam _Znaj",
      1)
def _malloc(c):
    return c.alloc(c.arg(0))


@stub("free ??3@YAXPAX@Z ??_V@YAXPAX@Z ??3@YAXPEAX@Z ??_V@YAXPEAX@Z ??3@YAXPAXI@Z "
      "??3@YAXPEAX_K@Z _ZdlPv _ZdaPv _ZdlPvm _ZdlPvj", 1)
def _free(c):
    c.free(c.arg(0))
    return 0


@stub("calloc", 2)
def _calloc(c):
    n, s = c.args(2)
    return c.alloc(n * s)


@stub("realloc", 2)
def _realloc(c):
    p, n = c.args(2)
    return c.realloc(p, n)


@stub("_msize malloc_usable_size malloc_size", 1)
def _msize(c):
    return c.size_of(c.arg(0))


@stub("GetProcessHeap", 0, "w")
def _getprocessheap(c):
    return c.emu.heap_handle


@stub("HeapCreate", 3, "w")
def _heapcreate(c):
    return c.emu.heap_handle


@stub("HeapDestroy", 1, "w")
def _heapdestroy(c):
    return 1


@stub("HeapAlloc RtlAllocateHeap", 3, "w")
def _heapalloc(c):
    _, _, n = c.args(3)
    return c.alloc(n)


@stub("HeapFree RtlFreeHeap", 3, "w")
def _heapfree(c):
    c.free(c.arg(2))
    return 1


@stub("HeapReAlloc RtlReAllocateHeap", 4, "w")
def _heaprealloc(c):
    _, _, p, n = c.args(4)
    return c.realloc(p, n)


@stub("HeapSize RtlSizeHeap", 3, "w")
def _heapsize(c):
    return c.size_of(c.arg(2))


@stub("VirtualAlloc", 4, "w")
def _virtualalloc(c):
    addr, n, _, _ = c.args(4)
    if addr and c.emu.is_mapped(addr, max(n, 1)):
        return addr  # committing inside an earlier reservation
    if addr:
        c.note("requested address %#x ignored; allocated from the heap arena" % addr)
    return c.alloc(n, align=0x1000)


@stub("VirtualAllocEx", 5, "w")
def _virtualallocex(c):
    _, addr, n, _, _ = c.args(5)
    return c.alloc(n, align=0x1000)


@stub("VirtualFree", 3, "w")
def _virtualfree(c):
    c.free(c.arg(0))
    return 1


@stub("VirtualProtect", 4, "w")
def _virtualprotect(c):
    _, _, _, old = c.args(4)
    if old:
        c.w32(old, 0x40)  # PAGE_EXECUTE_READWRITE
    return 1


@stub("LocalAlloc GlobalAlloc", 2, "w")
def _localalloc(c):
    _, n = c.args(2)
    return c.alloc(n)


@stub("LocalReAlloc GlobalReAlloc", 3, "w")
def _localrealloc(c):
    p, n, _ = c.args(3)
    return c.realloc(p, n)


@stub("LocalFree GlobalFree", 1, "w")
def _localfree(c):
    c.free(c.arg(0))
    return 0


@stub("LocalLock GlobalLock", 1, "w")
def _locallock(c):
    return c.arg(0)


@stub("LocalUnlock GlobalUnlock", 1, "w")
def _localunlock(c):
    return 1


@stub("LocalSize GlobalSize", 1, "w")
def _localsize(c):
    return c.size_of(c.arg(0))


@stub("CoTaskMemAlloc", 1, "w")
def _cotaskmemalloc(c):
    return c.alloc(c.arg(0))


@stub("CoTaskMemFree", 1, "w")
def _cotaskmemfree(c):
    c.free(c.arg(0))
    return 0


def _bstr(c, nbytes, src=None):
    blk = c.alloc(4 + nbytes + 2)
    if not blk:
        return 0
    c.w32(blk, nbytes)
    if src:
        c.write(blk + 4, c.read(src, nbytes))
    return blk + 4


@stub("SysAllocString", 1, "w")
def _sysallocstring(c):
    p = c.arg(0)
    if not p:
        return 0
    return _bstr(c, len(c.wstr(p)), p)


@stub("SysAllocStringLen", 2, "w")
def _sysallocstringlen(c):
    p, n = c.args(2)
    return _bstr(c, 2 * n, p)


@stub("SysAllocStringByteLen", 2, "w")
def _sysallocstringbytelen(c):
    p, n = c.args(2)
    return _bstr(c, n, p)


@stub("SysReAllocStringLen", 3, "w")
def _sysreallocstringlen(c):
    pp, p, n = c.args(3)
    new = _bstr(c, 2 * n, p)
    if not new:
        return 0
    old = c.rptr(pp)
    if old:
        c.free(old - 4)
    c.wptr(pp, new)
    return 1


@stub("SysFreeString", 1, "w")
def _sysfreestring(c):
    p = c.arg(0)
    if p:
        c.free(p - 4)
    return 0


@stub("SysStringLen", 1, "w")
def _sysstringlen(c):
    p = c.arg(0)
    return c.r32(p - 4) // 2 if p else 0


@stub("SysStringByteLen", 1, "w")
def _sysstringbytelen(c):
    p = c.arg(0)
    return c.r32(p - 4) if p else 0


# --------------------------------------------------------------------------
# code pages
# --------------------------------------------------------------------------

def _codec(c, cp):
    if cp in (0, 1, 2, 3):          # CP_ACP, CP_OEMCP, CP_MACCP, CP_THREAD_ACP
        cp = c.emu.acp
    if cp == 65001:
        return "utf-8"
    if cp == 65000:
        return "utf-7"
    if cp == 1200:
        return "utf-16le"
    try:
        "".encode("cp%d" % cp)
        return "cp%d" % cp
    except LookupError:
        c.note("code page %d unknown, using latin-1" % cp)
        return "latin-1"


@stub("MultiByteToWideChar", 6, "w")
def _mb2wc(c):
    cp, _, src, n, dst, cap = c.args(6)
    n = c.signed(n, 32)
    data = c.cstr(src) + b"\0" if n == -1 else c.read(src, n)
    out = data.decode(_codec(c, cp), errors="replace").encode("utf-16le")
    count = len(out) // 2
    if cap == 0:
        return count
    if cap < count:
        c.set_last_error(ERROR_INSUFFICIENT_BUFFER)
        return 0
    c.write(dst, out)
    return count


@stub("WideCharToMultiByte", 8, "w")
def _wc2mb(c):
    cp, _, src, n, dst, cap, _, used = c.args(8)
    n = c.signed(n, 32)
    data = c.wstr(src) + b"\0\0" if n == -1 else c.read(src, 2 * n)
    text = data.decode("utf-16le", errors="replace")
    out = text.encode(_codec(c, cp), errors="replace")
    if used:
        c.w32(used, 0)
    if cap == 0:
        return len(out)
    if cap < len(out):
        c.set_last_error(ERROR_INSUFFICIENT_BUFFER)
        return 0
    c.write(dst, out)
    return len(out)


@stub("GetACP", 0, "w")
def _getacp(c):
    return c.emu.acp


@stub("GetOEMCP", 0, "w")
def _getoemcp(c):
    return 437 if c.emu.acp == 1252 else c.emu.acp


def _case_buff(c, wide, upper):
    p, n = c.args(2)
    unit = 2 if wide else 1
    data = c.read(p, n * unit)
    text = data.decode("utf-16le", errors="surrogatepass") if wide else data.decode("latin-1")
    new = "".join((ch.upper() if upper else ch.lower()) if len(ch.upper() if upper else ch.lower()) == 1
                  else ch for ch in text)
    c.write(p, new.encode("utf-16le", errors="surrogatepass") if wide else new.encode("latin-1"))
    return n


@stub("CharUpperBuffW", 2, "w")
def _charupperbuffw(c):
    return _case_buff(c, True, True)


@stub("CharLowerBuffW", 2, "w")
def _charlowerbuffw(c):
    return _case_buff(c, True, False)


@stub("CharUpperBuffA", 2, "w")
def _charupperbuffa(c):
    return _case_buff(c, False, True)


@stub("CharLowerBuffA", 2, "w")
def _charlowerbuffa(c):
    return _case_buff(c, False, False)


def _compare_string(c, wide):
    _, flags, a, na, b, nb = c.args(6)
    na, nb = c.signed(na, 32), c.signed(nb, 32)
    unit = 2 if wide else 1

    def get(p, n):
        data = (c.wstr(p) if wide else c.cstr(p)) if n < 0 else c.read(p, n * unit)
        return data.decode("utf-16le", errors="replace") if wide else data.decode("latin-1")
    x, y = get(a, na), get(b, nb)
    if flags & 1:                      # NORM_IGNORECASE
        x, y = x.lower(), y.lower()
    return 2 + _cmp(x, y)              # CSTR_LESS_THAN 1, CSTR_EQUAL 2, CSTR_GREATER_THAN 3


@stub("CompareStringW", 6, "w")
def _comparestringw(c):
    return _compare_string(c, True)


@stub("CompareStringA", 6, "w")
def _comparestringa(c):
    return _compare_string(c, False)


@stub("CharUpperW", 1, "w")
def _charupperw(c):
    p = c.arg(0)
    if p < 0x10000:
        return ord(chr(p).upper()[0])
    s = _text(c, p, True).upper()
    c.write(p, s.encode("utf-16le"))
    return p


@stub("CharLowerW", 1, "w")
def _charlowerw(c):
    p = c.arg(0)
    if p < 0x10000:
        return ord(chr(p).lower()[0])
    s = _text(c, p, True).lower()
    c.write(p, s.encode("utf-16le"))
    return p


# --------------------------------------------------------------------------
# process state (modelled, never the host's)
# --------------------------------------------------------------------------

@stub("GetLastError RtlGetLastWin32Error", 0, "w")
def _getlasterror(c):
    return c.get_last_error()


@stub("SetLastError RtlSetLastWin32Error", 1, "w")
def _setlasterror(c):
    c.set_last_error(c.arg(0))
    return 0


@stub("GetTickCount", 0, "w")
def _gettickcount(c):
    return c.emu.tick()


@stub("GetTickCount64", 0, "w")
def _gettickcount64(c):
    return c.emu.tick()


@stub("QueryPerformanceCounter", 1, "w")
def _qpc(c):
    c.w64(c.arg(0), c.emu.tick() * 10000)
    return 1


@stub("QueryPerformanceFrequency", 1, "w")
def _qpf(c):
    c.w64(c.arg(0), 10000000)
    return 1


@stub("GetSystemTimeAsFileTime", 1, "w")
def _getsystemtimeasfiletime(c):
    # 2024-01-01 00:00:00 UTC plus the emulated tick count
    c.w64(c.arg(0), 133485408000000000 + c.emu.tick() * 10000)
    return 0


@stub("Sleep", 1, "w")
def _sleep(c):
    c.emu.ticks += c.arg(0)
    return 0


@stub("GetCurrentProcessId", 0, "w")
def _getpid(c):
    return 0x1000


@stub("GetCurrentThreadId", 0, "w")
def _gettid(c):
    return 0x1004


@stub("GetCurrentProcess", 0, "w")
def _getcurrentprocess(c):
    return c.mask


@stub("GetCurrentThread", 0, "w")
def _getcurrentthread(c):
    return c.mask - 1


@stub("IsDebuggerPresent", 0, "w")
def _isdebuggerpresent(c):
    return 0


@stub("TlsAlloc", 0, "w")
def _tlsalloc(c):
    return c.emu.tls_alloc()


@stub("TlsFree", 1, "w")
def _tlsfree(c):
    return 1


@stub("TlsGetValue", 1, "w")
def _tlsgetvalue(c):
    c.set_last_error(0)
    return c.emu.tls_get(c.arg(0))


@stub("TlsSetValue", 2, "w")
def _tlssetvalue(c):
    i, v = c.args(2)
    return c.emu.tls_set(i, v)


def _interlocked(c, op):
    p = c.arg(0)
    old = c.r32(p)
    if op == "inc":
        new = (old + 1) & 0xFFFFFFFF
        c.w32(p, new)
        return new
    if op == "dec":
        new = (old - 1) & 0xFFFFFFFF
        c.w32(p, new)
        return new
    if op == "xchg":
        c.w32(p, c.arg(1))
        return old
    if op == "add":
        c.w32(p, (old + c.arg(1)) & 0xFFFFFFFF)
        return old
    if op == "cmpxchg":
        if old == c.arg(2) & 0xFFFFFFFF:
            c.w32(p, c.arg(1))
        return old


@stub("InterlockedIncrement", 1, "w")
def _iinc(c):
    return _interlocked(c, "inc")


@stub("InterlockedDecrement", 1, "w")
def _idec(c):
    return _interlocked(c, "dec")


@stub("InterlockedExchange", 2, "w")
def _ixchg(c):
    return _interlocked(c, "xchg")


@stub("InterlockedExchangeAdd", 2, "w")
def _iadd(c):
    return _interlocked(c, "add")


@stub("InterlockedCompareExchange", 3, "w")
def _icmpxchg(c):
    return _interlocked(c, "cmpxchg")


@stub("InitializeCriticalSection EnterCriticalSection LeaveCriticalSection "
      "DeleteCriticalSection", 1, "w")
def _critsec(c):
    return 0


@stub("InitializeCriticalSectionAndSpinCount", 2, "w")
def _critsec2(c):
    return 1


@stub("TryEnterCriticalSection", 1, "w")
def _trycritsec(c):
    return 1


@stub("GetModuleHandleA GetModuleHandleW", 1, "w")
def _getmodulehandle(c):
    p = c.arg(0)
    if p == 0:
        return c.emu.image.base
    name = _text(c, p, c.name.endswith("W"))
    return c.emu.module_handle(name)


@stub("LoadLibraryA LoadLibraryW", 1, "w")
def _loadlibrary(c):
    name = _text(c, c.arg(0), c.name.endswith("W"))
    return c.emu.module_handle(name)


@stub("LoadLibraryExA LoadLibraryExW", 3, "w")
def _loadlibraryex(c):
    name = _text(c, c.arg(0), c.name.endswith("W"))
    return c.emu.module_handle(name)


@stub("FreeLibrary", 1, "w")
def _freelibrary(c):
    return 1


@stub("GetProcAddress", 2, "w")
def _getprocaddress(c):
    h, p = c.args(2)
    name = "ord_%d" % p if p < 0x10000 else _text(c, p, False)
    return c.emu.dynamic_import(name, c.emu.module_name(h))


@stub("RaiseException", 4, "w")
def _raiseexception(c):
    c.stop("exception", "RaiseException(code=%#x); SEH dispatch is not emulated" % c.arg(0))
    return 0


@stub("RtlRaiseException", 1, "w")
def _rtlraise(c):
    c.stop("exception", "RtlRaiseException; SEH dispatch is not emulated")
    return 0


@stub("_CxxThrowException", 2, "w")
def _cxxthrow(c):
    c.stop("exception", "C++ throw; exception dispatch is not emulated")
    return 0


@stub("ExitProcess ExitThread FreeLibraryAndExitThread", 1, "w")
def _exitprocess(c):
    c.stop("exit", "%s(%#x)" % (c.name, c.arg(0)))
    return 0


@stub("TerminateProcess TerminateThread", 2, "w")
def _terminate(c):
    c.stop("exit", "%s(%#x, %#x)" % (c.name, c.arg(0), c.arg(1)))
    return 0


@stub("exit _exit abort __stack_chk_fail __chk_fail _invalid_parameter_noinfo", 1)
def _exit(c):
    c.stop("exit", "%s called" % c.name)
    return 0


# --------------------------------------------------------------------------
# rand / printf family
# --------------------------------------------------------------------------

@stub("srand", 1)
def _srand(c):
    c.emu.rand_state = c.arg(0) & 0xFFFFFFFF
    return 0


@stub("rand", 0)
def _rand(c):
    # The MSVC CRT generator; glibc differs, which matters only if the
    # sample depends on the exact sequence.
    c.emu.rand_state = (c.emu.rand_state * 214013 + 2531011) & 0xFFFFFFFF
    return (c.emu.rand_state >> 16) & 0x7FFF


_FMT = re.compile(rb"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|I64|I32|I|z|j|t|L|w)?([diouxXcsSpn%eEfgGaA])")


def format_printf(c, fmt, first, wide):
    """Render a printf format; arguments are taken from c.arg(first), c.arg(first+1), ..."""
    idx = [first]

    def nxt():
        v = c.arg(idx[0])
        idx[0] += 1
        return v

    out = []
    pos = 0
    text = fmt
    for m in _FMT.finditer(text):
        out.append(text[pos:m.start()].decode("latin-1"))
        pos = m.end()
        flags, width, prec, length, conv = (g.decode() if g else g for g in m.groups())
        if conv == "%":
            out.append("%")
            continue
        if width == "*":
            width = str(c.signed(nxt(), 32))
        if prec == "*":
            prec = str(c.signed(nxt(), 32))
        # long is 32-bit on Windows (LLP64) and 64-bit on 64-bit Unix (LP64)
        big = (length in ("ll", "I64", "j")
               or (c.word == 8 and length in ("z", "t", "I"))
               or (c.word == 8 and length == "l" and c.emu.image.filetype != "pe"))
        if conv in "diouxXc":
            v = nxt()
            if big and c.word == 4:
                v |= nxt() << 32
            bits = 64 if big else 32
            v &= (1 << bits) - 1
            if conv in "di":
                v = c.signed(v, bits)
            spec = "%" + (flags or "") + (width or "") + ("." + prec if prec else "")
            if conv == "c":
                s = chr(v & 0xFFFF)
                out.append(("%" + (flags or "").replace("0", "") + (width or "") + "s") % s)
            else:
                out.append((spec + {"u": "d", "i": "d"}.get(conv, conv)) % v)
        elif conv == "p":
            out.append("%0*X" % (2 * c.word, nxt()))
        elif conv in "sS":
            p = nxt()
            is_wide = (conv == "s") == wide
            if length in ("l", "w"):
                is_wide = True
            elif length == "h":
                is_wide = False
            n = int(prec) if prec else None
            s = "(null)" if p == 0 else _text(c, p, is_wide, n)
            out.append(("%" + (flags or "") + (width or "") + "s") % s)
        elif conv in "eEfgGaA":
            import struct
            if c.word == 4:
                lo, hi = nxt(), nxt()
                val = struct.unpack("<d", struct.pack("<II", lo, hi))[0]
            else:
                val = struct.unpack("<d", struct.pack("<Q", nxt()))[0]
                if c.emu.arch.name != "x64" or c.emu.image.filetype != "pe":
                    c.note("floating-point printf arguments are only modelled for x86 and Win64")
            out.append(("%" + (flags or "") + (width or "") + ("." + prec if prec else "") + conv) % val)
        elif conv == "n":
            nxt()
    out.append(text[pos:].decode("latin-1"))
    return "".join(out)


def _sprintf(c, wide, dst_i, fmt_i, cap_i=None):
    fmt_p = c.arg(fmt_i)
    fmt = (c.wstr(fmt_p).decode("utf-16le", errors="replace").encode("latin-1", errors="replace")
           if wide else c.cstr(fmt_p))
    s = format_printf(c, fmt, fmt_i + 1, wide)
    data = s.encode("utf-16le") if wide else s.encode("latin-1", errors="replace")
    unit = 2 if wide else 1
    n = len(data) // unit
    if cap_i is not None:
        cap = c.arg(cap_i)
        if cap == 0:
            return n
        if n >= cap:
            data = data[: (cap - 1) * unit]
    c.write(c.arg(dst_i), data + b"\0" * unit)
    return n


@stub("sprintf", 2, variadic=True)
def _sprintf_a(c):
    return _sprintf(c, False, 0, 1)


@stub("wsprintfA", 2, variadic=True)
def _wsprintfa(c):
    return _sprintf(c, False, 0, 1)


@stub("wsprintfW", 2, variadic=True)
def _wsprintfw(c):
    return _sprintf(c, True, 0, 1)


@stub("snprintf _snprintf", 3, variadic=True)
def _snprintf(c):
    return _sprintf(c, False, 0, 2, 1)


@stub("_snwprintf swprintf", 3, variadic=True)
def _snwprintf(c):
    return _sprintf(c, True, 0, 2, 1)


@stub("__errno_location __error _errno", 0)
def _errno(c):
    return c.emu.errno_cell
