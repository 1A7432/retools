"""rekit - compact, read-only views of an IDA database for LLM agents.

Load inside ida-mcp `execute_python` (once per session, globals persist):

    import sys; sys.path.insert(0, "<checkout>/tools/rekit")
    import rekit; rekit.help()

Design rules
  * read-only: nothing here renames, comments, patches or retypes anything
  * every call returns a JSON-compatible dict, hex addresses as strings
  * every call has a hard output budget (`max_chars`); cuts are always
    reported with totals and a way to fetch the rest, never silent
  * failures come back as {"error", "hint"} instead of a traceback
  * only the stdlib and IDAPython; no ida_domain, no third-party packages
"""

from __future__ import annotations

import json
import random
import re
import subprocess
import time

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_nalt
import ida_name
import ida_search
import ida_segment
import ida_strlist
import ida_typeinf
import ida_ua
import ida_xref

__version__ = "0.2.0"

BUDGET = 6000            # default max chars of one result
BIG_FUNC = 0x10000       # bytes; above this decompiling needs force=True
BADADDR = idaapi.BADADDR

_CALL = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMP = (ida_xref.fl_JN, ida_xref.fl_JF)
_KIND = {
    ida_xref.fl_CN: "call", ida_xref.fl_CF: "call",
    ida_xref.fl_JN: "jump", ida_xref.fl_JF: "jump",
    ida_xref.dr_O: "offset", ida_xref.dr_R: "read", ida_xref.dr_W: "write",
}

HELP = """rekit %s - compact read-only IDA views. Every call returns a dict.
An address argument may be an int, "0x1234", a symbol name, or a ref string.

  rekit.info()                      database overview: arch, counts, segments
  rekit.fn(ea)                      function card: callers, callees, imports,
                                    strings, globals, constants + trimmed code
      code="trim"|"raw"|"none"      default "trim"
  rekit.code(ea, mode="trim")       pseudocode only; paginate with start=<line>
  rekit.xrefs(ea)                   who references ea, grouped by function
  rekit.calls(ea, depth=2, dir="out"|"in")   call tree as indented text; "in"
                                    also lists functions that only take the
                                    address [addr] and pointers in data [data]
  rekit.find(name=..|string=..|bytes=..|imm=..)   one criterion, regex=True ok
  rekit.disasm(ea, n=40)            compact disassembly, continue with "next"
  rekit.scan(ea)                    inside one function, or [ea, end) with end=:
                                    direct calls counted by target. For code
                                    too big or too obfuscated to decompile
      show="imms", min=0x10000      the distinct immediates used there
      imm=0x9E3779B9                where one immediate is used there
      to="_syscall", reg="w0"       every call site of one target, with the
                                    immediate put in a register before the call
  rekit.decode(ea)                  strings this function builds at run time in
                                    flag-guarded one-time initialisers (split
                                    constants, XOR loops), found by emulation;
                                    cards show them as "decoded"
  rekit.batch([ea, ...], code="none")         several cards in one call
  rekit.notes(ea)                   findings recorded earlier for this function
  rekit.emu(ea, args=[...], cc=..)  run one function in an emulator and see
                                    what it returns and writes; rekit.help("emu")
  rekit.run(args=[..], stdin=..)    emulate the whole program on an input and
                                    see exactly what it prints (ELF; sandboxed,
                                    nothing runs natively)
  rekit.crypto(ea=None, init=[..])  known crypto tables, constants and curve
                                    parameters here, and each place one differs
                                    from the standard; init runs set-up
                                    functions first to catch decoded tables
  rekit.calc("code")                scratchpad: recompute a formula, decrypt,
                                    try a hash with one constant changed;
                                    rekit.help("calc") lists its functions

Conventions
  ref        "sub_3A44880" (address is in the name) or "name@0x3a44880"
  budget     max_chars=%d per call; raise it only when you need more
  truncated  any cut says how much was shown, the total, and how to continue
  errors     {"error": ..., "hint": ...}; no exception reaches you
  trim       folds the local-variable block and drops pointer casts that
             cannot change meaning; mode="raw" is the untouched Hex-Rays text
  read-only  to rename / comment / retype, use plain IDAPython yourself
  decoded    a card's "decoded" strings are built at run time: the function's
             one-time initialisers were emulated to get them. A quoted text
             beside a constant is that constant's bytes, a fragment only
  slow once  the first find(string=...) builds the string index (about 10 s
             on a very large database); later searches are instant
""" % (__version__, BUDGET)


EMU_HELP = """rekit.emu(ea, **request) interprets one function in a separate emulator
(Unicorn) on a snapshot of this database. Nothing runs natively and the
database is not changed. Use it to see what a decode/hash/format routine
produces for a given input instead of working it out by hand.

  rekit.emu(0x401000, args=[5, {"str": "abc"}, {"out": 64}])
  rekit.emu("sub_495BD0", cc="delphi", args=[{"struct": [{"u32": 0}, {"ptr": {"ref": "arr+4"}}]}],
            mem=[{"name": "arr", "struct": [{"u32": 2}, {"u32": 5}, {"u32": 0}, {"u32": 0}]}])

request keys
  args      values in calling-convention order. A value is an int, or a buffer
            passed by pointer: {"str": s} {"wstr": s} {"bytes": "de ad"} {"out": N}
            {"dstr": s} (Delphi UnicodeString) {"struct": [{"u32": 1}, {"ptr": v}, ...]}
            {"ref": "name+4"} points into a named buffer. Add "reg": "esi" or
            "stack": 8 to place one argument explicitly.
  cc        cdecl (x86 default) stdcall fastcall thiscall delphi ms64 sysv
            aapcs64 usercall. Delphi/Borland code (IDA shows a1@<eax>, a2@<edx>,
            a3@<ecx>) needs cc="delphi".
  mem       extra named buffers: [{"name": "tbl", "bytes": "..."}]
  regs      register presets {"esi": 1}; regs_out=["edx"] reports registers
  ret       how to show the return value: int cstr wstr dstr bytes:N
  read      memory to show afterwards: [{"addr": {"ref": "a2"}, "as": "wstr"}]
  imports   override an import: {"GetTickCount": {"ret": 1000}}
  replace   replace a function in the image, by address or name:
            {"0x407164": {"stub": "malloc", "cc": "delphi"}}
  start, until   run a fragment instead of a whole function (omit ea)
  init      set-up calls run first in the same memory, for tables or keys the
            program builds at run time: init=["sub_402000", {"func": "sub_402100",
            "args": [3, {"out": 8, "name": "key"}]}], then args=[{"ref": "key"}].
            Entries take func args cc regs mem replace imports max_insns; reply
            init = one {func, stop, ret, insns} each; stop init_failed if one fails.
  max_insns (2000000)  timeout (20)  trace=True  map_on_demand=True
  requests=[{...}, ...]   several runs in one call, each from a clean state

reply   stop.reason is "returned" when the function finished; anything else
        (unmapped_read, max_insns, exception, ...) says where and why it
        stopped. ret = return value. buffers = arguments the function changed
        (hex + text). writes = other memory it wrote, with strings found.
        imports = API calls made, with arguments. warnings = guesses made.

Common memory, string and heap APIs are modelled; other imports are logged
and return 0. There is no file system, network, thread or exception dispatch.
Code that allocates through a runtime the snapshot never initialised (Delphi
GetMem, some CRT heaps) stops with unmapped_read inside the allocator, and a
statically linked libc stops with reason syscall there: replace that allocator
with {"stub": "malloc"} and run again. Pass refresh=True after the database
bytes were patched.
"""


class RekitError(Exception):
    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.msg, self.hint = msg, hint


# --------------------------------------------------------------------------
# result plumbing
# --------------------------------------------------------------------------

def _size(obj):
    return len(json.dumps(obj, ensure_ascii=False))


def _fit(res, budget):
    """Last-resort guard: halve the biggest leaf until the result fits."""
    limit = int(budget * 1.25) + 200
    if _size(res) <= limit:
        return res
    cut = []
    for _ in range(40):
        if _size(res) <= limit:
            break
        best = None
        stack = [(res, k) for k in list(res)]
        while stack:
            box, key = stack.pop()
            val = box[key]
            if isinstance(val, dict):
                stack.extend((val, k) for k in list(val))
            elif isinstance(val, (str, list)) and len(val) > 4:
                weight = len(val) if isinstance(val, str) else _size(val)
                if best is None or weight > best[0]:
                    best = (weight, box, key)
        if best is None:
            break
        _, box, key = best
        val = box[key]
        box[key] = val[: len(val) // 2]
        if key not in cut:
            cut.append(str(key))
    res["truncated"] = ("hard budget hit, fields cut: %s. Narrow the query or "
                        "raise max_chars." % ", ".join(cut))
    return res


def _api(func):
    def wrapper(*args, **kwargs):
        try:
            res = func(*args, **kwargs)
        except RekitError as exc:
            out = {"error": exc.msg}
            if exc.hint:
                out["hint"] = exc.hint
            return out
        except Exception as exc:  # noqa: BLE001 - the contract is "no traceback"
            return {"error": "%s: %s" % (type(exc).__name__, exc),
                    "hint": "unexpected IDA state or a rekit bug; fall back to "
                            "plain IDAPython for this query"}
        budget = kwargs.get("max_chars") or BUDGET
        return _fit(res, budget) if isinstance(res, dict) else res
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


def _clip(text, n):
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= n else "%s...(%d chars)" % (text[:n], len(text))


# --------------------------------------------------------------------------
# addresses, names, refs
# --------------------------------------------------------------------------

def _ea(x):
    if isinstance(x, bool) or x is None:
        raise RekitError("bad address %r" % (x,), 'pass an int, "0x..." or a name')
    if isinstance(x, int):
        ea = x
    elif isinstance(x, str):
        s = x.strip()
        head, sep, tail = s.rpartition("@")
        if sep and tail.lower().startswith("0x"):
            s = tail
        if s.lower().startswith("0x"):
            try:
                ea = int(s, 16)
            except ValueError:
                raise RekitError("bad address %r" % x)
        else:
            ea = ida_name.get_name_ea(BADADDR, s)
            if ea == BADADDR:
                if re.fullmatch(r"[0-9A-Fa-f]{4,16}", s):
                    ea = int(s, 16)
                else:
                    raise RekitError("no symbol named %r" % x,
                                     "search with rekit.find(name=...)")
    else:
        raise RekitError("bad address %r" % (x,))
    if not ida_bytes.is_mapped(ea):
        raise RekitError("%#x is not mapped" % ea,
                         "image range is %#x-%#x" % (ida_ida.inf_get_min_ea(),
                                                     ida_ida.inf_get_max_ea()))
    return ea


def _seg(ea):
    seg = ida_segment.getseg(ea)
    return ida_segment.get_segm_name(seg) if seg else "?"


def _is_extern(ea):
    seg = ida_segment.getseg(ea)
    return bool(seg) and seg.type == ida_segment.SEG_XTRN


def _short(name, n=72):
    if not name:
        return name
    dem = ida_name.demangle_name(name, ida_ida.inf_get_short_demnames())
    out = dem or name
    return out if len(out) <= n else out[: n - 3] + "..."


def _ref(ea):
    """Stable label for an address: function-relative when inside a function."""
    f = ida_funcs.get_func(ea)
    base = f.start_ea if f else ea
    name = (ida_funcs.get_func_name(base) if f else ida_name.get_name(base)) or ""
    if not name:
        label = "%#x" % base
    elif ida_bytes.has_dummy_name(ida_bytes.get_flags(base)):
        label = name
    else:
        label = "%s@%#x" % (_short(name), base)
    return label if ea == base else "%s+%#x" % (label, ea - base)


def _func(x):
    ea = _ea(x)
    f = ida_funcs.get_func(ea)
    if f is None:
        flags = ida_bytes.get_flags(ea)
        what = "code outside any function" if ida_bytes.is_code(flags) else "data"
        raise RekitError("%#x is %s in segment %s, not a function" % (ea, what, _seg(ea)),
                         "use rekit.xrefs(%#x) to see who references it" % ea)
    return f


def _fsize(f):
    return ida_funcs.calc_func_size(f)


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------

def _strlit(ea):
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.is_strlit(flags):
        return None
    raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.get_str_type(ea))
    if raw is None:
        return None
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def _ptr(ea):
    return ida_bytes.get_qword(ea) if ida_ida.inf_is_64bit() else ida_bytes.get_dword(ea)


def _printable(text, least):
    return len(text) >= least and all(c.isprintable() or c in "\r\n\t" for c in text)


def _undefined_str(ea):
    """A string IDA has not typed as one.

    Delphi literals carry a header (element size, refcount -1, length) right
    before the characters, and IDA often types the first characters as an
    offset instead of text. Otherwise accept only a clean UTF-16 run.
    """
    if _is_pe() and ida_bytes.is_mapped(ea - 12) \
            and ida_bytes.get_dword(ea - 8) == 0xFFFFFFFF:
        count, width = ida_bytes.get_dword(ea - 4), ida_bytes.get_word(ea - 10)
        if 0 < count <= 4096 and width in (1, 2):
            raw = ida_bytes.get_bytes(ea, count * width)
            if raw:
                text = raw.decode("utf-16-le" if width == 2 else "latin-1", "replace")
                if _printable(text, 1):
                    return text
    raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C_16)
    if raw:
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        if _printable(text, 6):
            return text
    return None


def _str_at(ea):
    """String at ea, following one pointer (CFString, pointer tables)."""
    s = _strlit(ea)
    if s is not None:
        return s
    if ida_bytes.is_data(ida_bytes.get_flags(ea)) or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
        s = _undefined_str(ea)
        if s is not None:
            return s
    psz = 8 if ida_ida.inf_is_64bit() else 4
    if "cfstring" in _seg(ea).lower():
        return _strlit(_ptr(ea + 2 * psz))
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_data(flags) and ida_bytes.get_item_size(ea) == psz:
        target = _ptr(ea)
        if ida_bytes.is_mapped(target):
            return _strlit(target)
    return None


_STRINGS = {}


def _is_pe():
    return ida_ida.inf_get_filetype() == ida_ida.f_PE


def _strings(ascii_only=True, wide=None):
    """(ea, text) for the database's strings, built once per variant.

    IDA's string list defaults to 7-bit C strings only, which hides the wide
    strings Windows and Delphi code is full of, so UTF-16 is indexed too for
    PE files. Elsewhere it is opt-in: on a 1.9 GB Mach-O database adding
    UTF-16 took the build from 11 s to 86 s for almost no extra strings. The
    list options belong to the user's database and are put back afterwards.
    """
    if wide is None:
        wide = _is_pe()
    key = (ascii_only, bool(wide))
    if key not in _STRINGS:
        opts = ida_strlist.get_strlist_options()
        saved = (list(opts.strtypes), opts.minlen, opts.only_7bit,
                 opts.display_only_existing_strings, opts.ignore_heads)
        types = [ida_nalt.STRTYPE_C] + ([ida_nalt.STRTYPE_C_16] if wide else [])
        try:
            lister = idautils.Strings(default_setup=False)
            # Looking inside defined items is what finds Delphi literals that
            # IDA typed as offsets; it is also the expensive part, so it goes
            # with the wide index only.
            lister.setup(strtypes=types, minlen=max(4, saved[1]), only_7bit=ascii_only,
                         ignore_instructions=bool(wide or saved[4]),
                         display_only_existing_strings=False)
            _STRINGS[key] = [(s.ea, str(s)) for s in lister]
        finally:
            opts = ida_strlist.get_strlist_options()
            (opts.strtypes, opts.minlen, opts.only_7bit,
             opts.display_only_existing_strings, opts.ignore_heads) = saved
    return _STRINGS[key]


# --------------------------------------------------------------------------
# function scanning
# --------------------------------------------------------------------------

def _scan(f, max_insn=60000):
    """Outgoing references of a function: calls, imports, strings, globals."""
    start = f.start_ea
    calls, imps, strs, globs = {}, {}, {}, {}
    reads, writes, str_sites = {}, {}, {}
    seen, capped = 0, False
    for cs, ce in idautils.Chunks(start):
        for head in idautils.Heads(cs, ce):
            seen += 1
            if seen > max_insn:
                capped = True
                break
            ext = set()
            for x in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                to = x.to
                if _is_extern(to):
                    ext.add(to)
                    continue
                if x.iscode:
                    if x.type not in _CALL and x.type not in _JUMP:
                        continue
                    tf = ida_funcs.get_func(to)
                    if tf is None or tf.start_ea != to:
                        continue
                    if to == start and x.type in _JUMP:
                        continue
                    if tf.flags & ida_funcs.FUNC_THUNK:
                        name = ida_funcs.get_func_name(to) or "%#x" % to
                        imps[name] = imps.get(name, 0) + 1
                    else:
                        calls[to] = calls.get(to, 0) + 1
                else:
                    if x.type == ida_xref.dr_R:
                        reads.setdefault(to, head)
                    elif x.type == ida_xref.dr_W:
                        writes.setdefault(to, []).append(head)
                    text = _str_at(to)
                    if text is not None:
                        strs.setdefault(text, to)
                        str_sites.setdefault(text, []).append(head)
                    elif not f.contains(to) and ida_bytes.is_mapped(to):
                        # own labels are not globals; unmapped targets are
                        # struct-member and enum references, not addresses
                        globs[to] = globs.get(to, 0) + 1
            for to in ext:
                name = ida_name.get_name(to) or "%#x" % to
                imps[name] = imps.get(name, 0) + 1
        if capped:
            break
    return {"calls": calls, "imps": _quiet(imps, lambda n: n), "strs": strs,
            "globs": _quiet(globs, ida_name.get_name),
            "reads": reads, "writes": writes, "str_sites": str_sites,
            "insns": seen, "capped": capped}


_NOISE = re.compile(r"stack_chk_(guard|fail)|^_*security_(cookie|check_cookie)")


def _quiet(counter, name_of):
    """Drop stack-protector plumbing; it is in nearly every function."""
    return {k: v for k, v in counter.items() if not _NOISE.search(name_of(k) or "")}


def _ranked(counter, label, top):
    items = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    out = ["%s x%d" % (label(k), n) if n > 1 else label(k) for k, n in items[:top]]
    return out, len(items)


def _callers(ea, top, cap=20000):
    by, data, sites, capped = {}, [], 0, False
    for x in idautils.XrefsTo(ea, ida_xref.XREF_FAR):
        sites += 1
        if sites > cap:
            capped = True
            break
        if x.iscode:
            f = ida_funcs.get_func(x.frm)
            key = f.start_ea if f else x.frm
            by[key] = by.get(key, 0) + 1
        else:
            data.append(x.frm)
    lst, total = _ranked(by, _ref, top)
    out = {"total": total, "top": lst}
    if total > len(lst):
        out["more"] = "%d more: rekit.xrefs(%#x, limit=...)" % (total - len(lst), ea)
    if data:
        out["data_refs"] = {"total": len(data),
                            "at": ["%#x %s" % (d, _seg(d)) for d in data[:4]]}
    if capped:
        out["capped"] = "stopped after %d xrefs" % cap
    return out


# --------------------------------------------------------------------------
# pseudocode
# --------------------------------------------------------------------------

_HEXRAYS = None
_DECL = re.compile(r"^\s+(?P<type>.+?)\s(?P<name>\**[A-Za-z_]\w*(?:\[\w*\])*);\s*(?://.*)?$")
_TYPE = r"(?:const |struct |union |enum |unsigned |signed )*[A-Za-z_][\w:]*(?: [A-Za-z_]\w*)? ?\*+"
# Pointer-to-pointer casts on a whole identifier in a position where the value
# is only passed along (assigned, returned, or handed to a call). The pointer
# is never dereferenced or offset at the cast site, so the type cannot change
# what the expression means.
_PCAST = re.compile(
    r"(?:(?<== )|(?<=, )|(?<=return )|(?<=\w\())\(" + _TYPE + r"\)(?=[A-Za-z_]\w*[,;)])")
_CONST = re.compile(r"(?<![\w.])(0x[0-9A-Fa-f]{5,16}|[1-9]\d{6,})(?:u?LL|uL?|L|i64|ui64)?\b")


def _decompile(f, force=False):
    global _HEXRAYS
    if _HEXRAYS is None:
        _HEXRAYS = bool(ida_hexrays.init_hexrays_plugin())
    if not _HEXRAYS:
        raise RekitError("no Hex-Rays decompiler for this processor",
                         "use rekit.disasm(%#x)" % f.start_ea)
    size = _fsize(f)
    if size > BIG_FUNC and not force:
        raise RekitError("function is %d bytes; decompiling it can take minutes" % size,
                         "pass force=True, or read it with rekit.disasm()")
    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile(f.start_ea, failure)
    if cfunc is None:
        raise RekitError("decompile failed at %#x: %s" % (failure.errea, failure.desc()),
                         "use rekit.disasm(%#x)" % f.start_ea)
    return [idaapi.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]


def _fold_decls(lines):
    """Regroup the local-variable block as `type a, b, *c;` without comments."""
    try:
        open_i = next(i for i, l in enumerate(lines) if l.strip() == "{")
    except StopIteration:
        return lines
    end = None
    for i in range(open_i + 1, len(lines)):
        if lines[i].strip() == "":
            end = i
            break
    if end is None or end == open_i + 1:
        return lines
    block = lines[open_i + 1:end]
    groups, order, loose = {}, [], []
    for line in block:
        code = line.split("//", 1)[0].rstrip()
        if "=" in code or not code.endswith(";"):
            return lines          # not a declaration block after all
        m = _DECL.match(line)
        if m is None or "(" in m.group("type"):
            loose.append(code)
            continue
        typ = m.group("type").strip()
        if typ not in groups:
            groups[typ] = []
            order.append(typ)
        groups[typ].append(m.group("name"))
    folded, cur = [], "  "
    for typ in order:
        piece = "%s %s;" % (typ, ", ".join(groups[typ]))
        if len(cur) + len(piece) > 110 and cur.strip():
            folded.append(cur.rstrip())
            cur = "  "
        cur += piece + " "
    if cur.strip():
        folded.append(cur.rstrip())
    return lines[:open_i + 1] + folded + loose + lines[end:]


def _trim(lines):
    out = _fold_decls(lines)
    return [_PCAST.sub("", l) for l in out]


def _page(lines, start, room):
    """Whole lines from `start` that fit in `room` chars."""
    shown, used = [], 0
    for line in lines[start:]:
        if shown and used + len(line) + 1 > room:
            break
        shown.append(line)
        used += len(line) + 1
    return shown


def _code(f, mode, start, room, force=False):
    raw = _decompile(f, force)
    lines = raw if mode == "raw" else _trim(raw)
    start = max(0, min(int(start), len(lines)))
    shown = _page(lines, start, max(room, 400))
    end = start + len(shown)
    out = {"mode": mode, "lines": len(lines), "shown": [start, end],
           "text": "\n".join(shown)}
    if end < len(lines):
        out["more"] = "rekit.code(%#x, mode=%r, start=%d)" % (f.start_ea, mode, end)
    return out, raw


def _consts(raw_lines, top=8):
    seen = []
    for line in raw_lines:
        for m in _CONST.finditer(line.split("//", 1)[0]):
            tok = m.group(1)
            try:
                val = int(tok, 16) if tok.startswith("0x") else int(tok)
            except ValueError:
                continue
            if ida_bytes.is_mapped(val):
                continue
            hexed = "%#x" % val
            if re.fullmatch(r"0x(f+|7f+|80+|a+|5+)", hexed):
                continue          # masks, sign bits and fill patterns
            text = _const_text(val)
            if text:
                hexed = '%s "%s"' % (hexed, text)
            if hexed not in seen:
                seen.append(hexed)
    return seen[:top], len(seen)


def _const_text(val):
    """The constant's little-endian bytes when they are all printable text."""
    if not 0 < val < 1 << 64:
        return None
    raw = val.to_bytes(8, "little").rstrip(b"\0")
    if len(raw) >= 4 and all(0x20 <= b < 0x7F and b not in (0x22, 0x5C) for b in raw):
        return raw.decode("ascii")
    return None


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def help(topic=None):
    """Return the API cheat sheet, or the guide for help("emu") / help("calc")."""
    if topic == "emu":
        return {"help": EMU_HELP}
    if topic == "calc":
        return {"help": _calc_help()}
    return {"help": HELP}


CALC_HELP = """rekit.calc(code) evaluates a few lines of Python-like arithmetic in a
separate, restricted interpreter and returns the value of the last expression
(plus the names you assigned). Use it to check a formula against a value you
observed, to decrypt or re-hash with the parameters you worked out, and to
test "standard algorithm except for X" by overriding X.

  rekit.calc("pow(7, rotl(532, 4, 32) ^ 5, 1000003)")
  rekit.calc("sha256(b'abc', K={13: 0x80deb5fe}).hex()")
  rekit.calc("k = unhex('0123..'); pkcs7_unpad(cbc_dec('sm4', k, unhex(iv), unhex(ct)))")

Integers, bytes (b'..' or unhex('..')), lists, dicts; assignment, for/while,
if, comprehensions, top-level def. No imports, files, floats or attribute
access beyond .hex() and the like. Integers print as hex = decimal, bytes as
hex. Limits on steps, time and size are reported as errors, not hangs.

functions (name(signature)), by group
%s
"""

_CALC_FUNCS = None


def _calc_help():
    global _CALC_FUNCS
    if _CALC_FUNCS is None:
        import _calc
        try:
            raw = json.loads(subprocess.run([_calc.RECALC, "functions", "--json"],
                                            capture_output=True, timeout=20).stdout)
            _CALC_FUNCS = "\n".join(
                "  %s: %s" % (group, ", ".join(f.get("sig") or f["name"] for f in funcs))
                for group, funcs in raw["functions"].items())
        except Exception as exc:      # the tool is missing or broken: say so
            return CALC_HELP % ("  (function list unavailable: %s)" % exc)
    return CALC_HELP % _CALC_FUNCS


@_api
def image(refresh=False):
    """Snapshot the database bytes for emulation (cached); returns its location."""
    import _emu
    try:
        return _emu.export(refresh)
    except _emu.EmuError as exc:
        raise RekitError(exc.msg, exc.hint)


@_api
def emu(ea=None, requests=None, refresh=False, max_chars=BUDGET, **request):
    """Emulate one function (or a list of requests); see help("emu")."""
    import _emu

    def named(req):
        # The emulator only knows addresses; names and refs are resolved here.
        if not isinstance(req, dict):
            return req
        req = dict(req)
        if isinstance(req.get("replace"), dict):
            req["replace"] = {"%#x" % _ea(k): v for k, v in req["replace"].items()}
        for key in ("func", "start", "until"):
            val = req.get(key)
            if isinstance(val, (list, tuple)):
                req[key] = ["%#x" % _ea(v) for v in val]
            elif val is not None:
                req[key] = "%#x" % _ea(val)
        if isinstance(req.get("init"), (list, tuple)):
            # a bare entry is a function; in an object, func and replace are resolved
            req["init"] = [named(e) if isinstance(e, dict)
                           else e if isinstance(e, bool) else "%#x" % _ea(e)
                           for e in req["init"]]
        return req

    request = named(request)
    if requests is not None:
        if ea is not None or request:
            raise RekitError("pass either one request or requests=[...], not both")
        payload = {"requests": [named(r) for r in requests], "max_chars": max_chars}
        longest = max([r.get("timeout", 20) for r in payload["requests"]
                       if isinstance(r, dict)] or [20]) * max(1, len(payload["requests"]))
    else:
        payload = dict(request)
        if ea is not None:
            if "start" in payload:
                raise RekitError("pass ea to call a function, or start/until to run "
                                 "a fragment, not both")
            payload["func"] = "%#x" % _ea(ea)
        elif "start" not in payload:
            raise RekitError("emu needs a function address",
                             'e.g. rekit.emu(0x401000, args=[1, 2]); see rekit.help("emu")')
        payload["max_chars"] = max_chars
        longest = payload.get("timeout", 20)
    try:
        return _emu.run(payload, timeout=min(int(longest), 120), refresh=refresh)
    except _emu.EmuError as exc:
        raise RekitError(exc.msg, exc.hint)


def _init_list(init):
    """Set-up calls for emu-backed features: names and refs become addresses."""
    if init is None:
        return None
    if not isinstance(init, (list, tuple)):
        raise RekitError("init must be a list of functions to run first",
                         'e.g. init=["sub_402000", 0x402100]')
    out = []
    for e in init:
        if isinstance(e, dict):
            e = dict(e)
            if e.get("func") is not None:
                e["func"] = "%#x" % _ea(e["func"])
            if isinstance(e.get("replace"), dict):
                e["replace"] = {"%#x" % _ea(k): v for k, v in e["replace"].items()}
            out.append(e)
        else:
            out.append("%#x" % _ea(e))
    return out


@_api
def crypto(ea=None, init=None, max_chars=BUDGET, timeout=60):
    """Known cryptographic tables and constants, and where they deviate."""
    import _crypto
    return _crypto.scan(_ea(ea) if ea is not None else None, init=_init_list(init),
                        max_chars=max_chars, timeout=timeout)


@_api
def calc(code, timeout=10, max_chars=4000):
    """Evaluate arithmetic / crypto checks in the restricted scratchpad."""
    import _calc
    if not isinstance(code, str):
        raise RekitError("calc takes the code as one string",
                         'e.g. rekit.calc("pow(7, 541, 1000003)"); see rekit.help("calc")')
    out = _calc.run(code, timeout=timeout, max_chars=max_chars)
    if isinstance(out, dict) and "README" in str(out.get("hint", "")):
        out["hint"] = 'rekit.help("calc") lists the functions'
    return out


@_api
def run(args=None, stdin=None, env=None, timeout=20, max_chars=3000):
    """Emulate the whole input file on these inputs and report its output."""
    import _run
    return _run.run(args=args, stdin=stdin, env=env, timeout=timeout, max_chars=max_chars)


_INFO = None


@_api
def info(max_chars=BUDGET):
    """Database overview: file, architecture, function counts, segments."""
    global _INFO
    if _INFO is None:
        total = named = thunks = 0
        for ea in idautils.Functions():
            total += 1
            f = ida_funcs.get_func(ea)
            if f.flags & ida_funcs.FUNC_THUNK:
                thunks += 1
            elif not ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)):
                named += 1
        _INFO = {"total": total, "named": named, "thunks": thunks}
    segs = []
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        perm = "".join(c if seg.perm & bit else "-"
                       for c, bit in (("r", 4), ("w", 2), ("x", 1)))
        segs.append("%s %#x-%#x %s" % (ida_segment.get_segm_name(seg),
                                        seg.start_ea, seg.end_ea, perm))
    out = {"file": ida_nalt.get_root_filename(),
           "arch": ida_ida.inf_get_procname(),
           "bits": 64 if ida_ida.inf_is_64bit() else 32,
           "range": "%#x-%#x" % (ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()),
           "functions": dict(_INFO),
           "segments": segs[:40]}
    if len(segs) > 40:
        out["segments_more"] = len(segs) - 40
    return out


def _note_line(note):
    state = {True: "verified", False: "rejected"}.get(note.get("verified"), "unverified")
    if note.get("grounded") is False:
        state += ", ungrounded"
    return "%s | %s | %s, %s | #%s" % (_clip(str(note.get("claim", "")), 160), state,
                                       note.get("source", "?"),
                                       note.get("confidence", "?"), note.get("id", "?"))


def _notes_in(lo=None, hi=None):
    """Recorded findings for this database (optionally citing [lo, hi)).

    Findings come from the reworker ledger. Rejected ones are left out. A
    missing ledger or reader module simply means there are no notes.
    """
    try:
        import _notes
    except ImportError:
        return []
    try:
        found = _notes.load(ida_nalt.get_root_filename())
        if lo is not None:
            found = _notes.in_range(found, lo, hi)
    except Exception:  # noqa: BLE001 - notes are an extra, never a failure
        return []
    return [n for n in found if n.get("verified") is not False]


def _card(f, code, max_chars, top, force, decode=True, scan=None):
    start = f.start_ea
    out = {"fn": _ref(start), "ea": "%#x" % start, "size": _fsize(f)}
    noted = []
    # Cards carry verified notes only. An unchecked worker claim shown here
    # would be read as fact by the next worker and cited back as evidence.
    for cs, ce in idautils.Chunks(start):
        for note in _notes_in(cs, ce):
            if note.get("verified") is True and note not in noted:
                noted.append(note)
    if noted:
        noted.sort(key=lambda n: str(n.get("id")))
        out["notes"] = {"total": len(noted), "top": [_note_line(n) for n in noted[:5]]}
    flags = []
    if f.flags & ida_funcs.FUNC_THUNK:
        flags.append("thunk")
    if f.flags & ida_funcs.FUNC_NORET:
        flags.append("noreturn")
    if f.flags & ida_funcs.FUNC_LIB:
        flags.append("library")
    out["callers"] = _callers(start, top)
    scan = scan or _scan(f)
    if not scan["calls"] and not scan["imps"]:
        flags.append("leaf")
    if flags:
        out["flags"] = flags
    lst, total = _ranked(scan["calls"], _ref, top + 4)
    if total:
        out["callees"] = {"total": total, "top": lst}
    lst, total = _ranked(scan["imps"], lambda n: _short(n, 60), top + 8)
    if total:
        out["imports"] = {"total": total, "top": lst}
    dec = _decoded(f, scan) if decode else None
    texts = list(scan["strs"])
    hidden = 0
    if dec and dec["items"]:
        # A pool entry that an initialiser only reads a few bytes of is not a
        # string of this function; IDA shows it as one ("DeviceTyScen").
        keep = [t for t in texts if not _is_fragment(t, scan["str_sites"].get(t, ()), dec)]
        hidden, texts = len(texts) - len(keep), keep
    if texts:
        out["strings"] = {"total": len(texts), "top": [_clip(t, 80) for t in texts[:top + 4]]}
    if dec and (dec["items"] or dec.get("unavailable") or dec["failed"]):
        box = {"total": len(dec["items"])}
        if dec["items"]:
            box["top"] = [_decoded_line(i, 120) for i in dec["items"][:top + 4]]
            box["how"] = ("written at run time by this function's one-time "
                          "initialisers; recovered by emulating them")
            if len(dec["items"]) > top + 4:
                box["more"] = "%d more: rekit.decode(%#x)" % (len(dec["items"]) - top - 4, start)
        if hidden:
            box["replaces"] = ("%d constant-pool fragment%s the initialisers read, "
                               "left out of strings" % (hidden, "" if hidden == 1 else "s"))
        if dec["failed"]:
            box["failed"] = _failed_text(dec)
        if dec.get("unavailable"):
            box["unavailable"] = dec["unavailable"]
        out["decoded"] = box
    if scan["globs"]:
        lst, total = _ranked(scan["globs"], _ref, top)
        out["globals"] = {"total": total, "top": lst}
    if scan["capped"]:
        out["scan_capped"] = ("only the first %d instructions were scanned; rekit.scan(%#x) "
                              "counts calls and immediates over the whole function"
                              % (scan["insns"], start))
    if code == "none":
        proto = idc.get_type(start) or idc.guess_type(start)
        if proto:
            out["type"] = proto
        return out
    if code not in ("trim", "raw"):
        raise RekitError("bad code mode %r" % code, 'use "trim", "raw" or "none"')
    try:
        room = max_chars - _size(out) - 200
        body, raw = _code(f, code, 0, room, force)
    except RekitError as exc:
        out["code"] = {"error": exc.msg, "hint": exc.hint}
        return out
    consts, total = _consts(raw)
    if consts:
        out["consts"] = {"total": total, "top": consts}
        if any('"' in c for c in consts):
            out["consts"]["text"] = ("quoted = that constant's bytes read as text; "
                                     "fragments, not joined")
    out["code"] = body
    return out


@_api
def fn(ea, code="trim", max_chars=BUDGET, top=8, force=False, decode=True):
    """Function card: who calls it, what it calls and touches, and its code."""
    return _card(_func(ea), code, max_chars, top, force, decode)


@_api
def code(ea, mode="trim", start=0, max_chars=BUDGET, force=False):
    """Pseudocode of the function containing ea, paginated by line."""
    if mode not in ("trim", "raw"):
        raise RekitError("bad mode %r" % mode, 'use "trim" or "raw"')
    f = _func(ea)
    body, _ = _code(f, mode, start, max_chars - 200, force)
    out = {"fn": _ref(f.start_ea)}
    out.update(body)
    return out


@_api
def xrefs(ea, limit=20, max_chars=BUDGET):
    """References to ea, grouped by the function they come from."""
    target = _ea(ea)
    by, loose, total, cap = {}, [], 0, 50000
    for x in idautils.XrefsTo(target, ida_xref.XREF_FAR):
        total += 1
        if total > cap:
            break
        kind = _KIND.get(x.type, "ref")
        f = ida_funcs.get_func(x.frm)
        if f is None:
            loose.append("%#x %s (%s)" % (x.frm, _seg(x.frm), kind))
            continue
        rec = by.setdefault(f.start_ea, {"n": 0, "kinds": [], "at": []})
        rec["n"] += 1
        if kind not in rec["kinds"]:
            rec["kinds"].append(kind)
        if len(rec["at"]) < 3:
            rec["at"].append("%#x" % x.frm)
    rows = sorted(by.items(), key=lambda kv: (-kv[1]["n"], kv[0]))
    out = {"to": _ref(target), "total": min(total, cap), "functions": len(rows),
           "by_fn": ["%s | %s x%d | %s%s" % (_ref(k), "/".join(r["kinds"]), r["n"],
                                              " ".join(r["at"]),
                                              " ..." if r["n"] > len(r["at"]) else "")
                     for k, r in rows[:limit]]}
    if len(rows) > limit:
        out["more"] = "%d more functions: raise limit" % (len(rows) - limit)
    if loose:
        out["outside_fn"] = {"total": len(loose), "top": loose[:limit]}
    if total > cap:
        out["capped"] = "stopped after %d xrefs" % cap
    return out


@_api
def calls(ea, depth=2, dir="out", max_nodes=60, fanout=12, max_chars=BUDGET):
    """Call tree below (dir="out") or above (dir="in") a function, as text."""
    if dir not in ("out", "in"):
        raise RekitError("bad dir %r" % dir, 'use "out" or "in"')
    root = _func(ea).start_ea
    lines, seen, count = [], {root}, [1]
    indirect, marks = {}, set()

    def kids(node):
        f = ida_funcs.get_func(node)
        if dir == "out":
            scan = _scan(f)
            funcs = sorted(scan["calls"], key=lambda k: (-scan["calls"][k], k))
            imps = sorted(scan["imps"], key=lambda k: (-scan["imps"][k], k))
            return funcs, imps
        by, taken, data = {}, {}, []
        for x in idautils.XrefsTo(node, ida_xref.XREF_FAR):
            cf = ida_funcs.get_func(x.frm)
            if x.iscode:
                if x.type not in _CALL and x.type not in _JUMP:
                    continue
                if cf is not None and cf.start_ea != node:
                    by[cf.start_ea] = by.get(cf.start_ea, 0) + 1
            elif cf is None:
                data.append(x.frm)      # a pointer stored in a table or vtable
            elif cf.start_ea != node:
                taken.setdefault(cf.start_ea, x.frm)
            if len(by) + len(taken) + len(data) > 5000:
                break
        # the address is taken (stored, passed as a callback) without a call
        indirect[node] = ({k: v for k, v in taken.items() if k not in by}, data)
        return sorted(by, key=lambda k: (-by[k], k)), []

    def walk(node, level):
        funcs, imps = kids(node)
        pad = "  " * (level + 1)
        if imps:
            shown = [_short(i, 40) for i in imps[:fanout]]
            extra = " +%d" % (len(imps) - fanout) if len(imps) > fanout else ""
            lines.append("%simports: %s%s" % (pad, ", ".join(shown), extra))
        for i, child in enumerate(funcs):
            if i >= fanout or count[0] >= max_nodes:
                lines.append("%s... %d more" % (pad, len(funcs) - i))
                break
            if child in seen:
                lines.append("%s%s ^" % (pad, _ref(child)))
                continue
            seen.add(child)
            count[0] += 1
            lines.append(pad + _ref(child))
            if level + 1 < depth:
                walk(child, level + 1)
        taken, data = indirect.get(node, ({}, []))
        for i, child in enumerate(sorted(taken)):
            if i >= fanout or count[0] >= max_nodes:
                lines.append("%s... %d more [addr]" % (pad, len(taken) - i))
                break
            marks.add("addr")
            tag = " [addr %#x]" % taken[child]
            if child in seen:
                lines.append("%s%s%s ^" % (pad, _ref(child), tag))
                continue
            seen.add(child)
            count[0] += 1
            lines.append(pad + _ref(child) + tag)
            if level + 1 < depth:
                walk(child, level + 1)
        for i, at in enumerate(data):
            if i >= min(fanout, 4):
                lines.append("%s... %d more [data]" % (pad, len(data) - i))
                break
            marks.add("data")
            lines.append("%s%#x %s [data]" % (pad, at, _seg(at)))

    lines.append(_ref(root))
    walk(root, 0)
    legend = "^ = already expanded above; indentation = call depth"
    if "addr" in marks:
        legend += ("; [addr X] = takes the function's address at X instead of "
                   "calling it (callback, dispatch table)")
    if "data" in marks:
        legend += ("; [data] = a pointer to the function stored in data (vtable, "
                   "table): rekit.xrefs(that address) shows who reads it")
    out = {"root": _ref(root), "dir": dir, "depth": depth, "nodes": count[0],
           "tree": "\n".join(lines), "legend": legend}
    if count[0] >= max_nodes:
        out["capped"] = "max_nodes=%d reached; lower depth or start deeper" % max_nodes
    return out


def _matcher(pattern, regex):
    if regex:
        try:
            rx = re.compile(pattern, re.I)
        except re.error as exc:
            raise RekitError("bad regex: %s" % exc)
        return lambda s: rx.search(s) is not None
    low = pattern.lower()
    return lambda s: low in s.lower()


def _where(ea):
    return _ref(ea) if ida_funcs.get_func(ea) else "%#x %s" % (ea, _seg(ea))


def _fn_users(ea, top=3):
    fns, n = [], 0
    for x in idautils.XrefsTo(ea, ida_xref.XREF_FAR):
        n += 1
        if n > 500:
            break
        f = ida_funcs.get_func(x.frm)
        label = _ref(f.start_ea) if f else "%#x" % x.frm
        if label not in fns:
            fns.append(label)
    tail = " +%d" % (len(fns) - top) if len(fns) > top else ""
    return n, ", ".join(fns[:top]) + tail


@_api
def find(name=None, string=None, bytes=None, imm=None, limit=20, regex=False,
         max_chars=BUDGET, seconds=20, wide=None):
    """Search by symbol name, string content, byte pattern, or immediate.

    String search covers C strings, plus UTF-16 for PE files; wide=True adds
    UTF-16 for other formats (slow to index on very large databases).
    """
    given = [k for k, v in (("name", name), ("string", string), ("bytes", bytes),
                            ("imm", imm)) if v is not None]
    if len(given) != 1:
        raise RekitError("pass exactly one of name=, string=, bytes=, imm=",
                         'e.g. rekit.find(string="http")')
    kind = given[0]
    deadline = time.time() + seconds
    hits, total, note = [], 0, None

    if kind == "name":
        match = _matcher(name, regex)
        found = []
        for ea, nm in idautils.Names():
            if not match(nm):
                continue
            f = ida_funcs.get_func(ea)
            rank = (0 if _is_extern(ea) else 1 if f and f.start_ea == ea else 2)
            found.append((rank, ea))
        total = len(found)
        found.sort()                    # imports, then functions, then data
        for rank, ea in found[:limit]:
            n, _ = _fn_users(ea, 0)
            hits.append("%s | %s | %s xrefs" % (_ref(ea), ("import", "func", "data")[rank],
                                                 "500+" if n > 500 else n))
    elif kind == "string":
        match = _matcher(string, regex)
        # a non-ASCII pattern needs the (larger, slower) index of all strings
        for ea, text in _strings(ascii_only=string.isascii(), wide=wide):
            if not match(text):
                continue
            total += 1
            if len(hits) < limit:
                n, users = _fn_users(ea)
                hits.append('%#x "%s" <- %s' % (ea, _clip(text, 100), users or "no xrefs"))
    elif kind == "bytes":
        pat = bytes if isinstance(bytes, str) else " ".join("%02X" % b for b in bytes)
        ea, end = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
        while True:
            ea = ida_bytes.find_bytes(pat, ea, range_end=end)
            if ea == BADADDR:
                break
            total += 1
            if len(hits) < limit:
                hits.append("%#x in %s" % (ea, _where(ea)))
            elif total >= limit * 50:
                note = "stopped counting at %d hits" % total
                break
            if time.time() > deadline:
                note = "time budget of %ds hit; hits are a prefix" % seconds
                break
            ea += 1
    else:
        value = imm if isinstance(imm, int) else int(str(imm), 0)
        ea = ida_ida.inf_get_min_ea()
        while True:
            ea, _op = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
            if ea == BADADDR:
                break
            total += 1
            if len(hits) < limit:
                hits.append("%#x in %s | %s" % (ea, _where(ea),
                                               _clip(idc.generate_disasm_line(ea, 0) or "", 60)))
            else:
                note = "stopped at limit; raise limit for more"
                break
            if time.time() > deadline:
                note = ("time budget of %ds hit; hits are a prefix. To search one "
                        "function or range use rekit.scan(ea, imm=...)" % seconds)
                break
    out = {"query": {kind: name or string or bytes or imm}, "total": total, "hits": hits}
    if total > len(hits):
        out["more"] = "%d not shown: raise limit or narrow the pattern" % (total - len(hits))
    if kind == "string" and not total and not wide and not _is_pe():
        note = "UTF-16 strings are not indexed for this file type; retry with wide=True"
    if note:
        out["note"] = note
    return out


@_api
def disasm(ea, n=40, max_chars=BUDGET):
    """Compact disassembly: n lines from ea, stopping at the function end."""
    cur = _ea(ea)
    f = ida_funcs.get_func(cur)
    stop = BADADDR
    if f is not None:
        stop = max(ce for _cs, ce in idautils.Chunks(f.start_ea) if _cs <= cur < ce) \
            if any(cs <= cur < ce for cs, ce in idautils.Chunks(f.start_ea)) else f.end_ea
    lines, used = [], 0
    while cur != BADADDR and cur < stop and len(lines) < n:
        text = re.sub(r"\s{2,}", " ", idc.generate_disasm_line(cur, 0) or "?")
        line = "%x %s" % (cur, text)
        if lines and used + len(line) + 1 > max_chars - 300:
            break
        lines.append(line)
        used += len(line) + 1
        cur = idc.next_head(cur, stop)
    out = {"at": _ref(_ea(ea)), "lines": len(lines), "text": "\n".join(lines)}
    if cur != BADADDR and cur < stop:
        out["next"] = "%#x" % cur
    return out


@_api
def notes(ea=None, limit=20, max_chars=BUDGET):
    """Findings recorded for this database; with ea, only that function's.

    Notes are earlier conclusions kept in a ledger beside the tools, not facts
    read from the binary. "verified" means the orchestrator checked the cited
    evidence; "unverified" is a worker's claim nobody has checked yet.
    """
    if ea is None:
        found, scope = _notes_in(), "database"
    else:
        f = _func(ea)
        found, scope = [], _ref(f.start_ea)
        for cs, ce in idautils.Chunks(f.start_ea):
            for note in _notes_in(cs, ce):
                if note not in found:
                    found.append(note)
    found.sort(key=lambda n: (n.get("verified") is not True, str(n.get("id"))))
    out = {"scope": scope, "total": len(found),
           "notes": [dict(line=_note_line(n), evidence=n.get("evidence", []))
                     for n in found[:limit]]}
    if len(found) > limit:
        out["more"] = "%d not shown: raise limit" % (len(found) - limit)
    return out


@_api
def batch(eas, code="none", max_chars=BUDGET * 2, top=5, decode=True):
    """Several function cards in one call; the budget is shared between them."""
    eas = list(eas)
    if not eas:
        raise RekitError("empty list")
    if len(eas) > 40:
        raise RekitError("%d addresses is too many for one call" % len(eas),
                         "send at most 40 at a time")
    each = max(600, max_chars // len(eas))
    funcs, scans = [], {}
    for item in eas:
        try:
            funcs.append(_func(item))
        except RekitError as exc:
            funcs.append(exc)
    if decode:
        # one emulator process for every card's initialisers
        for f in funcs:
            if not isinstance(f, RekitError) and f.start_ea not in scans:
                scans[f.start_ea] = _scan(f)
        _decode_fill([(f, _init_regions(f, scans[f.start_ea])) for f in funcs
                      if not isinstance(f, RekitError) and f.start_ea not in _DECODED])
    cards = []
    for item, f in zip(eas, funcs):
        try:
            if isinstance(f, RekitError):
                raise f
            cards.append(_card(f, code, each, top, False, decode, scans.get(f.start_ea)))
        except RekitError as exc:
            shown = "%#x" % item if isinstance(item, int) else str(item)
            cards.append({"ea": shown, "error": exc.msg})
    return {"count": len(cards), "cards": cards}


# --------------------------------------------------------------------------
# scanning one function or address range
# --------------------------------------------------------------------------

_MASK = (1 << 64) - 1
_RANGES = {}             # spans -> index, the few most recent ones


def _int(x, what):
    if isinstance(x, int) and not isinstance(x, bool):
        return x
    try:
        return int(str(x), 0)
    except ValueError:
        raise RekitError("bad %s %r" % (what, x), "pass an int or a \"0x...\" string")


def _spans(ea, end):
    """(label, [(lo, hi), ...]) for a whole function or for [ea, end)."""
    if end is None:
        f = _func(ea)
        spans = sorted((cs, ce) for cs, ce in idautils.Chunks(f.start_ea))
        label = "%s %#x-%#x" % (_ref(f.start_ea), f.start_ea, f.end_ea)
        if len(spans) > 1:
            label += " and %d more chunks" % (len(spans) - 1)
        return label, spans
    lo = _ea(ea)
    hi = end if isinstance(end, int) and not isinstance(end, bool) else None
    if hi is None:
        text = str(end).strip()
        hi = int(text, 16) if re.fullmatch(r"0[xX][0-9A-Fa-f]+", text) else _ea(end)
    if hi <= lo:
        raise RekitError("end %#x is not above the start %#x" % (hi, lo),
                         "end is an address, not a length")
    return "%#x-%#x" % (lo, hi), [(lo, hi)]


def _range_index(spans, refresh, seconds):
    """Direct calls, tail calls, indirect calls and immediates of a range.

    One pass over the instructions; kept for the next question about the same
    range, since a flattened function is asked about many times.
    """
    key = tuple(spans)
    if not refresh and key in _RANGES:
        return _RANGES[key], True
    deadline = time.time() + seconds
    calls, tails, imms, indirect = {}, {}, {}, []
    count, partial = 0, None
    insn = ida_ua.insn_t()
    for lo, hi in spans:
        ea = lo
        while ea < hi:
            flags = ida_bytes.get_flags(ea)
            size = ida_ua.decode_insn(insn, ea) if ida_bytes.is_code(flags) else 0
            if size <= 0:
                ea = idc.next_head(ea, hi)
                if ea == BADADDR:
                    break
                continue
            count += 1
            if not count & 0x3FFF and time.time() > deadline:
                partial = ea
                break
            if ida_idp.is_call_insn(insn):
                for x in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
                    if x.iscode and x.type in _CALL:
                        calls.setdefault(x.to, []).append(ea)
                        break
                else:
                    indirect.append(ea)
            elif any(op.type in (ida_ua.o_near, ida_ua.o_far) for op in insn.ops):
                # a jump to the start of another function is a tail call
                for x in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
                    if x.iscode and x.type in _JUMP \
                            and not any(a <= x.to < b for a, b in spans):
                        tf = ida_funcs.get_func(x.to)
                        if tf is not None and tf.start_ea == x.to:
                            tails.setdefault(x.to, []).append(ea)
            mnem = None
            for op in insn.ops:
                if op.type == ida_ua.o_void:
                    break
                # operands IDA resolved to an address are not constants
                if op.type == ida_ua.o_imm and not ida_bytes.is_off(flags, op.n):
                    rec = imms.get(op.value & _MASK)
                    if rec is None:
                        rec = imms[op.value & _MASK] = ([], {})
                    rec[0].append(ea)
                    if mnem is None:
                        mnem = insn.get_canon_mnem().upper()
                    rec[1][mnem] = rec[1].get(mnem, 0) + 1
            ea += size
        if partial is not None:
            break
    index = {"insns": count, "calls": calls, "tails": tails, "imms": imms,
             "indirect": indirect, "partial": partial}
    if partial is None:
        _RANGES[key] = index
        while len(_RANGES) > 4:
            del _RANGES[next(iter(_RANGES))]
    return index, False


def _target_label(ea):
    f = ida_funcs.get_func(ea)
    if f is not None and f.start_ea == ea and f.flags & ida_funcs.FUNC_THUNK:
        return _short(ida_funcs.get_func_name(ea) or "%#x" % ea, 60)
    if _is_extern(ea):
        return _short(ida_name.get_name(ea) or "%#x" % ea, 60)
    return _ref(ea)


def _line(ea, n=60):
    return _clip(re.sub(r"\s{2,}", " ", idc.generate_disasm_line(ea, 0) or "?"), n)


def _reg_before(site, regno, floor, depth=64):
    """The immediate last moved into a register on the straight line into site.

    (value, "") or (None, reason). Only the fall-through path is read: the
    walk gives up at a jump target, where another path could bring a different
    value, and at a call, which leaves its own result in argument registers.
    """
    insn = ida_ua.insn_t()
    cur = site
    for _ in range(depth):
        if any(x.iscode and x.type in _JUMP for x in idautils.XrefsTo(cur, 0)):
            return None, "set before the jump target %#x" % cur
        prev = idc.prev_head(cur, floor)
        if prev == BADADDR or not ida_bytes.is_flow(ida_bytes.get_flags(cur)) \
                or ida_ua.decode_insn(insn, prev) <= 0:
            return None, "no straight-line code before %#x" % cur
        if ida_idp.is_call_insn(insn):
            return None, "left by the call at %#x" % prev
        feat = insn.get_canon_feature()
        ops = [op for op in insn.ops if op.type != ida_ua.o_void]
        for i, op in enumerate(ops[:6]):
            if op.type != ida_ua.o_reg or op.reg != regno \
                    or not feat & (ida_idp.CF_CHG1 << i):
                continue
            mnem = insn.get_canon_mnem().lower()
            if i == 0 and len(ops) == 2 and ops[1].type == ida_ua.o_imm \
                    and mnem in ("mov", "movz", "li"):
                return ops[1].value & _MASK, ""
            if mnem in ("xor", "eor") and len(ops) >= 2 and len({o.reg for o in ops}) == 1 \
                    and all(o.type == ida_ua.o_reg for o in ops):
                return 0, ""
            return None, _line(prev, 48)
        cur = prev
    return None, "not set in the %d instructions before the call" % depth


@_api
def scan(ea, end=None, show="calls", imm=None, to=None, reg=None, mnem=None,
         min=0x10000, start=0, limit=None, refresh=False, seconds=120,
         max_chars=BUDGET):
    """Calls and immediates inside one function, or inside [ea, end).

    For code that cannot be decompiled. Default: direct calls counted by
    target. show="imms": the distinct immediates of at least `min`. imm=V:
    where V is used. to=target: every call site of it; with reg="w0", also the
    immediate moved into that register on the straight line before the call.
    """
    floor_value, room = _int(min, "min"), max(max_chars, 800) - 500
    if imm is not None and to is not None:
        raise RekitError("pass imm= or to=, not both")
    if show not in ("calls", "imms"):
        raise RekitError("bad show %r" % (show,), 'use "calls" or "imms"')
    if reg is not None and to is None:
        raise RekitError("reg= needs to=<call target>",
                         'e.g. rekit.scan(ea, to="_syscall", reg="w0")')
    start = max(0, int(start))
    label, spans = _spans(ea, end)
    index, cached = _range_index(spans, refresh, seconds)
    out = {"range": label, "insns": index["insns"]}
    again = "%#x" % spans[0][0] if end is None else "%#x, end=%#x" % spans[0]
    if index["partial"] is not None:
        out["capped"] = ("time budget of %ds hit at %#x; the result covers the range "
                         "up to there. Raise seconds or scan a smaller range"
                         % (seconds, index["partial"]))

    if imm is not None:
        value = _int(imm, "imm") & _MASK
        sites = index["imms"].get(value, ([], {}))[0]
        cap = limit or 20
        out.update({"imm": "%#x" % value, "total": len(sites),
                    "hits": ["%#x %s" % (s, _line(s)) for s in sites[start:start + cap]]})
        if len(sites) > start + cap:
            out["more"] = "%d not shown: pass start=%d or raise limit" % (
                len(sites) - start - cap, start + cap)
        return out

    if to is not None:
        target = _ea(to)
        sites = [(s, "") for s in index["calls"].get(target, ())] \
            + [(s, " tail") for s in index["tails"].get(target, ())]
        if not sites:
            raise RekitError("no direct call to %s in %s" % (_target_label(target), label),
                             "rekit.scan(%s) lists the targets called there" % again)
        sites.sort()
        cap = limit or 40
        out.update({"to": _target_label(target), "sites": len(sites)})
        if reg is None:
            rows = ["%#x%s" % s for s in sites]
        else:
            info = ida_idp.reg_info_t()
            if not any(ida_idp.parse_reg_name(info, r)
                       for r in (str(reg), str(reg).upper(), str(reg).lower())):
                raise RekitError("no register named %r on this processor" % (reg,),
                                 'e.g. reg="w0" on arm64, reg="edi" on x64')
            rows, dist = [], {}
            for site, tail in sites:
                value, why = _reg_before(site, info.reg, spans[0][0])
                key = "?" if value is None else "%#x" % value
                dist[key] = dist.get(key, 0) + 1
                rows.append("%#x %s%s" % (site, key if value is not None else "? " + why, tail))
            out["reg"] = str(reg)
            out["values"], _ = _ranked(dist, str, 40)
            if "?" in dist:
                out["unknown"] = ("? = the last write before the call was not an "
                                  "immediate on the straight line; read that site "
                                  "with rekit.disasm")
        out["at"] = rows[start:start + cap]
        if len(rows) > start + cap:
            out["more"] = "%d not shown: pass start=%d or raise limit" % (
                len(rows) - start - cap, start + cap)
        return out

    if show == "imms":
        if mnem is None:
            wanted = None
        else:
            wanted = {str(m).upper() for m in ([mnem] if isinstance(mnem, str) else mnem)}
        rows = []
        for value in sorted(index["imms"]):
            if value < floor_value:
                continue
            sites, by = index["imms"][value]
            n = len(sites) if wanted is None else sum(c for m, c in by.items() if m in wanted)
            if n:
                rows.append("%#x%s %s" % (value, " x%d" % n if n > 1 else "",
                                          "/".join(sorted(m for m in by
                                                          if wanted is None or m in wanted))))
        shown = _page(rows, start, room)
        if limit:
            shown = shown[:limit]
        box = {"total": len(rows), "min": "%#x" % floor_value,
               "shown": [start, start + len(shown)], "top": shown}
        if wanted is not None:
            box["mnem"] = sorted(wanted)
        out["imms"] = box
        if start + len(shown) < len(rows):
            out["more"] = 'rekit.scan(%s, show="imms", start=%d)' % (again, start + len(shown))
        return out

    counts = {}
    for target, sites in index["calls"].items():
        counts[target] = [len(sites), 0]
    for target, sites in index["tails"].items():
        counts.setdefault(target, [0, 0])[1] = len(sites)
    order = sorted(counts, key=lambda k: (-sum(counts[k]), k))
    rows = []
    for target in order:
        direct, tail = counts[target]
        text = _target_label(target)
        if direct > 1 or (direct and tail):
            text += " x%d" % direct
        if tail:
            text += " +%d tail" % tail if direct else " tail x%d" % tail
        rows.append(text)
    cap = limit or 20
    shown = rows[start:start + cap]
    box = {"sites": sum(c[0] for c in counts.values()), "targets": len(rows), "top": shown}
    tail_total = sum(c[1] for c in counts.values())
    if tail_total:
        box["tail_calls"] = tail_total
    out["calls"] = box
    if index["indirect"]:
        out["indirect"] = {"total": len(index["indirect"]),
                           "at": ["%#x" % a for a in index["indirect"][:4]]}
    if len(rows) > start + cap:
        out["more"] = "%d more targets: pass start=%d or raise limit" % (
            len(rows) - start - cap, start + cap)
    return out


# --------------------------------------------------------------------------
# strings built at run time
# --------------------------------------------------------------------------

_DECODED = {}            # function start -> what its initialisers write
_WSTR = re.compile(r'^(0x[0-9a-fA-F]+) (L?)"(.*)"$', re.S)
_INIT_INSNS = 200000


def _writable(ea):
    seg = ida_segment.getseg(ea)
    if seg is None or seg.type == ida_segment.SEG_XTRN:
        return False
    if seg.perm:
        return bool(seg.perm & ida_segment.SEGPERM_WRITE)
    return seg.type in (ida_segment.SEG_DATA, ida_segment.SEG_BSS)


def _init_regions(f, scan, cap=32):
    """Flag-guarded one-time initialisers of a function.

    The compiler's form for a lazily built static is: read a flag byte, skip
    if set, build the value, set the flag. So a writable byte the function
    both reads and writes marks one, from the read to just after the write.
    What is built in between (a string split into constants, an XOR loop, the
    vectorised form of either) does not have to be recognised: it is run.
    """
    out = []
    for flag, first in scan["reads"].items():
        stores = scan["writes"].get(flag)
        if not stores or not _writable(flag) or ida_bytes.get_item_size(flag) != 1:
            continue
        begin = first
        prev = idc.prev_head(first, 0)
        if prev != BADADDR and ida_funcs.get_func(prev) is not None \
                and ida_funcs.get_func(prev).start_ea == f.start_ea:
            # the instruction that forms the flag's page address belongs too
            if any(x.to >> 12 == flag >> 12
                   for x in idautils.XrefsFrom(prev, ida_xref.XREF_DATA)):
                begin = prev
        ends = sorted({idc.next_head(w) for w in stores} - {BADADDR})
        if ends:
            out.append({"flag": flag, "start": begin, "until": ends})
    out.sort(key=lambda r: r["start"])
    return out[:cap]


def _decode_fill(jobs):
    """Emulate the initialisers of several functions in one emulator run."""
    todo = {}
    for f, regions in jobs:
        todo.setdefault(f.start_ea, regions)
    reqs, owner = [], []
    for start, regions in todo.items():
        for r in regions:
            reqs.append({"start": "%#x" % r["start"],
                         "until": ["%#x" % u for u in r["until"]],
                         "max_insns": _INIT_INSNS})
            owner.append((start, r))
    found = {start: {"regions": len(regions), "items": [], "spans": [], "failed": {}}
             for start, regions in todo.items()}
    error = None
    if reqs:
        import _emu
        try:
            reply = _emu.run({"requests": reqs, "max_chars": 6000 * len(reqs) + 4000},
                             timeout=60)
            error = reply.get("error")
        except _emu.EmuError as exc:
            reply, error = {}, exc.msg
        results = {r.get("id"): r for r in reply.get("results", []) if isinstance(r, dict)}
        for i, (start, region) in enumerate(owner):
            box = found[start]
            one = results.get(i)
            if error or one is None:
                continue
            stop = one.get("stop") or {}
            if stop.get("reason") != "until":
                reason = str(stop.get("reason") or one.get("error") or "error")
                box["failed"][reason] = box["failed"].get(reason, 0) + 1
                continue
            hit = int(stop["at"], 16)
            inline = hit > region["start"]
            # a backward jump inside the initialiser: the value is computed
            loop = inline and any(
                x.iscode and x.type in _JUMP and region["start"] <= x.to <= head
                for head in idautils.Heads(region["start"], hit)
                for x in idautils.XrefsFrom(head, ida_xref.XREF_FAR))
            if inline:
                box["spans"].append((region["start"], hit))
            for write in (one.get("writes") or {}).get("top", []):
                if not _writable(int(write["addr"], 16)):
                    continue        # a store through a register nobody set
                for shown in (write.get("strings") or {}).get("top", []):
                    m = _WSTR.match(shown)
                    if m is None:
                        continue
                    item = {"ea": int(m.group(1), 16), "text": m.group(3),
                            "wide": bool(m.group(2)), "start": region["start"],
                            "end": hit if inline else region["until"][-1], "loop": loop}
                    if not any(i["ea"] == item["ea"] and i["text"] == item["text"]
                               for i in box["items"]):
                        box["items"].append(item)
    for start, box in found.items():
        if error:
            box["unavailable"] = "emulation failed: %s" % _clip(str(error), 160)
        else:
            _DECODED[start] = box       # a failure may be transient: not kept
    while len(_DECODED) > 4000:
        del _DECODED[next(iter(_DECODED))]
    return found


def _decoded(f, scan=None, refresh=False):
    start = f.start_ea
    if refresh or start not in _DECODED:
        regions = _init_regions(f, scan or _scan(f))
        return _decode_fill([(f, regions)])[start]
    return _DECODED[start]


def _decoded_line(item, n):
    return '%#x %s"%s" | init %#x-%#x%s' % (
        item["ea"], "L" if item["wide"] else "", _clip(item["text"], n),
        item["start"], item["end"], " | loop" if item["loop"] else "")


def _failed_text(dec):
    return "%d of %d initialisers did not run to their end (%s)" % (
        sum(dec["failed"].values()), dec["regions"],
        ", ".join("%s x%d" % kv for kv in sorted(dec["failed"].items())))


def _is_fragment(text, sites, dec):
    """A pool entry referenced only inside initialisers that were decoded."""
    if not sites or not all(any(a <= s < b for a, b in dec["spans"]) for s in sites):
        return False
    if any(text == item["text"] for item in dec["items"]):
        return False            # a whole literal that was copied: a real string
    return len(text) < 4 or any(text[:4] in item["text"] for item in dec["items"])


@_api
def decode(ea, limit=50, refresh=False, max_chars=BUDGET):
    """Strings a function builds at run time in its one-time initialisers.

    Each flag-guarded initialiser is emulated on a snapshot of the database
    from the file's initial state; the strings it writes to static memory are
    reported with the address they are built at. Nothing runs natively.
    """
    f = _func(ea)
    dec = _decoded(f, refresh=refresh)
    out = {"fn": _ref(f.start_ea), "initialisers": dec["regions"],
           "total": len(dec["items"])}
    if dec.get("unavailable"):
        out["unavailable"] = dec["unavailable"]
    if not dec["regions"]:
        out["note"] = ("no flag-guarded one-time initialiser here. For a decode "
                       "routine that takes arguments, call it with rekit.emu")
        return out
    shown = _page([_decoded_line(i, 400) for i in dec["items"][:limit]], 0,
                  max(max_chars, 800) - 600)
    out["strings"] = shown
    if dec["items"]:
        out["how"] = ("each initialiser was emulated from the file's initial state; "
                      "the address is where the string is built, init is the code "
                      "that builds it, loop = computed in a loop (decoded, not "
                      "just stored)")
    if len(shown) < len(dec["items"]):
        out["more"] = "%d not shown: raise limit or max_chars" % (len(dec["items"]) - len(shown))
    if dec["failed"]:
        out["failed"] = _failed_text(dec)
    return out


# --------------------------------------------------------------------------
# self test
# --------------------------------------------------------------------------

def selftest(n=30, seed=1):
    """Exercise every call on the open database and report what broke.

    Read-only. Also reports how much `trim` saves on this binary.
    """
    rng = random.Random(seed)
    all_funcs = list(idautils.Functions())
    pool = []
    for ea in rng.sample(all_funcs, min(len(all_funcs), 6000)):
        f = ida_funcs.get_func(ea)
        if 80 <= _fsize(f) <= 6000 and not f.flags & ida_funcs.FUNC_THUNK:
            pool.append(ea)
        if len(pool) >= n:
            break
    fails, raw_chars, trim_chars, card_chars, started = [], 0, 0, [], time.time()
    undecompilable = set()
    proc = ida_ida.inf_get_procname().lower()
    arg_reg = "x0" if proc.startswith("arm") and ida_ida.inf_is_64bit() else \
        "eax" if proc == "metapc" else None

    def check(label, res, budget=BUDGET):
        try:
            size = _size(res)
        except (TypeError, ValueError) as exc:
            fails.append("%s: not JSON-serialisable: %s" % (label, exc))
            return False
        if size > int(budget * 1.25) + 400:
            fails.append("%s: %d chars exceeds budget %d" % (label, size, budget))
        if "error" in res:
            if res["error"].startswith("decompile failed"):
                undecompilable.add(label.split()[-1])   # Hex-Rays' limit, not ours
            else:
                fails.append("%s: %s" % (label, res["error"]))
            return False
        return True

    for ea in pool:
        tag = "%#x" % ea
        card = fn(ea)
        if check("fn " + tag, card):
            card_chars.append(_size(card))
        try:
            raw = _decompile(ida_funcs.get_func(ea))
        except RekitError:
            raw = None
        if raw is not None:
            trimmed = _trim(raw)
            raw_chars += sum(len(l) + 1 for l in raw)
            trim_chars += sum(len(l) + 1 for l in trimmed)
            body = lambda ls: [l for l in ls[next((i for i, l in enumerate(ls)
                                                   if l.strip() == ""), 0):]]
            if len(body(raw)) != len(body(trimmed)):
                fails.append("trim %s: statement line count changed" % tag)
            words = lambda ls: re.findall(r"[A-Za-z_]\w*|\d+", _PCAST.sub("", "\n".join(body(ls))))
            if words(raw) != words(trimmed):
                fails.append("trim %s: body tokens changed" % tag)
        check("code raw " + tag, code(ea, mode="raw"))
        check("xrefs " + tag, xrefs(ea))
        check("calls out " + tag, calls(ea, depth=2))
        check("calls in " + tag, calls(ea, depth=1, dir="in"))
        check("disasm " + tag, disasm(ea, n=20))
        # a range scan sees at least every direct callee the card counts
        res = scan(ea)
        if check("scan " + tag, res):
            index = _RANGES.get(tuple(sorted(idautils.Chunks(ea)))) or {"calls": {}, "tails": {}}
            f = ida_funcs.get_func(ea)
            card_scan = _scan(f)
            missed = [t for t in card_scan["calls"]
                      if t not in index["calls"] and t not in index["tails"]]
            if missed and not card_scan["capped"]:
                fails.append("scan %s: misses callee %#x the card lists" % (tag, missed[0]))
            if index["calls"]:
                target = next(iter(index["calls"]))
                check("scan to " + tag, scan(ea, to=target))
                if arg_reg:
                    sites = scan(ea, to=target, reg=arg_reg)
                    if check("scan reg " + tag, sites) \
                            and len(sites.get("at", [])) != min(sites["sites"], 40):
                        fails.append("scan reg %s: site list and count disagree" % tag)
        listed = scan(ea, show="imms", min=0x100)
        if check("scan imms " + tag, listed) and listed["imms"]["top"]:
            value = listed["imms"]["top"][0].split()[0]
            if not scan(ea, imm=value).get("total"):
                fails.append("scan %s: immediate %s is listed but not found" % (tag, value))
        check("decode " + tag, decode(ea))
    # a string shown on a card must also be findable by search
    probes = []
    for ea in all_funcs[::max(1, len(all_funcs) // 3000)]:
        for text in _scan(ida_funcs.get_func(ea))["strs"]:
            if 8 <= len(text) <= 60 and text.isascii() and text.isprintable():
                probes.append(text)
                break
        if len(probes) >= 4:
            break
    for text in probes:
        res = find(string=text, limit=1)
        if not res.get("total"):
            fails.append("find(string=%r): shown on a card but not found by search" % text)
    # a function reached only through its address must not look uncalled
    for ea in all_funcs[::max(1, len(all_funcs) // 4000)]:
        refs = list(idautils.XrefsTo(ea, ida_xref.XREF_FAR))
        if refs and len(refs) <= 8 and not any(x.iscode for x in refs) \
                and not any((ida_funcs.get_func(x.frm) or ida_funcs.get_func(ea)).start_ea == ea
                            for x in refs):
            tree = calls(ea, depth=1, dir="in")
            if check("calls in (address only) %#x" % ea, tree) \
                    and "[addr" not in tree["tree"] and "[data]" not in tree["tree"]:
                fails.append("calls in %#x: has data references but the tree is empty" % ea)
            break
    for label, res in (("scan(0)", scan(0)), ("scan imm+to", scan(pool[0], imm=1, to=pool[0])
                                              if pool else {"error": 1}),
                       ("scan reg without to", scan(pool[0], reg="x0") if pool else {"error": 1}),
                       ("decode(0)", decode(0))):
        if "error" not in res:
            fails.append("%s should be an error" % label)
    check("info", info())
    if pool:
        check("batch", batch(pool[:8]), BUDGET * 2)
    check("find name", find(name="sub_", limit=3))
    if "error" not in fn(0):
        fails.append("fn(0) should be an error")
    if "error" not in fn("no_such_symbol_zz"):
        fails.append("unknown symbol should be an error")
    if "error" not in find():
        fails.append("find() without a criterion should be an error")
    cards = sorted(card_chars)
    return {
        "rekit": __version__, "functions_tested": len(pool), "failures": fails,
        "undecompilable": len(undecompilable),
        "seconds": round(time.time() - started, 1),
        "trim": {"raw_chars": raw_chars, "trim_chars": trim_chars,
                 "saved_pct": round(100.0 * (raw_chars - trim_chars) / raw_chars, 1)
                 if raw_chars else None},
        "card_chars": {"median": cards[len(cards) // 2] if cards else None,
                       "max": cards[-1] if cards else None},
    }
