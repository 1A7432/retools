"""Test images: tiny functions compiled/assembled with the system clang for
i386, x86_64 and aarch64, wrapped into format-1 image directories."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess

import pytest

from remu.arch import for_image
from remu.cli import handle
from remu.image import Image

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
CLANG = shutil.which("clang") or "/usr/bin/clang"
TARGETS = {"x86": "i386-unknown-linux-gnu", "x64": "x86_64-unknown-linux-gnu",
           "arm64": "aarch64-unknown-linux-gnu"}
CFLAGS = ["-c", "-O1", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-stack-protector",
          "-fno-asynchronous-unwind-tables", "-fno-jump-tables"]

IAT = 0x405000
DATA = 0x406000
SWEEP_IAT = 0x405100
SWEEP_THUNKS = 0x404000

# Imports reachable through generated thunks, to call stubs directly as functions.
SWEEP = ["memcpy", "memset", "memcmp", "strlen", "wcslen", "strcmp", "wsprintfA", "malloc",
         "calloc", "realloc", "free", "lstrlenA", "lstrlenW", "lstrcpyA", "lstrcatW", "lstrcmpiA",
         "lstrcpynW", "HeapAlloc", "HeapFree", "GetProcessHeap", "VirtualAlloc", "VirtualProtect",
         "LocalAlloc", "GlobalAlloc", "MultiByteToWideChar", "WideCharToMultiByte",
         "GetLastError", "SetLastError", "SysAllocStringLen", "TlsAlloc", "TlsSetValue",
         "TlsGetValue", "RtlMoveMemory", "GetTickCount", "CharUpperBuffW", "CompareStringW",
         "Unmodelled"]
CRT = {"memcpy", "memset", "memcmp", "strlen", "wcslen", "strcmp", "wsprintfA", "malloc",
       "calloc", "realloc", "free"}


def _elf_text(path):
    d = open(path, "rb").read()
    assert d[:4] == b"\x7fELF", path
    is64 = d[4] == 2
    if is64:
        shoff, = struct.unpack_from("<Q", d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3A)
        fmt = "<IIQQQQIIQQ"
    else:
        shoff, = struct.unpack_from("<I", d, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
        fmt = "<IIIIIIIIII"
    secs = [struct.unpack_from(fmt, d, shoff + i * shentsize) for i in range(shnum)]
    stroff = secs[shstrndx][4]

    def name(off, base):
        end = d.index(b"\0", base + off)
        return d[base + off:end].decode()

    names = [name(s[0], stroff) for s in secs]
    bad = [n for n in names if n in (".rel.text", ".rela.text")]
    assert not bad, "%s needs relocation (%s); fixtures must be self-contained" % (path, bad)
    ti = names.index(".text")
    text = d[secs[ti][4]:secs[ti][4] + secs[ti][5]]
    si = names.index(".symtab")
    symoff, symsize, link = secs[si][4], secs[si][5], secs[si][6]
    strbase = secs[link][4]
    syms = {}
    ent = 24 if is64 else 16
    for k in range(symsize // ent):
        o = symoff + k * ent
        if is64:
            st_name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", d, o)
        else:
            st_name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", d, o)
        if shndx == ti and st_name and (info & 0xF) in (0, 2):
            syms[name(st_name, strbase)] = value
    return text, syms


def _build(src, arch, out_dir):
    out = os.path.join(out_dir, "%s.%s.o" % (os.path.basename(src), arch))
    cmd = [CLANG, "-target", TARGETS[arch]]
    cmd += CFLAGS if src.endswith(".c") else ["-c"]
    subprocess.run(cmd + [os.path.join(FIX, src), "-o", out], check=True, capture_output=True)
    return _elf_text(out)


def write_image(path, arch, bits, filetype, segments, imports, thunks, base=0x400000, entry=0x401000):
    """segments: [(name, start, end, perm, extern, data or None)]"""
    os.makedirs(path, exist_ok=True)
    segs = []
    for n, (name, start, end, perm, extern, data) in enumerate(segments):
        rec = {"name": name, "start": hex(start), "end": hex(end), "perm": perm,
               "extern": extern, "file": None, "size": 0}
        if data:
            rec["file"] = "seg%d.bin" % n
            rec["size"] = len(data)
            with open(os.path.join(path, rec["file"]), "wb") as fh:
                fh.write(data)
        segs.append(rec)
    meta = {"format": 1, "file": "test.bin", "sha256": "", "arch": arch, "bits": bits,
            "endian": "little", "filetype": filetype, "base": hex(base), "entry": hex(entry),
            "segments": segs, "imports": {hex(k): v for k, v in imports.items()},
            "thunks": {hex(k): hex(v) for k, v in thunks.items()}, "bytes": 0}
    with open(os.path.join(path, "meta.json"), "w") as fh:
        json.dump(meta, fh)
    return path


class EmuImage:
    def __init__(self, path, syms):
        self.path, self.syms = path, syms
        self.image = Image(path)
        self.arch = for_image(self.image)

    def __getitem__(self, name):
        return hex(self.syms[name])

    def call(self, req):
        return handle(self.image, self.arch, req)


def _layout(arch, objs, sweep_slot):
    """Place each object's .text on its own page from 0x401000; return bytes and symbols."""
    code = bytearray()
    syms = {}
    for i, (text, s) in enumerate(objs):
        base = 0x1000 * i
        code[len(code):base] = b"\0" * (base - len(code))
        code[base:base + len(text)] = text
        for k, v in s.items():
            syms[k] = 0x401000 + base + v
    code[len(code):0x3000] = b"\0" * (0x3000 - len(code))
    thunks, imports = {}, {}
    for i, name in enumerate(SWEEP):
        slot = SWEEP_IAT + sweep_slot * i
        t = SWEEP_THUNKS + 8 * i
        rec = {"name": name, "module": "msvcrt" if name in CRT else "kernel32"}
        imports[slot] = rec
        thunks[t] = slot
        syms["thunk_" + name] = t
        if arch == "x86":
            stub = b"\xff\x25" + slot.to_bytes(4, "little") + b"\xcc\xcc"
        elif arch == "x64":
            stub = b"\xff\x25\x00\x00\x00\x00\xcc\xcc"
        else:
            stub = b"\x00\x00\x20\xd4" * 2
        off = t - 0x401000
        code[len(code):off] = b"\0" * (off - len(code))
        code[off:off + 8] = stub
    return bytes(code), syms, imports, thunks


@pytest.fixture(scope="session")
def build_dir(tmp_path_factory):
    if not os.path.exists(CLANG):
        pytest.skip("clang is needed to build the test images")
    return str(tmp_path_factory.mktemp("remu-images"))


@pytest.fixture(scope="session")
def x86img(build_dir):
    objs = [_build("common.c", "x86", build_dir), _build("x86only.c", "x86", build_dir),
            _build("x86.s", "x86", build_dir)]
    code, syms, imports, thunks = _layout("x86", objs, 4)
    imports.update({
        IAT + 0x00: {"name": "lstrlenA", "module": "kernel32", "nargs": 1, "purge": 4},
        IAT + 0x04: {"name": "GetProcessHeap", "module": "kernel32", "nargs": 0, "purge": 0},
        IAT + 0x08: {"name": "HeapAlloc", "module": "kernel32", "nargs": 3, "purge": 12},
        IAT + 0x0C: {"name": "memcpy", "module": "msvcrt", "nargs": 3, "purge": 0},
        IAT + 0x10: {"name": "MysteryStd", "module": "user32", "nargs": 2, "purge": 8},
        IAT + 0x14: {"name": "NoProto", "module": "foo"},
        IAT + 0x18: {"name": "MultiByteToWideChar", "module": "kernel32", "nargs": 6, "purge": 24},
        IAT + 0x1C: {"name": "GetTickCount", "module": "kernel32", "nargs": 0, "purge": 0},
        IAT + 0x20: {"name": "GetProcAddress", "module": "kernel32", "nargs": 2, "purge": 8},
        IAT + 0x24: {"name": "GetModuleHandleA", "module": "kernel32", "nargs": 1, "purge": 4},
        IAT + 0x28: {"name": "RaiseException", "module": "kernel32", "nargs": 4, "purge": 16},
    })
    thunks[syms["thunk_heapalloc"]] = IAT + 0x08
    data = bytearray(0x200)
    data[0:13] = b"kernel32.dll\0"
    data[0x10:0x1D] = b"GetTickCount\0"
    path = write_image(os.path.join(build_dir, "x86"), "x86", 32, "pe", [
        ("HEADER", 0x400000, 0x401000, "---", False, b"MZ"),
        (".text", 0x401000, 0x401000 + len(code), "r-x", False, code),
        (".idata", 0x405000, 0x405400, "rw-", True, None),
        (".data", 0x406000, 0x407000, "rw-", False, bytes(data)),
    ], imports, thunks)
    return EmuImage(path, syms)


@pytest.fixture(scope="session")
def x64img(build_dir):
    objs = [_build("common.c", "x64", build_dir), _build("x64only.c", "x64", build_dir),
            _build("x64.s", "x64", build_dir)]
    code, syms, imports, thunks = _layout("x64", objs, 8)
    imports.update({
        IAT + 0x00: {"name": "memset", "module": "msvcrt", "nargs": 3, "purge": 0},
        IAT + 0x08: {"name": "memcpy", "module": "msvcrt", "nargs": 3, "purge": 0},
    })
    thunks[syms["thunk_memcpy"]] = IAT + 0x08
    segs = [(".text", 0x401000, 0x401000 + len(code), "r-x", False, code),
            (".idata", 0x405000, 0x405400, "rw-", True, None)]
    path = write_image(os.path.join(build_dir, "x64"), "x64", 64, "pe", segs, imports, thunks)
    return EmuImage(path, syms)


@pytest.fixture(scope="session")
def x64elf(build_dir, x64img):
    meta = json.load(open(os.path.join(x64img.path, "meta.json")))
    path = os.path.join(build_dir, "x64elf")
    shutil.copytree(x64img.path, path)
    meta["filetype"] = "elf"
    json.dump(meta, open(os.path.join(path, "meta.json"), "w"))
    return EmuImage(path, x64img.syms)


@pytest.fixture(scope="session", params=["x86", "x64", "arm64"])
def tblimg(request, build_dir):
    """tables.c alone: .text at 0x401000 and a zeroed .data page at 0x406000
    that the functions use for their start-up tables (no imports)."""
    arch = request.param
    text, syms = _build("tables.c", arch, build_dir)
    syms = {k: 0x401000 + v for k, v in syms.items()}
    segs = [(".text", 0x401000, 0x401000 + len(text), "r-x", False, text),
            (".data", DATA, DATA + 0x1000, "rw-", False, None)]
    path = write_image(os.path.join(build_dir, "tables-" + arch), arch,
                       32 if arch == "x86" else 64, "elf", segs, {}, {})
    return EmuImage(path, syms)


@pytest.fixture(scope="session")
def a64img(build_dir):
    objs = [_build("common.c", "arm64", build_dir), _build("a64.s", "arm64", build_dir)]
    code, syms, imports, thunks = _layout("arm64", objs, 8)
    imports.update({
        IAT + 0x00: {"name": "memset", "module": "libc.so.6"},
        IAT + 0x08: {"name": "malloc", "module": "libc.so.6"},
        IAT + 0x10: {"name": "MockBoundary", "module": "mock", "nargs": 4},
    })
    thunks[syms["thunk_malloc"]] = IAT + 0x08
    segs = [(".text", 0x401000, 0x401000 + len(code), "r-x", False, code),
            ("extern", 0x405000, 0x405400, "r--", True, None)]
    path = write_image(os.path.join(build_dir, "arm64"), "arm64", 64, "elf", segs, imports, thunks)
    return EmuImage(path, syms)
