"""Minimal, defensive ELF header reader for `rebox live` (stdlib only).

Reads only the ELF header, program headers and, for the Go/stripped hints, the
section header string table, all with bounds checks. Never trusts a size or
offset from the file without checking it against the file length.
"""

from __future__ import annotations

import struct
from pathlib import Path

EM = {3: "x86", 62: "x86_64", 183: "aarch64", 40: "arm", 8: "mips", 20: "ppc", 21: "ppc64", 243: "riscv",
      22: "s390", 2: "sparc", 43: "sparcv9", 42: "sh", 4: "m68k", 258: "loongarch"}
ET = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}
PT_INTERP, PT_DYNAMIC = 3, 2

# arch -> (mode, qemu binary). Only these three are supported (owner's scope).
SUPPORTED = {
    ("aarch64", 64, "le"): ("native", None),
    ("x86_64", 64, "le"): ("qemu", "qemu-x86_64"),
    ("x86", 32, "le"): ("qemu", "qemu-i386"),
}


class NotElf(ValueError):
    pass


def parse(path: Path, max_read: int = 64 << 20) -> dict:
    with open(path, "rb") as f:
        data = f.read(max_read)
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise NotElf("not an ELF file")
    cls = {1: 32, 2: 64}.get(data[4])
    endian = {1: "le", 2: "be"}.get(data[5])
    if cls is None or endian is None:
        raise NotElf(f"bad ELF class/data bytes {data[4]}/{data[5]}")
    e = "<" if endian == "le" else ">"
    if cls == 64:
        if len(data) < 64:
            raise NotElf("truncated ELF64 header")
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
    info = {
        "class": cls,
        "endian": endian,
        "machine": e_machine,
        "arch": EM.get(e_machine, f"em_{e_machine}"),
        "elf_type": ET.get(e_type, f"type_{e_type}"),
        "entry": hex(e_entry),
        "osabi": data[7],
        "interp": None,
        "linkage": "static",
        "pie": False,
        "go": False,
        "sections": None,
        "stripped": None,
        "notes": [],
    }
    has_dynamic = False
    ph_size = 56 if cls == 64 else 32
    if e_phnum and e_phentsize >= ph_size and e_phnum < 4096:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + ph_size > len(data):
                info["notes"].append("program headers extend past the file")
                break
            if cls == 64:
                p_type, _pf, p_offset, _va, _pa, p_filesz = struct.unpack_from(e + "IIQQQQ", data, off)
            else:
                p_type, p_offset, _va, _pa, p_filesz = struct.unpack_from(e + "IIIII", data, off)
            if p_type == PT_INTERP and 0 < p_filesz < 4096 and p_offset + p_filesz <= len(data):
                raw = data[p_offset:p_offset + p_filesz].split(b"\0", 1)[0]
                info["interp"] = raw.decode("latin-1")
            elif p_type == PT_DYNAMIC:
                has_dynamic = True
    if info["interp"]:
        info["linkage"] = "dynamic"
    elif has_dynamic and e_type == 3:
        info["linkage"] = "static-pie"
    info["pie"] = e_type == 3
    names = _section_names(data, e, cls, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    if names is not None:
        info["sections"] = len(names)
        info["stripped"] = ".symtab" not in names
        info["go"] = any(n in names for n in (".go.buildinfo", ".gopclntab", ".note.go.buildid"))
    if not info["go"] and b"\xff Go buildinf:" in data:
        info["go"] = True
    return info


def _section_names(data, e, cls, shoff, shentsize, shnum, shstrndx) -> list[str] | None:
    sh_size = 64 if cls == 64 else 40
    if not shoff or shentsize < sh_size or not (0 < shnum < 65280) or shstrndx >= shnum:
        return None
    if shoff + shnum * shentsize > len(data):
        return None

    def sh(i):
        off = shoff + i * shentsize
        if cls == 64:
            name, _t, _fl, _a, offset, size = struct.unpack_from(e + "IIQQQQ", data, off)
        else:
            name, _t, _fl, _a, offset, size = struct.unpack_from(e + "IIIIII", data, off)
        return name, offset, size

    _n, str_off, str_size = sh(shstrndx)
    if str_off + str_size > len(data):
        return None
    table = data[str_off:str_off + str_size]
    names = []
    for i in range(shnum):
        n, _o, _s = sh(i)
        if n < len(table):
            names.append(table[n:table.find(b"\0", n) if b"\0" in table[n:] else len(table)].decode("latin-1"))
    return names


def support(info: dict) -> tuple[str, str | None] | None:
    return SUPPORTED.get((info["arch"], info["class"], info["endian"]))
