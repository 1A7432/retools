"""Value specs: turning request JSON into integers and memory blocks.

A value spec is one of
    5, "0x401000", "-1"                    an integer
    {"int": v}                             the same, explicit
    {"ref": "name+0x10"}                   address of a named block (or builtin) + offset
    {"bytes": "hex", "size": N}            buffer with these bytes (zero-padded to size)
    {"str": "text", "enc": "utf-8"}        NUL-terminated byte string
    {"wstr": "text"}                       NUL-terminated UTF-16LE string
    {"out": N, "fill": "00"}               N-byte output buffer
    {"dstr": "text"} / {"dastr": "text"}   Delphi UnicodeString / AnsiString (pointer to chars)
    {"struct": [items]}                    a laid-out structure (see struct items below)
Pointer-producing specs take optional "name" (for refs and the reply) and
"addr" (place it at that address instead of the auto-allocated args region).

Struct items (inline fields, laid out in order):
    {"u8"|"u16"|"u32"|"u64"|"i8"|"i16"|"i32"|"i64": value spec}
    {"ptr": value spec}  (pointer-sized; a nested pointer spec is allocated separately)
    {"f32": x} {"f64": x}
    {"bytes": hex} {"str": s} {"wstr": s}   inline data, not a pointer
    {"zero": n} {"align": n}
    a bare integer = pointer-sized field
"""

from __future__ import annotations

import re
import struct as _struct

from .errors import RemuError
from .image import parse_int

POINTER_KINDS = ("bytes", "hex", "str", "wstr", "out", "dstr", "dastr", "struct")
INT_FIELDS = {"u8": (1, False), "u16": (2, False), "u32": (4, False), "u64": (8, False),
              "i8": (1, True), "i16": (2, True), "i32": (4, True), "i64": (8, True)}
_REF = re.compile(r"^\s*([A-Za-z_][\w.\[\]]*)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*$")


def codec_for_cp(cp):
    if cp in (65001, "utf-8", "utf8"):
        return "utf-8"
    if cp in (1200,):
        return "utf-16le"
    return "cp%d" % int(cp)


def _hex(s, what):
    try:
        return bytes.fromhex(s.replace(" ", ""))
    except (ValueError, AttributeError):
        raise RemuError("%s: %r is not a hex byte string" % (what, s),
                        'write bytes as "de ad be ef" or "deadbeef"')


def pointer_kind(spec):
    if isinstance(spec, dict):
        for k in POINTER_KINDS:
            if k in spec:
                return k
    return None


class Block:
    __slots__ = ("name", "addr", "size", "ptr", "spec", "kind", "initial", "origin")

    def __init__(self, name, spec, kind, origin=None):
        self.name, self.spec, self.kind = name, spec, kind
        self.addr = self.size = self.ptr = 0
        self.initial = b""
        self.origin = origin      # index of the init call that made it, None for the main call


class Builder:
    def __init__(self, emu):
        self.emu = emu
        self.word = emu.arch.word
        self.blocks = []
        self.names = {}
        self._planned = {}
        self._filled = 0
        self.origin = None        # set per call by the emulator

    # ---- phase 1: sizes and addresses -----------------------------------

    def plan(self, spec, name):
        kind = pointer_kind(spec)
        if kind is None:
            return None
        if id(spec) in self._planned:
            return self._planned[id(spec)]
        if "name" in spec:
            name = str(spec["name"])
            if name in self.names or name in self.emu.builtin_refs():
                raise RemuError("block name %r is used twice" % name, "give each block its own name")
        blk = Block(name, spec, kind, self.origin)
        self._planned[id(spec)] = blk
        size, ptr_off = self._measure(spec, kind, name)
        blk.size = size
        if "addr" in spec:
            blk.addr = parse_int(spec["addr"], "%s.addr" % name)
            if not self.emu.is_mapped(blk.addr, size):
                lo, hi = self.emu.layout["scratch"]
                raise RemuError("%s: %#x..%#x is not mapped memory" % (name, blk.addr, blk.addr + size),
                                "place blocks in the scratch region %#x..%#x, inside an image "
                                "segment, or omit addr to auto-allocate" % (lo, hi))
        else:
            align = int(spec.get("align", 16))
            blk.addr = self.emu.args_alloc(size, align)
        blk.ptr = blk.addr + ptr_off
        self.names[name] = blk
        self.blocks.append(blk)
        return blk

    def _measure(self, spec, kind, name):
        """(size in bytes, offset of the pointer value within the block)."""
        if kind in ("bytes", "hex"):
            n = len(_hex(spec[kind], name))
        elif kind == "str":
            n = len(self._encode(spec, name)) + 1
        elif kind == "wstr":
            n = len(str(spec["wstr"]).encode("utf-16le")) + 2
        elif kind == "out":
            n = parse_int(spec["out"], "%s.out" % name)
        elif kind in ("dstr", "dastr"):
            body = self._delphi_body(spec, kind)
            hdr = self._delphi_hdr_size()
            return hdr + len(body) + (2 if kind == "dstr" else 1), hdr
        else:
            n = self._struct_size(spec["struct"], name)
        if "size" in spec:
            want = parse_int(spec["size"], "%s.size" % name)
            if want < n and kind != "struct":
                raise RemuError("%s: size %d is smaller than its contents (%d bytes)" % (name, want, n))
            n = max(n, want)
        if n < 0 or n > 64 << 20:
            raise RemuError("%s: size %d is out of range" % (name, n), "buffers are limited to 64 MB")
        return n, 0

    def _encode(self, spec, name):
        enc = spec.get("enc", "utf-8")
        try:
            return str(spec["str"]).encode(enc)
        except (LookupError, UnicodeEncodeError) as exc:
            raise RemuError("%s: cannot encode with %r: %s" % (name, enc, exc))

    def _delphi_hdr_size(self):
        return 16 if self.word == 8 else 12

    def _delphi_body(self, spec, kind):
        text = str(spec[kind])
        if kind == "dstr":
            return text.encode("utf-16le")
        return text.encode(codec_for_cp(spec.get("cp", self.emu.acp)), errors="replace")

    def _struct_size(self, items, name):
        if not isinstance(items, list):
            raise RemuError("%s: struct must be a list of fields" % name)
        off = 0
        for item in items:
            off = self._item(item, off, "%s+%#x" % (name, off), None)
        return off

    def _item(self, item, off, where, out):
        """Lay out one struct field at off; write it into out (bytearray) when given.
        Returns the offset after the field."""
        if isinstance(item, (int, str)) and not isinstance(item, bool):
            item = {"ptr": item}
        if not isinstance(item, dict) or len(item) != 1:
            raise RemuError("%s: struct field must be one {type: value} pair, got %r" % (where, item),
                            'e.g. {"u32": 5}, {"ptr": {"str": "x"}}, {"bytes": "00ff"}')
        (key, val), = item.items()
        if key in INT_FIELDS or key in ("ptr", "word"):
            size, signed = INT_FIELDS.get(key, (self.word, False))
            if pointer_kind(val):
                self.plan(val, where)
            if out is not None:
                v = self.scalar(val, where)
                out[off:off + size] = (v & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
            return off + size
        if key in ("f32", "f64"):
            size = 4 if key == "f32" else 8
            if out is not None:
                out[off:off + size] = _struct.pack("<f" if size == 4 else "<d", float(val))
            return off + size
        if key in ("bytes", "hex", "str", "wstr"):
            if key in ("bytes", "hex"):
                data = _hex(val, where)
            elif key == "str":
                data = str(val).encode("utf-8") + b"\0"
            else:
                data = str(val).encode("utf-16le") + b"\0\0"
            if out is not None:
                out[off:off + len(data)] = data
            return off + len(data)
        if key == "zero":
            return off + parse_int(val, where)
        if key == "align":
            a = parse_int(val, where)
            return (off + a - 1) // a * a if a > 0 else off
        raise RemuError("%s: unknown struct field type %r" % (where, key),
                        "use u8..u64, i8..i64, ptr, f32, f64, bytes, str, wstr, zero, align")

    # ---- phase 2: values and contents --------------------------------------

    def scalar(self, spec, what):
        if isinstance(spec, bool):
            return int(spec)
        if isinstance(spec, (int, str)):
            try:
                return parse_int(spec, what)
            except RemuError:
                raise RemuError("%s: %r is not a number" % (what, spec),
                                'pass text as {"str": ...} or {"wstr": ...}; refer to a named '
                                'block as {"ref": "name+0x10"}')
        if isinstance(spec, dict):
            if pointer_kind(spec):
                blk = self.plan(spec, what)
                return blk.ptr
            if "ref" in spec:
                return self.resolve(spec["ref"], what)
            if "int" in spec:
                return parse_int(spec["int"], what)
        raise RemuError("%s: cannot use %r as a value" % (what, spec),
                        "a value is an int, a hex string, a ref or a buffer spec")

    def resolve(self, ref, what):
        m = _REF.match(str(ref))
        if not m:
            raise RemuError("%s: bad ref %r" % (what, ref), 'write refs as "name", "name+0x10" or "name-4"')
        name, sign, off = m.groups()
        builtins = self.emu.builtin_refs()
        if name in self.names:
            base = self.names[name].ptr
        elif name in builtins:
            base = builtins[name]
        else:
            known = sorted(self.names) + sorted(builtins)
            raise RemuError("%s: no block named %r" % (what, name),
                            "known names: %s" % ", ".join(known[:30]))
        delta = int(off, 0) if off else 0
        return base - delta if sign == "-" else base + delta

    def fill(self):
        """Write the blocks planned since the last fill; earlier ones (from init
        calls) keep whatever those calls left in them."""
        for blk in self.blocks[self._filled:]:
            data = self._contents(blk)
            blk.initial = bytes(data)
            self.emu.uc.mem_write(blk.addr, blk.initial)
        self._filled = len(self.blocks)

    def _contents(self, blk):
        spec, kind, size = blk.spec, blk.kind, blk.size
        out = bytearray(size)
        if kind in ("bytes", "hex"):
            data = _hex(spec[kind], blk.name)
            out[:len(data)] = data
        elif kind == "str":
            data = self._encode(spec, blk.name)
            out[:len(data)] = data
        elif kind == "wstr":
            data = str(spec["wstr"]).encode("utf-16le")
            out[:len(data)] = data
        elif kind == "out":
            fill = _hex(spec.get("fill", "00"), blk.name) or b"\0"
            out[:] = (fill * (size // len(fill) + 1))[:size]
        elif kind in ("dstr", "dastr"):
            body = self._delphi_body(spec, kind)
            hdr = self._delphi_hdr_size()
            wide = kind == "dstr"
            cp = 1200 if wide else int(spec.get("cp", self.emu.acp))
            pad = b"\0\0\0\0" if hdr == 16 else b""
            nchars = len(body) // 2 if wide else len(body)
            # codePage, elemSize, refCnt = -1 (a constant: the RTL never frees it), length
            out[:hdr] = pad + _struct.pack("<HHiI", cp, 2 if wide else 1, -1, nchars)
            out[hdr:hdr + len(body)] = body
        else:
            off = 0
            for item in spec["struct"]:
                off = self._item(item, off, "%s+%#x" % (blk.name, off), out)
        return out
