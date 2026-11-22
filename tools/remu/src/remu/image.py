"""Loading a format-1 image directory (meta.json + seg<N>.bin)."""

from __future__ import annotations

import json
import os

from .errors import RemuError

PAGE = 0x1000
SUPPORTED = {("x86", 32), ("x64", 64), ("arm64", 64)}


def page_down(x):
    return x & ~(PAGE - 1)


def page_up(x):
    return (x + PAGE - 1) & ~(PAGE - 1)


def parse_int(v, what="value"):
    if isinstance(v, bool):
        raise RemuError("%s: expected an integer, got a boolean" % what)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip().replace("_", ""), 0)
        except ValueError:
            pass
    raise RemuError("%s: expected an integer or a hex string, got %r" % (what, v),
                    'write addresses as "0x401000" and numbers as ints or hex strings')


class Segment:
    __slots__ = ("name", "start", "end", "perm", "extern", "file", "size", "data")

    def __init__(self, rec, root):
        self.name = rec.get("name") or "?"
        self.start = parse_int(rec["start"], "segment start")
        self.end = parse_int(rec["end"], "segment end")
        self.perm = rec.get("perm") or "rwx"
        self.extern = bool(rec.get("extern"))
        self.file = rec.get("file")
        self.size = int(rec.get("size") or 0)
        self.data = b""
        if self.file:
            path = os.path.join(root, os.path.basename(self.file))
            try:
                with open(path, "rb") as fh:
                    self.data = fh.read()
            except OSError as exc:
                raise RemuError("cannot read %s: %s" % (path, exc.strerror),
                                "re-export the image (rekit emulation with refresh=True)")
        # Never let initialised bytes spill past the segment end.
        if len(self.data) > self.end - self.start:
            self.data = self.data[: self.end - self.start]


class Image:
    def __init__(self, root):
        self.root = root
        meta_path = os.path.join(root, "meta.json")
        try:
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
        except FileNotFoundError:
            raise RemuError("no meta.json in %s" % root,
                            "pass the image directory written by rekit's exporter")
        except (OSError, ValueError) as exc:
            raise RemuError("cannot load %s: %s" % (meta_path, exc))
        if meta.get("format") != 1:
            raise RemuError("unsupported image format %r" % meta.get("format"),
                            "this remu understands format 1 only")
        self.meta = meta
        self.arch = meta.get("arch")
        self.bits = int(meta.get("bits") or 0)
        self.endian = meta.get("endian", "little")
        self.filetype = meta.get("filetype", "other")
        if (self.arch, self.bits) not in SUPPORTED or self.endian != "little":
            raise RemuError(
                "unsupported architecture %s/%s-bit/%s-endian" % (self.arch, self.bits, self.endian),
                "remu emulates little-endian x86, x64 and arm64 only")
        self.base = parse_int(meta.get("base", "0"), "base")
        self.entry = parse_int(meta.get("entry", "0"), "entry")
        self.segments = sorted((Segment(s, root) for s in meta.get("segments", [])),
                               key=lambda s: s.start)
        self.imports = {}
        for k, v in (meta.get("imports") or {}).items():
            self.imports[parse_int(k, "import address")] = v
        self.thunks = {}
        for k, v in (meta.get("thunks") or {}).items():
            self.thunks[parse_int(k, "thunk address")] = parse_int(v, "thunk target")
        self.regions = self._regions()

    def _regions(self):
        """Merge the page ranges covering all segments into mappable regions."""
        spans = sorted((page_down(s.start), page_up(s.end)) for s in self.segments if s.end > s.start)
        out = []
        for a, b in spans:
            if out and a <= out[-1][1]:
                out[-1][1] = max(out[-1][1], b)
            else:
                out.append([a, b])
        return [(a, b) for a, b in out]

    def segment_at(self, addr):
        for s in self.segments:
            if s.start <= addr < s.end:
                return s
        return None

    def label(self, addr):
        s = self.segment_at(addr)
        if s is None:
            return None
        return "%s+%#x" % (s.name, addr - s.start)
