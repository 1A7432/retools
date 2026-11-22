"""Rendering bytes for humans and LLMs: printable views and string extraction."""

from __future__ import annotations

import re

_ASCII_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")
# Candidate UTF-16 text: code units that are not controls, surrogates, private use
# or specials. Exact printability is checked afterwards.
_WIDE_RUN = re.compile("[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-￰-￿]{2,}")
_PRINTABLE = bytes(range(0x20, 0x7f))


def printable(data):
    """One char per byte: printable ASCII as is, everything else '.'."""
    return "".join(chr(b) if b in _PRINTABLE else "." for b in data)


# Unicode blocks that real UTF-16 text is made of. Random binary data (pointers,
# return addresses) read two bytes at a time mostly lands in CJK extension A, Yi,
# private use and other rare blocks, so a whitelist keeps the noise out.
_TEXT_BLOCKS = (
    (0x0020, 0x007E), (0x00A0, 0x052F), (0x0590, 0x06FF), (0x0E00, 0x0E7F),
    (0x2000, 0x206F), (0x20A0, 0x20CF), (0x2100, 0x218F), (0x2190, 0x21FF),
    (0x2460, 0x24FF), (0x2500, 0x25FF), (0x3000, 0x312F), (0x4E00, 0x9FFF),
    (0xAC00, 0xD7A3), (0xFF00, 0xFFEF),
)


def _utf16_ok(ch):
    if ch in "\t\r\n":
        return True
    o = ord(ch)
    for lo, hi in _TEXT_BLOCKS:
        if lo <= o <= hi:
            return ch.isprintable()
    return False


def _both_ascii(ch):
    o = ord(ch)
    return 0x20 <= (o >> 8) < 0x7f and 0x20 <= (o & 0xFF) < 0x7f


def _script(o):
    if o < 0x250:
        return "latin"
    if 0x2000 <= o < 0x2600:
        return "symbol"
    if 0x3000 <= o <= 0x9FFF or 0xFF00 <= o <= 0xFFEF:
        return "cjk"
    if 0xAC00 <= o <= 0xD7A3:
        return "hangul"
    return o >> 8


def _binary_noise(run):
    """Wide runs that are really pointers or other binary data: Latin and wide
    chars alternating one by one (0x0040xxxx addresses give '@'), or mostly
    code units whose low byte is zero (ASCII UTF-16 read at an odd offset)."""
    if any(ord(c) >= 0x100 for c in run):
        # Real text uses one non-Latin script, with at least two letters of it.
        scripts = [_script(ord(c)) for c in run]
        letters = [x for x in scripts if x not in ("latin", "symbol")]
        latin = scripts.count("latin")
        if letters and (len(set(letters)) != 1 or (len(letters) < 2 and latin < 3)):
            return True
        kinds = [ord(c) < 0x100 for c in run]
        changes = sum(1 for a, b in zip(kinds, kinds[1:]) if a != b)
        if len(run) >= 3 and changes >= len(run) - 1:
            return True
        if sum(1 for c in run if ord(c) >= 0x100 and ord(c) & 0xFF == 0) * 2 > len(run):
            return True
    return False


def _ascii_misread(run):
    """True when a "wide" run is really plain ASCII text read two bytes at a time:
    its wide code units then have two printable ASCII bytes each (real CJK text
    rarely does), and Latin chars (NUL high byte) are a minority."""
    wide = [c for c in run if ord(c) >= 0x100]
    if not wide or 2 * (len(run) - len(wide)) >= len(run):
        return False
    return sum(map(_both_ascii, wide)) > 0.6 * len(wide)


def _utf16_runs(data, minlen):
    out = []
    for parity in (0, 1):
        chunk = data[parity: parity + ((len(data) - parity) & ~1)]
        text = chunk.decode("utf-16le", errors="replace")
        for m in _WIDE_RUN.finditer(text):
            run = m.group()
            if not all(_utf16_ok(c) for c in run):
                continue
            # Pure Latin-1 runs need the full minimum length; runs with wide chars
            # (CJK etc.) carry more information per char and may be shorter.
            need = minlen if all(ord(c) < 0x100 for c in run) else max(2, minlen - 2)
            if len(run) >= need and not _ascii_misread(run) and not _binary_noise(run):
                out.append((parity + 2 * m.start(), run))
    return out


def _pointer_soup(data, off, run, is_ptr):
    """True when the aligned dwords under a wide run are mostly valid pointers:
    saved return addresses and frame pointers read as UTF-16 look like CJK text."""
    lo, hi = off & ~3, off + 2 * len(run)
    words = [int.from_bytes(data[k:k + 4], "little") for k in range(lo, hi - 3, 4)]
    # Only dwords holding a non-Latin unit matter: Latin UTF-16 pairs (0x00XX00YY)
    # often fall inside a low image base and would look like pointers too.
    words = [w for w in words if (w & 0xFF00) or (w & 0xFF000000)]
    return bool(words) and 2 * sum(1 for w in words if is_ptr(w)) >= len(words)


def find_strings(data, minlen=4, is_ptr=None):
    """[(offset, kind, text)] for ASCII ("a") and UTF-16LE ("w") strings, by offset.
    is_ptr(value), when given, filters wide runs made of pointers (data must then
    start 4-byte aligned)."""
    wide = [(off, "w", run) for off, run in _utf16_runs(data, minlen)
            if is_ptr is None or all(ord(c) < 0x100 for c in run)
            or not _pointer_soup(data, off, run, is_ptr)]
    spans = [(off, off + 2 * len(run)) for off, _, run in wide]
    # ASCII-looking bytes inside UTF-16 text (CJK code units) are not strings
    found = [(m.start(), "a", m.group().decode("ascii"))
             for m in _ASCII_RUN.finditer(data)
             if len(m.group()) >= minlen
             and not any(a <= m.start() and m.end() <= b for a, b in spans)]
    found += wide
    found.sort()
    return found


def wide_prefix(data):
    """The UTF-16LE string at the start of data (up to NUL) if it looks like text."""
    n = len(data) & ~1
    text = data[:n].decode("utf-16le", errors="replace")
    end = text.find("\x00")
    if end <= 0:
        return None
    s = text[:end]
    if not all(_utf16_ok(c) for c in s) or _ascii_misread(s) or _binary_noise(s):
        return None
    if len(s) < 2 and ord(s[0]) >= 0x100:
        return None
    return s


def c_prefix(data):
    """The NUL-terminated byte string at the start of data if it is printable text."""
    nul = data.find(b"\x00")
    head = data if nul < 0 else data[:nul]
    if not head:
        return None
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in head):
        return head.decode("ascii")
    try:
        s = head.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if all(c.isprintable() or c in "\t\r\n" for c in s) else None


def render(data):
    """The most useful readable views of a byte string."""
    out = {"text": printable(data)}
    s = c_prefix(data)
    if s and len(s) >= 2 and (data.find(b"\x00") >= 0 or len(s) == len(data)):
        if s != out["text"]:
            out["cstr"] = s
    w = wide_prefix(data)
    if w:
        out["wstr"] = w
    return out


def guess_string(data):
    """('a'|'w', text) if data starts with something that reads as a string."""
    w = wide_prefix(data)
    if w and len(w) >= 2:
        return "w", w
    s = c_prefix(data)
    if s and len(s) >= 3 and data.find(b"\x00") >= 0:
        return "a", s
    return None


def clip(s, n):
    if len(s) <= n:
        return s
    return "%s...[+%d chars]" % (s[:n], len(s) - n)
