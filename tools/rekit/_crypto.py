"""rekit crypto matcher: find known cryptographic tables and constants in an IDA
database and report exactly where a near copy deviates from the standard.

    _crypto.scan(ea=None, init=None, max_chars=6000, timeout=60) -> dict

The reference data (_crypto_refs.json, written by _crypto_gen.py) is computed
from the definitions and cross-checked against libraries at build time; this
module only reads it, with the standard library.

Layout
  * core (no IDA): reference loading, scan_bytes() over a byte range,
    match_immediates() over per-function immediate lists, alphabets.
    test_crypto.py exercises it with plain python3.
  * adapter (IDA, imported lazily): reads segments, immediates and
    cross-references, runs the set-up functions in remu and scans the memory
    they left behind, then ranks everything into one compact reply.

Storage forms reported in "form"
  bytes        byte table as stored
  bytes>u32    byte table widened to little-endian 32-bit words
  u32le/u32be  32-bit word table, little/big-endian
  u64le/u64be  64-bit word table, little/big-endian
  u64hi.lo     64-bit words stored as (high, low) little-endian 32-bit pairs
  be / le      big number as big-endian / little-endian bytes ("le" is also
               the little-endian 32- and 64-bit limb array, least significant
               limb first)
  u32msl/u64msl  big number as 32/64-bit native words, most significant first
"""

from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
REFS_PATH = os.path.join(HERE, "_crypto_refs.json")
BUDGET = 6000
NATIVE = sys.byteorder

# A near match needs this share of elements equal and this much matched
# "information" (distinct non-zero bytes per element; 1 per byte-table entry).
NEAR_RATIO = 0.75
NEAR_INFO = 24
PARTIAL_INFO = 32
MAX_POS_PER_KEY = 2000
MAX_ANCHORS = 24
SCOPE_DEPTH = 3          # a function scan follows direct calls this many levels
SCOPE_CAP = 40           # and covers at most this many functions


# =============================================================================
# reference database
# =============================================================================

class Ref:
    """One reference item: a table, a big number, a string or an alphabet."""
    __slots__ = ("id", "name", "algo", "kind", "elem", "values", "extra")

    def __init__(self, id_, name, algo, kind, elem, values, extra=None):
        self.id, self.name, self.algo, self.kind = id_, name, algo, kind
        self.elem, self.values, self.extra = elem, values, extra or {}


class Pattern:
    """A reference in one storage form: the exact bytes and how to read them."""
    __slots__ = ("ref", "form", "data", "esize", "n", "info", "anchors", "exact_only")

    def __init__(self, ref, form, data, esize):
        self.ref, self.form, self.data, self.esize = ref, form, data, esize
        self.n = len(data) // esize
        self.info = [_info(data[i * esize:(i + 1) * esize]) for i in range(self.n)]
        self.anchors = []
        self.exact_only = False


def _info(chunk):
    if len(chunk) == 1:
        return 1 if chunk[0] else 0.5
    return len(set(chunk) - {0})


class DB:
    def __init__(self, doc):
        self.refs, self.patterns, self.scalars = [], [], []
        self.alphabets, self.strings = doc.get("alphabets", []), []
        for t in doc["tables"]:
            self.refs.append(Ref(t["id"], t["name"], t["algo"], "table", t["elem"], t["values"]))
        for b in doc["bignums"]:
            v = int(b["value"], 16)
            self.refs.append(Ref(b["id"], b["name"], b["algo"], "bignum", b["bytes"], v,
                                 {"curve": b["curve"], "param": b["param"]}))
        for st in doc["strings"]:
            if not st.get("dup_of"):     # sigma/tau are matched as word tables
                self.refs.append(Ref(st["id"], st["name"], st["algo"], "string", 1, st["text"].encode()))
        self.scalars = [dict(s) for s in doc["scalars"]]
        for ref in self.refs:
            self.patterns.extend(_forms(ref))
        self.k4, self.k8, self.exact = {}, {}, []
        for pi, pat in enumerate(self.patterns):
            _anchor(pat)
            if not pat.anchors:
                pat.exact_only = True
                self.exact.append(pi)
            for off, size in pat.anchors:
                key = int.from_bytes(pat.data[off:off + size], NATIVE)
                (self.k4 if size == 4 else self.k8).setdefault(key, []).append((pi, off))
        self._imm_index()

    # -- immediates: value -> [(ref, index)], scalar values -> scalar
    def _imm_index(self):
        self.imm_tables = []        # (ref, values as ints of width, width)
        for ref in self.refs:
            if ref.kind == "table" and ref.elem in (4, 8) and len(ref.values) >= 2:
                self.imm_tables.append((ref, list(ref.values), ref.elem, "words"))
            elif ref.kind == "table" and ref.elem == 1 and len(ref.values) >= 16:
                raw = bytes(ref.values)
                self.imm_tables.append((ref, [int.from_bytes(raw[i:i + 4], "little")
                                              for i in range(0, len(raw) - 3, 4)], 4, "u32 chunks"))
            elif ref.kind == "bignum" and _bignum_matchable(ref.values):
                raw = ref.values.to_bytes(32, "big")
                self.imm_tables.append((ref, [int.from_bytes(raw[i:i + 8], "big")
                                              for i in range(0, 32, 8)], 8, "u64 limbs, most significant first"))
                self.imm_tables.append((ref, [int.from_bytes(raw[i:i + 4], "big")
                                              for i in range(0, 32, 4)], 4, "u32 limbs, most significant first"))
            elif ref.kind == "string" and len(ref.values) % 4 == 0:
                pass        # sigma/tau words are tables already
        self.known = {}             # value -> list of (label)
        for ti, (ref, vals, w, how) in enumerate(self.imm_tables):
            for i, v in enumerate(vals):
                if _good_imm(v, w):
                    self.known.setdefault(v, []).append((ti, i))
        self.scalar_vals = {}
        for s in self.scalars:
            if _good_imm(s["value"], s["width"]):
                self.scalar_vals.setdefault(s["value"], []).append(s)


def _bignum_matchable(v):
    raw = v.to_bytes(32, "big")
    return sum(1 for b in raw if b) >= 16


def _forms(ref):
    out = []
    if ref.kind == "table":
        vals, e = ref.values, ref.elem
        if e == 1:
            out.append(Pattern(ref, "bytes", bytes(vals), 1))
            if len(vals) >= 64:
                out.append(Pattern(ref, "bytes>u32", b"".join(v.to_bytes(4, "little") for v in vals), 4))
        elif e == 4:
            out.append(Pattern(ref, "u32le", b"".join(v.to_bytes(4, "little") for v in vals), 4))
            out.append(Pattern(ref, "u32be", b"".join(v.to_bytes(4, "big") for v in vals), 4))
        elif e == 8:
            out.append(Pattern(ref, "u64le", b"".join(v.to_bytes(8, "little") for v in vals), 8))
            out.append(Pattern(ref, "u64be", b"".join(v.to_bytes(8, "big") for v in vals), 8))
            out.append(Pattern(ref, "u64hi.lo", b"".join((v >> 32).to_bytes(4, "little")
                                                         + (v & 0xFFFFFFFF).to_bytes(4, "little")
                                                         for v in vals), 8))
    elif ref.kind == "bignum":
        if not _bignum_matchable(ref.values):
            return out
        be = ref.values.to_bytes(32, "big")
        out.append(Pattern(ref, "be", be, 1))
        out.append(Pattern(ref, "le", be[::-1], 1))
        out.append(Pattern(ref, "u32msl", b"".join(be[i:i + 4][::-1] for i in range(0, 32, 4)), 4))
        out.append(Pattern(ref, "u64msl", b"".join(be[i:i + 8][::-1] for i in range(0, 32, 8)), 8))
    elif ref.kind == "string":
        out.append(Pattern(ref, "bytes", ref.values, 1))
    return out


def _good_window(w):
    if len(w) == 4:
        return len(set(w)) >= 3
    return len(set(w)) >= 5


def _anchor(pat):
    """Pick up to MAX_ANCHORS distinctive windows spread over the pattern."""
    d, L = pat.data, len(pat.data)
    cands = []
    if pat.form == "bytes>u32":
        # two widened entries per window: s0 0 0 0 s1 0 0 0
        for off in range(0, L - 7, 4):
            w = d[off:off + 8]
            if w[0] and w[4] and w[0] != w[4]:
                cands.append((off, 8))
    else:
        size = 8 if pat.esize == 8 else 4
        step = pat.esize if pat.esize > 1 else 4
        for off in range(0, L - size + 1, step):
            if _good_window(d[off:off + size]):
                cands.append((off, size))
        if not cands and size == 4 and pat.esize == 1:
            for off in range(0, L - 3):
                if _good_window(d[off:off + 4]):
                    cands.append((off, 4))
    seen, uniq = set(), []
    for off, size in cands:
        w = d[off:off + size]
        if w not in seen:
            seen.add(w)
            uniq.append((off, size))
    if len(uniq) > MAX_ANCHORS:
        step = len(uniq) / MAX_ANCHORS
        uniq = [uniq[int(i * step)] for i in range(MAX_ANCHORS)]
    pat.anchors = uniq


_DB = None


def db():
    global _DB
    if _DB is None:
        with open(REFS_PATH, encoding="utf-8") as fh:
            _DB = DB(json.load(fh))
    return _DB


# =============================================================================
# byte-range matching
# =============================================================================

def _present(buf, keys, size):
    """Keys of the given width occurring at any byte offset of buf."""
    found = set()
    if not keys or len(buf) < size:
        return found
    mv = memoryview(buf)
    fmt = "I" if size == 4 else "Q"
    for k in range(size):
        n = (len(buf) - k) // size
        if n <= 0:
            continue
        found |= keys.intersection(mv[k:k + n * size].cast(fmt))
    return found


def _positions(buf, needle, cap=MAX_POS_PER_KEY):
    out, i = [], buf.find(needle)
    while i >= 0 and len(out) < cap:
        out.append(i)
        i = buf.find(needle, i + 1)
    return out


def _fmt(v, e):
    return "0x%0*x" % (2 * e, v)


def _nibbles(a, b):
    x, n = a ^ b, 0
    while x:
        n += 1 if x & 0xF else 0
        x >>= 4
    return n


def _classify(pat, win):
    """Compare pattern and window element by element; None if too weak."""
    e, n = pat.esize, pat.n
    avail = len(win) // e
    ok = [False] * n
    data = pat.data
    for i in range(min(n, avail)):
        if data[i * e:(i + 1) * e] == win[i * e:(i + 1) * e]:
            ok[i] = True
    m = sum(ok)
    if m == n:
        if sum(pat.info) < 8:
            return None
        return {"status": "exact", "m": m, "lo": 0, "hi": n, "diff": []}
    info = sum(pat.info[i] for i in range(n) if ok[i])
    # densest stretch: +1 per match, -4 per mismatch
    best, cur, cs, lo, hi = 0, 0, 0, 0, 0
    for i in range(n):
        cur += 1 if ok[i] else -4
        if cur <= 0:
            cur, cs = 0, i + 1
        elif cur > best:
            best, lo, hi = cur, cs, i + 1
    tail = n - hi
    head = lo
    full = m >= NEAR_RATIO * n and info >= NEAR_INFO and avail >= n
    # a clean cut (all wrong after the stretch, more than a couple of entries)
    # reads as a truncated copy, not as edits
    cut = max(2, n // 8)
    trunc = (avail < n) or ((tail > cut or head > cut) and
                            not any(ok[:lo]) and not any(ok[hi:]))
    if full and not trunc:
        diff = [i for i in range(n) if not ok[i]]
        return {"status": "near", "m": m, "lo": 0, "hi": n, "diff": diff}
    rinfo = sum(pat.info[i] for i in range(lo, hi) if ok[i])
    if hi - lo >= 4 and rinfo >= PARTIAL_INFO and pat.ref.kind == "table":
        inside = sum(ok[lo:hi])
        if inside >= 0.9 * (hi - lo):
            diff = [i for i in range(lo, hi) if not ok[i]]
            return {"status": "partial", "m": inside, "lo": lo, "hi": hi, "diff": diff}
    return None


def scan_bytes(buf, base=0, refs=None, region=""):
    """All table/bignum/string hits in buf (bytes); addresses are base-relative.

    Returns a list of hit dicts:
      {"ref", "name", "algo", "form", "addr", "end", "status", "match",
       "diff": [{"i", "found", "std"}], "lo", "hi", "n", "region"}
    """
    D = refs or db()
    buf = bytes(buf)
    cands = set()
    for keys, size in ((D.k4, 4), (D.k8, 8)):
        for key in _present(buf, set(keys), size):
            needle = key.to_bytes(size, NATIVE)
            pos = _positions(buf, needle)
            for pi, off in keys[key]:
                for p in pos:
                    s = p - off
                    if s >= -len(D.patterns[pi].data):
                        cands.add((pi, s))
    for pi in D.exact:
        for p in _positions(buf, D.patterns[pi].data, 64):
            cands.add((pi, p))
    hits = []
    for pi, s in cands:
        pat = D.patterns[pi]
        if s < 0:
            # starts before the buffer: compare the visible tail as a partial
            continue
        win = buf[s:s + len(pat.data)]
        if win == pat.data:
            res = {"status": "exact", "m": pat.n, "lo": 0, "hi": pat.n, "diff": []}
            if sum(pat.info) < 8:
                continue
        else:
            res = _classify(pat, win)
            if res is None:
                continue
        hits.append(_hit(pat, s, res, buf, base, region))
    return _dedup(hits)


def _hit(pat, s, res, buf, base, region):
    e = pat.esize
    ref = pat.ref
    h = {"ref": ref.id, "name": ref.name, "algo": ref.algo, "form": pat.form,
         "addr": base + s + res["lo"] * e, "end": base + s + res["hi"] * e,
         "start": base + s, "status": res["status"], "n": pat.n, "m": res["m"],
         "lo": res["lo"], "hi": res["hi"], "region": region, "esize": e, "kind": ref.kind}
    if res["status"] == "partial":
        h["match"] = "entries %d-%d of %d" % (res["lo"], res["hi"] - 1, pat.n)
    else:
        h["match"] = "%d of %d" % (res["m"], pat.n)
    diffs = []
    for i in res["diff"]:
        raw_f = buf[s + i * e: s + (i + 1) * e]
        if len(raw_f) < e:
            continue
        # values as the standard writes them, whatever the storage order
        diffs.append({"i": i, "found": _logical(pat.form, raw_f),
                      "std": _logical(pat.form, pat.data[i * e:(i + 1) * e])})
    h["diff"] = diffs
    if ref.kind == "bignum" and res["status"] != "exact":
        win = buf[s:s + len(pat.data)]
        h["found_value"] = "%064x" % _bignum_from(pat.form, win)
    return h


def _logical(form, raw):
    if form in ("u32be", "u64be", "be"):
        return int.from_bytes(raw, "big")
    if form == "u64hi.lo":
        return (int.from_bytes(raw[:4], "little") << 32) | int.from_bytes(raw[4:], "little")
    return int.from_bytes(raw, "little")


def _bignum_from(form, raw):
    if form == "be":
        return int.from_bytes(raw, "big")
    if form == "le":
        return int.from_bytes(raw, "little")
    w = 4 if form == "u32msl" else 8
    return int.from_bytes(b"".join(raw[i:i + w][::-1] for i in range(0, len(raw), w)), "big")


_RANK = {"exact": 0, "near": 1, "partial": 2}


def _dedup(hits):
    """One hit per place: best form per (ref, range); fold contained hits."""
    hits.sort(key=lambda h: (_RANK[h["status"]], -h["m"] * h["esize"], h["addr"]))
    kept = []
    for h in hits:
        dup = False
        for k in kept:
            overlap = h["addr"] < k["end"] and k["addr"] < h["end"]
            if not overlap:
                continue
            if k["ref"] == h["ref"]:
                dup = True
                break
            # a smaller hit inside a stronger one (MD5 init inside SHA-1 IV)
            if k["addr"] <= h["addr"] and h["end"] <= k["end"] and \
                    _RANK[k["status"]] <= _RANK[h["status"]]:
                k.setdefault("contains", []).append(h["name"])
                dup = True
                break
        if not dup:
            kept.append(h)
    kept.sort(key=lambda h: h["addr"])
    return kept


# =============================================================================
# alphabets and strings
# =============================================================================

def scan_alphabets(buf, base=0, region=""):
    """base64/base32 alphabets: standard ones and permutations of them."""
    D = db()
    out = []
    buf = bytes(buf)
    std = {a["id"]: a["text"].encode() for a in D.alphabets}
    b64set = set(std["base64"])
    b64url = set(std["base64url"])
    allowed64 = b64set | b64url | set(b".*!~$")
    out.extend(_alpha_runs(buf, base, region, 64, allowed64, std, "base64", b64set, b64url))
    b32set, b32hex = set(std["base32"]), set(std["base32hex"])
    out.extend(_alpha_runs(buf, base, region, 32, b32set | b32hex, std, "base32", b32set, b32hex))
    return out


def _alpha_runs(buf, base, region, size, allowed, std, family, set_a, set_b):
    out = []
    i, n = 0, len(buf)
    table = bytes(1 if c in allowed else 0 for c in range(256))
    flags = buf.translate(table)
    while True:
        i = flags.find(b"\x01" * size, i)
        if i < 0:
            break
        j = flags.find(b"\x00", i)
        j = n if j < 0 else j
        run = buf[i:j]
        # sliding window of `size` distinct characters
        counts, distinct, p = {}, 0, 0
        found_at = []
        for q, c in enumerate(run):
            counts[c] = counts.get(c, 0) + 1
            if counts[c] == 1:
                distinct += 1
            if q - p + 1 > size:
                d = run[p]
                counts[d] -= 1
                if counts[d] == 0:
                    distinct -= 1
                p += 1
            if q - p + 1 == size and distinct == size:
                found_at.append(p)
        last = -size
        for p in found_at:
            if p < last + size:
                continue
            last = p
            text = run[p:p + size]
            chars = set(text)
            letters_digits = sum(1 for c in chars if chr(c).isalnum())
            if family == "base64":
                exact = [k for k in ("base64", "base64url") if text == std[k]]
                if not exact and letters_digits < 62:
                    continue
                kind = "standard" if exact else ("permutation" if chars in (set_a, set_b)
                                                 else "custom characters")
                name = ("base64url alphabet" if exact == ["base64url"] else "base64 alphabet")
            else:
                exact = [k for k in ("base32", "base32hex") if text == std[k]]
                if not exact and chars not in (set_a, set_b):
                    continue
                kind = "standard" if exact else "permutation"
                name = "base32hex alphabet" if (exact == ["base32hex"] or
                                                (not exact and chars == set_b)) else "base32 alphabet"
            out.append({"ref": family, "name": name, "algo": family, "kind": "alphabet",
                        "form": "chars", "status": "exact" if kind == "standard" else kind,
                        "addr": base + i + p, "end": base + i + p + size, "start": base + i + p,
                        "text": text.decode("latin-1"), "n": size, "m": size, "esize": 1,
                        "lo": 0, "hi": size, "region": region, "diff": [],
                        "match": "%d distinct characters" % size})
        i = j
    return out


# =============================================================================
# immediates
# =============================================================================

_NOISE_IMM = {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0x8000000000000000,
              0x7FFFFFFFFFFFFFFF, 0x55555555, 0xAAAAAAAA, 0x33333333, 0xCCCCCCCC, 0x0F0F0F0F,
              0xF0F0F0F0, 0x01010101, 0x80808080, 0x7F7F7F7F, 0xFEFEFEFF, 0x00FF00FF, 0xFF00FF00,
              0x0000FFFF, 0xFFFF0000, 0x00FFFFFF, 0xFFFFFF00}


def _good_imm(v, w):
    if v in _NOISE_IMM or v < 0x10000:
        return False
    raw = v.to_bytes(w, "little")
    return len(set(raw)) >= 3


def _variants(v):
    """(value, how) pairs an immediate may stand for."""
    out = [(v & 0xFFFFFFFF, "")]
    if v > 0xFFFFFFFF:
        out.append((v & 0xFFFFFFFFFFFFFFFF, ""))
    out.append(((-v) & 0xFFFFFFFF, "negated"))
    if v > 0xFFFFFFFF:
        out.append(((-v) & 0xFFFFFFFFFFFFFFFF, "negated"))
    return out


def match_immediates(funcs, refs=None, pair_window=6):
    """Constant sets and scalars among instruction immediates, per function.

    funcs: {fn_label: [(value, insn_ea), ...]} in instruction order.
    Returns (table_hits, scalar_hits).
    """
    D = refs or db()
    table_hits = []
    scalar_uses = {}
    for fn, imms in funcs.items():
        seen = {}                 # logical value -> (ea, how)
        for v, ea in imms:
            for val, how in _variants(v):
                if val not in seen:
                    seen[val] = (ea, how)
        # scalars
        for val, (ea, how) in seen.items():
            for s in D.scalar_vals.get(val, []):
                if s["width"] == 4 and val > 0xFFFFFFFF:
                    continue
                key = s["id"]
                scalar_uses.setdefault(key, {"s": s, "fns": {}, "how": set()})
                scalar_uses[key]["fns"].setdefault(fn, ea)
                if how:
                    scalar_uses[key]["how"].add(how)
        # tables
        per_table = {}
        for val, (ea, how) in seen.items():
            for ti, i in D.known.get(val, []):
                ref, vals, w, form = D.imm_tables[ti]
                if w == 4 and val > 0xFFFFFFFF:
                    continue
                per_table.setdefault(ti, {}).setdefault(i, (ea, how, "imm"))
        # pairs of nearby immediates combined (two addends, xor halves)
        if pair_window and len(imms) >= 2:
            for a_i in range(len(imms)):
                a, ea_a = imms[a_i]
                if ea_a is None:
                    continue
                for b_i in range(a_i + 1, min(len(imms), a_i + 1 + pair_window)):
                    b, ea_b = imms[b_i]
                    if ea_b is None:
                        continue
                    for w, mask in ((4, 0xFFFFFFFF), (8, 0xFFFFFFFFFFFFFFFF)):
                        x, y = a, b
                        if w == 4:
                            if (x >> 32) not in (0, 0xFFFFFFFF) or (y >> 32) not in (0, 0xFFFFFFFF):
                                continue
                            x, y = x & mask, y & mask
                        elif x <= 0xFFFFFFFF and y <= 0xFFFFFFFF:
                            continue
                        for val, how in (((x + y) & mask, "+"), (x ^ y, "^"),
                                         ((x - y) & mask, "-"), ((y - x) & mask, "-r")):
                            if val in seen or not _good_imm(val, w):
                                continue
                            desc = ("%#x - %#x" % (y, x)) if how == "-r" else ("%#x %s %#x" % (x, how, y))
                            for ti, i in D.known.get(val, []):
                                if D.imm_tables[ti][2] != w:
                                    continue
                                per_table.setdefault(ti, {}).setdefault(i, (ea_a, desc, "pair"))
                            for sc in D.scalar_vals.get(val, []):
                                if sc["width"] != w:
                                    continue
                                key = sc["id"]
                                u = scalar_uses.setdefault(key, {"s": sc, "fns": {}, "how": set()})
                                u["fns"].setdefault(fn, ea_a)
                                u["how"].add("%s = %s" % (_fmt(val, w), desc))
        for ti, found in per_table.items():
            ref, vals, w, form = D.imm_tables[ti]
            n = len(vals)
            good = [i for i in range(n) if _good_imm(vals[i], w)]
            direct = [i for i in found if found[i][2] == "imm" and i in good]
            paired = [i for i in found if found[i][2] == "pair" and i in good]
            need = 2 if len(good) <= 5 else 3
            if len(direct) < need and not (len(paired) >= 2 and len(direct) + len(paired) >= need):
                continue
            missing = [i for i in range(n) if i not in found]
            near = []
            if missing:
                explained = set()
                for val in seen:
                    if val in D.known or val in D.scalar_vals:
                        explained.add(val)
                for i in missing:
                    sv = vals[i]
                    for v, ea in imms:
                        lv = v & ((1 << (8 * w)) - 1)
                        if lv in explained or lv == sv:
                            continue
                        nd, bd = _nibbles(lv, sv), bin(lv ^ sv).count("1")
                        if w == 4 and (v >> 32) not in (0, 0xFFFFFFFF):
                            continue
                        if nd <= 2 or bd <= 2:
                            near.append({"i": i, "found": lv, "std": sv, "ea": ea,
                                         "nibbles": nd, "bits": bd})
                            break
            table_hits.append({"fn": fn, "ref": ref.id, "name": ref.name, "algo": ref.algo,
                               "form": form, "n": n, "found": found, "missing": missing,
                               "near": near, "w": w, "paired": paired})
    table_hits = _fold_imm(table_hits)
    scalars = []
    for key, u in scalar_uses.items():
        s = u["s"]
        scalars.append({"ref": key, "name": s["name"], "algo": s["algo"], "value": s["value"],
                        "w": s["width"], "fns": u["fns"], "how": sorted(u["how"])})
    return table_hits, scalars


def _fold_imm(hits):
    """Drop a hit whose values are all explained by a bigger hit in the same function."""
    out = []
    for h in hits:
        vals = set(_imm_vals(h))
        mine = (len(h["found"]), len(h["found"]) / h["n"])
        better = [k for k in hits if k is not h and k["fn"] == h["fn"]
                  and (len(k["found"]), len(k["found"]) / k["n"]) > mine
                  and vals <= set(_imm_vals(k))]
        if better:
            continue
        out.append(h)
    return out


def _imm_vals(h):
    D = db()
    for ti, (ref, vals, w, form) in enumerate(D.imm_tables):
        if ref.id == h["ref"] and form == h["form"]:
            return [vals[i] for i in h["found"]]
    return []


def match_combined(arrays, refs=None, min_run=4, max_words=64):
    """Word tables stored as two arrays that are combined at run time.

    arrays: {addr: bytes} of data one function refers to. Looks for
    A[i] + B[i], A[i] ^ B[i] or A[i] - B[i] (32-bit little-endian words) equal
    to a run of a known word table (the whole table if it is shorter than
    min_run). Returns [{"ref", "name", "algo", "a", "b", "op", "lo", "hi", "n"}].
    """
    D = refs or db()
    M = 0xFFFFFFFF
    words = {}
    for addr, raw in arrays.items():
        n = min(len(raw) // 4, max_words)
        if n:
            words[addr] = struct_unpack(raw[:4 * n])
    out, seen = [], set()
    keys = sorted(words)
    ops = (("+", lambda x, y: (x + y) & M), ("^", lambda x, y: x ^ y), ("-", lambda x, y: (x - y) & M))
    for ai, a in enumerate(keys):
        for b in keys:
            if b == a:
                continue
            wa, wb = words[a], words[b]
            n = min(len(wa), len(wb))
            for opname, op in ops:
                if opname != "-" and b < a:
                    continue            # + and ^ are symmetric
                comb = [op(wa[j], wb[j]) for j in range(n)]
                j = 0
                while j < n:
                    best = 0
                    for ti, i in D.known.get(comb[j], []):
                        ref, vals, w, form = D.imm_tables[ti]
                        if w != 4:
                            continue
                        L = 0
                        while j + L < n and i + L < len(vals) and comb[j + L] == vals[i + L]:
                            L += 1
                        need = min(min_run, len(vals))
                        if L < need:
                            continue
                        if all(wa[j + k] == vals[i + k] for k in range(L)) or \
                                all(wb[j + k] == vals[i + k] for k in range(L)):
                            continue    # one array is the plain table
                        if not any(wa[j:j + L]) or not any(wb[j:j + L]):
                            continue
                        key = (ref.id, form, a + 4 * (j - i), b + 4 * (j - i), opname)
                        best = max(best, L)
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append({"ref": ref.id, "name": ref.name, "algo": ref.algo, "form": form,
                                    "a": a + 4 * j, "b": b + 4 * j, "op": opname,
                                    "lo": i, "hi": i + L, "n": len(vals)})
                    j += max(best, 1)
    return out


def struct_unpack(raw):
    import struct
    return struct.unpack("<%dI" % (len(raw) // 4), raw)


def walk_callees(root, callees, depth=3, cap=40):
    """Breadth-first walk of direct calls from root.

    callees(fn) -> iterable of called functions (imports and thunks already
    left out). Returns ([(fn, parent)], capped) with root first (parent None);
    capped is True when the function cap cut the walk short.
    """
    order, parent, frontier, capped = [(root, None)], {root: None}, [root], False
    for _ in range(depth):
        nxt = []
        for fn in frontier:
            for c in callees(fn):
                if c in parent:
                    continue
                if len(order) >= cap:
                    return order, True
                parent[c] = fn
                order.append((c, fn))
                nxt.append(c)
        frontier = nxt
        if not frontier:
            break
    return order, capped


# =============================================================================
# presentation (pure)
# =============================================================================

def _ranges(idx):
    out, start, prev = [], None, None
    for i in sorted(idx):
        if start is None:
            start = prev = i
        elif i == prev + 1:
            prev = i
        else:
            out.append((start, prev))
            start = prev = i
    if start is not None:
        out.append((start, prev))
    return ",".join("%d" % a if a == b else "%d-%d" % (a, b) for a, b in out)


def _diff_lines(h, cap=8):
    e = h["esize"]
    width = {"u64hi.lo": 8}.get(h["form"], e)
    lines = []
    for d in h["diff"][:cap]:
        f, s = d["found"], d["std"]
        nd = _nibbles(f, s)
        lines.append("[%d] %s, standard %s (%s)" % (d["i"], _fmt(f, width), _fmt(s, width),
                                                    "%d hex digit%s" % (nd, "" if nd == 1 else "s")))
    if len(h["diff"]) > cap:
        lines.append("+%d more" % (len(h["diff"]) - cap))
    return lines


def render_data_hit(h, label=None):
    out = {"what": h["name"], "algo": h["algo"], "at": label or "%#x" % h["addr"],
           "form": h["form"], "status": h["status"], "match": h["match"]}
    if h.get("region"):
        out["where"] = h["region"]
    if h["diff"]:
        out["diff"] = _diff_lines(h)
    if h.get("found_value"):
        out["found_value"] = "0x" + h["found_value"]
    if h.get("text"):
        out["text"] = h["text"]
    if h.get("contains"):
        out["contains"] = h["contains"]
    if h.get("params"):
        out["params"] = h["params"]
    return out


def render_imm_hit(h, fn_label=None, ea_label=None):
    ea_label = ea_label or (lambda ea: "%#x" % ea)
    w = h["w"]
    out = {"what": h["name"], "algo": h["algo"], "in": fn_label or str(h["fn"]),
           "kind": "immediates", "match": "%d of %d" % (len(h["found"]), h["n"])}
    if h["form"] != "words":
        out["form"] = h["form"]
    if h["missing"]:
        out["missing"] = _ranges(h["missing"])
    neg = sorted({i for i, v in h["found"].items() if v[1] == "negated"})
    if neg:
        out["negated"] = _ranges(neg)
    if h["paired"]:
        out["combined"] = ["[%d] %s" % (i, h["found"][i][1]) for i in sorted(h["paired"])[:6]]
    if h["near"]:
        out["near"] = ["unexplained %s at %s differs from [%d] %s in %d hex digit%s"
                       % (_fmt(d["found"], w), ea_label(d["ea"]) if d["ea"] is not None else "(pseudocode)",
                          d["i"], _fmt(d["std"], w),
                          d["nibbles"], "" if d["nibbles"] == 1 else "s") for d in h["near"][:6]]
    return out


# =============================================================================
# IDA adapter
# =============================================================================

def scan(ea=None, init=None, max_chars=BUDGET, timeout=60):
    """Find known crypto tables/constants; see the module docstring."""
    try:
        return _Scan(ea, init, max_chars, timeout).run()
    except _ScanError as exc:
        out = {"error": exc.args[0]}
        if len(exc.args) > 1:
            out["hint"] = exc.args[1]
        return out
    except Exception as exc:  # noqa: BLE001 - rekit's contract: no traceback
        import traceback
        return {"error": "%s: %s" % (type(exc).__name__, exc),
                "hint": "a _crypto bug; last frame: %s" % traceback.format_exc().strip().splitlines()[-3][:200]}


class _ScanError(Exception):
    pass


class _Scan:
    def __init__(self, ea, init, max_chars, timeout):
        import idaapi, idautils, ida_bytes, ida_funcs, ida_segment, ida_ua, ida_xref, ida_name  # noqa
        self.idaapi, self.idautils, self.ida_bytes = idaapi, idautils, ida_bytes
        self.ida_funcs, self.ida_segment, self.ida_ua = ida_funcs, ida_segment, ida_ua
        self.ida_xref, self.ida_name = ida_xref, ida_name
        self.ea, self.init = ea, init
        self.max_chars, self.timeout = max_chars or BUDGET, timeout
        self.t0 = time.time()
        self.notes = []
        self.func = None
        self.decompile, self.decompiled = True, 0
        if ea is not None:
            f = ida_funcs.get_func(ea)
            if f is None:
                raise _ScanError("%#x is not inside a function" % ea,
                                 "pass a function address, or ea=None to scan the whole database")
            self.func = f
            self.scope, self.scope_capped = walk_callees(f.start_ea, self.direct_callees,
                                                         SCOPE_DEPTH, SCOPE_CAP)
            self.parent = dict(self.scope)

    def direct_callees(self, start):
        """Functions start calls directly, without imports, thunks and externs."""
        f = self.ida_funcs.get_func(start)
        out = []
        for cs, ce in self.idautils.Chunks(start):
            for head in self.idautils.Heads(cs, ce):
                for x in self.idautils.XrefsFrom(head, 0):
                    if not x.iscode or x.type not in (self.ida_xref.fl_CN, self.ida_xref.fl_CF):
                        continue
                    g = self.ida_funcs.get_func(x.to)
                    if g is None or g.start_ea != x.to or g.start_ea == f.start_ea:
                        continue
                    seg = self.ida_segment.getseg(x.to)
                    if g.flags & self.ida_funcs.FUNC_THUNK or seg is None or \
                            seg.type == self.ida_segment.SEG_XTRN:
                        continue
                    if x.to not in out:
                        out.append(x.to)
        return out

    def where_fn(self, start):
        """'sub_X' for the function asked about, 'sub_Y, called from sub_X' below it."""
        name = self.fn_label(start)
        par = getattr(self, "parent", {}).get(start)
        return name if par is None else "%s, called from %s" % (name, self.fn_label(par))

    # ---------------------------------------------------------------- labels
    def label(self, ea):
        f = self.ida_funcs.get_func(ea)
        if f:
            name = self.ida_funcs.get_func_name(f.start_ea) or "sub_%X" % f.start_ea
            return name if ea == f.start_ea else "%s+%#x" % (name, ea - f.start_ea)
        seg = self.ida_segment.getseg(ea)
        if seg:
            nm = self.ida_name.get_name(ea)
            segname = self.ida_segment.get_segm_name(seg)
            return "%#x %s+%#x%s" % (ea, segname, ea - seg.start_ea, " (%s)" % nm if nm else "")
        return "%#x" % ea

    def short(self, ea):
        return self.ida_name.get_name(ea) or "%#x" % ea

    def fn_label(self, start):
        return self.ida_funcs.get_func_name(start) or "sub_%X" % start

    # ---------------------------------------------------------------- bytes
    def segments(self):
        out = []
        for s in self.idautils.Segments():
            seg = self.ida_segment.getseg(s)
            if seg.type == self.ida_segment.SEG_XTRN:
                continue
            ib = self.ida_bytes
            if ib.is_loaded(seg.end_ea - 1):
                last = seg.end_ea - 1
            else:
                last = ib.prev_inited(seg.end_ea - 1, seg.start_ea)
                if last != self.idaapi.BADADDR and ib.is_loaded(last + 1):
                    last += 1
            if ib.is_loaded(seg.start_ea):
                last = max(last, seg.start_ea) if last != self.idaapi.BADADDR else seg.start_ea
            if last == self.idaapi.BADADDR:
                continue
            data = ib.get_bytes(seg.start_ea, last + 1 - seg.start_ea) or b""
            out.append((seg.start_ea, self.ida_segment.get_segm_name(seg), data,
                        bool(seg.perm & 1)))
        return out

    # ---------------------------------------------------------------- xrefs
    def users(self, lo, hi):
        """Functions referencing [lo, hi), and whether they look alive."""
        refs = {}
        data_refs = []
        heads = [lo]
        h = self.ida_bytes.next_head(lo, hi)
        n = 0
        while h != self.idaapi.BADADDR and h < hi and n < 2048:
            heads.append(h)
            h = self.ida_bytes.next_head(h, hi)
            n += 1
        for a in heads:
            for x in self.idautils.XrefsTo(a, 0):
                f = self.ida_funcs.get_func(x.frm)
                if f:
                    refs.setdefault(f.start_ea, x.frm)
                elif not self.ida_bytes.is_code(self.ida_bytes.get_flags(x.frm)):
                    data_refs.append(x.frm)
        # one level through data pointers (a pointer table holding the address)
        for d in data_refs[:16]:
            for x in self.idautils.XrefsTo(d, 0):
                f = self.ida_funcs.get_func(x.frm)
                if f:
                    refs.setdefault(f.start_ea, x.frm)
        return refs, data_refs

    def callers(self, start):
        n = 0
        for x in self.idautils.XrefsTo(start, 0):
            f = self.ida_funcs.get_func(x.frm)
            if f is not None and f.start_ea == start:
                continue        # recursion
            n += 1
        return n

    def describe_users(self, lo, hi):
        refs, data_refs = self.users(lo, hi)
        via = None
        if not refs and not data_refs:
            # code often addresses a group of globals through the first one
            # (lea rdi, base; ... [rdi+0x20]); take the nearest referenced head
            # up to 256 bytes before
            p = lo
            seg = self.ida_segment.getseg(lo)
            for _ in range(64):
                p = self.ida_bytes.prev_head(p, max(seg.start_ea if seg else 0, lo - 256))
                if p == self.idaapi.BADADDR:
                    break
                r2, d2 = self.users(p, p + 1)
                if r2:
                    refs, via = r2, p
                    break
        if not refs:
            return [], ("unreferenced: no code refers to it" if not data_refs
                        else "referenced only from data at %s" % ", ".join("%#x" % d for d in data_refs[:3]))
        out, alive = [], 0
        for start in sorted(refs):
            nc = self.callers(start)
            alive += 1 if nc else 0
            out.append("%s (%s)" % (self.fn_label(start), "%d caller%s" % (nc, "" if nc == 1 else "s")
                                    if nc else "no callers"))
        note = None if alive else "only referenced by functions with no callers (dead code or a decoy?)"
        if via is not None:
            base = "via %s+%#x (no direct reference)" % (self.short(via), lo - via)
            note = base if note is None else base + "; " + note
        return out, note

    # ---------------------------------------------------------------- immediates
    def func_imms(self, f, cap=200000):
        o_imm, o_displ = self.ida_ua.o_imm, self.ida_ua.o_displ
        out = []
        insn = self.ida_ua.insn_t()
        for cs, ce in self.idautils.Chunks(f.start_ea):
            for head in self.idautils.Heads(cs, ce):
                if not self.ida_bytes.is_code(self.ida_bytes.get_flags(head)):
                    continue
                if not self.ida_ua.decode_insn(insn, head):
                    continue
                for op in insn.ops:
                    t = op.type
                    if t == 0:
                        break
                    if t == o_imm:
                        v = op.value & 0xFFFFFFFFFFFFFFFF
                        if v >= 0x10000 and not self.ida_bytes.is_mapped(v):
                            out.append((v, head))
                    elif t == o_displ:
                        v = op.addr & 0xFFFFFFFFFFFFFFFF
                        if v >= 0x10000 and not self.ida_bytes.is_mapped(v):
                            sv = v - (1 << 64) if v >> 63 else v
                            if abs(sv) >= 0x10000:
                                out.append((v & 0xFFFFFFFF if abs(sv) < (1 << 32) else v, head))
                if len(out) > cap:
                    return out
        return out

    _LIT = None

    def decompiled_consts(self, f):
        """Numeric literals of the pseudocode: Hex-Rays folds the arithmetic that
        obfuscators use to hide constants (x ^ k, a + b) back into plain values."""
        import re
        try:
            import ida_hexrays
            import ida_lines
            if not ida_hexrays.init_hexrays_plugin():
                return None
            if self.ida_funcs.calc_func_size(f) > 0x10000:
                return []
            cf = ida_hexrays.decompile(f.start_ea)
        except Exception:  # noqa: BLE001 - decompilation failure is just "no data"
            return []
        if cf is None:
            return []
        if _Scan._LIT is None:
            _Scan._LIT = re.compile(r"(?<![\w.])(-?)(0x[0-9A-Fa-f]+|\d+)(?:u|U|i64|ui64|LL|uLL|ULL|L)*(?![\w.])")
        out = []
        for line in cf.get_pseudocode():
            text = ida_lines.tag_remove(line.line).split("//", 1)[0]
            for m in _Scan._LIT.finditer(text):
                v = int(m.group(2), 0)
                if m.group(1):
                    v = (-v) & 0xFFFFFFFFFFFFFFFF
                if v >= 0x10000 and not self.ida_bytes.is_mapped(v):
                    out.append((v, None))
        return out

    def func_targets(self, f):
        """Data addresses the function refers to (not code, not its own body)."""
        out = set()
        for cs, ce in self.idautils.Chunks(f.start_ea):
            for head in self.idautils.Heads(cs, ce):
                for x in self.idautils.XrefsFrom(head, 0):
                    if x.iscode:
                        continue
                    to = x.to
                    if f.contains(to) or not self.ida_bytes.is_mapped(to):
                        continue
                    seg = self.ida_segment.getseg(to)
                    if seg is None or seg.type == self.ida_segment.SEG_XTRN:
                        continue
                    out.add(to)
        return out

    # ---------------------------------------------------------------- static
    def static_data(self):
        hits = []
        segs = self.segments()
        self.seg_bytes = segs
        if self.func is None:
            for start, name, data, is_x in segs:
                if self.time_left() < (self.timeout * 0.4 if self.init else 1):
                    self.notes.append("static data scan stopped at %s: time budget" % name)
                    break
                for h in scan_bytes(data, start, region=name):
                    hits.append(h)
                for h in scan_alphabets(data, start, region=name):
                    hits.append(h)
        else:
            self.target_fns = {}
            for fn, _par in self.scope:
                for t in self.func_targets(self.ida_funcs.get_func(fn)):
                    self.target_fns.setdefault(t, []).append(fn)
            targets = sorted(self.target_fns)
            self.targets = targets
            windows = []
            for t in targets:
                seg = self.ida_segment.getseg(t)
                end = min(seg.end_ea, t + max(4352, self.ida_bytes.get_item_size(t)))
                if windows and t <= windows[-1][1]:
                    windows[-1][1] = max(windows[-1][1], end)
                else:
                    windows.append([t, end])
            for lo, hi in windows:
                data = self._bytes(lo, hi)
                region = self.ida_segment.get_segm_name(self.ida_segment.getseg(lo))
                for h in scan_bytes(data, lo, region=region) + scan_alphabets(data, lo, region=region):
                    inside = [t for t in targets if h["start"] <= t < max(h["end"], h["start"] + 1)]
                    if inside:
                        h["fns"] = sorted({fn for t in inside for fn in self.target_fns[t]})
                        hits.append(h)
            hits = _dedup_overlaps(hits)
        for h in hits:
            h["when"] = "static"
        return hits

    def _bytes(self, lo, hi):
        for start, name, data, is_x in self.seg_bytes:
            if start <= lo < start + len(data):
                return data[lo - start: hi - start]
        return b""

    def static_imms(self):
        funcs, combos = {}, {}
        if self.func is not None:
            fl = [self.ida_funcs.get_func(fn) for fn, _par in self.scope]
        else:
            fl = [self.ida_funcs.get_func(e) for e in self.idautils.Functions()]
        done = 0
        for f in fl:
            if f is None or f.flags & self.ida_funcs.FUNC_THUNK:
                continue
            if self.time_left() < (self.timeout * 0.4 if self.init else 1):
                self.notes.append("immediates collected for %d of %d functions (time budget)"
                                  % (done, len(fl)))
                break
            imms = self.func_imms(f)
            if self.decompile and self.time_left() > self.timeout / 2:
                extra = self.decompiled_consts(f)
                if extra is None:
                    self.decompile = False
                    self.notes.append("Hex-Rays is unavailable: pseudocode constants not used")
                else:
                    have = {v for v, _ in imms}
                    imms = imms + [x for x in extra if x[0] not in have]
                    self.decompiled += 1
            done += 1
            if imms:
                funcs[f.start_ea] = imms
            targets = sorted(self.func_targets(f)) if self.func is None else \
                sorted(t for t, fns in self.target_fns.items() if f.start_ea in fns)
            if 2 <= len(targets) <= 40:
                arrays = {}
                for t in targets:
                    seg = self.ida_segment.getseg(t)
                    raw = self._bytes(t, min(seg.end_ea, t + 256))
                    if len(raw) >= 16:
                        arrays[t] = raw
                for m in match_combined(arrays):
                    key = (m["ref"], m["a"] - 4 * m["lo"], m["b"] - 4 * m["lo"], m["op"])
                    if key in combos:
                        combos[key]["fns"].add(f.start_ea)
                        old = combos[key]
                        if m["hi"] - m["lo"] > old["hi"] - old["lo"]:
                            m["fns"] = old["fns"]
                            combos[key] = m
                    else:
                        m["fns"] = {f.start_ea}
                        combos[key] = m
        self.combos = list(combos.values())
        if self.decompiled < done:
            self.notes.append("pseudocode constants used for %d of %d functions (time budget)"
                              % (self.decompiled, done))
        tables, scalars = match_immediates(funcs)
        # constants loaded from data the function points at (one word)
        if self.func is not None:
            D = db()
            for t in getattr(self, "targets", []):
                for w in (4, 8):
                    raw = self._bytes(t, t + w)
                    if len(raw) == w:
                        v = int.from_bytes(raw, "little")
                        for s in D.scalar_vals.get(v, []):
                            if s["width"] == w:
                                scalars.append({"ref": s["id"], "name": s["name"], "algo": s["algo"],
                                                "value": v, "w": w,
                                                "fns": {fn: t for fn in self.target_fns[t]},
                                                "how": ["loaded from %#x" % t]})
        return tables, scalars

    # ---------------------------------------------------------------- after init
    def after_init(self):
        import tempfile
        entries = []
        for e in self.init:
            if isinstance(e, dict):
                ent = dict(e)
                ent["func"] = "%#x" % self._addr(ent["func"])
                ent.setdefault("max_insns", 1_000_000_000)
                entries.append(ent)
            else:
                entries.append({"func": "%#x" % self._addr(e), "max_insns": 1_000_000_000})
        if not entries:
            return [], None
        dump = tempfile.mkdtemp(prefix="rekit-crypto-")
        try:
            return self._emulate(entries, dump)
        finally:
            shutil_rm(dump)

    def _emulate(self, entries, dump):
        import _emu
        main = dict(entries[-1])
        req = {"func": main.pop("func"), "init": entries[:-1], "dump": dump,
               "timeout": max(5, int(self.time_left() - 5)), "max_chars": 1500,
               "fields": ["stop", "init", "dump", "insns", "warnings"]}
        for k in ("args", "cc", "regs", "mem", "replace", "imports", "max_insns"):
            if k in main:
                req[k] = main[k]
        try:
            reply = _emu.run(req, timeout=req["timeout"])
        except _emu.EmuError as exc:
            return [], {"error": exc.msg, "hint": exc.hint}
        info = {"stop": reply.get("stop", {}).get("reason") if isinstance(reply.get("stop"), dict)
                else reply.get("stop")}
        if "error" in reply:
            return [], {"error": reply["error"], "hint": reply.get("hint", "")}
        st = reply.get("stop") or {}
        if st.get("reason") == "init_failed":
            info["stop"] = "init[%s] %s stopped: %s" % (st.get("entry"), st.get("func"),
                                                       (st.get("cause") or {}).get("reason"))
            info["partial"] = "memory is scanned as that entry left it"
        elif st.get("reason") != "returned":
            info["stop"] = "last entry stopped: %s at %s" % (st.get("reason"), st.get("at"))
        info["insns"] = sum(int(x.get("insns", 0)) for x in reply.get("init", [])) + int(reply.get("insns", 0))
        try:
            with open(os.path.join(dump, "dump.json"), encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            info["error"] = "no memory dump was written"
            return [], info
        hits = []
        self.dump_regions = []
        for r in meta["regions"]:
            start = int(r["start"], 16)
            with open(os.path.join(dump, r["file"]), "rb") as fh:
                data = fh.read()
            self.dump_regions.append((r, start, data))
            changed = [(int(a, 16), int(b, 16)) for a, b in r["changed"]]
            if not changed:
                continue
            if r["kind"] == "segment":
                wins = []
                for a, b in changed:
                    lo, hi = max(start, a - 8192), min(start + len(data), b + 8192)
                    if wins and lo <= wins[-1][1]:
                        wins[-1][1] = max(wins[-1][1], hi)
                    else:
                        wins.append([lo, hi])
            else:
                wins = [[start, start + len(data)]]
            for lo, hi in wins:
                chunk = data[lo - start: hi - start]
                for h in scan_bytes(chunk, lo, region=r["name"]) + scan_alphabets(chunk, lo, region=r["name"]):
                    if any(h["start"] < b and a < h["end"] for a, b in changed):
                        h["when"] = "after init"
                        h["dump_kind"] = r["kind"]
                        hits.append(h)
        return _dedup_overlaps(hits), info

    def _addr(self, x):
        if isinstance(x, int):
            return x
        s = str(x).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        ea = self.ida_name.get_name_ea(self.idaapi.BADADDR, s)
        if ea == self.idaapi.BADADDR:
            raise _ScanError("init entry %r is not an address or a known name" % (x,))
        return ea

    def pointer_holders(self, addr_lo, addr_hi):
        """Image addresses (after init) holding a pointer into [lo, hi)."""
        out = []
        for r, start, data in getattr(self, "dump_regions", []):
            if r["kind"] != "segment":
                continue
            for i in range(0, len(data) - 7, 8):
                v = int.from_bytes(data[i:i + 8], "little")
                if addr_lo <= v < addr_hi:
                    out.append(start + i)
                    if len(out) > 8:
                        return out
        return out

    def time_left(self):
        return self.timeout - (time.time() - self.t0)

    # ---------------------------------------------------------------- assemble
    def run(self):
        stat = self.static_data()
        tables, scalars = self.static_imms()
        dyn, emu_info = [], None
        if self.init:
            dyn, emu_info = self.after_init()
        items = []
        static_by_ref = {}
        for h in stat:
            static_by_ref.setdefault(h["ref"], []).append(h)
        for h in _merge_curves(stat) + _merge_curves(dyn):
            r = render_data_hit(h, self.label(h["addr"]) if h.get("dump_kind") in (None, "segment")
                                else "%#x %s" % (h["addr"], h["region"]))
            r["when"] = h["when"]
            users, note, used = [], None, False
            if h.get("dump_kind") in ("heap", "args", "buffer"):
                holders = self.pointer_holders(h["start"] - 0x10000, h["end"])
                for p in holders[:3]:
                    us, nt = self.describe_users(p, p + 8)
                    users.extend("%s via pointer at %s" % (u, self.label(p)) for u in us)
                if not users:
                    note = "heap memory written by the init calls; no pointer to it found in the image"
            else:
                users, note = self.describe_users(h["start"], max(h["end"], h["start"] + 1))
            if self.func is not None and h["when"] == "after init" and h.get("dump_kind") == "segment":
                if not any(h["start"] <= t < h["end"] for t in getattr(self, "targets", [])):
                    continue
            if self.func is not None:
                fns = h.get("fns") or sorted({fn for t in self.targets if h["start"] <= t < h["end"]
                                              for fn in self.target_fns[t]})
                if fns and self.func.start_ea not in fns:
                    r["in"] = "; ".join(self.where_fn(fn) for fn in fns[:3])
            if users:
                r["used_by"] = users[:4] + (["+%d more" % (len(users) - 4)] if len(users) > 4 else [])
                used = not note or note.startswith("via ")
            if note:
                r["note"] = note
            if h["when"] == "after init":
                r["when"] = "present only after init"
                others = [s for s in static_by_ref.get(h["ref"], []) if s["start"] != h["start"]]
                if others:
                    r["also_static"] = [self.label(s["addr"]) for s in others[:3]]
            elif h["ref"] in {d["ref"] for d in dyn}:
                r["also_after_init"] = [("%#x %s" % (d["addr"], d["region"])) for d in dyn
                                        if d["ref"] == h["ref"]][:3]
            score = self._score(h, used)
            items.append((score, r, h))
        for t in tables:
            r = render_imm_hit(t, self.where_fn(t["fn"]), self.label)
            nc = self.callers(t["fn"])
            if not nc:
                r["note"] = "function has no callers"
            dev = bool(t["near"])
            items.append(((0 if dev else 2, -len(t["found"])), r, t))
        for m in getattr(self, "combos", []):
            whole = m["lo"] == 0 and m["hi"] == m["n"]
            # a and b point at entry lo; name the arrays at the table start
            a0, b0 = m["a"] - 4 * m["lo"], m["b"] - 4 * m["lo"]
            r = {"what": m["name"], "algo": m["algo"], "kind": "two data arrays combined",
                 "how": "%s[i] %s %s[i]" % (self.short(a0), m["op"], self.short(b0)),
                 "match": ("%d of %d" % (m["n"], m["n"])) if whole
                 else "entries %d-%d of %d" % (m["lo"], m["hi"] - 1, m["n"]),
                 "in": [self.where_fn(f) for f in sorted(m["fns"])[:4]]}
            if m["form"] != "words":
                r["form"] = m["form"]
            items.append(((1, 0, -(m["hi"] - m["lo"])), r, m))
        for s in scalars:
            fns = sorted(s["fns"])
            r = {"what": s["name"], "algo": s["algo"], "value": _fmt(s["value"], s["w"]),
                 "kind": "scalar", "in": [self.where_fn(f) for f in fns[:5]]}
            if len(fns) > 5:
                r["in"].append("+%d more" % (len(fns) - 5))
            if s["how"]:
                r["how"] = s["how"]
            items.append(((5, 0), r, s))
        items.sort(key=lambda x: x[0])
        out = {"scope": "function %s" % self.fn_label(self.func.start_ea) if self.func else "database"}
        out["summary"] = self._summary(items)
        if self.func is not None:
            cov = [self.fn_label(fn) for fn, _p in self.scope]
            out["covered"] = {"total": len(cov), "top": cov[:12], "depth": SCOPE_DEPTH}
            if len(cov) > 12:
                out["covered"]["more"] = "+%d" % (len(cov) - 12)
            if self.scope_capped:
                out["covered"]["capped"] = ("stopped at %d functions; scan a callee with ea= to "
                                            "go deeper there" % SCOPE_CAP)
        curves = {}
        for _, r, h in items:
            if h.get("kind") == "bignum":
                curves.setdefault(h["algo"], set()).add(
                    "after init" if h.get("when") == "after init" else "static")
        if len(curves) > 1:
            out["candidates"] = ("parameters of %d curves are present: %s; check which one the "
                                 "code that runs actually uses" % (len(curves), ", ".join(
                                     "%s (%s)" % (k, "/".join(sorted(v))) for k, v in curves.items())))
        if self.init:
            out["after_init"] = emu_info or {}
        shown, total = [], len(items)
        out["hits"] = {"total": total, "top": shown}
        if not items:
            out["hits"]["note"] = "no known tables or constants found"
        for _, r, _h in items:
            shown.append(r)
            if len(json.dumps(out, ensure_ascii=False)) > self.max_chars - 300:
                shown.pop()
                break
        if len(shown) < total:
            out["truncated"] = ("%d of %d hits shown (most significant first); raise max_chars "
                                "or scan one function with ea=" % (len(shown), total))
        if self.notes:
            out["notes"] = self.notes
        out["ms"] = int((time.time() - self.t0) * 1000)
        return _fit(out, self.max_chars)

    def _score(self, h, used):
        st = h["status"]
        deviation = st == "near" or (st == "partial" and h["diff"]) or st in ("permutation",
                                                                               "custom characters")
        if deviation:
            return (0, 0 if used else 1, -h["m"])
        if h["when"] == "after init":
            return (1, 0 if used else 1, -h["m"])
        if st == "exact":
            return (2 if used else 4, 0, -h["m"] * h["esize"])
        return (3, 0 if used else 1, -h["m"])

    def _summary(self, items):
        by = {}
        for score, r, h in items:
            algo = r.get("algo", "?")
            what = r["what"]
            if r.get("kind") == "scalar":
                bit = "%s %s" % (what, "imm")
            elif r.get("kind") == "two data arrays combined":
                bit = "%s as %s" % (what, r["how"])
            elif r.get("kind") == "immediates":
                bit = "%s imm %s in %s" % (what, r["match"], r["in"])
                if r.get("near"):
                    bit += " (near-miss)"
            else:
                bit = "%s %s%s" % (what, r["status"] if r["status"] != "exact" else "",
                                   (" " + r["match"]) if r["status"] != "exact" else "")
                bit = bit.replace("  ", " ").strip()
                bit += " @%s" % r["at"].split(" ")[0]
                if r.get("when", "").startswith("present only"):
                    bit += " after init"
                if r.get("note", "").startswith(("unreferenced", "only referenced")):
                    bit += " unused"
            by.setdefault(algo, []).append(bit)
        lines = []
        for algo, bits in by.items():
            uniq = list(dict.fromkeys(bits))
            lines.append("%s: %s" % (algo, "; ".join(uniq[:4]) + (" +%d" % (len(uniq) - 4) if len(uniq) > 4 else "")))
        return lines[:20]


def _merge_curves(hits):
    """Adjacent exact parameters of one curve in one form become one entry."""
    out, groups = [], []
    for h in sorted(hits, key=lambda h: h["addr"]):
        if h.get("kind") == "bignum" and h["status"] == "exact":
            g = groups[-1] if groups else None
            if g and g[-1]["algo"] == h["algo"] and g[-1]["form"] == h["form"] \
                    and g[-1].get("region") == h.get("region") and 0 <= h["addr"] - g[-1]["end"] <= 32:
                g.append(h)
                continue
            groups.append([h])
        else:
            out.append(h)
    for g in groups:
        if len(g) == 1:
            out.append(g[0])
            continue
        m = dict(g[0])
        m.update({"name": "%s parameters" % g[0]["algo"], "ref": "curve:" + g[0]["algo"],
                  "end": g[-1]["end"], "m": sum(x["m"] for x in g), "kind": "bignum",
                  "match": "%d parameters, each 32 of 32" % len(g),
                  "params": " ".join("%s@+%#x" % (x["name"].split()[-1], x["addr"] - g[0]["addr"])
                                     for x in g)})
        out.append(m)
    return out


def _dedup_overlaps(hits):
    out = []
    for h in sorted(hits, key=lambda h: (_RANK.get(h["status"], 3), -h["m"])):
        if any(k["ref"] == h["ref"] and h["start"] < k["end"] and k["start"] < h["end"] for k in out):
            continue
        out.append(h)
    return out


def shutil_rm(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def _fit(res, budget):
    """Halve the biggest leaf until the result fits (rekit's last-resort guard)."""
    limit = int(budget * 1.25) + 200
    cut = []
    for _ in range(40):
        if len(json.dumps(res, ensure_ascii=False)) <= limit:
            break
        best = None
        stack = [(res, k) for k in list(res)]
        while stack:
            box, key = stack.pop()
            val = box[key]
            if isinstance(val, dict):
                stack.extend((val, k) for k in list(val))
            elif isinstance(val, list):
                if len(val) > 1:
                    w = len(json.dumps(val))
                    if best is None or w > best[0]:
                        best = (w, box, key)
                stack.extend((val, i) for i in range(len(val)) if isinstance(val[i], (dict, list)))
            elif isinstance(val, str) and len(val) > 40:
                if best is None or len(val) > best[0]:
                    best = (len(val), box, key)
        if best is None:
            break
        _, box, key = best
        val = box[key]
        box[key] = val[: len(val) // 2]
        cut.append(str(key))
    if cut:
        res["truncated"] = (res.get("truncated", "") + " hard budget hit, cut: %s"
                            % ", ".join(sorted(set(cut)))).strip()
    return res
