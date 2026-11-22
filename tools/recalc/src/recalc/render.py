"""Rendering values for a reader that must copy them exactly.

int     -> 5 (|x| < 10), "0x8e42a = 582698" (up to 64 bits), "0x..." beyond;
           inside containers of more than 16 items, hex only
bytes   -> {"bytes": n, "hex": "...", "ascii": "..."} (ascii only when every byte is printable)
str     -> the string
list    -> a JSON array; tuple -> {"tuple": [...]}; dict -> {"dict": [[key, value], ...]}
Long values are cut in the middle only, with a marker that says how much was
cut and the total length: "...[cut 900 of 1024 bytes]...".
"""

from __future__ import annotations

import json

# (hex bytes shown, list items shown, str chars shown, nesting depth)
LEVELS = [(1024, 256, 2000, 12), (256, 48, 400, 8), (64, 16, 120, 5), (16, 6, 40, 3), (8, 3, 16, 2)]


def _cut(s, keep, unit_total, unit, per_unit=1):
    """Cut text s in the middle, keeping about `keep` characters."""
    if len(s) <= keep + 40:
        return s
    head = (keep * 2 // 3) // per_unit * per_unit
    tail = (keep - head) // per_unit * per_unit
    cut_units = (len(s) - head - tail) // per_unit
    return "%s...[cut %d of %d %s]...%s" % (s[:head], cut_units, unit_total, unit, s[len(s) - tail:] if tail else "")


def _printable(b):
    return all(32 <= x < 127 or x in (9, 10, 13) for x in b)


def render_int(x, level=0, in_list=False):
    if -10 < x < 10:
        return x
    h = hex(x)
    if x.bit_length() <= 64 and not in_list:
        return "%s = %d" % (h, x)
    keep = LEVELS[level][0] * 2
    if len(h) > keep + 40:
        sign = "-" if x < 0 else ""
        digits = h[len(sign) + 2:]
        return "%s0x%s (%d bits)" % (sign, _cut(digits, keep, len(digits), "hex digits"), x.bit_length())
    return h


MAX_NODES = 3000      # values rendered per reply section, whatever the nesting


def render(v, level=0, depth=0, in_list=False, seen=None, budget=None):
    hexmax, items, strmax, maxdepth = LEVELS[level]
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        return "[not shown: too many nested values]"
    t = type(v)
    if v is None or t is bool:
        return v
    if t is int:
        return render_int(v, level, in_list)
    if t is str:
        return _cut(v, strmax, len(v), "chars")
    if t is bytes:
        out = {"bytes": len(v), "hex": _cut(v.hex(), 2 * hexmax, len(v), "bytes", 2)}
        if v and _printable(v):
            out["ascii"] = _cut(v.decode("ascii"), hexmax, len(v), "bytes")
        return out
    if t is range:
        def b(x):
            return str(x) if abs(x) < 1 << 64 else render_int(x, 3, True)
        return "range(%s, %s, %s)" % (b(v.start), b(v.stop), b(v.step))
    if t in (list, tuple, dict):
        seen = seen or set()
        if id(v) in seen:
            return "[cycle]"
        if depth >= maxdepth:
            return "[%s of %d items, nested too deep to show]" % (t.__name__, len(v))
        seen = seen | {id(v)}
        seq = list(v.items()) if t is dict else v
        n = len(seq)
        if n > items:
            head = items * 2 // 3
            tail = items - head
            shown = list(seq[:head]) + [None] + (list(seq[n - tail:]) if tail else [])
        else:
            head, shown = None, list(seq)
        out = []
        compact = n > 16          # long containers show integers in hex only
        for i, x in enumerate(shown):
            if head is not None and i == head:
                out.append("...[cut %d of %d items]..." % (n - items, n))
                continue
            if t is dict:
                out.append([render(x[0], level, depth + 1, compact, seen, budget),
                            render(x[1], level, depth + 1, compact, seen, budget)])
            else:
                out.append(render(x, level, depth + 1, compact, seen, budget))
        if t is tuple:
            return {"tuple": out}
        if t is dict:
            return {"dict": out}
        return out
    return "<%s>" % t.__name__


def text(v):
    """Short one-line text for print() and assertion messages."""
    r = render(v, 2)
    return r if isinstance(r, str) else json.dumps(r, ensure_ascii=False, separators=(",", ":"))


def size(obj):
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def fit(base, result, has_result, variables, printed, max_chars):
    """Build the reply within max_chars: shorten values level by level, then
    drop variables (largest first), then printed lines; say what was cut."""
    notes = []
    for level in range(len(LEVELS)):
        reply = dict(base)
        if has_result:
            reply["result"] = render(result, level)
        if variables:
            reply["vars"] = {k: render(v, level) for k, v in variables.items()}
        if printed:
            reply["printed"] = list(printed)
        if level:
            reply["truncated"] = "values shortened (detail level %d of %d); long values are cut in the " \
                                 "middle at ...[cut N of M]... markers" % (level, len(LEVELS) - 1)
        elif "...[cut " in json.dumps(reply, ensure_ascii=False):
            reply["truncated"] = "long values are cut in the middle at ...[cut N of M]... markers"
        if size(reply) <= max_chars:
            return reply
    reply.pop("truncated", None)
    level = len(LEVELS) - 1
    notes.append("values shortened (detail level %d of %d)" % (level, level))
    dropped = []
    if "vars" in reply:
        order = sorted(reply["vars"], key=lambda k: -size(reply["vars"][k]))
        for k in order:
            if size(reply) + 120 <= max_chars:
                break
            del reply["vars"][k]
            dropped.append(k)
        if not reply["vars"]:
            del reply["vars"]
    if dropped:
        notes.append("vars not shown: " + ", ".join(dropped))
    if "printed" in reply and size(reply) + 120 > max_chars:
        total = len(reply["printed"])
        while reply["printed"] and size(reply) + 120 > max_chars:
            reply["printed"].pop()
        notes.append("printed: %d of %d lines shown" % (len(reply["printed"]), total))
        if not reply["printed"]:
            del reply["printed"]
    if has_result and size(reply) + 120 > max_chars:
        reply["result"] = "[result too large to show in max_chars=%d; assign it and print a slice]" % max_chars
        notes.append("result not shown")
    reply["truncated"] = "; ".join(notes)
    return reply
