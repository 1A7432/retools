"""Keeping a reply inside its max_chars budget, and saying what was cut."""

from __future__ import annotations

import json
import re

# Least important first: these sections give up space before the ones after them.
SHRINK_ORDER = ["trace", "stack_strings", "mapped_on_demand", "writes", "unchanged", "warnings",
                "imports", "reads", "buffers", "regs", "ret_view", "ret_points_to", "regs_out"]
_CUT = re.compile(r"\.\.\.\[\+(\d+) chars\]$")
NOTE_RESERVE = 300


def size(obj):
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def _cut_string(s):
    m = _CUT.search(s)
    extra = int(m.group(1)) if m else 0
    body = s[: m.start()] if m else s
    keep = len(body) // 2
    if keep and body[:keep].strip("0123456789abcdef") == "" and keep % 2:
        keep -= 1   # keep hex dumps byte-aligned
    return "%s...[+%d chars]" % (body[:keep], extra + len(body) - keep)


def _candidates(obj, out, min_str):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "top" and isinstance(v, list) and v:
                out.append((size(v), obj, k))
            elif isinstance(v, str) and len(v) > min_str:
                out.append((len(v), obj, k))
            if isinstance(v, (dict, list)):
                _candidates(v, out, min_str)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str) and len(v) > min_str:
                out.append((len(v), obj, i))
            elif isinstance(v, (dict, list)):
                _candidates(v, out, min_str)


# Shrinking a section goes in phases: first long strings (hex dumps, text views)
# are halved down to 120 chars, then lists lose their tail but keep one item,
# then everything goes down to empty lists and 48-char strings.
PHASES = ((120, False, 1), (120, True, 1), (48, True, 0))


def _shrink(section, phase):
    min_str, lists, keep = PHASES[phase]
    cands = []
    _candidates(section, cands, min_str)
    cands = [c for c in cands if isinstance(c[1][c[2]], str)
             or (lists and len(c[1][c[2]]) > keep)]
    if not cands:
        return False
    _, box, key = max(cands, key=lambda c: c[0])
    val = box[key]
    if isinstance(val, list):
        del val[max(len(val) // 2, keep):]
    else:
        box[key] = _cut_string(val)
    return True


def _shown(top):
    # entries that stand for repeated events carry "n" (imports, trace)
    return sum(e.get("n", 1) if isinstance(e, dict) else 1 for e in top)


def annotate(reply):
    """Every {"total", "top"} list that shows less than its total says so in "more"."""
    for v in reply.values():
        if isinstance(v, dict) and "total" in v and isinstance(v.get("top"), list):
            shown = _shown(v["top"])
            if shown < v["total"]:
                v["more"] = "%d of %d shown" % (shown, v["total"])
            else:
                v.pop("more", None)


def _note(budget, cut):
    return ("over max_chars=%d: shortened %s. Lists show 'more'; strings end in ...[+N chars]. "
            "Raise max_chars, pass fields, or read exact addresses with read."
            % (budget, ", ".join(cut)))


def fit(reply, budget):
    budget = max(int(budget), 200)
    annotate(reply)
    if size(reply) <= budget:
        return reply
    target = max(budget - NOTE_RESERVE, 150)
    cut = []
    for key in SHRINK_ORDER:
        for phase in range(len(PHASES)):
            while key in reply and size(reply) > target:
                sec = reply[key]
                if isinstance(sec, str):
                    if len(sec) <= 48:
                        break
                    reply[key] = _cut_string(sec)
                elif not _shrink(sec, phase):
                    break
                if key not in cut:
                    cut.append(key)
    # Then whatever is left, until the reply with its notes fits.
    for _ in range(80):
        annotate(reply)
        if cut:
            reply["truncated"] = _note(budget, cut)
        if size(reply) <= budget:
            break
        reply.pop("truncated", None)
        if not _shrink(reply, 2):
            if cut:
                reply["truncated"] = _note(budget, cut)
            break
        if "other" not in cut:
            cut.append("other")
    return reply
