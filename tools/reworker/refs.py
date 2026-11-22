"""Exact values in a worker's answer: references to tool results, and a check
for long values the worker retyped.

The guard proxy numbers every execute_python call that runs (refused and
over-budget calls get no number) and shows the worker "[call N ...]" above
the result. In its final JSON the worker may then write a reference inside
any string, and rew replaces it with the exact value before validation:

    {{7}}                              the whole returned value (if scalar)
    {{7.ret}}                          key `ret` of what call 7 returned
    {{7.buffers.top[0].hex}}           keys and list indexes
    {{7.buffers.top[name=out].hex}}    the first list item whose `name` is out
    {{7.reads[0].hex[0:64]}}           a slice of a string (Python rules)
    {{7.imports.counts[".dynsym!strlen"]}}   a key with dots or spaces
    {{7.stdout}}                       stdout/stderr of the snippet

The path starts inside the returned value (the "result" member of the
ida-mcp reply); a first key the value lacks but the reply has (result,
stdout, stderr) is looked up in the reply.

After filling, long literals still in the summary and claims (16+ hex digits,
or base64-looking runs of 16+ characters) are looked up, ignoring case and
separators, in the task, in every tool result and in the worker's own call
arguments. One found nowhere is reported as unmatched, with the call it
nearly matches when it looks like a typing slip.
"""

from __future__ import annotations

import collections
import difflib
import json
import re

# --------------------------------------------------------------------------
# calls as the worker saw them
# --------------------------------------------------------------------------

WRAPPER_KEYS = {"result", "stdout", "stderr"}


class CallTable:
    """Numbered execute_python results of one run, read from guard.jsonl records.

    A record carries `call_no` (written by the proxy); logs without it are
    numbered in order of allowed execute_python calls.
    """

    def __init__(self, log):
        self.records = {}
        explicit = any(r.get("call_no") is not None for r in log if r.get("event") == "call")
        n = 0
        for rec in log:
            if not (rec.get("event") == "call" and rec.get("tool") == "execute_python"
                    and rec.get("allowed")):
                continue
            n += 1
            no = rec.get("call_no") if explicit else n
            if isinstance(no, int) and rec.get("source") == "ida-mcp":
                self.records[no] = rec
        self._parsed = {}

    def numbers(self):
        return sorted(self.records)

    def get(self, n):
        """(root, wrapper, error) for call n; error is a sentence or None."""
        if n in self._parsed:
            return self._parsed[n]
        rec = self.records.get(n)
        if rec is None:
            nums = self.numbers()
            have = ("calls %d-%d ran" % (nums[0], nums[-1]) if len(nums) > 1
                    else "only call %d ran" % nums[0] if nums
                    else "no execute_python call ran")
            out = (None, None, "there is no call %d: %s (refused calls get no number)"
                   % (n, have))
        else:
            text = rec.get("result")
            try:
                obj = json.loads(text) if isinstance(text, str) else None
            except ValueError:
                obj = None
            if obj is None and rec.get("structured") is not None:
                obj = rec["structured"]
            if rec.get("is_error"):
                out = (None, None, "call %d ended in an error, so it has no value to quote: %s"
                       % (n, (text or "")[:160]))
            elif isinstance(obj, dict) and "result" in obj and set(obj) <= WRAPPER_KEYS:
                out = (obj["result"], obj, None)
            elif obj is not None:
                out = (obj, None, None)
            else:
                out = (text if isinstance(text, str) else "", None, None)
        self._parsed[n] = out
        return out


# --------------------------------------------------------------------------
# parsing and resolving one reference
# --------------------------------------------------------------------------

REF = re.compile(r"\{\{([^{}]{1,300})\}\}")
_ATTEMPT = re.compile(r"^\s*(?:#|call\s*|c)?\d")
_HEAD = re.compile(r"\s*(\d+)")
_KEY = re.compile(r"\.([^.\[\]\s]+)")
_INDEX = re.compile(r"-?\d+$")
_SLICE = re.compile(r"(-?\d*)\s*:\s*(-?\d*)$")
_MATCH = re.compile(r"([^=\s]+)\s*=\s*(.+)$")
_IDENT = re.compile(r"[A-Za-z_$][\w$-]*$")


class RefError(Exception):
    pass


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        if s[0] == '"':
            try:
                return json.loads(s)
            except ValueError:
                pass
        return s[1:-1]
    return s


def parse(body):
    """(call number, steps) of a reference body such as `7.buffers.top[0].hex`.

    A step is ("key", k), ("index", i), ("slice", a, b) or ("match", field, value).
    """
    m = _HEAD.match(body)
    if not m:
        raise RefError("it does not start with a call number")
    call, pos, steps = int(m.group(1)), m.end(), []
    body = body.rstrip()
    while pos < len(body):
        ch = body[pos]
        if ch == ".":
            k = _KEY.match(body, pos)
            if not k:
                raise RefError("nothing usable after the '.' at %r" % body[pos:pos + 20])
            steps.append(("key", k.group(1)))
            pos = k.end()
        elif ch == "[":
            end, quote = pos + 1, None
            while end < len(body):            # find the closing ], honouring quotes
                c = body[end]
                if quote:
                    if c == "\\":
                        end += 1
                    elif c == quote:
                        quote = None
                elif c in "\"'":
                    quote = c
                elif c == "]":
                    break
                end += 1
            if end >= len(body):
                raise RefError("a '[' is not closed")
            inner = body[pos + 1:end].strip()
            pos = end + 1
            if inner[:1] in "\"'":
                steps.append(("key", _unquote(inner)))
            elif _INDEX.match(inner):
                steps.append(("index", int(inner)))
            elif _SLICE.match(inner):
                a, b = _SLICE.match(inner).groups()
                steps.append(("slice", int(a) if a else None, int(b) if b else None))
            elif _MATCH.match(inner):
                f, v = _MATCH.match(inner).groups()
                steps.append(("match", f, _unquote(v)))
            else:
                raise RefError("[%s] is not an index, slice, \"key\" or field=value" % inner)
        else:
            raise RefError("unexpected %r; separate keys with '.' and put indexes in []"
                           % body[pos:pos + 20])
    return call, steps


def show_step(step):
    kind = step[0]
    if kind == "key":
        return "." + step[1] if _IDENT.match(step[1]) else "[%s]" % json.dumps(step[1])
    if kind == "index":
        return "[%d]" % step[1]
    if kind == "slice":
        return "[%s:%s]" % ("" if step[1] is None else step[1], "" if step[2] is None else step[2])
    return "[%s=%s]" % (step[1], step[2])


def show_path(steps):
    return "".join(show_step(s) for s in steps)


def _names(keys, limit=20):
    keys = [str(k) for k in keys]
    more = len(keys) - limit
    return ", ".join(keys[:limit]) + (", ... (%d more)" % more if more > 0 else "")


def _kind(v):
    return ("an object" if isinstance(v, dict) else "a list" if isinstance(v, list)
            else "a string" if isinstance(v, str) else "a number" if isinstance(v, (int, float))
            and not isinstance(v, bool) else "a %s" % type(v).__name__)


def first_leaf(value, steps=(), depth=0):
    """Path to the first scalar under value, for a suggestion."""
    if depth > 8:
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            got = first_leaf(v, steps + (("key", str(k)),), depth + 1)
            if got is not None:
                return got
        return None
    if isinstance(value, list):
        return first_leaf(value[0], steps + (("index", 0),), depth + 1) if value else None
    return steps


def walk(value, steps):
    """Follow steps through value; RefError names where and what exists there."""
    cur, done = value, []
    for step in steps:
        here = "at %s" % show_path(done).lstrip(".") if done else "at the top of the returned value"
        kind = step[0]
        if kind == "key":
            if isinstance(cur, dict):
                if step[1] not in cur:
                    raise RefError("no key %s %s; keys there: %s"
                                   % (json.dumps(step[1]), here, _names(cur)))
                cur = cur[step[1]]
            elif isinstance(cur, list):
                raise RefError("%s is a list of %d items, not an object; use an index "
                               "like [0] or a match like [name=...]" % (here[3:], len(cur)))
            else:
                raise RefError("%s is %s, it has no key %s" % (here[3:], _kind(cur),
                                                               json.dumps(step[1])))
        elif kind == "index":
            if isinstance(cur, list):
                if not -len(cur) <= step[1] < len(cur):
                    raise RefError("index [%d] out of range %s: the list has %d items"
                                   % (step[1], here, len(cur)))
                cur = cur[step[1]]
            elif isinstance(cur, dict) and str(step[1]) in cur:
                cur = cur[str(step[1])]
            elif isinstance(cur, dict):
                raise RefError("%s is an object, not a list; keys there: %s"
                               % (here[3:], _names(cur)))
            else:
                raise RefError("%s is %s, not a list" % (here[3:], _kind(cur)))
        elif kind == "slice":
            if not isinstance(cur, str):
                raise RefError("the slice %s needs a string, but %s is %s"
                               % (show_step(step), here[3:], _kind(cur)))
            cur = cur[step[1]:step[2]]
        else:
            field, want = step[1], step[2]
            if not isinstance(cur, list):
                raise RefError("[%s=...] needs a list of objects, but %s is %s"
                               % (field, here[3:], _kind(cur)))
            for item in cur:
                if isinstance(item, dict) and field in item and _scalar_text(item[field]) == want:
                    cur = item
                    break
            else:
                vals = [_scalar_text(i[field]) for i in cur if isinstance(i, dict) and field in i]
                if vals:
                    raise RefError("no item with %s=%s %s; %s values there: %s"
                                   % (field, want, here, field, _names(vals)))
                keys = sorted({k for i in cur if isinstance(i, dict) for k in i})
                raise RefError("no item %s has a field %s; fields there: %s"
                               % (here, json.dumps(field), _names(keys) or "none"))
        done.append(step)
    return cur


def _scalar_text(v):
    if isinstance(v, str):
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return json.dumps(v)


def resolve(table, body):
    """Exact text for one reference body, or RefError."""
    call, steps = parse(body)
    root, wrapper, error = table.get(call)
    if error:
        raise RefError(error)
    base = root
    if steps and steps[0][0] == "key" and wrapper is not None \
            and not (isinstance(root, dict) and steps[0][1] in root) and steps[0][1] in wrapper:
        base = wrapper
    try:
        value = walk(base, steps)
    except RefError as exc:
        raise RefError("call %d: %s" % (call, exc))
    if isinstance(value, (dict, list)):
        what = ("an object with keys %s" % _names(value) if isinstance(value, dict)
                else "a list of %d items" % len(value))
        hint = first_leaf(value)
        tip = (", e.g. {{%d%s}}" % (call, show_path(list(steps) + list(hint)))
               if hint is not None else "")
        raise RefError("{{%s}} is %s, not a single value; extend the path to one value%s"
                       % (body.strip(), what, tip))
    return _scalar_text(value)


# --------------------------------------------------------------------------
# filling a whole reply
# --------------------------------------------------------------------------

def _fields(obj):
    """(path, getter-free location) of every worker-written string in a reply.

    A path is a tuple: ("summary",), ("findings", i, "claim"),
    ("findings", i, "evidence", k), ("unknowns", k), ("needs", k).
    """
    if isinstance(obj.get("summary"), str):
        yield ("summary",)
    if isinstance(obj.get("findings"), list):
        for i, f in enumerate(obj["findings"]):
            if not isinstance(f, dict):
                continue
            if isinstance(f.get("claim"), str):
                yield ("findings", i, "claim")
            ev = f.get("evidence")
            if isinstance(ev, str):
                yield ("findings", i, "evidence")
            elif isinstance(ev, list):
                for k, e in enumerate(ev):
                    if isinstance(e, str):
                        yield ("findings", i, "evidence", k)
    for key in ("unknowns", "needs"):
        val = obj.get(key)
        if isinstance(val, str):
            yield (key,)
        elif isinstance(val, list):
            for k, e in enumerate(val):
                if isinstance(e, str):
                    yield (key, k)


def _get(obj, path):
    cur = obj
    for p in path:
        cur = cur[p]
    return cur


def _set(obj, path, value):
    cur = obj
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value


def show_where(path, base=0):
    """findings[2].claim style; base=1 for messages to the worker."""
    out = path[0]
    for p in path[1:]:
        out += "[%d]" % (p + base) if isinstance(p, int) else "." + p
    return out


def fill(obj, table):
    """Replace references in a reply (in place). Return (filled, problems).

    `filled` lists {"ref", "path", "at": [start, end]}; offsets are in the
    final string. Problems are sentences for the correction prompt.
    """
    filled, problems = [], []
    if not isinstance(obj, dict):
        return filled, problems
    for path in list(_fields(obj)):
        text = _get(obj, path)
        if "{{" not in text:
            continue
        out, last, spans = [], 0, []
        size = 0
        for m in REF.finditer(text):
            body = m.group(1)
            if not _ATTEMPT.match(body):
                continue                      # ordinary text that happens to use {{ }}
            try:
                value = resolve(table, body)
            except RefError as exc:
                problems.append("%s: the reference %s does not resolve: %s%s"
                                % (show_where(path, 1), m.group(0), exc,
                                   "" if _HEAD.match(body) else
                                   "; write the call number alone, e.g. {{7.ret}}"))
                continue
            piece = text[last:m.start()]
            out.append(piece)
            size += len(piece)
            spans.append({"ref": "{{%s}}" % body.strip(), "path": path,
                          "at": [size, size + len(value)]})
            out.append(value)
            size += len(value)
            last = m.end()
        if spans:
            out.append(text[last:])
            _set(obj, path, "".join(out))
            filled.extend(spans)
    return filled, problems


def mark_findings(clean, filled, key="filled"):
    """Add each finding's references (as written) under `key`."""
    by = collections.defaultdict(list)
    for f in filled:
        if f["path"][0] == "findings":
            by[f["path"][1]].append(f["ref"])
    for i, refs in by.items():
        if i < len(clean.get("findings") or []):
            clean["findings"][i][key] = list(dict.fromkeys(refs))


def filled_meta(filled, limit=20):
    """The bounded list printed under worker.filled."""
    return [{"ref": f["ref"], "in": show_where(f["path"]), "at": f["at"],
             "chars": f["at"][1] - f["at"][0]} for f in filled[:limit]]


# --------------------------------------------------------------------------
# long literals and where they were seen
# --------------------------------------------------------------------------

MIN_HEX = 16
MAX_ANCHORS = 40        # substrings of one value searched for a near miss
MAX_NEAR = 16           # values given a near-miss search per reply
MIN_B64 = 16
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z_])(?:0[xX])?[0-9a-fA-F]{%d,}(?![0-9A-Za-z_])" % MIN_HEX)
_HEX_GROUPED = re.compile(
    r"(?<![0-9A-Za-z_])(?:[0-9a-fA-F]{2}(?:[ :-][0-9a-fA-F]{2}){7,}"
    r"|[0-9a-fA-F]{4}(?:[ :-][0-9a-fA-F]{4}){3,}"
    r"|[0-9a-fA-F]{8}(?:[ :-][0-9a-fA-F]{8})+)(?![0-9A-Za-z_])")
_B64 = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/]{%d,}={0,2}(?![A-Za-z0-9+/_=-])" % MIN_B64)
_ESC = re.compile(r"\\[nrt]")


def norm_hex(text):
    return re.sub(r"[^0-9a-f]", "", _ESC.sub(" ", text.lower()).replace("0x", ""))


def norm_b64(text):
    return re.sub(r"[^0-9a-z+/]", "", _ESC.sub(" ", text.lower()))


def looks_b64(raw):
    """Random-looking base64 rather than CamelCase names, paths or address lists.

    Random base64 has short lowercase runs and capitals in runs; CamelCase
    names (FindWindowW/SendMessageW, kernel32GetModuleHandleW) have long
    lowercase runs and single capitals.
    """
    body = raw.rstrip("=")
    if "0x" in body or not any(c.isdigit() for c in body):
        return False
    if all(re.fullmatch(r"[0-9A-F]+h?|[0-9a-f]+", p) for p in re.split(r"[+/]", body) if p):
        return False                          # IDA-style constants: 0EC238FE7h/0C1A2h
    lows = [len(x) for x in re.findall(r"[a-z]+", body)]
    ups = [len(x) for x in re.findall(r"[A-Z]+", body)]
    if not lows or not ups:
        return False
    return sum(lows) / len(lows) <= 3.0 or len(ups) >= 3 and sum(ups) / len(ups) >= 1.4


def literals(text, masks=()):
    """[(start, end, raw, kind, normalised)] of long values in text.

    masks: (start, end) spans to ignore (filled-in values).
    """
    if masks:
        chars = list(text)
        for s, e in masks:
            chars[s:e] = " " * (e - s)
        text = "".join(chars)
    found, taken = [], []

    def free(s, e):
        return not any(s < te and ts < e for ts, te in taken)

    for m in _HEX_GROUPED.finditer(text):
        raw = m.group(0)
        groups = re.split(r"[ :-]", raw)
        if len(groups[0]) > 2 and not re.search(r"[a-fA-F]", raw):
            continue                          # a list of decimal numbers
        found.append((m.start(), m.end(), raw, "hex", norm_hex(raw)))
        taken.append((m.start(), m.end()))
    for m in _HEX_RUN.finditer(text):
        if free(m.start(), m.end()):
            found.append((m.start(), m.end(), m.group(0), "hex", norm_hex(m.group(0))))
            taken.append((m.start(), m.end()))
    for m in _B64.finditer(text):
        raw = m.group(0)
        if not free(m.start(), m.end()):
            continue
        if not looks_b64(raw):
            continue
        found.append((m.start(), m.end(), raw, "b64", norm_b64(raw)))
        taken.append((m.start(), m.end()))
    found.sort()
    return found


class Haystack:
    """Everything the worker was shown or wrote into a call, normalised once."""

    def __init__(self, task_text, log):
        self.sources = []                     # (label, call_no or None, raw text)
        self.sources.append(("the task", None, task_text or ""))
        n = 0
        explicit = any(r.get("call_no") is not None for r in log if r.get("event") == "call")
        for rec in log:
            if rec.get("event") != "call":
                continue
            if rec.get("tool") == "execute_python" and rec.get("allowed"):
                n += 1
                no = rec.get("call_no") if explicit else n
                code = (rec.get("arguments") or {}).get("code") \
                    if isinstance(rec.get("arguments"), dict) else None
                if isinstance(code, str):
                    self.sources.append(("the arguments of call %s" % no, None, code))
                if rec.get("source") == "ida-mcp" and isinstance(rec.get("result"), str):
                    self.sources.append(("call %s" % no, no, rec["result"]))
            elif rec.get("source") == "ida-mcp" and isinstance(rec.get("result"), str):
                self.sources.append(("a %s result" % rec.get("tool"), None, rec["result"]))
        self._soups = {}

    def soups(self, kind):
        if kind not in self._soups:
            fn = norm_hex if kind == "hex" else norm_b64
            self._soups[kind] = [fn(raw) for _, _, raw in self.sources]
        return self._soups[kind]

    def seen(self, norm, kind):
        return any(norm in soup for soup in self.soups(kind))

    def near(self, norm, kind):
        """Best near match: {"source", "call", "distance", "length", "match"} or None."""
        n = len(norm)
        limit = max(2, n // 10)
        chunk = max(6, min(12, n // 4))
        step = max(1, chunk // 2)
        offs = sorted(set(list(range(0, n - chunk + 1, step)) + [n - chunk]))
        if len(offs) > MAX_ANCHORS:           # long values: spread a fixed number of anchors
            offs = sorted({offs[i * (len(offs) - 1) // (MAX_ANCHORS - 1)]
                           for i in range(MAX_ANCHORS)})
        bucket = max(4, limit)
        votes = collections.Counter()
        first = {}
        soups = self.soups(kind)
        for off in offs:
            piece = norm[off:off + chunk]
            if len(set(piece)) < 3:
                continue                      # 000000... matches everywhere
            for si, soup in enumerate(soups):
                pos, hits = soup.find(piece), 0
                while pos != -1 and hits < 40:
                    key = (si, (pos - off) // bucket)
                    votes[key] += 1
                    first.setdefault(key, pos - off)
                    pos = soup.find(piece, pos + 1)
                    hits += 1
        best = None
        for key, _ in votes.most_common(6):
            si, start = key[0], first[key]
            soup = soups[si]
            lo = max(0, start - limit - bucket)
            window = soup[lo:start + n + limit + bucket]
            sm = difflib.SequenceMatcher(None, norm, window, autojunk=False)
            blocks = [b for b in sm.get_matching_blocks() if b.size >= 3]
            if not blocks:
                continue
            matched = sum(b.size for b in blocks)
            s, e = blocks[0].b, blocks[-1].b + blocks[-1].size
            # unmatched ends of the needle count as differences too
            s -= blocks[0].a
            e += n - (blocks[-1].a + blocks[-1].size)
            s, e = max(0, s), min(len(window), e)
            dist = max(n, e - s) - matched
            if dist <= limit and (best is None or dist < best["distance"]):
                label, call, _ = self.sources[si]
                best = {"source": label, "call": call, "distance": dist,
                        "length": e - s, "match": window[s:e]}
        return best


def _leaves(value, steps=(), depth=0, out=None):
    out = [] if out is None else out
    if len(out) > 20000 or depth > 12:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            _leaves(v, steps + (("key", str(k)),), depth + 1, out)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _leaves(v, steps + (("index", i),), depth + 1, out)
    elif isinstance(value, str) or isinstance(value, (int, float)) and not isinstance(value, bool):
        out.append((steps, value))
    return out


def suggest(table, call, match, kind):
    """A reference into `call` whose value is `match` (normalised), or None."""
    root, _, error = table.get(call)
    if error:
        return None
    fn = norm_hex if kind == "hex" else norm_b64
    best = None
    for steps, value in _leaves(root):
        raw = value if isinstance(value, str) else json.dumps(value)
        if len(raw) < len(match) or match not in fn(raw):
            continue
        low = raw.lower()
        if fn(raw) == match:
            ref = "{{%d%s}}" % (call, show_path(steps))
        else:
            a = low.find(match)
            if a < 0:
                continue
            ref = "{{%d%s[%d:%d]}}" % (call, show_path(steps), a, a + len(match))
        if best is None or len(raw) < best[0]:
            best = (len(raw), ref)
    return best[1] if best else None


def preview(raw, head=12, tail=8):
    return raw if len(raw) <= head + tail + 3 else raw[:head] + "…" + raw[-tail:]


def unmatched(clean, filled, haystack_factory, table):
    """Long literals in summary and claims that match nothing the worker saw.

    Returns a list of {"value", "chars", "paths": [path...], "near": {...}?}
    in order of first appearance. haystack_factory() builds the Haystack only
    when there is something to look up.
    """
    masks = collections.defaultdict(list)
    for f in filled:
        masks[f["path"]].append(tuple(f["at"]))
    fields = []
    if isinstance(clean.get("summary"), str):
        fields.append((("summary",), clean["summary"]))
    for i, f in enumerate(clean.get("findings") or []):
        if isinstance(f.get("claim"), str):
            fields.append((("findings", i, "claim"), f["claim"]))
    lits = []
    for path, text in fields:
        for lit in literals(text, masks.get(path, ())):
            lits.append((path, lit))
    if not lits:
        return []
    hay = haystack_factory()
    out, index = [], {}
    for path, (_, _, raw, kind, norm) in lits:
        if norm in index:
            if index[norm] is not None and path not in out[index[norm]]["paths"]:
                out[index[norm]]["paths"].append(path)
            continue
        if hay.seen(norm, kind):
            index[norm] = None
            continue
        entry = {"value": raw, "chars": len(raw), "kind": kind, "paths": [path]}
        near = hay.near(norm, kind) if len(out) < MAX_NEAR else None
        if near:
            info = {"source": near["source"], "distance": near["distance"],
                    "length": near["length"]}
            if near["call"] is not None:
                info["call"] = near["call"]
                ref = suggest(table, near["call"], near["match"], kind)
                if ref:
                    info["ref"] = ref
            entry["near"] = info
        index[norm] = len(out)
        out.append(entry)
    return out


def unmatched_meta(entries, asked, limit=8):
    """The bounded object printed under worker.unmatched."""
    values = []
    for e in entries[:limit]:
        v = {"value": preview(e["value"]), "chars": e["chars"],
             "in": [show_where(p) for p in e["paths"]]}
        if "near" in e:
            v["near"] = e["near"]
        values.append(v)
    return {"total": len(entries), "asked": asked, "values": values}


def mark_unmatched(clean, entries):
    for e in entries:
        for p in e["paths"]:
            if p[0] == "findings":
                clean["findings"][p[1]]["unmatched"] = True


def unmatched_prompt(entries, limit=8):
    """One correction round: replace each value with a reference or say how it was derived."""
    lines = []
    for e in entries[:limit]:
        where = " and ".join(show_where(p, 1) for p in e["paths"])
        val = '"%s" (%d chars)' % (preview(e["value"], 16, 10), e["chars"])
        near = e.get("near")
        if near:
            if near["length"] == e["chars"]:
                diff = "same length, %d characters differ" % near["distance"]
            else:
                diff = "%d characters there, %d in yours" % (near["length"], e["chars"])
            line = ("%s in %s nearly matches a value in %s (%s), almost certainly a typing "
                    "slip. " % (val, where, near["source"], diff))
            line += ("Write %s instead." % near["ref"] if near.get("ref") else
                     "Replace it with a {{N.path}} reference to that value.")
        else:
            line = ("%s in %s matches nothing in your tool results or the task. If you "
                    "copied it, replace it with a {{N.path}} reference; if you computed "
                    "it, keep it and say in the same sentence what it was derived from."
                    % (val, where))
        lines.append(line)
    more = len(entries) - limit
    if more > 0:
        lines.append("%d more such values; treat them the same way." % more)
    return ("Your result is accepted, but long values in it were typed rather than "
            "quoted:\n- " + "\n- ".join(lines) +
            "\n\nSend the whole result again as exactly one JSON object, changed only "
            "where these values are. Do not make tool calls.")
