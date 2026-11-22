"""Task and result contract between an orchestrator and a re-worker.

The orchestrator hands over a task (dict). The worker model answers with one
JSON object. This module builds the worker prompt, pulls the JSON out of the
model's reply, validates it, and checks that the addresses cited as evidence
really showed up in the worker's own tool results.
"""

from __future__ import annotations

import ast
import json
import os
import re

REKIT_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "..", "rekit"))
CONFIDENCE = ("high", "medium", "low")
STATUS = ("ok", "partial", "blocked")
DEFAULT_CALLS = 25
DEFAULT_FINDINGS = 8
MAX_EVIDENCE = 4
MIN_ADDRESS = 0x1000     # below this a value is an offset or a constant, not an address

MODE_TEXT = {
    "strict": ("In this run execute_python accepts only rekit calls with literal "
               "arguments, for example rekit.fn(0x1234) or "
               '{"a": rekit.xrefs("sub_1234"), "b": rekit.code(0x1234, start=80)}. '
               "Anything else is refused before it runs."),
    "free": ("In this run execute_python also accepts plain IDAPython for reading "
             "(ida_* modules, idautils, idc, and the ida-domain `db` object), for "
             "the lookups rekit does not cover. Prefer rekit where it fits: its "
             "results are smaller and its API cannot be guessed wrong. End a "
             "snippet with an expression to get its value back, and keep results "
             "to a few thousand characters. Calls that change the database or "
             "reach outside IDA are refused."),
}

RESULT_SHAPE = """{
  "status": "ok" | "partial" | "blocked",
  "summary": "the direct answer to the task's questions, in a few sentences",
  "findings": [
    {"claim": "one or two sentences on what the code does, stated so it can be checked",
     "evidence": ["0x3e76224", "sub_3E6DB38+0x240 call to sub_67F6880"],
     "confidence": "high" | "medium" | "low"}
  ],
  "unknowns": ["what you looked for and could not determine"],
  "needs": ["what the orchestrator would have to do or allow for you to go further"]
}"""


class ContractError(Exception):
    pass


# --------------------------------------------------------------------------
# task
# --------------------------------------------------------------------------

def load_task(raw):
    """Normalise a task dict; raise ContractError on a bad one."""
    if not isinstance(raw, dict):
        raise ContractError("task must be a JSON object")
    goal = raw.get("goal")
    if not isinstance(goal, str) or not goal.strip():
        raise ContractError('task needs a non-empty "goal" string')
    task = {"goal": goal.strip()}
    for key in ("targets", "questions"):
        val = raw.get(key) or []
        if isinstance(val, (str, int)):
            val = [val]
        if not isinstance(val, list):
            raise ContractError('"%s" must be a list' % key)
        task[key] = ["%#x" % v if isinstance(v, int) else str(v) for v in val]
    task["context"] = str(raw.get("context") or "").strip()
    task["db"] = str(raw.get("db") or "").strip()
    calls = raw.get("max_calls", DEFAULT_CALLS)
    if not isinstance(calls, int) or not 1 <= calls <= 200:
        raise ContractError('"max_calls" must be an integer from 1 to 200')
    task["max_calls"] = calls
    nfind = raw.get("max_findings", DEFAULT_FINDINGS)
    if not isinstance(nfind, int) or isinstance(nfind, bool) or not 1 <= nfind <= 50:
        raise ContractError('"max_findings" must be an integer from 1 to 50')
    task["max_findings"] = nfind
    mode = raw.get("mode", "strict")
    if mode not in MODE_TEXT:
        raise ContractError('"mode" must be "strict" or "free"')
    task["mode"] = mode
    unknown = set(raw) - {"goal", "targets", "questions", "context", "db",
                          "max_calls", "max_findings", "mode"}
    if unknown:
        raise ContractError("unknown task fields: %s" % ", ".join(sorted(unknown)))
    return task


def rekit_help(path=None):
    """rekit.HELP, read from rekit.py without importing it (that needs IDA)."""
    path = path or os.path.join(REKIT_DIR, "rekit.py")
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    consts = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            continue
        name, value = node.targets[0].id, node.value
        if isinstance(value, ast.Constant):
            consts[name] = value.value
        elif name == "HELP":
            if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod) \
                    and isinstance(value.left, ast.Constant):
                args = value.right.elts if isinstance(value.right, ast.Tuple) \
                    else [value.right]
                vals = tuple(a.value if isinstance(a, ast.Constant) else consts[a.id]
                             for a in args)
                return value.left.value % vals
            raise ContractError("rekit.HELP has an unexpected form")
    raise ContractError("rekit.HELP not found in %s" % path)


def build_prompt(task, help_text=None):
    """The whole message the worker model receives."""
    help_text = help_text if help_text is not None else rekit_help()
    lines = [
        "You are a reverse-engineering worker. An orchestrator model has handed "
        "you one narrow task on an IDA database. The orchestrator does not see "
        "your tool calls, only the JSON object you return at the end, so that "
        "object has to carry the evidence for everything it says.",
        "",
        "## Setup",
        "Database: %s" % task["db"],
        "Open it with the ida open_database tool (path exactly as above; other "
        "databases are refused), then load rekit with execute_python. Put your "
        "first lookups in the same snippet:",
        "",
        "    import sys",
        '    sys.path.insert(0, "%s")' % REKIT_DIR,
        "    import rekit",
        "    rekit.info()",
        "",
        "Only the ida tools are available to you. " + MODE_TEXT[task["mode"]],
        "You have at most %d execute_python calls; after that every call is "
        "refused, so batch lookups into one call where you can (rekit.batch, or "
        "a dict literal of several rekit calls). There is no need to call "
        "rekit.help(); this is its text:" % task["max_calls"],
        "",
    ]
    for line in help_text.rstrip("\n").split("\n"):
        # Advice for the orchestrator, and a call workers are not given:
        # verified notes already ride on function cards, and the full list
        # includes unchecked claims that must not come back as evidence.
        if line.strip().startswith(("read-only", "rekit.notes")):
            continue
        lines.append("    " + line if line else "")
    lines += [
        "",
        "## Task",
        task["goal"],
    ]
    if task["targets"]:
        lines += ["", "Targets: " + ", ".join(task["targets"])]
    if task["questions"]:
        lines += ["", "Questions to answer:"]
        lines += ["%d. %s" % (i, q) for i, q in enumerate(task["questions"], 1)]
    if task["context"]:
        lines += ["", "What the orchestrator already knows:", task["context"]]
    lines += [
        "",
        "## How to work",
        "- Triage with cards first (rekit.fn(ea, code=\"none\") or rekit.batch), "
        "then read code only for the functions that matter to the task.",
        "- Every finding needs evidence: addresses or refs copied from your tool "
        "results. The orchestrator re-checks them, and a finding whose addresses "
        "never appeared in your tool results is thrown away.",
        "- State what the code does. When you infer purpose from thin evidence, "
        "say so and mark the finding low confidence. \"Could not determine\" is a "
        "useful answer; put it under unknowns rather than guessing.",
        "- You only read. Do not rename, comment, retype, patch, save or close "
        "the database. If the task calls for one of those, or for a lookup you "
        "cannot make in this mode, describe it under needs and carry on with "
        "the rest.",
        "- A refused call comes back as an error whose text says why. Read it and "
        "change approach; do not repeat the same call.",
        "- Stay on the task. Interesting side discoveries go in one line under "
        "needs for the orchestrator to decide on.",
        "",
        "## Result",
        "Keep the result short: the orchestrator reads it with a limited "
        "context and pays for every character.",
        "- Answer the task's questions first and directly in summary, in a few "
        "sentences at most.",
        "- At most %d findings, most important first. Each claim is one or two "
        "sentences." % task["max_findings"],
        "- Each evidence entry is a bare address or ref (0x495bd5, sub_402A10, "
        "sub_402A10+0x38), optionally followed by a few words; at most %d per "
        "finding. No sentences in evidence. An import, string or constant is "
        "cited by the address where it is used (sub_402A10+0x38 call MoveFileW)."
        % MAX_EVIDENCE,
        "- Never retype a long value (hex, base64, bytes, a long string) from a "
        "tool result. Each execute_python result is headed [call N ...]; inside "
        "any string of your JSON write {{N.path}} and the exact value is filled "
        "in. The path goes into what the call returned: .key, [index], "
        "[field=value] for a list item, [a:b] for part of a string. Example: "
        "\"claim\": \"sub_401000 writes {{7.buffers.top[name=out].hex}} to out\". "
        "For a value you computed yourself, say what it was computed from.",
        "- Detail the task did not ask for belongs in one line under needs, not "
        "in extra findings.",
        "",
        "When you are done, reply with exactly one JSON object and no other "
        "text, in this shape:",
        "",
        RESULT_SHAPE,
        "",
        "Use status \"partial\" if you ran out of calls or answered only some "
        "questions, and \"blocked\" if you could not start (for example the "
        "database would not open); explain either under unknowns.",
    ]
    return "\n".join(lines)


def fix_prompt(problems):
    """Follow-up message when the reply did not validate."""
    return ("Your reply could not be accepted:\n- " + "\n- ".join(problems) +
            "\n\nSend the result again as exactly one JSON object in the shape "
            "you were given, with no text around it. Do not make further tool "
            "calls unless a finding lacks evidence you still need to look up.")


# --------------------------------------------------------------------------
# result
# --------------------------------------------------------------------------

_CONF_WORDS = {"verified": "high", "confirmed": "high", "certain": "high", "definite": "high",
               "moderate": "medium", "likely": "medium", "probable": "medium", "mid": "medium",
               "uncertain": "low", "guess": "low", "speculative": "low", "unsure": "low"}


def normal_confidence(conf):
    """(confidence, assumed). A missing or unrecognised value is not worth a
    correction round: it becomes "medium" and the finding is flagged."""
    if isinstance(conf, str):
        word = (re.findall(r"[a-z]+", conf.lower()) or [""])[0]
        word = _CONF_WORDS.get(word, word)
        if word in CONFIDENCE:
            return word, False
    return "medium", True


def json_problem(text):
    """Why the reply as a whole is not one JSON object, or None if it is.

    extract_json() falls back to the last object that parses, which for a
    reply with one syntax slip is some nested finding; this names the slip so
    the correction round can fix it instead of guessing.
    """
    if not isinstance(text, str):
        return "the reply did not contain a JSON object"
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return "the reply did not contain a JSON object"
    body = text[start:end + 1]
    try:
        json.loads(body)
    except ValueError as exc:
        pos = getattr(exc, "pos", 0)
        return ("the reply is not valid JSON: %s. The error is at the end of this "
                "excerpt: %r. Strings need plain double quotes and no code or "
                "expressions; send the corrected object in full"
                % (getattr(exc, "msg", str(exc)), body[max(0, pos - 160):pos + 1]))
    return None


def extract_json(text):
    """The last top-level JSON object in a model reply, or None."""
    if not isinstance(text, str):
        return None
    decoder = json.JSONDecoder()
    found = None
    i = text.find("{")
    while i != -1:
        try:
            obj, end = decoder.raw_decode(text, i)
        except ValueError:
            i = text.find("{", i + 1)
            continue
        if isinstance(obj, dict):
            found = obj
        i = text.find("{", end)
    return found


_ADDR = re.compile(r"0x[0-9a-fA-F]+|\b(?:sub|loc|locret|nullsub|unk|off|byte|word|dword|"
                   r"qword|stru|asc|j)_[0-9A-Fa-f]+\b")
# A bare hex word at a line start, as in rekit.disasm text. In tool results
# that are still JSON-encoded a line start is also a literal "\n" or the
# opening quote of a string.
_BARE = re.compile(r'(?m)(?:^|\\n|")[ \t]*([0-9a-fA-F]{5,16})[ \t]')


def addresses(text, floor=MIN_ADDRESS):
    """Every address-like value in a piece of text, as integers >= floor."""
    out = set()
    for tok in _ADDR.findall(text or ""):
        try:
            out.add(int(tok[2:], 16) if tok[:2].lower() == "0x"
                    else int(tok.rsplit("_", 1)[1], 16))
        except ValueError:
            pass
    for tok in _BARE.findall(text or ""):       # disassembly line prefixes
        out.add(int(tok, 16))
    return {a for a in out if a >= floor}


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _strings(item)


def result_addresses(text):
    """Addresses in a tool result as the worker saw it.

    ida-mcp returns JSON text, so the disassembly lines rekit produces sit
    inside JSON strings with escaped newlines. Decode it and scan each string;
    scan the raw text as well, for results that are not JSON.
    """
    found = addresses(text)
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError):
        return found
    for piece in _strings(decoded):
        found |= addresses(piece)
    return found


def _evidence_addrs(item):
    """Addresses an evidence string points at; base+offset counts as both."""
    found = addresses(item)
    m = re.search(r"(\S+)\+(0x[0-9a-fA-F]+)", item.strip())
    if m:
        base = addresses(m.group(1))
        off = int(m.group(2), 16)
        found.discard(off)
        found |= base | {b + off for b in base}
    return found


def validate(result, seen_addresses=None, max_findings=None):
    """Return (clean_result, problems).

    `problems` is empty when the result is acceptable. Length alone is not a
    problem (the wrapper shortens); more than `max_findings` findings is.
    With `seen_addresses` (integers that appeared in the task or in tool
    results, at or above MIN_ADDRESS) each finding gets
    a `grounded` flag: False means none of its evidence was ever shown to the
    worker, so the claim has nothing behind it.
    """
    problems = []
    if not isinstance(result, dict):
        return None, ["the reply did not contain a JSON object"]
    clean = {}
    status = result.get("status")
    if status not in STATUS:
        problems.append('"status" must be one of %s' % ", ".join(STATUS))
    clean["status"] = status
    summary = result.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        problems.append('"summary" must be a non-empty string')
    clean["summary"] = summary if isinstance(summary, str) else ""
    findings = result.get("findings")
    if not isinstance(findings, list):
        problems.append('"findings" must be a list (it may be empty)')
        findings = []
    if max_findings is not None and len(findings) > max_findings:
        problems.append("%d findings; send at most %d, the most important first, "
                        "and put the rest in one line under needs"
                        % (len(findings), max_findings))
    clean["findings"] = []
    for n, item in enumerate(findings, 1):
        where = "findings[%d]" % n
        if not isinstance(item, dict):
            problems.append("%s must be an object" % where)
            continue
        claim, evidence, conf = item.get("claim"), item.get("evidence"), item.get("confidence")
        if not isinstance(claim, str) or not claim.strip():
            problems.append('%s needs a non-empty "claim"' % where)
        conf, assumed = normal_confidence(conf)
        if isinstance(evidence, str):
            evidence = [evidence]
        if not isinstance(evidence, list) or not evidence:
            problems.append('%s needs an "evidence" list with at least one address' % where)
            evidence = []
        evidence = [str(e) for e in evidence]
        cited = set()
        for k, e in enumerate(evidence, 1):
            here = _evidence_addrs(e)
            if not here:
                problems.append('%s evidence[%d] %r contains no address (expected e.g. '
                                '"0x401a2c" or "sub_401000+0x1c", optionally followed '
                                'by a few words)' % (where, k, e[:80]))
            cited |= here
        entry = {"claim": claim, "evidence": evidence, "confidence": conf}
        if assumed:
            entry["confidence_assumed"] = True
        if seen_addresses is not None and cited:
            entry["grounded"] = bool(cited & seen_addresses)
        clean["findings"].append(entry)
    for key in ("unknowns", "needs"):
        val = result.get(key, [])
        if isinstance(val, str):
            val = [val]
        if not isinstance(val, list):
            problems.append('"%s" must be a list of strings' % key)
            val = []
        clean[key] = [str(v) for v in val]
    return clean, problems


# --------------------------------------------------------------------------
# fitting a result into the reader's budget
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\S*(?:0x[0-9a-fA-F]+|\b(?:sub|loc|locret|nullsub|unk|off|byte|"
                    r"word|dword|qword|stru|asc|j)_[0-9A-Fa-f]+)\S*")
_RANK = {"low": 0, "medium": 1, "high": 2}
EVIDENCE_ROOM = 60
CLAIM_ROOM = 400
LIST_ROOM = 200
RAW_ROOM = 1000


def dump(obj):
    """How rew prints a result; its length is what the budget counts."""
    return json.dumps(obj, ensure_ascii=False)


def _cut(text, room):
    return text if len(text) <= room else text[:room].rstrip() + "…"


def _cut_spans(text, cut, spans=()):
    """(text cut at `cut` with "…", [spans lost]). A filled-in value (span
    with "at": [start, end] and "ref") is never split: if the cut falls inside
    one, the text stops before it and a marker names the reference."""
    if len(text) <= cut:
        return text, []
    lost = [s for s in spans if s["at"][1] > cut]
    for sp in sorted(spans, key=lambda s: s["at"][0]):
        s, e = sp["at"]
        if s < cut < e:
            return (text[:s].rstrip() + "…[%s: %d chars omitted]" % (sp["ref"], e - s),
                    [x for x in spans if x["at"][1] > s])
    return text[:cut].rstrip() + "…", lost


def _short_evidence(entry, room=EVIDENCE_ROOM, spans=()):
    m = _TOKEN.search(entry)
    if not m:
        return _cut_spans(entry, room, spans)
    tail = entry[m.end():]
    r0 = m.end() + len(tail) - len(tail.lstrip())
    rest = entry[r0:].rstrip()
    lost = [s for s in spans if s["at"][1] <= m.start()]       # text before the token
    shifted = [dict(s, at=[max(0, s["at"][0] - r0), s["at"][1] - r0])
               for s in spans if s["at"][1] > r0]
    cut, gone = _cut_spans(rest, room, shifted)
    out = m.group(0) + (" " + cut if rest else "")
    if len(out) >= len(entry):
        return entry, []
    return out, lost + gone


def short_evidence(entry, room=EVIDENCE_ROOM):
    """The address token plus at most `room` characters of what follows."""
    return _short_evidence(entry, room)[0]


def _show(path):
    out = path[0]
    for p in path[1:]:
        out += "[%d]" % p if isinstance(p, int) else "." + p
    return out


def _span_index(spans):
    """{field path as printed, 0-based: [span, ...]} for fit_result."""
    out = {}
    for s in spans or ():
        path = tuple(s["path"])
        if path[0] == "findings" and len(path) == 3 and path[2] == "evidence":
            path += (0,)                        # a lone evidence string became a list
        if path[0] in ("unknowns", "needs") and len(path) == 1:
            path += (0,)
        out.setdefault(path, []).append(s)
    return out


def fit_result(result, max_chars, full_path, spans=None):
    """Shorten a result until dump(result) fits max_chars; report every cut.

    Order: evidence entries, then claims, then the lowest-confidence findings
    (latest first among equals) are dropped, then long unknowns/needs entries
    and worker.raw are cut. The result gains a `truncated` object naming each
    step, the totals, and the path of the complete result.

    `spans` are the values rew filled in from references ({"ref", "path",
    "at"}, see refs.fill). A cut never splits one: the text stops before it
    with a "…[{{ref}}: N chars omitted]" marker, and `truncated.filled_omitted`
    lists every filled value a cut removed.
    """
    if len(dump(result)) <= max_chars:
        return result
    r = json.loads(dump(result))
    findings = r.get("findings") or []
    total = len(findings)
    ids = ((r.get("worker") or {}).get("ledger") or {}).get("ids") or []
    note = {"max_chars": max_chars, "full_result": full_path,
            "findings_total": total, "findings_shown": total}
    r["truncated"] = note
    where = _span_index(spans)
    omitted = []

    def lose(path, gone):
        for s in gone:
            item = {"ref": s["ref"], "in": _show(path)}
            if item not in omitted:
                omitted.append(item)
        if omitted:
            note["filled_omitted"] = omitted

    def fits():
        return len(dump(r)) <= max_chars

    n = 0
    for i, f in enumerate(findings):
        old = f.get("evidence") or []
        new = []
        for k, e in enumerate(old):
            out, gone = _short_evidence(e, EVIDENCE_ROOM, where.get(("findings", i, "evidence", k), ()))
            lose(("findings", i, "evidence", k), gone)
            new.append(out)
        n += sum(a != b for a, b in zip(new, old))
        f["evidence"] = new
    if n:
        note["evidence_shortened"] = n
    if fits():
        return r

    n = 0
    for i, f in enumerate(findings):
        if isinstance(f.get("claim"), str) and len(f["claim"]) > CLAIM_ROOM:
            f["claim"], gone = _cut_spans(f["claim"], CLAIM_ROOM,
                                          where.get(("findings", i, "claim"), ()))
            lose(("findings", i, "claim"), gone)
            n += 1
    if n:
        note["claims_shortened"] = n
    if fits():
        return r

    order = sorted(range(total), key=lambda i: (_RANK.get(findings[i].get("confidence"), -1), -i))
    dropped = []
    for i in order:
        if fits():
            break
        dropped.append(i)
        drop = {"index": i, "confidence": findings[i].get("confidence")}
        if i < len(ids):
            drop["id"] = ids[i]
        note.setdefault("dropped", []).append(drop)
        r["findings"] = [f for k, f in enumerate(findings) if k not in dropped]
        note["findings_shown"] = len(r["findings"])
    if fits():
        return r

    n = 0
    for key in ("unknowns", "needs"):
        items = r.get(key) or []
        for k, item in enumerate(items):
            if len(item) > LIST_ROOM:
                items[k], gone = _cut_spans(item, LIST_ROOM, where.get((key, k), ()))
                lose((key, k), gone)
                n += 1
    if n:
        note["list_entries_shortened"] = n
    worker = r.get("worker") or {}
    if isinstance(worker.get("raw"), str) and len(worker["raw"]) > RAW_ROOM:
        worker["raw"] = _cut(worker["raw"], RAW_ROOM)
        note["raw_shortened"] = True
    if not fits():
        note["over_budget"] = True
    return r
