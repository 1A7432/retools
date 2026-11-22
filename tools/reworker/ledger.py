"""Write side of the findings ledger; rekit/_notes.py is the read side.

One append-only JSONL file per database (see _notes for the record shapes).
Finding ids are a hash of the claim and its evidence, so the same finding
reported twice keeps one id and one verification.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "rekit")))

import _notes  # noqa: E402

CONFIDENCE = ("high", "medium", "low")


class LedgerError(Exception):
    pass


def path_for(db):
    return _notes.ledger_path(db)


def finding_id(claim, evidence):
    key = json.dumps([" ".join(str(claim).split()).lower(),
                      sorted(" ".join(str(e).split()) for e in evidence)])
    return "f-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]


def _append(db, records):
    path = path_for(db)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    return path


def add_findings(db, findings, goal, source, run_dir=None):
    """Append a worker's findings; return their ids."""
    now = time.time()
    records = []
    for f in findings:
        evidence = list(f.get("evidence") or [])
        records.append({"kind": "finding", "id": finding_id(f["claim"], evidence),
                        "ts": round(now, 3), "source": source, "goal": goal,
                        "claim": f["claim"], "evidence": evidence,
                        "confidence": f.get("confidence"), "grounded": f.get("grounded"),
                        "verified": None, "run": run_dir})
    if records:
        _append(db, records)
    return [r["id"] for r in records]


def add_note(db, claim, evidence, confidence="high"):
    """The orchestrator's own, already verified finding."""
    if not claim.strip():
        raise LedgerError("--claim must not be empty")
    if confidence not in CONFIDENCE:
        raise LedgerError("--confidence must be high, medium or low")
    cited = set()
    for e in evidence:
        cited |= _notes.addresses(e)
    if not cited:
        raise LedgerError("--evidence must contain at least one address "
                          "(0x..., sub_XXXX or base+0xOFF)")
    rec = {"kind": "finding", "id": finding_id(claim, evidence), "ts": round(time.time(), 3),
           "source": "orchestrator", "goal": None, "claim": claim,
           "evidence": list(evidence), "confidence": confidence, "grounded": None,
           "verified": True}
    _append(db, [rec])
    return rec


def verify(db, fid, ok, note=None):
    known = {n["id"] for n in _notes.load(db)}
    if fid not in known:
        raise LedgerError("no finding %s in %s" % (fid, path_for(db)))
    rec = {"kind": "verify", "id": fid, "ts": round(time.time(), 3), "verified": bool(ok)}
    if note:
        rec["note"] = note
    _append(db, [rec])
    return rec


def load(db):
    return _notes.load(db)


# Words that mark a claim as a judgement about purpose rather than a statement
# of what the code does. Workers got their facts right far more often than
# their characterisations, so these are checked first.
_JUDGEMENT = ("purpose", "used for", "used to", "responsible for", "intended",
              "likely", "probably", "appears", "seems", "suggests", "presumably",
              "malicious", "backdoor", "injection", "inject", "persistence", "c2",
              "exfiltrat", "keylog", "anti-debug", "obfuscat", "decoy", "implements",
              "用于", "负责", "目的", "可能", "疑似", "应该", "推测", "看起来", "注入", "后门",
              "持久化", "窃取", "诱饵", "实现")


def priority(note):
    """(score, reasons): higher means check sooner. A heuristic for ordering
    the backlog, not a measure of whether the claim is right."""
    score, reasons = 0, []
    if note.get("grounded") is False:
        score += 4
        reasons.append("evidence never appeared in the worker's tool results")
    claim = str(note.get("claim") or "").lower()
    hit = next((w for w in _JUDGEMENT if w in claim), None)
    if hit:
        score += 2
        reasons.append("judgement about purpose (%s)" % hit)
    conf = note.get("confidence")
    if conf == "low":
        score += 2
        reasons.append("low confidence")
    elif conf != "high":
        score += 1
        reasons.append("%s confidence" % (conf or "no"))
    return score, reasons


def backlog(db):
    """Worker findings nobody has ruled on, most urgent first."""
    out = []
    for n in _notes.load(db):
        if n.get("verified") is not None:
            continue
        score, reasons = priority(n)
        out.append({"id": n["id"], "priority": score, "why": reasons,
                    "confidence": n.get("confidence"), "claim": n.get("claim"),
                    "evidence": n.get("evidence") or [], "source": n.get("source")})
    out.sort(key=lambda r: -r["priority"])     # stable: ledger order within a score
    return out


def summary():
    """Per ledger file: how many findings are verified, rejected, still open."""
    root = _notes.resolve_dir()
    rows = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        names = []
    for name in names:
        if not name.endswith(".jsonl"):
            continue
        notes = _notes.load(name[:-len(".jsonl")])
        rows.append({"db": name[:-len(".jsonl")],
                     "open": sum(n.get("verified") is None for n in notes),
                     "verified": sum(n.get("verified") is True for n in notes),
                     "rejected": sum(n.get("verified") is False for n in notes)})
    rows.sort(key=lambda r: -r["open"])
    return rows
