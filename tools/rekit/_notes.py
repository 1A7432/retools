"""Read the findings ledger that rew writes, without IDA.

The ledger is one append-only JSONL file per database, named after the input
file (`sample.bin.jsonl` for sample.bin or sample.bin.i64), in
findings/ or in $REKIT_FINDINGS. Two record kinds:

    {"kind": "finding", "id", "ts", "source", "goal", "claim", "evidence",
     "confidence", "grounded", "verified"}
    {"kind": "verify", "id", "ts", "verified": true|false, "note"}

Later records win. A repeated finding (same id) refreshes its fields but keeps
an earlier verification unless it carries one itself.

    load(root_filename, ledger_dir=None) -> [finding, ...]
    in_range(notes, lo, hi) -> findings citing an address in [lo, hi)

Pure stdlib; it imports nothing from IDA or from reworker.
"""

from __future__ import annotations

import json
import os
import re

DEFAULT_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "..", "..", "findings"))
DB_SUFFIXES = (".i64", ".idb")
MIN_ADDRESS = 0x1000    # below this a value is an offset or a constant, not an address

_ADDR = re.compile(r"0x[0-9a-fA-F]+|\b(?:sub|loc|locret|nullsub|unk|off|byte|word|dword|"
                   r"qword|stru|asc|j)_([0-9A-Fa-f]+)\b")
_SITE = re.compile(r"(\S+?)\+(0x[0-9a-fA-F]+)")


def resolve_dir(ledger_dir=None):
    return ledger_dir or os.environ.get("REKIT_FINDINGS") or DEFAULT_DIR


def ledger_name(root_filename):
    """`a.bin.i64` and `a.bin` both map to `a.bin.jsonl`."""
    base = os.path.basename(str(root_filename))
    for suffix in DB_SUFFIXES:
        if base.lower().endswith(suffix):
            base = base[:-len(suffix)]
    return base + ".jsonl"


def ledger_path(root_filename, ledger_dir=None):
    return os.path.join(resolve_dir(ledger_dir), ledger_name(root_filename))


def load(root_filename, ledger_dir=None):
    """Current state of every finding, in first-seen order."""
    path = ledger_path(root_filename, ledger_dir)
    notes = {}
    try:
        fh = open(path, encoding="utf-8")
    except FileNotFoundError:
        return []
    with fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict) or not rec.get("id"):
                continue
            kind = rec.get("kind", "finding")
            fid = rec["id"]
            if kind == "finding":
                old = notes.get(fid)
                new = {k: v for k, v in rec.items() if k != "kind"}
                if old is not None and new.get("verified") is None:
                    for key in ("verified", "verified_ts", "verify_note"):
                        if key in old:
                            new[key] = old[key]
                notes[fid] = new
            elif kind == "verify" and fid in notes:
                notes[fid]["verified"] = rec.get("verified")
                notes[fid]["verified_ts"] = rec.get("ts")
                if rec.get("note"):
                    notes[fid]["verify_note"] = rec["note"]
    return list(notes.values())


def addresses(text):
    """Addresses an evidence string cites; `base+0xOFF` counts as base and site.

    Values below MIN_ADDRESS (struct offsets, small constants) are ignored.
    """
    text = str(text)
    found = set()
    for m in _ADDR.finditer(text):
        tok = m.group(0)
        found.add(int(tok, 16) if tok[:2].lower() == "0x" else int(m.group(1), 16))
    site = _SITE.search(text.strip())
    if site:
        bases = addresses(site.group(1))
        off = int(site.group(2), 16)
        found.discard(off)
        found |= bases | {b + off for b in bases}
    return {a for a in found if a >= MIN_ADDRESS}


def cited(note):
    out = set()
    evidence = note.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    for item in evidence:
        out |= addresses(item)
    return out


def in_range(notes, lo, hi):
    """Findings that cite at least one address in [lo, hi)."""
    return [n for n in notes if any(lo <= a < hi for a in cited(n))]
