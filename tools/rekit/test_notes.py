#!/usr/bin/env python3
"""Tests for _notes.py. Run: python3 test_notes.py"""

import json
import os
import sys
import tempfile

import _notes as n


def run():
    bad = []

    def expect(label, cond):
        if not cond:
            bad.append(label)

    # address parsing
    expect("hex", n.addresses("0x401A2C") == {0x401A2C})
    expect("autoname", n.addresses("sub_3E6DB38") == {0x3E6DB38})
    expect("site counts base and site",
           n.addresses("sub_3E6DB38+0x240") == {0x3E6DB38, 0x3E6DB38 + 0x240})
    expect("hex base + offset", n.addresses("0x1000+0x1c") == {0x1000, 0x101C})
    expect("name@ea", n.addresses("TForm1.Create@0x8004b4") == {0x8004B4})
    expect("name@ea+off", n.addresses("Foo@0x8000+0x10") == {0x8000, 0x8010})
    expect("loc_", n.addresses("jumps to loc_B5EBA0") == {0xB5EBA0})
    expect("no address", n.addresses("the main function") == set())
    expect("no decimal", n.addresses("12345") == set())
    expect("small values are not addresses", n.addresses("a1 + 0x2c9, 0xfff") == set())
    expect("floor is inclusive", n.addresses("0x1000") == {0x1000})
    expect("site with trailing words",
           n.addresses("sub_401000+0x2c9 reads the flag") == {0x401000, 0x4012C9})

    with tempfile.TemporaryDirectory() as d:
        expect("missing ledger is empty", n.load("nothing.bin", d) == [])
        path = os.path.join(d, "a.bin.jsonl")
        recs = [
            {"kind": "finding", "id": "f1", "ts": 1, "source": "worker:m:strict",
             "goal": "g", "claim": "c1", "evidence": ["sub_1000+0x10"],
             "confidence": "high", "grounded": True, "verified": None},
            {"kind": "finding", "id": "f2", "ts": 2, "source": "worker:m:strict",
             "goal": "g", "claim": "c2", "evidence": ["0x5000", "sub_6000"],
             "confidence": "low", "grounded": False, "verified": None},
            {"kind": "verify", "id": "f1", "ts": 3, "verified": True, "note": "checked"},
            {"kind": "verify", "id": "f2", "ts": 4, "verified": True},
            {"kind": "verify", "id": "f2", "ts": 5, "verified": False, "note": "wrong"},
            {"kind": "verify", "id": "nope", "ts": 6, "verified": True},
            {"kind": "finding", "id": "f1", "ts": 7, "source": "worker:m:free",
             "goal": "g2", "claim": "c1", "evidence": ["sub_1000+0x10"],
             "confidence": "medium", "grounded": True, "verified": None},
            {"kind": "finding", "id": "f3", "ts": 8, "source": "orchestrator",
             "goal": None, "claim": "c3", "evidence": "0x9000",
             "confidence": "high", "grounded": None, "verified": True},
        ]
        with open(path, "w") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
            fh.write("not json\n\n")
        notes = n.load("a.bin.i64", d)
        by = {x["id"]: x for x in notes}
        expect("three findings, verify-only id ignored", sorted(by) == ["f1", "f2", "f3"])
        expect("order kept", [x["id"] for x in notes] == ["f1", "f2", "f3"])
        expect("verification applied", by["f1"]["verified"] is True
               and by["f1"].get("verify_note") == "checked")
        expect("later verification wins", by["f2"]["verified"] is False
               and by["f2"]["verify_note"] == "wrong")
        expect("repeat finding refreshes fields", by["f1"]["source"] == "worker:m:free"
               and by["f1"]["confidence"] == "medium")
        expect("repeat finding keeps verification", by["f1"]["verified"] is True)
        expect("no kind key in output", "kind" not in by["f1"])
        expect("same ledger for a.bin", len(n.load("a.bin", d)) == 3)
        expect("same ledger for a full path", len(n.load("/x/y/a.bin.idb", d)) == 3)

        ids = lambda xs: sorted(x["id"] for x in xs)
        expect("range hits a site", ids(n.in_range(notes, 0x1010, 0x1011)) == ["f1"])
        expect("range hits a base", ids(n.in_range(notes, 0x1000, 0x1001)) == ["f1"])
        expect("half-open upper bound", ids(n.in_range(notes, 0x0, 0x1000)) == [])
        expect("string evidence", ids(n.in_range(notes, 0x9000, 0x9001)) == ["f3"])
        expect("wide range", ids(n.in_range(notes, 0, 0x10000)) == ["f1", "f2", "f3"])
        small = [{"id": "s", "evidence": ["+0x2c9", "0x10"]}]
        expect("offsets never match a low range", n.in_range(small, 0, 0x1000) == [])

        old = os.environ.get("REKIT_FINDINGS")
        os.environ["REKIT_FINDINGS"] = d
        try:
            expect("REKIT_FINDINGS is honoured", len(n.load("a.bin")) == 3)
        finally:
            if old is None:
                del os.environ["REKIT_FINDINGS"]
            else:
                os.environ["REKIT_FINDINGS"] = old
    expect("default dir is <checkout>/findings", n.DEFAULT_DIR == os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(n.__file__)), "..", "..", "findings")))

    for label in bad:
        print("FAIL:", label)
    print("%d failed" % len(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
