#!/usr/bin/env python3
"""Tests for contract.py. Run: python3 test_contract.py"""

import json
import sys

import contract as c

GOOD = {
    "status": "ok",
    "summary": "sub_3E76224 builds a request object and hands it to sub_67F6880.",
    "findings": [
        {"claim": "allocates a 0x48-byte shared control block",
         "evidence": ["0x3e76224", "sub_3E6DB38+0x240"], "confidence": "high"},
        {"claim": "probably a network request", "evidence": ["sub_67F6880"],
         "confidence": "low"},
    ],
    "unknowns": [],
    "needs": ["rename sub_3E76224"],
}


def run():
    bad = []
    checks = [0]

    def expect(label, cond, detail=None):

        checks[0] += 1
        if not cond:
            bad.append(label if detail is None else "%s %s" % (label, str(detail)[:500]))

    # task normalisation
    t = c.load_task({"goal": " find the C2 ", "targets": [0x401000, "sub_402000"],
                     "questions": "where is the key?", "db": "/x/a.bin"})
    expect("task goal stripped", t["goal"] == "find the C2")
    expect("task int target hexed", t["targets"] == ["0x401000", "sub_402000"])
    expect("task question listified", t["questions"] == ["where is the key?"])
    expect("task defaults", t["mode"] == "strict" and t["max_calls"] == c.DEFAULT_CALLS)
    for raw in ({}, {"goal": ""}, {"goal": "x", "mode": "yolo"},
                {"goal": "x", "max_calls": 0}, {"goal": "x", "bogus": 1}, "str",
                {"goal": "x", "targets": {"a": 1}}):
        try:
            c.load_task(raw)
            bad.append("task should be rejected: %r" % (raw,))
        except c.ContractError:
            pass

    # prompt carries what the worker needs
    p = c.build_prompt(c.load_task({"goal": "G", "db": "/x/a.bin", "targets": ["0x10"],
                                    "questions": ["Q1"], "context": "CTX",
                                    "mode": "free", "max_calls": 7}))
    for needle in ("/x/a.bin", c.REKIT_DIR, "0x10", "1. Q1", "CTX", "at most 7",
                   "plain IDAPython", '"findings"', "rekit.batch([ea, ...]",
                   "max_chars=6000"):
        expect("prompt contains %r" % needle, needle in p)
    expect("prompt drops the orchestrator-only rekit line",
           "use plain IDAPython yourself" not in p)

    # rekit's cheat sheet is read from rekit.py without importing it
    h = c.rekit_help()
    expect("rekit help parsed", h.startswith("rekit ") and "rekit.fn(ea)" in h
           and "%" not in h.split("\n")[0])
    import os, tempfile
    with tempfile.TemporaryDirectory() as d:
        fake = os.path.join(d, "rekit.py")
        with open(fake, "w") as fh:
            fh.write('V = "9"\nN = 5\nHELP = """v%s n=%d\n""" % (V, N)\n')
        expect("rekit help formats its constants", c.rekit_help(fake) == "v9 n=5\n")
        with open(fake, "w") as fh:
            fh.write("X = 1\n")
        try:
            c.rekit_help(fake)
            bad.append("missing HELP should raise")
        except c.ContractError:
            pass
    expect("custom help text is used",
           "HELPTEXT" in c.build_prompt(c.load_task({"goal": "G"}), help_text="HELPTEXT"))
    expect("strict prompt wording",
           "only rekit calls" in c.build_prompt(c.load_task({"goal": "G"})))

    # JSON extraction
    expect("extract plain", c.extract_json('{"a": 1}') == {"a": 1})
    expect("extract fenced", c.extract_json('ok:\n```json\n{"a": {"b": 2}}\n```\nbye')
           == {"a": {"b": 2}})
    expect("extract last object",
           c.extract_json('first {"x": 1} then {"status": "ok"}') == {"status": "ok"})
    expect("extract skips braces in prose",
           c.extract_json('set {a, b} and {"k": "v}"}') == {"k": "v}"})
    expect("extract none", c.extract_json("no json here {") is None)
    expect("extract non-str", c.extract_json(None) is None)

    # address harvesting
    seen = c.addresses('{"fn":"sub_3E76224","at":"0x3e6dd78"}\n3e7623c STP X26\n'
                       'name@0x18d20 loc_AB12 12345 notanaddr')
    expect("addresses", seen == {0x3E76224, 0x3E6DD78, 0x3E7623C, 0x18D20, 0xAB12})

    # validation
    clean, problems = c.validate(GOOD)
    expect("good result validates", problems == [])
    expect("good result kept", len(clean["findings"]) == 2 and "grounded" not in clean["findings"][0])

    clean, problems = c.validate(GOOD, {0x3E76224})
    expect("grounded when cited address was seen", clean["findings"][0]["grounded"] is True)
    expect("ungrounded when never seen", clean["findings"][1]["grounded"] is False)

    clean, _ = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "x", "evidence": ["sub_1000+0x1c"], "confidence": "high"}]}, {0x101C})
    expect("base+offset grounds on the site address", clean["findings"][0]["grounded"])
    clean, _ = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "x", "evidence": ["sub_1000+0x1c"], "confidence": "high"}]}, {0x1C})
    expect("a bare offset does not ground", clean["findings"][0]["grounded"] is False)

    cases = [
        ("not a dict", "text"),
        ("bad status", dict(GOOD, status="done")),
        ("no summary", dict(GOOD, summary="")),
        ("findings not list", dict(GOOD, findings="none")),
        ("finding without evidence", dict(GOOD, findings=[
            {"claim": "x", "evidence": [], "confidence": "high"}])),
        ("evidence without address", dict(GOOD, findings=[
            {"claim": "x", "evidence": ["the main function"], "confidence": "high"}])),
        ("bad confidence", dict(GOOD, findings=[
            {"claim": "x", "evidence": ["0x10"], "confidence": "certain"}])),
        ("empty claim", dict(GOOD, findings=[
            {"claim": " ", "evidence": ["0x10"], "confidence": "low"}])),
        ("needs not list", dict(GOOD, needs={"a": 1})),
    ]
    for label, res in cases:
        _, problems = c.validate(res)
        expect("should report: " + label, bool(problems))

    clean, problems = c.validate({"status": "blocked", "summary": "db would not open",
                                  "findings": [], "unknowns": "everything"})
    expect("blocked with no findings is valid", problems == [])
    expect("string unknowns listified", clean["unknowns"] == ["everything"] and clean["needs"] == [])
    expect("fix prompt lists problems", "- a\n- b" in c.fix_prompt(["a", "b"]))

    # --- grounding against tool results as the worker saw them -------------
    # Shape of a real logged rekit.disasm result (rew-runs/...-2f63/guard.jsonl):
    # ida-mcp returns JSON text, so the disassembly lines are inside a JSON
    # string and the line breaks are the two characters \ and n.
    real = ('{\n  "result": {\n    "dis": {\n      "at": "sub_75C49C",\n'
            '      "lines": 67,\n      "text": "75c49c push ebp\\n75c49d mov ebp, esp\\n'
            '75c49f add esp, 0FFFFFFF0h\\n495bd5 call sub_40B3A4\\n'
            '75c4d1 mov edx, 80000001h"\n    }\n  }\n}')
    expect("real disasm result is JSON", json.loads(real)["result"]["dis"]["at"] == "sub_75C49C")
    seen = c.result_addresses(real)
    for ea in (0x75C49C, 0x75C49D, 0x495BD5, 0x75C4D1, 0x40B3A4):
        expect("instruction address %#x harvested" % ea, ea in seen)
    expect("raw scan also sees escaped line starts", 0x495BD5 in c.addresses(real))
    clean, problems = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "calls sub_40B3A4", "evidence": ["0x495bd5"], "confidence": "high"}]}, seen)
    expect("disasm address grounds", not problems and clean["findings"][0]["grounded"] is True)
    expect("non-JSON results still scanned", 0x401000 in c.result_addresses("401000 push ebp"))
    expect("nested lists and keys scanned", 0x402000 in c.result_addresses(
        json.dumps({"by_fn": [{"sub_402000": ["x"]}]})))

    # --- small values are not addresses ------------------------------------
    expect("floor", c.addresses("a1 + 0x2c9, 0x10, 0xfff, sub_401000, 0x1000")
           == {0x401000, 0x1000})
    clean, problems = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "x", "evidence": ["+0x2c9"], "confidence": "high"}]}, {0x2C9})
    expect("an offset alone is not evidence", problems and "grounded" not in clean["findings"][0])
    clean, problems = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "x", "evidence": ["sub_401000+0x2c9 reads the flag"], "confidence": "high"}]},
        {0x4012C9})
    expect("base+off with trailing words grounds on the site", not problems
           and clean["findings"][0]["grounded"] is True)
    clean, problems = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "x", "evidence": ["sub_401000+0x2c9"], "confidence": "high"}]}, {0x2C9})
    expect("a seen small value does not ground", clean["findings"][0]["grounded"] is False)

    # --- evidence entries and finding count --------------------------------
    _, problems = c.validate({"status": "ok", "summary": "s", "findings": [
        {"claim": "x", "evidence": ["0x401000", "the main loop"], "confidence": "high"}]})
    expect("every evidence entry needs an address",
           len(problems) == 1 and "evidence[2]" in problems[0], problems)
    nine = {"status": "ok", "summary": "s", "findings": [
        {"claim": "c%d" % i, "evidence": ["0x40%04x" % i], "confidence": "low"} for i in range(9)]}
    _, problems = c.validate(nine, max_findings=8)
    expect("too many findings rejected", any("9 findings" in p for p in problems), problems)
    _, problems = c.validate(dict(nine, findings=nine["findings"][:8]), max_findings=8)
    expect("max_findings findings accepted", problems == [], problems)
    _, problems = c.validate({"status": "ok", "summary": "x" * 20000, "findings": [
        {"claim": "y" * 5000, "evidence": ["0x401000 " + "z" * 3000], "confidence": "low"}]})
    expect("length alone is not rejected", problems == [], problems)
    t2 = c.load_task({"goal": "g"})
    expect("max_findings default", t2["max_findings"] == 8)
    expect("max_findings set", c.load_task({"goal": "g", "max_findings": 3})["max_findings"] == 3)
    for v in (0, 51, "3", True):
        try:
            c.load_task({"goal": "g", "max_findings": v})
            bad.append("max_findings %r should be rejected" % (v,))
        except c.ContractError:
            pass
    p = c.build_prompt(c.load_task({"goal": "G", "max_findings": 5}))
    for needle in ("At most 5 findings", "limited context", "at most 4 per finding",
                   "directly in summary", "under needs, not in extra findings"):
        expect("prompt asks for brevity: %r" % needle, needle in p)

    # --- fitting a result into the print budget ----------------------------
    def big_result(n=10):
        conf = ["high", "low", "medium", "low", "high", "medium", "low", "high", "medium", "low"]
        return {"status": "ok", "summary": "short", "unknowns": [], "needs": [],
                "findings": [{"claim": ("claim %d " % i) + "w" * 600,
                              "evidence": ["sub_4%05X+0x10 " % i + "because " * 30,
                                           "0x5%05x" % i],
                              "confidence": conf[i % 10], "grounded": True}
                             for i in range(n)],
                "worker": {"valid": True, "ledger": {"ids": ["f-%d" % i for i in range(n)]}}}
    r = big_result()
    full = c.dump(r)
    same = c.fit_result(r, len(full), "/runs/x/result.json")
    expect("a result within budget is unchanged", same == r and "truncated" not in same)
    expect("fit does not modify its input", c.dump(r) == full)
    sizes = {}
    after_evidence = len(c.dump(c.fit_result(big_result(), len(full) - 100, "/runs/x/result.json")))
    claims_budget = after_evidence - 100
    for budget in (len(full) - 100, claims_budget, 4000, 1500):
        out = c.fit_result(big_result(), budget, "/runs/x/result.json")
        tr = out["truncated"]
        sizes[budget] = tr
        expect("fits %d" % budget, len(c.dump(out)) <= budget, (len(c.dump(out)), tr))
        expect("totals and path kept at %d" % budget, tr["findings_total"] == 10
               and tr["full_result"] == "/runs/x/result.json"
               and tr["findings_shown"] == len(out["findings"]))
    tr = sizes[len(full) - 100]
    expect("evidence is shortened first", tr.get("evidence_shortened") == 10
           and "claims_shortened" not in tr and "dropped" not in tr, tr)
    out = c.fit_result(big_result(), len(full) - 100, "p")
    ev = out["findings"][0]["evidence"][0]
    expect("evidence keeps the address token", ev.startswith("sub_400000+0x10 ")
           and len(ev) <= len("sub_400000+0x10 ") + 61 and ev.endswith("…"), ev)
    expect("short evidence untouched", out["findings"][0]["evidence"][1] == "0x500000")
    tr = sizes[claims_budget]
    expect("claims next", tr.get("claims_shortened") == 10 and "dropped" not in tr, tr)
    tr = sizes[4000]
    expect("then low-confidence findings dropped", tr.get("dropped")
           and all(d["confidence"] == "low" for d in tr["dropped"][:4])
           and tr["dropped"][0] == {"index": 9, "confidence": "low", "id": "f-9"}, tr)
    out = c.fit_result(big_result(), 4000, "p")
    kept = [f["claim"].split()[1] for f in out["findings"]]
    expect("kept findings stay in order", kept == sorted(kept, key=int), kept)
    out = c.fit_result(big_result(), 300, "p")
    expect("an impossible budget says so", out["truncated"].get("over_budget") is True
           and out["findings"] == [])
    raw = {"status": "blocked", "summary": "", "findings": [], "unknowns": ["u" * 900],
           "needs": [], "worker": {"valid": False, "raw": "r" * 20000}}
    out = c.fit_result(raw, 3000, "p")
    expect("raw reply and long list entries are cut last", len(c.dump(out)) <= 3000
           and out["truncated"].get("raw_shortened") and out["truncated"].get(
               "list_entries_shortened") == 1, out["truncated"])
    expect("short_evidence without address", c.short_evidence("x" * 100) == "x" * 60 + "…")

    # --- references in the prompt -------------------------------------------
    p = c.build_prompt(c.load_task({"goal": "G"}))
    for needle in ("Never retype a long value", "[call N ...]", "{{N.path}}",
                   "{{7.buffers.top[name=out].hex}}", "[field=value]", "[a:b]",
                   "say what it was computed from"):
        expect("prompt explains references: %r" % needle, needle in p)

    # --- shortening never splits a filled-in value ---------------------------
    val = "ab" * 300                                     # a 600-char filled value
    claim = "the key is " + val + " and then more words " * 5
    ev = "0x401000 out " + val
    res = {"status": "ok", "summary": "s", "unknowns": ["u " + val], "needs": [],
           "findings": [{"claim": claim, "evidence": [ev, "0x402000"], "confidence": "high"},
                        {"claim": "short", "evidence": ["0x403000"], "confidence": "low"}],
           "worker": {"valid": True}}
    spans = [{"ref": "{{7.buffers.top[0].hex}}", "path": ("findings", 0, "claim"),
              "at": [11, 611]},
             {"ref": "{{7.buffers.top[0].hex}}", "path": ("findings", 0, "evidence", 0),
              "at": [13, 613]},
             {"ref": "{{7.reads[0].hex}}", "path": ("unknowns", 0), "at": [2, 602]}]
    full = len(c.dump(res))
    for budget in (full - 100, full - 700, 900):
        out = c.fit_result(res, budget, "p", spans)
        tr = out["truncated"]
        text = c.dump(out)
        broken = [s for s in (out["findings"][0]["claim"] if out["findings"] else "",
                              *(out["findings"][0]["evidence"] if out["findings"] else []),
                              *out["unknowns"])
                  if "ab" * 5 in s and val not in s]
        expect("no filled value cut in the middle at %d" % budget, not broken, broken)
        expect("cut values are named at %d" % budget, tr.get("filled_omitted")
               and all("{{" in o["ref"] for o in tr["filled_omitted"]), tr)
        expect("marker in the text at %d" % budget,
               "}}: 600 chars omitted]" in text, text[:300])
    out = c.fit_result(res, full - 100, "p", spans)
    expect("evidence marker keeps the address", out["findings"][0]["evidence"][0]
           == "0x401000 out…[{{7.buffers.top[0].hex}}: 600 chars omitted]",
           out["findings"][0]["evidence"][0])
    expect("filled_omitted lists place and ref", out["truncated"]["filled_omitted"] == [
        {"ref": "{{7.buffers.top[0].hex}}", "in": "findings[0].evidence[0]"}],
        out["truncated"])
    out = c.fit_result(res, full - 700, "p", spans)
    expect("claim cut before the value", out["findings"][0]["claim"]
           == "the key is…[{{7.buffers.top[0].hex}}: 600 chars omitted]",
           out["findings"][0]["claim"])
    small = dict(res, findings=[dict(res["findings"][0], claim="the key is " + "ab" * 50)])
    sp = [{"ref": "{{7.ret}}", "path": ("findings", 0, "claim"), "at": [11, 111]}]
    out = c.fit_result(small, len(c.dump(small)) - 50, "p", sp)
    expect("a value that fits is left whole", out["findings"][0]["claim"] == "the key is "
           + "ab" * 50 and not any(o["ref"] == "{{7.ret}}" for o in
                                   out["truncated"].get("filled_omitted", [])), out)
    sp = [{"ref": "{{3.x}}", "path": ("findings", 0, "evidence"), "at": [13, 613]}]
    out = c.fit_result(res, full - 100, "p", sp)
    expect("a lone evidence string's span still applies",
           "{{3.x}}: 600 chars omitted]" in out["findings"][0]["evidence"][0],
           out["findings"][0]["evidence"][0])
    expect("filled values count toward the size", len(c.dump(c.fit_result(
        res, 900, "p", spans))) <= 900 or c.fit_result(res, 900, "p", spans)[
            "truncated"].get("over_budget"))

    for label in bad:
        print("FAIL:", label)
    print("%d checks, %d failed" % (checks[0], len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
