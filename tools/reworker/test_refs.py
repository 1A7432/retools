#!/usr/bin/env python3
"""Tests for refs.py (references and unmatched long values). Run: python3 test_refs.py"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import refs  # noqa: E402

# Shaped like real rekit.emu replies in rew-runs/*/guard.jsonl.
OUT_HEX = "dc8f7629a85b42f544f7de9110c3aa5dac5f46f9782b12c514c7ae61e0937a2d"
EMU = {"stop": {"reason": "returned", "at": "0x495c08"}, "insns": 97, "ret": "0x2",
       "buffers": {"total": 2, "top": [
           {"name": "a1", "addr": "0x7fff0000", "size": 32, "changed": True,
            "hex": "00" * 32, "text": "." * 32},
           {"name": "out", "addr": "0x7fff1000", "size": 32, "changed": True,
            "hex": OUT_HEX, "text": "..v).[B.D......"}]},
       "reads": [{"addr": "0x1004f66", "hex": OUT_HEX * 2, "cstr": "bOMicyE0JAPRI4F8HtUks8"}],
       "regs": {"rax": "0xffffffff8033194b", "rip": "0x495c08"},
       "imports": {"counts": {".dynsym!strlen@@GLIBC_2.2.5": 3}},
       "writes": {"total": 0, "top": []}}


def call(n, result, code="rekit.emu('sub_495BD0')", wrap=True, **kw):
    text = json.dumps({"result": result, "stdout": "printed\n", "stderr": ""}, indent=2) \
        if wrap else result
    rec = {"event": "call", "tool": "execute_python", "arguments": {"code": code},
           "allowed": True, "result": text, "is_error": False, "source": "ida-mcp",
           "call_no": n}
    rec.update(kw)
    return rec


LOG = [
    {"event": "start"},
    {"event": "call", "tool": "open_database", "allowed": True, "source": "ida-mcp",
     "result": '{"opened": "/x/a.bin"}'},
    call(1, {"fn": "sub_401000", "callees": ["sub_402A10"]}),
    {"event": "call", "tool": "execute_python", "allowed": False, "source": "guard",
     "arguments": {"code": "import os"}, "result": "refused", "is_error": True},
    call(2, EMU),
    call(3, "a plain string value 0x401000"),
    call(4, "Traceback: NameError", wrap=False, is_error=True),
    call(5, {"check": EMU, "xrefs": {"to": "sub_495BD0", "total": 1}},
         code='{"check": rekit.emu("sub_495BD0", args=[{"bytes": "0011223344556677aabb"}])}'),
]


def run():
    bad = []
    checks = [0]

    def expect(label, cond, detail=""):
        checks[0] += 1
        if not cond:
            bad.append("%s %s" % (label, str(detail)[:600]))

    table = refs.CallTable(LOG)
    expect("numbered calls", table.numbers() == [1, 2, 3, 4, 5], table.numbers())
    implicit = refs.CallTable([dict(r, call_no=None) if r.get("call_no") else r for r in LOG])
    expect("logs without call_no are numbered in order",
           implicit.numbers() == [1, 2, 3, 4, 5], implicit.numbers())

    # -- every kind of path ---------------------------------------------------
    cases = {
        "2.ret": "0x2",
        "2.insns": "97",
        "2.stop.at": "0x495c08",
        "2.buffers.top[1].hex": OUT_HEX,
        "2.buffers.top[-1].name": "out",
        "2.buffers.top[name=out].hex": OUT_HEX,
        '2.buffers.top[name="out"].addr': "0x7fff1000",
        "2.buffers.top[name=out].changed": "true",
        "2.reads[0].hex[0:16]": OUT_HEX[:16],
        "2.reads[0].hex[64:]": OUT_HEX,
        "2.reads[0].hex[-8:]": OUT_HEX[-8:],
        "2.regs.rax": "0xffffffff8033194b",
        '2.imports.counts[".dynsym!strlen@@GLIBC_2.2.5"]': "3",
        "2.result.ret": "0x2",
        "2.stdout": "printed\n",
        "3": "a plain string value 0x401000",
        "3[0:7]": "a plain",
        "5.check.buffers.top[name=out].hex": OUT_HEX,
        " 1.fn ": "sub_401000",
    }
    for body, want in cases.items():
        try:
            got = refs.resolve(table, body)
        except refs.RefError as exc:
            got = "RefError: %s" % exc
        expect("resolve {{%s}}" % body, got == want, got)

    # -- references that do not resolve, and what the message says ---------------
    errors = {
        "9.ret": ["no call 9", "calls 1-5 ran", "refused calls get no number"],
        "2.rett": ['no key "rett"', "keys there:", "ret", "buffers", "stop"],
        "2.buffers.top[0].hexx": ['no key "hexx" at buffers.top[0]',
                                  "name, addr, size, changed, hex, text"],
        "2.buffers.top[5].hex": ["out of range", "2 items"],
        "2.buffers.top[name=key].hex": ["no item with name=key", "a1, out"],
        "2.buffers.top[nm=out].hex": ['no item at buffers.top has a field "nm"', "name"],
        "2.buffers.top.hex": ["list of 2 items", "[0]", "[name=...]"],
        "2.buffers": ["an object with keys total, top", "not a single value",
                      "{{2.buffers.total}}"],
        "2.buffers.top[0]": ["not a single value", "{{2.buffers.top[0].name}}"],
        "2.insns[0:2]": ["needs a string", "a number"],
        "4.ret": ["ended in an error", "NameError"],
        "2.buffers.top[x]": ["not an index, slice"],
        "2..ret": ["nothing usable"],
        "2 ret": ["unexpected"],
    }
    for body, needles in errors.items():
        try:
            got = "resolved to %r" % refs.resolve(table, body)
        except refs.RefError as exc:
            got = str(exc)
        for n in needles:
            expect("error for {{%s}} mentions %r" % (body, n), n in got, got)

    # -- filling a reply ---------------------------------------------------------
    reply = {"status": "ok",
             "summary": "out is {{2.buffers.top[name=out].hex}}; ret {{2.ret}}.",
             "findings": [
                 {"claim": "returns {{2.ret}} after {{2.insns}} instructions",
                  "evidence": ["{{2.stop.at}} ret", "sub_495BD0"], "confidence": "high"},
                 {"claim": "set {{a, b}} and {{ x }} stay text; so does {{}}",
                  "evidence": "0x401000 {{1.fn}}", "confidence": "low"}],
             "unknowns": ["{{2.regs.rax}}"], "needs": []}
    filled, problems = refs.fill(reply, table)
    expect("fill: no problems", problems == [], problems)
    s = reply["summary"]
    expect("fill: summary", s == "out is %s; ret 0x2." % OUT_HEX, s)
    expect("fill: spans point at the values", all(
        refs._get(reply, f["path"])[f["at"][0]:f["at"][1]] == refs.resolve(
            table, f["ref"][2:-2]) for f in filled), filled)
    expect("fill: claim, evidence list, evidence string, unknowns",
           reply["findings"][0]["claim"] == "returns 0x2 after 97 instructions"
           and reply["findings"][0]["evidence"][0] == "0x495c08 ret"
           and reply["findings"][1]["evidence"] == "0x401000 sub_401000"
           and reply["unknowns"] == ["0xffffffff8033194b"], reply)
    expect("fill: ordinary braces untouched", reply["findings"][1]["claim"]
           == "set {{a, b}} and {{ x }} stay text; so does {{}}")
    expect("fill: refs recorded in order", [f["ref"] for f in filled] == [
        "{{2.buffers.top[name=out].hex}}", "{{2.ret}}", "{{2.ret}}", "{{2.insns}}",
        "{{2.stop.at}}", "{{1.fn}}", "{{2.regs.rax}}"], [f["ref"] for f in filled])
    meta = refs.filled_meta(filled)
    expect("filled meta", meta[0] == {"ref": "{{2.buffers.top[name=out].hex}}",
                                      "in": "summary", "at": [7, 71], "chars": 64}
           and meta[2]["in"] == "findings[0].claim"
           and meta[4]["in"] == "findings[0].evidence[0]", meta)
    expect("filled meta is bounded", len(refs.filled_meta(filled * 10, 20)) == 20)
    clean = {"findings": [{"claim": "a"}, {"claim": "b"}]}
    refs.mark_findings(clean, filled)
    expect("findings marked with their refs", clean["findings"][0]["filled"]
           == ["{{2.ret}}", "{{2.insns}}", "{{2.stop.at}}"]
           and clean["findings"][1]["filled"] == ["{{1.fn}}"], clean)

    reply = {"summary": "x {{9.ret}} y", "findings": [
        {"claim": "{{2.buffers.top[0].hexx}}", "evidence": ["{{call 2.ret}}"]}]}
    filled, problems = refs.fill(reply, table)
    expect("unresolved: one problem each", len(problems) == 3, problems)
    expect("unresolved: named by place and reference",
           problems[0].startswith("summary: the reference {{9.ret}} does not resolve")
           and problems[1].startswith("findings[1].claim: the reference "
                                      "{{2.buffers.top[0].hexx}} does not resolve")
           and "keys there: name, addr, size, changed, hex, text" in problems[1]
           and problems[2].startswith("findings[1].evidence[1]: ")
           and "e.g. {{7.ret}}" in problems[2], problems)
    expect("unresolved text is left as written", reply["summary"] == "x {{9.ret}} y")

    # -- long literals -----------------------------------------------------------
    def kinds(text, masks=()):
        return [(l[2], l[3]) for l in refs.literals(text, masks)]

    expect("hex run", kinds("key %s." % OUT_HEX) == [(OUT_HEX, "hex")])
    expect("0x prefix kept", kinds("v=0x%s" % OUT_HEX[:16]) == [("0x" + OUT_HEX[:16], "hex")])
    expect("15 digits is short", kinds("v=%s" % OUT_HEX[:15]) == [])
    expect("separated bytes", kinds("bytes dc 8f 76 29 a8 5b 42 f5 then")
           == [("dc 8f 76 29 a8 5b 42 f5", "hex")])
    expect("dwords", kinds("words dc8f7629 a85b42f5") == [("dc8f7629 a85b42f5", "hex")])
    expect("decimal lists are not hex", kinds("sizes 1024 2048 4096 8192") == [])
    expect("address lists are not one value", kinds("0x401000, 0x402000, 0x403000") == [])
    expect("base64", kinds("cstr bOMicyE0JAPRI4F8HtUks8llGMGeb.") ==
           [("bOMicyE0JAPRI4F8HtUks8llGMGeb", "b64")])
    expect("names and paths are not base64", kinds(
        "FindWindowW/SendMessageW kernel32GetModuleHandleW /Users/x/ClaudeCode2 "
        "KernelMsgService+0x18 0EC238FE7h/0C1A2B3C4h encrypt/sign/KDF sub_4010001234567890") == [])
    text = "a %s b" % OUT_HEX
    expect("masked spans are skipped", kinds(text, [(2, 66)]) == [])

    # -- unmatched values --------------------------------------------------------
    task = "Find the key. The orchestrator saw 5566778899aabbccddeeff00 in a dump."
    built = []

    def hay():
        built.append(1)
        return refs.Haystack(task, LOG)

    def check(claim, summary="s", filled=()):
        clean = {"summary": summary, "findings": [{"claim": claim, "evidence": ["0x401000"]}]}
        return refs.unmatched(clean, list(filled), hay, table), clean

    um, _ = check("no long values here, 0x401000")
    expect("no literals, no haystack", um == [] and built == [])
    um, _ = check("out is %s" % OUT_HEX.upper())
    expect("exact, other case: seen", um == [], um)
    spaced = " ".join(OUT_HEX[i:i + 2] for i in range(0, 32, 2))
    um, _ = check("first bytes %s" % spaced)
    expect("exact, with separators: seen", um == [], um)
    um, _ = check("input 0011223344556677aabb was passed")
    expect("the worker's own call arguments count as seen", um == [], um)
    um, _ = check("dump value 5566778899AABBCCDDEEFF00")
    expect("the task counts as seen", um == [], um)
    um, _ = check("rax 0xffffffff8033194b")
    expect("register value seen", um == [], um)

    typo = OUT_HEX[:20] + OUT_HEX[23:]                      # three characters lost
    um, clean = check("out is %s" % typo, summary="key %s" % typo)
    expect("near miss: flagged once for both places", len(um) == 1
           and [refs.show_where(p) for p in um[0]["paths"]] == ["summary", "findings[0].claim"],
           um)
    near = um[0].get("near") or {}
    expect("near miss names the call and the reference", near.get("call") == 2
           and near.get("distance") == 3 and near.get("length") == 64
           and near.get("ref") in ("{{2.buffers.top[1].hex}}", "{{2.reads[0].hex[0:64]}}"),
           near)
    changed = OUT_HEX[:30] + "0000" + OUT_HEX[34:]
    um, _ = check("out is %s" % changed)
    near = um[0].get("near") if um else {}
    expect("near miss: same length, short changed run", near and near["length"] == 64
           and near["distance"] <= 4 and near["call"] == 2, um)
    derived = "7b1c0e9f33a2d4c85e6f0a1b2c3d4e5f"
    um, clean = check("sha of it is %s" % derived)
    expect("derived: flagged without a near match", len(um) == 1 and "near" not in um[0], um)
    refs.mark_unmatched(clean, um)
    expect("finding marked", clean["findings"][0].get("unmatched") is True, clean)
    meta = refs.unmatched_meta(um, asked=False)
    expect("meta shape", meta == {"total": 1, "asked": False, "values": [
        {"value": "7b1c0e9f33a2…2c3d4e5f", "chars": 32, "in": ["findings[0].claim"]}]}, meta)
    expect("meta is bounded", len(refs.unmatched_meta(um * 20, True, 8)["values"]) == 8
           and refs.unmatched_meta(um * 20, True, 8)["total"] == 20)
    s = "key {{2.buffers.top[name=out].hex}}"
    reply = {"summary": s, "findings": [{"claim": "c", "evidence": ["0x401000"]}]}
    filled, _ = refs.fill(reply, table)
    um = refs.unmatched(reply, filled, hay, table)
    expect("a filled value is not checked again", um == [], um)
    um, _ = check("b64 bOMicyE0JAPRI4F8HtUks8 and bOMicyE0JAPRI4F8HtUkz8")
    expect("base64: seen one passes, a near miss is flagged", len(um) == 1
           and um[0]["value"] == "bOMicyE0JAPRI4F8HtUkz8" and um[0]["near"]["call"] == 2, um)

    um, _ = check("out is %s; sha %s" % (typo, derived))
    p = refs.unmatched_prompt(um)
    expect("prompt: near miss says typing slip and gives the reference",
           "nearly matches a value in call 2" in p and "typing slip" in p
           and ("Write {{2.buffers.top[1].hex}} instead" in p
                or "Write {{2.reads[0].hex[0:64]}} instead" in p), p)
    expect("prompt: derived value asks what from", "what it was derived from" in p
           and "in findings[1].claim" in p and "Do not make tool calls" in p, p)

    # -- speed on megabytes of tool output ----------------------------------------
    big = [{"event": "start"}]
    for n in range(1, 31):
        bufs = [{"name": "b%d" % i, "hex": os.urandom(160).hex() + "00" * 200}
                for i in range(100)]
        big.append(call(n, {"buffers": {"top": bufs}}))
    target = json.loads(big[20]["result"])["result"]["buffers"]["top"][42]["hex"][:360]
    slip = target[:100] + target[103:]
    started = time.time()
    btable = refs.CallTable(big)
    um = refs.unmatched({"summary": "s", "findings": [
        {"claim": "a %s b %s c %s" % (slip, os.urandom(32).hex(), "00" * 40)}]}, [],
        lambda: refs.Haystack("t", big), btable)
    took = time.time() - started
    size = sum(len(r.get("result") or "") for r in big)
    expect("megabytes: near miss found", len(um) == 2 and um[0]["near"]["call"] == 20
           and um[0]["near"]["ref"] == "{{20.buffers.top[42].hex[0:360]}}", um)
    expect("megabytes: fast (%.1f MB in %.2fs)" % (size / 1e6, took), took < 3.0, took)

    for label in bad:
        print("FAIL:", label)
    print("%d checks, %d failed" % (checks[0], len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
