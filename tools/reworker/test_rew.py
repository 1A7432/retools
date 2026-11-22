#!/usr/bin/env python3
"""Tests for rew against fake_dsh.py (no model, no IDA). Run: python3 test_rew.py"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REW = os.path.join(HERE, "rew")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "rekit"))

import contract  # noqa: E402
import _notes  # noqa: E402

GOOD = {"status": "ok", "summary": "sub_401000 calls sub_402A10.",
        "findings": [
            {"claim": "sub_401000 calls sub_402A10", "evidence": ["sub_401000+0x1c", "sub_402A10"],
             "confidence": "high"},
            {"claim": "something deep in a long result", "evidence": ["0x4beef0"],
             "confidence": "medium"},
            {"claim": "made up", "evidence": ["0x777777"], "confidence": "low"}],
        "unknowns": [], "needs": []}
CALL = {"call": "mcp__ida__execute_python", "input": {"code": "rekit.fn(0x401000)"},
        # the cited 0x4beef0 sits past the stream's 8 KiB cap; only the guard log has it
        "result": '{"fn": "sub_401000", "callees": ["sub_402A10"]} ' + "x" * 9000 + " sub_4BEEF0"}
OPEN = {"call": "mcp__ida__open_database", "input": {"path": "/db"}, "result": "opened"}


def attempt(steps, **kw):
    return dict(kw, steps=steps)


class Env:
    def __init__(self, tmp):
        self.tmp = tmp
        self.db = os.path.join(tmp, "sample.bin")
        open(self.db, "wb").close()
        self.env = dict(os.environ, REW_DSH=os.path.join(HERE, "fake_dsh.py"),
                        DSH_HOME=os.path.join(tmp, "home"), REW_RUNS=os.path.join(tmp, "runs"),
                        REKIT_FINDINGS=os.path.join(tmp, "findings"))
        self.n = 0

    def rew(self, *args, scenario=None):
        env = dict(self.env)
        if scenario is not None:
            self.n += 1
            path = os.path.join(self.tmp, "scenario-%d.json" % self.n)
            with open(path, "w") as fh:
                json.dump(scenario, fh)
            env["FAKE_DSH_SCENARIO"] = path
            self.scenario = path
        p = subprocess.run([REW] + list(args), capture_output=True, text=True, env=env,
                           timeout=120)
        try:
            out = json.loads(p.stdout)
        except ValueError:
            out = {"unparsed": p.stdout, "stderr": p.stderr}
        return p.returncode, out, p.stderr

    def invocations(self):
        with open(self.scenario + ".calls.jsonl") as fh:
            return [json.loads(l) for l in fh]


def run():
    bad = []
    checks = [0]

    def expect(label, cond, detail=""):

        checks[0] += 1
        if not cond:
            bad.append("%s %s" % (label, str(detail)[:600]))

    with tempfile.TemporaryDirectory() as tmp:
        e = Env(tmp)
        good = attempt([OPEN, CALL, {"text": "Here you go:\n" + json.dumps(GOOD)}])

        # -- profile missing: refuse, then setup fixes it --------------------------
        rc, out, err = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [good]})
        expect("missing profile refuses to run", rc == 2 and not out["worker"]["valid"]
               and any("rew setup" in p for p in out["worker"]["problems"]), out)
        expect("missing profile message on stderr", "rew setup" in err)
        rc, out, _ = e.rew("setup")
        expect("setup creates the profile", rc == 0 and out["ok"], out)
        patch = os.path.join(tmp, "home", "profiles", "re-worker", "cordis.patch.yml")
        with open(patch) as fh:
            installed = fh.read()
        expect("setup installs the rendered repo patch",
               "@" + "PROVIDER" not in installed and "# @PROVIDER_ROWS@" not in installed
               and "- id: llm-pi-ai" in installed and "guardproxy.py" in installed, installed[:400])
        rc, out, _ = e.rew("setup")
        expect("setup is idempotent", rc == 0 and out["actions"] == ["already up to date"], out)
        with open(patch, "a") as fh:
            fh.write("# local edit\n")
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [good]})
        expect("edited profile refuses to run", rc == 2 and "differs" in json.dumps(out), out)
        e.rew("setup")

        # -- a valid run -------------------------------------------------------------
        rc, out, err = e.rew("--db", e.db, "--goal", "describe sub_401000",
                             "--target", "0x401000", "--max-calls", "7", "--effort", "low",
                             "--out", os.path.join(tmp, "out.json"),
                             scenario={"attempts": [good]})
        w = out.get("worker", {})
        expect("valid run exits 0", rc == 0 and w.get("valid") is True, (rc, out, err))
        expect("result fields kept", out.get("status") == "ok" and len(out["findings"]) == 3)
        g = [f.get("grounded") for f in out.get("findings", [])]
        expect("grounding uses the full proxy log, not the capped stream",
               g == [True, True, False], g)
        expect("worker fields", w.get("mode") == "strict" and w.get("effort") == "low"
               and w.get("model") == "deepseek-v4.1-flash" and w.get("tool_calls") == 2
               and w.get("refused") == 0 and w.get("attempts") == 1
               and w.get("session") == "session-fake-1" and os.path.isdir(w.get("run_dir", "")), w)
        expect("tokens summed", w.get("tokens", {}).get("inputTokens") == 3000
               and w["tokens"].get("outputTokens") == 150, w.get("tokens"))
        expect("--out written", json.load(open(os.path.join(tmp, "out.json"))) == out)
        inv = e.invocations()[0]
        expect("dsh runs read-only, json, from stdin", inv["perm"] == "read-only"
               and "--json" in inv["argv"] and inv["argv"][-1] == "-"
               and "--permission-mode" in inv["argv"], inv["argv"])
        expect("dsh runs in an empty scratch dir", inv["cwd_files"] == []
               and inv["cwd"].startswith(os.path.realpath(os.path.join(tmp, "runs")))
               or inv["cwd"].startswith(os.path.join(tmp, "runs")), inv["cwd"])
        expect("prompt is the contract prompt", inv["prompt"].startswith("You are a reverse-engineering")
               and e.db in inv["prompt"] and "at most 7" in inv["prompt"])
        expect("overlay carries this run's settings", '"--max-calls"' in inv["overlay"]
               and '"7"' in inv["overlay"] and '"--db"' in inv["overlay"]
               and 'reasoningEffort: "low"' in inv["overlay"]
               and "guardproxy.py" in inv["overlay"], inv["overlay"])
        notes = _notes.load(e.db, os.path.join(tmp, "findings"))
        expect("findings appended to the ledger", len(notes) == 3
               and notes[0]["source"] == "worker:deepseek-v4.1-flash:strict"
               and notes[0]["goal"] == "describe sub_401000" and notes[0]["verified"] is None
               and [n["grounded"] for n in notes] == [True, True, False], notes)
        expect("ledger ids reported", w.get("ledger", {}).get("ids") == [n["id"] for n in notes])

        # no profile effort override when --effort is not given
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [good]})
        inv = e.invocations()[0]
        expect("default effort leaves the model row alone",
               "agent-default-model" not in inv["overlay"] and out["worker"]["effort"] == "high")

        # -- verify / note -------------------------------------------------------------
        fid = notes[0]["id"]
        rc, out, _ = e.rew("backlog", "--db", e.db)
        expect("backlog lists every open finding, ungrounded first", rc == 0
               and out["open"] == 3 and out["shown"] == 3
               and out["items"][0]["id"] == notes[2]["id"]
               and any("never appeared" in w for w in out["items"][0]["why"]), out)
        rc, out, _ = e.rew("backlog", "--db", e.db, "--limit", "1")
        expect("backlog --limit says how many are left", out["shown"] == 1
               and out["more"].startswith("2 more"), out)
        rc, out, _ = e.rew("verify", "--db", e.db, "--id", fid, "--ok", "--note", "read it")
        expect("verify ok", rc == 0 and out["record"]["verified"] is True)
        rc, out, _ = e.rew("verify", "--db", e.db, "--id", notes[2]["id"], "--reject")
        rc, out, _ = e.rew("verify", "--db", e.db, "--id", "f-nope", "--ok")
        expect("verify unknown id fails", rc == 1 and "no finding" in out["error"])
        rc, out, _ = e.rew("note", "--db", e.db + ".i64", "--claim", "orchestrator claim",
                           "--evidence", "sub_401000+0x20", "0x402a10")
        expect("note recorded", rc == 0 and out["record"]["source"] == "orchestrator"
               and out["record"]["verified"] is True)
        rc, out, _ = e.rew("note", "--db", e.db, "--claim", "x", "--evidence", "main")
        expect("note without an address fails", rc == 1)
        state = {n["id"]: n for n in _notes.load("sample.bin", os.path.join(tmp, "findings"))}
        expect("ledger state after verify", state[fid]["verified"] is True
               and state[notes[2]["id"]]["verified"] is False and len(state) == 4, state)
        rc, out, _ = e.rew("backlog", "--db", e.db)
        expect("ruled-on findings leave the backlog", out["open"] == 1
               and out["items"][0]["id"] == notes[1]["id"], out)
        rc, out, _ = e.rew("backlog")
        expect("backlog without --db counts per database", rc == 0 and out["open"] == 1
               and out["databases"] == [{"db": "sample.bin", "open": 1, "verified": 2,
                                         "rejected": 1}], out)
        expect("note is in range", [n["claim"] for n in _notes.in_range(
            list(state.values()), 0x401020, 0x401021)] == ["orchestrator claim"])

        # -- invalid, then fixed by the resumed session ----------------------------
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, CALL, {"text": "I think sub_401000 calls sub_402A10."}]),
            attempt([{"text": json.dumps(GOOD)}])]})
        inv = e.invocations()
        expect("fixed on the second attempt", rc == 0 and out["worker"]["valid"]
               and out["worker"]["attempts"] == 2, out.get("worker"))
        expect("retry resumes the same session in the same dir", len(inv) == 2
               and inv[1]["argv"][inv[1]["argv"].index("--session-id") + 1] == "session-fake-1"
               and inv[1]["cwd"] == inv[0]["cwd"], [i["argv"] for i in inv])
        expect("retry prompt is the fix prompt",
               inv[1]["prompt"].startswith("Your reply could not be accepted"))
        expect("grounding still sees the first attempt's results",
               [f["grounded"] for f in out["findings"]] == [True, True, False])

        # -- a syntax slip in the corrected reply gets its own round, with the place named
        slip = json.dumps(GOOD).replace('"status"', '"status" ', 1)
        slip = slip[:-1] + ', "needs": ["x".upper()]}'
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, CALL, {"text": "prose only"}]),
            attempt([{"text": slip}]),
            attempt([{"text": json.dumps(GOOD)}])]})
        inv = e.invocations()
        expect("fixed on the third attempt", rc == 0 and out["worker"]["valid"]
               and out["worker"]["attempts"] == 3, out.get("worker"))
        expect("the syntax slip is named in the correction prompt",
               "not valid JSON" in inv[2]["prompt"] and ".upper()" in inv[2]["prompt"]
               or '"x"' in inv[2]["prompt"], inv[2]["prompt"][:400])

        # -- an odd or missing confidence is normalised, not sent back ---------------------
        odd = json.loads(json.dumps(GOOD))
        odd["findings"][0]["confidence"] = "High (verified by emulation)"
        odd["findings"][1].pop("confidence", None)
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, CALL, {"text": json.dumps(odd)}])]})
        f = out["findings"]
        expect("confidence normalised in one attempt", rc == 0 and out["worker"]["attempts"] == 1
               and f[0]["confidence"] == "high" and "confidence_assumed" not in f[0]
               and f[1]["confidence"] == "medium" and f[1].get("confidence_assumed") is True, f)

        # -- never valid --------------------------------------------------------------
        before = len(_notes.load(e.db, os.path.join(tmp, "findings")))
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([{"text": "no json"}]), attempt([{"text": "still none"}]),
            attempt([{"text": "nor now"}]), attempt([{"text": '{"status": "done"}'}])]})
        w = out["worker"]
        expect("never valid exits 1 after three correction rounds",
               rc == 1 and w["valid"] is False and w["attempts"] == 4, w)
        expect("problems and raw reported", w["problems"] and w["raw"] == '{"status": "done"}', w)
        expect("ledger untouched by an invalid run",
               len(_notes.load(e.db, os.path.join(tmp, "findings"))) == before)

        # -- timeout --------------------------------------------------------------------
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", "--timeout", "2", scenario={
            "attempts": [attempt([OPEN, {"text": json.dumps(GOOD)}], sleep=60)]})
        w = out["worker"]
        expect("timeout stops the worker", rc == 1 and not w["valid"] and w["seconds"] < 30
               and any("timed out" in p for p in w["problems"]) and w["attempts"] == 1, w)

        # -- dsh fails without a final event --------------------------------------------
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([{"text": ""}], exit=1, no_final=True, usage=False)]})
        w = out["worker"]
        expect("no final answer is reported", rc == 1 and any(
            "without a final answer" in p for p in w["problems"]), w)
        expect("missing usage is flagged", w["tokens"].get("incomplete") is True, w["tokens"])
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([{"text": ""}], exit=1)]})
        expect("a failed turn is reported", rc == 1 and any(
            "did not complete" in p for p in out["worker"]["problems"]), out["worker"])

        # -- audit -----------------------------------------------------------------------
        def audited(steps, **kw):
            rc, out, err = e.rew("--db", e.db, "--goal", "g", scenario={
                "attempts": [attempt(steps + [{"text": json.dumps(GOOD)}], **kw)]})
            return rc, out["worker"], err

        rc, w, err = audited([{"call": "bash", "input": {"command": "ls"}, "proxy": "none"}])
        expect("a non-ida tool call fails the audit", rc == 3 and not w["valid"]
               and not w["audit"]["ok"] and "AUDIT FAILED" in w["problems"][0]
               and "AUDIT FAILED" in err, w)
        rc, w, _ = audited([{"call": "mcp__ida__save_database", "proxy": "none",
                             "status": "error", "error": {"code": "UNKNOWN_TOOL"},
                             "result": "unknown tool"}])
        expect("an unregistered tool the model made up is only noted",
               rc == 0 and w["audit"]["ok"] and w["audit"]["notes"], w)
        rc, w, _ = audited([{"call": "mcp__ida__execute_python", "input": {"code": "x"},
                             "proxy": "leak", "status": "error"}])
        expect("a refused call answered by ida-mcp fails the audit",
               rc == 3 and any("refused call" in b for b in w["audit"]["breaches"]), w)
        rc, w, _ = audited([CALL, dict(CALL, proxy="none")])
        expect("an ida result that bypassed the proxy fails the audit",
               rc == 3 and any("guard proxy" in b for b in w["audit"]["breaches"]), w)
        rc, w, _ = audited([CALL], proxy_mode="free")
        expect("a proxy running the wrong mode fails the audit", rc == 3, w)
        rc, w, _ = audited([dict(CALL, proxy="refused", status="error")])
        expect("refusals are counted", rc == 0 and w["refused"] == 1, w)

        # -- print budget and finding count -------------------------------------
        many = {"status": "ok", "summary": "s", "unknowns": [], "needs": [], "findings": [
            {"claim": "claim %d about sub_401000 " % i + "w" * 500,
             "evidence": ["sub_401000 " + "detail " * 40, "sub_402A10"],
             "confidence": ["high", "low", "medium"][i % 3]} for i in range(8)]}
        out_file = os.path.join(tmp, "short.json")
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", "--max-chars", "2500", "--out", out_file,
                           scenario={"attempts": [attempt([CALL, {"text": json.dumps(many)}])]})
        tr = out.get("truncated", {})
        printed = subprocess.run([REW, "--db", e.db, "--goal", "g", "--max-chars", "2500"],
                                 capture_output=True, text=True, env=dict(
                                     e.env, FAKE_DSH_SCENARIO=e.scenario)).stdout
        expect("printed result fits the budget", len(printed.strip()) <= 2500, len(printed))
        expect("shortening reported", rc == 0 and tr.get("findings_total") == 8
               and tr.get("evidence_shortened") and tr.get("claims_shortened")
               and tr.get("dropped") and tr["findings_shown"] == len(out["findings"]), tr)
        full = json.load(open(tr.get("full_result", "/nonexistent")))
        expect("full result kept in the run dir", len(full["findings"]) == 8
               and full["findings"][0]["claim"] == many["findings"][0]["claim"]
               and "truncated" not in full)
        expect("--out gets the shortened result", json.load(open(out_file)) == out)
        expect("ledger gets the full findings", len([n for n in _notes.load(
            e.db, os.path.join(tmp, "findings")) if n["claim"].startswith("claim ")]) == 8)
        rc, out, _ = e.rew("--db", e.db, "--goal", "g",
                           scenario={"attempts": [attempt([CALL, {"text": json.dumps(GOOD)}])]})
        expect("a short result is not marked truncated", rc == 0 and "truncated" not in out)
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", "--max-findings", "2", scenario={
            "attempts": [attempt([CALL, {"text": json.dumps(GOOD)}]),
                         attempt([{"text": json.dumps(dict(GOOD, findings=GOOD["findings"][:2]))}])]})
        inv = e.invocations()
        expect("too many findings triggers the fix-up round", rc == 0
               and out["worker"]["attempts"] == 2 and "3 findings" in inv[1]["prompt"]
               and "At most 2 findings" in inv[0]["prompt"], out["worker"])
        bad_ev = dict(GOOD, findings=[{"claim": "x", "evidence": ["sub_401000", "see the loop"],
                                       "confidence": "high"}])
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([CALL, {"text": json.dumps(bad_ev)}]), attempt([{"text": json.dumps(GOOD)}])]})
        expect("evidence without an address triggers the fix-up round",
               rc == 0 and out["worker"]["attempts"] == 2
               and "evidence[2]" in e.invocations()[1]["prompt"], out["worker"])

        # -- references to tool results ----------------------------------------------------
        hexv = ("dc8f7629a85b42f544f7de9110c3aa5dac5f46f9782b12c514c7ae61e0937a2d"
                "3cefd68908bba255a4573ef170230abd0cbfa659d88b722574270ec1")      # 60 bytes
        emu = {"stop": {"reason": "returned", "at": "0x495c08"}, "ret": "0x1",
               "buffers": {"total": 1, "top": [{"name": "out", "addr": "0x7fff1000",
                                                "size": 60, "hex": hexv}]}}
        ECALL = {"call": "mcp__ida__execute_python",
                 "input": {"code": "rekit.emu('sub_495BD0', args=[{'out': 60}])"},
                 "result": json.dumps({"result": emu, "stdout": "", "stderr": ""}, indent=2)}

        def answer(claim, evidence=("{{1.stop.at}} ret",), summary="sub_495BD0 returns {{1.ret}}."):
            return json.dumps({"status": "ok", "summary": summary, "findings": [
                {"claim": claim, "evidence": list(evidence), "confidence": "high"}],
                "unknowns": [], "needs": []})

        ref_claim = "sub_495BD0 writes {{1.buffers.top[name=out].hex}} to out"
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": answer(ref_claim)}])]})
        w = out.get("worker", {})
        f = (out.get("findings") or [{}])[0]
        expect("reference run valid in one attempt", rc == 0 and w.get("valid")
               and w.get("attempts") == 1, w)
        expect("values filled in exactly", out.get("summary") == "sub_495BD0 returns 0x1."
               and f.get("claim") == "sub_495BD0 writes %s to out" % hexv
               and f.get("evidence") == ["0x495c08 ret"], out)
        expect("a filled address grounds the finding", f.get("grounded") is True, f)
        expect("finding lists its references", f.get("filled") == [
            "{{1.buffers.top[name=out].hex}}", "{{1.stop.at}}"], f)
        expect("worker.filled metadata", w.get("filled") == [
            {"ref": "{{1.ret}}", "in": "summary", "at": [19, 22], "chars": 3},
            {"ref": "{{1.buffers.top[name=out].hex}}", "in": "findings[0].claim",
             "at": [18, 138], "chars": 120},
            {"ref": "{{1.stop.at}}", "in": "findings[0].evidence[0]", "at": [0, 8], "chars": 8}],
            w.get("filled"))
        expect("no unmatched values", "unmatched" not in w and "unmatched" not in f, w)
        expect("the worker prompt explains references",
               "{{N.path}}" in e.invocations()[0]["prompt"])
        notes = [n for n in _notes.load(e.db, os.path.join(tmp, "findings"))
                 if n["claim"].startswith("sub_495BD0 writes")]
        expect("the ledger gets the filled claim", notes and hexv in notes[-1]["claim"], notes)

        # an unresolved reference: correction round names the keys that exist
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": answer("writes {{1.buffers.top[0].bytes}}")}]),
            attempt([{"text": answer(ref_claim)}])]})
        inv = e.invocations()
        expect("unresolved reference fixed in round two", rc == 0 and out["worker"]["valid"]
               and out["worker"]["attempts"] == 2 and hexv in out["findings"][0]["claim"],
               out.get("worker"))
        expect("correction prompt names the reference and the keys there",
               "findings[1].claim: the reference {{1.buffers.top[0].bytes}} does not resolve"
               in inv[1]["prompt"] and "keys there: name, addr, size, hex" in inv[1]["prompt"],
               inv[1]["prompt"][:600])
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": answer("x", evidence=["{{2.stop.at}}"])}]),
            attempt([{"text": answer(ref_claim)}])]})
        expect("a call that does not exist is named",
               "there is no call 2: only call 1 ran" in e.invocations()[1]["prompt"]
               and rc == 0, e.invocations()[1]["prompt"][:400])
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": answer("writes {{1.buffers}}")}])] * 4})
        expect("never resolved: invalid, problem kept", rc == 1 and not out["worker"]["valid"]
               and any("not a single value" in p for p in out["worker"]["problems"]),
               out["worker"])

        # a retyped value with three characters lost: one round asks for the reference
        slip = hexv[:50] + hexv[53:]
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": answer("sub_495BD0 writes %s to out" % slip)}]),
            attempt([{"text": answer(ref_claim)}])]})
        inv = e.invocations()
        w = out["worker"]
        expect("near miss: one question round, then valid", rc == 0 and w["valid"]
               and w["attempts"] == 2, w)
        expect("near miss: the question names the call and the reference",
               inv[1]["prompt"].startswith("Your result is accepted, but long values")
               and "nearly matches a value in call 1" in inv[1]["prompt"]
               and "Write {{1.buffers.top[0].hex}} instead" in inv[1]["prompt"],
               inv[1]["prompt"])
        expect("near miss: fixed by a reference", hexv in out["findings"][0]["claim"]
               and w.get("unmatched") == {"total": 0, "asked": True, "values": []}
               and "unmatched" not in out["findings"][0], (w.get("unmatched"), out["findings"]))

        # a derived value the worker stands by: flagged, asked once, accepted
        derived = "7b1c0e9f33a2d4c85e6f0a1b2c3d4e5f"
        first = answer("the SHA-256 prefix of out is %s" % derived)
        second = answer("the SHA-256 prefix of out is %s, computed from "
                        "{{1.buffers.top[0].hex}}" % derived)
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": first}]), attempt([{"text": second}])]})
        w = out["worker"]
        um = w.get("unmatched") or {}
        expect("derived: valid after the one question", rc == 0 and w["valid"]
               and w["attempts"] == 2, w)
        expect("derived: listed, marked, asked", um.get("total") == 1 and um.get("asked")
               and um["values"][0] == {"value": "7b1c0e9f33a2…2c3d4e5f", "chars": 32,
                                       "in": ["findings[0].claim"]}
               and out["findings"][0].get("unmatched") is True, (um, out["findings"]))
        expect("derived: the question asks what it was derived from",
               "what it was derived from" in e.invocations()[1]["prompt"])

        # the question must not cost a valid result
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": first}]), attempt([{"text": "sorry"}]),
            attempt([{"text": "no"}]), attempt([{"text": "nope"}])]})
        w = out["worker"]
        expect("earlier valid reply kept when the later ones fail", rc == 0 and w["valid"]
               and w["attempts"] == 4 and w["unmatched"].get("kept_earlier_reply")
               and w["unmatched"]["later_reply_problems"]
               and derived in out["findings"][0]["claim"], w)

        # with no rounds left the value is only listed
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", scenario={"attempts": [
            attempt([OPEN, ECALL, {"text": "prose"}]), attempt([{"text": "prose"}]),
            attempt([{"text": "prose"}]), attempt([{"text": first}])]})
        w = out["worker"]
        expect("no rounds left: listed, not asked", rc == 0 and w["attempts"] == 4
               and w["unmatched"]["asked"] is False and w["unmatched"]["total"] == 1, w)

        # print budget: a filled value is never cut in the middle
        long_hex = hexv * 10                                       # 1200 chars
        emu_long = dict(emu, buffers={"total": 1, "top": [{"name": "out", "hex": long_hex}]})
        LCALL = dict(ECALL, result=json.dumps({"result": emu_long, "stdout": "", "stderr": ""}))
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", "--max-chars", "2200", scenario={
            "attempts": [attempt([OPEN, LCALL, {"text": answer(
                "out holds {{1.buffers.top[0].hex}} after the call")}])]})
        tr = out.get("truncated", {})
        claim = out["findings"][0]["claim"] if out.get("findings") else ""
        expect("truncated run valid and within budget", rc == 0 and len(contract.dump(out)) <= 2200
               and tr.get("findings_shown") == 1,
               len(contract.dump(out)))
        expect("long filled value omitted whole, with a marker", long_hex[:40] not in claim
               and claim.startswith("out holds…[") and "{{1.buffers.top[0].hex}}: 1200 chars omitted]" in claim
               and tr.get("filled_omitted") == [{"ref": "{{1.buffers.top[0].hex}}",
                                                 "in": "findings[0].claim"}], (claim, tr))
        full = json.load(open(tr["full_result"]))
        expect("the full result has the whole value", long_hex in full["findings"][0]["claim"])

        # -- task file and bad input -----------------------------------------------------
        task = os.path.join(tmp, "task.json")
        with open(task, "w") as fh:
            json.dump({"goal": "from file", "targets": ["sub_401000"], "mode": "free",
                       "max_calls": 4}, fh)
        rc, out, _ = e.rew("run", "--db", e.db, "--task", task, scenario={"attempts": [good]})
        inv = e.invocations()[0]
        expect("task file honoured", rc == 0 and out["worker"]["mode"] == "free"
               and '"free"' in inv["overlay"] and "from file" in inv["prompt"], out["worker"])
        rc, out, _ = e.rew("--db", e.db, "--task", task, "--mode", "strict",
                           scenario={"attempts": [good]})
        expect("--mode overrides the task file", out["worker"]["mode"] == "strict")
        rc, out, _ = e.rew("--db", os.path.join(tmp, "missing.bin"), "--goal", "g")
        expect("missing database is refused", rc == 2 and "not found" in json.dumps(out))
        rc, out, _ = e.rew("--db", e.db)
        expect("missing goal is refused", rc == 2)
        rc, out, _ = e.rew("--db", e.db, "--goal", "g", "--max-calls", "0")
        expect("bad budget is refused", rc == 2 and "max_calls" in json.dumps(out))

    for label in bad:
        print("FAIL:", label)
    print("%d checks, %d failed" % (checks[0], len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
