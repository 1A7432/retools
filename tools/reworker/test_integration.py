#!/usr/bin/env python3
"""rew with the real dsh CLI and the installed re-worker profile, but a fake
model (fake_llm_server.py) and a fake ida-mcp (fake_mcp_server.py) behind the
real guard proxy. No network, no IDA. Needs `rew setup` to have been run.

Run: python3 test_integration.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import backend_dsh  # noqa: E402
import contract  # noqa: E402


def run():
    bad = []
    checks = [0]

    def expect(label, cond, detail=""):

        checks[0] += 1
        if not cond:
            bad.append("%s %s" % (label, str(detail)[:800]))

    problems = backend_dsh.DshBackend().problems()
    if problems:
        print("cannot run: %s" % problems)
        return 1
    sessions = os.path.join(backend_dsh.dsh_home(), "sessions")
    before = set(os.listdir(sessions)) if os.path.isdir(sessions) else set()

    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "sample.bin")
        open(db, "wb").close()
        load = 'import sys\nsys.path.insert(0, "%s")\nimport rekit\n' % contract.REKIT_DIR
        script = [
            {"reasoning": "open, load, look", "tool_calls": [
                {"name": "mcp__ida__open_database", "arguments": {"path": db}},
                {"name": "mcp__ida__execute_python",
                 "arguments": {"code": load + "rekit.fn(0x401000)"}},
                {"name": "mcp__ida__execute_python", "arguments": {"code": "import os"}},
                {"name": "mcp__ida__save_database", "arguments": {}}]},
            {"text": "sub_401000 calls sub_402A10, I am fairly sure."},
            {"text": json.dumps({"status": "ok", "summary": "out is {{1.buffers.top[name=out].hex}}",
                "findings": [
                {"claim": "{{1.fn}} calls sub_402A10", "evidence": ["{{1.callees[0]}}"],
                 "confidence": "high"},
                {"claim": "invented", "evidence": ["0x999999"], "confidence": "low"}],
                "unknowns": [], "needs": []})},
        ]
        with open(os.path.join(tmp, "script.json"), "w") as fh:
            json.dump(script, fh)
        port_file = os.path.join(tmp, "port")
        llm = subprocess.Popen([sys.executable, os.path.join(HERE, "fake_llm_server.py"),
                                "--script", os.path.join(tmp, "script.json"),
                                "--record", os.path.join(tmp, "llm"), "--port-file", port_file])
        try:
            for _ in range(100):
                if os.path.exists(port_file):
                    break
                time.sleep(0.05)
            port = int(open(port_file).read())
            extra = os.path.join(tmp, "fake-model.yml")
            with open(extra, "w") as fh:
                fh.write(backend_dsh.fake_provider_rows(port))
            env = dict(os.environ, REW_EXTRA_PATCH=extra, REW_FAKE_LLM_KEY="fake",
                       REW_IDA_MCP=os.path.join(HERE, "fake_mcp_server.py"),
                       REW_RUNS=os.path.join(tmp, "runs"),
                       REKIT_FINDINGS=os.path.join(tmp, "findings"))
            p = subprocess.run([os.path.join(HERE, "rew"), "--db", db, "--goal",
                                "what does sub_401000 call?", "--max-calls", "4"],
                               capture_output=True, text=True, env=env, timeout=300)
        finally:
            llm.terminate()
            llm.wait(5)
        try:
            out = json.loads(p.stdout)
        except ValueError:
            print("rew printed:", p.stdout, p.stderr)
            return 1
        w = out["worker"]
        expect("valid after one correction", p.returncode == 0 and w["valid"]
               and w["attempts"] == 2, (p.returncode, w))
        expect("real stream parsed", w["tool_calls"] == 4 and w["session"]
               and w["exit"] == [0, 0], w)
        expect("strict refusal counted", w["refused"] == 1 and w["budget"]["used"] == 1, w)
        expect("made-up save_database only noted", w["audit"]["ok"] and any(
            "save_database" in n for n in w["audit"]["notes"]), w["audit"])
        expect("references filled from the real proxy log",
               out["summary"] == "out is 00112233445566778899aabbccddeeff"
               and out["findings"][0]["claim"] == "sub_401000 calls sub_402A10"
               and out["findings"][0]["evidence"] == ["sub_402A10"]
               and len(w.get("filled", [])) == 3 and "unmatched" not in w, out)
        expect("grounding against the real proxy log",
               [f["grounded"] for f in out["findings"]] == [True, False], out["findings"])
        expect("tokens from the real stream", w["tokens"].get("inputTokens", 0) > 0, w["tokens"])
        reqs = sorted(os.listdir(os.path.join(tmp, "llm")))
        with open(os.path.join(tmp, "llm", reqs[0])) as fh:
            body = json.load(fh)
        offered = sorted(t["function"]["name"] for t in body["tools"])
        expect("only the ida tools were offered", offered == sorted(backend_dsh.IDA_TOOL_NAMES),
               offered)
        with open(os.path.join(tmp, "llm", reqs[-1])) as fh:
            last = json.load(fh)
        expect("the fix prompt went to the same conversation",
               last["messages"][-1]["content"].startswith("Your reply could not be accepted")
               and any("rekit" in str(m.get("content")) for m in last["messages"]))
        tool_msgs = [m for m in last["messages"] if m.get("role") == "tool"]
        shown = json.dumps(tool_msgs)
        expect("the model saw the call number above the result",
               "[call 1 of 4] quote values from this result as {{1.path}}" in shown
               and "sub_401000" in shown and shown.count("[call ") == 1, shown[:1500])
        log = [json.loads(l) for l in open(os.path.join(w["run_dir"], "guard.jsonl"))]
        expect("call number in the guard log", [r.get("call_no") for r in log
               if r.get("tool") == "execute_python"] == [1, None], log)
        starts = [r for r in log if r.get("event") == "start"]
        expect("proxy started with this run's settings", starts and all(
            s["mode"] == "strict" and s["max_calls"] == 4 and s["db"] == db for s in starts))
        expect("dsh session kept in the run dir",
               os.path.isdir(os.path.join(w["run_dir"], "dsh", "sessions")))
    after = set(os.listdir(sessions)) if os.path.isdir(sessions) else set()
    expect("nothing new in ~/.dsh/sessions", after == before, after - before)

    for label in bad:
        print("FAIL:", label)
    print("%d checks, %d failed" % (checks[0], len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
