#!/usr/bin/env python3
"""The whole jsw flow with the real dsh CLI, the installed js-worker profile, the
real jsre_mcp.py and a real container, but a scripted fake model
(reworker/fake_llm_server.py): run, resume, merge, gc and doctor. No model
tokens are spent. Needs `jsw setup` and the image.
Run: python3 tests/test_flow.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import (Checks, FIXTURE_BENCH, JSWORKER, image_ready, jsw,  # noqa: E402
                      read_log, wait_for)

JSW = os.path.join(JSWORKER, "jsw")
IMPL = ("def sign(s):\n    h = 0\n    for ch in s:\n        h = (h * 31 + ord(ch)) & 0xFFFFFFFF\n"
        "    return '%08x' % h\n")


def tc(name, **arguments):
    return {"name": "mcp__jsre__" + name, "arguments": arguments}


FIRST = [
    {"reasoning": "look around", "tool_calls": [tc("fs_list", path="/task"),
                                                tc("fs_read", path="/task/public/README.md")]},
    {"tool_calls": [tc("node_run", code="const m=require('/task/public/t1/app.js');"
                                        "console.log('SIG', m.sign('abc'))")]},
    {"tool_calls": [tc("fs_write", path="/task/work/submission/T1-01.py", content=IMPL),
                    tc("fs_write", path="/task/work/submission/answers.json",
                       content=json.dumps({"T1-01": "T1-01.py", "T1-02": 31}))]},
    {"tool_calls": [tc("submit_check")]},
    {"tool_calls": [tc("fs_read", path="/etc/passwd"),
                    {"name": "bash", "arguments": {"command": "id"}}]},
    {"text": "Submitted T1-01 (sign) and T1-02 = 31."},
]
SECOND = [
    {"tool_calls": [tc("py_run", code="print('again')")]},
    {"tool_calls": [tc("node_run", code="1")]},
    {"tool_calls": [tc("fs_edit", path="/task/work/submission/answers.json", old="31",
                       new="31 ")]},
    {"text": "Done again."},
]


class FakeModel:
    def __init__(self, tmp, script, tag):
        self.dir = os.path.join(tmp, "llm-" + tag)
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "script.json"), "w") as fh:
            json.dump(script, fh)
        port_file = os.path.join(self.dir, "port")
        self.p = subprocess.Popen([sys.executable, os.path.join(jsw.REWORKER,
                                                                "fake_llm_server.py"),
                                   "--script", os.path.join(self.dir, "script.json"),
                                   "--record", os.path.join(self.dir, "req"),
                                   "--port-file", port_file])
        wait_for(port_file)
        port = int(open(port_file).read())
        self.patch = os.path.join(self.dir, "fake-model.yml")
        with open(self.patch, "w") as fh:
            fh.write(jsw.backend_dsh.fake_provider_rows(port))

    def requests(self):
        d = os.path.join(self.dir, "req")
        return [json.load(open(os.path.join(d, n))) for n in sorted(os.listdir(d))]

    def close(self):
        self.p.terminate()
        self.p.wait(5)


def jsw_cmd(args, env, timeout=600):
    p = subprocess.run([sys.executable, JSW] + args, capture_output=True, text=True, env=env,
                       timeout=timeout)
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = None
    return p.returncode, out, p.stdout, p.stderr


def container_exists(name):
    rc, out, err = jsw.docker("inspect", name)
    return rc == 0


def run(c, tmp):
    sessions = os.path.join(jsw.backend_dsh.dsh_home(), "sessions")
    before = set(os.listdir(sessions)) if os.path.isdir(sessions) else set()
    runs = os.path.join(tmp, "runs")
    base_env = dict(os.environ, JSW_RUNS=runs, REW_FAKE_LLM_KEY="fake")

    # ---- a run that cannot start ----------------------------------------------------------
    rc, b, so, se = jsw_cmd(["run", "--target", "t9", "--bench", FIXTURE_BENCH], base_env)
    c.expect("unknown target blocks the run", rc == 2 and b and b["status"] == "blocked" and
             "staging failed" in b["problems"][0], (rc, so, se))
    rcd, out, err = jsw.docker("ps", "-a", "--filter", "label=jsw.run", "--format",
                               "{{.Label \"jsw.run\"}}")
    c.expect("no container for a blocked run", "-t9-" not in out, out)

    # ---- run ----------------------------------------------------------------------------
    model = FakeModel(tmp, FIRST, "1")
    try:
        rc, s, so, se = jsw_cmd(["run", "--target", "t1", "--bench", FIXTURE_BENCH,
                                 "--timeout", "300", "--max-calls", "8"],
                                dict(base_env, REW_EXTRA_PATCH=model.patch))
        reqs = model.requests()
    finally:
        model.close()
    if not c.expect("jsw run printed a summary", isinstance(s, dict), (rc, so[-2000:], se[-2000:])):
        return
    run_dir = s["run_dir"]
    c.expect("run finished with a clean audit", rc == 0 and s["status"] == "finished" and
             s["audit"]["ok"], (rc, s["status"], s["audit"], s["attempts"]))
    c.expect("the refused read is flagged", any("/etc/passwd" in f for f in s["audit"]["flags"]),
             s["audit"])
    c.expect("the made-up tool is only noted", any("'bash'" in n for n in s["audit"]["notes"]),
             s["audit"])
    offered = sorted(t["function"]["name"] for t in reqs[0]["tools"])
    c.expect("the model was offered exactly the jsre tools", offered == jsw.TOOL_NAMES, offered)
    first_msgs = json.dumps(reqs[0]["messages"], ensure_ascii=False)
    c.expect("the prompt carries this target's questions only",
             "What multiplier does sign use per character?" in first_msgs and
             "T2-01" not in first_msgs and "SEALED" not in first_msgs, first_msgs[:1500])
    c.expect("no workspace instructions in the prompt", "AGENTS.md" not in first_msgs and
             "CLAUDE.md" not in first_msgs and "Sub-agent economy" not in first_msgs)
    shown = json.dumps([m for m in reqs[-1]["messages"] if m.get("role") == "tool"],
                       ensure_ascii=False)
    c.expect("the model saw the node output", "SIG 00017862" in shown, shown[:2000])
    c.expect("the model saw submit_check pass", "public samples 3/3 passed" in shown, shown[:3000])
    c.expect("the model saw the refusal", "outside /task" in shown)
    c.expect("tool counts", s["tool_calls"]["total"] == 7 and s["tool_calls"]["refused"] == 1 and
             s["tool_calls"]["budget_used"] == 7, s["tool_calls"])
    c.expect("tokens from the stream", s["tokens"].get("inputTokens", 0) > 0, s["tokens"])
    c.expect("submission exported", s["submission"]["files"] == ["T1-01.py", "answers.json"]
             and s["submission"]["answered"] == ["T1-01", "T1-02"], s["submission"])
    c.expect("final submit_check recorded", s["submit_check"] and
             s["submit_check"].get("passed") == 3 and not s["submit_check"].get("errors"),
             s["submit_check"])
    c.expect("container removed", not container_exists(s["container"]))
    c.expect("model and effort defaults", s["model"] == "deepseek-v4.1-flash" and
             s["effort"] == "max", (s["model"], s["effort"]))
    for name in ("overlay.yml", "events-1.jsonl", "stderr-1.txt", "tools.jsonl", "summary.json",
                 "prompt.txt", "run.json", "public/README.md", "public/t1/app.js",
                 "submission/answers.json", "work/submission/T1-01.py"):
        c.expect("artifact %s" % name, os.path.exists(os.path.join(run_dir, name)))
    c.expect("no pid file after the run", not os.path.exists(os.path.join(run_dir, "jsw.pid")))
    c.expect("dsh ran outside work/", os.path.isdir(os.path.join(run_dir, "dsh-cwd")) and
             os.path.isdir(os.path.join(run_dir, "dsh", "sessions")))
    log = read_log(os.path.join(run_dir, "tools.jsonl"))
    starts = [r for r in log if r.get("event") == "start"]
    c.expect("jsre_mcp ran with this run's container and budget", starts and all(
        r["container"] == s["container"] and r["max_calls"] == 8 for r in starts), starts)

    # ---- resume: same session, budget continues ---------------------------------------
    model = FakeModel(tmp, SECOND, "2")
    try:
        rc, s2, so, se = jsw_cmd(["resume", s["run_id"], "--timeout", "300"],
                                 dict(base_env, REW_EXTRA_PATCH=model.patch))
        reqs2 = model.requests()
    finally:
        model.close()
    if not c.expect("jsw resume printed a summary", isinstance(s2, dict),
                    (rc, so[-2000:], se[-2000:])):
        return
    c.expect("resume finished", rc == 0 and s2["status"] == "finished" and
             len(s2["attempts"]) == 2 and s2["audit"]["ok"], (rc, s2["status"], s2["audit"]))
    c.expect("same dsh session", s2["attempts"][1]["session"] == s["session"],
             [a["session"] for a in s2["attempts"]])
    hist = json.dumps(reqs2[0]["messages"], ensure_ascii=False)
    c.expect("the resumed conversation has the earlier turns",
             "Submitted T1-01 (sign)" in hist and "SIG 00017862" in hist, hist[-1500:])
    log = read_log(os.path.join(run_dir, "tools.jsonl"))
    calls = [r for r in log if r.get("event") == "call"]
    late = sorted(((r.get("call_no"), r["tool"], bool(r.get("refused")),
                    bool(r.get("over_budget"))) for r in calls[-3:]),
                  key=lambda x: (x[0] is None, x[0] or 0))
    c.expect("budget continued across the resume",
             late == [(8, "py_run", False, False), (9, "fs_edit", False, True),
                      (None, "node_run", True, False)], late)
    shown = json.dumps([m for m in reqs2[-1]["messages"] if m.get("role") == "tool"])
    c.expect("the model was told to write its submission", "budget exhausted" in shown and
             "Write your submission now" in shown, shown[-1500:])
    c.expect("resume summary counts", s2["tool_calls"]["budget_used"] == 8 and
             s2["tool_calls"]["over_budget"] == 1, s2["tool_calls"])
    c.expect("container removed after resume", not container_exists(s2["container"]))

    # ---- merge ------------------------------------------------------------------------------
    out = os.path.join(tmp, "merged")
    rc, m, so, se = jsw_cmd(["merge", s["run_id"], "-o", out], base_env)
    c.expect("merge", rc == 0 and json.load(open(os.path.join(out, "answers.json"))) ==
             {"T1-01": "T1-01.py", "T1-02": 31} and os.path.isfile(os.path.join(out, "T1-01.py")),
             (rc, so, se))
    rc, m, so, se = jsw_cmd(["merge", s["run_id"], s["run_id"], "-o",
                             os.path.join(tmp, "m2")], base_env)
    c.expect("merging the same qids twice is refused", rc == 2 and "answered by both" in so, so)

    # ---- gc -----------------------------------------------------------------------------------
    names = []
    for pid in ("999999", str(os.getpid())):
        name = "jsw-gc-test-%s" % pid
        jsw.docker("rm", "-f", name)
        rcd, o, e = jsw.docker("run", "-d", "--name", name, "--label", "jsw.run=gc-test",
                               "--label", "jsw.pid=%s" % pid, "--network", "none",
                               jsw.expected_image(), "sleep", "infinity")
        names.append(name)
    rc, g, so, se = jsw_cmd(["gc"], base_env)
    removed = [x["container"] for x in (g or {}).get("removed", [])]
    kept = [x["container"] for x in (g or {}).get("kept", [])]
    c.expect("gc removes containers of dead runs", names[0] in removed and
             not container_exists(names[0]), (so, se))
    c.expect("gc keeps containers of live runs", names[1] in kept and container_exists(names[1]),
             so)
    jsw.docker("rm", "-f", names[1])

    after = set(os.listdir(sessions)) if os.path.isdir(sessions) else set()
    c.expect("nothing new in ~/.dsh/sessions", after == before, after - before)


def doctor(c):
    p = subprocess.run([sys.executable, JSW, "doctor"], capture_output=True, text=True,
                       timeout=600)
    try:
        d = json.loads(p.stdout)
    except ValueError:
        c.expect("doctor printed JSON", False, (p.stdout[-1000:], p.stderr[-1000:]))
        return
    c.expect("doctor ok", p.returncode == 0 and d["ok"], d)
    offered = [x for x in d["checks"] if x["check"] == "tools offered to the model"]
    c.expect("doctor saw exactly the jsre tools", offered and offered[0]["ok"] and
             offered[0]["detail"] == jsw.TOOL_NAMES, offered)
    rc, out, err = jsw.docker("ps", "-a", "--filter", "label=jsw.run", "--format", "{{.Names}}")
    c.expect("doctor leaves no container", not [n for n in out.split() if "doctor" in n], out)


def main():
    c = Checks()
    problems = jsw.JsBackend().problems() + jsw.image_problems()
    if problems:
        print("cannot run: %s" % problems)
        return 1
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="jsw-flow-") as tmp:
        try:
            run(c, os.path.realpath(tmp))
        except Exception as exc:
            import traceback
            traceback.print_exc()
            c.expect("flow raised", False, exc)
    try:
        doctor(c)
    except Exception as exc:
        c.expect("doctor raised", False, exc)
    print("(%.0f s)" % (time.time() - started))
    return c.report()


if __name__ == "__main__":
    sys.exit(main())
