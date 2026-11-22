#!/usr/bin/env python3
"""jsworker pieces that need neither docker nor dsh: path and flag policy,
staging against MANIFEST.sha256, the prompt, the overlay, export, audit, merge,
and the MCP server's protocol and budget (against a container that does not
exist). Run: python3 tests/test_unit.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Checks, FIXTURE_BENCH, JSWORKER, jsw, jsre_mcp  # noqa: E402


def refused(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except jsre_mcp.Refusal as exc:
        return str(exc)
    return None


def test_paths(c):
    ok = {"/task": "/task", "/task/public/t1/app.js": "/task/public/t1/app.js",
          "/task/work/a/../b.js": "/task/work/b.js", "//task//public": "/task/public"}
    for p, want in ok.items():
        try:
            got = jsre_mcp.check_path(p)
        except jsre_mcp.Refusal as exc:
            got = exc
        c.expect("read path %s accepted" % p, got == want, got)
    for p in ["/etc/passwd", "/", "/task/../etc/passwd", "/task/public/../../etc/passwd",
              "../etc/passwd", "task/public/x", "/taskx/y", "", "/task/\x00x",
              os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                                            "..", "bench", "jsvm1", "sealed", "answers.json")),
              os.path.join(FIXTURE_BENCH, "sealed", "answers.json"), "/opt/jsre/pyrun.py",
              "/proc/self/environ", None, 7]:
        c.expect("read path %r refused" % (p,), refused(jsre_mcp.check_path, p) is not None)
    c.expect("write path accepted", jsre_mcp.check_path("/task/work/sub/x.py", write=True)
             == "/task/work/sub/x.py")
    for p in ["/task/public/t1/app.js", "/task/work/../public/x", "/task", "/task/workx",
              "/tmp/x", "/task/public"]:
        c.expect("write path %s refused" % p,
                 refused(jsre_mcp.check_path, p, write=True) is not None)


def test_flags(c):
    c.expect("allowed node flags", jsre_mcp.check_flags(
        ["--stack-size=4000", "--max-old-space-size=2048"]) ==
        ["--stack-size=4000", "--max-old-space-size=2048"])
    c.expect("no flags", jsre_mcp.check_flags(None) == [])
    for f in ["--inspect", "--inspect-brk=0", "--inspect=0.0.0.0:9229", "--allow-child-process",
              "--allow-worker", "--allow-fs-read=/", "--allow-fs-write=/", "--allow-addons",
              "--allow-wasi", "--stack-size=abc", "--stack-size=1 --inspect", "-e",
              "--eval=1", "--require=/task/work/x.js", "--import=x", "--experimental-loader=x",
              "--max-old-space-size=", "--stack-size=0", "--no-permission", "--expose-gc",
              "--stack-size=10000000"]:
        c.expect("node flag %r refused" % f, refused(jsre_mcp.check_flags, [f]) is not None)
    c.expect("flags must be a list", refused(jsre_mcp.check_flags, "--stack-size=1") is not None)


def test_run_spec(c):
    prefix, file, code, args, stdin, timeout = jsre_mcp.run_spec(
        "node_run", {"file": "/task/public/t1/app.js", "args": ["--inspect", "x"],
                     "node_flags": ["--stack-size=2000"]})
    c.expect("node argv prefix", prefix == ["node", "--permission", "--allow-fs-read=/task",
                                            "--allow-fs-read=/opt/jsre",
                                            "--allow-fs-write=/task/work", "--stack-size=2000"],
             prefix)
    c.expect("script args stay script args", args == ["--inspect", "x"] and timeout == 60)
    prefix, *_ = jsre_mcp.run_spec("py_run", {"code": "print(1)"})
    c.expect("python argv prefix", prefix == ["python3", "-I", "-B", "-X", "utf8",
                                              "/opt/jsre/pyrun.py"], prefix)
    for tool, a in [("node_run", {}), ("node_run", {"file": "/task/x.js", "code": "1"}),
                    ("node_run", {"code": "x" * 100001}),
                    ("node_run", {"code": "1", "args": [1]}),
                    ("node_run", {"code": "1", "timeout": 601}),
                    ("node_run", {"code": "1", "timeout": 0}),
                    ("node_run", {"code": "1", "node_flags": ["--inspect"]}),
                    ("node_run", {"file": "/etc/passwd"}),
                    ("py_run", {"code": "1", "node_flags": []}),
                    ("py_run", {"file": "/opt/jsre/pyrun.py"}),
                    ("py_run", {"code": "1", "env": {"A": "1"}})]:
        c.expect("run spec %s %s refused" % (tool, str(a)[:60]),
                 refused(jsre_mcp.run_spec, tool, a) is not None)
    long = "a" * 15000 + "b" * 15000
    cut = jsre_mcp.fit_output(long, "/task/work/.jsw/out/3.txt")
    c.expect("long output cut to head and tail",
             cut.startswith("a" * 10000) and cut.endswith("b" * 10000)
             and "/task/work/.jsw/out/3.txt" in cut and len(cut) < 20300, len(cut))
    c.expect("short output untouched", jsre_mcp.fit_output("hi", "x") == "hi")


def test_tools_list(c):
    names = [t["name"] for t in jsre_mcp.TOOLS]
    c.expect("nine tools", names == ["fs_list", "fs_read", "fs_grep", "fs_write", "fs_edit",
                                     "node_run", "py_run", "js_beautify", "submit_check"], names)
    allowed = {"type", "properties", "required", "additionalProperties", "items", "enum",
               "description"}

    def keys(node):
        out = set(node)
        for sub in (node.get("properties") or {}).values():
            out |= keys(sub)
        if isinstance(node.get("items"), dict):
            out |= keys(node["items"])
        return out
    for t in jsre_mcp.TOOLS:
        c.expect("%s schema uses dsh's JSON-schema subset" % t["name"],
                 keys(t["inputSchema"]) <= allowed, keys(t["inputSchema"]) - allowed)
    c.expect("jsw expects exactly these tools",
             jsw.TOOL_NAMES == sorted("mcp__jsre__" + n for n in names), jsw.TOOL_NAMES)
    c.expect("descriptions mention no host path",
             "/Users" not in json.dumps(jsre_mcp.TOOLS))


def test_stage(c):
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = os.path.join(tmp, "run")
        st = jsw.stage(FIXTURE_BENCH, "t1", run_dir)
        rels = [f[0] for f in st["files"]]
        c.expect("staged files", rels == ["README.md", "t1/app.js", "t1/samples.json",
                                          "questions.json"], rels)
        qs = json.load(open(os.path.join(run_dir, "public", "questions.json")))
        c.expect("questions filtered to the target", [q["id"] for q in qs] == ["T1-01", "T1-02"])
        c.expect("other targets not staged",
                 not os.path.exists(os.path.join(run_dir, "public", "t2")))
        c.expect("sealed never staged", not any("sealed" in r for r in rels) and
                 "SEALED-SECRET" not in json.dumps(st))
        run = {"bench": FIXTURE_BENCH, "staging": st}
        c.expect("recheck clean", jsw.recheck_staging(run_dir, run) == [],
                 jsw.recheck_staging(run_dir, run))
        with open(os.path.join(run_dir, "public", "t1", "extra.js"), "w") as fh:
            fh.write("1")
        c.expect("recheck sees an extra file", jsw.recheck_staging(run_dir, run))
        os.unlink(os.path.join(run_dir, "public", "t1", "extra.js"))
        with open(os.path.join(run_dir, "public", "t1", "app.js"), "a") as fh:
            fh.write("//x")
        c.expect("recheck sees a changed file", jsw.recheck_staging(run_dir, run))

        bench = os.path.join(tmp, "bench")
        shutil.copytree(FIXTURE_BENCH, bench)

        def fails(label, target="t1"):
            try:
                jsw.stage(bench, target, os.path.join(tmp, "r-%s" % label.replace(" ", "-")))
            except jsw.StageError as exc:
                return str(exc)
            return None
        c.expect("unknown target refused", fails("unknown", "t9"))
        c.expect("bad target name refused", fails("dots", "../x"))
        with open(os.path.join(bench, "public", "t1", "app.js"), "a") as fh:
            fh.write("// tampered\n")
        c.expect("tampered file refused", "MANIFEST" in (fails("tampered") or ""))
        shutil.copy(os.path.join(FIXTURE_BENCH, "public", "t1", "app.js"),
                    os.path.join(bench, "public", "t1", "app.js"))
        c.expect("restored file stages", fails("restored") is None)
        with open(os.path.join(bench, "public", "t1", "notes.txt"), "w") as fh:
            fh.write("x")
        c.expect("unlisted file refused", "not in MANIFEST" in (fails("unlisted") or ""))
        os.unlink(os.path.join(bench, "public", "t1", "notes.txt"))
        os.symlink(os.path.join(FIXTURE_BENCH, "sealed", "answers.json"),
                   os.path.join(bench, "public", "t1", "link.json"))
        c.expect("symlink refused", "symbolic link" in (fails("symlink") or ""))
        os.unlink(os.path.join(bench, "public", "t1", "link.json"))
        with open(os.path.join(bench, "public", "questions.json"), "a") as fh:
            fh.write(" ")
        c.expect("changed questions.json refused", "questions.json" in (fails("q") or ""))


def test_prompt(c):
    with tempfile.TemporaryDirectory() as tmp:
        st = jsw.stage(FIXTURE_BENCH, "t1", tmp)
        readme = open(os.path.join(tmp, "public", "README.md")).read()
        p = jsw.build_prompt("t1", readme, st["questions"], st["files"], 400, 7200)
        qs = json.load(open(os.path.join(FIXTURE_BENCH, "public", "questions.json")))
        for q in qs[:2]:
            c.expect("prompt has %s verbatim" % q["id"], q["question"] in p
                     and q["answer_format"] in p)
        c.expect("prompt lacks the other target's question", qs[2]["question"] not in p
                 and "T2-01" not in p)
        c.expect("prompt has README verbatim", readme.strip() in p)
        c.expect("prompt lists files", "/task/public/t1/app.js" in p and
                 "/task/public/t1/samples.json" in p)
        c.expect("prompt states budget", "400 tool calls" in p and "120 minutes" in p)
        c.expect("prompt names the submission", "/task/work/submission/answers.json" in p
                 and "/task/work/submission/T1-01.py" in p and "`sign`" in p)
        c.expect("prompt has no host path or sealed", "/Users" not in p and
                 "sealed" not in p.lower())


def test_overlay(c):
    text = jsw.overlay_text({"run_dir": "/r", "container": "jsw-x", "log": "/r/tools.jsonl",
                             "max_calls": 9, "docker_host": "unix:///s.sock"})
    c.expect("overlay row", "- id: mcp-jsre" in text and '"jsre"' in text)
    c.expect("overlay command", 'command: "%s"' % jsw.JSRE in text)
    c.expect("overlay args", '"--container"' in text and '"jsw-x"' in text and '"9"' in text
             and '"unix:///s.sock"' in text)
    c.expect("overlay keeps sessions in the run", '"/r/dsh/sessions"' in text)
    c.expect("no model row by default", "agent-default-model" not in text)
    text = jsw.overlay_text({"run_dir": "/r", "container": "c", "log": "l", "max_calls": 1,
                             "model": "m1"})
    c.expect("model row uses effort max", 'model: "m1"' in text and
             'reasoningEffort: "max"' in text)


def test_export_and_audit(c):
    with tempfile.TemporaryDirectory() as tmp:
        sub = os.path.join(tmp, "work", "submission")
        os.makedirs(sub)
        with open(os.path.join(sub, "answers.json"), "w") as fh:
            fh.write('{"T1-02": 31}')
        with open(os.path.join(sub, "T1-01.py"), "w") as fh:
            fh.write("def sign(s): return s\n")
        secret = os.path.join(tmp, "secret.json")
        with open(secret, "w") as fh:
            fh.write("SECRET")
        os.symlink(secret, os.path.join(sub, "T1-03.py"))
        os.symlink("/etc/passwd", os.path.join(tmp, "work", "pw"))
        os.symlink("../submission", os.path.join(tmp, "work", "rel"))
        os.makedirs(os.path.join(sub, "dir"))
        rep = jsw.export_submission(tmp)
        c.expect("only regular files exported", rep["files"] == ["T1-01.py", "answers.json"], rep)
        c.expect("symlink not followed", not os.path.exists(
            os.path.join(tmp, "submission", "T1-03.py")) and
            any(s["name"] == "T1-03.py" for s in rep["skipped"]))
        links = jsw.scan_symlinks(os.path.join(tmp, "work"))
        outside = sorted(s["path"] for s in links if not s["inside"])
        c.expect("symlinks found", outside == ["/task/work/pw", "/task/work/submission/T1-03.py"],
                 links)
        shutil.rmtree(sub)
        os.symlink(secret, sub)
        rep = jsw.export_submission(tmp)
        c.expect("submission dir symlink refused", rep["files"] == [] and rep["skipped"])

    run = {"run_dir": "/x/run", "bench": "/x/bench", "max_calls": 3, "container": "jsw-r"}
    good_events = [{"calls": [{"tool": "mcp__jsre__fs_list", "status": "completed"},
                              {"tool": "mcp__jsre__fs_read", "status": "error"}]}]
    good_log = [{"event": "start", "container": "jsw-r", "max_calls": 3},
                {"event": "call", "tool": "fs_list", "arguments": {"path": "/task"},
                 "allowed": True, "call_no": 1, "result": "ok"},
                {"event": "call", "tool": "fs_read", "arguments": {"path": "/etc/passwd"},
                 "allowed": True, "call_no": 2, "refused": True,
                 "reason": "path '/etc/passwd' is outside /task; only /task is visible",
                 "result": "refused"}]
    empty = {"skipped": []}
    a = jsw.audit(good_events, good_log, run, [], [], [], empty)
    c.expect("clean audit", a["ok"] and any("/etc/passwd" in f for f in a["flags"]), a)
    bad = [{"calls": [{"tool": "bash", "status": "completed"}]}]
    c.expect("non-jsre tool is a breach", not jsw.audit(bad, good_log, run, [], [], [],
                                                        empty)["ok"])
    unk = [{"calls": [{"tool": "bash", "status": "error", "error": {"code": "UNKNOWN_TOOL"}}]}]
    a = jsw.audit(unk, good_log, run, [], [], [], empty)
    c.expect("unknown tool only noted", a["ok"] and a["notes"], a)
    many = [{"calls": [{"tool": "mcp__jsre__fs_list", "status": "completed"}] * 3}]
    c.expect("results without log records is a breach",
             not jsw.audit(many, good_log, run, [], [], [], empty)["ok"])
    log = good_log + [{"event": "call", "tool": "node_run", "arguments": {"code": "1"},
                       "allowed": True, "call_no": 4, "result": ""}]
    c.expect("exec past budget is a breach", not jsw.audit([], log, run, [], [], [], empty)["ok"])
    log = good_log + [{"event": "call", "tool": "fs_read", "arguments": {"path": "/etc/x"},
                       "allowed": True, "call_no": 3, "result": "x"}]
    c.expect("allowed outside path is a breach",
             not jsw.audit([], log, run, [], [], [], empty)["ok"])
    log = good_log + [{"event": "call", "tool": "fs_read", "arguments": {"path": "/task/x"},
                       "allowed": True, "call_no": 3, "result": "see /x/bench/sealed"}]
    c.expect("host path out of the sandbox is a breach",
             not jsw.audit([], log, run, [], [], [], empty)["ok"])
    log = good_log + [{"event": "call", "tool": "py_run",
                       "arguments": {"code": "open('/x/bench/sealed/a')"},
                       "allowed": True, "call_no": 3, "result": "No such file: /x/bench/sealed/a"}]
    a = jsw.audit([], log, run, [], [], [], empty)
    c.expect("typed host path is a flag", a["ok"] and any("host path" in f for f in a["flags"])
             and any("sealed" in f for f in a["flags"]), a)
    c.expect("Object.isSealed is not flagged", not jsw.SEALED_RE.search("Object.isSealed(x)"))
    c.expect("staging problems are breaches",
             not jsw.audit([], good_log, run, [], ["x"], [], empty)["ok"])
    c.expect("container problems are breaches",
             not jsw.audit([], good_log, run, [], [], ["network"], empty)["ok"])
    c.expect("start with other budget is a breach", not jsw.audit(
        [], [{"event": "start", "container": "jsw-r", "max_calls": 99}], run, [], [], [],
        empty)["ok"])


def test_merge(c):
    with tempfile.TemporaryDirectory() as tmp:
        runs = os.path.join(tmp, "runs")
        for rid, target, answers, files in [
                ("r1", "t1", {"T1-01": "T1-01.py", "T1-02": 31}, {"T1-01.py": "def sign(s): pass\n"}),
                ("r2", "t2", {"T2-01": 42}, {}),
                ("r3", "t1", {"T1-02": 30}, {})]:
            d = os.path.join(runs, rid)
            os.makedirs(os.path.join(d, "submission"))
            st = jsw.stage(FIXTURE_BENCH, target, os.path.join(tmp, "st-" + rid))
            jsw.save_json(os.path.join(d, "run.json"), {"run_id": rid, "target": target,
                                                        "staging": st})
            jsw.save_json(os.path.join(d, "summary.json"), {"audit": {"ok": rid != "r3"}})
            jsw.save_json(os.path.join(d, "submission", "answers.json"), answers)
            for name, body in files.items():
                with open(os.path.join(d, "submission", name), "w") as fh:
                    fh.write(body)
        env = dict(os.environ, JSW_RUNS=runs)
        out = os.path.join(tmp, "merged")

        def merge(*args):
            p = subprocess.run([sys.executable, os.path.join(JSWORKER, "jsw"), "merge"] +
                               list(args), capture_output=True, text=True, env=env)
            return p.returncode, p.stdout
        rc, so = merge("r1", "r2", "-o", out)
        merged = json.load(open(os.path.join(out, "answers.json")))
        c.expect("merge ok", rc == 0 and merged == {"T1-01": "T1-01.py", "T1-02": 31,
                                                     "T2-01": 42}, (rc, so))
        c.expect("merge copies implementations", os.path.isfile(os.path.join(out, "T1-01.py")))
        rc, so = merge("r1", "r3", "-o", os.path.join(tmp, "m2"))
        c.expect("failed audit refused", rc == 2 and "audit" in so, so)
        rc, so = merge("r1", "r3", "-o", os.path.join(tmp, "m3"), "--force")
        c.expect("overlapping qid refused", rc == 2 and "T1-02 answered by both" in so, so)
        rc, so = merge("r2", "-o", out)
        c.expect("non-empty output refused", rc == 2, so)


def test_server_protocol(c):
    """jsre_mcp.py against a container that does not exist: protocol, budget, fail-closed."""
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "tools.jsonl")

        def start(max_calls):
            return subprocess.Popen([sys.executable, os.path.join(JSWORKER, "jsre_mcp.py"),
                                     "--container", "jsw-no-such-container", "--log", log,
                                     "--max-calls", str(max_calls), "--docker", jsw.DOCKER],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "fs_read", "arguments": {"path": "/etc/passwd"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "node_run", "arguments": {"code": "1"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
             "params": {"name": "py_run", "arguments": {"code": "1"}}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "fs_write", "arguments": {"path": "/task/work/x", "content": ""}}},
            {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
             "params": {"name": "bash", "arguments": {"cmd": "id"}}},
        ]
        p = start(2)
        out, err = p.communicate(b"".join(json.dumps(f).encode() + b"\n" for f in frames),
                                 timeout=60)
        replies = {}
        for line in out.splitlines():
            m = json.loads(line)
            replies[m.get("id")] = m
        c.expect("initialize", replies[1]["result"]["serverInfo"]["name"] == "jsre" and
                 replies[1]["result"]["protocolVersion"] == "2025-06-18", replies.get(1))
        names = [t["name"] for t in replies[2]["result"]["tools"]]
        c.expect("tools/list has the nine tools", names == jsre_mcp.TOOL_NAMES, names)
        c.expect("other methods refused", replies[3]["error"]["code"] == -32601)

        def text(i):
            r = replies[i]["result"]
            return r["content"][0]["text"], r["isError"]
        t, e = text(4)
        c.expect("outside path refused", e and "outside /task" in t, t)
        t, e = text(5)
        c.expect("allowed call reaches docker", e and "not running" in t, t)
        t, e = text(6)
        c.expect("execution refused after the budget", e and "budget exhausted" in t and
                 "write your submission" in t.lower(), t)
        t, e = text(7)
        c.expect("fs_write still allowed after the budget", "budget" not in t, t)
        t, e = text(8)
        c.expect("unknown tool refused", e and "unknown tool" in t, t)
        records = [json.loads(l) for l in open(log)]
        calls = sorted((r for r in records if r.get("event") == "call"), key=lambda r: r["id"])
        c.expect("log numbers", [(r["tool"], r.get("call_no"), bool(r.get("over_budget")))
                                 for r in calls] ==
                 [("fs_read", 1, False), ("node_run", 2, False), ("py_run", None, False),
                  ("fs_write", 3, True), ("bash", None, False)], calls)
        c.expect("refusals logged", calls[0].get("refused") and calls[2].get("refused"))

        # a restarted server keeps the count
        p = start(2)
        out, err = p.communicate(b"".join(json.dumps(f).encode() + b"\n" for f in [
            frames[0], {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                        "params": {"name": "fs_list", "arguments": {"path": "/task"}}}]),
            timeout=60)
        r = [json.loads(l) for l in out.splitlines() if json.loads(l).get("id") == 9][0]
        c.expect("budget survives a restart", "budget exhausted" in
                 r["result"]["content"][0]["text"], r)

        # grace calls run out too
        log2 = os.path.join(tmp, "grace.jsonl")
        with open(log2, "w") as fh:
            fh.write(json.dumps({"event": "call", "tool": "fs_write", "call_no": 60,
                                 "over_budget": True}) + "\n")
            for i in range(jsre_mcp.GRACE_CALLS - 1):
                fh.write(json.dumps({"event": "call", "tool": "fs_write", "call_no": 61 + i,
                                     "over_budget": True}) + "\n")
        c.expect("count_log", jsre_mcp.count_log(log2) == (60 + jsre_mcp.GRACE_CALLS - 1,
                                                           jsre_mcp.GRACE_CALLS))
        p = subprocess.Popen([sys.executable, os.path.join(JSWORKER, "jsre_mcp.py"),
                              "--container", "jsw-none", "--log", log2, "--max-calls", "5"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, _ = p.communicate((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                            "params": {"name": "submit_check",
                                                       "arguments": {}}}) + "\n").encode(),
                               timeout=60)
        c.expect("closed after the grace calls", b"No more tool calls" in out, out[:300])

        # fail closed
        for bad in [b"this is not json\n", b"[1, 2]\n", b'{"jsonrpc": "2.0", "method": 5}\n']:
            p = start(5)
            out, err = p.communicate(json.dumps(frames[0]).encode() + b"\n" + bad +
                                     json.dumps(frames[2]).encode() + b"\n", timeout=30)
            ids = [json.loads(l).get("id") for l in out.splitlines()]
            c.expect("malformed frame %r ends the server" % bad[:12],
                     p.returncode == 1 and ids == [1], (p.returncode, ids, err[-200:]))
        fatal = [json.loads(l) for l in open(log) if '"fatal"' in l]
        c.expect("fatal logged", len(fatal) == 3, fatal)


def main():
    c = Checks()
    for t in (test_paths, test_flags, test_run_spec, test_tools_list, test_stage, test_prompt,
              test_overlay, test_export_and_audit, test_merge, test_server_protocol):
        try:
            t(c)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            c.expect("%s raised" % t.__name__, False, exc)
    return c.report()


if __name__ == "__main__":
    sys.exit(main())
