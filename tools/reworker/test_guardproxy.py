#!/usr/bin/env python3
"""Tests for guardproxy.py against fake_mcp_server.py. Run: python3 test_guardproxy.py"""

import json
import os
import select
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROXY = os.path.join(HERE, "guardproxy.py")
FAKE = os.path.join(HERE, "fake_mcp_server.py")
DB = "/x/samples/a.bin"


class Session:
    """A proxy with a fake server behind it, driven one frame at a time."""

    def __init__(self, tmp, mode="strict", max_calls=3, server_args=(), db=DB):
        self.log = os.path.join(tmp, "guard.jsonl")
        self.record = os.path.join(tmp, "server-%d.jsonl" % time.time_ns())
        cmd = [sys.executable, PROXY, "--mode", mode, "--max-calls", str(max_calls),
               "--log", self.log]
        if db:
            cmd += ["--db", db]
        cmd += ["--", sys.executable, FAKE, "--record", self.record] + list(server_args)
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        self.next_id = 100

    def send(self, msg):
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def recv(self, timeout=10):
        ready, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not ready:
            return None
        line = self.p.stdout.readline()
        return json.loads(line) if line else None

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.recv()

    def call(self, name, **arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self, timeout=30):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        return self.p.wait(timeout)

    def wait(self, timeout=15):
        try:
            return self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return "still running"

    def log_records(self):
        with open(self.log) as fh:
            return [json.loads(l) for l in fh]

    def server_calls(self):
        try:
            with open(self.record) as fh:
                frames = [json.loads(l) for l in fh]
        except FileNotFoundError:
            return []
        return [f["params"]["name"] for f in frames if f.get("method") == "tools/call"]


def text(reply):
    return "".join(b.get("text", "") for b in reply["result"]["content"])


def run():
    bad = []
    checks = [0]

    def expect(label, cond, detail=""):

        checks[0] += 1
        if not cond:
            bad.append("%s %s" % (label, detail))

    sys.path.insert(0, HERE)
    import guardproxy as gp
    expect("label: plenty left says nothing more",
           gp.call_label(3, 25).rstrip("\n").endswith("{{3.ret}}"))
    expect("label: low budget warns with the count",
           "5 calls left" in gp.call_label(20, 25) and "1 call left" in gp.call_label(24, 25)
           and "calls left" not in gp.call_label(19, 25))
    expect("label: last call says so", "last call" in gp.call_label(25, 25)
           and gp.call_label(25, 25).startswith("[call 25 of 25] "))
    expect("label: small budgets warn on the call before last",
           "1 call left" in gp.call_label(3, 4) and "left" not in gp.call_label(2, 4))

    with tempfile.TemporaryDirectory() as tmp:
        # -- list filtering, refusal shape, budget, log ------------------------
        s = Session(tmp, max_calls=2, server_args=["--big", "20000"])
        init = s.request("initialize", {"protocolVersion": "2025-06-18"})
        expect("initialize relayed", init and init["result"]["serverInfo"]["name"] == "fake-ida")
        s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = s.request("tools/list")
        names = sorted(t["name"] for t in listed["result"]["tools"])
        expect("tools/list filtered", names == ["execute_python", "list_databases",
                                                "open_database", "reference"], names)

        r = s.call("save_database")
        expect("save refused as a tool result", r["result"]["isError"] is True
               and "reserved for the orchestrator" in text(r) and "error" not in r, r)
        r = s.call("close_database", instance_id="x")
        expect("close refused", r["result"]["isError"] is True)
        r = s.call("open_database", path="/x/samples/other.bin")
        expect("other database refused", r["result"]["isError"] and "only open" in text(r))
        r = s.call("open_database", path=DB + ".i64")
        expect("task database allowed", not r["result"]["isError"], r)
        r = s.call("execute_python", code="import idc\nidc.set_name(1, 'x')")
        expect("strict refuses IDAPython", r["result"]["isError"] and "refused" in text(r))
        r = s.request("tools/call", {"name": "execute_python", "arguments": {
            "code": "rekit.info()", "instance_id": "2c37436dbad4"}})
        expect("instance_id refused", r["result"]["isError"] and "instance_id" in text(r), r)
        r = s.call("execute_python", code="rekit.fn(0x401000)")
        expect("allowed call relayed", not r["result"]["isError"] and "sub_401000" in text(r))
        r = s.call("execute_python", code="rekit.xrefs(0x401000)")
        expect("second call within budget", not r["result"]["isError"])
        r = s.call("execute_python", code="rekit.info()")
        expect("third call over budget", r["result"]["isError"]
               and "budget exhausted" in text(r) and "result JSON now" in text(r), r)
        r = s.call("list_databases")
        expect("non-python tools are outside the budget", not r["result"]["isError"])
        r = s.request("resources/read", {"uri": "x"})
        expect("unknown method gets a JSON-RPC error", r and r.get("error", {}).get("code") == -32601, r)
        r = s.request("ping")
        expect("ping relayed", r and r.get("result") == {})
        expect("clean exit on client EOF", s.close() == 0)

        expect("only allowed calls reached the server",
               s.server_calls() == ["open_database", "execute_python", "execute_python",
                                    "list_databases"], s.server_calls())
        recs = s.log_records()
        calls = [r for r in recs if r.get("event") == "call"]
        expect("one log line per call", len(calls) == 10, len(calls))
        expect("log has start and stop", recs[0]["event"] == "start" and recs[-1]["event"] == "stop")
        big = [c for c in calls if c["tool"] == "execute_python" and c["allowed"]]
        expect("full result logged, not truncated",
               big and len(big[0]["result"]) > 20000 and big[0]["result"].endswith("sub_4BEEF0"))
        expect("log carries arguments and source",
               big[0]["arguments"] == {"code": "rekit.fn(0x401000)"}
               and big[0]["source"] == "ida-mcp" and big[0]["is_error"] is False)
        refused = [c for c in calls if not c["allowed"]]
        expect("refused calls logged with reason", len(refused) == 6 and all(
            c["source"] == "guard" and c["reason"] and c["is_error"] for c in refused))
        expect("budget recorded", max(c.get("budget_used", 0) for c in calls) == 2)

        # -- budget survives a proxy restart (same log) -------------------------
        s = Session(tmp, max_calls=2)
        s.request("initialize", {})
        r = s.call("execute_python", code="rekit.info()")
        expect("restarted proxy remembers the budget", r["result"]["isError"]
               and "budget exhausted" in text(r))
        s.close()

        # -- call numbers ------------------------------------------------------------
        tn = os.path.join(tmp, "numbers")
        os.makedirs(tn)
        s = Session(tn, max_calls=3)
        s.request("initialize", {})

        def first_block(reply):
            return reply["result"]["content"][0].get("text", "")

        r1 = s.call("execute_python", code="rekit.fn(0x401000)")
        r_open = s.call("open_database", path=DB)
        r_ref = s.call("execute_python", code="import os")                 # refused
        r2 = s.call("execute_python", code="rekit.xrefs(0x401000)")
        expect("first call labelled", first_block(r1).startswith("[call 1 of 3]")
               and "{{1.path}}" in first_block(r1), first_block(r1))
        expect("label is a block of its own; the result block is unchanged",
               len(r1["result"]["content"]) == 2
               and json.loads(r1["result"]["content"][1]["text"])["result"]["fn"] == "sub_401000",
               r1["result"]["content"])
        expect("structuredContent untouched", r1["result"].get("structuredContent")
               == json.loads(r1["result"]["content"][1]["text"]), r1["result"])
        expect("other tools are not numbered", "[call" not in text(r_open), text(r_open))
        expect("a refused call gets no number", "[call" not in text(r_ref)
               and r_ref["result"]["isError"], text(r_ref))
        expect("refusals do not use up numbers", first_block(r2).startswith("[call 2 of 3]"),
               first_block(r2))
        s.close()
        s = Session(tn, max_calls=4)                                          # restart
        s.request("initialize", {})
        r3 = s.call("execute_python", code="rekit.info()")
        r4 = s.call("execute_python", code="rekit.info()")
        r5 = s.call("execute_python", code="rekit.info()")
        expect("numbers continue across a restart", first_block(r3).startswith("[call 3 of 4]")
               and first_block(r4).startswith("[call 4 of 4]"), first_block(r3))
        expect("over budget: refused, no number", r5["result"]["isError"]
               and "[call" not in text(r5) and "budget exhausted" in text(r5), text(r5))
        s.close()
        recs = [r for r in s.log_records() if r.get("event") == "call"]
        nums = [(r["tool"], r.get("call_no")) for r in recs]
        expect("call_no in the log", nums == [
            ("execute_python", 1), ("open_database", None), ("execute_python", None),
            ("execute_python", 2), ("execute_python", 3), ("execute_python", 4),
            ("execute_python", None)], nums)
        expect("the logged result has no label", all(
            "[call" not in (r.get("result") or "") for r in recs), recs)

        # -- free mode ------------------------------------------------------------
        t2 = os.path.join(tmp, "free")
        os.makedirs(t2)
        s = Session(t2, mode="free", max_calls=5)
        s.request("initialize", {})
        r = s.call("execute_python", code="import idautils\nlen(list(idautils.Functions()))")
        expect("free allows IDAPython reads", not r["result"]["isError"], r)
        r = s.call("execute_python", code="import subprocess")
        expect("free refuses subprocess", r["result"]["isError"])
        s.close()

        # -- fail closed ----------------------------------------------------------
        t3 = os.path.join(tmp, "die")
        os.makedirs(t3)
        s = Session(t3, server_args=["--die-after", "1"])
        s.request("initialize", {})
        s.call("execute_python", code="rekit.info()")
        rc = s.wait()
        expect("child death ends the proxy with an error", rc == 1, rc)
        expect("child death logged", any(r.get("event") == "fatal" for r in s.log_records()))

        t4 = os.path.join(tmp, "garbage")
        os.makedirs(t4)
        s = Session(t4, server_args=["--garbage-after", "1"])
        s.request("initialize", {})
        s.call("execute_python", code="rekit.info()")
        expect("garbage from the server ends the proxy", s.wait() == 1)

        t5 = os.path.join(tmp, "client-garbage")
        os.makedirs(t5)
        s = Session(t5)
        s.request("initialize", {})
        s.p.stdin.write(b"{not json\n")
        s.p.stdin.flush()
        expect("garbage from the client ends the proxy", s.wait() == 1)

        t6 = os.path.join(tmp, "batch")
        os.makedirs(t6)
        s = Session(t6)
        s.send([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "save_database", "arguments": {}}}])
        expect("a batch frame ends the proxy", s.wait() == 1)
        expect("the batched call never reached the server", s.server_calls() == [])

        t7 = os.path.join(tmp, "leak")
        os.makedirs(t7)
        s = Session(t7, server_args=["--answer-id", "101"])
        s.request("initialize", {})                               # id 101
        s.call("save_database")                                   # id 102, refused
        s.close()
        t7b = os.path.join(tmp, "leak2")
        os.makedirs(t7b)
        s = Session(t7b, server_args=["--answer-id", "102"])
        s.request("initialize", {})                               # id 101
        r = s.call("save_database")                               # id 102, refused
        expect("refused call answered by guard", r["result"]["isError"])
        s.call("list_databases")                                  # id 103; server also answers 102
        rc = s.wait()
        expect("server answering a refused id ends the proxy", rc == 1, rc)
        expect("anomaly logged", any(r.get("event") == "anomaly" for r in s.log_records()))

        t8 = os.path.join(tmp, "nocall")
        os.makedirs(t8)
        s = Session(t8)
        s.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_databases"}})
        expect("tools/call without id ends the proxy", s.wait() == 1)

        # bad command line and missing server
        p = subprocess.run([sys.executable, PROXY, "--mode", "strict", "--max-calls", "1",
                            "--log", os.path.join(tmp, "x.jsonl")], capture_output=True)
        expect("missing -- is a usage error", p.returncode == 2)
        p = subprocess.run([sys.executable, PROXY, "--mode", "strict", "--max-calls", "1",
                            "--log", os.path.join(tmp, "y.jsonl"), "--",
                            "/nonexistent/ida-mcp"], input=b"", capture_output=True, timeout=20)
        expect("unstartable server fails closed", p.returncode == 1, p.returncode)

        # self-test entry point used by rew doctor
        p = subprocess.run([sys.executable, PROXY, "--self-test"], capture_output=True, text=True)
        expect("self-test passes", p.returncode == 0 and json.loads(p.stdout)["ok"], p.stdout)

    for label in bad:
        print("FAIL:", label)
    print("%d checks, %d failed" % (checks[0], len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
