#!/usr/bin/env python3
"""MCP stdio proxy that enforces the re-worker tool policy.

dsh starts this as the worker's ida MCP server. It starts the real server as
a child and relays newline-delimited JSON-RPC both ways, except that:

- tools/list results are cut down to the tools guard.ALLOWED_TOOLS names, so
  the model never sees save_database or close_database;
- every tools/call is checked with guard.check_ida first. A refused call never
  reaches the child; it is answered with an ordinary tool result whose text is
  the reason, with isError set, so the model can read it and adapt;
- after --max-calls allowed execute_python calls, further ones are refused
  with a message telling the model to write its result. The count is read back
  from the log at start-up, so a restarted proxy keeps the same budget;
- one JSON line per tool call is appended to --log: tool, arguments, decision,
  and the full result text;
- every execute_python call that is relayed gets a number, `call_no` in the
  log, equal to the budget count after it (1, 2, ...; it continues across
  proxy restarts). The worker sees "[call N of MAX] ..." as an extra text
  block ahead of the result, so it can quote values as {{N.path}} (see
  refs.py). Refused and over-budget calls get no number and use none up; a
  numbered call that ida-mcp answers with a JSON-RPC error keeps its number
  but shows no label (there is nothing to quote);
- client methods outside a small allow-list are answered with a JSON-RPC error.

It fails closed: a malformed frame, an internal error, or the child's death
ends the proxy instead of letting traffic through unchecked.

    guardproxy.py --mode strict|free --max-calls N --log PATH [--db PATH] -- CMD...
    guardproxy.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import guard  # noqa: E402

CLIENT_METHODS = {"initialize", "ping", "tools/list", "tools/call",
                  "resources/list", "resources/templates/list", "prompts/list",
                  "logging/setLevel"}
CHILD_GRACE = 20        # seconds the child gets to release its database lease


def budget_message(used):
    return ("call budget exhausted: %d execute_python calls used. Do not call "
            "any more tools. Write your result JSON now with what you have; use "
            "status \"partial\" and list what is still open under unknowns." % used)


def call_label(n, max_calls):
    """The line shown above execute_python result number n."""
    return ("[call %d of %d] quote values from this result as {{%d.path}}, "
            "e.g. {{%d.ret}}\n" % (n, max_calls, n, n))


def result_text(result):
    """Joined text of an MCP tool result (non-text blocks are named, not dropped)."""
    parts = []
    for block in (result or {}).get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
        elif isinstance(block, dict):
            parts.append("[%s block]" % block.get("type"))
    return "".join(parts)


def count_budget(log_path):
    """Allowed execute_python calls already recorded in this run's log."""
    used = 0
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if (rec.get("tool") == "execute_python" and rec.get("allowed")
                        and rec.get("event", "call") == "call"):
                    used += 1
    except FileNotFoundError:
        pass
    return used


class Proxy:
    def __init__(self, mode, max_calls, log_path, command, db=None,
                 stdin=None, stdout=None):
        self.mode = mode
        self.max_calls = max_calls
        self.log_path = log_path
        self.command = command
        self.db = db
        self.stdin = stdin or sys.stdin.buffer
        self.stdout = stdout or sys.stdout.buffer
        self.lock = threading.Lock()
        self.out_lock = threading.Lock()
        self.pending = {}            # json id -> ("list",) or ("call", record)
        self.refused = set()         # json ids answered by the proxy itself
        self.used = count_budget(log_path)
        self.done = threading.Event()
        self.exit_code = 0
        self.closing = False
        self.child = None
        self.log_fd = None

    # -- plumbing ------------------------------------------------------------

    def log(self, record):
        record.setdefault("ts", round(time.time(), 3))
        record.setdefault("pid", os.getpid())
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        with self.lock:
            os.write(self.log_fd, line)

    def to_client(self, msg):
        data = (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        with self.out_lock:
            self.stdout.write(data)
            self.stdout.flush()

    def to_child(self, raw):
        self.child.stdin.write(raw if raw.endswith(b"\n") else raw + b"\n")
        self.child.stdin.flush()

    def fail(self, why):
        """Fail closed: stop relaying, record why, and end the proxy."""
        if self.done.is_set():
            return
        sys.stderr.write("guardproxy: %s\n" % why)
        try:
            self.log({"event": "fatal", "reason": why})
        except Exception:
            pass
        self.exit_code = 1
        self.done.set()

    # -- client -> child -------------------------------------------------------

    def on_client(self, raw):
        msg = json.loads(raw)
        if not isinstance(msg, dict):
            raise ValueError("client sent a non-object frame (batches are not supported)")
        method = msg.get("method")
        if method is None:
            self.to_child(raw)                   # a response to a child request
            return
        if not isinstance(method, str):
            raise ValueError("client frame has a non-string method")
        has_id = "id" in msg
        key = json.dumps(msg.get("id"))
        if method == "tools/call":
            if not has_id:
                raise ValueError("tools/call without an id")
            self.on_call(msg, key, raw)
            return
        if method.startswith("notifications/"):
            self.to_child(raw)
            return
        if method not in CLIENT_METHODS:
            if has_id:
                self.to_client({"jsonrpc": "2.0", "id": msg["id"], "error": {
                    "code": -32601, "message": "%s is not available through the "
                    "re-worker guard proxy" % method}})
                self.log({"event": "method_refused", "method": method})
            return
        if method == "tools/list" and has_id:
            with self.lock:
                self.pending[key] = ("list",)
        self.to_child(raw)

    def on_call(self, msg, key, raw):
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = params.get("name")
        args = params.get("arguments")
        if args is None:
            args = {}
        allowed, reason = guard.check_ida(tool, args, self.mode, self.db)
        record = {"event": "call", "id": msg["id"], "tool": tool, "arguments": args,
                  "allowed": allowed, "reason": reason}
        if allowed and tool == "execute_python":
            with self.lock:
                if self.used >= self.max_calls:
                    allowed = False
                    reason = budget_message(self.used)
                else:
                    self.used += 1
                    record["call_no"] = self.used
                record.update(allowed=allowed, reason=reason, budget_used=self.used)
        if not allowed:
            with self.lock:
                self.refused.add(key)
            result = {"content": [{"type": "text", "text": reason}], "isError": True}
            record.update(result=reason, is_error=True, source="guard")
            self.log(record)
            self.to_client({"jsonrpc": "2.0", "id": msg["id"], "result": result})
            return
        record["started"] = time.time()
        with self.lock:
            self.pending[key] = ("call", record)
        self.to_child(raw)

    # -- child -> client -------------------------------------------------------

    def on_child(self, raw):
        msg = json.loads(raw)
        if not isinstance(msg, dict):
            raise ValueError("server sent a non-object frame (batches are not supported)")
        is_response = "id" in msg and ("result" in msg or "error" in msg) \
            and "method" not in msg
        if not is_response:
            self.to_client(msg)                  # server request or notification
            return
        key = json.dumps(msg["id"])
        with self.lock:
            entry = self.pending.pop(key, None)
            was_refused = key in self.refused
        if was_refused and entry is None:
            # By construction impossible: a refused call is never forwarded.
            self.log({"event": "anomaly", "id": msg["id"], "source": "ida-mcp",
                      "reason": "ida-mcp answered a call the guard refused"})
            raise ValueError("ida-mcp answered a refused call id %s" % key)
        if entry and entry[0] == "list" and isinstance(msg.get("result"), dict):
            tools = msg["result"].get("tools") or []
            kept = [t for t in tools if isinstance(t, dict)
                    and t.get("name") in guard.ALLOWED_TOOLS]
            msg["result"]["tools"] = kept
        elif entry and entry[0] == "call":
            record = entry[1]
            started = record.pop("started")
            if "error" in msg:
                err = msg.get("error") or {}
                record.update(result="JSON-RPC error %s: %s" % (
                    err.get("code"), err.get("message")), is_error=True)
            else:
                res = msg.get("result") or {}
                record.update(result=result_text(res), is_error=bool(res.get("isError")))
                if res.get("structuredContent") is not None:
                    record["structured"] = res["structuredContent"]
            record.update(source="ida-mcp", seconds=round(time.time() - started, 3))
            self.log(record)
            res = msg.get("result")
            if record.get("call_no") and isinstance(res, dict) \
                    and isinstance(res.get("content"), list):
                # The number goes in a block of its own ahead of the result, so
                # the result text (and structuredContent) stay exactly as
                # ida-mcp sent them; the log above has them unlabelled.
                res["content"] = [{"type": "text", "text": call_label(
                    record["call_no"], self.max_calls)}] + res["content"]
        self.to_client(msg)

    # -- threads ---------------------------------------------------------------

    def pump_client(self):
        try:
            while not self.done.is_set():
                raw = self.stdin.readline()
                if self.done.is_set():
                    return
                if not raw:
                    self.shutdown()
                    return
                if raw.strip():
                    self.on_client(raw.rstrip(b"\r\n"))
        except Exception as exc:              # fail closed
            self.fail("client side: %s: %s" % (type(exc).__name__, exc))

    def pump_child(self):
        try:
            while not self.done.is_set():
                raw = self.child.stdout.readline()
                if self.done.is_set():
                    return
                if not raw:
                    if not self.closing:
                        self.fail("ida-mcp exited unexpectedly (code %s)"
                                  % self.child.poll())
                    self.done.set()
                    return
                if raw.strip():
                    self.on_child(raw.rstrip(b"\r\n"))
        except Exception as exc:              # fail closed
            self.fail("server side: %s: %s" % (type(exc).__name__, exc))

    def shutdown(self):
        """Client closed its side: let the child release its lease and exit."""
        self.closing = True
        try:
            self.child.stdin.close()
        except Exception:
            pass
        try:
            self.child.wait(CHILD_GRACE)
        except subprocess.TimeoutExpired:
            self.child.terminate()
        self.done.set()

    def flush_pending(self):
        with self.lock:
            left = [e[1] for e in self.pending.values() if e[0] == "call"]
            self.pending.clear()
        for record in left:
            record.pop("started", None)
            record.update(result=None, is_error=True, source=None, incomplete=True)
            self.log(record)

    def run(self):
        self.log_fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            self.child = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE)
        except OSError as exc:
            self.fail("cannot start %s: %s" % (self.command[0], exc))
            return 1
        self.log({"event": "start", "mode": self.mode, "max_calls": self.max_calls,
                  "budget_used": self.used, "db": self.db, "command": self.command})

        def on_term(signum, _frame):
            self.closing = True
            self.done.set()
        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGINT, on_term)

        for target in (self.pump_client, self.pump_child):
            threading.Thread(target=target, daemon=True).start()
        while not self.done.wait(0.5):
            pass
        self.flush_pending()
        if self.child.poll() is None:
            try:
                self.child.stdin.close()
            except Exception:
                pass
            try:
                self.child.wait(CHILD_GRACE if self.closing else 2)
            except subprocess.TimeoutExpired:
                self.child.terminate()
                try:
                    self.child.wait(5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
        self.log({"event": "stop", "exit": self.exit_code, "budget_used": self.used})
        return self.exit_code


# --------------------------------------------------------------------------
# self-test against fake_mcp_server.py, for `rew doctor`
# --------------------------------------------------------------------------

def self_test():
    """Run the proxy against the fake server; return a list of failures."""
    import tempfile
    fails = []
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "guard.jsonl")
        record = os.path.join(tmp, "server.jsonl")
        cmd = [sys.executable, os.path.abspath(__file__), "--mode", "strict",
               "--max-calls", "1", "--log", log, "--",
               sys.executable, os.path.join(HERE, "fake_mcp_server.py"), "--record", record]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "save_database", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                "name": "execute_python", "arguments": {"code": "import os"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
                "name": "execute_python", "arguments": {"code": "rekit.info()"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
                "name": "execute_python", "arguments": {"code": "rekit.info()"}}},
        ]
        out, err = p.communicate(b"".join(json.dumps(f).encode() + b"\n" for f in frames),
                                 timeout=30)
        replies = {}
        for line in out.splitlines():
            msg = json.loads(line)
            replies[msg.get("id")] = msg
        tools = [t["name"] for t in replies.get(2, {}).get("result", {}).get("tools", [])]
        if sorted(tools) != sorted(guard.ALLOWED_TOOLS):
            fails.append("tools/list not filtered: %s" % tools)
        for i, label in ((3, "save_database"), (4, "import os"), (6, "over budget")):
            res = replies.get(i, {}).get("result", {})
            if not res.get("isError"):
                fails.append("%s was not refused" % label)
        if replies.get(5, {}).get("result", {}).get("isError"):
            fails.append("an allowed call was refused")
        blocks = replies.get(5, {}).get("result", {}).get("content") or [{}]
        if not str(blocks[0].get("text", "")).startswith("[call 1 of 1]"):
            fails.append("the allowed call is not numbered: %s" % blocks[0])
        try:
            with open(record) as fh:
                seen = [json.loads(l)["params"]["name"] for l in fh
                        if json.loads(l).get("method") == "tools/call"]
        except OSError:
            seen = []
        if seen != ["execute_python"]:
            fails.append("calls that reached the server: %s" % seen)
        if p.returncode != 0:
            fails.append("proxy exit %s: %s" % (p.returncode, err.decode()[-300:]))
        with open(log) as fh:
            calls = [json.loads(l) for l in fh if '"event": "call"' in l]
        decisions = {c["id"]: c["allowed"] for c in calls}
        if decisions != {3: False, 4: False, 5: True, 6: False}:
            fails.append("log decisions: %s" % decisions)
        numbers = {c["id"]: c.get("call_no") for c in calls}
        if numbers != {3: None, 4: None, 5: 1, 6: None}:
            fails.append("log call numbers: %s" % numbers)
    return fails


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["--self-test"]:
        fails = self_test()
        print(json.dumps({"ok": not fails, "failures": fails}))
        return 1 if fails else 0
    if "--" not in argv:
        sys.stderr.write("guardproxy: expected `-- <server command>`\n")
        return 2
    split = argv.index("--")
    parser = argparse.ArgumentParser(prog="guardproxy.py")
    parser.add_argument("--mode", choices=("strict", "free"), required=True)
    parser.add_argument("--max-calls", type=int, required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--db")
    opts = parser.parse_args(argv[:split])
    command = argv[split + 1:]
    if not command:
        sys.stderr.write("guardproxy: no server command after --\n")
        return 2
    if opts.max_calls < 0:
        sys.stderr.write("guardproxy: --max-calls must be >= 0\n")
        return 2
    return Proxy(opts.mode, opts.max_calls, opts.log, command, opts.db).run()


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    # Reader threads may still be blocked on a pipe; a normal interpreter
    # shutdown would then abort while taking the stdin lock.
    os._exit(code)
