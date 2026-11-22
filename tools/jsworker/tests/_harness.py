"""Shared helpers for the jsworker tests (not a test file itself)."""

import importlib.machinery
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
JSWORKER = os.path.dirname(TESTS)
FIXTURE_BENCH = os.path.join(TESTS, "fixtures", "bench")
sys.path.insert(0, JSWORKER)


def load_jsw():
    loader = importlib.machinery.SourceFileLoader("jsw_cli", os.path.join(JSWORKER, "jsw"))
    spec = importlib.util.spec_from_loader("jsw_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


jsw = load_jsw()
import jsre_mcp  # noqa: E402


class Checks:
    def __init__(self):
        self.n = 0
        self.bad = []

    def expect(self, label, cond, detail=""):
        self.n += 1
        if not cond:
            self.bad.append("%s %s" % (label, str(detail)[:1500]))
        return cond

    def report(self):
        for label in self.bad:
            print("FAIL:", label)
        print("%d checks, %d failed" % (self.n, len(self.bad)))
        return 1 if self.bad else 0


def image_ready():
    return not jsw.image_problems()


class Sandbox:
    """A staged fixture target in a real container (as `jsw run` makes it)."""

    def __init__(self, target="t1"):
        self.tmp = tempfile.mkdtemp(prefix="jsw-test-")
        self.run_dir = os.path.realpath(self.tmp)
        os.makedirs(os.path.join(self.run_dir, "work", "submission"))
        os.chmod(os.path.join(self.run_dir, "work"), 0o777)
        os.chmod(os.path.join(self.run_dir, "work", "submission"), 0o777)
        self.staging = jsw.stage(FIXTURE_BENCH, target, self.run_dir)
        self.run_id = "test-%s" % secrets.token_hex(3)
        self.name, problems = jsw.start_container(self.run_id, self.run_dir,
                                                  jsw.expected_image())
        if problems:
            self.close()
            raise RuntimeError("container: %s" % problems)
        self.log = os.path.join(self.run_dir, "tools.jsonl")

    def server(self, max_calls=100):
        return McpClient(self.name, self.log, max_calls)

    def close(self):
        jsw.remove_container(jsw.container_name(self.run_id))
        shutil.rmtree(self.tmp, ignore_errors=True)


class McpClient:
    """jsre_mcp.py as a subprocess, driven with JSON-RPC frames."""

    def __init__(self, container, log, max_calls=100):
        self.p = subprocess.Popen(
            [sys.executable, os.path.join(JSWORKER, "jsre_mcp.py"), "--container", container,
             "--log", log, "--max-calls", str(max_calls), "--docker", jsw.DOCKER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.next_id = 1
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "0"}})
        self.notify("notifications/initialized")

    def send(self, msg):
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def notify(self, method):
        self.send({"jsonrpc": "2.0", "method": method})

    def request(self, method, params=None):
        mid = self.next_id
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed: %s" % self.p.stderr.read().decode()[-500:])
            reply = json.loads(line)
            if reply.get("id") == mid:
                return reply

    def call(self, tool, **arguments):
        """(text, is_error)."""
        reply = self.request("tools/call", {"name": tool, "arguments": arguments})
        res = reply.get("result") or {}
        text = "".join(b.get("text", "") for b in res.get("content") or [])
        return text, bool(res.get("isError"))

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(30)
        except subprocess.TimeoutExpired:
            self.p.kill()


def read_log(path):
    return jsw.read_log(path)


def wait_for(path, seconds=10):
    end = time.time() + seconds
    while time.time() < end and not os.path.exists(path):
        time.sleep(0.05)
    return os.path.exists(path)
