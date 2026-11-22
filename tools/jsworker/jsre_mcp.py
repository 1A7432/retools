#!/usr/bin/env python3
"""jsre: the MCP stdio server that is the js-worker's only tool source.

dsh starts it from the per-run overlay written by `jsw`. It speaks
newline-delimited JSON-RPC (MCP) on stdin/stdout and offers nine tools:

    fs_list  fs_read  fs_grep  fs_write  fs_edit
    node_run  py_run  js_beautify  submit_check

Every tool runs inside the run's container through `docker exec` with an argv
list (never a shell): file operations through jsre_helper.py (sent as
`python3 -I -c SOURCE`), programs as

    node --permission --allow-fs-read=/task --allow-fs-read=/opt/jsre
         --allow-fs-write=/task/work [--stack-size=N] [--max-old-space-size=N] FILE ARGS
    python3 -I -B -X utf8 /opt/jsre/pyrun.py FILE ARGS

each wrapped in coreutils `timeout` inside the container, so a runaway program
dies there even if this process is killed.

Policy (HARNESS.md sections 3 and 5.3):
- paths must be absolute, and still under /task after normalisation; writes
  only under /task/work. The helper re-checks after resolving symlinks.
- node flags: only --stack-size=N and --max-old-space-size=N.
- program output over 20000 characters is cut to head and tail; the full
  text is saved as /task/work/.jsw/out/<n>.txt.
- call budget (--max-calls): every executed call takes a number; after the
  budget, the execution tools are refused ("write your submission now") while
  fs_write, fs_edit and submit_check keep working for GRACE_CALLS more calls.
  The count is read back from the log at start-up, so a restarted server (jsw
  resume) keeps the same budget.
- one JSON line per tool call in --log: tool, arguments, decision, call
  number, seconds, exit code, the text the model saw, and the path of the
  saved full output.

It fails closed: a frame that is not a JSON object ends the server.

    jsre_mcp.py --container NAME --log PATH --max-calls N [--docker PATH] [--docker-host URL]
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "jsre_helper.py")

SERVER_NAME = "jsre"
SERVER_VERSION = "1.0"
USER = "1000:1000"
WORKDIR = "/task/work"
ROOT = "/task"
OUT_DIR = "/task/work/.jsw/out"
CODE_DIR = "/task/work/.jsw/code"
SUBMISSION = "/task/work/submission"
NODE_BASE = ["node", "--permission", "--allow-fs-read=/task", "--allow-fs-read=/opt/jsre",
             "--allow-fs-write=/task/work"]
NODE_FLAG_RE = re.compile(r"^--(stack-size=[1-9][0-9]{0,5}|max-old-space-size=[1-9][0-9]{0,4})$")
# -B: never write __pycache__ under /task/work. -I ignores PYTHONDONTWRITEBYTECODE, and
# a .pyc written in the same second as an equally long edit would be reused stale.
PY_BASE = ["python3", "-I", "-B", "-X", "utf8", "/opt/jsre/pyrun.py"]
GRADE_RUNNER = ["python3", "-I", "-B", "-X", "utf8", "/opt/jsre/grade_runner.py"]
BEAUTIFY = "/opt/jsre/beautify.js"

MAX_OUTPUT = 20000           # characters of program output shown to the model
CAPTURE_CAP = 8 << 20        # bytes kept per stream; the rest is discarded
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 600
FS_TIMEOUT = 120             # fs_* helper calls (a slow regex is killed after this)
BEAUTIFY_TIMEOUT = 300
CHECK_TIMEOUT = 130          # one implementation over its public samples
KILL_GRACE = 5               # `timeout -k`: SIGKILL this long after SIGTERM
HOST_GRACE = 20              # extra seconds before the host gives up on docker exec
MAX_CODE = 100000            # characters of inline code (an argv string is capped by Linux)
MAX_CONTENT = 4 << 20        # characters per fs_write
MAX_ARGS = 200
GRACE_CALLS = 50             # submission calls accepted after the budget is spent
WORKERS = 4                  # tool calls run concurrently at most

EXEC_TOOLS = ("fs_list", "fs_read", "fs_grep", "node_run", "py_run", "js_beautify")
SUBMIT_TOOLS = ("fs_write", "fs_edit", "submit_check")
CLIENT_METHODS = {"initialize", "ping", "tools/list", "tools/call"}
PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")


def _s(desc, **kw):
    d = {"type": "string", "description": desc}
    d.update(kw)
    return d


def _i(desc, **kw):
    d = {"type": "integer", "description": desc}
    d.update(kw)
    return d


def _obj(props, required=()):
    return {"type": "object", "properties": props, "required": list(required),
            "additionalProperties": False}


RUN_COMMON = {
    "args": {"type": "array", "items": {"type": "string"},
             "description": "Arguments passed to the program after the file."},
    "stdin": _s("Text fed to the program's standard input (default empty)."),
    "timeout": _i("Seconds before the program is killed (default 60, at most 600)."),
}

TOOLS = [
    {"name": "fs_list",
     "description": "List a directory under /task, recursively to `depth` levels "
                    "(default 2, at most 6). Files show their size in bytes and the "
                    "first 12 hex digits of their sha256.",
     "inputSchema": _obj({"path": _s("Absolute path under /task."),
                          "depth": _i("Levels to descend (default 2).")}, ["path"])},
    {"name": "fs_read",
     "description": "Read a text file under /task. unit=\"line\" (default): offset is the "
                    "first line number (1-based, default 1) and limit the number of lines "
                    "(default 400). unit=\"byte\": offset is a 0-based byte offset and "
                    "limit a byte count; use it for minified files whose single line is "
                    "hundreds of KB. At most 40000 bytes of the file are returned per call; "
                    "the reply says where to continue.",
     "inputSchema": _obj({"path": _s("Absolute path under /task."),
                          "offset": _i("First line (unit=line) or first byte (unit=byte)."),
                          "limit": _i("Number of lines (unit=line) or bytes (unit=byte)."),
                          "unit": _s("\"line\" or \"byte\".", enum=["line", "byte"])},
                         ["path"])},
    {"name": "fs_grep",
     "description": "Search a file, or every file under a directory, for a Python regular "
                    "expression applied line by line to the raw UTF-8 bytes. Each hit is "
                    "shown as path:line:byte-offset: text; a long line is shown only "
                    "200 bytes either side of the match (read more with fs_read "
                    "unit=\"byte\").",
     "inputSchema": _obj({"pattern": _s("Python `re` pattern."),
                          "path": _s("File or directory under /task."),
                          "max": _i("Most hits to show (default 50, at most 500).")},
                         ["pattern", "path"])},
    {"name": "fs_write",
     "description": "Create or overwrite a UTF-8 text file under /task/work; missing parent "
                    "directories are created.",
     "inputSchema": _obj({"path": _s("Absolute path under /task/work."),
                          "content": _s("The whole file content.")}, ["path", "content"])},
    {"name": "fs_edit",
     "description": "Replace the exact text `old` with `new` in a file under /task/work. "
                    "`old` must occur exactly once in the file.",
     "inputSchema": _obj({"path": _s("Absolute path under /task/work."),
                          "old": _s("Text to replace, copied exactly."),
                          "new": _s("Replacement text.")}, ["path", "old", "new"])},
    {"name": "node_run",
     "description": "Run JavaScript with Node.js v22.21.1 in the sandbox, as `node "
                    "--permission --allow-fs-read=/task --allow-fs-read=/opt/jsre "
                    "--allow-fs-write=/task/work [node_flags] FILE ARGS` with working "
                    "directory /task/work. Give `file` (a script under /task) or `code` "
                    "(saved as /task/work/.jsw/code/<n>.js and run as that file, so a "
                    "relative require() starts there; prefer absolute paths). The program "
                    "may read /task and write /task/work; there is no network and child "
                    "processes and worker threads are denied. NODE_PATH provides "
                    "@babel/parser, @babel/traverse, @babel/generator, @babel/types, acorn, "
                    "acorn-walk and astring. Output beyond 20000 characters is cut to its "
                    "head and tail and saved in full under /task/work/.jsw/out/.",
     "inputSchema": _obj(dict({
         "file": _s("Script path under /task."),
         "code": _s("JavaScript source to run instead of a file."),
         "node_flags": {"type": "array", "items": {"type": "string"},
                        "description": "Only --stack-size=N and --max-old-space-size=N."},
     }, **RUN_COMMON))},
    {"name": "py_run",
     "description": "Run Python 3.13 in the sandbox, as `python3 -I -B -X utf8 "
                    "/opt/jsre/pyrun.py FILE ARGS` with working directory /task/work. Give "
                    "`file` (a script under /task) or `code` (saved as "
                    "/task/work/.jsw/code/<n>.py and run as that file). Third-party "
                    "packages: pycryptodome (import Crypto) and gmssl only - the same "
                    "environment the graded implementations run in. Subprocesses, sockets "
                    "and loading native libraries are blocked; there is no network. Output "
                    "beyond 20000 characters is cut to its head and tail and saved in full "
                    "under /task/work/.jsw/out/.",
     "inputSchema": _obj(dict({
         "file": _s("Script path under /task."),
         "code": _s("Python source to run instead of a file."),
     }, **RUN_COMMON))},
    {"name": "js_beautify",
     "description": "Re-print a JavaScript file with @babel/generator: one statement per "
                    "line and normal indentation. Layout only: no renaming, no constant "
                    "folding, no deobfuscation.",
     "inputSchema": _obj({"path": _s("JavaScript file under /task."),
                          "out": _s("Output path under /task/work.")}, ["path", "out"])},
    {"name": "submit_check",
     "description": "Check /task/work/submission/: answers.json is a JSON object whose keys "
                    "are this target's question ids; each implementation answer names a "
                    ".py file there that defines the required function and imports only "
                    "the standard library, Crypto (pycryptodome) and gmssl. Then run every "
                    "implementation on its public samples and report pass/fail per "
                    "sample. Passing the public samples does not guarantee a correct grade.",
     "inputSchema": _obj({})},
]
TOOL_NAMES = [t["name"] for t in TOOLS]


def budget_message(used, max_calls):
    return ("Tool budget exhausted: %d of %d calls used. The execution tools are closed. "
            "Write your submission now: put your answers in /task/work/submission/ with "
            "fs_write or fs_edit, and validate them with submit_check." % (used, max_calls))


def closed_message():
    return ("No more tool calls are accepted: the call budget and the extra calls for "
            "writing the submission are both used up. Stop and give your final reply.")


class Refusal(Exception):
    """A call the policy does not allow; the model sees the reason."""


class ToolError(Exception):
    """A call that was allowed but failed; the model sees the message."""


# --------------------------------------------------------------------------
# argument checks (pure; tested without docker)
# --------------------------------------------------------------------------

def check_path(value, name="path", write=False):
    """The normalised container path, or raise Refusal."""
    if not isinstance(value, str) or not value:
        raise Refusal("%s is required (an absolute path under /task)" % name)
    if "\x00" in value or len(value) > 4096:
        raise Refusal("%s is not a usable path" % name)
    if not value.startswith("/"):
        raise Refusal("%s %r is not absolute; give a path under /task (your files are in "
                      "/task/work, the target in /task/public)" % (name, value))
    norm = posixpath.normpath(value)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    root = "/task/work" if write else ROOT
    if norm != root and not norm.startswith(root + "/"):
        if write:
            raise Refusal("%s %r is outside /task/work; only /task/work is writable"
                          % (name, value))
        raise Refusal("%s %r is outside /task; only /task is visible" % (name, value))
    return norm


def check_flags(flags):
    if flags is None:
        return []
    if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
        raise Refusal("node_flags must be a list of strings")
    for f in flags:
        if not NODE_FLAG_RE.match(f):
            raise Refusal("node flag %r is not allowed; only --stack-size=N and "
                          "--max-old-space-size=N may be given" % f)
    return list(flags)


def check_args(arguments, allowed, required=()):
    if not isinstance(arguments, dict):
        raise Refusal("arguments must be a JSON object")
    extra = sorted(set(arguments) - set(allowed))
    if extra:
        raise Refusal("unknown argument(s): %s" % ", ".join(extra))
    for key in required:
        if arguments.get(key) is None:
            raise Refusal("%s is required" % key)


def opt_int(arguments, key, default, lo, hi):
    v = arguments.get(key)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        elif isinstance(v, str) and v.strip().isdigit():
            v = int(v.strip())
        else:
            raise Refusal("%s must be an integer" % key)
    if v < lo or v > hi:
        raise Refusal("%s must be between %d and %d" % (key, lo, hi))
    return v


def run_spec(tool, arguments):
    """Validated (argv_prefix, file, code, args, stdin, timeout) for node_run/py_run."""
    keys = ["file", "code", "args", "stdin", "timeout"] + (["node_flags"] if tool == "node_run"
                                                           else [])
    check_args(arguments, keys)
    file, code = arguments.get("file"), arguments.get("code")
    if (file is None) == (code is None):
        raise Refusal("give exactly one of file or code")
    if file is not None:
        file = check_path(file, "file")
    elif not isinstance(code, str):
        raise Refusal("code must be a string")
    elif len(code) > MAX_CODE:
        raise Refusal("code is %d characters; the limit is %d. Write it to a file under "
                      "/task/work with fs_write and run the file" % (len(code), MAX_CODE))
    args = arguments.get("args") or []
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise Refusal("args must be a list of strings")
    if len(args) > MAX_ARGS or sum(len(a) for a in args) > MAX_CODE:
        raise Refusal("too many or too long args; pass data through a file or stdin")
    if any("\x00" in a for a in args):
        raise Refusal("args must not contain NUL characters")
    stdin = arguments.get("stdin") or ""
    if not isinstance(stdin, str):
        raise Refusal("stdin must be a string")
    if len(stdin) > MAX_CONTENT:
        raise Refusal("stdin is too long; pass data through a file")
    timeout = opt_int(arguments, "timeout", DEFAULT_TIMEOUT, 1, MAX_TIMEOUT)
    if tool == "node_run":
        prefix = NODE_BASE + check_flags(arguments.get("node_flags"))
    else:
        prefix = list(PY_BASE)
    return prefix, file, code, args, stdin, timeout


def fit_output(text, saved_path):
    """Head and tail of text when it is longer than MAX_OUTPUT."""
    if len(text) <= MAX_OUTPUT:
        return text
    half = MAX_OUTPUT // 2
    return (text[:half] + "\n\n... [%d characters omitted; the full output (%d characters) "
            "is in %s] ...\n\n" % (len(text) - 2 * half, len(text), saved_path)
            + text[-half:])


# --------------------------------------------------------------------------
# the container side
# --------------------------------------------------------------------------

class Capture:
    """Read a pipe to EOF, keeping at most CAPTURE_CAP bytes."""

    def __init__(self, pipe):
        self.pipe = pipe
        self.chunks = []
        self.size = 0
        self.dropped = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while True:
                chunk = self.pipe.read(65536)
                if not chunk:
                    break
                room = CAPTURE_CAP - self.size
                if room > 0:
                    self.chunks.append(chunk[:room])
                    self.size += min(room, len(chunk))
                self.dropped += max(0, len(chunk) - max(room, 0))
        except (OSError, ValueError):
            pass

    def text(self):
        self.thread.join(5)
        return b"".join(self.chunks).decode("utf-8", "replace")


def docker_failed(res):
    """Raise ToolError when docker itself (not the program) failed."""
    err = res["stderr"].lstrip()
    if not res["stdout"] and res["exit"] != 0 and (
            err.startswith("Error response from daemon") or err.startswith("Error: No such")
            or "Cannot connect to the Docker daemon" in err):
        if "is not running" in err or "No such container" in err:
            raise ToolError("the sandbox container is not running")
        raise ToolError("the sandbox is unavailable (docker exit %s)" % res["exit"])


class Container:
    """docker exec into one run's container."""

    def __init__(self, name, docker="docker", docker_host=None):
        self.name = name
        self.docker = docker
        self.env = dict(os.environ)
        if docker_host:
            self.env["DOCKER_HOST"] = docker_host
        with open(HELPER, encoding="utf-8") as fh:
            self.helper_src = fh.read()

    def exec(self, argv, stdin=b"", timeout=DEFAULT_TIMEOUT):
        """Run argv in the container. Returns dict(exit, stdout, stderr, seconds,
        timed_out, dropped). `timeout` runs inside the container."""
        cmd = [self.docker, "exec", "-i", "--user", USER, "-w", WORKDIR, self.name,
               "timeout", "-k", str(KILL_GRACE), str(timeout)] + list(argv)
        started = time.time()
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.env)
        except OSError as exc:
            raise ToolError("cannot run docker: %s" % exc)
        out, err = Capture(p.stdout), Capture(p.stderr)

        def feed():
            try:
                if stdin:
                    p.stdin.write(stdin)
                p.stdin.close()
            except (OSError, ValueError):
                pass
        threading.Thread(target=feed, daemon=True).start()
        host_kill = False
        try:
            rc = p.wait(timeout + KILL_GRACE + HOST_GRACE)
        except subprocess.TimeoutExpired:
            host_kill = True
            p.kill()
            rc = p.wait()
        seconds = time.time() - started
        stdout, stderr = out.text(), err.text()
        timed_out = host_kill or (rc in (124, 137) and seconds >= timeout - 0.5)
        return {"exit": rc, "stdout": stdout, "stderr": stderr, "seconds": round(seconds, 3),
                "timed_out": timed_out, "dropped": out.dropped + err.dropped}

    def helper(self, req, timeout=FS_TIMEOUT):
        """One jsre_helper.py operation. Returns the reply dict."""
        res = self.exec(["python3", "-I", "-X", "utf8", "-c", self.helper_src],
                        json.dumps(req, ensure_ascii=False).encode("utf-8"), timeout)
        if res["timed_out"]:
            raise ToolError("the operation took longer than %d s and was stopped" % timeout)
        try:
            reply = json.loads(res["stdout"])
        except ValueError:
            docker_failed(res)
            detail = (res["stderr"] or res["stdout"]).strip()[-800:]
            raise ToolError("the operation failed (exit %s): %s" % (res["exit"], detail))
        if not reply.get("ok"):
            if reply.get("refused"):
                raise Refusal(reply.get("error"))
            raise ToolError(reply.get("error") or "failed")
        return reply

    def save(self, path, content):
        return self.helper({"op": "save", "path": path, "content": content})


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------

class Tools:
    """The nine tools. Each returns (text, extra-log-fields) or raises."""

    def __init__(self, container):
        self.c = container

    def call(self, tool, arguments, call_no):
        return getattr(self, "t_" + tool)(arguments, call_no)

    def t_fs_list(self, a, n):
        check_args(a, ["path", "depth"], ["path"])
        path = check_path(a["path"])
        depth = opt_int(a, "depth", 2, 1, 6)
        return self.c.helper({"op": "list", "path": path, "depth": depth})["text"], {}

    def t_fs_read(self, a, n):
        check_args(a, ["path", "offset", "limit", "unit"], ["path"])
        path = check_path(a["path"])
        unit = a.get("unit") or "line"
        if unit not in ("line", "byte"):
            raise Refusal("unit must be \"line\" or \"byte\"")
        if unit == "line":
            offset = opt_int(a, "offset", None, 0, 1 << 40)
            limit = opt_int(a, "limit", 400, 1, 100000)
        else:
            offset = opt_int(a, "offset", 0, 0, 1 << 40)
            limit = opt_int(a, "limit", 40000, 1, 1 << 30)
        return self.c.helper({"op": "read", "path": path, "offset": offset, "limit": limit,
                              "unit": unit})["text"], {}

    def t_fs_grep(self, a, n):
        check_args(a, ["pattern", "path", "max"], ["pattern", "path"])
        if not isinstance(a["pattern"], str) or not a["pattern"]:
            raise Refusal("pattern must be a non-empty string")
        path = check_path(a["path"])
        limit = opt_int(a, "max", 50, 1, 500)
        return self.c.helper({"op": "grep", "pattern": a["pattern"], "path": path,
                              "max": limit})["text"], {}

    def t_fs_write(self, a, n):
        check_args(a, ["path", "content"], ["path", "content"])
        path = check_path(a["path"], write=True)
        if not isinstance(a["content"], str):
            raise Refusal("content must be a string")
        if len(a["content"]) > MAX_CONTENT:
            raise Refusal("content is longer than %d characters" % MAX_CONTENT)
        return self.c.helper({"op": "write", "path": path, "content": a["content"]})["text"], {}

    def t_fs_edit(self, a, n):
        check_args(a, ["path", "old", "new"], ["path", "old", "new"])
        path = check_path(a["path"], write=True)
        if not isinstance(a["old"], str) or not isinstance(a["new"], str):
            raise Refusal("old and new must be strings")
        return self.c.helper({"op": "edit", "path": path, "old": a["old"],
                              "new": a["new"]})["text"], {}

    def _program(self, argv, stdin, timeout, n, code_path=None):
        res = self.c.exec(argv, stdin.encode("utf-8"), timeout)
        docker_failed(res)
        if res["timed_out"]:
            status = "TIMEOUT: stopped after %d s" % timeout
        else:
            status = "exit code %s" % res["exit"]
        head = "[%s, %.2f s%s]\n" % (status, res["seconds"],
                                     ", code saved as %s" % code_path if code_path else "")
        body = res["stdout"]
        if res["stderr"]:
            if body and not body.endswith("\n"):
                body += "\n"
            body += "--- stderr ---\n" + res["stderr"]
        if res["dropped"]:
            body += "\n[%d further bytes of output were discarded]" % res["dropped"]
        extra = {"exit": res["exit"], "timed_out": res["timed_out"],
                 "run_seconds": res["seconds"]}
        if len(body) > MAX_OUTPUT:
            saved = "%s/%d.txt" % (OUT_DIR, n)
            try:
                self.c.save(saved, head + body)
                extra["saved"] = saved
            except (Refusal, ToolError) as exc:
                saved = "(not saved: %s)" % exc
            body = fit_output(body, saved)
        return head + body, extra

    def _run(self, tool, a, n):
        prefix, file, code, args, stdin, timeout = run_spec(tool, a)
        code_path = None
        if code is not None:
            code_path = "%s/%d.%s" % (CODE_DIR, n, "js" if tool == "node_run" else "py")
            self.c.save(code_path, code)
            file = code_path
        return self._program(prefix + [file] + args, stdin, timeout, n, code_path)

    def t_node_run(self, a, n):
        return self._run("node_run", a, n)

    def t_py_run(self, a, n):
        return self._run("py_run", a, n)

    def t_js_beautify(self, a, n):
        check_args(a, ["path", "out"], ["path", "out"])
        src = check_path(a["path"])
        out = check_path(a["out"], "out", write=True)
        argv = NODE_BASE + ["--max-old-space-size=3072", BEAUTIFY, src, out]
        return self._program(argv, "", BEAUTIFY_TIMEOUT, n)

    def t_submit_check(self, a, n):
        check_args(a, [])
        report = submit_check(self.c)
        return report["text"], {"check": {k: report[k] for k in
                                          ("errors", "passed", "failed", "missing")}}


def same(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=False) == \
        json.dumps(b, sort_keys=True, ensure_ascii=False)


def short(v, n=200):
    s = json.dumps(v, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "...(%d chars)" % len(s)


def submit_check(container):
    """Static checks in the container, then each implementation on its public
    samples through /opt/jsre/grade_runner.py. Returns a dict with a text report."""
    data = container.helper({"op": "check"})["data"]
    lines = []
    errors = list(data["errors"])
    warnings = list(data["warnings"])
    passed = failed = 0
    for item in data["impl"]:
        label = "%s (implementation of %s%s)" % (
            item["qid"], item["function"], " in %s" % item["file"] if item["file"] else "")
        errors += ["%s: %s" % (item["qid"], e) for e in item["errors"]]
        warnings += ["%s: %s" % (item["qid"], w) for w in item["warnings"]]
        if item["errors"]:
            lines.append("%s: not run (see errors)" % label)
            continue
        if not item["inputs"]:
            lines.append("%s: no public samples to run" % label)
            continue
        res = container.exec(GRADE_RUNNER + ["%s/%s" % (SUBMISSION, item["file"]),
                                             item["function"], item["inputs"]],
                             b"", CHECK_TIMEOUT)
        results = {}
        for line in res["stdout"].splitlines():
            if line.startswith("@@R "):
                try:
                    rec = json.loads(line[4:])
                except ValueError:
                    continue
                results[rec.get("i")] = rec
        expected = item["expected"]
        sample_lines = []
        ok = 0
        if -1 in results:
            sample_lines.append("  could not load: %s" % results[-1].get("err"))
        else:
            for i, want in enumerate(expected):
                rec = results.get(i)
                if rec is None:
                    sample_lines.append("  sample %d: no result (%s)" % (
                        i + 1, "timed out" if res["timed_out"] else "the run stopped early"))
                elif not rec.get("ok"):
                    sample_lines.append("  sample %d: ERROR %s" % (i + 1, rec.get("err")))
                elif same(rec.get("out"), want):
                    ok += 1
                    sample_lines.append("  sample %d: pass" % (i + 1))
                else:
                    sample_lines.append("  sample %d: FAIL expected %s, got %s"
                                        % (i + 1, short(want), short(rec.get("out"))))
        passed += ok
        failed += len(expected) - ok
        lines.append("%s: public samples %d/%d passed" % (label, ok, len(expected)))
        lines += sample_lines
        tail = res["stderr"].strip()
        if tail:
            lines.append("  stderr (last 1500 chars): " + tail[-1500:])
    head = "submit_check: %s" % ("OK" if not errors else "%d error(s)" % len(errors))
    head += "; answered %d of %d questions" % (len(data["answered"]), len(data["questions"]))
    if data["missing"]:
        head += "; not answered: %s" % ", ".join(data["missing"])
    out = [head] + lines
    if errors:
        out += ["errors:"] + ["  - " + e for e in errors]
    if warnings:
        out += ["warnings:"] + ["  - " + w for w in warnings]
    return {"text": "\n".join(out), "errors": errors, "warnings": warnings,
            "passed": passed, "failed": failed, "missing": data["missing"],
            "answered": data["answered"]}


# --------------------------------------------------------------------------
# the MCP server
# --------------------------------------------------------------------------

def count_log(log_path):
    """(last call number, calls made after the budget) recorded in the log."""
    last = grace = 0
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("event") == "call" \
                        and isinstance(rec.get("call_no"), int):
                    last = max(last, rec["call_no"])
                    if rec.get("over_budget"):
                        grace += 1
    except FileNotFoundError:
        pass
    return last, grace


class Server:
    def __init__(self, container, log_path, max_calls, stdin=None, stdout=None):
        self.container = container
        self.tools = Tools(container)
        self.log_path = log_path
        self.max_calls = max_calls
        self.stdin = stdin or sys.stdin.buffer
        self.stdout = stdout or sys.stdout.buffer
        self.lock = threading.Lock()
        self.out_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(WORKERS)
        self.last, self.grace = count_log(log_path)
        self.active = set()
        self.done = threading.Event()
        self.exit_code = 0
        self.log_fd = None

    def log(self, record):
        record.setdefault("ts", round(time.time(), 3))
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        with self.lock:
            os.write(self.log_fd, line)

    def send(self, msg):
        data = (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        with self.out_lock:
            self.stdout.write(data)
            self.stdout.flush()

    def fail(self, why):
        sys.stderr.write("jsre_mcp: %s\n" % why)
        try:
            self.log({"event": "fatal", "reason": why})
        except Exception:
            pass
        self.exit_code = 1
        self.done.set()

    # -- requests ----------------------------------------------------------------

    def on_frame(self, raw):
        msg = json.loads(raw)
        if not isinstance(msg, dict):
            raise ValueError("a frame that is not a JSON object (batches are not supported)")
        method = msg.get("method")
        if method is None:
            return                              # a response; this server sends no requests
        if not isinstance(method, str):
            raise ValueError("a frame with a non-string method")
        has_id = "id" in msg
        if method.startswith("notifications/"):
            return
        if not has_id:
            return
        if method not in CLIENT_METHODS:
            self.send({"jsonrpc": "2.0", "id": msg["id"], "error": {
                "code": -32601, "message": "%s is not supported by %s" % (method, SERVER_NAME)}})
            self.log({"event": "method_refused", "method": method})
            return
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[1],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}})
        elif method == "ping":
            self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        elif method == "tools/list":
            self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}})
        else:
            self.on_call(msg["id"], params)

    def decide(self, tool, arguments):
        """(allowed, reason, call_no, over_budget). Runs on the reader thread."""
        if tool not in TOOL_NAMES:
            return False, "unknown tool %r; the tools are %s" % (tool, ", ".join(TOOL_NAMES)), \
                None, False
        with self.lock:
            if self.last < self.max_calls:
                self.last += 1
                return True, None, self.last, False
            if tool in SUBMIT_TOOLS and self.grace < GRACE_CALLS:
                self.last += 1
                self.grace += 1
                return True, None, self.last, True
            if tool in SUBMIT_TOOLS:
                return False, closed_message(), None, False
            return False, budget_message(min(self.last, self.max_calls), self.max_calls), \
                None, False

    def on_call(self, mid, params):
        tool = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        allowed, reason, call_no, over = self.decide(tool, arguments)
        record = {"event": "call", "id": mid, "tool": tool, "arguments": arguments,
                  "allowed": allowed, "call_no": call_no}
        if over:
            record["over_budget"] = True
        if not allowed:
            record.update(refused=True, reason=reason, result=reason, is_error=True,
                          budget_used=min(self.last, self.max_calls))
            self.log(record)
            self.reply(mid, reason, True)
            return
        self.slots.acquire()
        t = threading.Thread(target=self.execute, args=(mid, tool, arguments, record),
                             daemon=True)
        with self.lock:
            self.active.add(t)
        t.start()

    def execute(self, mid, tool, arguments, record):
        started = time.time()
        try:
            try:
                text, extra = self.tools.call(tool, arguments, record["call_no"])
                record.update(extra)
                is_error = False
            except Refusal as exc:
                text = str(exc) if str(exc).startswith("refused:") else "refused: %s" % exc
                is_error = True
                record.update(refused=True, reason=str(exc))
            except ToolError as exc:
                text, is_error = "error: %s" % exc, True
            except Exception as exc:             # a bug here must not kill the server
                text, is_error = "internal error: %s: %s" % (type(exc).__name__, exc), True
            record.update(result=text, is_error=is_error,
                          seconds=round(time.time() - started, 3))
            if record["call_no"] is not None and record["call_no"] >= self.max_calls \
                    and not record.get("over_budget"):
                text += ("\n[this was call %d of %d; the execution tools are now closed - "
                         "write your submission]" % (record["call_no"], self.max_calls))
            self.log(record)
            self.reply(mid, text, is_error)
        finally:
            self.slots.release()
            with self.lock:
                self.active.discard(threading.current_thread())

    def reply(self, mid, text, is_error):
        self.send({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": text}], "isError": bool(is_error)}})

    # -- main loop -----------------------------------------------------------------

    def pump(self):
        try:
            while not self.done.is_set():
                raw = self.stdin.readline()
                if not raw:
                    self.done.set()
                    return
                if raw.strip():
                    self.on_frame(raw.rstrip(b"\r\n"))
        except Exception as exc:                 # fail closed
            self.fail("client side: %s: %s" % (type(exc).__name__, exc))

    def run(self):
        self.log_fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        self.log({"event": "start", "container": self.container.name,
                  "max_calls": self.max_calls, "calls_so_far": self.last,
                  "grace_used": self.grace, "pid": os.getpid()})

        def on_term(signum, _frame):
            self.done.set()
        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGINT, on_term)
        threading.Thread(target=self.pump, daemon=True).start()
        while not self.done.wait(0.5):
            pass
        deadline = time.time() + 10
        while time.time() < deadline:
            with self.lock:
                if not self.active:
                    break
            time.sleep(0.1)
        self.log({"event": "stop", "exit": self.exit_code, "calls": self.last})
        return self.exit_code


def main(argv=None):
    ap = argparse.ArgumentParser(prog="jsre_mcp.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--container", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--max-calls", type=int, required=True)
    ap.add_argument("--docker", default="docker")
    ap.add_argument("--docker-host")
    opts = ap.parse_args(argv)
    if opts.max_calls < 0:
        sys.stderr.write("jsre_mcp: --max-calls must be >= 0\n")
        return 2
    container = Container(opts.container, opts.docker, opts.docker_host)
    return Server(container, opts.log, opts.max_calls).run()


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
