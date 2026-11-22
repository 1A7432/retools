"""rekit calculator bridge: hand a few lines of arithmetic to the out-of-process
`recalc` tool and return its JSON reply.

recalc evaluates a small Python subset with its own interpreter (no eval/exec,
no imports, no attribute access beyond a fixed method table) under step, size,
time and memory limits, in a separate process started with an empty
environment. Nothing here touches the IDA database. Standard library only.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess

TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
RECALC = os.environ.get("REKIT_RECALC") or os.path.join(TOOLS, "recalc", "recalc")
MAX_CODE = 20000
MAX_TIMEOUT = 60
# How long past the requested timeout the process may run before it is killed
# from here (the tool stops itself at the timeout; this covers start-up and a
# stuck process).
GRACE = 5

_SIGNALS = {
    getattr(signal, "SIGXCPU", 24): ("cpu_time", "the CPU time limit killed the calculator"),
    getattr(signal, "SIGKILL", 9): ("killed", "the calculator was killed (probably out of memory)"),
    getattr(signal, "SIGSEGV", 11): ("crash", "the calculator crashed"),
    getattr(signal, "SIGXFSZ", 25): ("output_size", "the calculator wrote too much output"),
}


def _err(msg, hint=""):
    return {"error": msg, "hint": hint}


def run(code, timeout=10, max_chars=4000):
    """Evaluate `code` in recalc; return its reply dict.

    The reply has "result" (value of the last line, if it is an expression),
    "vars" (assigned names), "printed", "steps", "ms" and "truncated" when the
    reply was shortened to max_chars; or {"error", "hint", "line", "at"}.
    Failures of the tool itself come back in the same {"error", "hint"} shape;
    this function does not raise.
    """
    if not isinstance(code, str):
        return _err("code must be a string", 'calc("pow(7, 5, 13)")')
    if len(code) > MAX_CODE:
        return _err("limit 'code_length' exceeded: %d characters of code (limit %d)" % (len(code), MAX_CODE),
                    "split the work into several calls")
    try:
        timeout = min(max(int(timeout), 1), MAX_TIMEOUT)
        max_chars = int(max_chars)
    except (TypeError, ValueError):
        return _err("timeout and max_chars must be integers")
    if not os.path.exists(RECALC):
        return _err("the recalc calculator is not installed at %s" % RECALC,
                    "calculation is unavailable; compute by hand and say so")
    request = json.dumps({"code": code, "timeout": timeout, "max_chars": max_chars})
    try:
        proc = subprocess.run([RECALC], input=request, capture_output=True, text=True,
                              timeout=timeout + GRACE, env={}, start_new_session=True)
    except subprocess.TimeoutExpired:
        return _err("limit 'time' exceeded: the calculator did not finish within %ds and was killed"
                    % (timeout + GRACE), "make the computation smaller")
    except OSError as exc:
        return _err("cannot start recalc: %s" % exc, "calculation is unavailable")
    text = (proc.stdout or "").strip()
    if proc.returncode < 0:
        name, what = _SIGNALS.get(-proc.returncode, ("signal", "the calculator was stopped by signal %d"
                                                      % -proc.returncode))
        return _err("limit '%s' exceeded: %s" % (name, what) if name != "crash" else what,
                    "make the computation smaller")
    try:
        reply = json.loads(text.splitlines()[-1]) if text else None
    except ValueError:
        reply = None
    if not isinstance(reply, dict):
        tail = ((proc.stderr or "") or text or "no output").strip()[-400:]
        return _err("recalc failed (exit %d): %s" % (proc.returncode, tail),
                    "a calculator problem; compute by hand and say so")
    if "error" in reply and "hint" not in reply:
        reply["hint"] = ""
    return reply
