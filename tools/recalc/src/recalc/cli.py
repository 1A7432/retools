"""Command line: one JSON request on stdin, one JSON reply on stdout.

    recalc                     evaluate {"code": ..., "timeout": 10, "max_chars": 4000}
    recalc functions [--json]  list the function table
"""

from __future__ import annotations

import json
import os
import resource
import signal
import sys
import time
import traceback

from . import limits as L
from . import render
from .errors import CalcError, LimitError, TimeLimit

MAX_REQUEST = 256 * 1024
KEYS = {"code", "timeout", "max_chars", "id"}


def _emit(obj):
    # backslashreplace turns a lone surrogate (chr(0xd800)) into the JSON escape \ud800
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n"
    sys.stdout.buffer.write(text.encode("utf-8", "backslashreplace"))
    sys.stdout.flush()


def _prewarm():
    """Import and initialise everything evaluation may need, before the file
    descriptor limit makes further imports impossible."""
    from . import table, interp  # noqa: F401
    for enc in table._ENCODINGS:
        "a".encode(enc)
        b"a".decode(enc, "replace")
    for name in list(table.FUNCTIONS):
        table.signature(name)
    import difflib  # noqa: F401
    difflib.get_close_matches("x", ["y"])
    import tokenize, io  # noqa: E401,F401
    list(tokenize.generate_tokens(io.StringIO("x = 1\n").readline))


def _set(limit, value):
    try:
        soft, hard = resource.getrlimit(limit)
        if hard != resource.RLIM_INFINITY and value > hard:
            value = hard
        resource.setrlimit(limit, (value, hard if hard != resource.RLIM_INFINITY else value))
        return True
    except (ValueError, OSError):
        return False


def lockdown(timeout):
    """Process-level limits. macOS ignores some (address space); each is
    best effort and the in-evaluator limits do not depend on them."""
    applied = {}
    applied["cpu"] = _set(resource.RLIMIT_CPU, int(timeout) + 2)
    applied["as"] = _set(resource.RLIMIT_AS, 2 << 30)
    applied["data"] = _set(resource.RLIMIT_DATA, 2 << 30)
    applied["fsize"] = _set(resource.RLIMIT_FSIZE, 4 << 20)
    applied["core"] = _set(resource.RLIMIT_CORE, 0)
    applied["nproc"] = _set(resource.RLIMIT_NPROC, 0)
    applied["nofile"] = _set(resource.RLIMIT_NOFILE, 3)
    return applied


def _alarm(signum, frame):
    raise TimeLimit()


def _source_line(code, line):
    if not line:
        return None
    lines = code.splitlines()
    if 1 <= line <= len(lines):
        s = lines[line - 1].strip()
        return s if len(s) <= 200 else s[:200] + "..."
    return None


def _cap(reply, max_chars):
    """Last resort: shorten the text fields until the reply fits max_chars."""
    for key in ("note", "hint", "at", "error", "truncated"):
        over = render.size(reply) - max_chars
        if over <= 0:
            break
        if key in reply and isinstance(reply[key], str):
            s = reply[key]
            keep = max(len(s) - over - 20, 0)
            reply[key] = s[:keep] + ("...[cut]" if keep < len(s) else "")
            if key == "note" and keep == 0:
                del reply["note"]
    return reply


def evaluate(req, budget_factory=None):
    """Evaluate one request dict; always returns a reply dict."""
    from . import table
    from .interp import Interp, parse

    if not isinstance(req, dict):
        return {"error": "the request must be a JSON object", "hint": '{"code": "1 + 1"}'}
    extra = set(req) - KEYS
    if extra:
        return {"error": "unknown request keys: %s" % ", ".join(sorted(extra)),
                "hint": "valid keys: " + ", ".join(sorted(KEYS))}
    if "id" in req and not (isinstance(req["id"], (str, int)) and len(str(req["id"])) <= 100):
        return {"error": "id must be a short string or integer", "hint": ""}
    code = req.get("code")
    if not isinstance(code, str):
        return {"error": "code must be a string", "hint": '{"code": "pow(7, 5, 13)"}'}
    try:
        timeout = int(req.get("timeout", L.DEFAULT_TIMEOUT))
        max_chars = int(req.get("max_chars", L.DEFAULT_CHARS))
    except (TypeError, ValueError):
        return {"error": "timeout and max_chars must be integers", "hint": ""}
    timeout = min(max(timeout, 1), L.MAX_TIMEOUT)
    max_chars = min(max(max_chars, L.MIN_CHARS), L.MAX_CHARS)
    budget = (budget_factory or L.Budget)(timeout)
    it = Interp(budget, table.FUNCTIONS, table.METHODS, table.STATICS, render.text)
    t0 = time.monotonic()
    err = None
    use_alarm = budget_factory is None and hasattr(signal, "setitimer")
    if use_alarm:
        old = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, timeout + 0.5)
    try:
        try:
            tree = parse(code)
            it.run(tree)
        finally:
            L._CURRENT[0] = None
            if use_alarm:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old)
    except CalcError as exc:
        err = exc
    except TimeLimit:
        err = LimitError("time", "ran longer than %ss" % timeout,
                         "make the computation smaller, or raise timeout (at most %ds)" % L.MAX_TIMEOUT)
    except RecursionError:
        err = LimitError("recursion_depth", "the computation nested too deeply",
                         "values nested very deeply (lists inside lists) cannot be compared or hashed")
    except MemoryError:
        err = LimitError("memory", "out of memory")
    except KeyError:
        err = CalcError("KeyError: key not found", "check the operand types and values")
    except (TypeError, ValueError, IndexError, OverflowError, ZeroDivisionError) as exc:
        err = CalcError("%s: %s" % (type(exc).__name__, str(exc)[:200]), "check the operand types and values")
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON reply
        traceback.print_exc(file=sys.stderr)
        err = CalcError("internal error: %s: %s" % (type(exc).__name__, str(exc)[:200]),
                        "a recalc bug; please report it")
    ms = int((time.monotonic() - t0) * 1000)
    base = {}
    if "id" in req:
        base["id"] = req["id"]
    if err is not None:
        rep = err.reply()
        if err.line is None and it.lineno is not None:
            rep["line"] = it.lineno
        at = _source_line(code, rep.get("line"))
        if at:
            rep["at"] = at
        base.update(rep)
        if not it.globals and not it.printed:
            return _cap(base, max_chars)
        base["note"] = "vars and printed lines are as they were when the error happened"
        try:
            return _cap(render.fit(base, None, False, it.globals, it.printed, max_chars), max_chars)
        except (RecursionError, ValueError):
            base.pop("note", None)
            return _cap(base, max_chars)
    base["steps"] = budget.steps
    base["ms"] = ms
    if it.print_dropped:
        base["print_dropped"] = it.print_dropped
    try:
        return _cap(render.fit(base, it.result, it.has_result, it.globals, it.printed, max_chars), max_chars)
    except (RecursionError, ValueError) as exc:
        traceback.print_exc(file=sys.stderr)
        return dict(base, error="the result cannot be shown (%s)" % type(exc).__name__,
                    hint="print parts of it instead")


def cmd_functions(as_json):
    from . import table
    groups = {}
    for g, names in table.GROUPS.items():
        groups[g] = [{"name": n, "sig": table.signature(n) if n != "print" else "print(*values)",
                      "doc": table.DOCS.get(n, "")} for n in names]
    methods = sorted("%s.%s" % (t.__name__, n) for (t, n) in table.METHODS)
    statics = sorted("%s.%s" % (s, n) for s, tb in table.STATICS.items() for n in tb)
    if as_json:
        _emit({"functions": groups, "methods": methods, "statics": statics})
        return 0
    for g, items in groups.items():
        sys.stdout.write("[%s]\n" % g)
        for it in items:
            sys.stdout.write("  %-60s %s\n" % (it["sig"], it["doc"]))
    sys.stdout.write("[methods]\n  %s\n" % ", ".join(methods + statics))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "functions":
        return cmd_functions("--json" in argv)
    if argv:
        sys.stderr.write(__doc__)
        return 2
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    except Exception as exc:  # noqa: BLE001
        _emit({"error": "cannot read the request: %s" % exc, "hint": ""})
        return 0
    # No stdin after the request.
    try:
        fd = os.open(os.devnull, os.O_RDONLY)
        os.dup2(fd, 0)
        os.close(fd)
    except OSError:
        pass
    if len(raw) > MAX_REQUEST:
        _emit({"error": "limit 'request_size' exceeded: the request is over %d bytes" % MAX_REQUEST,
               "hint": "code is limited to %d characters" % L.MAX_CODE})
        return 0
    try:
        req = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        _emit({"error": "the request is not valid JSON: %s" % exc, "hint": '{"code": "1 + 1"}'})
        return 0
    timeout = L.DEFAULT_TIMEOUT
    if isinstance(req, dict):
        try:
            timeout = min(max(int(req.get("timeout", timeout)), 1), L.MAX_TIMEOUT)
        except (TypeError, ValueError):
            pass
    _prewarm()
    lockdown(timeout)
    sys.setrecursionlimit(20000)
    try:
        reply = evaluate(req)
    except BaseException as exc:  # noqa: BLE001 - always answer with one JSON object
        traceback.print_exc(file=sys.stderr)
        reply = {"error": "internal error: %s" % type(exc).__name__, "hint": "a recalc bug; please report it"}
    _emit(reply)
    return 0
