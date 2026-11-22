"""Run one submitted implementation over a file of inputs (grader side).

    python3 -I -X utf8 /opt/jsre/grade_runner.py SUBMISSION.py FUNC INPUTS.jsonl

INPUTS.jsonl holds one JSON array of positional arguments per line. The file
carries inputs only; expected outputs never enter the container. For each line
one JSON object is written to the original stdout, prefixed with a marker:

    @@R {"i": 0, "ok": true, "out": ...}
    @@R {"i": 1, "ok": false, "err": "ValueError: ..."}

The submission's own prints go to stderr. Each call is limited to PER_CALL
seconds of wall time (SIGALRM); the grader enforces the overall limit.
"""
import importlib.util
import json
import os
import signal
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sandbox_hook  # noqa: E402

sys.path.pop(0)

PER_CALL = float(os.environ.get("JSRE_PER_CALL", "2"))


class CallTimeout(Exception):
    pass


def _alarm(_sig, _frm):
    raise CallTimeout("call exceeded %.1f s" % PER_CALL)


def _plain(v):
    if isinstance(v, tuple):
        return [_plain(x) for x in v]
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    return v


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: grade_runner.py SUBMISSION.py FUNC INPUTS.jsonl")
    path, func, inputs = sys.argv[1:]
    with open(inputs, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    out = os.fdopen(os.dup(1), "w", encoding="utf-8")
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    sandbox_hook.install()

    def emit(rec):
        out.write("@@R " + json.dumps(rec, ensure_ascii=True) + "\n")
        out.flush()

    try:
        spec = importlib.util.spec_from_file_location("submission", path)
        mod = importlib.util.module_from_spec(spec)
        signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, max(PER_CALL * 5, 10))
        spec.loader.exec_module(mod)
        signal.setitimer(signal.ITIMER_REAL, 0)
        fn = getattr(mod, func)
    except BaseException as exc:  # noqa: BLE001 - report anything as a load failure
        signal.setitimer(signal.ITIMER_REAL, 0)
        emit({"i": -1, "ok": False, "err": "load: %s: %s" % (type(exc).__name__, exc)})
        return
    for i, args in enumerate(rows):
        try:
            signal.setitimer(signal.ITIMER_REAL, PER_CALL)
            res = fn(*args)
            signal.setitimer(signal.ITIMER_REAL, 0)
            res = _plain(res)
            json.dumps(res)
            emit({"i": i, "ok": True, "out": res})
        except BaseException as exc:  # noqa: BLE001
            signal.setitimer(signal.ITIMER_REAL, 0)
            tb = traceback.format_exception_only(type(exc), exc)[-1].strip()
            emit({"i": i, "ok": False, "err": tb[:300]})


if __name__ == "__main__":
    main()
