"""rekit whole-program bridge: "what does this program print for this input?"

Runs the input file of the open IDA database through `rebox run`, which
EMULATES the whole program (Speakeasy for a Windows PE, Qiling for a Linux ELF)
inside rebox's no-network sandbox-exec jail, and condenses rebox's report into
one compact dict: the program's output first (exact), how it stopped, then the
highlights of the behaviour summary, within `max_chars`.

Safety
  * only `rebox run` is ever invoked (emulation, sandboxed); nothing here can
    reach `rebox live` or execute the sample natively
  * the file is used only if its SHA-256 equals the hash IDA recorded when the
    database was created; the verified bytes are copied to a private temporary
    file and rebox runs on that copy, so a file swapped in afterwards is never
    used, and rebox's own hash of what it emulated is checked again
  * arguments go to the subprocess as an argv list, never through a shell
  * the IDA database is not touched

Entry points
  run(args, stdin, env, timeout, max_chars)        inside IDA (the rekit.run wrapper)
  run_file(path, expected_sha256, ...)             same core, driven by a path (tests)

Output streams are shown exactly: as a JSON string when the bytes are valid
UTF-8 made only of printable characters, newlines, CR and tabs; otherwise as
{"hex": ..., "escaped": ...}. A long stream keeps a head and a tail, never a
silently shortened middle, and says what was cut and how long the whole was.

Standard library only (runs inside IDA's Python).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
REBOX = os.environ.get("REKIT_REBOX") or os.path.join(TOOLS, "rebox", "rebox")
BUDGET = 3000
MAX_TIMEOUT = 60            # seconds of emulation; larger requests are capped
MAX_STDIN = 1 << 20         # same limit as rebox
MAX_SAMPLE = 256 << 20
MAX_ARGS = 256
MAX_ARG_CHARS = 64 << 10    # all arguments and environment values together
MIN_CHARS = 600

_EXIT_HINTS = {
    2: "rebox rejected the request; check args/stdin/env",
    3: "the sandbox was unavailable or failed its self-check; nothing was run",
    4: "the emulator crashed without a report; see the report directory",
    5: "rebox cannot emulate this file (not PE/ELF, .NET, unsupported architecture, "
       "or the ELF backend is not set up); analyse statically",
    6: "the emulator hung past its hard limit; try a smaller timeout or analyse statically",
}


class RunError(Exception):
    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.msg, self.hint = msg, hint


def _err(exc):
    out = {"error": exc.msg}
    if exc.hint:
        out["hint"] = exc.hint
    return out


# --------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------

def run(args=None, stdin=None, env=None, timeout=20, max_chars=BUDGET):
    """Emulate the database's input file with these inputs; see the module docstring."""
    try:
        candidates, sha = _ida_input()
        return run_file(candidates, sha, args=args, stdin=stdin, env=env, timeout=timeout,
                        max_chars=max_chars)
    except RunError as exc:
        return _err(exc)
    except Exception as exc:  # noqa: BLE001 - the contract is "no traceback"
        return {"error": "%s: %s" % (type(exc).__name__, exc),
                "hint": "unexpected state or a rekit bug; use rekit.emu on single functions instead"}


def _ida_input():
    """(candidate paths, sha256 hex) of the database's input file, from IDA."""
    import ida_nalt
    import idc

    raw = ida_nalt.retrieve_input_file_sha256()
    sha = raw.hex() if isinstance(raw, (bytes, bytearray)) else ""
    path = ida_nalt.get_input_file_path() or ""
    candidates = [path] if path else []
    # a database moved together with its input file: same name next to the .i64
    idb = idc.get_idb_path() or ""
    name = ida_nalt.get_root_filename() or os.path.basename(path)
    if idb and name:
        alt = os.path.join(os.path.dirname(idb), name)
        if alt not in candidates:
            candidates.append(alt)
    return candidates, sha


def run_file(path, expected_sha256, args=None, stdin=None, env=None, timeout=20,
             max_chars=BUDGET, rebox=None):
    """Core of run(): `path` is a path or a list of candidate paths; the first
    whose SHA-256 equals `expected_sha256` is emulated."""
    try:
        return _run_file(path, expected_sha256, args, stdin, env, timeout, max_chars, rebox or REBOX)
    except RunError as exc:
        return _err(exc)


def _run_file(path, expected, args, stdin, env, timeout, max_chars, rebox):
    argv = _check_args(args)
    data_in = _check_stdin(stdin)
    envl = _check_env(env)
    if sum(len(a) for a in argv) + sum(len(e) for e in envl) > MAX_ARG_CHARS:
        raise RunError("arguments and environment exceed %d characters" % MAX_ARG_CHARS)
    timeout, capped = _check_timeout(timeout)
    try:
        max_chars = max(MIN_CHARS, int(max_chars))
    except (TypeError, ValueError):
        raise RunError("max_chars must be an int")
    name, blob = _verified_input(path, expected)
    if not os.path.exists(rebox):
        raise RunError("rebox is not installed at %s" % rebox,
                       "whole-program emulation is unavailable; use rekit.emu on single functions")

    tmp = tempfile.mkdtemp(prefix="rekit-run-")
    try:
        sample = os.path.join(tmp, name)
        _write_private(sample, blob)
        cmd = [rebox, "run", sample, "--timeout", str(timeout), "--max-chars", "100000"]
        cmd += ["--arg=" + a for a in argv]
        cmd += ["--env=" + e for e in envl]
        if data_in is not None:
            stdin_path = os.path.join(tmp, "stdin.bin")
            _write_private(stdin_path, data_in)
            cmd += ["--stdin-file", stdin_path]
        child_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("PYTHON") and k != "__PYVENV_LAUNCHER__"}
        try:
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=timeout + max(60, timeout) + 60, cwd=tmp,
                                  env=child_env, shell=False)
        except subprocess.TimeoutExpired:
            raise RunError("rebox did not finish in time", _EXIT_HINTS[6])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    summary = _parse_rebox(proc)
    out_dir = summary.get("out_dir") or ""
    if not summary.get("ok"):
        code = summary.get("exit", proc.returncode)
        res = {"error": "rebox: %s" % str(summary.get("error") or "failed")[:600],
               "hint": _EXIT_HINTS.get(code, "see the report directory")}
        if out_dir:
            res["report"] = out_dir
        return res
    got = ((summary.get("sample") or {}).get("sha256") or "").lower()
    if got != expected.lower():
        raise RunError("rebox emulated a file with SHA-256 %s, not the database's %s"
                       % (got[:16] or "?", expected[:16]), "nothing was reported; retry")
    report = {}
    try:
        with open(os.path.join(out_dir, "report.json"), encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError):
        pass
    return _reply(summary, report, out_dir, data_in, timeout, capped, max_chars)


# --------------------------------------------------------------------------
# input checks
# --------------------------------------------------------------------------

def _check_args(args):
    if args is None:
        return []
    if isinstance(args, (str, bytes)):
        raise RunError("args must be a list of strings",
                       'e.g. args=["hello"]; each element is one argv entry, no shell splitting')
    if not isinstance(args, (list, tuple)):
        raise RunError("args must be a list of strings, got %s" % type(args).__name__)
    if len(args) > MAX_ARGS:
        raise RunError("at most %d arguments" % MAX_ARGS)
    for a in args:
        if not isinstance(a, str):
            raise RunError("every argument must be a string, got %r" % (a,),
                           'write numbers as strings: args=["42"]')
        if "\0" in a:
            raise RunError("an argument cannot contain a NUL character")
    return list(args)


def _check_stdin(stdin):
    if stdin is None:
        return None
    if isinstance(stdin, str):
        data = stdin.encode("utf-8")
    elif isinstance(stdin, (bytes, bytearray)):
        data = bytes(stdin)
    elif isinstance(stdin, dict) and len(stdin) == 1 and ("bytes" in stdin or "hex" in stdin):
        text = stdin.get("bytes", stdin.get("hex"))
        if not isinstance(text, str):
            raise RunError("stdin bytes must be a hex string")
        try:
            data = bytes.fromhex(re.sub(r"\s+", "", text))
        except ValueError:
            raise RunError("stdin bytes is not valid hex", 'e.g. stdin={"bytes": "68 69 0a"}')
    else:
        raise RunError("stdin must be a string, bytes, or {\"bytes\": \"<hex>\"}",
                       'text: stdin="hello\\n"  raw bytes: stdin={"bytes": "de ad 00 0a"}')
    if len(data) > MAX_STDIN:
        raise RunError("stdin is %d bytes, over the %d byte limit" % (len(data), MAX_STDIN))
    return data


def _check_env(env):
    if env is None:
        return []
    if not isinstance(env, dict):
        raise RunError("env must be a dict of strings", 'e.g. env={"LANG": "C"}')
    out = []
    for k, v in env.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise RunError("env keys and values must be strings, got %r=%r" % (k, v))
        if not k or "=" in k or "\0" in k or "\0" in v:
            raise RunError("bad environment variable name or value: %r" % k)
        out.append("%s=%s" % (k, v))
    return out


def _check_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise RunError("timeout must be a positive number of seconds")
    t = max(1, int(timeout))
    return (MAX_TIMEOUT, True) if t > MAX_TIMEOUT else (t, False)


def _verified_input(path, expected):
    """-> (basename, bytes) of the first candidate whose SHA-256 equals expected."""
    if not expected or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        raise RunError("the database has no recorded SHA-256 of its input file",
                       "cannot prove which file the database was built from; refusing to run")
    candidates = [path] if isinstance(path, str) else list(path or [])
    seen = []
    for cand in candidates:
        if not cand or not os.path.isfile(cand):
            seen.append("%s (missing)" % cand)
            continue
        size = os.path.getsize(cand)
        if size > MAX_SAMPLE:
            seen.append("%s (%d MB, too large)" % (cand, size >> 20))
            continue
        with open(cand, "rb") as fh:
            blob = fh.read(MAX_SAMPLE + 1)
        digest = hashlib.sha256(blob).hexdigest()
        if digest == expected.lower():
            return os.path.basename(cand) or "sample", blob
        seen.append("%s (sha256 %s..., expected %s...)" % (cand, digest[:12], expected.lower()[:12]))
    raise RunError("the database's input file is not available: " + "; ".join(seen or ["no path"]),
                   "put the original file back at that path; a different file is never emulated")


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _parse_rebox(proc):
    text = proc.stdout.decode("utf-8", "replace") if isinstance(proc.stdout, bytes) else proc.stdout
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    try:
        res = json.loads(lines[-1])
        if isinstance(res, dict):
            return res
    except (IndexError, ValueError):
        pass
    err = proc.stderr.decode("utf-8", "replace") if isinstance(proc.stderr, bytes) else proc.stderr
    tail = (err or text or "no output").strip()[-400:]
    raise RunError("rebox failed (exit %d): %s" % (proc.returncode, tail), _EXIT_HINTS[4])


# --------------------------------------------------------------------------
# the reply
# --------------------------------------------------------------------------

def _size(obj):
    return len(json.dumps(obj, ensure_ascii=False))


def _clean_text(data):
    """The bytes as str if they are printable UTF-8 text (plus \\n \\r \\t), else None."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all(c.isprintable() or c in "\n\r\t" for c in text):
        return text
    return None


def _escape(data):
    """Exact, reversible: printable ASCII as is, \\\\ \\n \\r \\t, \\xNN otherwise."""
    out = []
    for b in data:
        if b == 0x5C:
            out.append("\\\\")
        elif b == 10:
            out.append("\\n")
        elif b == 13:
            out.append("\\r")
        elif b == 9:
            out.append("\\t")
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append("\\x%02x" % b)
    return "".join(out)


def _fit_str(text, limit, from_end=False):
    """Longest prefix (or suffix) of text whose JSON form is at most limit chars."""
    if limit <= 2:
        return ""
    n = min(len(text), limit)
    while n > 0:
        part = text[-n:] if from_end else text[:n]
        if _size(part) <= limit:
            return part
        n = int(n * 0.9) if n > 20 else n - 1
    return ""


def _show(data, limit, file_name, written):
    """-> JSON value for one output stream, at most about `limit` chars of JSON."""
    kept_note = ""
    if written is not None and written > len(data):
        kept_note = "; the program wrote %d bytes, rebox kept the first %d" % (written, len(data))
    where = "; full: %s in the report directory" % file_name
    text = _clean_text(data)
    if text is not None:
        if _size(text) <= limit and not kept_note:
            return text
        if _size(text) + len(kept_note) + len(where) + 20 <= limit:
            return {"text": text, "cut": kept_note[2:] + where}
        room = max(40, limit - len(kept_note) - len(where) - 110)
        head = _fit_str(text, room * 2 // 3)
        tail = _fit_str(text[len(head):], room - _size(head), from_end=True)
        return {"head": head, "tail": tail,
                "cut": "shown chars 0-%d and %d-%d of %d chars (%d bytes)%s%s"
                       % (len(head), len(text) - len(tail), len(text), len(text), len(data),
                          where, kept_note)}
    full = {"hex": data.hex(), "escaped": _escape(data)}
    if _size(full) <= limit and not kept_note:
        return full
    room = max(60, limit - len(kept_note) - len(where) - 130)
    nb = len(data)

    def cost(n_head, n_tail):     # hex (2/byte) + escaped, head and tail
        h, t = data[:n_head], data[nb - n_tail:] if n_tail else b""
        return 2 * (n_head + n_tail) + _size(_escape(h)) + _size(_escape(t))

    head_n = max(1, min(nb, room // 4))
    while head_n > 1 and cost(head_n, 0) > room * 2 // 3:
        head_n = int(head_n * 0.9)
    tail_n = max(0, min(nb - head_n, room // 8))
    while tail_n > 0 and cost(head_n, tail_n) > room:
        tail_n = int(tail_n * 0.9)
    res = {"hex_head": data[:head_n].hex(), "escaped_head": _escape(data[:head_n])}
    if tail_n:
        res["hex_tail"] = data[nb - tail_n:].hex()
        res["escaped_tail"] = _escape(data[nb - tail_n:])
    if head_n + tail_n >= nb:
        res["cut"] = kept_note[2:] + where
    else:
        res["cut"] = ("shown bytes 0-%d%s of %d bytes%s%s"
                      % (head_n, " and %d-%d" % (nb - tail_n, nb) if tail_n else "", nb,
                         where, kept_note))
    return res


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _tl(t, n=8):
    """A summary {"total", "top"} list -> plain list when complete, else the cut form."""
    if not isinstance(t, dict):
        return t
    top = list(t.get("top") or [])
    if n is not None:
        top = top[:n]
    total = t.get("total", len(top))
    return top if total == len(top) else {"total": total, "top": top}


def _stop(summary, report):
    em = summary.get("emulation") or {}
    runs = (em.get("runs") or {}).get("top") or []
    main = runs[0] if runs else {}
    if (summary.get("sample") or {}).get("format") == "elf":
        stop = {"reason": em.get("stop")}
        if main.get("exit_code") is not None:
            stop["exit_code"] = main["exit_code"]
        if em.get("stop") != "exited":
            for k in ("pc", "detail"):
                if main.get(k):
                    stop[k] = main[k]
            if em.get("stop_detail") and em.get("stop_detail") != main.get("detail"):
                stop["why"] = em["stop_detail"]
        total = (em.get("runs") or {}).get("total", len(runs))
        if total > 1:
            stop["processes"] = ["%s %s: %s%s" % (r.get("type"), r.get("pid"), r.get("stop"),
                                                  " %s" % r["exit_code"] if r.get("exit_code") is not None
                                                  else "")
                                 for r in runs[:6]]
            if total > 6:
                stop["processes"].append("+%d more" % (total - 6))
        return stop
    # PE: one run per entry point
    stop = {"reason": main.get("stop")}
    for k in ("ret", "pc", "detail"):
        if main.get(k) is not None:
            stop[k] = main[k]
    if len(runs) > 1:
        stop["runs"] = ["%s %s: %s" % (r.get("type"), r.get("start"), r.get("stop")) for r in runs[:6]]
    return stop


def _stdin_line(report, given):
    st = report.get("stdin") or {}
    reads = st.get("reads", 0)
    consumed = st.get("consumed", 0)
    if given is None:
        if reads:
            return ("the program read stdin and got end-of-file (no stdin was given); "
                    "pass stdin=\"...\" to answer it")
        return None
    return "given %d bytes, the program read %d%s" % (
        len(given), consumed, "" if reads else " (it never read stdin)")


def _behaviour(summary):
    """Highlights, most useful first, as (key, value) pairs."""
    ind = summary.get("indicators") or {}
    api = summary.get("api") or {}
    em = summary.get("emulation") or {}
    items = []
    for key in ("files_written", "files_deleted", "conns", "hosts", "urls", "cmdlines",
                "listening", "registry_written", "mutexes", "injections"):
        if isinstance(ind.get(key), dict) and ind[key].get("total"):
            items.append((key, _tl(ind[key])))
    hist = (api.get("histogram") or {}).get("top") or []
    if hist:
        kind = "syscalls" if api.get("kind") == "syscalls" else "api_calls"
        items.append((kind, "%s total; top: %s" % (
            api.get("calls"), ", ".join("%s %s" % (n, c) for n, c, *_ in hist[:10]))))
    uns = api.get("unsupported")
    if isinstance(uns, dict) and uns.get("total"):
        items.append(("unsupported", _tl(uns)))
    errs = em.get("errors")
    if isinstance(errs, dict) and errs.get("total"):
        items.append(("emulator_errors", _tl(errs)))
    pay = summary.get("payloads") or {}
    if pay.get("total"):
        items.append(("payloads", ["%s %s %dB" % (p.get("kind"), p.get("emu_path") or p.get("base") or "",
                                                  p.get("size") or 0) for p in pay.get("top") or []]))
    for key in ("files_read", "files_probed", "anti_analysis", "persistence_paths", "process_names"):
        if isinstance(ind.get(key), dict) and ind[key].get("total"):
            items.append((key, _tl(ind[key])))
    strs = summary.get("strings") or {}
    if isinstance(strs.get("api_args"), dict) and strs["api_args"].get("total"):
        items.append(("api_args", _tl(strs["api_args"])))   # PE: printf/WriteFile text lands here
    return items


def _shrink(value, room):
    """Cut a list value (plain or {"total","top"}) to a prefix that fits room, or None."""
    top = value["top"] if isinstance(value, dict) else value
    if not isinstance(top, list):
        return value if _size(value) <= room else None
    total = value["total"] if isinstance(value, dict) else len(top)
    for n in range(len(top), 0, -1):
        cand = top[:n] if n == total else {"total": total, "top": top[:n]}
        if _size(cand) <= room:
            return cand
    return None


def _reply(summary, report, out_dir, given, timeout, capped, max_chars):
    """Compose the reply; shrink the output share until the whole fits max_chars."""
    scale = 1.0
    for _ in range(8):
        res = _compose(summary, report, out_dir, given, capped, max_chars, scale)
        if _size(res) <= max_chars:
            break
        scale *= 0.75
    return res


def _stream_cost(data):
    text = _clean_text(data)
    return _size(text) if text is not None else 2 * len(data) + _size(_escape(data))


def _compose(summary, report, out_dir, given, capped, max_chars, scale):
    elf = (summary.get("sample") or {}).get("format") == "elf"
    res = {}
    notes = []
    head = {}
    head["stop"] = _stop(summary, report)
    line = _stdin_line(report, given)
    if line:
        head["stdin"] = line
    if capped:
        notes.append("timeout capped at %ds" % MAX_TIMEOUT)
    tail = {"report": out_dir}

    if elf:
        streams = []
        for name in ("stdout", "stderr"):
            data = _read(os.path.join(out_dir, "%s.txt" % name))
            if data is None:
                data = ((report.get(name) or {}).get("head") or "").encode("utf-8")
                notes.append("%s.txt missing; %s shown from the report head (lossy)" % (name, name))
            streams.append((name, data, (report.get(name) or {}).get("bytes")))
        fixed = _size(head) + _size(tail) + 120 + (_size(notes) if notes else 0)
        if not all(_clean_text(d) is not None for _, d, _ in streams):
            fixed += 110          # the note explaining the escaped form
        reserve = min(700, max_chars // 4)
        room = max(120, int((max_chars - fixed - reserve) * scale))
        out_len, err_len = (_stream_cost(d) for _, d, _ in streams)
        if not streams[1][1]:
            alloc = {"stdout": room}
        elif out_len + err_len + 160 <= room:
            alloc = {"stdout": out_len + 80, "stderr": err_len + 80}
        else:
            err_room = min(err_len + 80, max(room // 4, room - out_len - 80))
            alloc = {"stdout": room - err_room, "stderr": err_room}
        for name, data, written in streams:
            if name == "stderr" and not data:
                continue
            res[name] = _show(data, alloc[name], "%s.txt" % name, written)
            if isinstance(res[name], dict) and ("escaped" in res[name] or "escaped_head" in res[name]):
                if not any(n.startswith("escaped") for n in notes):
                    notes.append("escaped: printable ASCII as is, \\\\ \\n \\r \\t, \\xNN for other "
                                 "bytes; hex is the same bytes")
        order = (report.get("output_order") or {})
        runs = order.get("runs") or []
        if streams[1][1] and runs:
            shown = runs[:12]
            res["order"] = ", ".join("%s %d" % (s, n) for s, n in shown) + (
                ", ... (%d write runs)" % len(runs) if len(runs) > 12 else "") + (
                " (incomplete)" if not order.get("complete", True) else "")
    else:
        res["stdout"] = None
        notes.append("PE: Speakeasy does not capture console output as a stream; text the program "
                     "printed through printf/WriteFile appears in api_args, the full API log in the report")

    res.update(head)
    used = _size(res) + _size(tail) + (_size(notes) + 12 if notes else 0)
    behaviour, omitted = {}, []
    for key, value in _behaviour(summary):
        room = max_chars - used - _size(behaviour) - len(key) - 8 - 60
        fit = _shrink(value, room) if room > 0 else None
        if fit is None:
            omitted.append(key)
            continue
        behaviour[key] = fit
    if behaviour:
        res["behaviour"] = behaviour
    if omitted:
        res["omitted"] = omitted
    if notes:
        res["notes"] = notes
    res.update(tail)
    return res
