"""File operations for jsre_mcp.py, run *inside* the worker's container.

jsre_mcp.py passes this file's source as `python3 -I -X utf8 -c SOURCE` through
`docker exec` and one JSON request on stdin; the reply is one JSON object on
stdout: {"ok": true, "text": ...} / {"ok": true, "data": ...} or
{"ok": false, "error": ..., "refused": bool}.

Paths were already checked by the server (absolute, under /task, writes under
/task/work); here they are checked again after resolving symlinks inside the
container, so a symlink the worker made cannot point a tool outside /task.
Standard library only; it runs with the image's python3.
"""
import ast
import hashlib
import json
import os
import re
import sys

ROOT = "/task"
WORK = "/task/work"
PUBLIC = "/task/public"
SUBMISSION = "/task/work/submission"
CHECK_DIR = "/task/work/.jsw/check"
READ_MAX = 40000            # bytes of file content per fs_read reply
LIST_MAX = 1000             # entries per fs_list reply
HASH_MAX = 64 << 20         # files larger than this are listed without a hash
GREP_LINE = 400             # lines up to this length are shown whole
GREP_CONTEXT = 200          # bytes either side of a hit in a longer line
GREP_COUNT_LIMIT = 100000   # stop counting hits after this many
EXTRA_MODULES = {"Crypto", "Cryptodome", "gmssl"}
# stdlib modules the grader's sandbox blocks at run time (or that need the network)
BLOCKED_MODULES = {"subprocess", "socket", "ssl", "ctypes", "multiprocessing", "urllib",
                   "http", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc",
                   "socketserver", "pty", "webbrowser", "asyncio", "selectors"}


class Refused(Exception):
    pass


class Failed(Exception):
    pass


def resolve(path, write=False):
    if not isinstance(path, str) or not path.startswith("/"):
        raise Refused("path must be absolute and under /task")
    real = os.path.realpath(path)
    root = WORK if write else ROOT
    if real != root and not real.startswith(root + "/"):
        if real != path:
            raise Refused("%s resolves to %s, which is outside %s" % (path, real, root))
        raise Refused("%s is outside %s" % (path, root))
    return real


def utf8_window(data, at_start, at_end):
    """Indices that cut `data` at UTF-8 character boundaries."""
    a = 0
    if not at_start:
        while a < len(data) and a < 3 and (data[a] & 0xC0) == 0x80:
            a += 1
    b = len(data)
    if not at_end:
        i = b - 1
        while i >= a and b - i <= 4 and (data[i] & 0xC0) == 0x80:
            i -= 1
        if i >= a:
            lead = data[i]
            need = 1 if lead < 0x80 else 2 if lead >> 5 == 6 else 3 if lead >> 4 == 14 \
                else 4 if lead >> 3 == 30 else 1
            if b - i < need:
                b = i
    return a, b


def text(data):
    return data.decode("utf-8", "replace")


# --------------------------------------------------------------------------
# fs_list
# --------------------------------------------------------------------------

def sha12(path, size):
    if size > HASH_MAX:
        return "-" * 12
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


def op_list(req):
    path = resolve(req["path"])
    depth = req["depth"]
    lines = []
    state = {"n": 0, "cut": False}

    def entry(p):
        if os.path.islink(p):
            lines.append("%10s  %12s  %s -> %s" % ("link", "", p, os.readlink(p)))
        elif os.path.isdir(p):
            lines.append("%10s  %12s  %s/" % ("dir", "", p))
        elif os.path.isfile(p):
            size = os.path.getsize(p)
            lines.append("%10d  %s  %s" % (size, sha12(p, size), p))
        else:
            lines.append("%10s  %12s  %s" % ("other", "", p))

    def walk(d, level):
        try:
            names = sorted(os.listdir(d))
        except OSError as exc:
            lines.append("%10s  %12s  %s/ (%s)" % ("dir", "", d, exc.strerror))
            return
        for name in names:
            if state["n"] >= LIST_MAX:
                state["cut"] = True
                return
            p = os.path.join(d, name)
            state["n"] += 1
            entry(p)
            if os.path.isdir(p) and not os.path.islink(p) and level < depth:
                walk(p, level + 1)

    if os.path.isdir(path):
        walk(path, 1)
        head = "%s (depth %d): %d entries" % (path, depth, state["n"])
    elif os.path.exists(path):
        entry(path)
        head = "%s:" % path
    else:
        raise Failed("%s does not exist" % req["path"])
    if state["cut"]:
        head += " (stopped at %d; list a subdirectory or use a smaller depth)" % LIST_MAX
    return head + "\n" + "      size  sha256[:12]   path\n" + "\n".join(lines)


# --------------------------------------------------------------------------
# fs_read
# --------------------------------------------------------------------------

def op_read(req):
    path = resolve(req["path"])
    if os.path.isdir(path):
        raise Failed("%s is a directory; use fs_list" % req["path"])
    if not os.path.isfile(path):
        raise Failed("%s does not exist" % req["path"])
    size = os.path.getsize(path)
    if req["unit"] == "byte":
        off = req["offset"] if req["offset"] is not None else 0
        lim = min(req["limit"] or READ_MAX, READ_MAX)
        if off > size:
            raise Failed("offset %d is past the end of the file (%d bytes)" % (off, size))
        with open(path, "rb") as fh:
            fh.seek(off)
            data = fh.read(lim)
        a, b = utf8_window(data, off == 0, off + len(data) >= size)
        start, end = off + a, off + b
        head = "%s: bytes %d-%d of %d" % (req["path"], start, end, size)
        head += " (continue with offset=%d)" % end if end < size else " (end of file)"
        return head + "\n" + text(data[a:b])
    first = req["offset"] if req["offset"] is not None else 1
    first = max(1, first)
    count = req["limit"] or 400
    out = []
    budget = READ_MAX
    lineno = 0
    pos = 0
    shown_last = 0
    note = ""
    stopped = False
    with open(path, "rb") as fh:
        for raw in fh:
            lineno += 1
            if stopped or lineno < first or lineno >= first + count:
                pos += len(raw)
                continue
            line = raw[:-1] if raw.endswith(b"\n") else raw
            if line.endswith(b"\r"):
                line = line[:-1]
            if len(line) > budget:
                if out:          # start this long line in the next call
                    note = ("line %d is %d bytes; read it with "
                            "offset=%d (or unit=\"byte\", offset=%d)"
                            % (lineno, len(line), lineno, pos))
                else:
                    a, b = utf8_window(line[:budget], True, False)
                    out.append("%6d\t%s" % (lineno, text(line[:b])))
                    shown_last = lineno
                    note = ("line %d is %d bytes; shown its first %d. Continue with "
                            "unit=\"byte\", offset=%d" % (lineno, len(line), b, pos + b))
                stopped = True
                pos += len(raw)
                continue
            out.append("%6d\t%s" % (lineno, text(line)))
            shown_last = lineno
            budget -= len(line) + 8
            pos += len(raw)
    total = lineno
    if size == 0:
        return "%s: empty file" % req["path"]
    if first > total:
        raise Failed("the file has %d lines; offset %d is past the end" % (total, first))
    head = "%s: lines %d-%d of %d (%d bytes)" % (req["path"], first, shown_last, total, size)
    if note:
        head += "\n[" + note + "]"
    elif shown_last < total:
        head += " (continue with offset=%d)" % (shown_last + 1)
    return head + "\n" + "\n".join(out)


# --------------------------------------------------------------------------
# fs_grep
# --------------------------------------------------------------------------

def grep_files(path):
    if os.path.isfile(path):
        return [path]
    files = []
    for d, dirs, names in os.walk(path):
        dirs[:] = sorted(x for x in dirs if not os.path.islink(os.path.join(d, x)))
        for name in sorted(names):
            p = os.path.join(d, name)
            if os.path.isfile(p) and not os.path.islink(p):
                files.append(p)
    return files


def op_grep(req):
    try:
        pat = re.compile(req["pattern"].encode("utf-8"))
    except (re.error, UnicodeEncodeError) as exc:
        raise Failed("bad pattern: %s" % exc)
    path = resolve(req["path"])
    if not os.path.exists(path):
        raise Failed("%s does not exist" % req["path"])
    limit = req["max"]
    hits = []
    total = 0
    binary = 0
    capped = False
    for fp in grep_files(path):
        with open(fp, "rb") as fh:
            data = fh.read()
        if b"\x00" in data[:8192]:
            binary += 1
            continue
        pos = 0
        lineno = 0
        for line in data.split(b"\n"):
            lineno += 1
            for m in pat.finditer(line):
                total += 1
                if len(hits) < limit:
                    s, e = m.span()
                    if len(line) <= GREP_LINE:
                        ctx = text(line)
                    else:
                        a, b = max(0, s - GREP_CONTEXT), min(len(line), e + GREP_CONTEXT)
                        if b - a > 2 * GREP_CONTEXT + 1000:      # a huge match
                            b = a + 2 * GREP_CONTEXT + 1000
                        piece = line[a:b]
                        x, y = utf8_window(piece, a == 0, b == len(line))
                        ctx = ("..." if a + x > 0 else "") + text(piece[x:y]) + \
                            ("..." if a + y < len(line) else "")
                    hits.append("%s:%d:%d: %s" % (fp, lineno, pos + s, ctx))
                if total >= GREP_COUNT_LIMIT:
                    capped = True
                    break
            if capped:
                break
            pos += len(line) + 1
        if capped:
            break
    if not total:
        head = "no matches"
    else:
        head = "%s%d matches" % ("at least " if capped else "", total)
        if total > len(hits):
            head += ", showing the first %d" % len(hits)
    head += " (file:line:byte-offset: text)"
    if binary:
        head += "; %d binary file(s) skipped" % binary
    return head + ("\n" + "\n".join(hits) if hits else "")


# --------------------------------------------------------------------------
# fs_write / fs_edit
# --------------------------------------------------------------------------

def write_file(path, data):
    if os.path.isdir(path):
        raise Failed("%s is a directory" % path)
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    real = os.path.realpath(parent)
    if real != WORK and not real.startswith(WORK + "/"):
        raise Refused("%s is outside %s" % (parent, WORK))
    with open(path, "wb") as fh:
        fh.write(data)


def op_write(req):
    path = resolve(req["path"], write=True)
    try:
        data = req["content"].encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Failed("content is not valid text: %s" % exc)
    write_file(path, data)
    return "wrote %d bytes to %s" % (len(data), req["path"])


def op_edit(req):
    path = resolve(req["path"], write=True)
    if not os.path.isfile(path):
        raise Failed("%s does not exist" % req["path"])
    old, new = req["old"], req["new"]
    if not old:
        raise Failed("old must not be empty")
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Failed("%s is not UTF-8 text: %s" % (req["path"], exc))
    n = body.count(old)
    if n == 0:
        raise Failed("old text not found in %s" % req["path"])
    if n > 1:
        raise Failed("old text occurs %d times in %s; include more context so it is "
                     "unique" % (n, req["path"]))
    body = body.replace(old, new, 1)
    try:
        data = body.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Failed("new is not valid text: %s" % exc)
    write_file(path, data)
    return "replaced 1 occurrence in %s (now %d bytes)" % (req["path"], len(data))


def op_save(req):
    """Server-side writes (saved outputs, code files): content is given as text."""
    path = resolve(req["path"], write=True)
    data = req["content"].encode("utf-8", "replace")
    write_file(path, data)
    return "saved %d bytes" % len(data)


# --------------------------------------------------------------------------
# submit_check, static part
# --------------------------------------------------------------------------

def defines(tree, name):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and node.name == name:
            return True
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return True
        if isinstance(node, (ast.AnnAssign, ast.AugAssign)) and \
                isinstance(node.target, ast.Name) and node.target.id == name:
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) == name:
                    return True
    return False


def import_problems(tree):
    errors, warnings = [], []
    allowed = set(sys.stdlib_module_names) | EXTRA_MODULES
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                errors.append("line %d: relative import is not allowed" % node.lineno)
                continue
            names = [node.module or ""]
        for full in names:
            top = full.split(".")[0]
            if top not in allowed:
                errors.append("line %d: import %s - only the standard library, Crypto "
                              "(pycryptodome) and gmssl are available" % (node.lineno, full))
            elif top in BLOCKED_MODULES:
                warnings.append("line %d: import %s - network, subprocess and native-code "
                                "modules are blocked when the submission is graded"
                                % (node.lineno, full))
    return errors, warnings


def op_check(req):
    errors, warnings = [], []
    with open(os.path.join(PUBLIC, "questions.json"), encoding="utf-8") as fh:
        questions = json.load(fh)
    qids = [q["id"] for q in questions]
    answers = None
    ans_path = os.path.join(SUBMISSION, "answers.json")
    if os.path.islink(ans_path):
        errors.append("answers.json is a symbolic link; write it as a regular file")
    elif not os.path.isfile(ans_path):
        errors.append("%s does not exist" % ans_path)
    else:
        try:
            with open(ans_path, encoding="utf-8") as fh:
                answers = json.load(fh)
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append("answers.json is not valid JSON: %s" % exc)
        else:
            if not isinstance(answers, dict):
                errors.append("answers.json must be one JSON object {question id: answer}")
                answers = None
    answers_ok = answers is not None
    answers = answers or {}
    for key in answers:
        if key not in qids:
            errors.append("answers.json has %r, which is not a question of this target "
                          "(its questions: %s)" % (key, ", ".join(qids)))
    missing, impls = [], []
    for q in questions:
        qid = q["id"]
        impl = q.get("impl")
        if not impl:
            if qid not in answers:
                missing.append(qid)
            elif answers[qid] is None or answers[qid] == "" or answers[qid] == [] \
                    or answers[qid] == {}:
                warnings.append("%s: the answer is empty" % qid)
            continue
        item = {"qid": qid, "function": impl.get("function"), "file": None,
                "inputs": None, "expected": [], "errors": [], "warnings": []}
        impls.append(item)
        val = answers.get(qid)
        fname = None
        if val is None:
            if os.path.lexists(os.path.join(SUBMISSION, qid + ".py")):
                fname = qid + ".py"
                item["warnings"].append("not listed in answers.json; the grader looks for "
                                        "%s by convention" % fname)
            else:
                missing.append(qid)
                continue
        elif not isinstance(val, str) or "/" in val or val.startswith(".") \
                or not val.endswith(".py"):
            item["errors"].append("the answer must be the implementation's file name, "
                                  "e.g. %r" % (qid + ".py"))
            continue
        else:
            fname = val
        fpath = os.path.join(SUBMISSION, fname)
        item["file"] = fname
        if os.path.islink(fpath):
            item["errors"].append("%s is a symbolic link; write it as a regular file" % fname)
            continue
        if not os.path.isfile(fpath):
            item["errors"].append("%s does not exist in %s" % (fname, SUBMISSION))
            continue
        try:
            with open(fpath, "rb") as fh:
                src = fh.read()
            tree = ast.parse(src, filename=fname)
        except SyntaxError as exc:
            item["errors"].append("%s: syntax error at line %s: %s" % (fname, exc.lineno, exc.msg))
            continue
        except ValueError as exc:
            item["errors"].append("%s: %s" % (fname, exc))
            continue
        errs, warns = import_problems(tree)
        item["errors"] += ["%s %s" % (fname, e) for e in errs]
        item["warnings"] += ["%s %s" % (fname, w) for w in warns]
        if item["function"] and not defines(tree, item["function"]):
            item["errors"].append("%s does not define %s at module level"
                                  % (fname, item["function"]))
        rel = impl.get("samples")
        rows = []
        if rel:
            spath = os.path.realpath(os.path.join(PUBLIC, rel))
            if spath.startswith(PUBLIC + "/") and os.path.isfile(spath):
                with open(spath, encoding="utf-8") as fh:
                    rows = (json.load(fh) or {}).get(qid) or []
        if not rows:
            item["warnings"].append("no public samples for %s" % qid)
        elif not item["errors"]:
            os.makedirs(CHECK_DIR, exist_ok=True)
            inputs = os.path.join(CHECK_DIR, "%s.inputs.jsonl" % qid)
            with open(inputs, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row.get("args", []), ensure_ascii=False) + "\n")
            item["inputs"] = inputs
            item["expected"] = [row.get("out") for row in rows]
    return {"answers_ok": answers_ok, "answered": sorted(k for k in answers if k in qids),
            "questions": qids, "missing": missing, "errors": errors,
            "warnings": warnings, "impl": impls}


OPS = {"list": op_list, "read": op_read, "grep": op_grep, "write": op_write,
       "edit": op_edit, "save": op_save, "check": op_check}


def main():
    try:
        req = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = OPS[req["op"]](req)
        reply = {"ok": True, "data": result} if isinstance(result, dict) \
            else {"ok": True, "text": result}
    except Refused as exc:
        reply = {"ok": False, "refused": True, "error": "refused: %s" % exc}
    except Failed as exc:
        reply = {"ok": False, "refused": False, "error": str(exc)}
    except OSError as exc:
        reply = {"ok": False, "refused": False,
                 "error": "%s%s" % (exc.strerror or exc, ": %s" % exc.filename
                                    if exc.filename else "")}
    except MemoryError:
        reply = {"ok": False, "refused": False, "error": "out of memory"}
    sys.stdout.write(json.dumps(reply, ensure_ascii=False))


if __name__ == "__main__":
    main()
