#!/usr/bin/env python3
"""Tool-call policy for re-worker runs.

guardproxy.py, the MCP stdio proxy between dsh and ida-mcp, asks this module
about every tools/call before it reaches IDA.

strict
    execute_python may only load rekit and call rekit.<api>(...) with literal
    arguments. The worker is read-only by construction and cannot guess at
    IDA API names.
free
    execute_python may run arbitrary IDAPython for reading. Database writes
    and anything reaching outside IDA are refused by name. This is a guardrail
    against a careless model, not a sandbox: determined code can get around a
    name check.

Either way, only the ida MCP tools open_database, list_databases,
execute_python and reference are allowed; save/close are refused. With `db`
given, open_database may only open that database (or its .i64/.idb), and
execute_python may not name another database with instance_id.

    check(tool_name, tool_input, mode, db=None) -> (allowed, reason)
        tool_name as the model sees it, e.g. "mcp__ida__execute_python"
    check_ida(raw_name, arguments, mode, db=None) -> (allowed, reason)
        raw MCP tool name, e.g. "execute_python" (what the proxy sees)
"""

from __future__ import annotations

import ast
import os
import re

REKIT_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "..", "rekit"))
REKIT_API = {"help", "info", "fn", "code", "xrefs", "calls", "find", "disasm",
             "batch", "emu", "selftest",
             # range scans of code that cannot be decompiled, and strings the
             # one-time initialisers build (emulated on the snapshot, like emu)
             "scan", "decode",
             # whole-program emulation in the rebox sandbox (never the Docker
             # mode), the crypto-constant matcher, and the restricted calculator
             "run", "crypto", "calc"}
IDA_TOOL = re.compile(r"(?:^|__|[_:])ida__?(\w+)$")
ALLOWED_TOOLS = {"open_database", "list_databases", "execute_python", "reference"}

LOAD_HINT = ('load with: import sys; sys.path.insert(0, "%s"); import rekit'
             % REKIT_DIR)
STRICT_HINT = ("Only rekit calls with literal arguments are allowed here, e.g. "
               "rekit.fn(0x1234) or {\"a\": rekit.xrefs(\"sub_1234\")}. If the "
               "task needs something rekit cannot do, stop and list it under "
               "\"needs\" in your result.")

# free mode: names that write to the database or leave IDA
WRITE_CALL = re.compile(
    r"^(set_|patch_|del_|add_|create_|apply_|rename|make_|put_|revert_|save_|"
    r"Set[A-Z]|Patch|Del[A-Z]|Add[A-Z]|Create|Make[A-Z]|"
    r"save_database|qexit|load_and_run_plugin|run_plugin|exec_idc|process_ui_action)")
BANNED_MODULES = {"os", "subprocess", "shutil", "socket", "urllib", "requests",
                  "http", "ctypes", "multiprocessing", "pathlib", "tempfile",
                  "ftplib", "smtplib", "pty", "signal", "webbrowser"}
BANNED_BUILTINS = {"eval", "exec", "compile", "__import__", "open", "input",
                   "breakpoint", "getattr", "setattr", "delattr", "globals",
                   "vars"}


class Denied(Exception):
    pass


# --------------------------------------------------------------------------
# strict mode
# --------------------------------------------------------------------------

def _strict_expr(node, names):
    """Literals, earlier results, containers of those, and rekit calls."""
    if isinstance(node, ast.Constant):
        return
    if isinstance(node, ast.Name):
        if node.id in names:
            return
        raise Denied("unknown name %r" % node.id)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return _strict_expr(node.operand, names)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for item in node.elts:
            _strict_expr(item, names)
        return
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if key is None:
                raise Denied("dict unpacking")
            _strict_expr(key, names)
            _strict_expr(value, names)
        return
    if isinstance(node, ast.Subscript):
        _strict_expr(node.value, names)
        index = node.slice
        if isinstance(index, ast.Slice):
            for part in (index.lower, index.upper, index.step):
                if part is not None:
                    _strict_expr(part, names)
            return
        return _strict_expr(index, names)
    if isinstance(node, ast.Call):
        func = node.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id == "rekit"):
            raise Denied("call to something other than rekit.<api>(...)")
        if func.attr not in REKIT_API:
            raise Denied("rekit.%s is not a rekit call (rekit.help() lists them)"
                         % func.attr)
        if "rekit" not in names:
            raise Denied("rekit is not imported in this snippet; " + LOAD_HINT)
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                raise Denied("argument unpacking")
            _strict_expr(arg, names)
        for kw in node.keywords:
            if kw.arg is None:
                raise Denied("keyword unpacking")
            _strict_expr(kw.value, names)
        return
    raise Denied("%s is not allowed" % type(node).__name__)


def _is_path_insert(node):
    """sys.path.insert(0, "<rekit dir>") or sys.path.append("<rekit dir>")."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    func = node.func
    if func.attr not in ("insert", "append"):
        return False
    target = func.value
    if not (isinstance(target, ast.Attribute) and target.attr == "path"
            and isinstance(target.value, ast.Name) and target.value.id == "sys"):
        return False
    if node.keywords or not node.args:
        return False
    path = node.args[-1]
    if not (isinstance(path, ast.Constant) and isinstance(path.value, str)):
        return False
    if os.path.normpath(path.value) != REKIT_DIR:
        raise Denied("sys.path may only gain the rekit directory; " + LOAD_HINT)
    return True


def check_strict(code, session_names=("rekit", "sys")):
    """Raise Denied unless the snippet stays inside the rekit vocabulary.

    `rekit` and `sys` count as known names because execute_python keeps
    globals for the lifetime of the database lease.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise Denied("syntax error: %s" % exc.msg)
    names = set(session_names)
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.name not in ("sys", "rekit") or alias.asname:
                    raise Denied("import %s" % alias.name)
                names.add(alias.name)
        elif isinstance(stmt, ast.Expr):
            if _is_path_insert(stmt.value):
                continue
            _strict_expr(stmt.value, names)
        elif isinstance(stmt, ast.Assign):
            _strict_expr(stmt.value, names)
            for target in stmt.targets:
                if not isinstance(target, ast.Name) or target.id in ("rekit", "sys"):
                    raise Denied("assignment target must be a plain new name")
                names.add(target.id)
        else:
            raise Denied("%s statements" % type(stmt).__name__.lower())


# --------------------------------------------------------------------------
# free mode
# --------------------------------------------------------------------------

def check_free(code):
    """Raise Denied for database writes and for code that leaves IDA."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise Denied("syntax error: %s" % exc.msg)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in BANNED_MODULES:
                    raise Denied("import %s (outside IDA)" % alias.name)
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in BANNED_MODULES:
                raise Denied("from %s import ... (outside IDA)" % node.module)
        elif isinstance(node, ast.Call):
            func = node.func
            name = (func.attr if isinstance(func, ast.Attribute)
                    else func.id if isinstance(func, ast.Name) else "")
            if isinstance(func, ast.Name) and name in BANNED_BUILTINS:
                raise Denied("%s() is not available to workers" % name)
            if WRITE_CALL.match(name):
                raise Denied("%s() changes the database; workers only read. "
                             "Describe the change under \"needs\" instead" % name)
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") \
                and node.attr not in ("__name__", "__doc__", "__class__"):
            raise Denied("dunder attribute %s" % node.attr)


# --------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------

DB_SUFFIXES = (".i64", ".idb")


def _db_key(path):
    """Compare databases by input file: a.bin, a.bin.i64 and a.bin.idb match."""
    path = os.path.realpath(os.path.expanduser(str(path)))
    for suffix in DB_SUFFIXES:
        if path.lower().endswith(suffix):
            return path[:-len(suffix)]
    return path


def check_ida(tool, arguments, mode="strict", db=None):
    """Return (allowed, reason) for one ida-mcp tool, by its raw MCP name."""
    if tool not in ALLOWED_TOOLS:
        return False, ("%s is reserved for the orchestrator; leave the database "
                       "open and unsaved" % tool)
    arguments = arguments if isinstance(arguments, dict) else {}
    if tool == "open_database":
        if arguments.get("load_options"):
            return False, "load_options are not available to workers"
        path = arguments.get("path")
        if db and (not isinstance(path, str) or _db_key(path) != _db_key(db)):
            return False, ("this worker may only open %s; other databases are "
                           "out of scope" % db)
        return True, ""
    if tool != "execute_python":
        return True, ""
    if arguments.get("instance_id") is not None:
        return False, ("instance_id is not available to workers; execute_python "
                       "runs on the database you opened. Leave instance_id out")
    code = arguments.get("code")
    if not isinstance(code, str) or not code.strip():
        return False, "execute_python needs a non-empty `code` string"
    try:
        if mode == "free":
            check_free(code)
        else:
            check_strict(code)
    except Denied as exc:
        hint = STRICT_HINT if mode != "free" else ""
        return False, ("refused: %s. %s" % (exc, hint)).strip()
    return True, ""


def check(tool_name, tool_input, mode="strict", db=None):
    """Return (allowed, reason) for a tool as the model names it.

    `reason` is shown to the worker model.
    """
    m = IDA_TOOL.search(tool_name or "")
    if not m:
        return False, ("tool %r is not available to workers; use the ida tools "
                       "only" % tool_name)
    return check_ida(m.group(1), tool_input, mode, db)
