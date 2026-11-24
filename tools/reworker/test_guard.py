#!/usr/bin/env python3
"""Tests for guard.py. Run: python3 test_guard.py"""

import json
import sys

import guard

LOAD = 'import sys\nsys.path.insert(0, "%s")\nimport rekit\n' % guard.REKIT_DIR
EXEC = "mcp__ida__execute_python"

STRICT_OK = [
    LOAD + "rekit.help()",
    "rekit.fn(0x3e76224)",
    'rekit.fn("sub_3E76224", code="none", max_chars=3000)',
    'rekit.find(string="http", limit=5, regex=True)',
    'rekit.find(bytes="FD 7B ?? A9")',
    "rekit.batch([0x1000, 0x2000, 'sub_3000'])",
    '{"a": rekit.xrefs(0x1000), "b": rekit.calls(0x1000, depth=1, dir="in")}',
    "r = rekit.fn(0x1000)\nr['code']['text'][:500]",
    "a = rekit.fn(0x1000)\nb = rekit.fn(0x2000)\n[a, b]",
    "rekit.disasm(0x1000, n=-1)",
    "rekit.emu(0x401000, args=[1, 2], max_steps=5000)",
    'rekit.scan("sub_1A2B3C0")',
    'rekit.scan(0x1a2b3c0, end=0x1c13ef0, show="imms", min=0x10000, '
    'mnem=["MOV", "EOR"], start=60)',
    'rekit.scan("sub_1A2B3C0", imm=0x5BD1E995)',
    '{"n": rekit.scan(0x1a2b3c0, to="_syscall", reg="w0", limit=40), '
    '"s": rekit.decode("sub_2F4D10", limit=20)}',
    'rekit.fn(0x1000, decode=False)',
    'rekit.emu("sub_1002660", args=[{"bytes": "00 11"}, {"out": 16}], '
    'init=["sub_1002480", 0x1002890, {"func": "sub_1002A00", "args": [3, {"out": 8, "name": "seed"}], '
    '"replace": {"sub_1001000": {"stub": "malloc"}}}])',
]

STRICT_BAD = [
    "import idautils\nlist(idautils.Functions())",
    "import os\nos.system('id')",
    "rekit._decompile(1)",
    "rekit.fn(ea)",
    "rekit.fn(0x1000).keys()",
    "print(rekit.fn(0x1000))",
    "[rekit.fn(x) for x in range(3)]",
    "idc.set_name(0x1000, 'x')",
    "rekit.fn(**{'ea': 1})",
    "rekit = 1",
    "import sys\nsys.path.insert(0, '/tmp/evil')\nimport rekit",
    "import rekit as r\nr.fn(1)",
    "def f():\n    pass",
    "rekit.fn(0x1000) if True else 0",
    "__import__('os')",
    "rekit.fn(open('/etc/passwd').read())",
    "lambda: 1",
    "rekit.nope(1)",
    "rekit.notes(0x1000)",
    "rekit.image(0x1000)",
    "this is not python",
]

FREE_OK = STRICT_OK + [
    "import idautils, idc\n[hex(ea) for ea in idautils.Functions()][:10]",
    "import ida_hexrays\nstr(ida_hexrays.decompile(0x1000))",
    "import ida_bytes\nida_bytes.get_bytes(0x1000, 16).hex()",
    "for x in idautils.XrefsTo(0x1000):\n    print(hex(x.frm))",
    "import re, json, struct, collections\nstruct.unpack('<I', b'abcd')",
    "idc.get_func_name(0x1000)",
]

FREE_BAD = [
    "import idc\nidc.set_name(0x1000, 'x')",
    "idc.set_cmt(0x1000, 'x', 0)",
    "ida_bytes.patch_byte(0x1000, 0x90)",
    "ida_name.set_name(0x1000, 'x')",
    "idc.SetType(0x1000, 'int f(void)')",
    "ida_typeinf.apply_tinfo(0x1000, t, 0)",
    "ida_funcs.add_func(0x1000)",
    "ida_funcs.del_func(0x1000)",
    "ida_bytes.create_strlit(0x1000, 0, 0)",
    "db.functions.rename(f, 'x')",
    "import os\nos.system('id')",
    "import subprocess",
    "from os import path",
    "import urllib.request",
    "open('/tmp/x', 'w').write('1')",
    "eval('1+1')",
    "__import__('os').system('id')",
    "getattr(idc, 'set_' + 'name')(0x1000, 'x')",
    "().__class__.__bases__[0].__subclasses__()",
    "ida_loader.save_database('/tmp/x', 0)",
    "idc.qexit(0)",
]

TOOLS = [
    ("mcp__ida__open_database", {"path": "/x"}, True),
    ("mcp__ida__list_databases", {}, True),
    ("mcp__ida__reference", {"query": "xrefs"}, True),
    ("mcp__ida__save_database", {}, False),
    ("mcp__ida__close_database", {}, False),
    ("mcp__plugin_ida-mcp_ida__execute_python", {"code": "rekit.info()"}, True),
    ("bash", {"command": "ls"}, False),
    ("write_file", {"path": "/tmp/x"}, False),
    ("mcp__other__execute_python", {"code": "rekit.info()"}, False),
    (EXEC, {"code": ""}, False),
    (EXEC, {}, False),
]


def run():
    bad = []
    for code in STRICT_OK:
        ok, why = guard.check(EXEC, {"code": code}, "strict")
        if not ok:
            bad.append(("strict should allow", code, why))
    for code in STRICT_BAD:
        ok, _ = guard.check(EXEC, {"code": code}, "strict")
        if ok:
            bad.append(("strict should refuse", code, ""))
    for code in FREE_OK:
        ok, why = guard.check(EXEC, {"code": code}, "free")
        if not ok:
            bad.append(("free should allow", code, why))
    for code in FREE_BAD:
        ok, _ = guard.check(EXEC, {"code": code}, "free")
        if ok:
            bad.append(("free should refuse", code, ""))
    for name, inp, want in TOOLS:
        ok, why = guard.check(name, inp, "strict")
        if ok != want:
            bad.append(("tool %s expected %s" % (name, want), json.dumps(inp), why))

    # raw MCP names, as the proxy sees them, and the database pin
    DB = "/x/samples/a.bin"
    for tool, inp, want in [
        ("execute_python", {"code": "rekit.info()"}, True),
        ("execute_python", {"code": "import os"}, False),
        ("list_databases", {}, True),
        ("reference", {"query": "xrefs"}, True),
        ("save_database", {}, False),
        ("close_database", {"instance_id": "x"}, False),
        ("bash", {"command": "ls"}, False),
        ("open_database", {"path": DB}, True),
        ("open_database", {"path": DB + ".i64"}, True),
        ("open_database", {"path": "/x/samples/../samples/a.bin"}, True),
        ("open_database", {"path": "/x/samples/b.bin"}, False),
        ("open_database", {"path": "/x/samples/a.bin.id0"}, False),
        ("open_database", {}, False),
        ("open_database", {"path": DB, "load_options": {"processor": "arm"}}, False),
    ]:
        ok, why = guard.check_ida(tool, inp, "strict", db=DB)
        if ok != want:
            bad.append(("check_ida %s expected %s" % (tool, want), json.dumps(inp), why))
    ok, _ = guard.check_ida("open_database", {"path": "/anything.bin"}, "strict")
    if not ok:
        bad.append(("open_database without a pin is allowed", "/anything.bin", ""))
    ok, _ = guard.check("mcp__ida__open_database", {"path": "/x/b.bin"}, "strict", db=DB)
    if ok:
        bad.append(("check() passes the pin on", "/x/b.bin", ""))
    ok, why = guard.check_ida("execute_python", {"code": "idc.get_name(1)"}, "free", db=DB)
    if not ok:
        bad.append(("free check_ida should allow", "idc.get_name", why))
    for mode in ("strict", "free"):
        ok, why = guard.check_ida("execute_python", {"code": "rekit.info()",
                                                     "instance_id": "2c37436dbad4"}, mode, db=DB)
        if ok or "instance_id" not in why:
            bad.append(("%s refuses instance_id" % mode, "", why))
        ok, why = guard.check_ida("execute_python", {"code": "rekit.info()",
                                                     "instance_id": None}, mode, db=DB)
        if not ok:
            bad.append(("%s allows an explicit null instance_id" % mode, "", why))
    if hasattr(guard, "main"):
        bad.append(("guard.main is gone", "", "the hook entry point was replaced by guardproxy"))

    total = (len(STRICT_OK) + len(STRICT_BAD) + len(FREE_OK) + len(FREE_BAD)
             + len(TOOLS) + 23)
    for item in bad:
        print("FAIL: %s\n    %s\n    %s" % item)
    print("%d checks, %d failed" % (total, len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
