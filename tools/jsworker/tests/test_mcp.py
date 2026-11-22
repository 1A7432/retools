#!/usr/bin/env python3
"""The nine jsre tools against a real container (image jsvm1-tools:1), driven
through jsre_mcp.py's JSON-RPC interface. No dsh, no model.
Run: python3 tests/test_mcp.py
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Checks, FIXTURE_BENCH, Sandbox, image_ready, jsw, read_log  # noqa: E402

GOOD_IMPL = '''import json  # stdlib is fine
from Crypto.Hash import SHA256  # pycryptodome is available


def sign(s):
    h = 0
    for ch in s.encode("utf-16-le").decode("utf-16-le"):
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return "%08x" % h
'''


def run(c, sb, srv):
    call = srv.call
    manifest = jsw.read_manifest(os.path.join(FIXTURE_BENCH, "public"))

    # -- fs_list / fs_read --------------------------------------------------------
    t, e = call("fs_list", path="/task", depth=3)
    c.expect("fs_list /task", not e and "/task/public/t1/app.js" in t and "/task/work/" in t
             and manifest["t1/app.js"][:12] in t, t)
    c.expect("fs_list does not show other targets", "/task/public/t2" not in t, t)
    t, e = call("fs_list", path="/task/public", depth=1)
    c.expect("fs_list depth 1", not e and "/task/public/t1/" in t and
             "/task/public/t1/app.js" not in t, t)
    t, e = call("fs_read", path="/task/public/README.md")
    c.expect("fs_read lines", not e and "lines 1-" in t and "\t# Fixture benchmark" in t, t)
    t, e = call("fs_read", path="/task/public/README.md", offset=2, limit=1)
    c.expect("fs_read line window", not e and "lines 2-2" in t and "continue with offset=3" in t, t)
    t, e = call("fs_read", path="/task/public/t1/app.js", unit="byte", offset=3, limit=7)
    c.expect("fs_read byte window", not e and t.endswith("\nFixture") and "bytes 3-10" in t, t)
    t, e = call("fs_read", path="/task/public/nope.js")
    c.expect("fs_read missing file", e and "does not exist" in t, t)

    # a megabyte on one line
    t, e = call("py_run", code=(
        "s = 'var a=' + 'x' * 654314 + ';MARK_42();' + 'y' * 400000 + '\\n'\n"
        "open('/task/work/big.js', 'w').write(s)\nprint(len(s), s.index('MARK_42'))"))
    c.expect("big file written", not e and "1054332 654321" in t, t)
    t, e = call("fs_read", path="/task/work/big.js")
    c.expect("fs_read caps a huge line", not e and len(t) < 41000 and
             "line 1 is 1054331 bytes" in t and "unit=\"byte\", offset=" in t, t[:300])
    t, e = call("fs_read", path="/task/work/big.js", unit="byte", offset=654300, limit=40)
    c.expect("fs_read byte window into the huge line", not e and "MARK_42();" in t and
             "bytes 654300-654340 of 1054332" in t, t)
    t, e = call("fs_read", path="/task/work/big.js", unit="byte", offset=0, limit=10 ** 6)
    c.expect("fs_read byte window is capped at 40000", not e and "bytes 0-40000" in t, t[:200])
    t, e = call("fs_grep", pattern=r"MARK_\d+", path="/task/work/big.js")
    hit = [l for l in t.splitlines() if l.startswith("/task/work/big.js:1:654321: ")]
    c.expect("fs_grep reports line and byte offset", not e and hit, t[:500])
    c.expect("fs_grep shows 200 bytes either side", hit and "x" * 199 + ";MARK_42();" in hit[0]
             and "y" * 150 in hit[0] and "x" * 201 not in hit[0] and len(hit[0]) < 450,
             hit[:1])
    t, e = call("fs_grep", pattern="sign", path="/task/public/t1", max=2)
    c.expect("fs_grep over a directory", not e and "/task/public/t1/app.js:2:" in t and
             "showing the first 2" in t, t)
    t, e = call("fs_grep", pattern="(unclosed", path="/task/public")
    c.expect("fs_grep bad pattern", e and "bad pattern" in t, t)

    # -- fs_write / fs_edit -------------------------------------------------------------
    t, e = call("fs_write", path="/task/work/notes/a.txt", content="one\ntwo\ntwo\n")
    c.expect("fs_write makes parents", not e and "wrote 12 bytes" in t, t)
    t, e = call("fs_edit", path="/task/work/notes/a.txt", old="one", new="ONE")
    c.expect("fs_edit unique", not e and "replaced 1" in t, t)
    t, e = call("fs_edit", path="/task/work/notes/a.txt", old="two", new="2")
    c.expect("fs_edit ambiguous", e and "occurs 2 times" in t, t)
    t, e = call("fs_edit", path="/task/work/notes/a.txt", old="zzz", new="2")
    c.expect("fs_edit missing", e and "not found" in t, t)
    t, e = call("fs_read", path="/task/work/notes/a.txt")
    c.expect("edit landed", "\tONE" in t and t.count("\ttwo") == 2, t)
    c.expect("file visible on the host",
             open(os.path.join(sb.run_dir, "work", "notes", "a.txt")).read() == "ONE\ntwo\ntwo\n")

    # -- node_run ---------------------------------------------------------------------------
    t, e = call("node_run", code="const m = require('/task/public/t1/app.js');\n"
                                 "console.log(m.sign('abc'), process.argv.slice(2).join(','));",
                args=["p", "--inspect"])
    c.expect("node_run code", not e and "00017862 p,--inspect" in t and "exit code 0" in t, t)
    m = re.search(r"code saved as (/task/work/\.jsw/code/\d+\.js)", t)
    c.expect("code saved as a file", m and os.path.isfile(os.path.join(
        sb.run_dir, "work", m.group(1)[len("/task/work/"):])), t)
    t, e = call("node_run", code=(
        "const p = require('@babel/parser'), g = require('@babel/generator').default;\n"
        "const t = require('@babel/traverse').default, a = require('acorn');\n"
        "require('acorn-walk'); require('astring'); require('@babel/types');\n"
        "const ast = p.parse('var x=1+2'); let n = 0; t(ast, {enter() { n++ }});\n"
        "console.log(g(ast).code, n, a.parse('1', {ecmaVersion: 2022}).type, process.version)"))
    c.expect("AST libraries on NODE_PATH", not e and "var x = 1 + 2;" in t and "Program" in t
             and "v22.21.1" in t, t)
    t, e = call("node_run", code="let d='';process.stdin.on('data',x=>d+=x);"
                                 "process.stdin.on('end',()=>{console.error('E');"
                                 "console.log(d.toUpperCase());process.exit(3)})",
                stdin="hello")
    c.expect("node_run stdin, stderr and exit code", "exit code 3" in t and "HELLO" in t and
             "--- stderr ---\nE" in t, t)
    t, e = call("node_run", code="console.log(JSON.stringify(process.execArgv))",
                node_flags=["--stack-size=2000", "--max-old-space-size=512"])
    c.expect("node argv exactly as built by the server (repeated --allow-fs-read)", json.dumps(
        ["--permission", "--allow-fs-read=/task", "--allow-fs-read=/opt/jsre",
         "--allow-fs-write=/task/work", "--stack-size=2000", "--max-old-space-size=512"],
        separators=(",", ":")) in t, t)
    t, e = call("node_run", code="const fs=require('fs');"
                                 "console.log(fs.readFileSync('/opt/jsre/beautify.js','utf8')"
                                 ".length>100, fs.readFileSync('/task/public/README.md','utf8')"
                                 ".length>10, require.resolve('@babel/traverse'))")
    c.expect("node may read both /task and /opt/jsre", "true true /opt/jsre/node_modules/"
             "@babel/traverse" in t, t)
    t, e = call("node_run", code="while (true) {}", timeout=2)
    c.expect("node_run timeout", "TIMEOUT: stopped after 2 s" in t, t)
    t, e = call("node_run", code="const vm=require('vm');"
                                 "console.log(vm.runInNewContext('navigator', {navigator: 7}))")
    c.expect("vm module works", "\n7" in t, t)
    t, e = call("node_run", code="process.stdout.write('A'.repeat(15000)+'Z'.repeat(15000))")
    m = re.search(r"full output \((\d+) characters\) is in (/task/work/\.jsw/out/\d+\.txt)", t)
    c.expect("long output cut", m and t.count("A") >= 9000 and len(t) < 20600, t[-400:])
    if m:
        saved = os.path.join(sb.run_dir, "work", m.group(2)[len("/task/work/"):])
        body = open(saved).read() if os.path.isfile(saved) else ""
        c.expect("full output saved", body.count("A") == 15000 and body.count("Z") == 15000,
                 len(body))
    log = read_log(sb.log)
    rec = [r for r in log if r.get("saved")]
    c.expect("saved path logged", rec and rec[-1]["saved"].startswith("/task/work/.jsw/out/"))
    t, e = call("node_run", file="/task/public/t1/app.js")
    c.expect("node_run file", not e and "exit code 0" in t, t)
    t, e = call("node_run", code="process.stdout.write(Buffer.from([0xff, 0xfe, 0x41]))")
    c.expect("non-UTF-8 output survives", "A" in t and not e, t)

    # -- py_run ---------------------------------------------------------------------------
    t, e = call("py_run", code="import sys, Crypto, gmssl\nprint(sys.version_info[:2], "
                               "sys.argv[1:], sys.stdin.read())", args=["a", "b"], stdin="in")
    c.expect("py_run code", not e and "(3, 13) ['a', 'b'] in" in t, t)
    call("fs_write", path="/task/work/s.py", content="import sys\nprint('file', sys.argv[1:])\n")
    t, e = call("py_run", file="/task/work/s.py", args=["x"])
    c.expect("py_run file", not e and "file ['x']" in t, t)
    t, e = call("py_run", code="raise SystemExit(4)")
    c.expect("py_run exit code", "exit code 4" in t, t)
    t, e = call("py_run", code="import time\ntime.sleep(30)", timeout=2)
    c.expect("py_run timeout", "TIMEOUT" in t, t)

    # -- js_beautify -------------------------------------------------------------------------
    t, e = call("js_beautify", path="/task/public/t1/app.js", out="/task/work/pretty.js")
    c.expect("js_beautify", not e and "wrote /task/work/pretty.js" in t, t)
    t, e = call("node_run", code="console.log(require('/task/work/pretty.js').sign('abc'))")
    c.expect("beautified code still runs", "00017862" in t, t)
    pretty = open(os.path.join(sb.run_dir, "work", "pretty.js")).read()
    c.expect("beautified has many lines", pretty.count("\n") > 8, pretty[:200])

    # -- submit_check -----------------------------------------------------------------------
    t, e = call("submit_check")
    c.expect("submit_check without answers", "answers.json does not exist" in t, t)
    call("fs_write", path="/task/work/submission/answers.json",
         content=json.dumps({"T1-01": "T1-01.py", "T1-02": 31}))
    call("fs_write", path="/task/work/submission/T1-01.py", content=GOOD_IMPL)
    t, e = call("submit_check")
    c.expect("submit_check good", t.startswith("submit_check: OK; answered 2 of 2") and
             "public samples 3/3 passed" in t, t)
    call("fs_write", path="/task/work/submission/T1-01.py",
         content=GOOD_IMPL.replace("h * 31", "h * 33"))
    t, e = call("submit_check")
    c.expect("submit_check wrong impl", "public samples 1/3 passed" in t and
             'FAIL expected "00017862"' in t, t)
    c.expect("no bytecode cache written into the submission",
             not os.path.exists(os.path.join(sb.run_dir, "work", "submission", "__pycache__")))
    call("fs_write", path="/task/work/submission/T1-01.py",
         content="import requests\nimport os, subprocess\n\ndef other():\n    pass\n")
    call("fs_write", path="/task/work/submission/answers.json",
         content=json.dumps({"T1-01": "T1-01.py", "T2-01": 42, "T1-02": ""}))
    t, e = call("submit_check")
    c.expect("submit_check bad import", "import requests" in t, t)
    c.expect("submit_check blocked module warned", "import subprocess" in t and "warnings" in t, t)
    c.expect("submit_check missing function", "does not define sign" in t, t)
    c.expect("submit_check foreign qid", "'T2-01', which is not a question of this target" in t, t)
    c.expect("submit_check empty answer", "T1-02: the answer is empty" in t, t)
    call("fs_write", path="/task/work/submission/T1-01.py", content="def sign(s:\n")
    t, e = call("submit_check")
    c.expect("submit_check syntax error", "syntax error at line 1" in t, t)
    call("fs_write", path="/task/work/submission/answers.json", content="{not json")
    t, e = call("submit_check")
    c.expect("submit_check bad json", "not valid JSON" in t, t)
    call("fs_write", path="/task/work/submission/answers.json",
         content=json.dumps({"T1-02": 31}))
    call("fs_write", path="/task/work/submission/T1-01.py",
         content="def sign(s):\n    raise ValueError('boom ' + s)\n")
    t, e = call("submit_check")
    c.expect("submit_check by convention and errors", "by convention" in t and
             "ERROR ValueError: boom abc" in t, t)
    call("py_run", code="import os\nos.remove('/task/work/submission/T1-01.py')\n"
                        "os.symlink('/task/public/t1/app.js', '/task/work/submission/T1-01.py')")
    call("fs_write", path="/task/work/submission/answers.json",
         content=json.dumps({"T1-01": "T1-01.py"}))
    t, e = call("submit_check")
    c.expect("submit_check refuses a symlinked implementation", "symbolic link" in t, t)
    call("py_run", code="import os\nos.remove('/task/work/submission/T1-01.py')")
    call("fs_write", path="/task/work/submission/T1-01.py",
         content="import time\ndef sign(s):\n    time.sleep(5)\n")
    t, e = call("submit_check")
    c.expect("submit_check per-sample time limit", "call exceeded" in t, t)

    log = read_log(sb.log)
    calls = [r for r in log if r.get("event") == "call"]
    c.expect("every call logged with a number",
             all(isinstance(r.get("call_no"), int) for r in calls) and
             sorted(r["call_no"] for r in calls) == list(range(1, len(calls) + 1)),
             [r.get("call_no") for r in calls])
    c.expect("log has results and timings", all("result" in r and "seconds" in r for r in calls))


def main():
    c = Checks()
    if not image_ready():
        print("cannot run: %s" % jsw.image_problems())
        return 1
    sb = Sandbox("t1")
    srv = sb.server(max_calls=500)
    try:
        run(c, sb, srv)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        c.expect("test raised", False, exc)
    finally:
        srv.close()
        sb.close()
    return c.report()


if __name__ == "__main__":
    sys.exit(main())
