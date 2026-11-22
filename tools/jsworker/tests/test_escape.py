#!/usr/bin/env python3
"""Escape attempts against a real run sandbox; every one must be refused or fail.

Layers exercised: the jsre MCP policy (paths, writes, node flags), the
container (no network, read-only mounts, nothing of the host mounted), node's
permission model (fs, child_process, worker_threads) and pyrun's audit hook
(subprocess, os.system, sockets, ctypes). Run: python3 tests/test_escape.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _harness import Checks, FIXTURE_BENCH, Sandbox, image_ready, jsw  # noqa: E402

SEALED = os.path.join(FIXTURE_BENCH, "sealed", "answers.json")
MARKER = "SEALED-SECRET-7f3a9c"
HOST_PATHS = [SEALED, os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.zshrc"),
              os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "..", "..", "bench", "jsvm1", "sealed"))]
DENIED = "ERR_ACCESS_DENIED"
# Names that exist only on the host: the user name and the checkout directory.
HOST_NAMES = (os.path.basename(os.path.expanduser("~")),
              os.path.basename(os.path.normpath(os.path.join(
                  os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))))


def run(c, sb, srv):
    call = srv.call

    def refused(label, tool, **kw):
        t, e = call(tool, **kw)
        c.expect("%s is refused" % label, e and t.startswith("refused:"), t[:300])
        c.expect("%s leaks nothing" % label, MARKER not in t and "root:x:0" not in t, t[:300])

    # -- MCP path policy: host paths, outside /task, traversal, relative ---------------
    for p in HOST_PATHS + ["/etc/passwd", "/", "/proc/self/environ", "/opt/jsre/pyrun.py"]:
        refused("fs_read %s" % p, "fs_read", path=p)
    refused("fs_list /", "fs_list", path="/")
    refused("fs_list host bench", "fs_list", path=os.path.dirname(SEALED))
    refused("fs_grep /etc", "fs_grep", pattern="root", path="/etc")
    refused("fs_grep host", "fs_grep", pattern=MARKER, path=os.path.dirname(SEALED))
    for p in ["/task/../etc/passwd", "/task/public/../../etc/passwd",
              "/task/work/../../../etc/shadow", "/task/..", "../etc/passwd",
              "task/public/README.md", "public/README.md", "./README.md"]:
        refused("traversal/relative %s" % p, "fs_read", path=p)
    refused("node_run file outside", "node_run", file="/etc/passwd")
    refused("node_run file traversal", "node_run", file="/task/../opt/jsre/beautify.js")
    refused("py_run file outside", "py_run", file="/opt/jsre/pyrun.py")
    refused("js_beautify input outside", "js_beautify", path="/opt/jsre/beautify.js",
            out="/task/work/b.js")

    # -- writes only under /task/work ----------------------------------------------------
    for p in ["/task/public/t1/app.js", "/task/public/new.js", "/task/work/../public/x.js",
              "/task/x", "/tmp/x", "/etc/x", SEALED]:
        refused("fs_write %s" % p, "fs_write", path=p, content="pwned")
    refused("fs_edit public", "fs_edit", path="/task/public/README.md", old="#", new="!")
    refused("js_beautify into public", "js_beautify", path="/task/public/t1/app.js",
            out="/task/public/t1/pretty.js")
    refused("js_beautify into /tmp", "js_beautify", path="/task/public/t1/app.js",
            out="/tmp/pretty.js")
    t, e = call("node_run", code="const fs=require('fs');"
                                 "for (const p of ['/task/public/x','/task/public/t1/app.js',"
                                 "'/task/x','/tmp/x']) { try { fs.writeFileSync(p,'1');"
                                 "console.log('WROTE', p) } catch (e) { console.log(e.code) } }")
    c.expect("node cannot write outside /task/work", "WROTE" not in t and
             t.count(DENIED) == 4, t)
    t, e = call("py_run", code="import os\nfor p in ['/task/public/x', '/task/public/t1/app.js',"
                               " '/etc/x', '/task/x']:\n"
                               "    try:\n        open(p, 'a').write('1'); print('WROTE', p)\n"
                               "    except OSError as exc:\n        print(type(exc).__name__, "
                               "exc.errno)\n")
    c.expect("python cannot write public or the root fs", "WROTE" not in t and
             t.count("OSError 30") + t.count("PermissionError 13") +
             t.count("FileNotFoundError 2") == 4, t)
    c.expect("public is unchanged", open(os.path.join(sb.run_dir, "public", "t1", "app.js")).read()
             == open(os.path.join(FIXTURE_BENCH, "public", "t1", "app.js")).read())

    # -- symlinks the worker makes do not widen the tools' reach ------------------------
    t, e = call("py_run", code="import os\nos.symlink('/etc/passwd', '/task/work/pw')\n"
                               "os.symlink('/', '/task/work/rootdir')\n"
                               "os.symlink('/task/public/README.md', '/task/work/readme')\n"
                               "os.symlink('%s', '/task/work/hostlink')\nprint('ok')" % SEALED)
    c.expect("symlinks made", "ok" in t, t)
    refused("fs_read via symlink to /etc", "fs_read", path="/task/work/pw")
    refused("fs_list via symlink to /", "fs_list", path="/task/work/rootdir/etc")
    refused("fs_grep via symlink to /", "fs_grep", pattern="root", path="/task/work/rootdir/etc")
    refused("fs_write via symlink into public", "fs_write", path="/task/work/readme",
            content="pwned")
    t, e = call("fs_read", path="/task/work/hostlink")
    c.expect("host path through a symlink is refused", e and MARKER not in t, t)
    # node's permission model checks the path it is given, not a symlink's target
    # (documented Node behaviour), so node can follow a link that py_run made into
    # the image's own files - which py_run can read anyway. The host stays out of
    # reach because it is not mounted:
    t, e = call("node_run", code="try{console.log(require('fs').readFileSync("
                                 "'/task/work/hostlink','utf8'))}catch(e){console.log(e.code)}")
    c.expect("node through a symlink cannot reach the host", "ENOENT" in t and MARKER not in t, t)

    # -- the host is not in the container at all -------------------------------------------
    for p in HOST_PATHS:
        t, e = call("py_run", code="import os\nprint(os.path.exists(%r))" % p)
        c.expect("python cannot see %s" % p, t.rstrip().endswith("False"), t)
    t, e = call("py_run", code=(
        "import os\nhits = []\n"
        "for d, ds, fs in os.walk('/'):\n"
        "    if d.startswith(('/proc', '/sys', '/dev')):\n        ds[:] = []\n        continue\n"
        "    for n in ds + fs:\n"
        "        if 'sealed' in n.lower() or n in %r:\n" % (HOST_NAMES,) +
        "            hits.append(os.path.join(d, n))\n"
        "print('HITS', hits[:20])\nprint(sorted(os.listdir('/task')))"), timeout=120)
    c.expect("no sealed or host files anywhere in the container", "HITS []" in t, t[-600:])
    c.expect("/task holds only public and work", "['public', 'work']" in t, t[-300:])
    t, e = call("fs_grep", pattern=MARKER, path="/task")
    c.expect("the sealed marker is nowhere under /task", "no matches" in t, t[:300])
    t, e = call("node_run", code="try{require('fs').readFileSync('/etc/passwd')}"
                                 "catch(e){console.log(e.code)}")
    c.expect("node cannot read outside /task and /opt/jsre", DENIED in t, t)
    t, e = call("py_run", code="import os\nprint(os.getuid(), os.getgid())")
    c.expect("tools run as uid 1000", "1000 1000" in t, t)

    # -- network ---------------------------------------------------------------------------
    t, e = call("node_run", code=(
        "const net=require('net'),dns=require('dns');let n=0;const done=()=>{if(++n===4)"
        "process.exit(0)};\n"
        "const s=net.connect(80,'1.1.1.1',()=>{console.log('CONNECTED tcp');done()});"
        "s.on('error',e=>{console.log('tcp',e.code);done()});\n"
        "dns.lookup('example.com',(e,a)=>{console.log(e?'dns '+e.code:'RESOLVED '+a);done()});\n"
        "fetch('http://1.1.1.1/').then(()=>{console.log('FETCHED');done()})"
        ".catch(e=>{console.log('fetch',e.cause&&e.cause.code||e.message);done()});\n"
        "require('dgram').createSocket('udp4').send('x',53,'8.8.8.8',e=>{console.log("
        "e?'udp '+e.code:'udp sent?');done()});\n"
        "setTimeout(()=>{console.log('TIMEOUT');process.exit(1)},20000)"), timeout=60)
    c.expect("node has no network", "CONNECTED" not in t and "RESOLVED" not in t and
             "FETCHED" not in t and "tcp E" in t and "dns E" in t, t)
    c.expect("node udp fails", "udp E" in t, t)
    t, e = call("py_run", code=(
        "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 80), timeout=5)\n"
        "    print('CONNECTED')\nexcept Exception as exc:\n    print(type(exc).__name__, exc)\n"
        "try:\n    import urllib.request\n    urllib.request.urlopen('http://1.1.1.1', timeout=5)\n"
        "    print('FETCHED')\nexcept Exception as exc:\n    print(type(exc).__name__, exc)\n"
        "try:\n    socket.getaddrinfo('example.com', 80)\n    print('RESOLVED')\n"
        "except Exception as exc:\n    print(type(exc).__name__, exc)\n"))
    c.expect("python has no network", "CONNECTED" not in t and "FETCHED" not in t and
             "RESOLVED" not in t and t.count("SandboxViolation") >= 2, t)

    # -- node: child processes, workers, native code ------------------------------------
    t, e = call("node_run", code=(
        "const cp=require('child_process');\n"
        "const tries={execSync:()=>cp.execSync('id'),spawnSync:()=>cp.spawnSync('/bin/sh',['-c','id']),"
        "fork:()=>cp.fork('/task/public/t1/app.js'),exec:()=>cp.exec('id'),"
        "worker:()=>new (require('worker_threads').Worker)('1',{eval:true}),"
        "binding:()=>process.binding('spawn_sync').spawn({file:'/bin/sh',args:['sh','-c','id'],"
        "stdio:[{type:'pipe',readable:true},{type:'pipe',writable:true},{type:'pipe',writable:true}]}),"
        "dlopen:()=>process.dlopen({exports:{}},'/usr/lib/x.node'),"
        "wasi:()=>new (require('wasi').WASI)({version:'preview1'}),"
        "inspector:()=>require('inspector').open(9229),"
        "session:()=>{const s=new (require('inspector').Session)();s.connect();return 'x'}};\n"
        "for (const [k,f] of Object.entries(tries)) { try { const r=f();"
        "console.log('RAN', k, r && r.output ? String(r.output) : '') } catch (e) {"
        "console.log('denied', k, e.code || e.message) } }"))
    for k in ["execSync", "spawnSync", "fork", "exec", "worker", "binding", "dlopen", "wasi",
              "inspector", "session"]:
        c.expect("node %s denied" % k, "RAN %s" % k not in t and "denied %s" % k in t, t)
    t, e = call("node_run", code="try{require('child_process').execSync('id')}"
                                 "catch(e){console.log(e.code)}", args=["--allow-child-process"])
    c.expect("node flags in args stay script args", DENIED in t, t)

    # -- unknown node flags are never passed to node ------------------------------------
    for flags in (["--inspect"], ["--inspect-brk=0.0.0.0:9229"], ["--allow-child-process"],
                  ["--allow-worker"], ["--allow-fs-read=/"], ["--allow-fs-write=/"],
                  ["--stack-size=2000", "--inspect"], ["--require=/task/work/x.js"],
                  ["--no-permission"], ["-e", "1"], ["--allow-addons"]):
        refused("node_flags %s" % flags, "node_run", code="1", node_flags=flags)

    # -- python: subprocesses, shells, sockets, native code ------------------------------
    attempts = {
        "subprocess": "import subprocess\nsubprocess.run(['id'])",
        "check_output": "import subprocess\nsubprocess.check_output('id', shell=True)",
        "os.system": "import os\nos.system('id')",
        "os.popen": "import os\nos.popen('id').read()",
        "os.fork": "import os\nos.fork()",
        "os.execv": "import os\nos.execv('/bin/sh', ['sh', '-c', 'id'])",
        "os.posix_spawn": "import os\nos.posix_spawn('/bin/sh', ['sh'], {})",
        "os.spawnv": "import os\nos.spawnv(os.P_WAIT, '/bin/sh', ['sh', '-c', 'id'])",
        "pty.spawn": "import pty\npty.spawn('/bin/sh')",
        "socket": "import socket\nsocket.socket()",
        "socketpair": "import socket\nsocket.socketpair()",
        "ctypes system": "import ctypes\nctypes.CDLL(None).system(b'id')",
        "ctypes libc": "import ctypes\nctypes.CDLL('libc.so.6')",
        "ctypes dlsym execv": "import ctypes\nctypes.CDLL(None).execv",
        "multiprocessing": "import multiprocessing\nmultiprocessing.Process(target=print).start()",
        "os.kill": "import os\nos.kill(1, 9)",
    }
    for label, code in attempts.items():
        t, e = call("py_run", code=code + "\nprint('RAN-THROUGH')")
        c.expect("python %s blocked" % label, "RAN-THROUGH" not in t and "uid=" not in t and
                 ("SandboxViolation" in t or "not allowed" in t), t[-400:])
    t, e = call("py_run", code="import sys\nsys.addaudithook(lambda *a: None)\n"
                               "import os\nos.system('id')\nprint('RAN-THROUGH')")
    c.expect("a second audit hook does not lift the first", "RAN-THROUGH" not in t, t[-300:])


def main():
    c = Checks()
    if not image_ready():
        print("cannot run: %s" % jsw.image_problems())
        return 1
    sb = Sandbox("t1")
    srv = sb.server(max_calls=1000)
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
