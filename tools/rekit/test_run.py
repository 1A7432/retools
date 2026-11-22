#!/usr/bin/env python3
"""Tests for _run.py outside IDA. Run: python3 test_run.py

Unit tests drive run_file() with a path and an expected hash, against a fake
`rebox` (a small script that records its argv and writes a canned run
directory). The end-to-end tests use the real rebox on a harmless test program
(rebox/tests/elfsrc/stdin.c) cross-compiled with zig; they are skipped with a
message when zig or rebox's ELF backend is missing. Test binaries are only
ever emulated, never executed natively.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _run  # noqa: E402

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STDIN_C = os.path.join(TOOLS, "rebox", "tests", "elfsrc", "stdin.c")
ZIG = shutil.which("zig") or "/opt/homebrew/bin/zig"

FAKE = r'''#!%(py)s
import json, os, sys
argv = sys.argv[1:]
spec = json.load(open(%(spec)r))
rec = {"argv": argv}
if "--stdin-file" in argv:
    rec["stdin"] = open(argv[argv.index("--stdin-file") + 1], "rb").read().hex()
rec["sample_sha"] = __import__("hashlib").sha256(open(argv[1], "rb").read()).hexdigest()
json.dump(rec, open(%(log)r, "w"))
out = spec["out_dir"]
os.makedirs(out, exist_ok=True)
for name, hexdata in spec.get("files", {}).items():
    open(os.path.join(out, name), "wb").write(bytes.fromhex(hexdata))
if "report" in spec:
    json.dump(spec["report"], open(os.path.join(out, "report.json"), "w"))
summary = spec["summary"]
if summary.get("ok"):
    summary.setdefault("out_dir", out)
if summary.get("sample", {}).get("sha256") == "SAMPLE":
    summary["sample"]["sha256"] = rec["sample_sha"]
print(json.dumps(summary))
sys.exit(spec.get("exit", 0))
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unescape(s):
    """Inverse of _run._escape, to prove it is exact."""
    out, i = bytearray(), 0
    while i < len(s):
        if s[i] == "\\":
            c = s[i + 1]
            if c == "x":
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            out += {"\\": b"\\", "n": b"\n", "r": b"\r", "t": b"\t"}[c]
            i += 2
        else:
            out += s[i].encode()
            i += 1
    return bytes(out)


def elf_summary(stop="exited", exit_code=0, **extra):
    s = {"schema": "rebox.summary/1", "ok": True,
         "sample": {"name": "prog", "sha256": "SAMPLE", "format": "elf"},
         "emulation": {"stop": stop, "stop_detail": "exit_group(%d)" % exit_code,
                       "runs": {"total": 1, "top": [{"pid": 2148, "type": "main", "stop": stop,
                                                     "exit_code": exit_code, "pc": "0x401000"}]},
                       "errors": {"total": 0, "top": []}},
         "api": {"kind": "syscalls", "calls": 12,
                 "histogram": {"total": 3, "top": [["write", 5], ["read", 4], ["exit_group", 1]]},
                 "unsupported": {"total": 0, "top": []}},
         "indicators": {"files_written": {"total": 1, "top": ["/tmp/x"]}, "empty": []},
         "payloads": {"total": 0, "top": []}, "strings": {}, "truncated": None}
    s.update(extra)
    return s


class Fake:
    def __init__(self, root, spec):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.spec_path = os.path.join(root, "spec.json")
        self.log = os.path.join(root, "log.json")
        self.path = os.path.join(root, "rebox")
        spec.setdefault("out_dir", os.path.join(root, "out"))
        with open(self.spec_path, "w") as fh:
            json.dump(spec, fh)
        with open(self.path, "w") as fh:
            fh.write(FAKE % {"py": sys.executable, "spec": self.spec_path, "log": self.log})
        os.chmod(self.path, 0o700)

    def record(self):
        with open(self.log) as fh:
            return json.load(fh)


def run():
    bad = []

    def expect(label, cond):
        if not cond:
            bad.append(label)

    root = tempfile.mkdtemp(prefix="test-run-")
    # rebox runs started here must not land in the checkout's tmp/rebox-runs
    os.environ["REBOX_RUNS"] = os.path.join(root, "rebox-runs")
    sample = os.path.join(root, "prog")
    blob = b"\x7fELF fake sample bytes"
    with open(sample, "wb") as fh:
        fh.write(blob)
    good = sha(blob)

    # ---- refusals before anything runs -------------------------------------------------------
    calls = []
    never = os.path.join(root, "never")
    with open(never, "w") as fh:
        fh.write("#!/bin/sh\ntouch %s/ran\n" % root)
    os.chmod(never, 0o700)
    r = _run.run_file(sample, "0" * 64, rebox=never)
    expect("wrong hash refused", "error" in r and "sha256" in r["error"] and "never emulated" in r["hint"])
    r = _run.run_file(os.path.join(root, "missing"), good, rebox=never)
    expect("missing file refused", "error" in r and "missing" in r["error"])
    r = _run.run_file(sample, "", rebox=never)
    expect("no recorded hash refused", "error" in r and "no recorded SHA-256" in r["error"])
    r = _run.run_file([os.path.join(root, "missing"), sample], good, args="hello", rebox=never)
    expect("string args refused", "error" in r and "list" in r["error"])
    r = _run.run_file(sample, good, args=[1], rebox=never)
    expect("non-string arg refused", "error" in r and "string" in r["error"])
    r = _run.run_file(sample, good, stdin={"bytes": "zz"}, rebox=never)
    expect("bad hex refused", "error" in r and "hex" in r["error"])
    r = _run.run_file(sample, good, stdin=12, rebox=never)
    expect("bad stdin type refused", "error" in r)
    r = _run.run_file(sample, good, env={"A=B": "x"}, rebox=never)
    expect("bad env name refused", "error" in r)
    r = _run.run_file(sample, good, env=["A=B"], rebox=never)
    expect("env list refused", "error" in r)
    r = _run.run_file(sample, good, timeout=0, rebox=never)
    expect("zero timeout refused", "error" in r)
    expect("nothing ran for refusals", not os.path.exists(os.path.join(root, "ran")) and not calls)

    # ---- argv, stdin and env reach rebox unchanged, no shell -------------------------------------
    fk = Fake(os.path.join(root, "f1"), {
        "summary": elf_summary(),
        "report": {"stdout": {"bytes": 6}, "stderr": {"bytes": 0},
                   "stdin": {"bytes": 4, "consumed": 4, "reads": 2}},
        "files": {"stdout.txt": b"hello\n".hex(), "stderr.txt": ""}})
    tricky = ["a b", "$(touch %s/pwned)" % root, "; rm -rf /", "-x", "--timeout=1", "", "naïve"]
    r = _run.run_file([os.path.join(root, "missing"), sample], good, args=tricky,
                      stdin={"bytes": "00 ff 0a 41"}, env={"K": "v w", "E": ""}, timeout=999,
                      rebox=fk.path)
    rec = fk.record()
    argv = rec["argv"]
    expect("runs rebox run", argv[0] == "run")
    expect("sample is a verified copy", rec["sample_sha"] == good and argv[1] != sample
           and os.path.basename(argv[1]) == "prog")
    expect("temp copy removed", not os.path.exists(argv[1]))
    expect("args passed verbatim as --arg=", [a[6:] for a in argv if a.startswith("--arg=")] == tricky)
    expect("no shell expansion", not os.path.exists(os.path.join(root, "pwned")))
    expect("env passed", "--env=K=v w" in argv and "--env=E=" in argv)
    expect("stdin bytes exact", rec["stdin"] == "00ff0a41")
    expect("timeout capped", argv[argv.index("--timeout") + 1] == str(_run.MAX_TIMEOUT))
    expect("cap reported", "timeout capped at %ds" % _run.MAX_TIMEOUT in r.get("notes", []))
    expect("never live", "live" not in argv)
    expect("stdout first", list(r)[0] == "stdout" and r["stdout"] == "hello\n")
    expect("stop", r["stop"] == {"reason": "exited", "exit_code": 0})
    expect("stdin line", r["stdin"] == "given 4 bytes, the program read 4")
    expect("behaviour", r["behaviour"]["files_written"] == ["/tmp/x"]
           and r["behaviour"]["syscalls"].startswith("12 total; top: write 5"))
    expect("report path", r["report"] == os.path.join(root, "f1", "out"))
    r = _run.run_file(sample, good, stdin="hé\n", rebox=fk.path)
    expect("text stdin is utf-8", fk.record()["stdin"] == "hé\n".encode().hex())
    _run.run_file(sample, good, rebox=fk.path)
    expect("no stdin flag without stdin", "--stdin-file" not in fk.record()["argv"])

    # ---- rebox failures and a hash mismatch inside rebox -------------------------------------------
    fk = Fake(os.path.join(root, "f2"), {"summary": {"ok": False, "exit": 5, "error": "not a PE or ELF",
                                                     "out_dir": "/x"}, "exit": 5})
    r = _run.run_file(sample, good, rebox=fk.path)
    expect("rebox error relayed", r.get("error") == "rebox: not a PE or ELF" and "statically" in r["hint"]
           and r["report"] == "/x")
    s = elf_summary()
    s["sample"]["sha256"] = "1" * 64
    fk = Fake(os.path.join(root, "f3"), {"summary": s, "report": {}})
    r = _run.run_file(sample, good, rebox=fk.path)
    expect("emulated-hash mismatch refused", "error" in r and "not the database's" in r["error"])
    r = _run.run_file(sample, good, rebox=os.path.join(root, "no-rebox"))
    expect("missing rebox", "error" in r and "not installed" in r["error"])

    # ---- PE: output not captured, stdin refused by rebox ---------------------------------------------
    pe = {"schema": "rebox.summary/1", "ok": True, "sample": {"name": "a.exe", "sha256": "SAMPLE"},
          "emulation": {"runs": {"total": 1, "top": [{"type": "module_entry", "start": "0x401000",
                                                       "stop": "returned", "ret": "0x0"}]},
                        "errors": {"total": 0, "top": []}},
          "api": {"calls": 3, "histogram": {"total": 1, "top": [["msvcrt.printf", 1]]}},
          "indicators": {"empty": []}, "payloads": {"total": 0, "top": []},
          "strings": {"api_args": {"total": 1, "top": ["hello %s"]}}}
    fk = Fake(os.path.join(root, "f4"), {"summary": pe, "report": {}})
    r = _run.run_file(sample, good, rebox=fk.path)
    expect("PE stop", r["stop"] == {"reason": "returned", "ret": "0x0"})
    expect("PE stdout None + note", r["stdout"] is None and any("PE" in n for n in r["notes"]))
    expect("PE api_args", r["behaviour"]["api_args"] == ["hello %s"]
           and r["behaviour"]["api_calls"].startswith("3 total"))

    # ---- output rendering -------------------------------------------------------------------------
    raw = b"\x00\x01\xffAB\\C\n\t\r\x7f"
    v = _run._show(raw, 2000, "/o/stdout.txt", len(raw))
    expect("binary as hex+escaped", v["hex"] == raw.hex() and unescape(v["escaped"]) == raw)
    v = _run._show(b"line one\nline two\n", 2000, "/o/stdout.txt", 18)
    expect("text exact with trailing newline", v == "line one\nline two\n")
    v = _run._show("中文 ok\n".encode(), 2000, "/o/stdout.txt", None)
    expect("utf-8 text kept", v == "中文 ok\n")
    long_text = "".join("line %04d\n" % i for i in range(2000))
    v = _run._show(long_text.encode(), 600, "/o/stdout.txt", len(long_text))
    expect("long text head/tail", long_text.startswith(v["head"]) and long_text.endswith(v["tail"])
           and "of 20000 chars" in v["cut"] and "/o/stdout.txt" in v["cut"]
           and _run._size(v) <= 800)
    long_bin = bytes(range(256)) * 40
    v = _run._show(long_bin, 600, "/o/stdout.txt", len(long_bin))
    expect("long binary head/tail exact", long_bin.startswith(bytes.fromhex(v["hex_head"]))
           and long_bin.endswith(bytes.fromhex(v["hex_tail"]))
           and unescape(v["escaped_head"]) == bytes.fromhex(v["hex_head"])
           and "of 10240 bytes" in v["cut"] and _run._size(v) <= 800)
    v = _run._show(b"abc", 2000, "/o/stdout.txt", 5000000)
    expect("rebox cap reported", v["text"] == "abc" and "wrote 5000000 bytes" in v["cut"])

    # interleaving and budget over a canned run with long output on both streams
    out_b = long_text.encode()
    err_b = b"warning: x\n" * 300
    many = elf_summary(stop="invalid_read")
    many["emulation"]["runs"]["top"][0].pop("exit_code")
    many["indicators"]["conns"] = {"total": 40, "top": ["tcp connect 198.51.100.%d:80" % i for i in range(40)]}
    fk = Fake(os.path.join(root, "f5"), {
        "summary": many,
        "report": {"stdout": {"bytes": len(out_b)}, "stderr": {"bytes": len(err_b)},
                   "output_order": {"runs": [["stdout", 10], ["stderr", len(err_b)], ["stdout", len(out_b) - 10]],
                                    "complete": True}},
        "files": {"stdout.txt": out_b.hex(), "stderr.txt": err_b.hex()}})
    for budget in (800, 1500, 3000, 6000):
        r = _run.run_file(sample, good, max_chars=budget, rebox=fk.path)
        size = _run._size(r)
        expect("budget %d (got %d)" % (budget, size), size <= budget)
        expect("budget %d keeps stop and report" % budget, "stop" in r and "report" in r)
    r = _run.run_file(sample, good, max_chars=3000, rebox=fk.path)
    expect("order shown", r["order"] == "stdout 10, stderr %d, stdout %d" % (len(err_b), len(out_b) - 10))
    expect("fault stop has pc", r["stop"]["reason"] == "invalid_read" and r["stop"]["pc"] == "0x401000")
    expect("stdout cut is head/tail", "head" in r["stdout"] and "of 20000 chars" in r["stdout"]["cut"])

    # ---- end to end with the real rebox (emulation only) --------------------------------------------
    e2e = os.path.join(root, "e2e")
    os.makedirs(e2e)
    elf = os.path.join(e2e, "stdin-x86_64")
    skip = None
    if not (os.path.isfile(ZIG) and os.access(ZIG, os.X_OK)):
        skip = "zig not found"
    elif not os.path.isdir(os.path.join(TOOLS, "rebox", ".venv-elf")):
        skip = "rebox ELF backend not set up"
    if skip is None:
        subprocess.run([ZIG, "cc", "-target", "x86_64-linux-musl", "-static", "-O1", "-g0", "-s",
                        "-o", elf, STDIN_C], check=True, capture_output=True, timeout=600)
        os.chmod(elf, 0o600)  # never executable on the host
        with open(elf, "rb") as fh:
            h = sha(fh.read())
        r = _run.run_file(elf, h, stdin="benchmark\n")
        expect("e2e stdout exact (%r)" % r.get("stdout"), r.get("stdout") == "prompt: line=[benchmark]\neof")
        expect("e2e stderr exact", r.get("stderr") == "err: got 9\n")
        expect("e2e order", r.get("order") == "stdout 8, stderr 11, stdout 20")
        expect("e2e stop", r.get("stop") == {"reason": "exited", "exit_code": 0})
        expect("e2e stdin", r.get("stdin") == "given 10 bytes, the program read 10")
        data = bytes([0, 1, 0xFF, 10, 0x5C]) + b"ABCDEFGHIJ"
        r = _run.run_file(elf, h, args=["raw"], stdin={"bytes": data.hex()})
        expect("e2e raw bytes exact", isinstance(r.get("stdout"), dict) and r["stdout"]["hex"] == data.hex())
        expect("e2e raw eof", r.get("stderr") == "raw total=15 last=0\n"
               and r["stop"].get("exit_code") == 3)
        r = _run.run_file(elf, h)
        expect("e2e no stdin hint", r.get("stdout") == "prompt: no input\n"
               and "end-of-file" in r.get("stdin", ""))
    else:
        print("skipped end-to-end tests: %s" % skip)

    shutil.rmtree(root, ignore_errors=True)
    if bad:
        print("FAIL (%d):" % len(bad))
        for b in bad:
            print("  " + b)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(run())
