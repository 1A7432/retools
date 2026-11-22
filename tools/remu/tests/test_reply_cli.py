"""Budget/truncation reporting and the command-line launcher."""

import json
import os
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMU = os.path.join(ROOT, "remu")


def test_budget_cuts_are_reported(x86img):
    n = 4096
    enc = bytes((i * 7) & 0xFF for i in range(n))
    req = {"func": x86img["xor_dec"], "args": [{"bytes": enc.hex()}, {"out": n, "name": "out"}, n, 1]}
    full = x86img.call(dict(req, max_chars=100000))
    assert "truncated" not in full
    # a big buffer is previewed (256 bytes) and the preview says so
    assert full["buffers"]["top"][0]["shown"] == "+0x0..+0xff of 0x1000 bytes"
    assert len(json.dumps(full)) > 1000
    for budget in (900, 400):
        r = x86img.call(dict(req, max_chars=budget))
        size = len(json.dumps(r, ensure_ascii=False, separators=(",", ":")))
        assert size <= budget, (budget, size)
        assert "truncated" in r and "buffers" in r["truncated"]
        assert r["stop"]["reason"] == "returned"
        assert "...[+" in json.dumps(r)


def test_lists_say_what_is_not_shown(x86img):
    r = x86img.call({"func": x86img["calls_leaf"], "trace": 1})
    assert r["trace"]["total"] == 2 and len(r["trace"]["top"]) == 1
    assert r["trace"]["more"] == "1 of 2 shown"


def test_fields_filter(x86img):
    r = x86img.call({"func": x86img["heap_dec"], "args": [{"str": "x"}], "fields": ["ret"]})
    assert set(r) == {"stop", "ret"}


def _run(args, stdin, env=None):
    return subprocess.run([REMU] + args, input=stdin, capture_output=True, text=True,
                          env={} if env is None else env, timeout=60)


def test_launcher_with_empty_environment(x86img):
    req = json.dumps({"func": x86img["add3"], "args": [1, 2, 3]})
    p = _run(["call", "--image", x86img.path], req)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert out["ret"] == "0xe"
    assert p.stdout.count("\n") == 1     # exactly one JSON object


def test_launcher_errors_are_json(x86img):
    p = _run(["call", "--image", x86img.path], "{not json")
    assert p.returncode == 0 and "error" in json.loads(p.stdout)
    p = _run(["call", "--image", "/nonexistent"], "{}")
    assert p.returncode == 0 and "error" in json.loads(p.stdout)


def test_unsupported_arch_rejected(tmp_path):
    from conftest import write_image
    path = write_image(str(tmp_path / "mips"), "mipsl", 32, "elf", [], {}, {})
    p = _run(["call", "--image", path], "{}")
    out = json.loads(p.stdout)
    assert "unsupported architecture" in out["error"] and out["hint"]


def test_info_and_stubs_commands(x86img):
    p = _run(["info", "--image", x86img.path], "")
    assert p.returncode == 0 and "emulation layout" in p.stdout and "scratch" in p.stdout
    p = _run(["stubs"], "")
    assert "MultiByteToWideChar" in p.stdout


def test_startup_is_fast(x86img):
    req = json.dumps({"func": x86img["add3"], "args": [1, 2, 3]})
    _run(["call", "--image", x86img.path], req)      # warm the file cache
    t0 = time.monotonic()
    _run(["call", "--image", x86img.path], req)
    assert time.monotonic() - t0 < 1.0
