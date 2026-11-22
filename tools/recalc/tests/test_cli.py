"""The launcher: empty environment, one JSON line out, function listing."""

import json
import time

from conftest import cli, RECALC
import subprocess


def test_launcher_one_line_and_fields():
    p = cli({"code": "x = 2\nx * 21", "id": "q1"})
    assert p.returncode == 0, p.stderr
    assert p.stdout.count("\n") == 1
    r = json.loads(p.stdout)
    assert r["id"] == "q1" and r["result"] == "0x2a = 42" and r["vars"] == {"x": 2}
    assert isinstance(r["steps"], int) and isinstance(r["ms"], int)


def test_launcher_errors_are_json():
    for payload in ("", "null", "[]", '{"code": "1 +"}'):
        p = cli(payload, raw=True)
        assert p.returncode == 0
        assert "error" in json.loads(p.stdout)
    r = json.loads(cli('{"code": "1 +"}', raw=True).stdout)
    assert r["error"].startswith("syntax error") and r["line"] == 1


def test_timeout_and_budget_are_clamped():
    t = time.monotonic()
    r = json.loads(cli({"code": "while 1:\n    x = [0] * 1000", "timeout": 1}).stdout)
    assert "limit" in r["error"]
    assert time.monotonic() - t < 8
    r = json.loads(cli({"code": "1", "max_chars": 1}).stdout)
    assert r["result"] == 1


def test_functions_listing():
    p = subprocess.run([RECALC, "functions", "--json"], capture_output=True, text=True, env={}, timeout=30)
    data = json.loads(p.stdout)
    names = {f["name"] for g in data["functions"].values() for f in g}
    for n in ("rotl", "sha256", "sm3", "hmac", "crc", "aes_enc", "sm4_dec", "ctr", "ec_mul", "sm2_verify",
              "b64dec", "u32le", "p64be", "xor", "unhex", "pow", "inverse"):
        assert n in names
    assert "bytes.hex" in data["methods"] and "int.from_bytes" in data["statics"]
