"""rekit/_calc.py, the bridge IDA's Python uses (standard library only)."""

import importlib.util
import os
import stat
import sys


from conftest import ROOT

BRIDGE = os.path.join(os.path.dirname(ROOT), "rekit", "_calc.py")


def load(env_tool=None):
    if env_tool:
        os.environ["REKIT_RECALC"] = env_tool
    else:
        os.environ.pop("REKIT_RECALC", None)
    spec = importlib.util.spec_from_file_location("rekit_calc_under_test", BRIDGE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    os.environ.pop("REKIT_RECALC", None)
    return mod


def fake(tmp_path, body):
    p = tmp_path / "fake-recalc"
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_bridge_uses_only_the_standard_library():
    src = open(BRIDGE).read()
    for line in src.splitlines():
        if line.startswith(("import ", "from ")) and "__future__" not in line:
            mod = line.split()[1].split(".")[0]
            assert mod in sys.stdlib_module_names, line


def test_run_returns_reply():
    calc = load()
    assert calc.RECALC == os.path.join(ROOT, "recalc")
    r = calc.run("pow(7, rotl(532, 4, 32) ^ 5, 1000003)")
    assert r["result"] == "0x8e42a = 582698"
    r = calc.run("x = undefined_name")
    assert set(r) >= {"error", "hint", "line"}
    r = calc.run("x = list(range(5000))", max_chars=400)
    assert "truncated" in r


def test_bridge_failures_become_error_dicts(tmp_path):
    calc = load(str(tmp_path / "missing"))
    r = calc.run("1")
    assert "not installed" in r["error"] and "hint" in r
    calc = load(fake(tmp_path, "echo not json"))
    assert "recalc failed" in calc.run("1")["error"]
    calc = load(fake(tmp_path, "kill -XCPU $$"))
    assert "cpu_time" in calc.run("1")["error"]
    calc = load(fake(tmp_path, "sleep 30"))
    calc.GRACE = 1
    r = calc.run("1", timeout=1)
    assert "limit 'time' exceeded" in r["error"]
    calc = load()
    assert "code must be a string" in calc.run(5)["error"]
    assert "code_length" in calc.run("x" * 30000)["error"]
