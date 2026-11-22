"""End-to-end runs of the launcher on benign PE files."""

import hashlib
import json
import os
import shutil
import stat
import time

import pebuild
import pytest
from conftest import find_pip_stub, run_rebox

from rebox import cli


def _assert_private_bins(out):
    for p in (out / "dumps").glob("*"):
        mode = stat.S_IMODE(p.stat().st_mode)
        assert p.suffix == ".bin", p
        assert mode == 0o600, (p, oct(mode))
    for p in out.rglob("*"):
        if p.is_file():
            assert not p.stat().st_mode & 0o111, f"executable file in output: {p}"


def test_pip_launcher_stub(tmp_path):
    stub = find_pip_stub()
    if stub is None:
        pytest.skip("no pip distlib launcher stub on this machine")
    out = tmp_path / "out"
    rc, s, text, err = run_rebox("run", stub, "--out", out, "--timeout", "30")
    assert rc == 0, err
    assert s["ok"] is True
    assert len(text) <= 6000
    assert s["sample"]["sha256"] == hashlib.sha256(stub.read_bytes()).hexdigest()
    assert s["sample"]["pe_type"] == "exe" and s["sample"]["arch"] in ("x86", "x64")
    assert s["emulation"]["runs"]["total"] >= 1
    assert s["api"]["calls"] > 50
    assert s["emulation"]["sandbox"].startswith("sandbox-exec")
    assert (out / "report.json").is_file() and (out / "summary.json").is_file()
    assert json.loads((out / "run.json").read_text())["sandbox"]["verified"] is True
    _assert_private_bins(out)


def test_synthetic_behaviour_pe(tmp_path, behave_exe):
    out = tmp_path / "out"
    rc, s, text, err = run_rebox("run", behave_exe, "--out", out, "--timeout", "30")
    assert rc == 0, err
    E = pebuild.EXPECT
    ind = s["indicators"]
    assert E["host"] in ind["hosts"]["top"]
    assert E["url"] in ind["urls"]["top"]
    assert E["ip"] in ind["ips"]["top"]
    assert f"tcp connect {E['ip']}:{E['port']}" in ind["conns"]["top"]
    assert E["mutex"] in ind["mutexes"]["top"]
    assert E["cmd"] in ind["cmdlines"]["top"]
    assert E["file"] in ind["files_written"]["top"]
    payloads = {p["kind"]: p for p in s["payloads"]["top"]}
    dyn = out / payloads["dyncode"]["file"]
    assert dyn.read_bytes()[:2] == b"\x6a\x01"  # the stub copied into the RWX buffer
    dropped = out / payloads["dropped"]["file"]
    assert dropped.read_bytes() == E["file_content"]
    assert payloads["dropped"]["sha256"] == hashlib.sha256(E["file_content"]).hexdigest()
    _assert_private_bins(out)


def test_args_reach_the_emulated_process(tmp_path, behave_exe):
    out = tmp_path / "out"
    rc, s, _, err = run_rebox("run", behave_exe, "--out", out, "--arg", "hello world", "--arg=-x")
    assert rc == 0, err
    expected = 'C:\\Windows\\system32\\behave.exe "hello world" -x'
    assert json.loads((out / "run.json").read_text())["command_line"] == expected
    report = json.loads((out / "report.json").read_text())
    shown = [a["display"] for ev in report["entry_points"][0]["events"]
             if ev.get("api_name") == "kernel32.OutputDebugStringA" for a in ev["args"]]
    assert expected in shown  # what GetCommandLineA returned inside the emulator


def test_budget_respected_end_to_end(tmp_path, behave_exe):
    out = tmp_path / "out"
    rc, s, text, _ = run_rebox("run", behave_exe, "--out", out, "--max-chars", "1800")
    assert rc == 0
    assert len(text) <= 1800
    assert s["truncated"]["cut"]
    assert s["raw_report"] == "report.json" and (out / "report.json").is_file()
    rc, s2, text2, _ = run_rebox("summarize", out, "--max-chars", "6000")
    assert rc == 0 and s2["truncated"] is None


def test_timeout_is_a_stop_reason_not_a_failure(tmp_path):
    idata, iat, n = pebuild._imports()
    spin = tmp_path / "spin.exe"
    spin.write_bytes(pebuild._assemble(b"\xeb\xfe", b"\0" * 4, idata, iat, n))  # jmp $
    t0 = time.monotonic()
    rc, s, _, err = run_rebox("run", spin, "--out", tmp_path / "out", "--timeout", "3")
    assert rc == 0, err
    assert s["emulation"]["runs"]["top"][0]["stop"] == "timeout"
    assert time.monotonic() - t0 < 60


def test_not_a_pe(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"ZZZZ" + os.urandom(4092))
    rc, s, _, _ = run_rebox("run", junk, "--out", tmp_path / "out")
    assert rc == cli.EXIT_UNSUPPORTED
    assert s["ok"] is False and "not a PE" in s["error"]


def test_usage_errors_are_json(tmp_path):
    rc, s, _, _ = run_rebox("run")
    assert rc == cli.EXIT_USAGE and s["ok"] is False
    rc, s, _, _ = run_rebox("run", tmp_path / "missing.exe")
    assert rc == cli.EXIT_USAGE and "not found" in s["error"]
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "x").write_text("x")
    rc, s, _, _ = run_rebox("run", __file__, "--out", busy)
    assert rc == cli.EXIT_USAGE and "not empty" in s["error"]


def test_default_out_dir_naming(behave_exe):
    rc, s, _, _ = run_rebox("run", behave_exe, "--timeout", "20")
    try:
        assert rc == 0
        out = s["out_dir"]
        assert os.path.dirname(out) == str(cli.DEFAULT_RUNS_DIR)
        sha = hashlib.sha256(behave_exe.read_bytes()).hexdigest()
        assert os.path.basename(out).startswith(sha[:12] + "-")
    finally:
        if s.get("out_dir", "").startswith(str(cli.DEFAULT_RUNS_DIR) + "/"):
            shutil.rmtree(s["out_dir"])


def test_elf_is_refused_clearly(tmp_path):
    elf = tmp_path / "hello.elf"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    rc, s, _, _ = run_rebox("run", elf, "--out", tmp_path / "out")
    assert rc == cli.EXIT_UNSUPPORTED
    assert "ELF samples are not supported" in s["error"]
