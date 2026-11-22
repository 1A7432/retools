"""ELF path (Qiling backend): end-to-end runs of harmless test programs built with zig.

Tests that need the Qiling environment, the rootfs or zig skip with the reason.
"""

import hashlib
import json
import socket
import stat
import threading
import time

import elfbuild
import pytest
from conftest import run_rebox

from rebox import cli, elfnet, elfsetup, sandbox

E = elfbuild.EXPECT

needs_venv = pytest.mark.skipif(not elfsetup.venv_ready(),
                                reason=f"Qiling environment missing: run `{elfsetup.SETUP_HINT}`")
needs_zig = pytest.mark.skipif(not elfbuild.zig_available(), reason="zig not found (needed to build test ELFs)")
needs_sandbox = pytest.mark.skipif(not sandbox.sandbox_available(), reason="sandbox-exec missing")


@pytest.fixture(scope="session")
def elf_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("elfbin")


def _private_outputs(out):
    for p in out.rglob("*"):
        if p.is_symlink():
            continue
        if p.is_file():
            assert not p.stat().st_mode & 0o111, f"executable file in output: {p}"
    for p in (out / "dumps").glob("*"):
        assert p.suffix == ".bin" and stat.S_IMODE(p.stat().st_mode) == 0o600, p


def _check_behaviour(s, out, dynamic=False):
    assert s["ok"] is True
    em = s["emulation"]
    assert em["engine"].startswith("qiling ")
    assert em["sandbox"].startswith("sandbox-exec")
    assert em["stop"] == "exited" and em["stop_detail"] == "exit_group(7)"
    runs = em["runs"]["top"]
    main = runs[0]
    assert main["type"] == "main" and main["exit_code"] == 7 and main["name"] == E["proc_name"]
    child = next(r for r in runs if r["type"] == "fork")
    assert child["stop"] == "execve" and child["detail"] == E["cmd"]
    ind = s["indicators"]
    assert E["host"] in ind["hosts"]["top"]
    assert ind["ips"]["top"] == [E["c2"]]  # the canned DNS answer is not an indicator
    assert elfnet.CANNED_IP not in ind["ips"]["top"]
    assert f"tcp connect {E['c2']}:{E['port']} sent=16B" in ind["conns"]["top"]
    assert E["cmd"] in ind["cmdlines"]["top"]
    assert E["drop"] in ind["files_written"]["top"]
    assert "/tmp/.rebox-after-fork.txt" in ind["files_written"]["top"]  # the parent resumed after the child
    assert "/tmp/.rebox-gone.txt" in ind["files_deleted"]["top"]
    assert f"{E['drop']} 0755" in ind["chmod"]["top"]
    assert E["listen"] in ind["listening"]["top"]
    assert E["proc_name"] in ind["process_names"]["top"]
    drop = next(p for p in s["payloads"]["top"] if p.get("emu_path") == E["drop"])
    assert drop["kind"] == "dropped"
    assert (out / drop["file"]).read_bytes() == E["drop_content"]
    assert drop["sha256"] == hashlib.sha256(E["drop_content"]).hexdigest()
    output = s["strings"]["output"]["top"]
    assert "connect=0" in output and "sent=16 recv=0" in output and "accept=-1 errno=11" in output
    if not dynamic:  # glibc cannot resolve without libnss_dns; static musl does real DNS over the fake net
        assert E["url"] in ind["urls"]["top"]
        assert f"resolved {E['host']} -> {elfnet.CANNED_IP}" in output
        assert any(c.startswith(f"tcp connect {elfnet.CANNED_IP}:80 ({E['host']}") for c in ind["conns"]["top"])
    meta = json.loads((out / "run.json").read_text())
    assert meta["sandbox"]["verified"] is True
    assert (out / "report.json").is_file() and (out / "syscalls.log").is_file()
    _private_outputs(out)


@needs_venv
@needs_zig
@needs_sandbox
@pytest.mark.parametrize("arch", ["x86-64", "arm64", "x86"])
def test_static_behaviour(tmp_path, elf_dir, arch):
    elf = elfbuild.build(elf_dir, arch)
    out = tmp_path / "out"
    rc, s, text, err = run_rebox("run", elf, "--out", out, "--timeout", "60")
    assert rc == 0, err
    assert len(text) <= 6000
    assert s["sample"]["arch"] == arch and s["sample"]["linkage"] == "static"
    _check_behaviour(s, out)


@needs_venv
@needs_zig
@needs_sandbox
@pytest.mark.parametrize("arch", ["x86-64", "arm64"])
def test_dynamic_behaviour(tmp_path, elf_dir, arch):
    if elfsetup.rootfs_dir(arch) is None:
        pytest.skip(f"{arch} Linux rootfs missing: run `{elfsetup.SETUP_HINT}`")
    elf = elfbuild.build(elf_dir, arch, dynamic=True)
    out = tmp_path / "out"
    rc, s, text, err = run_rebox("run", elf, "--out", out, "--timeout", "60")
    assert rc == 0, err
    assert s["sample"]["linkage"] == "dynamic" and s["sample"]["interp"]
    assert "/lib/libc.so.6" in s["indicators"]["modules_loaded"]["top"]
    _check_behaviour(s, out, dynamic=True)
    # the name glibc tried to resolve is recorded by the libc resolver hook
    report = json.loads((out / "report.json").read_text())
    assert any(x["name"] == E["host"] for x in report["network"]["libc_lookups"])


@needs_venv
@needs_zig
@needs_sandbox
def test_faked_connect_never_reaches_the_host(tmp_path, elf_dir):
    """A real local listener: the sample's connect is reported as succeeded, the listener sees nothing."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(0.2)
    port = srv.getsockname()[1]
    accepted = []
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                accepted.append(c)
            except OSError:
                pass

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    # control: the listener is reachable from an ordinary process
    probe = socket.create_connection(("127.0.0.1", port), timeout=3)
    probe.close()
    time.sleep(0.3)
    n_control = len(accepted)
    assert n_control == 1

    elf = elfbuild.build(elf_dir, "x86-64")
    out = tmp_path / "out"
    try:
        rc, s, _, err = run_rebox("run", elf, "--out", out, "--arg", "connect", "--arg", "127.0.0.1",
                                  "--arg", str(port))
        time.sleep(0.5)
    finally:
        stop.set()
        th.join(2)
        srv.close()
    assert rc == 0, err
    meta = json.loads((out / "run.json").read_text())
    assert meta["sandbox"]["verified"] is True  # the run happened under the active sandbox
    assert s["emulation"]["stop_detail"] == "exit_group(0)"
    assert "connect=0 send=15" in s["strings"]["output"]["top"]  # the program saw success
    assert f"tcp connect 127.0.0.1:{port} sent=15B" in s["indicators"]["conns"]["top"]
    assert len(accepted) == n_control, "the emulated connect reached the host listener"
    log = (out / "syscalls.log").read_text()
    assert "connect(3," in log and ") = 0" in log.split("connect(3,", 1)[1].splitlines()[0]


@needs_venv
@needs_zig
@needs_sandbox
@pytest.mark.parametrize("arch", ["x86-64", "arm64", "x86"])
def test_threads_run_cooperatively(tmp_path, elf_dir, arch):
    elf = elfbuild.build(elf_dir, arch)
    out = tmp_path / "out"
    rc, s, _, err = run_rebox("run", elf, "--out", out, "--arg", "thread", "--timeout", "30")
    assert rc == 0, err
    runs = s["emulation"]["runs"]["top"]
    assert [r["type"] for r in runs] == ["main", "thread"] and runs[1]["stop"] == "exited"
    assert s["emulation"]["stop_detail"] == "exit_group(3)"
    written = s["indicators"]["files_written"]["top"]
    assert "/tmp/.rebox-thread.txt" in written and "/tmp/.rebox-after-join.txt" in written


@needs_venv
@needs_zig
@needs_sandbox
def test_syscall_loop_is_bounded(tmp_path, elf_dir):
    elf = elfbuild.build(elf_dir, "x86-64")
    out = tmp_path / "out"
    rc, s, _, err = run_rebox("run", elf, "--out", out, "--arg", "loop", "--max-api", "3000")
    assert rc == 0, err
    assert s["emulation"]["stop"] == "max_syscalls"
    assert s["api"]["calls"] == 3001
    assert ["getpid", 2999] in s["api"]["histogram"]["top"] or s["api"]["histogram"]["top"][0][0] == "getpid"
    lines = (out / "syscalls.log").read_text().splitlines()
    assert len(lines) < 50  # identical repeats collapse into one line with a count
    assert any(" x" in ln and "getpid" in ln for ln in lines)


@needs_venv
@needs_zig
@needs_sandbox
def test_cpu_loop_hits_the_timeout(tmp_path, elf_dir):
    elf = elfbuild.build(elf_dir, "arm64")
    t0 = time.monotonic()
    rc, s, _, err = run_rebox("run", elf, "--out", tmp_path / "out", "--arg", "spin", "--timeout", "3")
    assert rc == 0, err
    assert s["emulation"]["stop"] == "timeout"
    assert s["emulation"]["runs"]["top"][0]["stop"] == "timeout"
    assert time.monotonic() - t0 < 40


@needs_venv
@needs_zig
@needs_sandbox
def test_args_env_and_budget(tmp_path, elf_dir):
    elf = elfbuild.build(elf_dir, "x86-64")
    out = tmp_path / "out"
    rc, s, text, err = run_rebox("run", elf, "--out", out, "--arg", "hello world", "--arg=-x",
                                 "--env", "REBOX_TEST=yes", "--max-chars", "1500")
    assert rc == 0, err
    assert len(text) <= 1500
    assert s["truncated"]["cut"] and "raw_report" in s["truncated"]["why"]
    meta = json.loads((out / "run.json").read_text())
    assert meta["command_line"] == f"/tmp/{elf.name} 'hello world' -x"
    out_lines = json.loads((out / "report.json").read_text())["stdout"]["head"].splitlines()
    assert "arg[1]=hello world" in out_lines and "arg[2]=-x" in out_lines and "env REBOX_TEST=yes" in out_lines
    rc, full, text2, _ = run_rebox("summarize", out, "--max-chars", "8000")
    assert rc == 0 and full["truncated"] is None and len(text2) <= 8000
    assert full["sample"]["format"] == "elf"
    for path, t in cli.summary._tlists(s):  # every cut list is a prefix of the full one, totals exact
        f = dict(cli.summary._tlists(full))[path]
        assert t["total"] == f["total"] and t["top"] == f["top"][: len(t["top"])], path


def test_pe_only_flags_are_rejected_for_elf(tmp_path):
    elf = tmp_path / "x.elf"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    for flags, word in ((["--trace-mem"], "PE samples only"), (["--children"], "PE samples only"),
                        (["--no-sandbox"], "refused for ELF"), (["--env", "NOEQUALS"], "KEY=VALUE")):
        rc, s, _, _ = run_rebox("run", elf, "--out", tmp_path / f"out{len(flags)}{word[:3]}", *flags)
        assert rc == cli.EXIT_USAGE and word in s["error"], (flags, s)


def test_env_flag_is_rejected_for_pe(tmp_path, behave_exe):
    rc, s, _, _ = run_rebox("run", behave_exe, "--out", tmp_path / "out", "--env", "A=B")
    assert rc == cli.EXIT_USAGE and "ELF samples only" in s["error"]


def test_missing_venv_names_the_setup_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(elfsetup, "READY", tmp_path / "no-such-marker")
    elf = tmp_path / "x.elf"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    rc = cli.main(["run", str(elf), "--out", str(tmp_path / "out")])
    res = json.loads(capsys.readouterr().out)
    assert rc == cli.EXIT_UNSUPPORTED and "rebox setup-elf" in res["error"]


@needs_venv
@needs_zig
@needs_sandbox
def test_missing_rootfs_names_the_setup_command(tmp_path, elf_dir, monkeypatch, capsys):
    elf = elfbuild.build(elf_dir, "x86-64", dynamic=True)
    monkeypatch.setattr(elfsetup, "ROOTFS", tmp_path / "empty-rootfs")
    rc = cli.main(["run", str(elf), "--out", str(tmp_path / "out")])
    res = json.loads(capsys.readouterr().out)
    assert rc == cli.EXIT_UNSUPPORTED, res
    assert "rebox setup-elf" in res["error"] and "dynamically linked" in res["error"]


@needs_venv
@needs_zig
@needs_sandbox
def test_static_elf_needs_no_rootfs(tmp_path, elf_dir, monkeypatch, capsys):
    elf = elfbuild.build(elf_dir, "x86-64")
    monkeypatch.setattr(elfsetup, "ROOTFS", tmp_path / "empty-rootfs")
    rc = cli.main(["run", str(elf), "--out", str(tmp_path / "out")])
    res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["emulation"]["stop"] == "exited"
    assert json.loads((tmp_path / "out" / "run.json").read_text())["rootfs"]["source"] is None


def test_dns_query_and_reply_roundtrip():
    q = bytes.fromhex("abcd01000001000000000000") + b"\x06beacon\x04test\x07invalid\x00" + b"\x00\x01\x00\x01"
    qid, name, qtype, question = elfnet.parse_dns_query(q)
    assert (qid, name, qtype) == (0xABCD, "beacon.test.invalid", 1)
    reply = elfnet.build_dns_reply(qid, qtype, question, "203.0.113.10")
    assert reply[:2] == q[:2] and reply[6:8] == b"\x00\x01" and reply.endswith(bytes([203, 0, 113, 10]))
    aaaa = elfnet.build_dns_reply(qid, 28, question, "203.0.113.10")
    assert aaaa[6:8] == b"\x00\x00"


def test_http_request_becomes_url():
    req = b"GET /a/b?c=1 HTTP/1.1\r\nHost: dl.test.invalid\r\n\r\n"
    assert elfnet.http_url(req, "203.0.113.10", 80) == ("GET", "http://dl.test.invalid/a/b?c=1")
    assert elfnet.http_url(b"POST /x HTTP/1.0\r\n\r\n", "198.51.100.7", 8080) == ("POST", "http://198.51.100.7:8080/x")
    assert elfnet.http_url(b"\x16\x03\x01binary", "198.51.100.7", 443) is None


# ---- standard input -----------------------------------------------------------------------------

def _outputs(out):
    report = json.loads((out / "report.json").read_text())
    return (out / "stdout.txt").read_bytes(), (out / "stderr.txt").read_bytes(), report


@needs_venv
@needs_zig
@needs_sandbox
@pytest.mark.parametrize("dynamic", [False, True], ids=["static-musl", "dynamic-glibc"])
def test_stdin_text_reaches_fgets_then_eof(tmp_path, elf_dir, dynamic):
    elf = elfbuild.build(elf_dir, "x86-64", dynamic=dynamic, src=elfbuild.STDIN_SRC)
    out = tmp_path / "out"
    rc, s, _, err = run_rebox("run", elf, "--out", out, "--stdin", "benchmark\n")
    assert rc == 0, err
    assert s["emulation"]["stop"] == "exited" and s["emulation"]["runs"]["top"][0]["exit_code"] == 0
    assert s["emulation"]["stdin"] == {"bytes": 10, "consumed": 10, "reads": s["emulation"]["stdin"]["reads"]}
    stdout, stderr, report = _outputs(out)
    # exact bytes: the second fgets saw end-of-file, and "eof" has no trailing newline
    assert stdout == b"prompt: line=[benchmark]\neof"
    assert stderr == b"err: got 9\n"
    assert report["output_order"]["runs"] == [["stdout", 8], ["stderr", 11], ["stdout", 20]]
    assert report["output_order"]["complete"] is True
    assert report["stdout"]["bytes"] == report["stdout"]["saved"] == len(stdout)
    assert report["stdout"]["sha256"] == hashlib.sha256(stdout).hexdigest()
    assert report["stdin"]["consumed"] == 10 and report["stdin"]["eof_reads"] >= 1
    assert (out / "stdin.bin").read_bytes() == b"benchmark\n"
    _private_outputs(out)


@needs_venv
@needs_zig
@needs_sandbox
def test_stdin_hex_bytes_reach_read_exactly(tmp_path, elf_dir):
    elf = elfbuild.build(elf_dir, "arm64", src=elfbuild.STDIN_SRC)
    data = bytes([0, 1, 0xFF, 0x0A, 0x5C]) + b"ABCDEFGHIJ" + bytes(range(0x80, 0x90))
    out = tmp_path / "out"
    rc, s, _, err = run_rebox("run", elf, "--out", out, "--arg", "raw", "--stdin-hex", data.hex(" "))
    assert rc == 0, err
    stdout, stderr, report = _outputs(out)
    assert stdout == data  # 7-byte reads, echoed unchanged, including NUL and non-UTF-8 bytes
    assert stderr == f"raw total={len(data)} last=0\n".encode()
    assert s["emulation"]["runs"]["top"][0]["exit_code"] == 3
    assert report["stdin"]["consumed"] == len(data) and report["stdin"]["reads"] >= 5


@needs_venv
@needs_zig
@needs_sandbox
def test_stdin_file_and_default_empty(tmp_path, elf_dir):
    elf = elfbuild.build(elf_dir, "x86-64", src=elfbuild.STDIN_SRC)
    src = tmp_path / "input.bin"
    src.write_bytes(b"one\ntwo\n")
    rc, s, _, err = run_rebox("run", elf, "--out", tmp_path / "a", "--stdin-file", src)
    assert rc == 0, err
    assert (tmp_path / "a" / "stdout.txt").read_bytes() == b"prompt: line=[one]\nmore=[two\n]"
    # without --stdin*, stdin is empty: the first fgets sees end-of-file
    rc, s, _, err = run_rebox("run", elf, "--out", tmp_path / "b")
    assert rc == 0, err
    stdout, _, report = _outputs(tmp_path / "b")
    assert stdout == b"prompt: no input\n" and s["emulation"]["runs"]["top"][0]["exit_code"] == 1
    assert report["stdin"]["bytes"] == 0 and report["stdin"]["reads"] >= 1
    assert s["emulation"]["stdin"]["bytes"] == 0 and not (tmp_path / "b" / "stdin.bin").exists()


def test_stdin_usage_errors(tmp_path, behave_exe):
    elf = tmp_path / "x.elf"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
    rc, s, _, _ = run_rebox("run", elf, "--out", tmp_path / "o1", "--stdin", "a", "--stdin-hex", "61")
    assert rc == cli.EXIT_USAGE and "not allowed with" in s["error"]
    rc, s, _, _ = run_rebox("run", elf, "--out", tmp_path / "o2", "--stdin-hex", "6g")
    assert rc == cli.EXIT_USAGE and "not valid hex" in s["error"]
    rc, s, _, _ = run_rebox("run", elf, "--out", tmp_path / "o3", "--stdin-file", tmp_path / "nope")
    assert rc == cli.EXIT_USAGE and "not found" in s["error"]
    rc, s, _, _ = run_rebox("run", behave_exe, "--out", tmp_path / "o4", "--stdin", "x")
    assert rc == cli.EXIT_USAGE and "ELF samples only" in s["error"] and "Speakeasy" in s["error"]
    assert not (tmp_path / "o4").exists()
