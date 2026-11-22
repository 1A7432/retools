"""The sandbox must stop network and out-of-tree writes, and rebox must fail closed."""

import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from rebox import cli, sandbox

PROBE = r'''
import errno, json, os, socket, subprocess, sys
out, port, outside, sandboxed = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4] == "1"
res = {}
def attempt(name, fn):
    try:
        fn()
        res[name] = "ok"
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno)) if e.errno else type(e).__name__
def tcp(host, p):
    s = socket.socket(); s.settimeout(3)
    try: s.connect((host, p))
    finally: s.close()
attempt("tcp_local", lambda: tcp("127.0.0.1", port))
attempt("tcp_external", lambda: tcp("1.1.1.1", 443))
attempt("udp_dns_server", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("8.8.8.8", 53)))
try:
    socket.getaddrinfo("example.com", 80)
    res["dns"] = "resolved"
except socket.gaierror as e:
    res["dns"] = "failed"
def write(path):
    with open(path, "w") as f: f.write("x")
attempt("write_outside", lambda: write(outside))
if sandboxed:  # never attempted unsandboxed: it would really write to $HOME
    attempt("write_home", lambda: write(os.path.join(os.environ.get("REAL_HOME", "/nonexistent"), ".rebox-sandbox-test")))
attempt("write_inside", lambda: write(os.path.join(out, "inside.txt")))
attempt("exec", lambda: subprocess.run(["/bin/echo", "hi"], capture_output=True))
print(json.dumps(res))
'''


@pytest.fixture
def listener():
    """A real local TCP listener, so a refused connect can only be the sandbox."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    accepted = []

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            accepted.append(c)
            c.close()

    threading.Thread(target=loop, daemon=True).start()
    yield srv.getsockname()[1], accepted
    srv.close()


def _probe(tmp_path, port, sandboxed):
    out = tmp_path / ("out_sb" if sandboxed else "out_plain")
    out.mkdir()
    (out / "tmp").mkdir()
    outside = tmp_path / ("outside_sb.txt" if sandboxed else "outside_plain.txt")
    script = tmp_path / "probe.py"
    script.write_text(PROBE)
    argv = [sys.executable, "-I", "-B", str(script), str(out), str(port), str(outside), "1" if sandboxed else "0"]
    if sandboxed:
        profile = sandbox.write_profile(tmp_path / "test.sb")
        argv = sandbox.wrap_command(argv, out, profile)
        env = {**sandbox.sandbox_env(out), "REAL_HOME": os.path.expanduser("~")}
    else:
        env = dict(os.environ)
    p = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout), out, outside


@pytest.mark.skipif(not sandbox.sandbox_available(), reason="sandbox-exec missing")
def test_sandbox_denies_network_and_outside_writes(tmp_path, listener):
    port, accepted = listener

    # Control run without the sandbox: the listener is reachable and the outside path writable.
    plain, _, plain_outside = _probe(tmp_path, port, sandboxed=False)
    assert plain["tcp_local"] == "ok"
    assert plain["write_outside"] == "ok"
    plain_outside.unlink()
    n_before = len(accepted)

    res, out, outside = _probe(tmp_path, port, sandboxed=True)
    assert res["tcp_local"] == "EPERM", res
    assert res["tcp_external"] == "EPERM", res
    assert res["udp_dns_server"] == "EPERM", res
    assert res["dns"] == "failed", res
    assert res["write_outside"] == "EPERM", res
    assert res["write_home"] == "EPERM", res
    assert res["exec"] == "EPERM", res
    assert res["write_inside"] == "ok", res
    assert (out / "inside.txt").read_text() == "x"
    assert not outside.exists()
    assert not os.path.exists(os.path.expanduser("~/.rebox-sandbox-test"))
    assert len(accepted) == n_before, "sandboxed process reached the local listener"


@pytest.mark.skipif(not sandbox.sandbox_available(), reason="sandbox-exec missing")
def test_inner_self_check_is_recorded(tmp_path, behave_exe):
    out = tmp_path / "out"
    rc = cli.main(["run", str(behave_exe), "--out", str(out), "--timeout", "20"])
    assert rc == 0
    meta = json.loads((out / "run.json").read_text())
    assert meta["sandbox"] == {"tcp_connect": "denied", "dns": "denied", "write_outside": "denied",
                               "write_inside": "ok", "verified": True}


def test_refuses_without_sandbox_exec(tmp_path, behave_exe, monkeypatch, capsys):
    monkeypatch.setattr(sandbox, "SANDBOX_EXEC", str(tmp_path / "no-such-sandbox-exec"))
    out = tmp_path / "out"
    rc = cli.main(["run", str(behave_exe), "--out", str(out)])
    res = json.loads(capsys.readouterr().out)
    assert rc == cli.EXIT_SANDBOX
    assert res["ok"] is False and "refusing" in res["error"]
    assert not out.exists()


@pytest.mark.skipif(not sandbox.sandbox_available(), reason="sandbox-exec missing")
def test_refuses_when_profile_fails_to_apply(tmp_path, behave_exe, monkeypatch, capsys):
    monkeypatch.setattr(sandbox, "PROFILE", "(version 1)\n(this-is-not-sbpl)\n")
    out = tmp_path / "out"
    rc = cli.main(["run", str(behave_exe), "--out", str(out)])
    res = json.loads(capsys.readouterr().out)
    assert rc == cli.EXIT_SANDBOX, res
    assert res["ok"] is False
    assert not (out / "report.json").exists()
    assert not (out / "run.json").exists()


@pytest.mark.skipif(not sandbox.sandbox_available(), reason="sandbox-exec missing")
def test_refuses_when_profile_does_not_isolate(tmp_path, behave_exe, monkeypatch, capsys):
    # A profile that applies but allows everything must be caught by the in-process self-check.
    monkeypatch.setattr(sandbox, "PROFILE", "(version 1)\n(allow default)\n")
    out = tmp_path / "out"
    rc = cli.main(["run", str(behave_exe), "--out", str(out)])
    res = json.loads(capsys.readouterr().out)
    assert rc == cli.EXIT_SANDBOX, res
    assert "self-check failed" in res["error"]
    assert res["sandbox"]["verified"] is False
    assert not (out / "report.json").exists()


def test_no_sandbox_flag_warns(tmp_path, behave_exe, capsys):
    out = tmp_path / "out"
    rc = cli.main(["run", str(behave_exe), "--out", str(out), "--no-sandbox", "--timeout", "20"])
    cap = capsys.readouterr()
    res = json.loads(cap.out)
    assert rc == 0
    assert "WARNING" in cap.err and "--no-sandbox" in cap.err
    assert res["emulation"]["sandbox"].startswith("DISABLED")
    assert not (out / "sandbox.sb").exists()
