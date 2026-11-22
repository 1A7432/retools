"""rebox live: parser, tar handling, ELF reader, container flags. No Docker needed."""

import io
import json
import os
import stat
import struct
import tarfile

import pytest

from rebox import live, live_docker, live_elf, live_summary, live_trace


# ---- strace line parsing ----------------------------------------------------------------

def call(line, tid=10):
    ev = live_trace.parse_line(tid, line)
    assert ev and ev[0] == "call", line
    return ev[1]


def test_parse_basic_and_padded_result():
    c = call('1.000001 close(3)              = 0')
    assert c.name == "close" and c.args == ["3"] and c.ret == "0" and c.err is None
    c = call('1.0 connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("198.51.100.7")}, 16)'
             ' = -1 ENETUNREACH (Network is unreachable)')
    assert c.err == "ENETUNREACH"
    assert live_trace.sockaddr(c, c.args[1]) == {"family": "inet", "ip": "198.51.100.7", "port": 4444}


def test_hostile_strings_cannot_forge_syntax():
    # A file name that looks like strace syntax, with an embedded quote and ") = 0".
    name = r'x\", sin_addr=inet_addr(\"6.6.6.6\")) = 0 \n'
    c = call(f'2.0 openat(AT_FDCWD, "/tmp/{name}", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)')
    assert c.name == "openat" and len(c.args) == 4 and c.err == "EACCES"
    assert c.s(c.args[1]) == '/tmp/x", sin_addr=inet_addr("6.6.6.6")) = 0 \n'
    # Inside a unix sockaddr the forged text stays a path.
    c = call('2.1 connect(4, {sa_family=AF_UNIX, sun_path="sin_addr=inet_addr(\\"6.6.6.6\\")"}, 110) = -1 ENOENT (x)')
    sa = live_trace.sockaddr(c, c.args[1])
    assert sa["family"] == "unix" and "6.6.6.6" in sa["path"]


def test_unescape_variants():
    assert live_trace.unescape(r'\2c2\nrebox\7inv\x41\\\"\0') == b'\x02c2\nrebox\x07invA\\"\x00'
    assert live_trace.unescape(r"\377\101") == b"\xffA"


def test_exit_and_kill_lines():
    assert live_trace.parse_line(1, "3.0 +++ exited with 42 +++") == ("exit", 3.0, 42)
    assert live_trace.parse_line(1, "3.0 +++ killed by SIGSEGV (core dumped) +++") == ("killed", 3.0, "SIGSEGV")
    assert live_trace.parse_line(1, "garbage") is None
    c = call("3.0 rt_sigsuspend([], 8")  # cut short when strace was stopped
    assert c.err == "UNFINISHED"


def test_dns_and_payload_helpers():
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02c2\x0arebox-test\x07invalid\x00\x00\x01\x00\x01"
    assert live_trace.dns_names(q) == [("c2.rebox-test.invalid", 1)]
    assert live_trace.dns_names(struct.pack("!H", len(q)) + q, tcp=True) == [("c2.rebox-test.invalid", 1)]
    assert live_trace.dns_names(q[:15]) == []
    assert live_trace.dns_names(b"\x00" * 12 + b"\xc0") == []  # qdcount 0
    bad = bytearray(q)
    bad[12] = 0x3F  # label length past the end
    assert live_trace.dns_names(bytes(bad)) == []
    assert live_trace.http_request(b"GET /x HTTP/1.1\r\nHost: a.invalid\r\n\r\n") == ("GET /x HTTP/1.1", "a.invalid")
    assert live_trace.tls_sni(b"\x16\x03\x01\x00\x05\x01") is None


def _write_trace(d, tid, lines):
    (d / f"t.{tid}").write_text("\n".join(lines) + "\n")


def test_analysis_end_to_end(tmp_path):
    d = tmp_path / "trace"
    d.mkdir()
    q = r'"\22\64\1\0\0\1\0\0\0\0\0\0\2c2\nrebox-test\7invalid\0\0\1\0\1"'
    _write_trace(d, 14, [
        '1.0 execve("/usr/bin/qemu-x86_64", ["qemu-x86_64", "-L", "/", "/tmp/s"], 0x1 /* 6 vars */) = 0',
        '1.1 openat(AT_FDCWD, "/tmp/drop.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3',
        '1.2 openat(AT_FDCWD, "/etc/cron.d/evil", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)',
        '1.3 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 4',
        '1.4 connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        f'1.5 sendmmsg(4, [{{msg_hdr={{msg_name=NULL, msg_namelen=0, msg_iov=[{{iov_base={q}, iov_len=39}}], '
        'msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=39}], 1, MSG_NOSIGNAL) = 1',
        '1.6 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 5',
        '1.7 connect(5, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("198.51.100.7")}, 16) = 0',
        '1.8 write(5, "GET /stage2 HTTP/1.1\\r\\nHost: dl.rebox-test.invalid\\r\\n\\r\\n", 52) = 52',
        '1.9 prctl(PR_SET_NAME, "[kworker/0:1]") = 0',
        '2.0 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 15',
        '2.5 exit_group(42)                 = ?',
        '2.6 +++ exited with 42 +++',
    ])
    _write_trace(d, 15, [
        '2.1 execve("/bin/sh", ["sh", "-c", "echo hi; rm -f /tmp/x"], 0x2 /* 6 vars */) = 0',
        '2.2 unlinkat(AT_FDCWD, "/tmp/x", 0) = -1 ENOENT (No such file or directory)',
        '2.3 exit_group(0) = ?',
        '2.4 +++ exited with 0 +++',
    ])
    an = live_trace.Analysis("/tmp/s")
    an.load_dir(d)
    assert an.root == 14 and an.root_exit() == "exit 42"
    assert list(an.ind["hosts"]) == ["c2.rebox-test.invalid", "dl.rebox-test.invalid"]
    assert "tcp connect 198.51.100.7:4444 ok" in an.ind["conns"]
    assert "http://dl.rebox-test.invalid/stage2" in an.ind["urls"]
    assert "/tmp/drop.bin" in an.ind["files_written"]
    assert "openat /etc/cron.d/evil [EACCES]" in an.ind["persistence"]
    assert "sh -c 'echo hi; rm -f /tmp/x'" in an.ind["cmdlines"]
    assert "/tmp/x [ENOENT]" in an.ind["files_deleted"]
    assert "[kworker/0:1]" in an.ind["proc_names"]
    procs = an.processes()
    assert procs[0]["cmd"] == "/tmp/s" and procs[0]["emulated"] == "qemu-x86_64"
    assert procs[1]["ppid"] == 14 and procs[1]["exit"] == "exit 0" and procs[1]["emulated"] is None
    assert an.unparsed == 0


# ---- tar handling: everything from the container is hostile -----------------------------

def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, data in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
                continue
            ti.type = {"sym": tarfile.SYMTYPE, "lnk": tarfile.LNKTYPE, "dir": tarfile.DIRTYPE,
                       "chr": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE}[kind]
            ti.linkname = data.decode() if data else ""
            tf.addfile(ti)
    buf.seek(0)
    return buf


def test_extract_out_tar_rejects_traversal_links_and_unknown_names(tmp_path):
    dest = tmp_path / "container"
    evil = tmp_path / "evil"
    tarbuf = _tar([
        ("out", "dir", b""),
        ("out/status.json", "file", b'{"stop":"exited"}'),
        ("out/trace/t.14", "file", b"1.0 close(3) = 0\n"),
        ("out/../../evil", "file", b"x"),
        ("/etc/passwd", "file", b"x"),
        ("out/trace/t.15", "sym", str(evil).encode()),
        ("out/trace/t.16", "lnk", b"out/status.json"),
        ("out/stdout.bin", "chr", b""),
        ("out/stderr.bin", "fifo", b""),
        ("out/run.sh", "file", b"#!/bin/sh\n"),
        ("out/status.json", "file", b"second copy"),
        ("out/netcheck.json", "file", b"A" * 5000),
    ])
    res = live_docker.extract_out_tar(tarbuf, dest, max_total=200)
    assert not evil.exists()
    names = sorted(str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file())
    assert names == ["netcheck.json", "status.json", "trace/t.14"]
    assert (dest / "status.json").read_bytes() == b'{"stop":"exited"}'
    assert (dest / "netcheck.json").stat().st_size < 5000 and res["truncated"]
    for p in dest.rglob("*"):
        if p.is_file():
            assert stat.S_IMODE(p.stat().st_mode) == 0o600
            assert not p.is_symlink()
    assert len(res["rejected"]) >= 7


def test_save_first_member_never_writes_links_or_devices(tmp_path):
    for kind, data in (("sym", b"/etc/shadow"), ("lnk", b"x"), ("chr", b""), ("dir", b"")):
        r = live_docker.save_first_member(_tar([("x", kind, data)]), tmp_path, "added", "/tmp/x", max_bytes=100)
        assert "saved" not in r, kind
    assert list(tmp_path.iterdir()) == []
    r = live_docker.save_first_member(_tar([("payload", "file", b"A" * 300)]), tmp_path, "added",
                                      "/tmp/../../a b;c", max_bytes=100)
    f = r["saved"]["file"]
    assert f.parent == tmp_path and f.name.startswith("added_a_b_c_") and f.suffix == ".bin"
    assert f.stat().st_size == 100 and r["saved"]["truncated"] and r["saved"]["orig_size"] == 300
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_safe_name():
    assert live_docker.safe_name("../../etc/passwd") == "etc_passwd"
    assert live_docker.safe_name("\n\x00") == "file"
    assert len(live_docker.safe_name("a" * 500)) == 60


# ---- container flags and the inspect check ------------------------------------------------

def _create(**kw):
    base = dict(labels={"rebox-live": "run"}, user_mode=False, fakenet=False, memory=str(1 << 30), cpus="2",
                pids=256, fsize=1 << 29)
    base.update(kw)
    return live_docker.create_args("rebox-live-x", "sha256:abc", **base)


def test_create_args_have_no_sharing_or_network():
    for kw in ({}, {"user_mode": True}, {"fakenet": True}, {"fakenet": True, "user_mode": True}):
        a = _create(**kw)
        joined = " ".join(a)
        for bad in ("-v", "--volume", "--mount", "--privileged", "--pid", "--userns", "--device", "-p",
                    "--publish", "--net=", "host", "docker.sock", "--tmpfs", "--volumes-from"):
            assert bad not in a and f" {bad}=" not in joined, (bad, kw)
        assert a[a.index("--network") + 1] == "none" and a.count("--network") == 1
        assert a[a.index("--cap-drop") + 1] == "ALL"
        assert "no-new-privileges" in a
        adds = [a[i + 1] for i, x in enumerate(a) if x == "--cap-add"]
        assert adds == ([] if not kw.get("fakenet") else
                        ["NET_ADMIN", "SETPCAP"] + (["SETUID", "SETGID"] if kw.get("user_mode") else []))


def _inspect(**over):
    d = {"HostConfig": {"NetworkMode": "none", "CapDrop": ["ALL"], "CapAdd": None,
                        "SecurityOpt": ["no-new-privileges"], "PidsLimit": 256, "Memory": 1 << 30,
                        "NanoCpus": 2_000_000_000, "PidMode": "", "IpcMode": "private", "UTSMode": "",
                        "UsernsMode": "", "CgroupnsMode": "private"},
         "Config": {"User": ""}, "Mounts": [], "NetworkSettings": {"Networks": {"none": {}}}}
    for k, v in over.items():
        d["HostConfig"][k] = v
    return d


def test_verify_accepts_good_and_refuses_bad():
    ok = dict(user_mode=False, fakenet=False, memory_bytes=1 << 30, pids=256)
    assert live_docker.verify(_inspect(), **ok) == []
    bad = [dict(NetworkMode="bridge"), dict(Privileged=True), dict(CapDrop=[]), dict(CapAdd=["SYS_ADMIN"]),
           dict(SecurityOpt=[]), dict(PidMode="host"), dict(PidsLimit=0), dict(Memory=0),
           dict(Binds=["/Users:/mnt"]), dict(UsernsMode="host")]
    for b in bad:
        assert live_docker.verify(_inspect(**b), **ok), b
    m = _inspect()
    m["Mounts"] = [{"Destination": "/data"}]
    assert live_docker.verify(m, **ok)


# ---- ELF identity and refusal before Docker ---------------------------------------------------

def _elf(machine, cls=2, data=1, etype=2):
    if cls == 2:
        hdr = b"\x7fELF" + bytes([cls, data, 1, 0]) + b"\0" * 8
        hdr += struct.pack("<HHIQQQIHHHHHH", etype, machine, 1, 0x400000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    else:
        hdr = b"\x7fELF" + bytes([cls, data, 1, 0]) + b"\0" * 8
        hdr += struct.pack("<HHIIIIIHHHHHH", etype, machine, 1, 0x8048000, 0, 0, 0, 52, 32, 0, 40, 0, 0)
    return hdr + b"\0" * 64


@pytest.mark.parametrize("machine,cls,arch", [(40, 1, "arm"), (8, 1, "mips"), (243, 2, "riscv"), (20, 1, "ppc")])
def test_unsupported_arch_refused_without_docker(tmp_path, monkeypatch, capsys, machine, cls, arch):
    p = tmp_path / "s"
    p.write_bytes(_elf(machine, cls))

    def boom(*a, **k):
        raise AssertionError("docker must not be contacted")
    monkeypatch.setattr(live_docker, "daemon", boom)
    monkeypatch.setattr(live_docker, "run", boom)
    rc = live._standalone([str(p)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 5 and out["exit"] == 5 and "unsupported architecture" in out["error"] and arch in out["error"]


def test_not_elf_refused(tmp_path, capsys):
    p = tmp_path / "s.exe"
    p.write_bytes(b"MZ" + b"\0" * 100)
    assert live._standalone([str(p)]) == 5
    assert "not an ELF" in json.loads(capsys.readouterr().out)["error"]


def test_elf_identity():
    import tempfile
    with tempfile.NamedTemporaryFile() as f:
        f.write(_elf(62))
        f.flush()
        info = live_elf.parse(f.name)
    assert info["arch"] == "x86_64" and info["class"] == 64 and info["linkage"] == "static"
    assert live_elf.support(info) == ("qemu", "qemu-x86_64")


def test_docker_down_and_image_missing_fail_closed(tmp_path, monkeypatch, capsys):
    p = tmp_path / "s"
    p.write_bytes(_elf(183))
    monkeypatch.setattr(live_docker, "daemon", lambda: None)
    assert live._standalone([str(p)]) == 3
    assert "not reachable" in json.loads(capsys.readouterr().out)["error"]
    monkeypatch.setattr(live_docker, "daemon", lambda: {"os": "linux", "arch": "arm64", "version": "x"})
    monkeypatch.setattr(live_docker, "image", lambda tag=None: None)
    assert live._standalone([str(p)]) == 3
    assert "live-setup" in json.loads(capsys.readouterr().out)["error"]


# ---- summary budget ---------------------------------------------------------------------------

def test_fit_budget_keeps_totals_and_limit():
    s = {"schema": "rebox.summary/1", "ok": True, "indicators": {"hosts": {"total": 300, "top": [f"h{i}.invalid" for i in range(300)]}},
         "syscalls": {"histogram": {"total": 300, "top": [[f"s{i}", i] for i in range(300)]}}, "truncated": None}
    live_summary.fit_budget(s, 1500)
    text = json.dumps(s, separators=(",", ":"), ensure_ascii=False)
    assert len(text) <= 1500
    assert s["indicators"]["hosts"]["total"] == 300 and s["truncated"]["cut"]
    assert len(s["indicators"]["hosts"]["top"]) > len(s["syscalls"]["histogram"]["top"])


def test_parsers_mount_into_a_foreign_cli():
    import argparse
    p = argparse.ArgumentParser(prog="rebox")
    sub = p.add_subparsers(dest="cmd", required=True)
    live.add_parsers(sub)
    a = p.parse_args(["live", "x.elf", "--timeout", "5", "--arg=-v", "--fakenet"])
    assert a._live_cmd == "run" and a.sample == "x.elf" and a.arg == ["-v"] and a.fakenet
    assert p.parse_args(["live-setup"])._live_cmd == "setup"
    assert p.parse_args(["live-summarize", "d"])._live_cmd == "summarize"
    assert p.parse_args(["live", "--cleanup"]).cleanup


def test_no_real_network_flag():
    import argparse
    p = argparse.ArgumentParser()
    live.add_parsers(p.add_subparsers(dest="cmd"))
    opts = {o for a in p._subparsers._group_actions[0].choices.values() for act in a._actions for o in act.option_strings}
    assert not any(k in o for o in opts for k in ("network", "net=", "bridge", "host", "volume", "mount", "privileged"))
    assert os.path.basename(live_docker.DOCKER_DIR) == "docker"
