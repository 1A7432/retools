"""PID 1 of a rebox live container: self-check, run the sample under strace, record.

Reads /rebox/job.json (copied in by the host together with the sample), writes
everything into /rebox/out:

  netcheck.json      isolation self-check (the sample is not started unless ok)
  trace/t.<tid>      strace -ff output, one file per process/thread
  stdout.bin, stderr.bin   the sample's output, first `max_output` bytes each
  fakenet.jsonl      fake network sink log (--fakenet only)
  status.json        how the run ended (written last; also on refusal)

Exit status: 0 sample was run, 3 refused (isolation check failed), 4 runner error.
Everything in /rebox/out is also writable by the sample (same uid as the tracer),
so the host treats all of it as untrusted input.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import traceback

sys.path.insert(0, "/opt/rebox-live")
import netcheck  # noqa: E402

OUT = "/rebox/out"
JOB = "/rebox/job.json"
PR_CAPBSET_READ, PR_CAPBSET_DROP, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 23, 24, 47, 4
PR_SET_DUMPABLE = 4
SYS_CAPSET = {"aarch64": 91, "x86_64": 126}
CAP_VERSION_3 = 0x20080522
SAMPLE_ENV_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

libc = ctypes.CDLL(None, use_errno=True)
status: dict = {"stop": None, "errors": []}


def write_json(name: str, obj) -> None:
    tmp = os.path.join(OUT, name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, os.path.join(OUT, name))


def cap_status() -> dict:
    return {k: v for k, v in netcheck.caps().items() if k.startswith("Cap")}


def caps_all_zero() -> bool:
    c = cap_status()
    return len(c) == 5 and all(int(v, 16) == 0 for v in c.values())


def drop_bounding() -> None:
    """Remove every capability from the bounding set (needs CAP_SETPCAP if any is present)."""
    for cap in range(64):
        r = libc.prctl(PR_CAPBSET_READ, cap, 0, 0, 0)
        if r < 0:
            break  # past the last capability the kernel knows
        if r == 1 and libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), f"PR_CAPBSET_DROP {cap} failed")


def clear_caps() -> None:
    """Clear ambient, then effective/permitted/inheritable of this process."""
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    hdr = (ctypes.c_uint32 * 2)(CAP_VERSION_3, 0)
    data = (ctypes.c_uint32 * 6)()
    nr = SYS_CAPSET.get(os.uname().machine)
    if nr is None or libc.syscall(nr, ctypes.byref(hdr), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")


def preexec_sample(drop_uid):
    def fn():
        os.setsid()
        if drop_uid is not None:
            os.setgroups([])
            os.setgid(drop_uid)
            os.setuid(drop_uid)  # root -> non-root clears permitted/effective caps
        libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        if not caps_all_zero():
            clear_caps()
        if not caps_all_zero():
            raise RuntimeError(f"capabilities still present before exec: {cap_status()}")
    return fn


def preexec_sink(drop_uid):
    def fn():
        if drop_uid is not None:
            os.setgroups([])
            os.setgid(drop_uid)
            os.setuid(drop_uid)
        if not caps_all_zero():
            clear_caps()
        if not caps_all_zero():
            raise RuntimeError(f"sink still has capabilities: {cap_status()}")
    return fn


def drop_self(drop_uid) -> None:
    """The runner itself ends with no capabilities, as the sample's uid (so it can still signal strace)."""
    if drop_uid is not None:
        os.setgroups([])
        os.setgid(drop_uid)
        os.setuid(drop_uid)
    if not caps_all_zero():
        clear_caps()


def setup_fakenet() -> dict:
    """Make every IPv4 address local on lo and redirect TCP (not to 127/8) to the sink."""
    cmds = [
        ["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "local"],
    ]
    rules = ("table ip rebox_fakenet {\n"
             "  chain out { type nat hook output priority -100; policy accept;\n"
             "    ip daddr != 127.0.0.0/8 meta l4proto tcp redirect to :65000\n"
             "  }\n}\n")
    for c in cmds:
        p = subprocess.run(c, capture_output=True, text=True, timeout=10)
        if p.returncode != 0:
            raise RuntimeError(f"{' '.join(c)}: {p.stderr.strip()}")
    p = subprocess.run(["nft", "-f", "-"], input=rules, capture_output=True, text=True, timeout=10)
    if p.returncode != 0:
        raise RuntimeError(f"nft: {p.stderr.strip()}")
    return {"routes": ["local 0.0.0.0/0 dev lo table local"], "nft": rules}


class Capped(threading.Thread):
    """Drain a pipe into a file, keeping only the first `limit` bytes (never blocks the writer)."""

    def __init__(self, fd, path, limit):
        super().__init__(daemon=True)
        self.fd, self.path, self.limit, self.total = fd, path, limit, 0

    def run(self):
        with open(self.path, "wb") as f:
            while True:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                if self.total < self.limit:
                    f.write(chunk[:self.limit - self.total])
                self.total += len(chunk)
        os.close(self.fd)


def survivors() -> list[dict]:
    me = os.getpid()
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) in (1, me):
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as f:
                cmd = f.read(400).replace(b"\0", b" ").decode("utf-8", "replace").strip()
            with open(f"/proc/{name}/comm") as f:
                comm = f.read().strip()
        except OSError:
            continue
        out.append({"pid": int(name), "comm": comm[:32], "cmdline": cmd[:200]})
    return out


def injected(sample: str, cap: int = 2000) -> dict:
    """Paths present now that are not in the image manifest (runtime injections), with hashes."""
    try:
        with open("/opt/rebox-live/manifest.txt") as f:
            known = set(f.read().splitlines())
    except OSError:
        return {"error": "no manifest"}
    out = {}
    for root, dirs, files in os.walk("/", topdown=True):
        if root == "/":
            dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev", "rebox")]
        for name in dirs + files:
            p = os.path.join(root, name)
            if p in known or p == sample:
                continue
            if len(out) >= cap:
                return out
            try:
                st = os.lstat(p)
            except OSError:
                continue
            ent = {"mode": oct(st.st_mode)}
            if os.path.isfile(p) and not os.path.islink(p) and st.st_size <= (4 << 20):
                try:
                    with open(p, "rb") as f:
                        ent["sha256"] = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    pass
            out[p] = ent
    return out


def free_bytes() -> int:
    st = os.statvfs("/")
    return st.f_bavail * st.f_frsize


def main() -> int:
    os.umask(0o022)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(sig, signal.SIG_DFL)  # as PID 1: ignored when sent from inside the container
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)  # the sample (same uid) cannot ptrace the runner
    os.makedirs(os.path.join(OUT, "trace"), exist_ok=True)
    with open(JOB) as f:
        job = json.load(f)
    status["job"] = {k: job.get(k) for k in ("mode", "qemu", "timeout", "fakenet", "drop_uid")}
    status["runner_uid"] = os.getuid()

    nc = netcheck.run()
    write_json("netcheck.json", nc)
    if not nc["ok"]:
        status["stop"] = "refused"
        status["errors"].append("netcheck failed: " + "; ".join(nc["reasons"])[:1000])
        return 3

    # Docker bind-mounts these three per-container files, so `docker diff` never shows
    # changes to them; the host compares this baseline with their content afterwards.
    baseline = {}
    for path in ("/etc/hosts", "/etc/resolv.conf", "/etc/hostname"):
        try:
            with open(path, "rb") as f:
                baseline[path] = f.read(65536).decode("utf-8", "replace")
        except OSError as e:
            baseline[path] = None
    status["etc_baseline"] = baseline
    status["preexisting_new"] = injected(job["sample"])

    sink = None
    if job.get("fakenet"):
        status["fakenet"] = setup_fakenet()
        after = netcheck.after_fakenet()
        status["fakenet"]["check"] = after
        if not after["ok"]:
            status["stop"] = "refused"
            status["errors"].append("post-fakenet check failed: " + "; ".join(after["reasons"]))
            return 3
    drop_bounding()  # no-op when Docker already dropped everything
    if job.get("fakenet"):
        log = os.path.join(OUT, "fakenet.jsonl")
        sink = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "/opt/rebox-live/fakenet.py", log],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=preexec_sink(job.get("drop_uid")), close_fds=True)
        for _ in range(50):
            try:
                with open(log) as f:
                    if '"ready"' in f.read(4096):
                        break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            status["stop"] = "refused"
            status["errors"].append("fake network sink did not start")
            return 4

    if job.get("drop_uid") is not None:  # strace runs as the sample's uid and must write here
        os.chmod(os.path.join(OUT, "trace"), 0o777)  # (no CAP_CHOWN for a chown)
    sample = job["sample"]
    target = [sample, *job.get("args", [])]
    if job["mode"] == "qemu":
        target = [f"/usr/bin/{job['qemu']}", "-L", "/", *target]
    cmd = ["/usr/bin/strace", "-f", "-ff", "-ttt", "-q", "-s", str(int(job.get("strsize", 4096))),
           "--kill-on-exit", "-o", os.path.join(OUT, "trace", "t"), "--", *target]
    home = "/root" if (job.get("drop_uid") is None and os.getuid() == 0) else "/home/user"
    env = {"PATH": SAMPLE_ENV_PATH, "HOME": home, "LANG": "C.UTF-8", "PWD": "/tmp",
           "SHELL": "/bin/sh", "USER": "root" if home == "/root" else "user",
           "LOGNAME": "root" if home == "/root" else "user"}
    status["cmd"] = cmd
    status["sample_env"] = env

    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    free0 = free_bytes()
    t0 = time.time()
    status["start"] = t0
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out_w, stderr=err_w, cwd="/tmp", env=env,
                            preexec_fn=preexec_sample(job.get("drop_uid")), close_fds=True)
    os.close(out_w)
    os.close(err_w)
    # Threads only after the last fork with preexec_fn.
    clear_caps_err = None
    try:
        drop_self(job.get("drop_uid"))
    except OSError as e:
        clear_caps_err = str(e)
    limit = int(job.get("max_output", 1 << 20))
    capture = [Capped(out_r, os.path.join(OUT, "stdout.bin"), limit),
               Capped(err_r, os.path.join(OUT, "stderr.bin"), limit)]
    for c in capture:
        c.start()
    if clear_caps_err:
        status["errors"].append(f"runner could not clear its own capabilities: {clear_caps_err}")

    deadline = t0 + float(job["timeout"])
    max_disk = int(job.get("max_disk", 2 << 30))
    stop = None
    while True:
        try:
            rc = proc.wait(timeout=0.25)
            stop = "exited"
            break
        except subprocess.TimeoutExpired:
            pass
        if time.time() >= deadline:
            stop = "timeout"
            break
        try:
            used = free0 - free_bytes()
        except OSError:
            used = 0
        if used > max_disk:
            stop = "disk_limit"
            status["disk_used"] = used
            break
    status["end_of_sample"] = time.time()
    if stop != "exited":
        status["survivors"] = [s for s in survivors() if s["pid"] != proc.pid and (sink is None or s["pid"] != sink.pid)]
        # SIGTERM lets strace flush its output; --kill-on-exit (PTRACE_O_EXITKILL)
        # kills every tracee when strace goes away, however it goes.
        proc.terminate()
        try:
            rc = proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                rc = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                rc = None
    else:
        left = [s for s in survivors() if s["pid"] != proc.pid and (sink is None or s["pid"] != sink.pid)]
        if left:
            status["survivors"] = left  # untraced leftovers (should not exist with -f)
    if sink is not None:
        sink.terminate()
        try:
            sink.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.kill(-1, signal.SIGKILL)  # everything but PID 1
    except ProcessLookupError:
        pass
    for c in capture:
        c.join(timeout=5)
    status["stop"] = stop
    status["strace_rc"] = rc
    status["end"] = time.time()
    status["stdout_bytes"] = capture[0].total
    status["stderr_bytes"] = capture[1].total
    status["output_limit"] = limit
    return 0


if __name__ == "__main__":
    code = 4
    try:
        code = main()
    except BaseException as e:  # noqa: BLE001 - record and exit, never hang as PID 1
        status["stop"] = status.get("stop") or "runner_error"
        status["errors"].append(f"{type(e).__name__}: {e}"[:1000])
        status["traceback"] = traceback.format_exc()[-3000:]
        code = 4
    status["runner_exit"] = code
    try:
        write_json("status.json", status)
    except OSError:
        pass
    sys.exit(code)
