"""In-container isolation self-check for rebox live.

Run by runner.py before the sample starts (and usable on its own:
`python3 -I -B /opt/rebox-live/netcheck.py` prints the JSON result). The sample
is only started when `ok` is true. Checks:

  * only the loopback interface exists (/proc/net/dev and /sys/class/net);
  * every route in every table (IPv4 and IPv6) goes through `lo`;
  * TCP and UDP to a reserved IPv4 address and TCP to a reserved IPv6 address
    fail with ENETUNREACH (no route), never succeed or time out;
  * a DNS lookup fails;
  * no Docker/containerd control socket is reachable at the usual paths;
  * no host file system is shared in: no mount of a sharing file system type
    (virtiofs, 9p, fuse, nfs, cifs, OrbStack's fakeowner, ...) and no bind
    mount other than the three files Docker manages itself
    (/etc/hostname, /etc/hosts, /etc/resolv.conf, which live in the Docker
    VM's per-container directory, not on the Mac);
  * effective/permitted/bounding/ambient capabilities are reported (the
    expected set is checked by the runner, which knows the mode).

`after_fakenet()` repeats the interface/route checks after the fake network
was configured (its routes are `local` routes on `lo`, which keeps every
packet inside this network namespace).
"""

from __future__ import annotations

import errno
import json
import os
import socket
import subprocess

RESERVED_V4 = "198.51.100.1"  # TEST-NET-2, never routed
RESERVED_V6 = "2001:db8::1"  # documentation prefix
SHARING_FS = {"virtiofs", "9p", "fuse", "fuseblk", "fuse.sshfs", "nfs", "nfs4", "cifs", "smb3", "smbfs",
              "fakeowner", "vboxsf", "prl_fs", "fuse.grpcfuse", "osxfs", "virtfs"}
DOCKER_MANAGED = {"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}
CONTROL_SOCKETS = ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                   "/var/run/containerd/containerd.sock", "/run/podman/podman.sock", "/var/run/orbstack.sock",
                   "/run/orbstack.sock", "/opt/orbstack-guest/run/docker.sock"]
CAP_KEYS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


def interfaces() -> list[str]:
    names = set()
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                if ":" in line:
                    names.add(line.split(":", 1)[0].strip())
    except OSError:
        names.add("?unreadable:/proc/net/dev")
    try:
        names.update(os.listdir("/sys/class/net"))
    except OSError:
        pass
    return sorted(names)


def routes() -> tuple[list[dict], str | None]:
    """All routes of all tables, via `ip -j`; returns (routes, error)."""
    out = []
    for fam in ("-4", "-6"):
        try:
            p = subprocess.run(["ip", "-j", fam, "route", "show", "table", "all"], capture_output=True,
                               text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as e:
            return out, f"ip route failed: {e}"
        if p.returncode != 0:
            return out, f"ip route exit {p.returncode}: {p.stderr.strip()[:200]}"
        try:
            for r in json.loads(p.stdout or "[]"):
                r["family"] = fam
                out.append(r)
        except ValueError as e:
            return out, f"ip route output not JSON: {e}"
    return out, None


def _connect(family, kind, addr) -> str:
    s = socket.socket(family, kind)
    s.settimeout(3)
    try:
        if kind == socket.SOCK_DGRAM:
            s.sendto(b"rebox-live-netcheck", addr)
        else:
            s.connect(addr)
        return "ok"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno)) if e.errno else type(e).__name__
    finally:
        s.close()


def probes() -> dict:
    res = {
        "tcp4": _connect(socket.AF_INET, socket.SOCK_STREAM, (RESERVED_V4, 80)),
        "udp4": _connect(socket.AF_INET, socket.SOCK_DGRAM, (RESERVED_V4, 53)),
    }
    try:
        res["tcp6"] = _connect(socket.AF_INET6, socket.SOCK_STREAM, (RESERVED_V6, 80))
    except OSError as e:  # IPv6 disabled altogether is fine
        res["tcp6"] = f"no-ipv6:{errno.errorcode.get(e.errno, e.errno)}"
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo("example.com", 80)
        res["dns"] = "resolved"
    except (socket.gaierror, socket.timeout, OSError):
        res["dns"] = "failed"
    finally:
        socket.setdefaulttimeout(None)
    return res


def mounts() -> tuple[list[dict], list[str]]:
    """Parse /proc/self/mountinfo; return (mounts, problems)."""
    items, problems = [], []
    try:
        with open("/proc/self/mountinfo") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return items, [f"cannot read mountinfo: {e}"]
    for line in lines:
        left, _, right = line.partition(" - ")
        lf, rf = left.split(), right.split()
        if len(lf) < 5 or len(rf) < 2:
            problems.append(f"unparsed mountinfo line: {line[:120]}")
            continue
        root, target, fstype, source = lf[3], lf[4], rf[0], rf[1]
        m = {"target": target, "root": root, "fstype": fstype, "source": source}
        items.append(m)
        if fstype in SHARING_FS or fstype.startswith("fuse"):
            problems.append(f"host-sharing file system {fstype} at {target}")
        # A bind mount shows the bound sub-path as `root`; proc/tmpfs masks
        # (/proc/keys -> /dev/null etc.) are Docker's own masking, not host paths.
        if root != "/" and fstype not in ("proc", "tmpfs", "sysfs", "devpts", "mqueue", "cgroup2", "cgroup"):
            if target not in DOCKER_MANAGED:
                problems.append(f"bind mount {root} -> {target} ({fstype})")
    return items, problems


def control_sockets() -> list[str]:
    found = [p for p in CONTROL_SOCKETS if os.path.exists(p)]
    for d in ("/run", "/var/run", "/tmp"):
        try:
            for name in os.listdir(d):
                p = os.path.join(d, name)
                try:
                    import stat

                    if stat.S_ISSOCK(os.lstat(p).st_mode):
                        found.append(p)
                except OSError:
                    pass
        except OSError:
            pass
    return sorted(set(found))


def caps() -> dict:
    out = {}
    try:
        with open("/proc/self/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in CAP_KEYS or k in ("NoNewPrivs", "Seccomp", "Uid"):
                    out[k] = v.strip()
    except OSError:
        pass
    return out


def check_routes_and_ifaces(res: dict) -> list[str]:
    reasons = []
    ifs = interfaces()
    res["interfaces"] = ifs
    if ifs != ["lo"]:
        reasons.append(f"interfaces other than lo present: {ifs}")
    rts, err = routes()
    res["routes"] = [{k: r.get(k) for k in ("family", "type", "dst", "dev", "table", "gateway")} for r in rts]
    if err:
        reasons.append(err)
    for r in rts:
        if r.get("dev") not in ("lo", None) or r.get("gateway"):
            reasons.append(f"route not on lo: {r.get('family')} {r.get('dst')} dev {r.get('dev')} via {r.get('gateway')}")
        elif r.get("dev") is None and r.get("type") not in ("unreachable", "prohibit", "blackhole", "throw"):
            reasons.append(f"route without device: {r.get('family')} {r.get('dst')} type {r.get('type')}")
    return reasons


def run() -> dict:
    res: dict = {}
    reasons = check_routes_and_ifaces(res)
    pr = probes()
    res["probes"] = pr
    for k in ("tcp4", "udp4"):
        if pr[k] != "ENETUNREACH":
            reasons.append(f"{k} to reserved address gave {pr[k]}, expected ENETUNREACH")
    if pr["tcp6"] not in ("ENETUNREACH", "EADDRNOTAVAIL") and not pr["tcp6"].startswith("no-ipv6"):
        reasons.append(f"tcp6 to reserved address gave {pr['tcp6']}, expected ENETUNREACH")
    if pr["dns"] != "failed":
        reasons.append("DNS lookup succeeded")
    m, problems = mounts()
    res["mounts"] = [f"{x['fstype']} {x['root']} -> {x['target']}" for x in m]
    reasons.extend(problems)
    socks = control_sockets()
    res["control_sockets"] = socks
    if socks:
        reasons.append(f"socket files present: {socks}")
    res["caps"] = caps()
    if res["caps"].get("NoNewPrivs") != "1":
        reasons.append("no_new_privs is not set")
    res["reasons"] = reasons
    res["ok"] = not reasons
    return res


def after_fakenet() -> dict:
    res: dict = {}
    reasons = check_routes_and_ifaces(res)
    res["reasons"] = reasons
    res["ok"] = not reasons
    return res


if __name__ == "__main__":
    print(json.dumps(run()))
