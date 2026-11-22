"""Docker plumbing for `rebox live` (stdlib only; drives the docker CLI).

Everything that comes back from the container (tar streams, file names, diff
paths) is treated as hostile: tar members are never extracted with
tarfile.extract*, only regular files are written, under names this module
builds itself, with O_CREAT|O_EXCL|O_NOFOLLOW and mode 0600, within byte and
member limits.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import threading
import time
import urllib.parse
from pathlib import Path

IMAGE_TAG = "rebox-live:1"
LABEL = "rebox-live"
LABEL_RUN = "run"
NAME_PREFIX = "rebox-live-"
DOCKER_DIR = Path(__file__).resolve().parents[2] / "docker"
SAMPLE_UID = 1000


class DockerError(RuntimeError):
    pass


def docker_bin() -> str | None:
    for cand in (shutil.which("docker"), "/usr/local/bin/docker", os.path.expanduser("~/.orbstack/bin/docker"),
                 "/opt/homebrew/bin/docker"):
        if cand and os.access(cand, os.X_OK):
            return cand
    return None


def run(args: list[str], timeout: float = 60, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    exe = docker_bin()
    if exe is None:
        raise DockerError("docker CLI not found")
    try:
        p = subprocess.run([exe, *args], input=input, capture_output=True, timeout=timeout,
                           stdin=None if input is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        raise DockerError(f"docker {args[0]} timed out after {timeout}s") from e
    if check and p.returncode != 0:
        raise DockerError(f"docker {' '.join(args[:2])} failed ({p.returncode}): "
                          f"{p.stderr.decode('utf-8', 'replace').strip()[-400:]}")
    return p


def daemon() -> dict | None:
    """Server info, or None if the daemon is not reachable."""
    try:
        p = run(["version", "--format", "{{json .Server}}"], timeout=15, check=False)
    except DockerError:
        return None
    if p.returncode != 0:
        return None
    try:
        s = json.loads(p.stdout or b"null")
    except ValueError:
        return None
    if not s:
        return None
    return {"version": s.get("Version"), "os": s.get("Os"), "arch": s.get("Arch")}


def image(tag: str = IMAGE_TAG) -> dict | None:
    p = run(["image", "inspect", tag], timeout=30, check=False)
    if p.returncode != 0:
        return None
    try:
        info = json.loads(p.stdout)[0]
    except (ValueError, IndexError):
        return None
    cfg = info.get("Config") or {}
    return {"id": info.get("Id"), "tag": tag, "created": info.get("Created"), "arch": info.get("Architecture"),
            "labels": cfg.get("Labels") or {}, "volumes": cfg.get("Volumes"), "entrypoint": cfg.get("Entrypoint"),
            "repo_digests": info.get("RepoDigests")}


def build_image(tag: str = IMAGE_TAG, no_cache: bool = False, timeout: float = 1800) -> subprocess.CompletedProcess:
    exe = docker_bin()
    if exe is None:
        raise DockerError("docker CLI not found")
    cmd = [exe, "build", "--pull=false", "-t", tag, "--label", f"{LABEL}=image", str(DOCKER_DIR)]
    if no_cache:
        cmd.insert(2, "--no-cache")
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)


def image_packages(image_id: str) -> str | None:
    """/opt/rebox-live/packages.txt from the image, read through a throw-away container (never started)."""
    name = f"{NAME_PREFIX}pkgs-{os.getpid()}-{int(time.time())}"
    try:
        run(["create", "--name", name, "--label", f"{LABEL}=pkgs", "--network", "none", image_id], timeout=60)
        p = run(["cp", f"{name}:/opt/rebox-live/packages.txt", "-"], timeout=60)
        with tarfile.open(fileobj=io.BytesIO(p.stdout[:4 << 20]), mode="r:") as tf:
            for m in tf:
                if m.isreg() and m.size < (1 << 20):
                    f = tf.extractfile(m)
                    return f.read().decode("utf-8", "replace") if f else None
    except (DockerError, tarfile.TarError):
        return None
    finally:
        run(["rm", "-f", name], timeout=60, check=False)
    return None


# ---- container configuration -----------------------------------------------------------

def create_args(name: str, image_id: str, *, labels: dict, user_mode: bool, fakenet: bool,
                memory: str, cpus: str, pids: int, fsize: int) -> list[str]:
    """The complete `docker create` argument list. No volume, mount or network flag beyond these."""
    caps = []
    run_as = []
    if fakenet:
        # Needed only by the runner before the sample starts; it removes them from the
        # bounding set and from its own and its children's sets before exec (runner.py).
        caps = ["NET_ADMIN", "SETPCAP"] + (["SETUID", "SETGID"] if user_mode else [])
    elif user_mode:
        run_as = ["--user", f"{SAMPLE_UID}:{SAMPLE_UID}"]
    args = ["create", "--name", name]
    for k, v in labels.items():
        args += ["--label", f"{k}={v}"]
    args += [
        "--network", "none",
        "--dns", "127.0.0.1",  # resolver on loopback: lookups become visible queries, not connect errors
        "--hostname", "debian",
        "--cap-drop", "ALL",
        *sum((["--cap-add", c] for c in caps), []),
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids),
        "--memory", memory,
        "--memory-swap", memory,
        "--cpus", cpus,
        "--ulimit", "core=0",
        "--ulimit", "nofile=4096:4096",
        "--ulimit", f"fsize={fsize}:{fsize}",
        "--ipc", "private",
        "--cgroupns", "private",
        "--log-driver", "none",
        "--stop-timeout", "1",
        *run_as,
        image_id,
    ]
    return args


def verify(inspect: dict, *, user_mode: bool, fakenet: bool, memory_bytes: int, pids: int) -> list[str]:
    """Check from `docker inspect` that the isolation flags were actually applied."""
    hc = inspect.get("HostConfig") or {}
    cfg = inspect.get("Config") or {}
    problems = []
    if hc.get("NetworkMode") != "none":
        problems.append(f"NetworkMode is {hc.get('NetworkMode')!r}, not 'none'")
    nets = ((inspect.get("NetworkSettings") or {}).get("Networks") or {})
    if set(nets) - {"none"}:
        problems.append(f"attached to networks {sorted(nets)}")
    if inspect.get("Mounts"):
        problems.append(f"mounts present: {[m.get('Destination') for m in inspect['Mounts']]}")
    for key in ("Binds", "VolumesFrom", "Mounts", "Devices", "DeviceRequests", "Links", "ExtraHosts"):
        if hc.get(key):
            problems.append(f"HostConfig.{key} is set: {str(hc.get(key))[:200]}")
    if hc.get("Tmpfs"):
        problems.append("tmpfs mounts present")
    if cfg.get("Volumes"):
        problems.append(f"image/container declares volumes {list(cfg['Volumes'])}")
    if hc.get("Privileged"):
        problems.append("container is privileged")
    if [c.upper() for c in (hc.get("CapDrop") or [])] not in (["ALL"], ["CAP_ALL"]):
        problems.append(f"CapDrop is {hc.get('CapDrop')}, not [ALL]")
    want_caps = {"CAP_NET_ADMIN", "CAP_SETPCAP"} | ({"CAP_SETUID", "CAP_SETGID"} if user_mode else set()) if fakenet else set()
    got_caps = {c.upper() if c.upper().startswith("CAP_") else "CAP_" + c.upper() for c in (hc.get("CapAdd") or [])}
    if got_caps != want_caps:
        problems.append(f"CapAdd is {sorted(got_caps)}, expected {sorted(want_caps)}")
    if not any(str(o).startswith("no-new-privileges") and not str(o).endswith("false") for o in hc.get("SecurityOpt") or []):
        problems.append("no-new-privileges not set")
    if any("unconfined" in str(o) for o in hc.get("SecurityOpt") or []):
        problems.append(f"unconfined security option: {hc.get('SecurityOpt')}")
    for mode_key in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
        v = str(hc.get(mode_key) or "")
        if v == "host" or v.startswith("container:"):
            problems.append(f"{mode_key} is {v!r}")
    if (hc.get("PidsLimit") or 0) <= 0 or hc.get("PidsLimit") > pids:
        problems.append(f"PidsLimit is {hc.get('PidsLimit')}")
    if not hc.get("Memory") or hc.get("Memory") > memory_bytes:
        problems.append(f"Memory limit is {hc.get('Memory')}")
    if not hc.get("NanoCpus"):
        problems.append("no CPU limit")
    if hc.get("PortBindings") or hc.get("PublishAllPorts"):
        problems.append("ports published")
    if user_mode and not fakenet and cfg.get("User") != f"{SAMPLE_UID}:{SAMPLE_UID}":
        problems.append(f"User is {cfg.get('User')!r}")
    return problems


# ---- copying in -------------------------------------------------------------------------

def tar_bytes(entries: list[tuple[str, bytes, int, int]]) -> bytes:
    """[(name, data, mode, uid)] -> tar archive bytes (regular files only)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data, mode, uid in entries:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.uid, ti.gid = len(data), mode, uid, uid
            ti.mtime = int(time.time())
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


# ---- copying out ------------------------------------------------------------------------

SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(name: str, cap: int = 60) -> str:
    s = SAFE_RE.sub("_", name).strip("._") or "file"
    return s[:cap]


def _write_new(path: Path, chunks) -> tuple[int, str]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    h = hashlib.sha256()
    n = 0
    with os.fdopen(fd, "wb") as f:
        for chunk in chunks:
            f.write(chunk)
            h.update(chunk)
            n += len(chunk)
    os.chmod(path, 0o600)
    return n, h.hexdigest()


def _member_chunks(f, limit: int):
    left = limit
    while left > 0:
        chunk = f.read(min(1 << 20, left))
        if not chunk:
            return
        left -= len(chunk)
        yield chunk


OUT_MEMBER_RE = re.compile(r"^out/(status\.json|netcheck\.json|stdout\.bin|stderr\.bin|fakenet\.jsonl|trace/t\.\d{1,9})$")


def _stream(src: str, handler, timeout: float):
    """Run `docker cp <src> -` and hand its stdout to handler(fileobj); kill it after `timeout`."""
    exe = docker_bin()
    if exe is None:
        raise DockerError("docker CLI not found")
    proc = subprocess.Popen([exe, "cp", src, "-"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        return handler(proc.stdout, proc)
    finally:
        timer.cancel()
        for f in (proc.stdout,):
            try:
                f.close()
            except OSError:
                pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.communicate(timeout=30)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass


def extract_out_tar(fileobj, dest: Path, *, max_total: int, max_members: int = 8192) -> dict:
    """Write the members of a /rebox/out tar stream that match OUT_MEMBER_RE into dest/.

    Only regular files whose whole name matches one of the fixed names the runner
    writes are accepted; everything else (other names, '..', absolute paths,
    links, devices, fifos) is listed under "rejected" and never written."""
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    (dest / "trace").mkdir(mode=0o700, exist_ok=True)
    res = {"files": 0, "bytes": 0, "rejected": [], "truncated": []}
    try:
        with tarfile.open(fileobj=fileobj, mode="r|") as tf:
            for n, m in enumerate(tf):
                if n >= max_members:
                    res["rejected"].append(f"more than {max_members} members")
                    break
                name = m.name[2:] if m.name.startswith("./") else m.name
                if m.isdir() and name.rstrip("/") in ("out", "out/trace"):
                    continue
                if not m.isreg() or not OUT_MEMBER_RE.match(name):
                    if len(res["rejected"]) < 50:
                        res["rejected"].append(f"{'reg' if m.isreg() else 'type ' + repr(m.type)} {safe_name(name, 80)}")
                    continue
                rel = name[len("out/"):]
                left = max_total - res["bytes"]
                if left <= 0:
                    res["truncated"].append(rel)
                    continue
                if (dest / rel).exists() or (dest / rel).is_symlink():
                    res["rejected"].append(f"duplicate {safe_name(rel, 80)}")
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                size, _sha = _write_new(dest / rel, _member_chunks(f, min(m.size, left)))
                if size < m.size:
                    res["truncated"].append(f"{rel} ({size} of {m.size} bytes)")
                res["files"] += 1
                res["bytes"] += size
    except tarfile.TarError as e:
        res["rejected"].append(f"tar error: {e}")
    return res


def collect_out(cid: str, dest: Path, *, max_total: int, max_members: int = 8192, timeout: float = 300) -> dict:
    """Stream /rebox/out out of the (stopped) container into dest/."""
    return _stream(f"{cid}:/rebox/out", lambda f, _p: extract_out_tar(f, dest, max_total=max_total,
                                                                      max_members=max_members), timeout)


def save_first_member(fileobj, dest_dir: Path, kind: str, path: str, *, max_bytes: int) -> dict:
    """Save the first member of a tar stream if it is a regular file, as <kind>_<name>_<sha12>.bin (0600)."""
    tmp = dest_dir / f".partial-{os.getpid()}-{time.monotonic_ns()}"
    try:
        with tarfile.open(fileobj=fileobj, mode="r|") as tf:
            m = tf.next()
            if m is None:
                return {"skipped": "empty archive"}
            if m.issym() or m.islnk():
                return {"skipped": f"link to {m.linkname[:200]!r}", "link": m.linkname[:400]}
            if m.isdir():
                return {"skipped": "directory"}
            if not m.isreg():
                return {"skipped": f"special file type {m.type!r}"}
            f = tf.extractfile(m)
            if f is None:
                return {"skipped": "unreadable member"}
            size, sha = _write_new(tmp, _member_chunks(f, min(m.size, max_bytes)))
            final = dest_dir / f"{kind}_{safe_name(os.path.basename(path), 48)}_{sha[:12]}.bin"
            if final.exists() or final.is_symlink():
                tmp.unlink()
            else:
                os.rename(tmp, final)
            out = {"saved": {"file": final, "size": size, "sha256": sha, "orig_size": m.size,
                             "mode": oct(m.mode & 0o7777)}}
            if size < m.size:
                out["saved"]["truncated"] = True
            return out
    except tarfile.TarError as e:
        return {"skipped": f"not copied: {e}"[:200]}
    finally:
        if tmp.exists():
            tmp.unlink()


def copy_out_file(cid: str, path: str, dest_dir: Path, kind: str, *, max_bytes: int, timeout: float = 120) -> dict:
    """Copy one regular file out of the container (directories, links, devices are reported, not written)."""
    def handler(f, proc):
        r = save_first_member(f, dest_dir, kind, path, max_bytes=max_bytes)
        if r.get("skipped", "").startswith(("not copied", "empty")):
            try:
                err = proc.stderr.read(400).decode("utf-8", "replace").strip()
            except (OSError, ValueError):
                err = ""
            if err:
                r["skipped"] = f"not copied: {err}"[:200]
        return r
    return _stream(f"{cid}:{path}", handler, timeout)


def read_small(cid: str, path: str, max_bytes: int = 1 << 16) -> bytes | None:
    """Content of a small regular file in the container (for /etc/hosts and friends)."""
    p = run(["cp", f"{cid}:{path}", "-"], timeout=60, check=False)
    if p.returncode != 0:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(p.stdout[:max_bytes * 2 + 65536]), mode="r:") as tf:
            m = tf.next()
            if m is None or not m.isreg() or m.size > max_bytes:
                return None
            f = tf.extractfile(m)
            return f.read(max_bytes) if f else None
    except tarfile.TarError:
        return None


# ---- file system changes ----------------------------------------------------------------

class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 30):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def _engine_socket() -> str | None:
    host = os.environ.get("DOCKER_HOST")
    if not host:
        try:
            p = run(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], timeout=15, check=False)
            host = p.stdout.decode().strip() if p.returncode == 0 else ""
        except DockerError:
            host = ""
    if host.startswith("unix://"):
        return host[len("unix://"):]
    return None


def changes(cid: str) -> tuple[list[tuple[str, str]], str]:
    """[(kind A/C/D, path)] via the Engine API (JSON, immune to newlines in names), else `docker diff`."""
    sock = _engine_socket()
    if sock and os.path.exists(sock):
        try:
            conn = _UnixHTTP(sock)
            conn.request("GET", f"/containers/{urllib.parse.quote(cid)}/changes")
            r = conn.getresponse()
            body = r.read(64 << 20)
            conn.close()
            if r.status == 200:
                items = json.loads(body or b"null") or []
                kinds = {0: "C", 1: "A", 2: "D"}
                return [(kinds.get(i.get("Kind"), "?"), str(i.get("Path"))) for i in items], "engine-api"
        except (OSError, ValueError, http.client.HTTPException):
            pass
    p = run(["diff", cid], timeout=120, check=False)
    out = []
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        if len(line) > 2 and line[0] in "ACD" and line[1] == " ":
            out.append((line[0], line[2:]))
    return out, "docker diff (line-based; a file name containing a newline can split into bogus entries)"


# ---- lifecycle ----------------------------------------------------------------------------

def inspect(cid: str) -> dict:
    p = run(["inspect", "--type", "container", cid], timeout=30)
    return json.loads(p.stdout)[0]


def remove(cid: str) -> bool:
    p = run(["rm", "-f", "-v", cid], timeout=120, check=False)
    gone = run(["ps", "-a", "-q", "--no-trunc", "--filter", f"id={cid}"], timeout=30, check=False)
    return gone.returncode == 0 and not gone.stdout.strip()


def list_runs() -> list[dict]:
    p = run(["ps", "-a", "--no-trunc", "--filter", f"label={LABEL}", "--format", "{{json .}}"], timeout=30,
            check=False)
    out = []
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        labels = dict(kv.split("=", 1) for kv in (d.get("Labels") or "").split(",") if "=" in kv)
        out.append({"id": d.get("ID"), "name": d.get("Names"), "state": d.get("State"), "labels": labels})
    return out


def stale_runs(now: float | None = None) -> list[dict]:
    """rebox-live containers whose owning rebox process is gone or whose deadline has passed."""
    now = now or time.time()
    out = []
    for c in list_runs():
        lb = c["labels"]
        if not (c["name"] or "").startswith(NAME_PREFIX):
            continue
        try:
            deadline = float(lb.get(f"{LABEL}.deadline", "0"))
            owner = int(lb.get(f"{LABEL}.pid", "0"))
        except ValueError:
            deadline, owner = 0, 0
        # A container owned by another machine sharing this daemon only counts as stale after its deadline.
        alive = lb.get(f"{LABEL}.host") != socket.gethostname()
        if owner > 0 and not alive:
            try:
                os.kill(owner, 0)
                alive = True
            except ProcessLookupError:
                alive = False
            except PermissionError:
                alive = True
        if not alive or now > deadline:
            out.append(c)
    return out
