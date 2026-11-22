"""rebox live: run a Linux ELF for real, traced, in a network-less Docker container.

    rebox live <sample> [--timeout 60] [--out DIR] [--max-chars 6000] [--arg A ...]
                        [--user] [--fakenet] [--memory 1g] [--cpus 2] [--pids 256]
    rebox live --cleanup                 remove leftover rebox-live containers
    rebox live-setup [--no-cache]        build the image (needs network once)
    rebox live-summarize <out_dir>       re-render the summary of an earlier run

Also `python -m rebox.live ...` (the first word may be omitted for a run).
The CLI mounts this module through `add_parsers(subparsers)` and `main(args)`.
Isolation, trace mechanism and limits: see LIVE.md.

stdout is always exactly one JSON object; diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from . import live_docker as ld
from . import live_elf, live_summary
from .summary import SCHEMA

TOOL_DIR = Path(__file__).resolve().parents[2]
DEFAULT_RUNS_DIR = TOOL_DIR.parent.parent / "tmp" / "rebox-runs"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ISOLATION = 3
EXIT_TOOL = 4
EXIT_UNSUPPORTED = 5
EXIT_BACKSTOP = 6
EXIT_INTERRUPTED = 130

MAX_DUMP_FILE = 64 << 20
MAX_COLLECT = 1 << 30  # traces + output + status, per run
IGNORED_CHANGES = ("/rebox", "/tmp")  # exact paths; children of /rebox are rebox's own
RUNNER_EXIT = {0: "sample run", 3: "refused (isolation check failed)", 4: "runner error"}


class Interrupted(BaseException):
    pass


def log(msg: str) -> None:
    print(f"rebox live: {msg}", file=sys.stderr, flush=True)


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fail(code: int, error: str, **extra) -> int:
    emit({"schema": SCHEMA, "ok": False, "mode": "live", "exit": code, "error": error, **extra})
    return code


def parse_size(s: str) -> int:
    m = re.fullmatch(r"(\d+)([kmgKMG]?)[bB]?", s.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"bad size {s!r}")
    return int(m.group(1)) * {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[m.group(2).lower()]


# ---- argument parsing ----------------------------------------------------------------------

def add_parsers(subparsers) -> None:
    """Add `live`, `live-setup` and `live-summarize` to an argparse subparsers object."""
    r = subparsers.add_parser("live", help="run a Linux ELF for real under a tracer in a network-less container")
    r.add_argument("sample", nargs="?")
    r.add_argument("--timeout", type=int, default=60, help="seconds the sample may run (default 60)")
    r.add_argument("--out", help="output directory (must be new or empty)")
    r.add_argument("--max-chars", type=int, default=6000, help="size limit of the printed summary (default 6000)")
    r.add_argument("--arg", action="append", default=[], metavar="ARG",
                   help="argument for the sample (repeatable; use --arg=-x for dash values)")
    r.add_argument("--user", action="store_true",
                   help="run as unprivileged uid 1000 instead of root-without-capabilities")
    r.add_argument("--fakenet", action="store_true",
                   help="answer DNS and accept TCP inside the container's loopback-only namespace (no route out)")
    r.add_argument("--memory", default="1g", help="memory limit (default 1g)")
    r.add_argument("--cpus", default="2", help="CPU limit (default 2)")
    r.add_argument("--pids", type=int, default=256, help="process/thread limit (default 256)")
    r.add_argument("--max-dump", type=parse_size, default=256 << 20,
                   help="total size of files copied out of the container (default 256m)")
    r.add_argument("--max-output", type=parse_size, default=1 << 20,
                   help="bytes kept of the sample's stdout and of its stderr (default 1m)")
    r.add_argument("--max-file", type=parse_size, default=512 << 20,
                   help="largest file any process may write inside the container (RLIMIT_FSIZE, default 512m)")
    r.add_argument("--max-disk", type=parse_size, default=2 << 30,
                   help="stop the run when the container has used this much disk (default 2g)")
    r.add_argument("--strsize", type=int, default=4096, help="strace -s: bytes shown per string/buffer (default 4096)")
    r.add_argument("--cleanup", action="store_true",
                   help="remove leftover rebox-live containers (owner gone or past deadline) and exit")
    r.set_defaults(_live_cmd="run")

    s = subparsers.add_parser("live-setup", help="build the rebox live container image (needs network once)")
    s.add_argument("--no-cache", action="store_true", help="rebuild every layer")
    s.set_defaults(_live_cmd="setup")

    z = subparsers.add_parser("live-summarize", help="re-render the summary of an existing live run directory")
    z.add_argument("out_dir")
    z.add_argument("--max-chars", type=int, default=6000)
    z.set_defaults(_live_cmd="summarize")


def main(args) -> int:
    os.umask(0o077)
    cmd = getattr(args, "_live_cmd", "run")
    try:
        if cmd == "setup":
            return cmd_setup(args)
        if cmd == "summarize":
            return cmd_summarize(args)
        if args.cleanup:
            return cmd_cleanup(args)
        return cmd_run(args)
    except Interrupted:
        return fail(EXIT_INTERRUPTED, "interrupted")
    except Exception as e:  # last resort: still one JSON object and a non-zero exit
        return fail(EXIT_TOOL, f"{type(e).__name__}: {e}")


# ---- setup / cleanup / summarize ----------------------------------------------------------

def cmd_setup(a) -> int:
    if ld.daemon() is None:
        return fail(EXIT_ISOLATION, "Docker daemon not reachable")
    log(f"building {ld.IMAGE_TAG} from {ld.DOCKER_DIR} (network is needed for this step only)")
    t0 = time.monotonic()
    p = ld.build_image(no_cache=a.no_cache)
    if p.returncode != 0:
        tail = p.stderr.decode("utf-8", "replace").strip().splitlines()[-15:]
        for line in tail:
            log(f"build: {line}")
        return fail(EXIT_TOOL, "image build failed", detail="\n".join(tail)[-1500:])
    img = ld.image()
    if img is None:
        return fail(EXIT_TOOL, "image built but not found afterwards")
    pk = ld.image_packages(img["id"]) or ""
    versions = {}
    for line in pk.splitlines():
        name, _, ver = line.partition(" ")
        if name.split(":")[0] in ("strace", "qemu-user", "python3", "libc6"):
            versions[name] = ver
    emit({"schema": SCHEMA, "ok": True, "mode": "live-setup", "image": img["tag"], "image_id": img["id"],
          "arch": img["arch"], "build_s": round(time.monotonic() - t0, 1), "versions": versions})
    return EXIT_OK


def cmd_cleanup(a) -> int:
    if ld.daemon() is None:
        return fail(EXIT_ISOLATION, "Docker daemon not reachable")
    removed, failed = [], []
    for c in ld.stale_runs():
        (removed if ld.remove(c["id"]) else failed).append(c["name"])
    emit({"schema": SCHEMA, "ok": not failed, "mode": "live-cleanup", "removed": removed, "failed": failed,
          "remaining": [c["name"] for c in ld.list_runs()]})
    return EXIT_OK if not failed else EXIT_TOOL


def cmd_summarize(a) -> int:
    out = Path(a.out_dir).expanduser().resolve()
    if not (out / "run.json").is_file():
        return fail(EXIT_USAGE, f"{out} has no run.json")
    sys.stdout.write(live_summary.render(out, a.max_chars) + "\n")
    return EXIT_OK


# ---- run ------------------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def prepare_out_dir(arg: str | None, sha: str) -> Path:
    if arg:
        out = Path(arg).expanduser().resolve()
        if out.exists() and any(out.iterdir()):
            raise ValueError(f"--out {out} exists and is not empty")
    else:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        out = DEFAULT_RUNS_DIR / f"{sha[:12]}-live-{stamp}"
        n = 1
        while out.exists():
            out = DEFAULT_RUNS_DIR / f"{sha[:12]}-live-{stamp}-{n}"
            n += 1
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    return out


def _signal_guard():
    """Turn SIGTERM/SIGHUP into Interrupted (SIGINT already raises KeyboardInterrupt)."""
    def handler(signum, frame):
        raise Interrupted(signal.Signals(signum).name)
    old = {}
    for s in (signal.SIGTERM, signal.SIGHUP):
        try:
            old[s] = signal.signal(s, handler)
        except (ValueError, OSError):  # not the main thread
            pass
    return old


def _restore(old):
    for s, h in old.items():
        try:
            signal.signal(s, h)
        except (ValueError, OSError):
            pass


def _no_interrupts():
    old = {}
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            old[s] = signal.signal(s, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    return old


def cmd_run(a) -> int:
    if not a.sample:
        return fail(EXIT_USAGE, "a sample path is required (or --cleanup)")
    sample = Path(a.sample).expanduser()
    if not sample.is_file():
        return fail(EXIT_USAGE, f"sample not found: {a.sample}")
    sample = sample.resolve()
    if not 0 < a.timeout <= 3600:
        return fail(EXIT_USAGE, "--timeout must be between 1 and 3600 seconds")
    if not 16 <= a.pids <= 4096:
        return fail(EXIT_USAGE, "--pids must be between 16 and 4096")
    try:
        mem_bytes = parse_size(a.memory)
    except argparse.ArgumentTypeError as e:
        return fail(EXIT_USAGE, str(e))
    if mem_bytes < 64 << 20:
        return fail(EXIT_USAGE, "--memory must be at least 64m")
    try:
        if not 0 < float(a.cpus) <= 64:
            raise ValueError
    except ValueError:
        return fail(EXIT_USAGE, "--cpus must be a positive number")

    # Identity and architecture before anything touches Docker.
    try:
        ident = live_elf.parse(sample)
    except live_elf.NotElf as e:
        return fail(EXIT_UNSUPPORTED, f"unsupported input: {e}; rebox live runs Linux ELF executables")
    sup = live_elf.support(ident)
    if sup is None:
        return fail(EXIT_UNSUPPORTED,
                    f"unsupported architecture: {ident['arch']} ({ident['class']}-bit, {ident['endian']}); "
                    "rebox live supports aarch64 (native), x86_64 and x86 (QEMU user mode)", sample=ident)
    if ident["elf_type"] not in ("exec", "dyn"):
        return fail(EXIT_UNSUPPORTED, f"unsupported ELF type {ident['elf_type']}: not an executable")
    mode, qemu = sup

    srv = ld.daemon()
    if srv is None:
        return fail(EXIT_ISOLATION, "Docker daemon not reachable; the sample was not run")
    if srv.get("os") != "linux" or srv.get("arch") not in ("arm64", "aarch64"):
        return fail(EXIT_ISOLATION, f"unexpected Docker server {srv}; rebox live expects linux/arm64")
    img = ld.image()
    if img is None:
        return fail(EXIT_ISOLATION, f"image {ld.IMAGE_TAG} not built; run `rebox live-setup` first")
    if img["labels"].get(ld.LABEL) != "image" or img["volumes"] or img["arch"] not in ("arm64", "aarch64"):
        return fail(EXIT_ISOLATION, f"image {ld.IMAGE_TAG} is not a rebox-live image as expected "
                                    f"(labels {img['labels']}, volumes {img['volumes']}, arch {img['arch']})")

    for c in ld.stale_runs():
        log(f"removing leftover container {c['name']}")
        ld.remove(c["id"])

    sha = sha256_file(sample)
    size = sample.stat().st_size
    if size > (512 << 20):
        return fail(EXIT_USAGE, "sample larger than 512 MiB")
    try:
        out = prepare_out_dir(a.out, sha)
    except (OSError, ValueError) as e:
        return fail(EXIT_USAGE, str(e))
    log(f"output directory {out}")

    inner_name = ld.safe_name(sample.name, 64) or "sample"
    sample_path = f"/tmp/{inner_name}"
    user_mode = bool(a.user)
    drop_uid = ld.SAMPLE_UID if (user_mode and a.fakenet) else None
    backstop = a.timeout + max(30, a.timeout)
    t_start = time.time()
    name = f"{ld.NAME_PREFIX}{sha[:12]}-{os.getpid()}-{secrets.token_hex(3)}"
    labels = {ld.LABEL: ld.LABEL_RUN, f"{ld.LABEL}.pid": str(os.getpid()),
              f"{ld.LABEL}.host": socket.gethostname(), f"{ld.LABEL}.sha256": sha,
              f"{ld.LABEL}.deadline": str(int(t_start + backstop + 600))}
    create = ld.create_args(name, img["id"], labels=labels, user_mode=user_mode, fakenet=a.fakenet,
                            memory=str(mem_bytes), cpus=str(a.cpus), pids=a.pids, fsize=a.max_file)
    pk = ld.image_packages(img["id"]) or ""
    versions = dict(line.split(" ", 1) for line in pk.splitlines() if " " in line)
    strace_v = versions.get("strace:arm64", "?")
    qemu_v = versions.get("qemu-user:arm64", "?")
    engine = (f"strace {strace_v} (native arm64)" if mode == "native"
              else f"strace {strace_v} over {qemu} (qemu-user {qemu_v})")
    isolation = ("docker --network none (+in-container check: only lo, no route), no mounts/volumes, "
                 f"cap-drop ALL{' (+NET_ADMIN/SETPCAP for fakenet setup, dropped before exec)' if a.fakenet else ''}, "
                 f"no-new-privileges, pids {a.pids}, memory {a.memory}, cpus {a.cpus}")
    meta = {
        "tool": "rebox live", "sample_name": sample.name, "sample_path": str(sample), "sha256": sha, "size": size,
        "identity": ident, "mode": mode, "qemu": qemu, "engine": engine, "sample_in_container": sample_path,
        "image": img, "image_short": f"{img['tag']} {str(img['id'])[7:19]}", "image_packages": versions,
        "docker_server": srv, "container_name": name, "docker_create": create, "isolation": isolation,
        "run_as": "uid 1000 (user)" if user_mode else "root (uid 0) without capabilities",
        "fakenet": bool(a.fakenet), "timeout": a.timeout, "backstop_s": backstop, "args": a.arg,
        "errors": [], "stop": None,
    }
    job = {"sample": sample_path, "args": list(a.arg), "timeout": a.timeout, "mode": mode, "qemu": qemu,
           "fakenet": bool(a.fakenet), "drop_uid": drop_uid, "max_output": a.max_output, "max_disk": a.max_disk,
           "strsize": max(64, min(a.strsize, 1 << 16))}

    old_handlers = _signal_guard()
    cid = None
    code = EXIT_OK
    try:
        code = _run_container(a, out, meta, job, create, sample, sample_path, user_mode, mem_bytes, backstop)
        cid = meta.get("container_id")
    except (KeyboardInterrupt, Interrupted) as e:
        meta["errors"].append(f"interrupted ({type(e).__name__} {e})")
        meta["stop"] = "interrupted"
        code = EXIT_INTERRUPTED
    except ld.DockerError as e:
        meta["errors"].append(f"docker: {e}")
        code = EXIT_TOOL
    except Exception as e:  # noqa: BLE001
        meta["errors"].append(f"{type(e).__name__}: {e}")
        code = EXIT_TOOL
    finally:
        guard = _no_interrupts()  # removal must not be interrupted
        try:
            cid = meta.get("container_id") or cid
            if cid or meta.get("create_attempted"):
                target = cid or name
                meta["container_removed"] = ld.remove(target)
                if not meta["container_removed"]:
                    meta["errors"].append(f"container {name} could not be removed; `rebox live --cleanup` retries")
                    log(f"WARNING: container {name} still present")
        finally:
            _restore(guard)
            _restore(old_handlers)
    meta["wall_s"] = round(time.time() - t_start, 2)
    _write_json(out / "run.json", meta)

    if code == EXIT_INTERRUPTED:
        return fail(code, "interrupted; container removed" if meta.get("container_removed") else "interrupted",
                    out_dir=str(out))
    if code == EXIT_ISOLATION:
        return fail(code, meta.get("refusal") or "isolation could not be verified; sample was not run",
                    out_dir=str(out), problems=meta.get("problems"))
    if code != EXIT_OK and meta.get("stop") not in ("backstop_kill",):
        return fail(code, "; ".join(meta["errors"])[:800] or f"failed with exit {code}", out_dir=str(out))
    try:
        text = live_summary.render(out, a.max_chars)
    except Exception as e:  # noqa: BLE001
        return fail(EXIT_TOOL, f"summary failed: {type(e).__name__}: {e}", out_dir=str(out))
    (out / "summary.json").write_text(text + "\n")
    if meta.get("stop") == "backstop_kill":
        return fail(EXIT_BACKSTOP, f"container killed by the host backstop after {backstop}s",
                    out_dir=str(out), summary_file=str(out / "summary.json"))
    sys.stdout.write(text + "\n")
    return EXIT_OK


def _write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str))
    os.replace(tmp, path)


def _run_container(a, out: Path, meta: dict, job: dict, create: list[str], sample: Path, sample_path: str,
                   user_mode: bool, mem_bytes: int, backstop: int) -> int:
    meta["create_attempted"] = True
    p = ld.run(create, timeout=120)
    cid = p.stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise ld.DockerError(f"unexpected container id {cid[:80]!r}")
    meta["container_id"] = cid

    info = ld.inspect(cid)
    problems = ld.verify(info, user_mode=user_mode, fakenet=a.fakenet, memory_bytes=mem_bytes, pids=a.pids)
    meta["inspect_check"] = {"ok": not problems, "problems": problems}
    if problems:
        meta["refusal"] = "container configuration does not match the required isolation; sample was not run"
        meta["problems"] = problems
        meta["stop"] = "refused"
        return EXIT_ISOLATION

    uid = ld.SAMPLE_UID if user_mode else 0
    data = sample.read_bytes()
    tar = ld.tar_bytes([("rebox/job.json", json.dumps(job).encode(), 0o644, 0),
                        (sample_path.lstrip("/"), data, 0o755, uid)])
    ld.run(["cp", "-", f"{cid}:/"], input=tar, timeout=300)

    ld.run(["start", cid], timeout=120)
    t0 = time.monotonic()
    meta["started"] = time.time()
    wait = None
    try:
        exe = ld.docker_bin()
        wait = subprocess.run([exe, "wait", cid], capture_output=True, timeout=backstop, stdin=subprocess.DEVNULL)
        runner_exit = wait.stdout.decode().strip()
        meta["runner_exit"] = int(runner_exit) if runner_exit.lstrip("-").isdigit() else runner_exit
    except subprocess.TimeoutExpired:
        meta["stop"] = "backstop_kill"
        meta["errors"].append(f"container still running after the {backstop}s backstop; killed from the host")
        ld.run(["kill", cid], timeout=60, check=False)
        ld.run(["wait", cid], timeout=60, check=False)
    meta["container_s"] = round(time.monotonic() - t0, 2)
    try:
        state = ld.inspect(cid).get("State") or {}
        meta["container_state"] = {k: state.get(k) for k in ("ExitCode", "OOMKilled", "Error")}
    except (ld.DockerError, ValueError, IndexError):
        state = {}

    # ---- collect (the container is stopped; everything below is untrusted data)
    meta["collect"] = ld.collect_out(cid, out / "container", max_total=MAX_COLLECT)
    status = _read_json(out / "container" / "status.json") or {}
    if meta.get("stop") is None and state.get("OOMKilled") and not status.get("stop"):
        meta["stop"] = "oom_killed"
        meta["errors"].append(f"container hit the memory limit ({a.memory}); the runner was killed")
    if meta.get("stop") is None:
        meta["stop"] = status.get("stop") if isinstance(status.get("stop"), str) else "unknown"
    if status.get("stop") == "refused" or meta.get("runner_exit") == 3:
        nc = _read_json(out / "container" / "netcheck.json") or {}
        meta["refusal"] = "in-container isolation self-check failed; sample was not run"
        meta["problems"] = (nc.get("reasons") or status.get("errors") or [])[:20]
        meta["stop"] = "refused"
        return EXIT_ISOLATION
    if status.get("stop") == "runner_error" or (meta.get("runner_exit") == 4 and meta["stop"] != "backstop_kill"):
        meta["errors"].append("in-container runner failed: " + "; ".join(map(str, status.get("errors") or []))[:400])
        meta["stop"] = "runner_error"
        return EXIT_TOOL

    _collect_changes(cid, out, meta, status, sample_path, a.max_dump)
    return EXIT_OK


def _read_json(path: Path):
    try:
        with open(path, "rb") as f:
            data = f.read(8 << 20)
        return json.loads(data)
    except (OSError, ValueError):
        return None


def _collect_changes(cid: str, out: Path, meta: dict, status: dict, sample_path: str, max_dump: int) -> None:
    changes, source = ld.changes(cid)
    meta["fs_changes_source"] = source
    _write_json(out / "fs_changes.json", {"source": source, "changes": changes[:100000]})
    # Paths that were already there when the runner started, i.e. put there by the
    # container runtime (OrbStack adds its CA certificate), not by the sample.
    pre = status.get("preexisting_new") if isinstance(status.get("preexisting_new"), dict) else {}
    fs = {"added": [], "changed": [], "deleted": []}
    kinds = {"A": "added", "C": "changed", "D": "deleted"}
    ignored = []

    dumps_dir = out / "dumps"
    dumps_dir.mkdir(mode=0o700, exist_ok=True)
    dumps, skipped = [], []
    total = 0
    for kind, path in changes:
        if kind not in kinds or path in IGNORED_CHANGES or path == sample_path or path.startswith("/rebox/"):
            continue
        before = pre.get(path) if isinstance(pre.get(path), dict) else None
        if kind == "D":
            fs["deleted"].append(path)
            continue
        if before is not None and str(before.get("mode", "")).startswith("0o40"):
            ignored.append(path)  # injected directory
            continue
        if len(dumps) >= 500:
            fs[kinds[kind]].append(path)
            skipped.append(f"{path}: more than 500 files")
            continue
        left = max_dump - total
        if left <= 0:
            fs[kinds[kind]].append(path)
            skipped.append(f"{path}: total dump budget {max_dump} bytes used up")
            continue
        dkind = "added" if kind == "A" else "modified"
        r = ld.copy_out_file(cid, path, dumps_dir, dkind, max_bytes=min(MAX_DUMP_FILE, left))
        if "saved" in r:
            s = r["saved"]
            if before is not None and before.get("sha256") == s["sha256"]:
                ignored.append(path)  # injected file, unchanged by the sample
                try:
                    Path(s["file"]).unlink()
                except OSError:
                    pass
                continue
            fs[kinds[kind]].append(path)
            total += s["size"]
            d = {"kind": dkind, "file": str(Path(s["file"]).relative_to(out)), "size": s["size"],
                 "sha256": s["sha256"], "path": path, "mode": s["mode"]}
            if s.get("truncated"):
                d["truncated_from"] = s["orig_size"]
            dumps.append(d)
        elif r.get("skipped") == "directory":
            if kind == "A":
                fs["added"].append(path + "/")  # changed directories only mean "something inside changed"
        else:
            fs[kinds[kind]].append(path + (f" -> {r['link'][:200]}" if r.get("link") else ""))
            if not r.get("link"):
                skipped.append(f"{path}: {r.get('skipped')}")
    meta["fs_changes"] = fs
    meta["fs_changes_ignored"] = ignored

    # Docker-managed bind-mounted files: compare with the runner's baseline.
    etc_changed = []
    base = status.get("etc_baseline") if isinstance(status.get("etc_baseline"), dict) else {}
    for path in ("/etc/hosts", "/etc/resolv.conf", "/etc/hostname"):
        now = ld.read_small(cid, path)
        before = base.get(path)
        if now is None or not isinstance(before, str):
            continue
        if now.decode("utf-8", "replace") != before:
            etc_changed.append(path)
            if total < max_dump:
                name = dumps_dir / f"etc_{ld.safe_name(os.path.basename(path))}_{hashlib.sha256(now).hexdigest()[:12]}.bin"
                if not name.exists():
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        f.write(now)
                total += len(now)
                dumps.append({"kind": "etc_modified", "file": str(name.relative_to(out)), "size": len(now),
                              "sha256": hashlib.sha256(now).hexdigest(), "path": path})
    meta["etc_changed"] = etc_changed
    meta["dumps"] = dumps
    meta["dumps_skipped"] = skipped


# ---- python -m rebox.live --------------------------------------------------------------------

class _JsonArgParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        log(message)
        fail(EXIT_USAGE, f"usage: {message}")
        sys.exit(EXIT_USAGE)


def _standalone(argv: list[str]) -> int:
    p = _JsonArgParser(prog="python -m rebox.live", description="rebox live (standalone entry point)")
    sub = p.add_subparsers(dest="cmd", required=True)
    add_parsers(sub)
    aliases = {"setup": "live-setup", "summarize": "live-summarize", "run": "live"}
    if argv and argv[0] in aliases:
        argv = [aliases[argv[0]], *argv[1:]]
    elif not argv or argv[0] not in ("live", "live-setup", "live-summarize", "-h", "--help"):
        argv = ["live", *argv]
    return main(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(_standalone(sys.argv[1:]))
