"""rebox command line.

    rebox run <sample> [--timeout 60] [--out DIR] [--max-chars 6000] [--arg A ...] [--env K=V ...]
              [--stdin TEXT | --stdin-hex HEX | --stdin-file PATH]
    rebox summarize <out_dir> [--max-chars N]
    rebox setup-elf [--force] [--venv-only | --rootfs-only]

`run` is the outer stage: it hashes the sample, prepares the output directory,
re-executes this module under sandbox-exec (`_inner` with the Speakeasy
environment for PE, `_inner-elf` with the Qiling environment .venv-elf for
ELF; the outer stage only looks at the first four bytes to choose), then reads
what the inner stage wrote and prints one compact JSON object on stdout.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import elfsetup, sandbox, summary

TOOL_DIR = Path(__file__).resolve().parents[2]
# REBOX_RUNS moves the default output root (the tests point it at a temp dir).
DEFAULT_RUNS_DIR = Path(os.environ.get("REBOX_RUNS") or TOOL_DIR.parent.parent / "tmp" / "rebox-runs")
VERSION = "rebox 0.1.0"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_SANDBOX = 3
EXIT_TOOL = 4
EXIT_UNSUPPORTED = 5
EXIT_TIMEOUT = 6


def log(msg: str) -> None:
    print(f"rebox: {msg}", file=sys.stderr, flush=True)


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fail(code: int, error: str, **extra) -> int:
    emit({"schema": summary.SCHEMA, "ok": False, "exit": code, "error": error, **extra})
    return code


class JsonArgParser(argparse.ArgumentParser):
    """Usage errors still produce exactly one JSON object on stdout."""

    def error(self, message):
        self.print_usage(sys.stderr)
        log(message)
        fail(EXIT_USAGE, f"usage: {message}")
        sys.exit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    p = JsonArgParser(prog="rebox", description="Sandboxed Speakeasy (PE) / Qiling (ELF) emulation with a compact JSON report")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="emulate a sample")
    r.add_argument("sample")
    r.add_argument("--timeout", type=int, default=60, help="emulation time budget in seconds (default 60)")
    r.add_argument("--out", help="output directory (must be new or empty)")
    r.add_argument("--max-chars", type=int, default=6000, help="size limit of the printed summary (default 6000)")
    r.add_argument("--arg", action="append", default=[], metavar="ARG",
                   help="argument for the emulated process (repeatable; use --arg=-x for dash values)")
    r.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                   help="ELF only: environment variable for the emulated process (repeatable)")
    sin = r.add_mutually_exclusive_group()
    sin.add_argument("--stdin", metavar="TEXT",
                     help="ELF only: standard input for the emulated program, this text as UTF-8, taken literally "
                          "(no escapes, no newline added), then end-of-file")
    sin.add_argument("--stdin-hex", metavar="HEX", help="ELF only: standard input as hex bytes (spaces allowed)")
    sin.add_argument("--stdin-file", metavar="PATH", help="ELF only: standard input read from this file")
    r.add_argument("--max-api", type=int, default=None,
                   help="stop a run after this many API calls (PE) or syscalls (ELF); default 10000")
    r.add_argument("--trace-mem", action="store_true",
                   help="PE only: per-region read/write/exec counters and instruction counts (much slower)")
    r.add_argument("--children", action="store_true",
                   help="PE only: also emulate child processes the sample creates")
    r.add_argument("--no-sandbox", action="store_true", help="DANGEROUS: run the emulator without sandbox-exec")

    s = sub.add_parser("summarize", help="re-render the summary of an existing run directory")
    s.add_argument("out_dir")
    s.add_argument("--max-chars", type=int, default=6000)

    i = sub.add_parser("_inner", help=argparse.SUPPRESS)
    i.add_argument("sample")
    i.add_argument("--out", required=True)
    i.add_argument("--timeout", type=int, required=True)
    i.add_argument("--arg", action="append", default=[])
    i.add_argument("--max-api", type=int, default=10000)
    i.add_argument("--trace-mem", action="store_true")
    i.add_argument("--children", action="store_true")
    i.add_argument("--sandboxed", action="store_true")

    e = sub.add_parser("_inner-elf", help=argparse.SUPPRESS)
    e.add_argument("sample")
    e.add_argument("--out", required=True)
    e.add_argument("--timeout", type=int, required=True)
    e.add_argument("--arg", action="append", default=[])
    e.add_argument("--env", action="append", default=[])
    e.add_argument("--max-syscalls", type=int, default=10000)
    e.add_argument("--rootfs-cache")
    e.add_argument("--stdin-file")
    e.add_argument("--sandboxed", action="store_true")

    st = sub.add_parser("setup-elf", help="build the Qiling environment and fetch the Linux rootfs (needs network)")
    st.add_argument("--force", action="store_true", help="delete and rebuild what exists")
    g = st.add_mutually_exclusive_group()
    g.add_argument("--venv-only", action="store_true", help="only build .venv-elf")
    g.add_argument("--rootfs-only", action="store_true", help="only fetch elf-rootfs")
    from . import live          # real execution in a network-less container (see LIVE.md)
    live.add_parsers(sub)
    return p


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
        out = DEFAULT_RUNS_DIR / f"{sha[:12]}-{stamp}"
        n = 1
        while out.exists():
            out = DEFAULT_RUNS_DIR / f"{sha[:12]}-{stamp}-{n}"
            n += 1
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    return out


MAX_STDIN = 1 << 20


def stdin_bytes(a) -> bytes | None:
    """The --stdin/--stdin-hex/--stdin-file content, or None; ValueError on bad input."""
    if a.stdin is not None:
        data = a.stdin.encode("utf-8", "surrogateescape")
    elif a.stdin_hex is not None:
        try:
            data = bytes.fromhex("".join(a.stdin_hex.split()))
        except ValueError:
            raise ValueError("--stdin-hex is not valid hex")
    elif a.stdin_file is not None:
        path = Path(a.stdin_file).expanduser()
        if not path.is_file():
            raise ValueError(f"--stdin-file not found: {a.stdin_file}")
        with open(path, "rb") as f:
            data = f.read(MAX_STDIN + 1)
    else:
        return None
    if len(data) > MAX_STDIN:
        raise ValueError(f"standard input is over the {MAX_STDIN} byte limit")
    return data


def cmd_run(a) -> int:
    sample = Path(a.sample).expanduser()
    if not sample.is_file():
        return fail(EXIT_USAGE, f"sample not found: {a.sample}")
    sample = sample.resolve()
    if a.timeout <= 0:
        return fail(EXIT_USAGE, "--timeout must be positive")
    with open(sample, "rb") as f:
        is_elf = f.read(4) == b"\x7fELF"  # the only sample bytes the outer stage reads
    max_api = a.max_api if a.max_api is not None else 10000
    try:
        stdin = stdin_bytes(a)
    except (OSError, ValueError) as e:
        return fail(EXIT_USAGE, str(e))
    if is_elf:
        if a.no_sandbox:
            return fail(EXIT_USAGE, "--no-sandbox is refused for ELF samples: the Qiling backend always runs "
                                    "under the sandbox")
        bad = [flag for flag, on in (("--trace-mem", a.trace_mem), ("--children", a.children)) if on]
        if bad:
            return fail(EXIT_USAGE, f"{' and '.join(bad)} apply to PE samples only (ELF: child processes are "
                                    f"always followed child-first; see README 'Linux ELF')")
        bad_env = [x for x in a.env if "=" not in x or x.startswith("=")]
        if bad_env:
            return fail(EXIT_USAGE, f"--env needs KEY=VALUE, got {bad_env[0]!r}")
        if not elfsetup.venv_ready():
            return fail(EXIT_UNSUPPORTED, f"ELF samples are not supported until the Qiling environment is built: "
                                          f"run `{elfsetup.SETUP_HINT}` ({elfsetup.VENV} is missing or incomplete)")
    elif a.env:
        return fail(EXIT_USAGE, "--env applies to ELF samples only")
    elif stdin is not None:
        return fail(EXIT_USAGE, "--stdin/--stdin-hex/--stdin-file apply to ELF samples only: Speakeasy (PE) has "
                                "no console-input model (ReadFile on the stdin handle and CRT fgets/scanf are not "
                                "emulated), so the input could not reach the program")

    if a.no_sandbox:
        log("WARNING: --no-sandbox given; the emulator runs WITHOUT network/file isolation")
    elif not sandbox.sandbox_available():
        return fail(EXIT_SANDBOX, f"{sandbox.SANDBOX_EXEC} not found; refusing to run without a sandbox")

    sha = sha256_file(sample)
    size = sample.stat().st_size
    try:
        out = prepare_out_dir(a.out, sha)
    except (OSError, ValueError) as e:
        return fail(EXIT_USAGE, str(e))
    log(f"output directory {out}")

    if is_elf:
        inner = [str(elfsetup.VENV_PY), "-I", "-B", "-m", "rebox", "_inner-elf", str(sample), "--out", str(out),
                 "--timeout", str(a.timeout), "--max-syscalls", str(max_api),
                 "--rootfs-cache", str(elfsetup.ROOTFS)]
        for x in a.env:
            inner.append(f"--env={x}")
        if stdin is not None:
            # the sandboxed stage reads it from out_dir (bytes of any value, no argv limits)
            stdin_path = out / "stdin.bin"
            fd = os.open(stdin_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(stdin)
            inner.append(f"--stdin-file={stdin_path}")
    else:
        inner = [sys.executable, "-I", "-B", "-m", "rebox", "_inner", str(sample), "--out", str(out),
                 "--timeout", str(a.timeout), "--max-api", str(max_api)]
    for x in a.arg:
        inner.append(f"--arg={x}")
    if a.trace_mem:
        inner.append("--trace-mem")
    if a.children:
        inner.append("--children")

    if a.no_sandbox:
        cmd, env = inner, {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        sandbox_state = "DISABLED (--no-sandbox)"
    else:
        profile = sandbox.write_profile(out / "sandbox.sb")
        cmd = sandbox.wrap_command(inner + ["--sandboxed"], out, profile)
        env = sandbox.sandbox_env(out)
        (out / "tmp").mkdir(mode=0o700, exist_ok=True)
        sandbox_state = "sandbox-exec: no network, writes only to out_dir"

    # The emulator enforces --timeout itself; this is the backstop if it hangs.
    hard_limit = a.timeout + max(60, a.timeout)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=hard_limit, cwd=str(out))
    except subprocess.TimeoutExpired:
        return fail(EXIT_TIMEOUT, f"emulator process killed after hard limit of {hard_limit}s", out_dir=str(out))
    wall = time.monotonic() - t0
    if proc.stderr:
        (out / "inner.stderr.txt").write_bytes(proc.stderr)
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-5:]
        for line in tail:
            log(f"inner: {line}")

    meta_path = out / "run.json"
    if not meta_path.is_file():
        hint = proc.stderr.decode("utf-8", "replace").strip()[-300:]
        code = EXIT_SANDBOX if (not a.no_sandbox and proc.returncode != 0) else EXIT_TOOL
        return fail(code, f"emulator stage produced no metadata (exit {proc.returncode}); "
                          f"sandbox may have failed to apply: {hint}", out_dir=str(out))
    meta = json.loads(meta_path.read_text())

    if not a.no_sandbox and not (meta.get("sandbox") or {}).get("verified"):
        return fail(EXIT_SANDBOX, "sandbox self-check failed inside the emulator process; sample was not run",
                    sandbox=meta.get("sandbox"), out_dir=str(out))

    report_path = out / "report.json"
    if proc.returncode != 0 or not report_path.is_file():
        errs = "; ".join(str(e.get("error")) for e in meta.get("errors") or [])[:500]
        code = proc.returncode if proc.returncode in (EXIT_UNSUPPORTED, EXIT_SANDBOX) else EXIT_TOOL
        return fail(code, errs or f"emulator stage exited {proc.returncode} without a report", out_dir=str(out))

    meta["rebox"] = {"sha256": sha, "size": size, "sample_name": sample.name, "wall_time": wall,
                     "timeout": a.timeout, "sandbox_state": sandbox_state}
    meta_path.write_text(json.dumps(meta, indent=1))
    text = render(out, a.max_chars)
    (out / "summary.json").write_text(text + "\n")
    sys.stdout.write(text + "\n")
    return EXIT_OK


def render(out: Path, max_chars: int) -> str:
    meta = json.loads((out / "run.json").read_text())
    report = json.loads((out / "report.json").read_text())
    rb = meta.get("rebox") or {}
    if str(report.get("format", "")).startswith("rebox.elf-report/"):
        from . import elfsummary

        s = elfsummary.build_summary(
            report, meta, sample_name=rb.get("sample_name") or Path(meta.get("sample") or "?").name,
            sha256=rb.get("sha256"), size=rb.get("size"), out_dir=str(out), wall_time=rb.get("wall_time"),
            timeout=rb.get("timeout"), sandbox_state=rb.get("sandbox_state") or "unknown")
        summary.fit_budget(s, max_chars)
        return summary.dumps(s)
    s = summary.build_summary(
        report, meta,
        sample_name=rb.get("sample_name") or Path(meta.get("sample") or "?").name,
        sha256=rb.get("sha256") or report.get("sha256"),
        size=rb.get("size") or report.get("size"),
        out_dir=str(out),
        raw_report_path=str(out / "report.json"),
        wall_time=rb.get("wall_time"),
        timeout=rb.get("timeout"),
        sandbox_state=rb.get("sandbox_state") or "unknown",
        noise_strings=summary.emulator_noise_strings(),
    )
    summary.fit_budget(s, max_chars)
    return summary.dumps(s)


def cmd_summarize(a) -> int:
    out = Path(a.out_dir).expanduser().resolve()
    if not (out / "report.json").is_file() or not (out / "run.json").is_file():
        return fail(EXIT_USAGE, f"{out} has no report.json/run.json")
    sys.stdout.write(render(out, a.max_chars) + "\n")
    return EXIT_OK


def cmd_inner(a) -> int:
    from . import emulate

    return emulate.run_inner(a.sample, a.out, a.timeout, a.arg, a.sandboxed, a.trace_mem, a.children, a.max_api)


def cmd_inner_elf(a) -> int:
    from . import elfemu

    return elfemu.run_inner(a.sample, a.out, a.timeout, a.arg, a.env, a.sandboxed, a.max_syscalls, a.rootfs_cache,
                            a.stdin_file)


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)  # run artefacts are private to the owner
    a = build_parser().parse_args(argv)
    if a.cmd == "run":
        try:
            return cmd_run(a)
        except Exception as e:  # last resort: still one JSON object and a non-zero exit
            return fail(EXIT_TOOL, f"{type(e).__name__}: {e}")
    if a.cmd == "summarize":
        return cmd_summarize(a)
    if a.cmd == "_inner":
        return cmd_inner(a)
    if a.cmd == "_inner-elf":
        return cmd_inner_elf(a)
    if a.cmd == "setup-elf":
        return elfsetup.main(force=a.force, venv_only=a.venv_only, rootfs_only=a.rootfs_only)
    if a.cmd in ("live", "live-setup", "live-summarize"):
        from . import live          # Docker mode; imported on demand, it has its own error handling
        return live.main(a)
    return fail(EXIT_USAGE, "unknown command")
