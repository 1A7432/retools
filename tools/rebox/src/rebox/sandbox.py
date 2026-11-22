"""macOS sandbox-exec wrapper for the emulator process.

The profile allows by default (CPython and Unicorn need broad read access to
start) and then removes everything a sample could use to reach the outside:
all network, all Mach service lookups (which closes the mDNSResponder path for
DNS), fork/exec of anything but the interpreter, and file writes anywhere but
the run's output directory.

Paths are passed with `-D` parameters rather than spliced into the profile
text, so unusual characters in a path cannot change the profile.
"""

from __future__ import annotations

import errno
import os
import socket
import sys
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

PROFILE = """\
(version 1)
(allow default)
(deny network*)
(deny mach-lookup)
(deny iokit-open)
(deny process-fork)
(deny process-exec*)
(allow process-exec (literal (param "PYTHON")) (literal (param "PYTHON_REAL")))
(deny file-write*)
(allow file-write* (subpath (param "OUT")) (literal "/dev/null"))
"""


def sandbox_available() -> bool:
    return os.path.isfile(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)


def wrap_command(argv: list[str], out_dir: str | os.PathLike, profile_path: str | os.PathLike) -> list[str]:
    """Prefix argv (whose argv[0] must be the Python interpreter) with sandbox-exec."""
    out_real = os.path.realpath(out_dir)
    python = argv[0]
    return [
        SANDBOX_EXEC,
        "-D", f"OUT={out_real}",
        "-D", f"PYTHON={python}",
        "-D", f"PYTHON_REAL={os.path.realpath(python)}",
        "-f", str(profile_path),
        *argv,
    ]


def write_profile(path: str | os.PathLike) -> Path:
    path = Path(path)
    path.write_text(PROFILE)
    os.chmod(path, 0o600)
    return path


def sandbox_env(out_dir: str | os.PathLike) -> dict[str, str]:
    """Minimal environment for the sandboxed child; TMPDIR points inside the output dir."""
    tmp = Path(os.path.realpath(out_dir)) / "tmp"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp),
        "TMPDIR": str(tmp) + "/",
        "LANG": "en_US.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    return env


def self_check(out_dir: str | os.PathLike) -> dict:
    """Run inside the child: prove the sandbox is active before touching the sample.

    Every probe must be refused with EPERM, which is what the sandbox returns;
    a plain permission problem would be EACCES and a closed port ECONNREFUSED,
    so neither can be mistaken for an active sandbox.
    """
    results: dict[str, str] = {}

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", 9))
        results["tcp_connect"] = "connected"
    except OSError as e:
        results["tcp_connect"] = "denied" if e.errno == errno.EPERM else f"errno {e.errno}"
    finally:
        s.close()

    try:
        socket.getaddrinfo("example.com", 80)
        results["dns"] = "resolved"
    except OSError:
        results["dns"] = "denied"

    probe = Path(os.path.realpath(out_dir)).parent / f".rebox-sandbox-probe-{os.getpid()}"
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.unlink(probe)
        results["write_outside"] = "written"
    except OSError as e:
        results["write_outside"] = "denied" if e.errno == errno.EPERM else f"errno {e.errno}"

    inside = Path(os.path.realpath(out_dir)) / ".rebox-write-probe"
    try:
        inside.write_bytes(b"ok")
        inside.unlink()
        results["write_inside"] = "ok"
    except OSError as e:
        results["write_inside"] = f"errno {e.errno}"

    results["verified"] = (
        results["tcp_connect"] == "denied"
        and results["dns"] == "denied"
        and results["write_outside"] == "denied"
        and results["write_inside"] == "ok"
    )
    return results


def interpreter() -> str:
    """The venv interpreter path (not resolved, so the venv's site-packages stay active)."""
    return sys.executable
