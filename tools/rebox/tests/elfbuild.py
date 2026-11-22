"""Cross-compile the harmless ELF test programs (tests/elfsrc/*.c) with zig.

The binaries are only ever run inside rebox's emulator, never natively.
"""

import os
import shutil
import subprocess
from pathlib import Path

SRC = Path(__file__).resolve().parent / "elfsrc" / "behave.c"
STDIN_SRC = SRC.with_name("stdin.c")   # reads stdin (fgets / raw read) and echoes it
ZIG = shutil.which("zig") or "/opt/homebrew/bin/zig"

# rebox arch -> zig target. Static builds use musl; dynamic ones glibc 2.17, which the
# Qiling rootfs libraries (glibc 2.2x) satisfy.
STATIC = {"x86-64": "x86_64-linux-musl", "arm64": "aarch64-linux-musl", "x86": "x86-linux-musl"}
DYNAMIC = {"x86-64": "x86_64-linux-gnu.2.17", "arm64": "aarch64-linux-gnu.2.17"}

# What behave.c does, for the assertions.
EXPECT = {
    "c2": "198.51.100.7", "port": 4444, "host": "beacon.rebox-test.invalid",
    "drop": "/tmp/.rebox-drop.txt", "drop_content": b"rebox test payload\n",
    "cmd": "/bin/sh -c 'echo rebox-test > /tmp/.rebox-exec'", "proc_name": "kworker/0:1",
    "url": "http://beacon.rebox-test.invalid/stage2.bin", "listen": "tcp 0.0.0.0:2323",
}


def zig_available() -> bool:
    return os.path.isfile(ZIG) and os.access(ZIG, os.X_OK)


def build(out_dir: Path, arch: str, dynamic: bool = False, src: Path = SRC) -> Path:
    target = (DYNAMIC if dynamic else STATIC)[arch]
    out = Path(out_dir) / f"{Path(src).stem}-{arch}-{'dyn' if dynamic else 'static'}.elf"
    if out.exists():
        return out
    cmd = [ZIG, "cc", "-target", target, "-O1", "-g0", "-s", "-o", str(out), str(src)]
    cmd[4:4] = [] if dynamic else ["-static", "-DWITH_THREADS"]
    subprocess.run(cmd, check=True, capture_output=True, timeout=600)
    os.chmod(out, 0o600)  # never executable on the host
    return out
