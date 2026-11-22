"""`rebox setup-elf`: build the Qiling environment and fetch the Linux rootfs.

Runs outside the sandbox (it needs the network) and never touches a sample.
Everything it creates lives inside the rebox directory:

    .venv-elf/          Python 3.12 venv with Qiling 1.4.10 (separate from the
                        Speakeasy .venv, whose uv.lock is not touched)
    elf-rootfs/<arch>_linux/lib{,64}/
                        shared libraries from github.com/qilingframework/rootfs,
                        pinned commit, sparse checkout of the lib directories only
                        (the repository's test programs and kernel modules are
                        not fetched)

The build recipe, each step of which was needed on macOS 26 / arm64:

1. `uv venv --python 3.12`, then cmake<4, setuptools, wheel into it.
2. keystone-engine 0.9.2 built from source with `--no-build-isolation`, so its
   build uses that CMake 3.31 (its CMakeLists sets a policy CMake 4 rejects),
   and with `--no-cache`, because uv's cache can hold a broken keystone wheel
   without libkeystone.dylib from an earlier attempt.
3. Qiling from its 1.4.10 git tag with unicorn overridden to 2.1.4 (Qiling pins
   2.1.3, which has no arm64 macOS wheel and does not compile here).
4. A .pth file so the venv can import this rebox source tree.

The open-flags patch Qiling needs on an arm64 macOS host is applied at run time
(rebox.elfemu.patch_qiling), not by editing site-packages.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parents[2]
VENV = TOOL_DIR / ".venv-elf"
VENV_PY = VENV / "bin" / "python"
READY = VENV / "rebox-elf-ready.json"
ROOTFS = TOOL_DIR / "elf-rootfs"
ROOTFS_READY = ROOTFS / "rebox-rootfs-ready.json"
CONSTRAINTS = TOOL_DIR / "elf-constraints.txt"

PYTHON = "3.12"
QILING_REPO = "https://github.com/qilingframework/qiling"
QILING_TAG = "1.4.10"
QILING_COMMIT = "da210f0757f3581de7e607b2b826b26eaa5aef66"  # tag 1.4.10
OVERRIDES = ("unicorn==2.1.4", "keystone-engine==0.9.2")
KEYSTONE = "keystone-engine==0.9.2"

ROOTFS_REPO = "https://github.com/qilingframework/rootfs"
ROOTFS_COMMIT = "df3fa4dfc0b9d4164f8678699d8923df847eb3d2"  # master, 2026-04-27
# rebox arch name -> rootfs directory. Only the supported architectures are
# fetched; 32-bit ARM and MIPS are not a goal (static samples for them may run,
# untested, but dynamic ones have no libraries).
ROOTFS_DIRS = {
    "x86-64": "x8664_linux",
    "x86": "x86_linux",
    "arm64": "arm64_linux",
}
SETUP_HINT = "rebox setup-elf"


def log(msg: str) -> None:
    print(f"rebox setup-elf: {msg}", file=sys.stderr, flush=True)


def find_uv() -> str:
    uv = shutil.which("uv") or os.path.expanduser("~/.local/bin/uv")
    if not os.path.isfile(uv):
        raise RuntimeError("uv not found (looked on PATH and ~/.local/bin/uv)")
    return uv


def _run(cmd: list[str], env: dict | None = None, cwd: str | None = None) -> None:
    log("$ " + " ".join(cmd))
    p = subprocess.run(cmd, env=env, cwd=cwd, stdout=sys.stderr, stderr=sys.stderr)
    if p.returncode != 0:
        raise RuntimeError(f"command failed with exit {p.returncode}: {' '.join(cmd)}")


def _out(cmd: list[str], env: dict | None = None) -> str:
    return subprocess.run(cmd, env=env, capture_output=True, text=True, check=True).stdout.strip()


def venv_ready() -> bool:
    return VENV_PY.is_file() and READY.is_file()


def rootfs_dir(arch: str) -> Path | None:
    name = ROOTFS_DIRS.get(arch)
    if not name:
        return None
    d = ROOTFS / name
    return d if (d / "lib").is_dir() else None


def build_venv(force: bool = False) -> dict:
    uv = find_uv()
    if force and VENV.exists():
        log(f"removing {VENV}")
        shutil.rmtree(VENV)
    if READY.exists():
        READY.unlink()
    if not VENV_PY.is_file():
        _run([uv, "venv", "--python", PYTHON, str(VENV)])
    # "Activate" the venv for the build steps: keystone's build looks for cmake on PATH.
    env = {**os.environ, "VIRTUAL_ENV": str(VENV), "PATH": f"{VENV / 'bin'}:{os.environ.get('PATH', '')}"}
    env.pop("PYTHONHOME", None)
    py = ["--python", str(VENV_PY)]

    _run([uv, "pip", "install", *py, "-c", str(CONSTRAINTS), "cmake<4", "setuptools", "wheel"], env=env)
    cmake = VENV / "bin" / "cmake"
    ver = _out([str(cmake), "--version"], env=env).splitlines()[0]
    log(f"build CMake: {ver}")
    if " 3." not in ver:
        raise RuntimeError(f"expected CMake 3.x in the venv, got {ver!r}")

    _run([uv, "pip", "install", *py, "--reinstall", "--no-cache", "--no-build-isolation",
          "--no-binary", "keystone-engine", KEYSTONE], env=env)
    _run([str(VENV_PY), "-I", "-c",
          "import keystone; keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64); print('keystone ok')"], env=env)

    ov = VENV / "rebox-overrides.txt"
    ov.write_text("\n".join(OVERRIDES) + "\n")
    _run([uv, "pip", "install", *py, "--override", str(ov), "-c", str(CONSTRAINTS),
          f"qiling @ git+{QILING_REPO}@{QILING_COMMIT}"], env=env)

    site = Path(_out([str(VENV_PY), "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"]))
    (site / "rebox_src.pth").write_text(str(TOOL_DIR / "src") + "\n")

    probe = ("import json, qiling, unicorn, keystone, capstone, elftools, rebox.elfemu as e; "
             "e.patch_qiling(); print(json.dumps({'qiling': qiling.__version__, 'unicorn': unicorn.__version__, "
             "'capstone': capstone.__version__, 'python': __import__('sys').version.split()[0]}))")
    versions = json.loads(_out([str(VENV_PY), "-I", "-B", "-c", probe]))
    info = {"versions": versions, "qiling_commit": QILING_COMMIT, "overrides": list(OVERRIDES),
            "freeze": _out([uv, "pip", "freeze", *py]).splitlines()}
    READY.write_text(json.dumps(info, indent=1) + "\n")
    log(f"Qiling environment ready: {versions}")
    return info


def fetch_rootfs(force: bool = False) -> dict:
    git = shutil.which("git") or "/usr/bin/git"
    if force and ROOTFS.exists():
        log(f"removing {ROOTFS}")
        shutil.rmtree(ROOTFS)
    if ROOTFS_READY.exists():
        ROOTFS_READY.unlink()
    ROOTFS.mkdir(exist_ok=True)
    g = [git, "-C", str(ROOTFS)]
    if not (ROOTFS / ".git").is_dir():
        _run(g + ["init", "-q"])
        _run(g + ["remote", "add", "origin", ROOTFS_REPO])
    # Libraries only: the repository also holds Qiling's test programs and kernel modules.
    patterns = [f"/{d}/{sub}/" for d in ROOTFS_DIRS.values() for sub in ("lib", "lib64")]
    _run(g + ["sparse-checkout", "set", "--no-cone", *patterns])
    _run(g + ["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", ROOTFS_COMMIT])
    _run(g + ["checkout", "-q", "--force", ROOTFS_COMMIT])
    head = _out(g + ["rev-parse", "HEAD"])
    missing = [d for d in ROOTFS_DIRS.values() if not (ROOTFS / d / "lib").is_dir()]
    if missing:
        raise RuntimeError(f"rootfs checkout lacks lib/ for: {', '.join(missing)}")
    info = {"repo": ROOTFS_REPO, "commit": head, "dirs": ROOTFS_DIRS, "patterns": patterns}
    ROOTFS_READY.write_text(json.dumps(info, indent=1) + "\n")
    log(f"rootfs ready at {ROOTFS} (commit {head[:12]}): {', '.join(ROOTFS_DIRS.values())}")
    return info


def main(force: bool = False, venv_only: bool = False, rootfs_only: bool = False) -> int:
    result = {"schema": "rebox.setup-elf/1", "ok": False, "venv": str(VENV), "rootfs": str(ROOTFS)}
    try:
        if not rootfs_only:
            result["qiling"] = build_venv(force)["versions"]
        if not venv_only:
            result["rootfs_commit"] = fetch_rootfs(force)["commit"]
        result["ok"] = True
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        log(result["error"])
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 4
