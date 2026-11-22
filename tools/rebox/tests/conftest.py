import atexit
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

TOOL_DIR = Path(__file__).resolve().parents[1]
LAUNCHER = TOOL_DIR / "rebox"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Runs started without --out must not land in the checkout's tmp/rebox-runs.
_RUNS = tempfile.mkdtemp(prefix="rebox-test-runs-")
os.environ["REBOX_RUNS"] = _RUNS
atexit.register(shutil.rmtree, _RUNS, ignore_errors=True)

# Benign Windows launcher stubs that ship with pip (distlib). Never executed natively.
PIP_STUB_GLOBS = [
    "/opt/homebrew/lib/python3*/site-packages/pip/_vendor/distlib/t32.exe",
    "/opt/homebrew/lib/python3*/site-packages/pip/_vendor/distlib/w64.exe",
    os.path.expanduser("~/.local/share/uv/python/*/lib/python3*/site-packages/pip/_vendor/distlib/t32.exe"),
    os.path.expanduser("~/.local/pipx/shared/lib/python3*/site-packages/pip/_vendor/distlib/t32.exe"),
]


def find_pip_stub():
    for pattern in PIP_STUB_GLOBS:
        hits = sorted(glob.glob(pattern))
        if hits:
            return Path(hits[0])
    return None


def run_rebox(*args, timeout=600):
    """Run the launcher; return (exit code, parsed stdout JSON, stdout text, stderr text)."""
    p = subprocess.run([str(LAUNCHER), *map(str, args)], capture_output=True, text=True, timeout=timeout)
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected exactly one stdout line, got {len(lines)}: {p.stdout[:500]!r}"
    return p.returncode, json.loads(lines[0]), lines[0], p.stderr


@pytest.fixture
def behave_exe(tmp_path):
    import pebuild

    path = tmp_path / "samples" / "behave.exe"
    path.parent.mkdir()
    path.write_bytes(pebuild.build())
    os.chmod(path, 0o600)
    return path
