"""Helpers: evaluate code in-process (fast) or through the launcher (as rekit does)."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from recalc.cli import evaluate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECALC = os.path.join(ROOT, "recalc")
sys.setrecursionlimit(20000)


def calc(code, **kw):
    req = dict(code=code, **kw)
    req.setdefault("max_chars", 50000)
    return evaluate(req)


def ok(code, **kw):
    """Evaluate and return the raw result value re-parsed from the rendering."""
    r = calc(code, **kw)
    assert "error" not in r, r
    return r


def err(code, **kw):
    r = calc(code, **kw)
    assert "error" in r, r
    assert "internal error" not in r["error"], r
    assert set(r) >= {"error", "hint"}
    return r


def cli(payload, timeout=90, raw=False):
    data = payload if raw else json.dumps(payload)
    p = subprocess.run([RECALC], input=data, capture_output=True, text=True, env={}, timeout=timeout)
    return p


@pytest.fixture
def run_cli():
    return cli
