"""The real Delphi sample image, when it is present on this machine.

Only its bytes are read into Unicorn; nothing from it is written to disk.
"""

import os
import random

import pytest

from remu.arch import for_image
from remu.cli import handle
from remu.image import Image

# A locally exported image of a 32-bit Delphi PE; the tests skip without it.
REAL = os.environ.get("REMU_REAL_IMAGE") or os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "tmp", "rekit-images",
    "50_DISKMGR.bin.4cc1bd35fc1e"))
pytestmark = pytest.mark.skipif(not os.path.exists(os.path.join(REAL, "meta.json")),
                                reason="real sample image not exported on this machine")

GETMEM = "0x407164"        # System.@GetMem (EAX = size), calls FastMM through a pointer
USTR_FROM_PWCHAR = "0x40c1fc"
USTR_FROM_PCHAR = "0x40c1cc"   # converts with MultiByteToWideChar (import thunk)


@pytest.fixture(scope="module")
def real():
    image = Image(REAL)
    arch = for_image(image)
    return lambda req: handle(image, arch, req)


def model_495bd0(firsts):
    """Python model of sub_495BD0 given the first dword of each 12-byte record."""
    n = len(firsts)
    v3 = (n - 1) & 0xFFFFFFFF
    count = 0
    for i, d in enumerate(firsts):
        if d != 0xFFFFFFFF and i != (v3 & d):
            count += 1
    return count


def request_495bd0(firsts):
    if firsts is None:
        obj = {"struct": [{"u32": 0}, {"u32": 0}]}      # nil array
        mem = []
    else:
        recs = [{"u32": len(firsts)}]
        for i, d in enumerate(firsts):
            recs += [{"u32": d}, {"u32": i}, {"u32": 0xABCD}]
        mem = [{"name": "arr", "struct": recs}]
        obj = {"struct": [{"u32": 0}, {"ptr": {"ref": "arr+4"}}]}
    return {"func": "0x495bd0", "cc": "delphi", "args": [obj], "mem": mem, "fields": ["ret", "insns"]}


def test_495bd0_against_model(real):
    rng = random.Random(1234)
    cases = [None, [], [0], [5, 0xFFFFFFFF, 2], [1, 1, 1, 1], list(range(8))]
    for n in (7, 16, 50):
        cases.append([rng.choice([0xFFFFFFFF, rng.randrange(0, 1 << 32), rng.randrange(0, 64)])
                      for _ in range(n)])
    reply = real({"requests": [request_495bd0(c) for c in cases], "max_chars": 20000})
    assert reply["reasons"] == {"returned": len(cases)}
    for c, res in zip(cases, reply["results"]):
        want = 0 if c is None else model_495bd0(c)
        assert int(res["ret"], 16) == want, (c, res)


def test_delphi_string_from_pwidechar(real):
    r = real({"func": USTR_FROM_PWCHAR, "cc": "delphi",
              "replace": {GETMEM: {"stub": "malloc", "cc": "delphi", "name": "System.GetMem"}},
              "args": [{"out": 4, "name": "dest"}, {"wstr": "Hello 世界"}],
              "read": [{"addr": {"ref": "dest"}, "deref": 1, "as": "dstr"}]})
    assert r["stop"]["reason"] == "returned"
    assert r["reads"][0]["dstr"] == "Hello 世界" and r["reads"][0]["len"] == 8


def test_delphi_string_from_pchar_goes_through_import(real):
    r = real({"func": USTR_FROM_PCHAR, "cc": "delphi",
              "replace": {GETMEM: {"stub": "malloc", "cc": "delphi", "name": "System.GetMem"}},
              "args": [{"out": 4, "name": "dest"}, {"str": "Hello"}],
              "read": [{"addr": {"ref": "dest"}, "deref": 1, "as": "dstr"}]})
    assert r["stop"]["reason"] == "returned"
    assert r["reads"][0]["dstr"] == "Hello"
    assert r["imports"]["top"][0]["fn"] == "kernel32!MultiByteToWideChar"


def test_uninitialised_memory_manager_is_reported(real):
    # Without the replacement the RTL's memory manager (never initialised in a
    # static image) dereferences NULL; the reply says where and how it got there.
    r = real({"func": USTR_FROM_PWCHAR, "cc": "delphi", "trace": True,
              "args": [{"out": 4}, {"wstr": "x"}]})
    assert r["stop"]["reason"] == "unmapped_read" and r["stop"]["addr"] == "0x10"
    assert [t["to"] for t in r["trace"]["top"]][-1] == "0x405ae4"


def test_ansi_upper_case_through_import_thunk(real):
    # SysUtils.AnsiUpperCase(S; out Result): copies S, then CharUpperBuffW (an import thunk)
    r = real({"func": "0x434b9c", "cc": "delphi",
              "replace": {GETMEM: {"stub": "malloc", "cc": "delphi"}},
              "args": [{"dstr": "Hello, wörld 世界"}, {"out": 4, "name": "result"}],
              "read": [{"addr": {"ref": "result"}, "deref": 1, "as": "dstr"}]})
    assert r["reads"][0]["dstr"] == "HELLO, WÖRLD 世界"
    assert [c["fn"] for c in r["imports"]["top"]] == ["sub_407164", "user32!CharUpperBuffW"]
