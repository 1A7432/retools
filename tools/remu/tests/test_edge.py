"""Odd endings on hand-assembled code: every one must stop cleanly with a reason."""

import pytest

from conftest import EmuImage, write_image

X86 = {
    "smc": "c60507104000" "40" "90" "c3",        # at 0x401000: patch the nop at 0x401007 into inc eax
    "div0": "31c9f7f1c3",                        # xor ecx,ecx; div ecx
    "hlt": "f4c3",
    "int2e": "cd2ec3",
    "sysenter": "0f34c3",
    "recurse": "e8fbffffffc3",                   # call self forever
    "into_stubs": "b801fdc07fffe0",              # jmp into the middle of a stub slot
}
X64 = {"syscall": "0f05c3", "div0": "31c948f7f1c3"}


def build(tmp_path, arch, fns):
    code, syms = b"", {}
    for k, h in fns.items():
        syms[k] = 0x401000 + len(code)
        code += bytes.fromhex(h) + b"\x90" * 3
    path = write_image(str(tmp_path / arch), arch, 32 if arch == "x86" else 64, "pe",
                       [(".text", 0x401000, 0x402000, "rwx", False, code)], {}, {})
    return EmuImage(path, syms)


@pytest.fixture(scope="module")
def edge(tmp_path_factory):
    d = tmp_path_factory.mktemp("edge")
    return build(d, "x86", X86), build(d, "x64", X64)


def test_x86_endings(edge):
    img = edge[0]
    r = img.call({"func": img["div0"]})
    assert r["stop"]["reason"] == "interrupt" and r["stop"]["name"] == "divide_error"
    assert img.call({"func": img["hlt"]})["stop"]["reason"] == "halt"
    assert img.call({"func": img["int2e"]})["stop"]["reason"] == "syscall"
    assert img.call({"func": img["sysenter"]})["stop"]["reason"] == "syscall"
    r = img.call({"func": img["recurse"], "max_insns": 50000})
    assert r["stop"]["reason"] == "max_insns" and r["insns"] == 50000
    r = img.call({"func": img["into_stubs"]})
    assert r["stop"]["reason"] == "interrupt" and r["stop"]["at"].startswith("0x7fc")


def test_self_modifying_code_within_a_run(edge):
    img = edge[0]
    r = img.call({"func": img["smc"], "regs": {"eax": 0}})
    assert r["ret"] == "0x1"
    assert r["writes"]["top"][0]["addr"] == hex(img.syms["smc"] + 7)
    # the next request starts from the original bytes again
    assert img.call({"func": img["smc"], "regs": {"eax": 0}})["ret"] == "0x1"


def test_x64_endings(edge):
    img = edge[1]
    assert img.call({"func": img["syscall"]})["stop"]["reason"] == "syscall"
    assert img.call({"func": img["div0"]})["stop"]["name"] == "divide_error"
