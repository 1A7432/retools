"""Rendering for exact copying, cutting in the middle, and the max_chars budget."""

import json

from recalc.render import render
from conftest import calc


def test_scalars():
    assert render(5) == 5 and render(-9) == -9
    assert render(582698) == "0x8e42a = 582698"
    assert render(-16) == "-0x10 = -16"
    assert render(1 << 64) == "0x10000000000000000"
    assert render(True) is True and render(None) is None
    assert render(b"abc") == {"bytes": 3, "hex": "616263", "ascii": "abc"}
    assert render(b"\x00ab") == {"bytes": 3, "hex": "006162"}
    assert render(b"") == {"bytes": 0, "hex": ""}
    assert render((1, 2)) == {"tuple": [1, 2]}
    assert render({1: b"a"}) == {"dict": [[1, {"bytes": 1, "hex": "61", "ascii": "a"}]]}


def test_long_values_cut_in_the_middle_with_totals():
    b = bytes(range(256)) * 20
    r = render(b, 2)
    assert r["bytes"] == 5120
    assert "...[cut " in r["hex"] and "of 5120 bytes]..." in r["hex"]
    assert r["hex"].startswith(b[:32].hex()[:40]) and r["hex"].endswith(b[-8:].hex())
    lst = list(range(1000))
    r = render(lst, 2)
    assert r[0] == 0 and r[-1] == "0x3e7" and "...[cut 984 of 1000 items]..." in r
    big = (1 << 40000) - 1
    r = render(big, 3)
    assert "hex digits]..." in r and r.endswith("(40000 bits)")
    s = "x" * 10000
    assert "of 10000 chars]" in render(s, 1)


def test_long_lists_show_hex_only():
    r = render(list(range(100, 130)))
    assert r[0] == "0x64"
    assert render([100, 200]) == ["0x64 = 100", "0xc8 = 200"]


def test_budget_is_respected_and_reported():
    code = "a = bytes(range(256)) * 40\nb = list(range(5000))\nc = 'z' * 20000\nd = 7\na[:4]"
    full = calc(code, max_chars=50000)
    assert full["truncated"] == "long values are cut in the middle at ...[cut N of M]... markers"
    for budget in (300, 600, 1000, 2000, 4000, 8000):
        r = calc(code, max_chars=budget)
        size = len(json.dumps(r, ensure_ascii=False, separators=(",", ":")))
        assert size <= budget, (budget, size)
        assert "truncated" in r
        assert r["result"] == {"bytes": 4, "hex": "00010203"} or "result" in r
    r = calc(code, max_chars=300)
    assert "vars not shown" in r["truncated"]


def test_print_lines_and_errors_fit_the_budget():
    r = calc("for i in range(500):\n    print(i, sha256(bytes([i % 256])))\n1", max_chars=1500)
    assert len(json.dumps(r, ensure_ascii=False, separators=(",", ":"))) <= 1500
    assert "truncated" in r
    r = calc("x = list(range(100000))\ny = x[10 ** 6]", max_chars=600)
    assert "error" in r and len(json.dumps(r, separators=(",", ":"))) <= 600
