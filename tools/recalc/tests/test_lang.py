"""The language: syntax, scoping, methods, results and error reporting."""

from conftest import calc, err, ok


def res(code):
    return ok(code)["result"]


def test_arithmetic_and_rendering():
    assert res("1 + 2 * 3") == 7
    assert res("7 // 2") == 3
    assert res("-7 % 3") == 2
    assert res("2 ** 10") == "0x400 = 1024"
    assert res("0xff & 0x0f | 0x100 ^ 1") == "0x10f = 271"
    assert res("~0") == -1
    assert res("1 << 70") == "0x400000000000000000"
    assert res("(1 << 70) >> 69") == 2
    assert res("divmod(17, 5)") == {"tuple": [3, 2]}
    assert res("not 0") is True
    assert res("3 if 1 > 2 else 4") == 4
    assert res("0 or 5") == 5 and res("3 and 0") == 0
    assert res("1 < 2 < 3 != 4") is True


def test_assignment_forms_and_vars():
    r = ok("a = b = 5\nc, d = 1, 2\n[e, f] = [3, 4]\na += 1\nlst = [0, 0]\nlst[1] += 7\nd2 = {}\nd2['k'] = 1")
    v = r["vars"]
    assert v["a"] == 6 and v["b"] == 5 and v["c"] == 1 and v["d"] == 2 and v["e"] == 3
    assert v["lst"] == [0, 7]
    assert v["d2"] == {"dict": [["k", 1]]}
    assert "result" not in r


def test_loops_break_continue_else():
    r = ok("""
s = 0
for i in range(10):
    if i == 3:
        continue
    if i == 8:
        break
    s += i
else:
    s = -1
n = 0
while n < 5:
    n += 1
else:
    n = n * 10
s, n
""")
    assert r["result"] == {"tuple": ["0x19 = 25", "0x32 = 50"]}


def test_comprehensions_and_scope():
    r = ok("x = 99\nsq = [x * x for x in range(5) if x % 2 == 0]\nd = {k: k + 1 for k in range(3)}\n"
           "pairs = [(a, b) for a in range(2) for b in range(2)]\ng = sum(i for i in range(4))\nx")
    assert r["result"] == "0x63 = 99"           # comprehension variable does not leak
    assert r["vars"]["sq"] == [0, 4, "0x10 = 16"]
    assert r["vars"]["d"] == {"dict": [[0, 1], [1, 2], [2, 3]]}
    assert len(r["vars"]["pairs"]) == 4
    assert r["vars"]["g"] == 6


def test_def_with_defaults_and_globals():
    r = ok("""
K = 0x9e3779b9
def rnd(x, k=K, n=1):
    for i in range(n):
        x = (rotl(x, 5) ^ k) & 0xffffffff
    return x
a = rnd(1)
b = rnd(1, n=2)
def noret(x):
    y = x
c = noret(1)
a == ((rotl(1, 5) ^ K) & 0xffffffff), b == rnd(a)
""")
    assert r["result"] == {"tuple": [True, True]}
    assert r["vars"]["c"] is None
    assert "y" not in r["vars"]                   # locals stay local


def test_methods_and_statics():
    assert res("b'abc'.hex()") == "616263"
    assert res("(0x1234).to_bytes(4, 'little')") == {"bytes": 4, "hex": "34120000"}
    assert res("int.from_bytes(b'\\x01\\x02', 'little')") == "0x201 = 513"
    assert res("bytes.fromhex('41 42')") == {"bytes": 2, "hex": "4142", "ascii": "AB"}
    assert res("'abc'.encode()") == {"bytes": 3, "hex": "616263", "ascii": "abc"}
    assert res("b'\\xe4\\xb8\\xad'.decode('utf-8')") == "中"
    assert res("l = [3, 1, 2]\nl.append(0)\nl.sort()\nl") == [0, 1, 2, 3]
    assert res("d = {'a': 1}\nd.get('b', 7)") == 7
    assert res("d = {'a': 1}\nd.items()") == [{"tuple": ["a", 1]}]
    assert res("(255).bit_length()") == 8
    assert res("b','.join([b'a', b'b'])") == {"bytes": 3, "hex": "612c62", "ascii": "a,b"}


def test_indexing_and_slicing():
    assert res("b'abcdef'[1:4]") == {"bytes": 3, "hex": "626364", "ascii": "bcd"}
    assert res("b'abc'[0]") == "0x61 = 97"
    assert res("[1, 2, 3][::-1]") == [3, 2, 1]
    assert res("x = list(range(6))\nx[1:3] = [9]\nx") == [0, 9, 3, 4, 5]
    assert res("range(10)[2:8:2]") == "range(2, 8, 2)"


def test_assert_and_print():
    r = calc("x = 3\nassert x == 4, 'wrong'")
    assert r["error"].startswith("assertion failed: wrong (left: 3, right: 4)") and r["line"] == 2
    r = ok("print('k =', 0x1234, b'ab')\n1")
    assert r["printed"] == ["k = 0x1234 = 4660 {\"bytes\":2,\"hex\":\"6162\",\"ascii\":\"ab\"}"]


def test_errors_name_line_and_suggestions():
    r = err("x = 1\ny = rotll(x, 3)")
    assert r["line"] == 2 and r["at"] == "y = rotll(x, 3)"
    assert "rotl" in r["hint"] and "rotr" in r["hint"]
    r = err("sha265(b'a')")
    assert "sha256" in r["hint"]
    r = err("valeu = 1\nvalue + 1")
    assert "valeu" in r["hint"]
    r = err("sum = 5\nsum([1, 2])")
    assert "variable" in r["error"] and "rename" in r["hint"]
    r = err("f = sha256")
    assert "is a function" in r["error"]
    r = err("1 / 2")
    assert "//" in r["error"]
    r = err("b'ab' ^ b'cd'")
    assert "xor(a, b)" in r["hint"]
    r = err("x = 5\ny = [1]\nz = y[3]")
    assert r["line"] == 3 and "out of range" in r["error"]
    assert r["vars"] == {"x": 5, "y": [1]}          # state at the failure is shown
    r = err("rotl(1)")
    assert "usage: rotl(x, n, width=32)" in r["hint"]


def test_bytes_vs_str_errors_are_explained():
    r = err("sha256('abc')")
    assert "not a string" in r["error"]
    r = err("xor(b'abc', 'k')")
    assert "not a string" in r["error"]


def test_result_only_for_trailing_expression():
    assert "result" not in ok("x = 1")
    assert ok("x = 1\nx")["result"] == 1
