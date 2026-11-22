"""Attempts to break out of the language or exhaust resources. Each must end
in a clean {"error", "hint"} reply (never a result that ran the payload, never a
crash, never a hang) and leave no side effect."""

import json
import os
import time

import pytest

from conftest import calc, cli, err

CANARY = "/private/tmp/recalc-canary-%d" % os.getpid()


@pytest.fixture(autouse=True)
def no_canary():
    if os.path.exists(CANARY):
        os.remove(CANARY)
    yield
    assert not os.path.exists(CANARY), "a payload created the canary file"


def fails(code, *words, **kw):
    r = err(code, **kw)
    text = (r["error"] + " " + r.get("hint", "")).lower()
    for w in words:
        assert w.lower() in text, (code, r)
    return r


ATTRIBUTE_WALKS = [
    "().__class__",
    "().__class__.__bases__[0].__subclasses__()",
    "b''.__class__.__mro__[1].__subclasses__()",
    "x = 1\nx.__class__",
    "[].__class__.__base__",
    "sha256.__globals__",
    "rotl.__code__",
    "int.__subclasses__()",
    "int.from_bytes.__self__",
    "b'a'.hex.__self__",
    "(1).real",
    "(1).numerator",
    "''.join.__call__",
    "{}.get.__globals__",
    "x = {}\nx.__init__",
    "print.__self__",
    "int.mro()",
    "bytes.maketrans(b'a', b'b')",
    "str.format('{}', 1)",
]


@pytest.mark.parametrize("code", ATTRIBUTE_WALKS)
def test_attribute_walks(code):
    fails(code)


DANGEROUS_NAMES = ["open", "eval", "exec", "compile", "getattr", "setattr", "delattr", "globals",
                   "locals", "vars", "dir", "type", "object", "input", "breakpoint", "help", "exit",
                   "quit", "memoryview", "bytearray", "classmethod", "staticmethod", "super",
                   "property", "issubclass", "isinstance", "callable", "id", "hash", "iter", "next",
                   "map", "filter", "format", "repr", "ascii", "slice", "frozenset", "set", "float",
                   "complex", "os", "sys", "subprocess", "builtins"]


@pytest.mark.parametrize("name", DANGEROUS_NAMES)
def test_python_builtins_are_absent(name):
    fails("%s('%s', 'w')" % (name, CANARY))
    fails("x = %s" % name)


def test_underscore_names_and_dunder_calls():
    fails("__import__('os').system('touch %s')" % CANARY, "_")
    fails("_ = 1", "_")
    fails("__builtins__", "_")
    fails("sha256(b'', __class__=1)", "_")
    fails("def _f():\n    return 1", "_")
    fails("for __x in range(2):\n    pass", "_")


def test_imports_and_unsupported_statements():
    fails("import os", "import")
    fails("from os import system", "import")
    fails("lambda: 1", "lambda")
    fails("class A:\n    pass", "class")
    fails("try:\n    x = 1\nexcept:\n    pass", "try")
    fails("with open('x') as f:\n    pass", "with")
    fails("global x", "global")
    fails("del x", "del")
    fails("raise ValueError", "raise")
    fails("x = (y := 3)", ":=")
    fails("def f():\n    yield 1", "generator")
    fails("async def f():\n    pass", "async")
    fails("print(*[1, 2])", "unpacking")
    fails("1.5 + 1", "float")
    fails("1j", "complex")
    fails("...", "ellipsis")
    fails("x = {1, 2}", "set")
    fails("def f(*a):\n    return a", "positional")
    fails("@print\ndef f():\n    return 1", "positional")
    fails("def f():\n    def g():\n        return 1\n    return g()", "top level")


def test_format_strings_cannot_reach_internals():
    fails("'{0.__class__}'.format(1)", "format")
    fails("'%s' % (1,)", "formatting")
    fails("b'%s' % (b'a',)", "formatting")
    fails("f'{(1).__class__}'", "f-string")
    fails("f'{1}'", "f-string")
    fails("x = 1\n'{x.__class__}'.format_map({'x': x})", "format_map")


def test_functions_are_not_values():
    fails("f = sha256", "function")
    fails("[sha256][0](b'')", "named")
    fails("def g(x):\n    return x\nh = g", "function")
    fails("sha256(b'')(1)", "named")


def test_unicode_lookalike_identifiers():
    # fullwidth letters normalise (NFKC) to "pow"; refused instead of silently mapped
    fails("\uff50\uff4f\uff57(2, 3)", "non-ascii")
    # fullwidth low lines normalise to "__import__"
    fails("\uff3f\uff3fimport\uff3f\uff3f('os')", "")
    # Cyrillic a
    fails("\u0430 = 1", "non-ascii")
    fails("x = 1\nx.\uff3f\uff3fclass\uff3f\uff3f", "")
    # strings may hold any text and are just data
    r = calc("s = '\uff3f\uff3fimport\uff3f\uff3f'\nlen(s)")
    assert r["result"] == "0xa = 10"


HUGE = [
    ("2 ** 10 ** 10", "int_bits"),
    ("10 ** 100000", "int_bits"),
    ("x = 3\nfor i in range(30):\n    x = x * x", "int_bits"),
    ("1 << 10 ** 9", "int_bits"),
    ("1 << (1 << 100)", "int_bits"),
    ("pow(3, 10 ** 6)", "int_bits"),
    ("pow(2, 2 ** 20000, 3 ** 20000)", "powmod_bits"),
    ("pow(2, 2 ** 9000, 2 ** 9000 + 1)", "powmod_bits"),
    ("[0] * 10 ** 9", "length"),
    ("b'a' * 10 ** 9", "length"),
    ("'a' * 2 ** 40", "length"),
    ("10 ** 9 * [0]", "length"),
    ("x = [0] * 1000000\ny = x + x", "length"),
    ("x = b'a' * 1000000\nx = x + x", "length"),
    ("bytes(10 ** 10)", "length"),
    ("list(range(10 ** 12))", "length"),
    ("sorted(range(10 ** 12))", "length"),
    ("sum(range(10 ** 12))", "length"),
    ("max(range(10 ** 12))", "length"),
    ("zip(range(10 ** 12))", "length"),
    ("x = []\nwhile True:\n    x.append(1)", "limit"),
    ("b'x'.ljust(10 ** 9)", "length"),
    ("b'a' * 1000 .replace(b'a', b'a' * 100000)", ""),
    ("(b'a' * 1000).replace(b'a', b'a' * 100000)", "length"),
    ("b','.join([b'a' * 100000] * 100)", "length"),
    ("to_bytes(1, 10 ** 9)", "length"),
    ("(1).to_bytes(10 ** 9, 'big')", "length"),
    ("int('9' * 100000)", "int_bits"),
    ("int('f' * 100000, 16)", "int_bits"),
    ("from_bytes(bytes(1000000))", "int_bits"),
    ("pack('999999999x')", "length"),
    ("p32le(list(range(300000)))", "length"),
    ("lcm(*[2 ** 60000, 3 ** 30000])", ""),
    ("rc4(b'k', b'', drop=10 ** 12)", "drop"),
    ("sm2_kdf(b'z', 10 ** 9)", "klen"),
    ("ec_mul('sm2', 1 << 5000)", "reduce"),
]


@pytest.mark.parametrize("code,word", HUGE)
def test_size_bombs_are_refused_before_running(code, word):
    t = time.monotonic()
    fails(code, word)
    assert time.monotonic() - t < 3, code


def test_loops_and_steps_are_bounded():
    t = time.monotonic()
    fails("while True:\n    pass", "loop_iterations")
    fails("while 1:\n    x = 1", "loop_iterations")
    fails("for i in range(10 ** 18):\n    pass", "loop_iterations")
    fails("x = [1]\nfor v in x:\n    x.append(v)", "")
    fails("[i for i in range(10 ** 9)]", "loop_iterations")
    fails("[[j for j in range(10000)] for i in range(10000)]", "")
    fails("n = 0\nfor i in range(900000):\n    n = n + i * 2 - 1 + i", "steps")
    assert time.monotonic() - t < 20


def test_recursion_is_refused():
    fails("def f(n):\n    return f(n - 1)\nf(5)", "recursion")
    fails("def a(n):\n    return b(n)\ndef b(n):\n    return a(n)\na(1)", "recursion")


def test_deep_nesting_in_code():
    fails("(" * 500 + "1" + ")" * 500)
    fails("[" * 300 + "]" * 300)
    fails("-" * 5000 + "1")
    fails("x = " + "+".join(["1"] * 6000))
    fails("x = " + "not " * 3000 + "1")
    fails("x = " + "f(" * 200 + ")" * 200)
    nest = "if 1:\n"
    for i in range(1, 120):
        nest += "    " * i + "if 1:\n"
    nest += "    " * 120 + "x = 1\n"
    fails(nest)


def test_deeply_nested_values_cannot_crash_hashing_or_comparison():
    # a 300000-deep tuple used as a dict key used to segfault CPython's tuple hash
    fails("t = ()\nfor i in range(200000):\n    t = (t,)\nd = {t: 1}", "nesting")
    fails("t = ()\nfor i in range(200000):\n    t = (t,)\nt in {}", "nesting")
    fails("a = []\na.append(a)\nb = []\nb.append(b)\na == b", "nesting")
    # shared sub-lists that expand exponentially when compared
    fails("a = [0]\nb = [0]\nfor i in range(60):\n    a = [a, a]\n    b = [b, b]\na == b", "structure")
    fails("a = [0]\nfor i in range(60):\n    a = [a, a]\nsorted([a, a])", "structure")
    fails("a = (0,)\nfor i in range(60):\n    a = (a, a)\n{a: 1}", "structure")
    # rendering such values is bounded too
    r = calc("a = [0]\nfor i in range(60):\n    a = [a, a]\na")
    assert "error" not in r and len(json.dumps(r)) <= 50000
    r = calc("a = []\na.append(a)\na")
    assert r["result"] == ["[cycle]"]


def test_long_input():
    fails("x = 1\n" * 4000, "code_length")
    fails("x = '" + "a" * 30000 + "'", "code_length")


STRING_PAYLOADS = [
    "__import__('os').system('touch {c}')",
    "open('{c}', 'w').write('x')",
    "exec(\"open('{c}','w')\")",
    "{{0.__class__.__mro__}}",
    "${{touch {c}}}",
    "`touch {c}`",
    "%(x)s",
]


@pytest.mark.parametrize("payload", STRING_PAYLOADS)
def test_code_in_strings_is_only_data(payload):
    s = payload.format(c=CANARY)
    lit = json.dumps(s)
    for call in ["hmac(%s, b'k', b'm')", "hash_consts(%s)", "hash_compress(%s, [0] * 8, bytes(64))",
                 "ec_curve(%s)", "ec_mul(%s, 2)", "b'x'.decode(%s)", "'x'.encode(%s)",
                 "bytes('x', %s)", "unhex(%s)", "int(%s)", "int(%s, 16)", "b64dec(%s)",
                 "b64enc(b'x', alphabet=%s)", "pack(%s, 1)", "unpack(%s, b'abcd')",
                 "cbc_enc(%s, bytes(16), bytes(16), bytes(16))", "ctr(%s, bytes(16), bytes(16), b'')",
                 "from_bytes(b'ab', %s)", "sm2_decrypt(1, bytes(97), mode=%s)", "hexstr(b'ab', %s)",
                 "chacha20_block(bytes(32), 0, bytes(12), sigma=%s)"]:
        r = calc(call % lit)
        assert "error" in r or "result" in r
        assert "internal error" not in r.get("error", ""), (call, r)
    # string methods treat the text as text
    r = calc("s = %s\ns.upper().lower() == s.lower()" % lit)
    assert r["result"] is True


def test_cli_request_limits():
    p = cli({"code": "x = 1", "extra": 1})
    assert "unknown request keys" in json.loads(p.stdout)["error"]
    p = cli("x" * (300 * 1024), raw=True)
    assert "request_size" in json.loads(p.stdout)["error"]
    p = cli("[1, 2", raw=True)
    assert "not valid JSON" in json.loads(p.stdout)["error"]
    p = cli("[" * 100000 + "]" * 100000, raw=True)
    assert "not valid JSON" in json.loads(p.stdout)["error"]
    p = cli({"code": "1", "id": [[1]]})
    assert "id must be" in json.loads(p.stdout)["error"]
    p = cli({"code": 5})
    assert "code must be a string" in json.loads(p.stdout)["error"]


def test_cli_time_limit_interrupts_long_builtins():
    t = time.monotonic()
    # pure-Python hashing of 1 MB, many times: interrupted by the alarm, not killed
    p = cli({"code": "x = bytes(1000000)\nfor i in range(100):\n    x = sha512(x) * 15000", "timeout": 1})
    r = json.loads(p.stdout)
    assert "limit 'time' exceeded" in r["error"], r
    assert time.monotonic() - t < 6


def test_cli_process_cannot_open_files_or_fork():
    # Even code that reached Python could not open a file or start a process:
    # check the limits the launcher's process runs under.
    import subprocess
    from conftest import ROOT
    probe = (
        "import sys, os, resource; sys.path.insert(0, %r)\n"
        "from recalc import cli\n"
        "cli._prewarm(); cli.lockdown(5)\n"
        "out = {}\n"
        "try:\n    open('/dev/null'); out['open'] = 'allowed'\n"
        "except OSError as e:\n    out['open'] = 'refused'\n"
        "try:\n    pid = os.fork()\n    out['fork'] = 'allowed'\n    os._exit(0) if pid == 0 else os.waitpid(pid, 0)\n"
        "except OSError:\n    out['fork'] = 'refused'\n"
        "out['cpu'] = resource.getrlimit(resource.RLIMIT_CPU)[0]\n"
        "print(out)\n" % os.path.join(ROOT, "src"))
    py = os.path.join(ROOT, ".venv", "bin", "python")
    p = subprocess.run([py, "-I", "-S", "-c", probe], capture_output=True, text=True, env={}, timeout=30)
    out = eval(p.stdout)   # our own probe's output
    assert out["open"] == "refused"
    assert out["fork"] == "refused"
    assert out["cpu"] == 7


def test_no_stdin_after_the_request():
    r = cli({"code": "1"})
    assert json.loads(r.stdout)["result"] == 1


# ---- regressions from an independent adversarial review ---------------------

def _reply(code, **kw):
    p = cli(dict(code=code, **kw))
    assert p.returncode == 0 and p.stdout.count("\n") == 1, (code, p.returncode, p.stderr[-300:])
    return json.loads(p.stdout)


def test_lone_surrogates_are_escaped_not_a_crash():
    r = _reply("chr(0xd800)")
    assert r["result"] == "\ud800"
    p = cli({"code": "1", "id": "\ud800"})
    assert json.loads(p.stdout)["id"] == "\ud800"


def test_membership_in_a_huge_range_is_constant_time():
    t = time.monotonic()
    assert _reply("None in range(10 ** 18)", timeout=2)["result"] is False
    assert _reply("b'x' not in range(10 ** 18)", timeout=2)["result"] is True
    assert _reply("5 in range(10 ** 18)", timeout=2)["result"] is True
    assert time.monotonic() - t < 3


def test_c_level_work_on_long_strings_is_bounded():
    t = time.monotonic()
    for code, word in [
        ("s = 'a' * 1000000\nc = 'b' * 999999 + 'a'\ns.strip(c)", "256"),
        ("s = b'a' * 1000000\ns.rstrip(b'b' * 5000)", "256"),
        ("s = 'x' * (1 << 20)\nt = 'x' * ((1 << 20) - 1) + 'y'\nL = [s] * 900000\nt in L", "structure"),
        ("s = 'x' * (1 << 20)\nt = 'x' * ((1 << 20) - 1) + 'y'\nsorted([s, t] * 400000)", "structure"),
        ("s = 'x' * (1 << 20)\nL = [s] * 900000\nL.count(s + '')", "structure"),
        ("s = 'x' * (1 << 20)\nL = [s] * 900000\nM = [s + ''] * 900000\nL == M", "structure"),
        ("'abc'.startswith(tuple(['a'] * 1000))", "64"),
    ]:
        r = _reply(code, timeout=5)
        assert word in r["error"] + r.get("hint", ""), (code, r)
    assert time.monotonic() - t < 20


def test_error_messages_are_bounded():
    for code in ['assert False, "x" * 1000000', 'b"".decode("x" * 1000000)', '{}.pop("x" * 1000000)',
                 'hmac("y" * 1000000, b"", b"")', '{}.pop(("x" * (1 << 20),) * 150)',
                 '{}.pop(("x" * (1 << 20),) * 900000)', "from_bytes(b'ab', ('x' * 100000,) * 100)",
                 "rotl(-(1 << 60000), 1)", "[1][2 ** 65000]", "x" * 15000]:
        r = _reply(code, max_chars=1000)
        assert "error" in r and len(json.dumps(r, ensure_ascii=False, separators=(",", ":"))) <= 1000, code
    r = _reply("1 +", max_chars=300)
    assert len(json.dumps(r, ensure_ascii=False, separators=(",", ":"))) <= 300


def test_bulk_growth_is_charged_so_memory_checks_keep_up():
    r = _reply("r = range(1 << 20)\nM = [[] for i in range(60)]\nfor x in M:\n    x.extend(r)", timeout=20)
    assert "limit" in r["error"], r
    # merging dicts is charged by size (200 merges of 100000 entries cost more than 1.2M steps)
    r = _reply("d = {i: i for i in range(100000)}\ne = {}\nfor i in range(200):\n    e = e | d", timeout=20)
    assert r["steps"] > 1_500_000, r


def test_huge_ranges_render():
    r = _reply("range(2 ** 20000)")
    assert r["result"].startswith("range(0, 0x1")
    assert _reply("range(3, 10)")["result"] == "range(3, 10, 1)"


def test_slices_never_become_values():
    fails("d = {}\nd[1:2, 0] = 5", "slice")
    fails("x = [1, 2, 3]\nx[1:2, 0]", "slice")
    assert calc("x = [1, 2, 3, 4]\nx[1:3] = [9]\nx[::2]")["result"] == [1, 4]


def test_dict_value_errors_are_not_misreported_as_key_errors():
    r = err("d = {1: rotl('a', 1)}")
    assert "dict key" not in r["error"]
    r = err("d = {k: rotl('a', 1) for k in range(2)}")
    assert "dict key" not in r["error"]
