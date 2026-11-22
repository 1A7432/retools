"""Random token soup and mutated programs: the evaluator must only ever give a
result or a clean error, never an internal error, crash or hang."""

import random
import time

from conftest import calc

TOKENS = (["x", "y", "i", "lst", "d", "b", "rotl", "sha256", "pow", "len", "range", "xor", "unhex",
           "ec_mul", "print", "hex", "int", "bytes", "list", "sorted", "__class__", "_", "def", "f",
           "return", "for", "in", "while", "if", "else", "elif", "break", "continue", "not", "and",
           "or", "is", "None", "True", "False", "lambda", "import", "class", "assert", "pass"]
          + ["0", "1", "2", "255", "0xffffffff", "10**9", "b'ab'", "'s'", "b''", "-1", "1<<40"]
          + list("+-*/%&|^~<>=()[]{}:,.") + ["**", "//", "<<", ">>", "==", "!=", "<=", ">=", "+=",
                                             "\n", "\n    ", "\n        ", " ", "'sm2'", "...", "@"])

SEEDS = [
    "x = 5\ny = rotl(x, 3)\nlst = [x, y]\nfor i in range(4):\n    lst.append(lst[-1] ^ i)\nlst",
    "def f(a, b=2):\n    return (a * b) & 0xff\nd = {i: f(i) for i in range(8)}\nsorted(d.values())",
    "b = unhex('00ff10')\nk = xor(b, 0x5a)\nhexstr(sha256(k + b))[:16]",
    "P = ec_mul('sm2', 3)\nQ = ec_add('sm2', P, P)\nec_on_curve('sm2', Q)",
    "n = 0\nwhile n < 10:\n    n += 3\n    if n > 6:\n        break\nn",
]


def _check(code):
    r = calc(code, timeout=2, max_chars=2000)
    assert isinstance(r, dict)
    if "error" in r:
        assert "internal error" not in r["error"], (code, r)
        assert isinstance(r.get("hint"), str)
    else:
        assert "steps" in r


def test_random_token_soup():
    rng = random.Random(20261114)
    t = time.monotonic()
    for _ in range(3000):
        code = "".join(rng.choice(TOKENS) + rng.choice(["", " "]) for _ in range(rng.randrange(1, 25)))
        _check(code)
    assert time.monotonic() - t < 120


def test_mutated_programs():
    rng = random.Random(7)
    for _ in range(1500):
        s = list(rng.choice(SEEDS))
        for _ in range(rng.randrange(1, 4)):
            op = rng.randrange(3)
            pos = rng.randrange(len(s))
            if op == 0:
                del s[pos]
            elif op == 1:
                s.insert(pos, rng.choice(TOKENS))
            else:
                s[pos] = rng.choice(TOKENS)
        _check("".join(s))
