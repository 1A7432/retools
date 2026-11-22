"""Resource limits and the value checks that enforce them."""

from __future__ import annotations

import math
import resource
import sys
import time

from .errors import LimitError

MAX_STEPS = 5_000_000          # evaluation steps (one per syntax node, plus charges for bulk work)
MAX_ITER = 1_000_000           # loop iterations in total (for, while, comprehensions)
MAX_INT_BITS = 65_536          # bit length of any integer
MAX_LEN = 1 << 20              # length of any bytes, str, list, tuple, dict
MAX_POWMOD_BITS = 8_192        # modulus and exponent size for pow(b, e, m) (8192-bit: about 0.8 s)
MAX_CALL_DEPTH = 16            # nested calls of user-defined functions (recursion is refused)
MAX_AST_DEPTH = 100            # nesting depth of the parsed code
MAX_CODE = 20_000              # characters of code
MAX_PRINT = 200                # print() lines kept
MAX_MEM = 512 << 20            # peak resident memory of the process
MAX_WALK = 1_000_000           # elements visited when comparing or hashing nested containers
MAX_NEST = 64                  # nesting depth of containers that are compared or hashed
DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 60
DEFAULT_CHARS = 4000
MIN_CHARS, MAX_CHARS = 300, 50_000

ALLOWED_TYPES = (int, bool, str, bytes, list, tuple, dict, type(None), range)

_RSS_SCALE = 1 if sys.platform == "darwin" else 1024


def peak_rss():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * _RSS_SCALE


_CURRENT = [None]


def charge(n):
    """Charge bulk work done inside a built-in to the running evaluation."""
    b = _CURRENT[0]
    if b is not None and n > 0:
        b.step(n)


class Budget:
    """Step, iteration, time and memory accounting for one evaluation."""

    def __init__(self, timeout=DEFAULT_TIMEOUT, max_steps=MAX_STEPS, max_iter=MAX_ITER, max_mem=MAX_MEM):
        self.steps = 0
        self.iters = 0
        self.max_steps, self.max_iter, self.max_mem = max_steps, max_iter, max_mem
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self.base_rss = peak_rss()
        self._next_check = 1024
        _CURRENT[0] = self

    def step(self, n=1):
        self.steps += n
        if n >= 4096:                      # bulk work: a large value is being built
            self._next_check = 0
        if self.steps >= self._next_check:
            self._next_check = self.steps + 1024
            if self.steps > self.max_steps:
                raise LimitError("steps", "more than %d evaluation steps" % self.max_steps,
                                 "the computation is too long, or builds too much data, for a scratchpad; shrink the input or the loop")
            self.check_time()
            self.check_mem()

    def iterate(self):
        self.iters += 1
        if self.iters > self.max_iter:
            raise LimitError("loop_iterations", "more than %d loop iterations in total" % self.max_iter,
                             "an endless while loop, or a range that is too large")
        self.step()

    def check_time(self):
        if time.monotonic() > self.deadline:
            raise LimitError("time", "ran longer than %ss" % self.timeout,
                             "make the computation smaller, or raise timeout (at most %ds)" % MAX_TIMEOUT)

    def check_mem(self):
        if peak_rss() - self.base_rss > self.max_mem:
            raise LimitError("memory", "more than %d MB in use" % (self.max_mem >> 20),
                             "too many or too large values are alive at once")


def check_value(v):
    """Shallow size check of one value; returns it."""
    t = type(v)
    if t is int:
        if v.bit_length() > MAX_INT_BITS:
            raise LimitError("int_bits", "an integer of %d bits (limit %d)" % (v.bit_length(), MAX_INT_BITS),
                             "reduce modulo something, or mask with & mask(width)")
    elif t in (bytes, str, list, tuple, dict):
        if len(v) > MAX_LEN:
            raise LimitError("length", "a %s of length %d (limit %d)" % (t.__name__, len(v), MAX_LEN))
    return v


def need_len(n, what="result"):
    if n > MAX_LEN:
        raise LimitError("length", "%s would have length %d (limit %d)" % (what, n, MAX_LEN))


def need_bits(bits, what="result"):
    if bits > MAX_INT_BITS:
        raise LimitError("int_bits", "%s would have about %d bits (limit %d)" % (what, bits, MAX_INT_BITS),
                         "reduce modulo something, use pow(b, e, m), or mask with & mask(width)")


def pow_bits(b, e):
    """Approximate bit length of b ** e for e >= 0, without computing it."""
    if e == 0 or b in (0, 1, -1):
        return 1
    return int(e * math.log2(abs(b))) + 1


_CONT = (list, tuple, dict)


def _units(x):
    """Comparison cost of one leaf: 1, plus 1 per KB of text or bytes (memcmp)."""
    t = type(x)
    if t is str or t is bytes:
        return 1 + (len(x) >> 10)
    return 1


def walk(v):
    """Bound the work CPython will do when comparing or hashing v: count the
    elements it visits (expanding shared sub-containers as it does, and adding
    one unit per KB of text or bytes), and refuse values that are nested too
    deeply or too large. These traversals run in C, cannot be interrupted by the
    time limit, and (tuple hashing) are not protected against deep recursion, so
    they must be bounded before they start."""
    t = type(v)
    if t not in _CONT:
        return _units(v) - 1
    count = 0
    stack = [(v, 1)]
    while stack:
        c, d = stack.pop()
        if d > MAX_NEST:
            raise LimitError("nesting", "a value nested more than %d containers deep is compared or hashed"
                             % MAX_NEST, "flatten the structure")
        count += len(c)
        if type(c) is dict:
            children = [y for kv in c.items() for y in kv]
        else:
            children = c
        for x in children:
            tx = type(x)
            if tx in _CONT:
                stack.append((x, d + 1))
            elif tx is str or tx is bytes:
                count += len(x) >> 10
        if count > MAX_WALK:
            raise LimitError("structure", "comparing or hashing would visit more than %d elements"
                             % MAX_WALK, "the value repeats large sub-lists or long strings many times; "
                             "compare smaller parts")
    return count
