"""The fixed tables of functions and methods the language can call.

Every function here receives only language values (int, bool, str, bytes,
list, tuple, dict, None, range) and returns only language values; the
interpreter re-checks the results. Nothing here evaluates text as code.
"""

from __future__ import annotations

import base64
import binascii
import inspect
import math
import struct

from . import ciphers, ec, hashes
from . import limits as L
from .errors import CalcError, short
from .limits import need_bits, need_len

FUNCTIONS = {}
GROUPS = {}          # group -> [names] in definition order
DOCS = {}


def fn(group, doc, name=None):
    def deco(f):
        nm = name or f.__name__.rstrip("_")
        FUNCTIONS[nm] = f
        GROUPS.setdefault(group, []).append(nm)
        DOCS[nm] = doc
        return f
    return deco


def alias(new, old, group):
    FUNCTIONS[new] = FUNCTIONS[old]
    GROUPS.setdefault(group, []).append(new)
    DOCS[new] = "same as %s" % old


_SIG_CACHE = {}


def signature(name):
    if name in _SIG_CACHE:
        return _SIG_CACHE[name]
    f = FUNCTIONS.get(name)
    if f is None:
        for st, table in STATICS.items():
            if name.startswith(st + ".") and name[len(st) + 1:] in table:
                f = table[name[len(st) + 1:]]
    if f is None and "." in name:
        tname, m = name.split(".", 1)
        for (t, mm), g in METHODS.items():
            if mm == m and t.__name__ == tname:
                f = g
    if f is None:
        return name + "(...)"
    try:
        sig = str(inspect.signature(f))
    except (TypeError, ValueError):
        sig = "(...)"
    if "." in name and sig.startswith("(obj"):
        sig = "(" + sig[4:].lstrip(", ")
    out = name + sig
    _SIG_CACHE[name] = out
    return out


# ------------------------------------------------------------------ helpers

def _int(v, what="value"):
    if type(v) not in (int, bool):
        raise CalcError("%s must be an integer, got %s" % (what, type(v).__name__))
    return int(v)


def _bytes(v, what="value"):
    if type(v) is str:
        raise CalcError("%s must be bytes, not a string" % what, 'write b"...", unhex("..."), or s.encode()')
    if type(v) is not bytes:
        raise CalcError("%s must be bytes, got %s" % (what, type(v).__name__))
    return v


def _width(w):
    w = _int(w, "width")
    if not 1 <= w <= 4096:
        raise CalcError("width must be 1..4096 bits")
    return w


def _seq(v, what="argument"):
    t = type(v)
    if t is range:
        try:
            n = len(v)
        except OverflowError:
            n = L.MAX_LEN + 1
        need_len(n, "range(...) materialised")
        L.charge(n >> 4)
        return v
    if t in (list, tuple, bytes, str):
        return v
    if t is dict:
        return list(v)
    raise CalcError("%s must be a list, tuple, range, bytes or str, got %s" % (what, t.__name__))


def _ints(v, what="argument"):
    s = _seq(v, what)
    for x in s:
        if type(x) not in (int, bool):
            raise CalcError("%s must contain only integers, found %s" % (what, type(x).__name__))
    return s


def _order(order):
    o = {"little": "little", "le": "little", "<": "little", "big": "big", "be": "big", ">": "big"}.get(order)
    if o is None:
        raise CalcError("byte order must be 'little' or 'big', got %s" % short(order))
    return o


_ENCODINGS = {"utf-8", "utf8", "ascii", "latin-1", "latin1", "iso-8859-1", "utf-16", "utf-16-le",
              "utf-16le", "utf-16-be", "utf-16be", "utf-32-le", "utf-32-be", "gbk", "gb2312",
              "gb18030", "cp936", "big5", "shift_jis", "cp1252", "cp437"}
_ERRORS = {"strict", "replace", "ignore", "backslashreplace"}


def _enc(encoding, errors="strict"):
    if not isinstance(encoding, str) or encoding.lower() not in _ENCODINGS:
        raise CalcError("unknown or unavailable encoding %s" % short(encoding),
                        "one of: " + ", ".join(sorted(_ENCODINGS)))
    if errors not in _ERRORS:
        raise CalcError("errors must be one of: " + ", ".join(sorted(_ERRORS)))
    return encoding.lower(), errors


# ---------------------------------------------------------- integers and bits

def _fit(x, width, what="x"):
    x = _int(x, what)
    if x < 0:
        if x < -(1 << (width - 1)) * 2:
            raise CalcError("%s = %s does not fit in %d bits" % (what, short(x), width))
        x &= (1 << width) - 1
    elif x >> width:
        raise CalcError("%s = %s does not fit in %d bits" % (what, short(x), width),
                        "mask it first, e.g. x & mask(%d), or pass the right width" % width)
    return x


@fn("int", "rotate x left by n within width bits (negative x is taken as two's complement)")
def rotl(x, n, width=32):
    w = _width(width)
    x = _fit(x, w)
    n = _int(n, "n") % w
    return ((x << n) | (x >> (w - n))) & ((1 << w) - 1)


@fn("int", "rotate x right by n within width bits")
def rotr(x, n, width=32):
    w = _width(width)
    x = _fit(x, w)
    n = _int(n, "n") % w
    return ((x >> n) | (x << (w - n))) & ((1 << w) - 1)


@fn("int", "reverse the byte order of a width-bit value (width a multiple of 8)")
def bswap(x, width=32):
    w = _width(width)
    if w % 8:
        raise CalcError("bswap width must be a multiple of 8")
    return int.from_bytes(_fit(x, w).to_bytes(w // 8, "little"), "big")


@fn("int", "(1 << width) - 1")
def mask(width):
    return (1 << _width(width)) - 1


def _mk_trunc(bits):
    def u(x):
        return _int(x) & ((1 << bits) - 1)

    def s(x):
        v = _int(x) & ((1 << bits) - 1)
        return v - (1 << bits) if v >> (bits - 1) else v
    u.__name__, s.__name__ = "u%d" % bits, "s%d" % bits
    fn("int", "low %d bits, unsigned" % bits)(u)
    fn("int", "low %d bits as a signed (two's complement) value" % bits)(s)


for _b in (8, 16, 32, 64):
    _mk_trunc(_b)


@fn("int", "low width bits, unsigned (x & mask(width))")
def unsigned(x, width):
    return _int(x) & mask(width)


@fn("int", "low width bits read as a signed value")
def signed(x, width):
    w = _width(width)
    v = _int(x) & ((1 << w) - 1)
    return v - (1 << w) if v >> (w - 1) else v


@fn("int", "b ** e, or b ** e mod m (negative e with m: modular inverse power)")
def pow_(b, e, m=None):
    b, e = _int(b, "base"), _int(e, "exponent")
    if m is None:
        if e < 0:
            raise CalcError("negative exponent without a modulus gives a fraction",
                            "pass a modulus: pow(b, e, m)")
        need_bits(L.pow_bits(b, e), "pow(b, e)")
        return b ** e
    m = _int(m, "modulus")
    if m == 0:
        raise CalcError("modulus is zero")
    if m.bit_length() > L.MAX_POWMOD_BITS or e.bit_length() > L.MAX_POWMOD_BITS:
        raise CalcError("limit 'powmod_bits' exceeded: modulus and exponent must be at most %d bits"
                        % L.MAX_POWMOD_BITS)
    try:
        return pow(b, e, m)
    except ValueError:
        raise CalcError("base %s is not invertible modulo m (gcd != 1)" % short(b))


@fn("int", "a**-1 mod m")
def inverse(a, m):
    a, m = _int(a), _int(m, "modulus")
    if m == 0:
        raise CalcError("modulus is zero")
    try:
        return pow(a, -1, m)
    except ValueError:
        raise CalcError("%s has no inverse modulo %s (gcd is %s)" % (short(a), short(m), short(math.gcd(a, m))))


alias("modinv", "inverse", "int")


@fn("int", "greatest common divisor of any number of integers")
def gcd(*xs):
    return math.gcd(*[_int(x) for x in xs])


@fn("int", "least common multiple")
def lcm(*xs):
    vals = [_int(x) for x in xs]
    need_bits(sum(v.bit_length() for v in vals), "lcm")
    return math.lcm(*vals)


@fn("int", "extended Euclid: (g, x, y) with a*x + b*y = g")
def egcd(a, b):
    a, b = _int(a), _int(b)
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return (a, x0, y0)


@fn("int", "Chinese remainder: x with x = r[i] mod m[i] for pairwise-coprime moduli")
def crt(remainders, moduli):
    rs, ms = list(_ints(remainders, "remainders")), list(_ints(moduli, "moduli"))
    if len(rs) != len(ms) or not rs:
        raise CalcError("remainders and moduli must be non-empty lists of the same length")
    x, m = 0, 1
    for r, mi in zip(rs, ms):
        need_bits(m.bit_length() + mi.bit_length(), "the combined modulus")
        g = math.gcd(m, mi)
        if g != 1:
            raise CalcError("moduli are not pairwise coprime")
        x = (x + (r - x) * m * pow(m, -1, mi)) % (m * mi)
        m *= mi
    return x


@fn("int", "integer square root")
def isqrt(x):
    return math.isqrt(_int(x))


@fn("int", "probable-prime test (Miller-Rabin, 32 fixed bases; exact below 3.3e24)")
def is_prime(n):
    n = _int(n)
    if n.bit_length() > 4096:
        raise CalcError("is_prime takes numbers up to 4096 bits")
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
             83, 89, 97, 101, 103, 107, 109, 113, 127, 131]
    for p in small:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


@fn("int", "number of set bits (negative x: of its width-bit two's complement, width required)")
def popcount(x, width=None):
    x = _int(x)
    if x < 0:
        if width is None:
            raise CalcError("popcount of a negative number needs a width", "popcount(x, 32)")
        x &= mask(width)
    return x.bit_count()


@fn("int", "count of leading zero bits in a width-bit value")
def clz(x, width=32):
    w = _width(width)
    return w - _fit(x, w).bit_length()


@fn("int", "count of trailing zero bits (width if x is 0)")
def ctz(x, width=32):
    w = _width(width)
    x = _fit(x, w)
    return w if x == 0 else (x & -x).bit_length() - 1


@fn("int", "bytes to integer; order 'big' or 'little'")
def from_bytes(b, order="big", signed=False):
    b = _bytes(b, "b")
    need_bits(8 * len(b), "from_bytes")
    return int.from_bytes(b, _order(order), signed=bool(signed))


@fn("int", "integer to n bytes; order 'big' or 'little'; negative x needs signed=True")
def to_bytes(x, n, order="big", signed=False):
    x, n = _int(x), _int(n, "n")
    need_len(n, "to_bytes")
    try:
        return x.to_bytes(n, _order(order), signed=bool(signed))
    except OverflowError:
        if x < 0 and not signed:
            raise CalcError("negative value with signed=False", "pass signed=True, or mask: x & mask(%d)" % (8 * n))
        raise CalcError("%s does not fit in %d bytes" % (short(x), n))


@fn("int", "hex text; with bits=N, zero-padded to N bits")
def hex_(x, bits=None):
    x = _int(x)
    if bits is None:
        return hex(x)
    w = _width(bits)
    digits = (w + 3) // 4
    return ("-" if x < 0 else "") + "0x" + format(abs(x), "x").rjust(digits, "0")


@fn("int", "binary text; with bits=N, zero-padded to N bits")
def bin_(x, bits=None):
    x = _int(x)
    if bits is None:
        return bin(x)
    return ("-" if x < 0 else "") + "0b" + format(abs(x), "b").rjust(_width(bits), "0")


@fn("int", "absolute value")
def abs_(x):
    return abs(_int(x))


@fn("int", "(a // b, a % b)")
def divmod_(a, b):
    a, b = _int(a), _int(b)
    if b == 0:
        raise CalcError("division by zero")
    return divmod(a, b)


@fn("int", "integer from int, bool or text (int('ff', 16)); not from bytes (use from_bytes)")
def int_(x=0, base=None):
    t = type(x)
    if t in (int, bool):
        if base is not None:
            raise CalcError("int(x, base) needs text")
        return int(x)
    if t is str:
        b = 10 if base is None else _int(base, "base")
        if not (b == 0 or 2 <= b <= 36):
            raise CalcError("base must be 0 or 2..36")
        need_bits(int(len(x) * math.log2(max(b, 16))), "int(text)")
        try:
            return int(x, b)
        except ValueError as exc:
            raise CalcError("int(): %s" % exc)
    if t is bytes:
        raise CalcError("int() does not take bytes", "use from_bytes(b, 'little') or int(b.decode(), 16)")
    raise CalcError("int() cannot convert a %s" % t.__name__)


# ------------------------------------------------------ generic Python-like

@fn("seq", "length")
def len_(x):
    if type(x) not in (list, tuple, bytes, str, dict, range):
        raise CalcError("len() of a %s" % type(x).__name__)
    try:
        return len(x)
    except OverflowError:
        raise CalcError("the range is too long for len()")


@fn("seq", "range(stop) / range(start, stop[, step]); lazy, so only its use is bounded")
def range_(*a):
    if not 1 <= len(a) <= 3:
        raise CalcError("range takes 1 to 3 integers")
    return range(*[_int(v) for v in a])


@fn("seq", "sum of integers")
def sum_(xs, start=0):
    return sum(_ints(xs, "sum()"), _int(start, "start"))


def _minmax(f, name, args, default):
    if len(args) == 1:
        seq = _seq(args[0], name + "()")
    else:
        seq = args
    if not len(seq):
        if default is not None:
            return default
        raise CalcError("%s() of an empty sequence" % name, "pass default=...")
    try:
        return f(seq)
    except TypeError:
        raise CalcError("%s(): values cannot be compared (mixed types)" % name)


@fn("seq", "smallest of a sequence or of several arguments")
def min_(*args, default=None):
    return _minmax(min, "min", args, default)


@fn("seq", "largest of a sequence or of several arguments")
def max_(*args, default=None):
    return _minmax(max, "max", args, default)


@fn("seq", "list of tuples, as long as the shortest input")
def zip_(*seqs):
    return list(zip(*[_seq(s, "zip()") for s in seqs]))


@fn("seq", "list of (index, item) tuples")
def enumerate_(seq, start=0):
    return list(enumerate(_seq(seq, "enumerate()"), _int(start, "start")))


@fn("seq", "the items in reverse order, as a list (or bytes/str/range for those)")
def reversed_(seq):
    t = type(seq)
    if t in (bytes, str, range, tuple):
        return seq[::-1]
    return list(reversed(_seq(seq, "reversed()")))


@fn("seq", "sorted list")
def sorted_(seq, reverse=False):
    try:
        return sorted(_seq(seq, "sorted()"), reverse=bool(reverse))
    except TypeError:
        raise CalcError("sorted(): values cannot be compared (mixed types)")


@fn("seq", "list from a sequence (bytes give their byte values)")
def list_(x=()):
    return list(_seq(x, "list()"))


@fn("seq", "tuple from a sequence")
def tuple_(x=()):
    return tuple(_seq(x, "tuple()"))


@fn("seq", "dict from pairs or another dict")
def dict_(x=None, **kw):
    out = {}
    if x is not None:
        if type(x) is dict:
            out.update(x)
        else:
            for pair in _seq(x, "dict()"):
                if type(pair) not in (list, tuple) or len(pair) != 2:
                    raise CalcError("dict() needs (key, value) pairs")
                out[pair[0]] = pair[1]
    out.update(kw)
    return out


@fn("seq", "truth value")
def bool_(x=False):
    return bool(x)


@fn("seq", "True if any item is true")
def any_(xs):
    return any(_seq(xs, "any()"))


@fn("seq", "True if all items are true")
def all_(xs):
    return all(_seq(xs, "all()"))


@fn("seq", "one-character string from a code point")
def chr_(i):
    return chr(_int(i))


@fn("seq", "code point of a 1-character string, or value of a 1-byte bytes")
def ord_(c):
    if type(c) not in (str, bytes) or len(c) != 1:
        raise CalcError("ord() takes a string or bytes of length 1")
    return ord(c)


@fn("seq", "text: str(int) is decimal; for bytes use hexstr(b) or b.decode()")
def str_(x=""):
    t = type(x)
    if t is str:
        return x
    if t in (int, bool) or x is None:
        try:
            return str(x)
        except ValueError:
            raise CalcError("the integer is too large for decimal text", "use hex(x)")
    if t is bytes:
        raise CalcError("str() of bytes is ambiguous", "use b.decode('utf-8'), hexstr(b) or b.hex()")
    raise CalcError("str() of a %s is not supported" % t.__name__)


@fn("bytes", "bytes(n zero bytes) / bytes(list of 0..255) / bytes(text, encoding)")
def bytes_(x=b"", encoding=None, errors="strict"):
    t = type(x)
    if t is str:
        if encoding is None:
            raise CalcError("bytes(text) needs an encoding", "bytes(s, 'utf-8') or s.encode()")
        enc, err = _enc(encoding, errors)
        return x.encode(enc, err)
    if t in (int, bool):
        need_len(x, "bytes(n)")
        if x < 0:
            raise CalcError("negative length")
        return bytes(x)
    if t is bytes:
        return x
    s = _ints(x, "bytes()")
    try:
        return bytes(s)
    except ValueError:
        raise CalcError("bytes() values must be 0..255", "mask first: [v & 0xff for v in xs]")


# ------------------------------------------------------------------ bytes

@fn("bytes", "hex text to bytes; ignores whitespace and a leading 0x")
def unhex(s):
    if type(s) is bytes:
        s = s.decode("ascii", "replace")
    if type(s) is not str:
        raise CalcError("unhex() takes hex text")
    s = "".join(s.split())
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    if len(s) % 2:
        raise CalcError("hex text has an odd number of digits (%d)" % len(s), "pad with a leading 0")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise CalcError("not hex text: %s" % short(s))


@fn("bytes", "bytes to hex text; sep is put between bytes")
def hexstr(b, sep=""):
    b = _bytes(b, "b")
    if type(sep) is not str or len(sep) > 4:
        raise CalcError("sep must be a short string")
    return b.hex(sep) if sep else b.hex()


@fn("bytes", "data XOR key; the key repeats over data (an int key is one byte); result has len(data)")
def xor(data, key):
    data = _bytes(data, "data")
    if type(key) in (int, bool):
        if not 0 <= key <= 255:
            raise CalcError("an integer key must be one byte 0..255", "for wider keys use p32le(k) etc.")
        key = bytes([key])
    key = _bytes(key, "key")
    if not key:
        raise CalcError("key is empty")
    if len(key) < len(data):
        key = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key))


@fn("bytes", "concatenate bytes values (or lists of bytes)")
def cat(*parts):
    flat = []
    for p in parts:
        if type(p) in (list, tuple):
            flat.extend(p)
        else:
            flat.append(p)
    for p in flat:
        _bytes(p, "cat() part")
    need_len(sum(len(p) for p in flat), "cat()")
    return b"".join(flat)


@fn("bytes", "split bytes (or a list) into pieces of n")
def chunks(b, n):
    n = _int(n, "n")
    if n < 1:
        raise CalcError("n must be at least 1")
    if type(b) not in (bytes, list, tuple, str):
        raise CalcError("chunks() takes bytes, str or a list")
    return [b[i:i + n] for i in range(0, len(b), n)]


def _mk_pack(bits, order):
    size = bits // 8
    code = {16: "H", 32: "I", 64: "Q"}[bits]
    pre = "<" if order == "little" else ">"
    tag = "%d%s" % (bits, "le" if order == "little" else "be")

    def unpack(b):
        b = _bytes(b, "b")
        if len(b) % size:
            raise CalcError("%d bytes is not a multiple of %d" % (len(b), size),
                            "slice first, e.g. b[:%d]" % (size * (len(b) // size)))
        return list(struct.unpack(pre + "%d%s" % (len(b) // size, code), b))

    def pack(xs):
        vals = [xs] if type(xs) in (int, bool) else list(_ints(xs, "values"))
        need_len(len(vals) * size, "the packed bytes")
        lim = 1 << bits
        for v in vals:
            if not -(lim >> 1) <= v < lim:
                raise CalcError("%s does not fit in %d bits" % (short(v), bits), "mask first: u%d(v)" % bits)
        return b"".join((v & (lim - 1)).to_bytes(size, order) for v in vals)

    unpack.__name__, pack.__name__ = "u" + tag, "p" + tag
    fn("bytes", "bytes to a list of %d-bit %s-endian integers" % (bits, order))(unpack)
    fn("bytes", "an int or list of ints to %d-bit %s-endian bytes" % (bits, order))(pack)


for _bits in (16, 32, 64):
    for _o in ("little", "big"):
        _mk_pack(_bits, _o)


def _fmt(fmt):
    if type(fmt) is not str or len(fmt) > 64:
        raise CalcError("struct format must be a short string such as '<IHH'")
    bad = set(fmt) - set("<>!=@ 0123456789xcbBhHiIlLqQnNsp?")
    if bad:
        raise CalcError("struct format characters not supported: %s" % "".join(sorted(bad)),
                        "integers and bytes only (no floats e/f/d)")
    try:
        size = struct.calcsize(fmt)
    except struct.error as exc:
        raise CalcError("bad struct format: %s" % exc)
    need_len(size, "the struct")
    return size


@fn("bytes", "struct.pack with a format such as '<IHH'")
def pack(fmt, *vals):
    _fmt(fmt)
    try:
        return struct.pack(fmt, *vals)
    except struct.error as exc:
        raise CalcError("pack: %s" % exc)


@fn("bytes", "struct.unpack, returns a tuple")
def unpack(fmt, b):
    _fmt(fmt)
    try:
        return struct.unpack(fmt, _bytes(b, "b"))
    except struct.error as exc:
        raise CalcError("unpack: %s" % exc)


_STD64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _alpha(alphabet):
    if alphabet is None:
        return None, "="
    if type(alphabet) is bytes:
        alphabet = alphabet.decode("latin-1")
    if type(alphabet) is not str or len(alphabet) not in (64, 65) or len(set(alphabet)) != len(alphabet):
        raise CalcError("alphabet must be 64 distinct characters (a 65th sets the pad character)")
    return alphabet[:64], (alphabet[64] if len(alphabet) == 65 else "=")


@fn("bytes", "base64 text; alphabet = 64 custom characters (+ optional pad char)")
def b64enc(b, alphabet=None, pad=True):
    b = _bytes(b, "b")
    need_len(len(b) * 4 // 3 + 4, "base64 text")
    alpha, padc = _alpha(alphabet)
    s = base64.b64encode(b).decode()
    if not pad:
        s = s.rstrip("=")
    if alpha is None:
        return s
    return s.translate(str.maketrans(_STD64 + "=", alpha + padc))


@fn("bytes", "decode base64 text (whitespace ignored, missing padding tolerated)")
def b64dec(s, alphabet=None):
    if type(s) is bytes:
        s = s.decode("latin-1")
    if type(s) is not str:
        raise CalcError("b64dec() takes text")
    alpha, padc = _alpha(alphabet)
    s = "".join(s.split())
    if alpha is not None:
        bad = set(s) - set(alpha) - {padc}
        if bad:
            raise CalcError("characters not in the alphabet: %r" % "".join(sorted(bad))[:20])
        s = s.translate(str.maketrans(alpha + padc, _STD64 + "="))
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        raise CalcError("base64 text has an impossible length (%d characters without padding)" % len(s))
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CalcError("bad base64: %s" % exc)


# ---------------------------------------------------------------- hashes

@fn("hash", "SHA-256; K = 64 round constants or {index: value} patch; IV = 8 words or patch")
def sha256(msg, K=None, IV=None):
    return hashes.sha256(msg, K, IV)


@fn("hash", "SHA-224 (SHA-256 constants, own IV)")
def sha224(msg, K=None, IV=None):
    return hashes.sha224(msg, K, IV)


@fn("hash", "SHA-512; K = 80 constants or patch; IV = 8 words or patch")
def sha512(msg, K=None, IV=None):
    return hashes.sha512(msg, K, IV)


@fn("hash", "SHA-384")
def sha384(msg, K=None, IV=None):
    return hashes.sha384(msg, K, IV)


@fn("hash", "SHA-1; K = 4 constants or patch; IV = 5 words or patch")
def sha1(msg, K=None, IV=None):
    return hashes.sha1(msg, K, IV)


@fn("hash", "MD5; K = 64 sine constants or patch; IV = 4 words or patch")
def md5(msg, K=None, IV=None):
    return hashes.md5(msg, K, IV)


@fn("hash", "SM3; IV = 8 words or patch; T = the two round constants [T0, T1] or patch")
def sm3(msg, IV=None, T=None):
    return hashes.sm3(msg, IV, T)


@fn("hash", "HMAC with any hash above; ipad/opad bytes and block size can be changed")
def hmac(hash_name, key, msg, ipad=0x36, opad=0x5C, block=None):
    return hashes.hmac(hash_name, key, msg, ipad, opad, block)


@fn("hash", "standard constant tables of a hash: {'K': [...], 'IV': [...]} (SM3: T, IV)")
def hash_consts(name):
    if not isinstance(name, str) or name.lower() not in hashes.CONSTS:
        raise CalcError("unknown hash %s" % short(name), "one of: " + ", ".join(sorted(hashes.CONSTS)))
    return {k: list(v) for k, v in hashes.CONSTS[name.lower()].items()}


@fn("hash", "one compression step: new state words from state words and one block (no padding)")
def hash_compress(name, state, block, K=None):
    return hashes.compress(name, state, block, K)


@fn("hash", "generic CRC (Rocksoft model): width, poly, init, xorout, refin, refout")
def crc(data, width, poly, init=0, xorout=0, refin=False, refout=False):
    data = _bytes(data, "data")
    w = _int(width, "width")
    if not 1 <= w <= 128:
        raise CalcError("CRC width must be 1..128")
    m = (1 << w) - 1
    poly, init, xorout = _int(poly) & m, _int(init) & m, _int(xorout) & m

    def refl(v, n):
        r = 0
        for _ in range(n):
            r, v = (r << 1) | (v & 1), v >> 1
        return r

    top = 1 << (w - 1)
    reg = init
    for byte in data:
        if refin:
            byte = refl(byte, 8)
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            fb = bool(reg & top) ^ bit
            reg = (reg << 1) & m
            if fb:
                reg ^= poly
    if refout:
        reg = refl(reg, w)
    return reg ^ xorout


@fn("hash", "CRC-32 (zlib / IEEE 802.3)")
def crc32(data):
    return crc(data, 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)


@fn("hash", "Adler-32 (zlib)")
def adler32(data):
    data = _bytes(data, "data")
    a, b = 1, 0
    for x in data:
        a = (a + x) % 65521
        b = (b + a) % 65521
    return (b << 16) | a


_FNV = {32: (0x811C9DC5, 0x01000193), 64: (0xCBF29CE484222325, 0x100000001B3)}


def _fnv(data, width, prime, basis, xor_first):
    data = _bytes(data, "data")
    w = _int(width, "width")
    if w not in _FNV:
        raise CalcError("FNV width must be 32 or 64")
    b0, p0 = _FNV[w]
    h = b0 if basis is None else _int(basis, "basis")
    p = p0 if prime is None else _int(prime, "prime")
    m = (1 << w) - 1
    for x in data:
        if xor_first:
            h = ((h ^ x) * p) & m
        else:
            h = ((h * p) & m) ^ x
    return h


@fn("hash", "FNV-1a (32 or 64 bit); prime and offset basis can be changed")
def fnv1a(data, width=32, prime=None, basis=None):
    return _fnv(data, width, prime, basis, True)


@fn("hash", "FNV-1 (32 or 64 bit)")
def fnv1(data, width=32, prime=None, basis=None):
    return _fnv(data, width, prime, basis, False)


# ---------------------------------------------------------------- ciphers

for _name in ("aes_enc", "aes_dec", "sm4_enc", "sm4_dec", "ecb_enc", "ecb_dec", "cbc_enc", "cbc_dec",
              "ctr", "pkcs7_pad", "pkcs7_unpad", "rc4", "chacha20_block", "chacha20", "tea_enc",
              "tea_dec", "xtea_enc", "xtea_dec", "xxtea_enc", "xxtea_dec"):
    _f = getattr(ciphers, _name)
    FUNCTIONS[_name] = _f
    GROUPS.setdefault("cipher", []).append(_name)
    DOCS[_name] = (_f.__doc__ or "").strip().split("\n")[0]

DOCS.update({
    "aes_enc": "AES-128/192/256 ECB over whole 16-byte blocks; sbox= to try a modified S-box",
    "aes_dec": "AES ECB decryption",
    "sm4_enc": "SM4 ECB over whole blocks; sbox=, FK=, CK= overrides",
    "sm4_dec": "SM4 ECB decryption",
    "ecb_enc": "ECB with a named cipher: ecb_enc('aes'|'sm4'|'tea'|'xtea', key, data, ...)",
    "ecb_dec": "ECB decryption with a named cipher",
    "cbc_enc": "CBC: cbc_enc(cipher, key, iv, data) (no padding added; use pkcs7_pad)",
    "cbc_dec": "CBC decryption (padding not removed; use pkcs7_unpad)",
    "ctr": "CTR: ctr(cipher, key, block0, data, ctr_len=16, ctr_pos=16-ctr_len, order='big')",
    "pkcs7_pad": "PKCS#7 padding to a block size (default 16)",
    "pkcs7_unpad": "remove PKCS#7 padding, with a clear error if it is invalid",
    "rc4": "RC4 keystream XOR; drop= skips that many keystream bytes first",
    "chacha20_block": "one 64-byte ChaCha block (key 32, counter, nonce 12 or 8 bytes, rounds, sigma)",
    "chacha20": "ChaCha20 stream XOR: chacha20(key, nonce, data, counter=0, rounds=20)",
    "tea_enc": "TEA on 8-byte blocks; bytes need order='little'/'big'; rounds=, delta=",
    "tea_dec": "TEA decryption",
    "xtea_enc": "XTEA; same conventions as tea_enc",
    "xtea_dec": "XTEA decryption",
    "xxtea_enc": "XXTEA (corrected block TEA) over the whole buffer; order= for bytes",
    "xxtea_dec": "XXTEA decryption",
})


# --------------------------------------------------------------- curves

def _reg(name, f, doc):
    FUNCTIONS[name] = f
    GROUPS.setdefault("ec", []).append(name)
    DOCS[name] = doc


_reg("ec_curve", ec.curve_params, "parameters {p, a, b, n, Gx, Gy} of 'sm2', 'p256', 'secp256k1'")
_reg("ec_on_curve", ec.on_curve, "True if the point (x, y) is on the curve")
_reg("ec_add", ec.add, "P + Q (points are (x, y) tuples, None is infinity)")
_reg("ec_neg", ec.neg, "-P")
_reg("ec_mul", ec.mul, "k * P, P defaults to the generator G")
_reg("ec_decompress", ec.decompress, "point from x and the parity of y (0/1, or prefix 2/3)")
_reg("ec_decode", ec.decode_point, "point from 04||x||y, x||y or 02/03||x bytes")
_reg("ec_encode", ec.encode, "point to 04||x||y bytes (compressed=True: 02/03||x)")
_reg("ec_affine", ec.affine, "Jacobian (X/Z^2, Y/Z^3) or kind='projective' (X/Z, Y/Z) to affine")
_reg("ecdsa_verify", ec.ecdsa_verify, "ECDSA check: ecdsa_verify(curve, P, e, r, s), e = hash bytes or int")
_reg("ecdsa_sign", ec.ecdsa_sign, "ECDSA with a given nonce k: (r, s)")
_reg("sm2_za", ec.sm2_za, "SM2 Z value: SM3(ENTL||ID||a||b||Gx||Gy||Px||Py); id default 1234567812345678")
_reg("sm2_kdf", ec.sm2_kdf, "SM2 KDF: klen bytes from z (SM3 with a 32-bit big-endian counter from 1)")
_reg("sm2_verify", ec.sm2_verify, "SM2 signature check: sm2_verify(P, msg, r, s, id=None, hashed=False)")
_reg("sm2_sign", ec.sm2_sign, "SM2 signature with a given nonce k: (r, s)")
_reg("sm2_encrypt", ec.sm2_encrypt, "SM2 encryption with a given k; mode 'c1c3c2' or 'c1c2c3'")
_reg("sm2_decrypt", ec.sm2_decrypt, "SM2 decryption with private key d; mode 'c1c3c2' or 'c1c2c3'")

FUNCTIONS["print"] = None     # handled by the interpreter
GROUPS.setdefault("seq", []).append("print")
DOCS["print"] = "add a line to the reply's 'printed' list"


# ---------------------------------------------------------------- methods

METHODS = {}


def method(t, name):
    def deco(f):
        METHODS[(t, name)] = f
        return f
    return deco


def _m(t, name, py=None, check=None):
    """Expose a Python method of a value type, after an optional argument check."""
    py = py or name

    def f(obj, *a, **kw):
        if check:
            check(obj, *a, **kw)
        return getattr(obj, py)(*a, **kw)
    f.__name__ = name
    METHODS[(t, name)] = f


def _chars_check(obj, chars=None):
    # strip with a long character set is O(len * len(chars)) in C
    if chars is not None and type(chars) in (str, bytes) and len(chars) > 256:
        raise CalcError("strip characters: at most 256", "pass the set of characters to remove")


def _affix_check(obj, affix, *rest):
    # a tuple of prefixes is tried one by one in C
    if type(affix) is tuple and (len(affix) > 64 or sum(len(a) if type(a) in (str, bytes) else 0
                                                         for a in affix) > L.MAX_LEN):
        raise CalcError("startswith/endswith take at most 64 alternatives")


for _t in (bytes, str):
    for _n in ("find", "rfind", "index", "count", "split", "upper", "lower", "isdigit", "isalnum",
               "isalpha", "isascii", "isspace"):
        _m(_t, _n)
    for _n in ("strip", "lstrip", "rstrip"):
        _m(_t, _n, check=_chars_check)
    for _n in ("startswith", "endswith"):
        _m(_t, _n, check=_affix_check)


def _just(obj, width, fill=None):
    need_len(_int(width, "width"), "the padded value")


for _t in (bytes, str):
    _m(_t, "ljust", check=_just)
    _m(_t, "rjust", check=_just)


def _join_check(obj, parts):
    s = _seq(parts, "join()")
    need_len(sum(len(p) if type(p) in (bytes, str) else 0 for p in s) + len(obj) * len(s), "join()")


def _replace_check(obj, old, new, count=-1):
    n = obj.count(old) if type(old) is type(obj) else 0
    if count >= 0:
        n = min(n, count)
    if old == obj[:0]:
        n = len(obj) + 1
    need_len(len(obj) + n * (len(new) - len(old)), "replace()")


for _t in (bytes, str):
    _m(_t, "join", check=_join_check)
    _m(_t, "replace", check=_replace_check)
_m(bytes, "hex")


@method(bytes, "decode")
def _decode(obj, encoding="utf-8", errors="strict"):
    enc, err = _enc(encoding, errors)
    try:
        return obj.decode(enc, err)
    except UnicodeDecodeError as exc:
        raise CalcError("cannot decode as %s: %s" % (enc, exc.reason),
                        "errors='replace', another encoding, or look at hexstr(b)")


@method(str, "encode")
def _encode(obj, encoding="utf-8", errors="strict"):
    enc, err = _enc(encoding, errors)
    try:
        return obj.encode(enc, err)
    except UnicodeEncodeError as exc:
        raise CalcError("cannot encode as %s: %s" % (enc, exc.reason))


@method(int, "to_bytes")
def _to_bytes(obj, length=1, byteorder="big", signed=False):
    return to_bytes(obj, length, byteorder, signed)


_m(int, "bit_length")
_m(int, "bit_count")


@method(list, "append")
def _append(obj, x):
    need_len(len(obj) + 1, "the list")
    obj.append(x)


@method(list, "extend")
def _extend(obj, xs):
    s = _seq(xs, "extend()")
    need_len(len(obj) + len(s), "the list")
    L.charge(len(s) >> 4)
    obj.extend(s)


@method(list, "insert")
def _insert(obj, i, x):
    need_len(len(obj) + 1, "the list")
    obj.insert(_int(i, "index"), x)


@method(list, "sort")
def _sort(obj, reverse=False):
    try:
        obj.sort(reverse=bool(reverse))
    except TypeError:
        raise CalcError("sort(): values cannot be compared (mixed types)")


for _n in ("pop", "index", "count", "reverse", "copy", "clear"):
    _m(list, _n)
for _n in ("index", "count"):
    _m(tuple, _n)


@method(dict, "keys")
def _keys(obj):
    return list(obj.keys())


@method(dict, "values")
def _values(obj):
    return list(obj.values())


@method(dict, "items")
def _items(obj):
    return list(obj.items())


@method(dict, "update")
def _update(obj, other):
    if type(other) is not dict:
        raise CalcError("update() takes a dict")
    need_len(len(obj) + len(other), "the dict")
    L.charge(len(other) >> 4)
    obj.update(other)


@method(dict, "setdefault")
def _setdefault(obj, key, default=None):
    if key not in obj:
        need_len(len(obj) + 1, "the dict")
    return obj.setdefault(key, default)


for _n in ("get", "pop", "copy", "clear"):
    _m(dict, _n)

METHOD_NAMES = frozenset(n for (_, n) in METHODS)

STATICS = {
    "int": {"from_bytes": lambda b, byteorder="big", signed=False: from_bytes(b, byteorder, signed)},
    "bytes": {"fromhex": lambda s: unhex(s)},
}
