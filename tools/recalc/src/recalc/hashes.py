"""Pure-Python hash functions with overridable constants.

Every function takes the message as bytes and returns the digest as bytes.
`K` (round constants) and `IV` (initial state) may be given as a full list or
as a {index: value} patch over the standard table, so that "standard except
for one constant" can be tested directly.
"""

from __future__ import annotations

import math
import struct

from .errors import CalcError, short

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def _primes(n):
    out, c = [], 2
    while len(out) < n:
        if all(c % p for p in out if p * p <= c):
            out.append(c)
        c += 1
    return out


def _icbrt(n):
    lo, hi = 0, 1 << ((n.bit_length() + 2) // 3 + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _frac_root(p, bits, cube):
    # first `bits` bits of the fractional part of p**(1/2) or p**(1/3)
    if cube:
        r = _icbrt(p << (3 * bits))
    else:
        r = math.isqrt(p << (2 * bits))
    return r & ((1 << bits) - 1)


_P80 = _primes(80)
SHA256_K = [_frac_root(p, 32, True) for p in _P80[:64]]
SHA256_IV = [_frac_root(p, 32, False) for p in _P80[:8]]
SHA224_IV = [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
             0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4]
SHA512_K = [_frac_root(p, 64, True) for p in _P80]
SHA512_IV = [_frac_root(p, 64, False) for p in _P80[:8]]
SHA384_IV = [_frac_root(p, 64, False) for p in _P80[8:16]]
SHA1_K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & M32 for i in range(64)]
MD5_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
SM3_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
SM3_T = [0x79CC4519, 0x7A879D8A]


def _table(name, std, override, width):
    """Return the standard table with a full replacement or a patch applied."""
    if override is None:
        return list(std)
    limit = (1 << width) - 1
    if isinstance(override, dict):
        out = list(std)
        for k, v in override.items():
            if not isinstance(k, int) or isinstance(k, bool) or not 0 <= k < len(std):
                raise CalcError("%s patch index %s is out of range 0..%d" % (name, short(k), len(std) - 1))
            if not isinstance(v, int) or not 0 <= v <= limit:
                raise CalcError("%s[%d] must be an integer 0..%#x" % (name, k, limit))
            out[k] = v
        return out
    if isinstance(override, (list, tuple)):
        if len(override) != len(std):
            raise CalcError("%s must have %d entries, got %d" % (name, len(std), len(override)),
                            "or pass a {index: value} dict to patch single entries")
        for i, v in enumerate(override):
            if not isinstance(v, int) or not 0 <= v <= limit:
                raise CalcError("%s[%d] must be an integer 0..%#x" % (name, i, limit))
        return list(override)
    raise CalcError("%s must be a list of %d integers or a {index: value} patch" % (name, len(std)))


def _msg(msg):
    if isinstance(msg, str):
        raise CalcError("hash input must be bytes, not a string",
                        'write b"..." or s.encode() (UTF-8), or unhex("...")')
    if not isinstance(msg, bytes):
        raise CalcError("hash input must be bytes, got %s" % type(msg).__name__)
    return msg


def _md_pad(msg, block, lenbytes, order):
    n = len(msg)
    pad = b"\x80" + b"\x00" * ((block - lenbytes - 1 - n) % block)
    return msg + pad + (8 * n).to_bytes(lenbytes, order)


# ---- SHA-256 / SHA-224 -------------------------------------------------

def _r32(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _l32(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def sha256_compress(state, block, K):
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        x, y = w[t - 15], w[t - 2]
        s0 = _r32(x, 7) ^ _r32(x, 18) ^ (x >> 3)
        s1 = _r32(y, 17) ^ _r32(y, 19) ^ (y >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = state
    for t in range(64):
        t1 = (h + (_r32(e, 6) ^ _r32(e, 11) ^ _r32(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & M32
        t2 = ((_r32(a, 2) ^ _r32(a, 13) ^ _r32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    return [(x + y) & M32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def _sha256_family(msg, K, IV, std_iv, outwords):
    msg = _msg(msg)
    K = _table("K", SHA256_K, K, 32)
    st = _table("IV", std_iv, IV, 32)
    data = _md_pad(msg, 64, 8, "big")
    for i in range(0, len(data), 64):
        st = sha256_compress(st, data[i:i + 64], K)
    return struct.pack(">8I", *st)[:4 * outwords]


def sha256(msg, K=None, IV=None):
    return _sha256_family(msg, K, IV, SHA256_IV, 8)


def sha224(msg, K=None, IV=None):
    return _sha256_family(msg, K, IV, SHA224_IV, 7)


# ---- SHA-512 / SHA-384 -------------------------------------------------

def _r64(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def sha512_compress(state, block, K):
    w = list(struct.unpack(">16Q", block))
    for t in range(16, 80):
        x, y = w[t - 15], w[t - 2]
        s0 = _r64(x, 1) ^ _r64(x, 8) ^ (x >> 7)
        s1 = _r64(y, 19) ^ _r64(y, 61) ^ (y >> 6)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M64)
    a, b, c, d, e, f, g, h = state
    for t in range(80):
        t1 = (h + (_r64(e, 14) ^ _r64(e, 18) ^ _r64(e, 41)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & M64
        t2 = ((_r64(a, 28) ^ _r64(a, 34) ^ _r64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))) & M64
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M64, c, b, a, (t1 + t2) & M64
    return [(x + y) & M64 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def _sha512_family(msg, K, IV, std_iv, outbytes):
    msg = _msg(msg)
    K = _table("K", SHA512_K, K, 64)
    st = _table("IV", std_iv, IV, 64)
    data = _md_pad(msg, 128, 16, "big")
    for i in range(0, len(data), 128):
        st = sha512_compress(st, data[i:i + 128], K)
    return struct.pack(">8Q", *st)[:outbytes]


def sha512(msg, K=None, IV=None):
    return _sha512_family(msg, K, IV, SHA512_IV, 64)


def sha384(msg, K=None, IV=None):
    return _sha512_family(msg, K, IV, SHA384_IV, 48)


# ---- SHA-1 -----------------------------------------------------------------

def sha1_compress(state, block, K):
    w = list(struct.unpack(">16I", block))
    for t in range(16, 80):
        w.append(_l32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    a, b, c, d, e = state
    for t in range(80):
        if t < 20:
            f, k = (b & c) | (~b & d), K[0]
        elif t < 40:
            f, k = b ^ c ^ d, K[1]
        elif t < 60:
            f, k = (b & c) | (b & d) | (c & d), K[2]
        else:
            f, k = b ^ c ^ d, K[3]
        a, b, c, d, e = (_l32(a, 5) + (f & M32) + e + k + w[t]) & M32, a, _l32(b, 30), c, d
    return [(x + y) & M32 for x, y in zip(state, (a, b, c, d, e))]


def sha1(msg, K=None, IV=None):
    msg = _msg(msg)
    K = _table("K", SHA1_K, K, 32)
    st = _table("IV", SHA1_IV, IV, 32)
    data = _md_pad(msg, 64, 8, "big")
    for i in range(0, len(data), 64):
        st = sha1_compress(st, data[i:i + 64], K)
    return struct.pack(">5I", *st)


# ---- MD5 ---------------------------------------------------------------

def md5_compress(state, block, K):
    x = struct.unpack("<16I", block)
    a, b, c, d = state
    for i in range(64):
        if i < 16:
            f, g = (b & c) | (~b & d), i
        elif i < 32:
            f, g = (d & b) | (~d & c), (5 * i + 1) % 16
        elif i < 48:
            f, g = b ^ c ^ d, (3 * i + 5) % 16
        else:
            f, g = c ^ (b | (~d & M32)), (7 * i) % 16
        f = (f + a + K[i] + x[g]) & M32
        a, d, c = d, c, b
        b = (b + _l32(f, MD5_S[i])) & M32
    return [(p + q) & M32 for p, q in zip(state, (a, b, c, d))]


def md5(msg, K=None, IV=None):
    msg = _msg(msg)
    K = _table("K", MD5_K, K, 32)
    st = _table("IV", MD5_IV, IV, 32)
    data = _md_pad(msg, 64, 8, "little")
    for i in range(0, len(data), 64):
        st = md5_compress(st, data[i:i + 64], K)
    return struct.pack("<4I", *st)


# ---- SM3 ---------------------------------------------------------------

def _p0(x):
    return x ^ _l32(x, 9) ^ _l32(x, 17)


def _p1(x):
    return x ^ _l32(x, 15) ^ _l32(x, 23)


def sm3_compress(state, block, T):
    w = list(struct.unpack(">16I", block))
    for j in range(16, 68):
        w.append(_p1(w[j - 16] ^ w[j - 9] ^ _l32(w[j - 3], 15)) ^ _l32(w[j - 13], 7) ^ w[j - 6])
    w1 = [w[j] ^ w[j + 4] for j in range(64)]
    a, b, c, d, e, f, g, h = state
    for j in range(64):
        t = T[0] if j < 16 else T[1]
        ss1 = _l32((_l32(a, 12) + e + _l32(t, j % 32)) & M32, 7)
        ss2 = ss1 ^ _l32(a, 12)
        if j < 16:
            ff, gg = a ^ b ^ c, e ^ f ^ g
        else:
            ff, gg = (a & b) | (a & c) | (b & c), (e & f) | (~e & g)
        tt1 = (ff + d + ss2 + w1[j]) & M32
        tt2 = (gg + h + ss1 + w[j]) & M32
        d, c, b, a = c, _l32(b, 9), a, tt1
        h, g, f, e = g, _l32(f, 19), e, _p0(tt2)
    return [x ^ y for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sm3(msg, IV=None, T=None):
    msg = _msg(msg)
    T = _table("T", SM3_T, T, 32)
    st = _table("IV", SM3_IV, IV, 32)
    data = _md_pad(msg, 64, 8, "big")
    for i in range(0, len(data), 64):
        st = sm3_compress(st, data[i:i + 64], T)
    return struct.pack(">8I", *st)


# ---- shared tables ---------------------------------------------------------

HASHES = {
    # name: (function, block size, digest size)
    "md5": (md5, 64, 16),
    "sha1": (sha1, 64, 20),
    "sha224": (sha224, 64, 28),
    "sha256": (sha256, 64, 32),
    "sha384": (sha384, 128, 48),
    "sha512": (sha512, 128, 64),
    "sm3": (sm3, 64, 32),
}

COMPRESS = {
    # name: (compress, block bytes, state words, word bits, constant table name, standard constants)
    "md5": (md5_compress, 64, 4, 32, "K", MD5_K),
    "sha1": (sha1_compress, 64, 5, 32, "K", SHA1_K),
    "sha256": (sha256_compress, 64, 8, 32, "K", SHA256_K),
    "sha512": (sha512_compress, 128, 8, 64, "K", SHA512_K),
    "sm3": (sm3_compress, 64, 8, 32, "T", SM3_T),
}

CONSTS = {
    "md5": {"K": MD5_K, "IV": MD5_IV, "S": MD5_S},
    "sha1": {"K": SHA1_K, "IV": SHA1_IV},
    "sha224": {"K": SHA256_K, "IV": SHA224_IV},
    "sha256": {"K": SHA256_K, "IV": SHA256_IV},
    "sha384": {"K": SHA512_K, "IV": SHA384_IV},
    "sha512": {"K": SHA512_K, "IV": SHA512_IV},
    "sm3": {"T": SM3_T, "IV": SM3_IV},
}


def hash_by_name(name):
    if not isinstance(name, str) or name.lower() not in HASHES:
        raise CalcError("unknown hash %s" % short(name), "one of: " + ", ".join(sorted(HASHES)))
    return HASHES[name.lower()]


def compress(name, state, block, K=None):
    if not isinstance(name, str) or name.lower() not in COMPRESS:
        raise CalcError("no compression function for %s" % short(name),
                        "one of: " + ", ".join(sorted(COMPRESS)))
    fn, bsize, nwords, width, kname, kstd = COMPRESS[name.lower()]
    block = _msg(block)
    if len(block) != bsize:
        raise CalcError("%s compresses %d-byte blocks, got %d bytes" % (name, bsize, len(block)))
    st = _table("state", [0] * nwords, list(state) if isinstance(state, tuple) else state, width)
    return fn(st, block, _table(kname, kstd, K, width))


def hmac(hash_name, key, msg, ipad=0x36, opad=0x5c, block=None):
    fn, bsize, _ = hash_by_name(hash_name)
    key, msg = _msg(key), _msg(msg)
    if block is not None:
        if not isinstance(block, int) or not 1 <= block <= 1024:
            raise CalcError("block must be an integer 1..1024")
        bsize = block
    for nm, v in (("ipad", ipad), ("opad", opad)):
        if not isinstance(v, int) or not 0 <= v <= 255:
            raise CalcError("%s must be a byte value 0..255" % nm)
    if len(key) > bsize:
        key = fn(key)
    key = key + b"\x00" * (bsize - len(key))
    inner = fn(bytes(b ^ ipad for b in key) + msg)
    return fn(bytes(b ^ opad for b in key) + inner)
