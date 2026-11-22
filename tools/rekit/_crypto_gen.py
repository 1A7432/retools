#!/usr/bin/env python3
"""Generate _crypto_refs.json, the reference database of _crypto.py.

Every table is computed from its definition (primes, sines, field arithmetic,
polynomials, pi) or taken from a library, and every algorithm is then
cross-checked by running a small implementation built on the generated
tables against a second source (hashlib, zlib, cryptography, pycryptodome,
gmssl, ecdsa, mmh3, xxhash). A failed check aborts without writing anything.

Run it in a throw-away virtualenv that has the libraries:

    uv venv /tmp/cg && VIRTUAL_ENV=/tmp/cg uv pip install gmssl cryptography \
        pycryptodome ecdsa mmh3 xxhash
    /tmp/cg/bin/python _crypto_gen.py            # writes _crypto_refs.json here

_crypto.py itself only reads the JSON with the standard library.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import struct
import sys
import zlib

M32, M64 = (1 << 32) - 1, (1 << 64) - 1
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_crypto_refs.json")
CHECKS = []


def check(label, cond):
    if not cond:
        sys.exit("cross-check failed: %s" % label)
    CHECKS.append(label)


def rotl(x, n, w=32):
    n %= w
    m = (1 << w) - 1
    return ((x << n) | (x >> (w - n))) & m if n else x & m


def rotr(x, n, w=32):
    return rotl(x, w - n % w, w)


def iroot(x, n):
    """floor(x ** (1/n)) for big ints."""
    if x < 2:
        return x
    r = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        s = ((n - 1) * r + x // r ** (n - 1)) // n
        if s >= r:
            break
        r = s
    while r ** n > x:
        r -= 1
    while (r + 1) ** n <= x:
        r += 1
    return r


def primes(n):
    out, k = [], 2
    while len(out) < n:
        if all(k % p for p in out if p * p <= k):
            out.append(k)
        k += 1
    return out


def is_prime(n):
    if n < 2:
        return False
    for p in primes(30):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in primes(24):
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


# ---------------------------------------------------------------- SHA-2, SHA-1, MD5

P80 = primes(80)
SHA256_K = [iroot(p << 96, 3) & M32 for p in P80[:64]]
SHA256_IV = [iroot(p << 64, 2) & M32 for p in P80[:8]]
SHA512_K = [iroot(p << 192, 3) & M64 for p in P80]
SHA512_IV = [iroot(p << 128, 2) & M64 for p in P80[:8]]
SHA384_IV = [iroot(p << 128, 2) & M64 for p in P80[8:16]]
SHA224_IV = [v & M32 for v in SHA384_IV]      # bits 33..64 of the same roots


def sha256(msg, iv, outlen):
    ml = len(msg) * 8
    msg += b"\x80" + b"\0" * ((55 - len(msg)) % 64) + struct.pack(">Q", ml)
    h = list(iv)
    for off in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", msg[off:off + 64]))
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g))
                  + SHA256_K[i] + w[i]) & M32
            t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M32
            a, b, c, d, e, f, g, hh = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
        h = [(x + y) & M32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return struct.pack(">8I", *h)[:outlen]


def sha512(msg, iv, outlen):
    ml = len(msg) * 8
    msg += b"\x80" + b"\0" * ((111 - len(msg)) % 128) + struct.pack(">QQ", 0, ml)
    h = list(iv)
    r = lambda x, n: rotr(x, n, 64)
    for off in range(0, len(msg), 128):
        w = list(struct.unpack(">16Q", msg[off:off + 128]))
        for i in range(16, 80):
            s0 = r(w[i - 15], 1) ^ r(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = r(w[i - 2], 19) ^ r(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M64)
        a, b, c, d, e, f, g, hh = h
        for i in range(80):
            t1 = (hh + (r(e, 14) ^ r(e, 18) ^ r(e, 41)) + ((e & f) ^ (~e & g))
                  + SHA512_K[i] + w[i]) & M64
            t2 = ((r(a, 28) ^ r(a, 34) ^ r(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))) & M64
            a, b, c, d, e, f, g, hh = (t1 + t2) & M64, a, b, c, (d + t1) & M64, e, f, g
        h = [(x + y) & M64 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return struct.pack(">8Q", *h)[:outlen]


SHA1_K = [iroot(n << 60, 2) for n in (2, 3, 5, 10)]          # 2^30 * sqrt(n)
_ctr = bytes.fromhex("0123456789abcdeffedcba9876543210")
SHA1_IV = list(struct.unpack("<4I", _ctr)) + [0xC3D2E1F0]
MD5_INIT = SHA1_IV[:4]
MD5_T = [int(abs(math.sin(i + 1)) * 2 ** 32) & M32 for i in range(64)]


def sha1(msg):
    ml = len(msg) * 8
    msg += b"\x80" + b"\0" * ((55 - len(msg)) % 64) + struct.pack(">Q", ml)
    h = list(SHA1_IV)
    for off in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", msg[off:off + 64]))
        for i in range(16, 80):
            w.append(rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f = (b & c) | (~b & d)
            elif i < 40 or i >= 60:
                f = b ^ c ^ d
            else:
                f = (b & c) | (b & d) | (c & d)
            t = (rotl(a, 5) + (f & M32) + e + SHA1_K[i // 20] + w[i]) & M32
            a, b, c, d, e = t, a, rotl(b, 30), c, d
        h = [(x + y) & M32 for x, y in zip(h, (a, b, c, d, e))]
    return struct.pack(">5I", *h)


MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4


def md5(msg):
    ml = len(msg) * 8
    msg += b"\x80" + b"\0" * ((55 - len(msg)) % 64) + struct.pack("<Q", ml)
    h = list(MD5_INIT)
    for off in range(0, len(msg), 64):
        m = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d = h
        for i in range(64):
            if i < 16:
                f, g = (b & c) | (~b & d), i
            elif i < 32:
                f, g = (d & b) | (~d & c), (5 * i + 1) % 16
            elif i < 48:
                f, g = b ^ c ^ d, (3 * i + 5) % 16
            else:
                f, g = c ^ (b | (~d & M32)), (7 * i) % 16
            f = (f + a + MD5_T[i] + m[g]) & M32
            a, d, c = d, c, b
            b = (b + rotl(f, MD5_S[i])) & M32
        h = [(x + y) & M32 for x, y in zip(h, (a, b, c, d))]
    return struct.pack("<4I", *h)


SAMPLES = [b"", b"abc", b"The quick brown fox jumps over the lazy dog", bytes(range(256)) * 3]
for s in SAMPLES:
    check("SHA-256 vs hashlib", sha256(s, SHA256_IV, 32) == hashlib.sha256(s).digest())
    check("SHA-224 vs hashlib", sha256(s, SHA224_IV, 28) == hashlib.sha224(s).digest())
    check("SHA-512 vs hashlib", sha512(s, SHA512_IV, 64) == hashlib.sha512(s).digest())
    check("SHA-384 vs hashlib", sha512(s, SHA384_IV, 48) == hashlib.sha384(s).digest())
    check("SHA-1 vs hashlib", sha1(s) == hashlib.sha1(s).digest())
    check("MD5 vs hashlib", md5(s) == hashlib.md5(s).digest())
check("SHA-256 K high halves of SHA-512 K", all(SHA512_K[i] >> 32 == SHA256_K[i] for i in range(64)))

# ---------------------------------------------------------------- SM3, SM4 (gmssl)

from gmssl import sm3 as g_sm3, sm4 as g_sm4, sm2 as g_sm2   # noqa: E402

SM3_IV = list(g_sm3.IV)
SM3_T0, SM3_T1 = g_sm3.T_j[0], g_sm3.T_j[16]
SM3_TROT = [rotl(SM3_T0 if j < 16 else SM3_T1, j % 32) for j in range(64)]


def sm3(msg):
    ml = len(msg) * 8
    msg += b"\x80" + b"\0" * ((55 - len(msg)) % 64) + struct.pack(">Q", ml)
    v = list(SM3_IV)
    p0 = lambda x: x ^ rotl(x, 9) ^ rotl(x, 17)
    p1 = lambda x: x ^ rotl(x, 15) ^ rotl(x, 23)
    for off in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", msg[off:off + 64]))
        for j in range(16, 68):
            w.append(p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = rotl((rotl(a, 12) + e + SM3_TROT[j]) & M32, 7)
            ss2 = ss1 ^ rotl(a, 12)
            ff = a ^ b ^ c if j < 16 else (a & b) | (a & c) | (b & c)
            gg = e ^ f ^ g if j < 16 else (e & f) | (~e & g)
            tt1 = (ff + d + ss2 + w1[j]) & M32
            tt2 = (gg + h + ss1 + w[j]) & M32
            a, b, c, d = tt1, a, rotl(b, 9), c
            e, f, g, h = p0(tt2), e, rotl(f, 19), g
        v = [x ^ y for x, y in zip(v, (a, b, c, d, e, f, g, h))]
    return struct.pack(">8I", *v)


for s in SAMPLES:
    d = sm3(s)
    check("SM3 vs gmssl", d.hex() == g_sm3.sm3_hash(list(s)))
    if "sm3" in hashlib.algorithms_available:
        check("SM3 vs hashlib/OpenSSL", d == hashlib.new("sm3", s).digest())
check("SM3 T constants", (SM3_T0, SM3_T1) == (0x79CC4519, 0x7A879D8A))

SM4_SBOX = list(g_sm4.SM4_BOXES_TABLE)
SM4_FK = list(g_sm4.SM4_FK)
SM4_CK = list(g_sm4.SM4_CK)
check("SM4 CK from its formula (4i+j)*7 mod 256",
      SM4_CK == [int.from_bytes(bytes(((4 * i + j) * 7) & 0xFF for j in range(4)), "big")
                 for i in range(32)])
check("SM4 S-box is a permutation", sorted(SM4_SBOX) == list(range(256)))


def sm4_tau(x):
    return int.from_bytes(bytes(SM4_SBOX[b] for b in x.to_bytes(4, "big")), "big")


def sm4_l(b):
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)


SM4_T0 = [sm4_l(SM4_SBOX[x] << 24) for x in range(256)]


def sm4_encrypt(key, block):
    mk = struct.unpack(">4I", key)
    k = [mk[i] ^ SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        t = sm4_tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i])
        k.append(k[i] ^ t ^ rotl(t, 13) ^ rotl(t, 23))
        rk.append(k[-1])
    x = list(struct.unpack(">4I", block))
    for i in range(32):
        a = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]
        # T-table form of L(tau(a)), to check T0 as well
        t = (SM4_T0[a >> 24] ^ rotr(SM4_T0[(a >> 16) & 255], 8) ^ rotr(SM4_T0[(a >> 8) & 255], 16)
             ^ rotr(SM4_T0[a & 255], 24))
        check_t = sm4_l(sm4_tau(a))
        if t != check_t:
            sys.exit("SM4 T0 inconsistent")
        x.append(x[i] ^ t)
    return struct.pack(">4I", x[35], x[34], x[33], x[32])


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes   # noqa: E402

for key in (bytes(16), bytes.fromhex("0123456789abcdeffedcba9876543210"), bytes(range(16))):
    for blk in (bytes(16), bytes.fromhex("0123456789abcdeffedcba9876543210")):
        enc = Cipher(algorithms.SM4(key), modes.ECB()).encryptor()
        check("SM4 vs cryptography", sm4_encrypt(key, blk) == enc.update(blk) + enc.finalize())

# ---------------------------------------------------------------- AES (field arithmetic)


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return r


def ginv(a):
    return 0 if a == 0 else next(b for b in range(1, 256) if gmul(a, b) == 1)


def affine(b):
    out = 0x63
    for i in range(5):
        out ^= ((b << i) | (b >> (8 - i))) & 0xFF
    return out


AES_SBOX = [affine(ginv(x)) for x in range(256)]
AES_INV = [0] * 256
for i, v in enumerate(AES_SBOX):
    AES_INV[v] = i
AES_RCON = []
_r = 1
for _ in range(10):
    AES_RCON.append(_r)
    _r = gmul(_r, 2)
TE0 = [(gmul(s, 2) << 24) | (s << 16) | (s << 8) | gmul(s, 3) for s in AES_SBOX]
TD0 = [(gmul(s, 14) << 24) | (gmul(s, 9) << 16) | (gmul(s, 13) << 8) | gmul(s, 11) for s in AES_INV]
TE = [[rotr(v, 8 * k) for v in TE0] for k in range(4)]
TD = [[rotr(v, 8 * k) for v in TD0] for k in range(4)]


def aes_keys(key):
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = rotl(t, 8)
            t = int.from_bytes(bytes(AES_SBOX[b] for b in t.to_bytes(4, "big")), "big")
            t ^= AES_RCON[i // nk - 1] << 24
        elif nk > 6 and i % nk == 4:
            t = int.from_bytes(bytes(AES_SBOX[b] for b in t.to_bytes(4, "big")), "big")
        w.append(w[i - nk] ^ t)
    return w, nr


def aes_enc(key, blk):
    w, nr = aes_keys(key)
    s = [x ^ w[i] for i, x in enumerate(struct.unpack(">4I", blk))]
    for r in range(1, nr):
        s = [TE[0][s[i] >> 24] ^ TE[1][(s[(i + 1) % 4] >> 16) & 255] ^ TE[2][(s[(i + 2) % 4] >> 8) & 255]
             ^ TE[3][s[(i + 3) % 4] & 255] ^ w[4 * r + i] for i in range(4)]
    out = []
    for i in range(4):
        v = (AES_SBOX[s[i] >> 24] << 24) | (AES_SBOX[(s[(i + 1) % 4] >> 16) & 255] << 16) \
            | (AES_SBOX[(s[(i + 2) % 4] >> 8) & 255] << 8) | AES_SBOX[s[(i + 3) % 4] & 255]
        out.append(v ^ w[4 * nr + i])
    return struct.pack(">4I", *out)


def aes_dec(key, blk):
    w, nr = aes_keys(key)
    imc = lambda v: (TD[0][AES_SBOX[v >> 24]] ^ TD[1][AES_SBOX[(v >> 16) & 255]]
                     ^ TD[2][AES_SBOX[(v >> 8) & 255]] ^ TD[3][AES_SBOX[v & 255]])
    dk = [w[4 * nr: 4 * nr + 4]] + [[imc(x) for x in w[4 * r: 4 * r + 4]] for r in range(nr - 1, 0, -1)] \
        + [w[0:4]]
    s = [x ^ dk[0][i] for i, x in enumerate(struct.unpack(">4I", blk))]
    for r in range(1, nr):
        s = [TD[0][s[i] >> 24] ^ TD[1][(s[(i + 3) % 4] >> 16) & 255] ^ TD[2][(s[(i + 2) % 4] >> 8) & 255]
             ^ TD[3][s[(i + 1) % 4] & 255] ^ dk[r][i] for i in range(4)]
    out = []
    for i in range(4):
        v = (AES_INV[s[i] >> 24] << 24) | (AES_INV[(s[(i + 3) % 4] >> 16) & 255] << 16) \
            | (AES_INV[(s[(i + 2) % 4] >> 8) & 255] << 8) | AES_INV[s[(i + 1) % 4] & 255]
        out.append(v ^ dk[nr][i])
    return struct.pack(">4I", *out)


from Crypto.Cipher import AES as P_AES, DES as P_DES, Blowfish as P_BF   # noqa: E402

for key in (bytes(16), bytes(range(16)), bytes(range(24)), bytes(range(32))):
    for blk in (bytes(16), bytes(range(16, 32))):
        ref = P_AES.new(key, P_AES.MODE_ECB).encrypt(blk)
        check("AES T-table encrypt vs pycryptodome", aes_enc(key, blk) == ref)
        check("AES T-table decrypt vs pycryptodome", aes_dec(key, ref) == blk)
check("AES S-box[0]", AES_SBOX[0] == 0x63 and TE0[0] == 0xC66363A5 and TD0[0] == 0x51F4A750)

# ---------------------------------------------------------------- DES (typed, verified)

DES_S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
           60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
           29, 21, 13, 5, 28, 20, 12, 4]
DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def perm(v, table, nin):
    out = 0
    for p in table:
        out = (out << 1) | ((v >> (nin - p)) & 1)
    return out


def des_enc(key, blk):
    k = perm(int.from_bytes(key, "big"), DES_PC1, 64)
    c, d = k >> 28, k & 0xFFFFFFF
    subkeys = []
    for s in DES_SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF
        d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
        subkeys.append(perm((c << 28) | d, DES_PC2, 56))
    v = perm(int.from_bytes(blk, "big"), DES_IP, 64)
    l, r = v >> 32, v & M32
    for sk in subkeys:
        x = perm(r, DES_E, 32) ^ sk
        o = 0
        for i in range(8):
            six = (x >> (42 - 6 * i)) & 63
            row = ((six >> 4) & 2) | (six & 1)
            col = (six >> 1) & 15
            o = (o << 4) | DES_S[i][row * 16 + col]
        l, r = r, l ^ perm(o, DES_P, 32)
    v = (r << 32) | l
    fp = [DES_IP.index(i) + 1 for i in range(1, 65)]
    return perm(v, fp, 64).to_bytes(8, "big")


for key in (bytes.fromhex("133457799bbcdff1"), bytes(range(1, 9)), bytes.fromhex("0e329232ea6d0d73")):
    for blk in (bytes.fromhex("0123456789abcdef"), bytes(8), bytes(range(8, 16))):
        check("DES vs pycryptodome", des_enc(key, blk) == P_DES.new(key, P_DES.MODE_ECB).encrypt(blk))
# the same boxes indexed directly by the 6-bit input (b1..b6), as many implementations store them
DES_S_LINEAR = [[box[(((x >> 4) & 2) | (x & 1)) * 16 + ((x >> 1) & 15)] for x in range(64)] for box in DES_S]

# ---------------------------------------------------------------- Blowfish (pi)


def pi_hex(ndigits):
    """Fractional hex digits of pi, by Machin's formula in fixed point."""
    prec = ndigits * 4 + 64
    one = 1 << prec

    def atan_inv(x):
        total, term, n, x2, sign = 0, one // x, 1, x * x, 1
        while term:
            total += sign * (term // n)
            term //= x2
            n += 2
            sign = -sign
        return total

    pi = 16 * atan_inv(5) - 4 * atan_inv(239)
    frac = (pi - 3 * one) >> 64
    return frac >> ((prec - 64) - ndigits * 4)


_pi = pi_hex(8 * (18 + 1024))
_words = [(_pi >> (32 * (18 + 1024 - 1 - i))) & M32 for i in range(18 + 1024)]
BF_P = _words[:18]
BF_S = [_words[18 + 256 * k: 18 + 256 * (k + 1)] for k in range(4)]


def bf_f(s, x):
    return ((((s[0][x >> 24] + s[1][(x >> 16) & 255]) & M32) ^ s[2][(x >> 8) & 255]) + s[3][x & 255]) & M32


def bf_block(p, s, l, r):
    for i in range(16):
        l ^= p[i]
        r ^= bf_f(s, l)
        l, r = r, l
    l, r = r, l
    return l ^ p[17], r ^ p[16]


def bf_enc(key, blk):
    p = list(BF_P)
    s = [list(b) for b in BF_S]
    kk = (key * (72 // len(key) + 1))[:72]
    for i in range(18):
        p[i] ^= struct.unpack(">I", kk[4 * i:4 * i + 4])[0]
    l = r = 0
    for i in range(0, 18, 2):
        l, r = bf_block(p, s, l, r)
        p[i], p[i + 1] = l, r
    for k in range(4):
        for i in range(0, 256, 2):
            l, r = bf_block(p, s, l, r)
            s[k][i], s[k][i + 1] = l, r
    l, r = struct.unpack(">2I", blk)
    return struct.pack(">2I", *bf_block(p, s, l, r))


for key in (b"abcdefgh", bytes(range(16)), b"keys!"):
    blk = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    check("Blowfish vs pycryptodome", bf_enc(key, blk) == P_BF.new(key, P_BF.MODE_ECB).encrypt(blk))
check("Blowfish P[0] is pi", BF_P[0] == 0x243F6A88)

# ---------------------------------------------------------------- ChaCha / Salsa
SIGMA, TAU = b"expand 32-byte k", b"expand 16-byte k"


def chacha_block(key, counter, nonce):
    st = list(struct.unpack("<4I", SIGMA)) + list(struct.unpack("<8I", key)) + [counter] \
        + list(struct.unpack("<3I", nonce))
    x = list(st)

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & M32; x[d] = rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & M32; x[b] = rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & M32; x[d] = rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & M32; x[b] = rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & M32 for a, b in zip(x, st)])


_k, _n = bytes(range(32)), bytes(range(12))
_enc = Cipher(algorithms.ChaCha20(_k, struct.pack("<I", 1) + _n), None).encryptor()
check("ChaCha20 sigma vs cryptography", _enc.update(bytes(64)) == chacha_block(_k, 1, _n))

# ---------------------------------------------------------------- CRC-32


def crc_table(poly, reflected):
    out = []
    for i in range(256):
        if reflected:
            c = i
            for _ in range(8):
                c = (c >> 1) ^ poly if c & 1 else c >> 1
        else:
            c = i << 24
            for _ in range(8):
                c = ((c << 1) ^ poly) & M32 if c & 0x80000000 else (c << 1) & M32
        out.append(c)
    return out


def rev32(x):
    return int("{:032b}".format(x)[::-1], 2)


CRC_IEEE, CRC_C = 0x04C11DB7, 0x1EDC6F41
T_IEEE_R, T_IEEE_N = crc_table(rev32(CRC_IEEE), True), crc_table(CRC_IEEE, False)
T_C_R, T_C_N = crc_table(rev32(CRC_C), True), crc_table(CRC_C, False)


def crc_r(t, data):
    c = M32
    for b in data:
        c = t[(c ^ b) & 255] ^ (c >> 8)
    return c ^ M32


def crc_n(t, data, xorout=M32):
    c = M32
    for b in data:
        c = ((c << 8) & M32) ^ t[((c >> 24) ^ b) & 255]
    return c ^ xorout


for s in SAMPLES:
    check("CRC-32 reflected table vs zlib", crc_r(T_IEEE_R, s) == zlib.crc32(s))
check("CRC-32/BZIP2 check value", crc_n(T_IEEE_N, b"123456789") == 0xFC891918)
check("CRC-32/MPEG-2 check value", crc_n(T_IEEE_N, b"123456789", 0) == 0x0376E6E7)
check("CRC-32C check value", crc_r(T_C_R, b"123456789") == 0xE3069283)
check("reflected polys", rev32(CRC_IEEE) == 0xEDB88320 and rev32(CRC_C) == 0x82F63B78)

# ---------------------------------------------------------------- FNV, Murmur, xxHash, golden ratio
FNV32_PRIME, FNV64_PRIME = (1 << 24) + (1 << 8) + 0x93, (1 << 40) + (1 << 8) + 0xB3


def fnv0(data, prime, mask):
    h = 0
    for b in data:
        h = (h * prime) & mask
        h ^= b
    return h


_chongo = b"chongo <Landon Curt Noll> /\\../\\"
FNV32_BASIS, FNV64_BASIS = fnv0(_chongo, FNV32_PRIME, M32), fnv0(_chongo, FNV64_PRIME, M64)
check("FNV offset bases", (FNV32_BASIS, FNV64_BASIS) == (0x811C9DC5, 0xCBF29CE484222325))

MUR3 = dict(c1=0xCC9E2D51, c2=0x1B873593, n=0xE6546B64, f1=0x85EBCA6B, f2=0xC2B2AE35)
MUR3_64 = dict(c1=0x87C37B91114253D5, c2=0x4CF5AD432745937F, f1=0xFF51AFD7ED558CCD, f2=0xC4CEB9FE1A85EC53)
MUR2_M, MUR64A_M = 0x5BD1E995, 0xC6A4A7935BD1E995


def murmur3_32(data, seed=0):
    h = seed
    n = len(data) // 4
    for i in range(n):
        k = struct.unpack_from("<I", data, 4 * i)[0]
        k = rotl((k * MUR3["c1"]) & M32, 15) * MUR3["c2"] & M32
        h = (rotl(h ^ k, 13) * 5 + MUR3["n"]) & M32
    tail, k = data[4 * n:], 0
    for i, b in enumerate(tail):
        k |= b << (8 * i)
    if tail:
        h ^= rotl((k * MUR3["c1"]) & M32, 15) * MUR3["c2"] & M32
    h ^= len(data)
    h ^= h >> 16; h = h * MUR3["f1"] & M32; h ^= h >> 13; h = h * MUR3["f2"] & M32; h ^= h >> 16
    return h


def fmix64(k):
    k ^= k >> 33; k = k * MUR3_64["f1"] & M64; k ^= k >> 33; k = k * MUR3_64["f2"] & M64
    return k ^ (k >> 33)


def murmur3_128(data, seed=0):
    h1 = h2 = seed
    c1, c2 = MUR3_64["c1"], MUR3_64["c2"]
    nb = len(data) // 16
    for i in range(nb):
        k1, k2 = struct.unpack_from("<QQ", data, 16 * i)
        k1 = rotl(k1 * c1 & M64, 31, 64) * c2 & M64; h1 ^= k1
        h1 = (rotl(h1, 27, 64) + h2) & M64; h1 = (h1 * 5 + 0x52DCE729) & M64
        k2 = rotl(k2 * c2 & M64, 33, 64) * c1 & M64; h2 ^= k2
        h2 = (rotl(h2, 31, 64) + h1) & M64; h2 = (h2 * 5 + 0x38495AB5) & M64
    tail = data[16 * nb:]
    k1 = int.from_bytes(tail[:8], "little")
    k2 = int.from_bytes(tail[8:], "little")
    if len(tail) > 8:
        h2 ^= rotl(k2 * c2 & M64, 33, 64) * c1 & M64
    if tail:
        h1 ^= rotl(k1 * c1 & M64, 31, 64) * c2 & M64
    h1 ^= len(data); h2 ^= len(data)
    h1 = (h1 + h2) & M64; h2 = (h2 + h1) & M64
    h1, h2 = fmix64(h1), fmix64(h2)
    h1 = (h1 + h2) & M64; h2 = (h2 + h1) & M64
    return h1 | (h2 << 64)


import mmh3   # noqa: E402

for s in SAMPLES + [b"a", b"ab", b"abcde"]:
    check("Murmur3-32 vs mmh3", murmur3_32(s, 7) == mmh3.hash(s, 7, signed=False))
    check("Murmur3-128 vs mmh3", murmur3_128(s, 7) == mmh3.hash128(s, 7, signed=False))

XXH32_P = [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1]
XXH64_P = [0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x85EBCA77C2B2AE63,
           0x27D4EB2F165667C5]


def xxh32(data, seed=0):
    P1, P2, P3, P4, P5 = XXH32_P
    n, i = len(data), 0
    if n >= 16:
        v = [(seed + P1 + P2) & M32, (seed + P2) & M32, seed, (seed - P1) & M32]
        while i + 16 <= n:
            for j in range(4):
                v[j] = rotl((v[j] + struct.unpack_from("<I", data, i + 4 * j)[0] * P2) & M32, 13) * P1 & M32
            i += 16
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & M32
    else:
        h = (seed + P5) & M32
    h = (h + n) & M32
    while i + 4 <= n:
        h = rotl((h + struct.unpack_from("<I", data, i)[0] * P3) & M32, 17) * P4 & M32
        i += 4
    while i < n:
        h = rotl((h + data[i] * P5) & M32, 11) * P1 & M32
        i += 1
    h ^= h >> 15; h = h * P2 & M32; h ^= h >> 13; h = h * P3 & M32
    return h ^ (h >> 16)


def xxh64(data, seed=0):
    P1, P2, P3, P4, P5 = XXH64_P
    r = lambda x, k: rotl(x, k, 64)

    def rnd(acc, v):
        return r((acc + v * P2) & M64, 31) * P1 & M64

    n, i = len(data), 0
    if n >= 32:
        v = [(seed + P1 + P2) & M64, (seed + P2) & M64, seed, (seed - P1) & M64]
        while i + 32 <= n:
            for j in range(4):
                v[j] = rnd(v[j], struct.unpack_from("<Q", data, i + 8 * j)[0])
            i += 32
        h = (r(v[0], 1) + r(v[1], 7) + r(v[2], 12) + r(v[3], 18)) & M64
        for j in range(4):
            h = ((h ^ rnd(0, v[j])) * P1 + P4) & M64
    else:
        h = (seed + P5) & M64
    h = (h + n) & M64
    while i + 8 <= n:
        h = (r(h ^ rnd(0, struct.unpack_from("<Q", data, i)[0]), 27) * P1 + P4) & M64
        i += 8
    if i + 4 <= n:
        h = (r(h ^ (struct.unpack_from("<I", data, i)[0] * P1 & M64), 23) * P2 + P3) & M64
        i += 4
    while i < n:
        h = r(h ^ (data[i] * P5 & M64), 11) * P1 & M64
        i += 1
    h ^= h >> 33; h = h * P2 & M64; h ^= h >> 29; h = h * P3 & M64
    return h ^ (h >> 32)


import xxhash   # noqa: E402

for s in SAMPLES + [b"a", b"abcdefg"]:
    check("xxHash32 vs xxhash", xxh32(s, 5) == xxhash.xxh32_intdigest(s, 5))
    check("xxHash64 vs xxhash", xxh64(s, 5) == xxhash.xxh64_intdigest(s, 5))

GOLD32 = (iroot(5 << 64, 2) - (1 << 32)) >> 1           # 2^32 / phi
GOLD64 = (iroot(5 << 128, 2) - (1 << 64)) >> 1
check("golden ratio", (GOLD32, GOLD64) == (0x9E3779B9, 0x9E3779B97F4A7C15))

# ---------------------------------------------------------------- alphabets (base64 module)
B64 = "".join(chr(base64.b64encode(bytes([i << 2]))[0]) for i in range(64))
B64URL = "".join(chr(base64.urlsafe_b64encode(bytes([i << 2]))[0]) for i in range(64))
B32 = "".join(chr(base64.b32encode(bytes([i << 3]))[0]) for i in range(32))
B32HEX = "".join(chr(base64.b32hexencode(bytes([i << 3]))[0]) for i in range(32))
check("alphabets", len(set(B64)) == 64 and B64.endswith("+/") and B64URL.endswith("-_")
      and len(set(B32)) == 32 and B32HEX.startswith("0123456789ABCDEFGHIJ"))

# ---------------------------------------------------------------- elliptic curves


def ec_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return x, (lam * (P[0] - x) - P[1]) % p


def ec_mul(k, P, a, p):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P, a, p)
        P = ec_add(P, P, a, p)
        k >>= 1
    return R


def weier(name, p, a, b, n, gx, gy):
    check("%s p, n prime" % name, is_prime(p) and is_prime(n))
    check("%s G on curve" % name, (gy * gy - gx ** 3 - a * gx - b) % p == 0)
    check("%s n*G = O" % name, ec_mul(n, (gx, gy), a, p) is None)
    return dict(p=p, a=a, b=b, n=n, Gx=gx, Gy=gy)


t = g_sm2.default_ecc_table
CURVES = {}
CURVES["SM2"] = weier("SM2", int(t["p"], 16), int(t["a"], 16), int(t["b"], 16), int(t["n"], 16),
                      int(t["g"][:64], 16), int(t["g"][64:], 16))
check("SM2 a = p - 3", CURVES["SM2"]["a"] == CURVES["SM2"]["p"] - 3)

import ecdsa   # noqa: E402
from Crypto.PublicKey import ECC   # noqa: E402

for name, pc, ec in (("P-256", "p256", ecdsa.NIST256p), ("secp256k1", "secp256k1", ecdsa.SECP256k1)):
    c = ECC._curves[pc]
    p, b, n, gx, gy = int(c.p), int(c.b), int(c.order), int(c.Gx), int(c.Gy)
    a = p - 3 if name == "P-256" else 0
    check("%s pycryptodome = ecdsa" % name,
          (p, a, b, n, gx, gy) == (ec.curve.p(), ec.curve.a() % p, ec.curve.b(), ec.order,
                                   ec.generator.x(), ec.generator.y()))
    CURVES[name] = weier(name, p, a, b, n, gx, gy)

# Curve25519 (Montgomery v^2 = u^3 + A u^2 + u): u = 9; v from the Ed25519 base
# point by the birational map, then checked on the curve and against X25519.
c = ECC._curves["ed25519"]
p25 = (1 << 255) - 19
check("Curve25519 p", int(c.p) == p25 and is_prime(p25))
ex, ey = int(c.Gx), int(c.Gy)
u = (1 + ey) * pow(1 - ey, -1, p25) % p25
sqrt_m486664 = pow(-486664 % p25, (p25 + 3) // 8, p25)
if (sqrt_m486664 * sqrt_m486664 - (-486664)) % p25:
    sqrt_m486664 = sqrt_m486664 * pow(2, (p25 - 1) // 4, p25) % p25
v = sqrt_m486664 * u * pow(ex, -1, p25) % p25
check("Curve25519 u = 9", u == 9)
check("Curve25519 G on curve", (v * v - u ** 3 - 486662 * u * u - u) % p25 == 0)
n25 = int(ECC._curves["curve25519"].order)
check("Curve25519 n", n25 == (1 << 252) + 27742317777372353535851937790883648493 and is_prime(n25))
if v > p25 // 2:
    v = p25 - v      # RFC 7748 gives the smaller of the two roots
check("Curve25519 Gy is RFC 7748's V",
      v == 14781619447589544791020593568409986887264606134616475288964881837755586237401)


def x25519(k, u0):
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, "little")
    x1, x2, z2, x3, z3, swap = u0, 1, 0, u0, 1, 0
    a24 = 121665
    for t_ in range(254, -1, -1):
        kt = (k >> t_) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = (x2 + z2) % p25; AA = A * A % p25; B = (x2 - z2) % p25; BB = B * B % p25; E = (AA - BB) % p25
        C = (x3 + z3) % p25; D = (x3 - z3) % p25; DA = D * A % p25; CB = C * B % p25
        x3 = (DA + CB) ** 2 % p25; z3 = x1 * (DA - CB) ** 2 % p25
        x2 = AA * BB % p25; z2 = E * (AA + a24 * E) % p25
    if swap:
        x2, z2 = x3, z3
    return x2 * pow(z2, p25 - 2, p25) % p25


from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey   # noqa: E402

_sk = bytes(range(1, 33))
_pub = X25519PrivateKey.from_private_bytes(_sk).public_key().public_bytes_raw()
check("Curve25519 base point vs cryptography X25519", x25519(_sk, u).to_bytes(32, "little") == _pub)
CURVES["Curve25519"] = dict(p=p25, a=486662, b=1, n=n25, Gx=u, Gy=v)
ED25519_D = (-121665 * pow(121666, -1, p25)) % p25
check("Ed25519 base point on curve", (-ex * ex + ey * ey - 1 - ED25519_D * ex * ex * ey * ey) % p25 == 0)

# ---------------------------------------------------------------- write

tables, bignums, scalars, strings, alphabets = [], [], [], [], []


def tab(id_, name, algo, elem, values, src):
    tables.append({"id": id_, "name": name, "algo": algo, "elem": elem, "values": list(values), "src": src})


def sca(id_, name, algo, width, value, src):
    scalars.append({"id": id_, "name": name, "algo": algo, "width": width, "value": value, "src": src})


tab("sha256_k", "SHA-256 K", "SHA-256", 4, SHA256_K, "cube roots of primes; hashlib")
tab("sha256_iv", "SHA-256 IV", "SHA-256", 4, SHA256_IV, "square roots of primes; hashlib")
tab("sha224_iv", "SHA-224 IV", "SHA-224", 4, SHA224_IV, "square roots of primes 9-16; hashlib")
tab("sha512_k", "SHA-512 K", "SHA-512", 8, SHA512_K, "cube roots of primes; hashlib")
tab("sha512_iv", "SHA-512 IV", "SHA-512", 8, SHA512_IV, "square roots of primes; hashlib")
tab("sha384_iv", "SHA-384 IV", "SHA-384", 8, SHA384_IV, "square roots of primes 9-16; hashlib")
tab("sha1_iv", "SHA-1 IV", "SHA-1", 4, SHA1_IV, "counting pattern; hashlib")
tab("sha1_k", "SHA-1 K", "SHA-1", 4, SHA1_K, "2^30*sqrt(2,3,5,10); hashlib")
tab("md5_t", "MD5 T", "MD5", 4, MD5_T, "sin(i+1)*2^32; hashlib")
tab("md5_init", "MD5 init", "MD5", 4, MD5_INIT, "counting pattern; hashlib (= SHA-1 IV[0:4])")
tab("sm3_iv", "SM3 IV", "SM3", 4, SM3_IV, "gmssl; hashlib/OpenSSL")
tab("sm3_t_rot", "SM3 T<<<j", "SM3", 4, SM3_TROT, "gmssl T_j rotated left by j mod 32; gmssl")
tab("sm4_sbox", "SM4 S-box", "SM4", 1, SM4_SBOX, "gmssl; cryptography")
tab("sm4_fk", "SM4 FK", "SM4", 4, SM4_FK, "gmssl; cryptography")
tab("sm4_ck", "SM4 CK", "SM4", 4, SM4_CK, "gmssl; formula; cryptography")
tab("sm4_t0", "SM4 T0 (L of S-box)", "SM4", 4, SM4_T0, "computed from S-box; cryptography")
tab("aes_sbox", "AES S-box", "AES", 1, AES_SBOX, "GF(2^8) inverse + affine; pycryptodome")
tab("aes_inv_sbox", "AES inverse S-box", "AES", 1, AES_INV, "GF(2^8); pycryptodome")
tab("aes_rcon", "AES Rcon", "AES", 1, AES_RCON, "powers of x in GF(2^8)")
tab("aes_rcon_w", "AES Rcon (words)", "AES", 4, [r << 24 for r in AES_RCON], "powers of x << 24")
for k in range(4):
    tab("aes_te%d" % k, "AES Te%d" % k, "AES", 4, TE[k], "GF(2^8) MixColumns of S-box; pycryptodome")
for k in range(4):
    tab("aes_td%d" % k, "AES Td%d" % k, "AES", 4, TD[k], "GF(2^8) InvMixColumns; pycryptodome")
for i in range(8):
    tab("des_s%d" % (i + 1), "DES S%d" % (i + 1), "DES", 1, DES_S[i], "FIPS 46-3 row-major; pycryptodome")
for i in range(8):
    tab("des_s%d_lin" % (i + 1), "DES S%d (6-bit index)" % (i + 1), "DES", 1, DES_S_LINEAR[i],
        "FIPS 46-3 indexed by input bits; pycryptodome")
tab("bf_p", "Blowfish P-array", "Blowfish", 4, BF_P, "hex digits of pi; pycryptodome")
for k in range(4):
    tab("bf_s%d" % k, "Blowfish S%d" % k, "Blowfish", 4, BF_S[k], "hex digits of pi; pycryptodome")
tab("chacha_sigma_w", "ChaCha/Salsa sigma \"expand 32-byte k\"", "ChaCha20/Salsa20", 4, struct.unpack("<4I", SIGMA),
    "\"expand 32-byte k\"; cryptography")
tab("chacha_tau_w", "ChaCha/Salsa tau \"expand 16-byte k\"", "ChaCha20/Salsa20", 4, struct.unpack("<4I", TAU),
    "\"expand 16-byte k\"")
tab("crc32_tab_r", "CRC-32 table (reflected, 0xEDB88320)", "CRC-32", 4, T_IEEE_R, "polynomial; zlib")
tab("crc32_tab_n", "CRC-32 table (MSB-first, 0x04C11DB7)", "CRC-32", 4, T_IEEE_N, "polynomial; check value")
tab("crc32c_tab_r", "CRC-32C table (reflected, 0x82F63B78)", "CRC-32C", 4, T_C_R, "polynomial; check value")
tab("crc32c_tab_n", "CRC-32C table (MSB-first, 0x1EDC6F41)", "CRC-32C", 4, T_C_N, "polynomial")
tab("xxh32_p", "xxHash32 primes", "xxHash32", 4, XXH32_P, "xxhash")
tab("xxh64_p", "xxHash64 primes", "xxHash64", 8, XXH64_P, "xxhash")
tab("murmur3_c", "Murmur3 x86_32 constants", "Murmur3", 4,
    [MUR3["c1"], MUR3["c2"], MUR3["n"], MUR3["f1"], MUR3["f2"]], "mmh3")
tab("murmur3_c64", "Murmur3 x64_128 constants", "Murmur3", 8,
    [MUR3_64["c1"], MUR3_64["c2"], MUR3_64["f1"], MUR3_64["f2"]], "mmh3")

sca("sha1_k0", "SHA-1 K0 (also RIPEMD)", "SHA-1", 4, SHA1_K[0], "2^30*sqrt(2)")
sca("tea_delta", "TEA/XTEA delta (golden ratio)", "TEA/XTEA", 4, GOLD32, "2^32/phi")
sca("tea_sum32", "TEA decrypt start sum (delta*32)", "TEA/XTEA", 4, (GOLD32 * 32) & M32, "delta*32")
sca("golden64", "golden ratio 64-bit", "hash mixing", 8, GOLD64, "2^64/phi")
sca("crc32_poly", "CRC-32 polynomial", "CRC-32", 4, CRC_IEEE, "IEEE 802.3")
sca("crc32_poly_r", "CRC-32 polynomial (reflected)", "CRC-32", 4, rev32(CRC_IEEE), "zlib")
sca("crc32c_poly", "CRC-32C polynomial", "CRC-32C", 4, CRC_C, "Castagnoli")
sca("crc32c_poly_r", "CRC-32C polynomial (reflected)", "CRC-32C", 4, rev32(CRC_C), "check value")
sca("fnv32_basis", "FNV-1 32 offset basis", "FNV-1/1a", 4, FNV32_BASIS, "FNV-0 of chongo string")
sca("fnv32_prime", "FNV 32 prime", "FNV-1/1a", 4, FNV32_PRIME, "2^24+2^8+0x93")
sca("fnv64_basis", "FNV-1 64 offset basis", "FNV-1/1a", 8, FNV64_BASIS, "FNV-0 of chongo string")
sca("fnv64_prime", "FNV 64 prime", "FNV-1/1a", 8, FNV64_PRIME, "2^40+2^8+0xb3")
for k, v in MUR3.items():
    sca("murmur3_" + k, "Murmur3 32 %s" % k, "Murmur3", 4, v, "mmh3")
for k, v in MUR3_64.items():
    sca("murmur3_64" + k, "Murmur3 x64 %s" % k, "Murmur3", 8, v, "mmh3")
sca("murmur2_m", "MurmurHash2 m", "Murmur2", 4, MUR2_M, "smhasher (no second source)")
sca("murmur64a_m", "MurmurHash64A m", "Murmur2", 8, MUR64A_M, "smhasher (no second source)")
for i, v in enumerate(XXH32_P):
    sca("xxh32_p%d" % (i + 1), "xxHash32 PRIME%d" % (i + 1), "xxHash32", 4, v, "xxhash")
for i, v in enumerate(XXH64_P):
    sca("xxh64_p%d" % (i + 1), "xxHash64 PRIME%d" % (i + 1), "xxHash64", 8, v, "xxhash")
sca("sm3_t0", "SM3 T0", "SM3", 4, SM3_T0, "gmssl")
sca("sm3_t1", "SM3 T1", "SM3", 4, SM3_T1, "gmssl")

for cname, prm in CURVES.items():
    for key in ("p", "a", "b", "n", "Gx", "Gy"):
        bignums.append({"id": "%s_%s" % (cname.lower().replace("-", ""), key.lower()),
                        "name": "%s %s" % (cname, key), "algo": cname, "curve": cname, "param": key,
                        "bytes": 32, "value": "%064x" % prm[key]})
bignums.append({"id": "ed25519_d", "name": "Ed25519 d", "algo": "Ed25519", "curve": "Ed25519",
                "param": "d", "bytes": 32, "value": "%064x" % ED25519_D})

strings += [
    # same bytes as the sigma/tau word tables (little-endian); kept for reference
    {"id": "chacha_sigma", "name": "ChaCha/Salsa sigma", "algo": "ChaCha20/Salsa20", "text": SIGMA.decode(),
     "dup_of": "chacha_sigma_w"},
    {"id": "chacha_tau", "name": "ChaCha/Salsa tau", "algo": "ChaCha20/Salsa20", "text": TAU.decode(),
     "dup_of": "chacha_tau_w"},
    # GM/T 0009 default signer ID used in the SM2 Z value when none is given
    {"id": "sm2_default_id", "name": "SM2 default user ID", "algo": "SM2", "text": "1234567812345678"},
]
alphabets += [
    {"id": "base64", "name": "base64 alphabet", "algo": "base64", "text": B64},
    {"id": "base64url", "name": "base64url alphabet", "algo": "base64", "text": B64URL},
    {"id": "base32", "name": "base32 alphabet", "algo": "base32", "text": B32},
    {"id": "base32hex", "name": "base32hex alphabet", "algo": "base32", "text": B32HEX},
]

doc = {"format": 1,
       "note": "generated by _crypto_gen.py; do not edit by hand",
       "checks": sorted(set(CHECKS)),
       "tables": tables, "bignums": bignums, "scalars": scalars,
       "strings": strings, "alphabets": alphabets}
with open(OUT + ".tmp", "w") as fh:
    json.dump(doc, fh, separators=(",", ":"))
os.replace(OUT + ".tmp", OUT)
print("wrote %s: %d tables, %d bignums, %d scalars, %d strings, %d alphabets; %d checks passed"
      % (OUT, len(tables), len(bignums), len(scalars), len(strings), len(alphabets), len(CHECKS)))
