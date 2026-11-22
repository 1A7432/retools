"""Hashes, HMAC, CRC and FNV against hashlib, hmac, zlib, gmssl and published vectors,
including the constant-override paths."""

import hashlib
import hmac as pyhmac
import os
import random
import zlib

import pytest
from gmssl import sm3 as gsm3

from recalc import hashes, table
from conftest import err, ok

LENGTHS = [0, 1, 3, 55, 56, 57, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 200, 1000, 4096]
RNG = random.Random(1234)
MSGS = [bytes(RNG.randrange(256) for _ in range(n)) for n in LENGTHS]


@pytest.mark.parametrize("name", ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
def test_against_hashlib(name):
    f = table.FUNCTIONS[name]
    for m in MSGS:
        assert f(m) == hashlib.new(name, m).digest(), (name, len(m))


def test_sm3_published_vectors_and_gmssl():
    # GB/T 32905-2016 appendix A
    assert hashes.sm3(b"abc").hex() == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert hashes.sm3(b"abcd" * 16).hex() == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    for m in MSGS:
        assert hashes.sm3(m).hex() == gsm3.sm3_hash(list(m))


def test_derived_constant_tables_are_the_standard_ones():
    assert hashes.SHA256_K[:2] == [0x428A2F98, 0x71374491] and hashes.SHA256_K[63] == 0xC67178F2
    assert hashes.SHA256_K[13] == 0x80DEB1FE
    assert hashes.SHA256_IV[0] == 0x6A09E667 and hashes.SHA256_IV[7] == 0x5BE0CD19
    assert hashes.SHA512_K[0] == 0x428A2F98D728AE22 and hashes.SHA512_K[79] == 0x6C44198C4A475817
    assert hashes.SHA384_IV[0] == 0xCBBB9D5DC1059ED8
    assert hashes.MD5_K[0] == 0xD76AA478 and hashes.MD5_K[63] == 0xEB86D391


# An independent SHA-256, written from FIPS 180-4 with the constants typed in,
# used only to compute the expected value for a modified K table.
_K_FIPS = [int(x, 16) for x in """
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be
550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa
5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85
2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3
d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f
682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2""".split()]


def _ref_sha256(msg, K):
    def rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    h = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += ml.to_bytes(8, "big")
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off + 4 * i: off + 4 * i + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) % 2 ** 32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)
            t1 = (hh + S1 + ch + K[i] + w[i]) % 2 ** 32
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) % 2 ** 32
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) % 2 ** 32, c, b, a, (t1 + t2) % 2 ** 32
        h = [(x + y) % 2 ** 32 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def test_independent_reference_matches_hashlib():
    for m in MSGS:
        assert _ref_sha256(m, _K_FIPS) == hashlib.sha256(m).digest()


# SHA-256("abc") with K[13] = 0x80deb5fe instead of 0x80deb1fe (one bit, 0x400, flipped)
PATCHED_ABC = "fd38a6ec8ff25682e16393a73c017dd75caf0aff7a492a9f23f322a162b2089d"


def test_sha256_k_patch_changes_digest_and_restores():
    std = hashlib.sha256(b"abc").digest()
    patched = hashes.sha256(b"abc", K={13: 0x80DEB5FE})
    assert patched != std
    assert patched.hex() == PATCHED_ABC
    k2 = list(_K_FIPS)
    k2[13] = 0x80DEB5FE
    assert patched == _ref_sha256(b"abc", k2)
    # patching back to the standard value restores the standard digest
    assert hashes.sha256(b"abc", K={13: 0x80DEB1FE}) == std
    # a full table equal to the standard one gives the standard digest
    assert hashes.sha256(b"abc", K=list(_K_FIPS)) == std
    full = list(_K_FIPS)
    full[13] = 0x80DEB5FE
    assert hashes.sha256(b"abc", K=full) == patched


def test_iv_override_paths():
    # SHA-256 compression with the SHA-224 IV, cut to 28 bytes, is SHA-224
    assert hashes.sha256(b"abc", IV=hashes.SHA224_IV)[:28] == hashlib.sha224(b"abc").digest()
    assert hashes.sha512(b"abc", IV=hashes.SHA384_IV)[:48] == hashlib.sha384(b"abc").digest()
    assert hashes.sha256(b"abc", IV={0: 0}) != hashlib.sha256(b"abc").digest()
    assert hashes.sha256(b"abc", IV={0: 0x6A09E667}) == hashlib.sha256(b"abc").digest()


@pytest.mark.parametrize("name,table_name,idx", [("md5", "K", 0), ("sha1", "K", 2), ("sha512", "K", 40),
                                                 ("sm3", "T", 1), ("md5", "IV", 3), ("sm3", "IV", 0)])
def test_patch_and_restore_every_hash(name, table_name, idx):
    f = getattr(hashes, name)
    std = f(b"abc")
    original = hashes.CONSTS[name][table_name][idx]
    assert f(b"abc", **{table_name: {idx: original ^ 1}}) != std
    assert f(b"abc", **{table_name: {idx: original}}) == std


def test_compress_matches_full_hash():
    blk = b"abc" + b"\x80" + b"\x00" * 52 + (24).to_bytes(8, "big")
    st = hashes.compress("sha256", hashes.SHA256_IV, blk)
    assert b"".join(x.to_bytes(4, "big") for x in st) == hashlib.sha256(b"abc").digest()
    st = hashes.compress("md5", hashes.MD5_IV, b"\x80" + b"\x00" * 63)
    assert b"".join(x.to_bytes(4, "little") for x in st) == hashlib.md5(b"").digest()


@pytest.mark.parametrize("name", ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
def test_hmac_against_stdlib(name):
    for key in (b"", b"k", b"key" * 30, os.urandom(200)):
        for m in (b"", b"The quick brown fox", MSGS[-1]):
            assert hashes.hmac(name, key, m) == pyhmac.new(key, m, name).digest()


def test_hmac_sm3_against_gmssl_construction_and_custom_pads():
    key, msg = b"secret", b"message"
    k = key + b"\x00" * (64 - len(key))
    inner = gsm3.sm3_hash(list(bytes(b ^ 0x36 for b in k) + msg))
    outer = gsm3.sm3_hash(list(bytes(b ^ 0x5C for b in k) + bytes.fromhex(inner)))
    assert hashes.hmac("sm3", key, msg).hex() == outer
    # non-standard pad bytes, computed independently with hashlib
    k = key + b"\x00" * (64 - len(key))
    exp = hashlib.sha256(bytes(b ^ 0x6A for b in k) + hashlib.sha256(bytes(b ^ 0x3C for b in k) + msg).digest())
    assert hashes.hmac("sha256", key, msg, ipad=0x3C, opad=0x6A) == exp.digest()


CRC_CATALOGUE = [
    # name, width, poly, init, refin, refout, xorout, check("123456789")
    ("CRC-8", 8, 0x07, 0x00, False, False, 0x00, 0xF4),
    ("CRC-16/ARC", 16, 0x8005, 0x0000, True, True, 0x0000, 0xBB3D),
    ("CRC-16/CCITT-FALSE", 16, 0x1021, 0xFFFF, False, False, 0x0000, 0x29B1),
    ("CRC-16/XMODEM", 16, 0x1021, 0x0000, False, False, 0x0000, 0x31C3),
    ("CRC-16/MODBUS", 16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37),
    ("CRC-32", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xCBF43926),
    ("CRC-32/BZIP2", 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF, 0xFC891918),
    ("CRC-32C", 32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xE3069283),
    ("CRC-32/MPEG-2", 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000, 0x0376E6E7),
    ("CRC-64/XZ", 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, True, True, 0xFFFFFFFFFFFFFFFF, 0x995DC9BBDF1939FA),
    ("CRC-64/ECMA-182", 64, 0x42F0E1EBA9EA3693, 0, False, False, 0, 0x6C40DF5F0B497347),
]


@pytest.mark.parametrize("row", CRC_CATALOGUE, ids=[r[0] for r in CRC_CATALOGUE])
def test_crc_catalogue(row):
    _, w, poly, init, refin, refout, xorout, check = row
    assert table.crc(b"123456789", w, poly, init, xorout, refin, refout) == check


def test_crc32_and_adler_against_zlib():
    for m in MSGS:
        assert table.crc32(m) == zlib.crc32(m)
        assert table.adler32(m) == zlib.adler32(m)


def test_fnv_published_vectors():
    # from the FNV reference test suite (isthe.com/chongo/tech/comp/fnv)
    assert table.fnv1a(b"") == 0x811C9DC5 and table.fnv1(b"") == 0x811C9DC5
    assert table.fnv1a(b"a") == 0xE40C292C and table.fnv1(b"a") == 0x050C5D7E
    assert table.fnv1a(b"foobar") == 0xBF9CF968 and table.fnv1(b"foobar") == 0x31F0B262
    assert table.fnv1a(b"a", 64) == 0xAF63DC4C8601EC8C and table.fnv1(b"a", 64) == 0xAF63BD4C8601B7BE
    assert table.fnv1a(b"foobar", 64) == 0x85944171F73967E8


def test_hash_calls_through_the_language():
    r = ok("hexstr(sha256(b'abc', K={13: 0x80deb5fe})) != hexstr(sha256(b'abc'))")
    assert r["result"] is True
    r = ok("c = hash_consts('sha256')\nc['K'].index(0x80deb1fe)")
    assert r["result"] == "0xd = 13"
    err("sha256(b'abc', K={64: 1})")
    err("sha256(b'abc', K=[1, 2, 3])")
    err("hmac('sha3', b'k', b'm')")
