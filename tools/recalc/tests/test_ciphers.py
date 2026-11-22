"""Block and stream ciphers against FIPS/GB/RFC vectors, cryptography,
pycryptodome, gmssl, and (TEA family) the reference C code compiled here."""

import os
import random
import shutil
import subprocess
import tempfile

import pytest
from Crypto.Cipher import AES as PAES, ARC4 as PARC4, ChaCha20 as PCHACHA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT

from recalc import ciphers as C
from recalc.errors import CalcError
from conftest import err, ok

RNG = random.Random(99)


def rb(n):
    return bytes(RNG.randrange(256) for _ in range(n))


def test_aes_fips197_appendix_c():
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    for klen, ct in ((16, "69c4e0d86a7b0430d8cdb78070b4c55a"), (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
                     (32, "8ea2b7ca516745bfeafc49904b496089")):
        key = bytes(range(klen))
        assert C.aes_enc(key, pt).hex() == ct
        assert C.aes_dec(key, bytes.fromhex(ct)) == pt


@pytest.mark.parametrize("klen", [16, 24, 32])
def test_aes_modes_against_cryptography(klen):
    for n in (16, 48, 160):
        key, iv, data = rb(klen), rb(16), rb(n)
        e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        assert C.aes_enc(key, data) == e.update(data) + e.finalize()
        assert C.aes_dec(key, C.aes_enc(key, data)) == data
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = e.update(data) + e.finalize()
        assert C.cbc_enc("aes", key, iv, data) == ct
        assert C.cbc_dec("aes", key, iv, ct) == data
        # CTR with the whole 16-byte block as a big-endian counter (cryptography's layout)
        odd = rb(n + 5)
        e = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        assert C.ctr("aes", key, iv, odd) == e.update(odd) + e.finalize()


def test_ctr_counter_layouts_against_pycryptodome():
    key, nonce, data = rb(16), rb(12), rb(100)
    # 12-byte nonce + 32-bit big-endian counter starting at 1 (the GCM/RFC 3686 style layout)
    p = PAES.new(key, PAES.MODE_CTR, nonce=nonce, initial_value=1)
    assert C.ctr("aes", key, nonce + (1).to_bytes(4, "big"), data, ctr_len=4) == p.encrypt(data)
    # 8-byte nonce + 64-bit counter
    n8 = rb(8)
    p = PAES.new(key, PAES.MODE_CTR, nonce=n8, initial_value=7)
    assert C.ctr("aes", key, n8 + (7).to_bytes(8, "big"), data, ctr_len=8) == p.encrypt(data)
    # little-endian counter in the first 4 bytes, computed block by block
    blk0 = (0xFFFFFFFE).to_bytes(4, "little") + rb(12)
    exp = b""
    for i in range(3):
        cb = ((0xFFFFFFFE + i) % 2 ** 32).to_bytes(4, "little") + blk0[4:]
        exp += bytes(a ^ b for a, b in zip(data[16 * i:16 * i + 16], C.aes_enc(key, cb)))
    assert C.ctr("aes", key, blk0, data[:48], ctr_len=4, ctr_pos=0, order="little") == exp


def test_aes_sbox_override():
    key, data = rb(16), rb(32)
    assert C.aes_enc(key, data, sbox=C.AES_SBOX) == C.aes_enc(key, data)
    sb = list(C.AES_SBOX)
    sb[0], sb[1] = sb[1], sb[0]
    ct = C.aes_enc(key, data, sbox=sb)
    assert ct != C.aes_enc(key, data)
    assert C.aes_dec(key, ct, sbox=sb) == data
    with pytest.raises(CalcError):
        C.aes_enc(key, data, sbox=[0] * 256)


def test_sm4_gbt32907_vector_and_gmssl():
    k = bytes.fromhex("0123456789abcdeffedcba9876543210")
    assert C.sm4_enc(k, k).hex() == "681edf34d206965e86b3e94f536e4246"
    assert C.sm4_dec(k, bytes.fromhex("681edf34d206965e86b3e94f536e4246")) == k
    for n in (0, 5, 16, 33, 100):
        key, iv, data = rb(16), rb(16), rb(n)
        g = CryptSM4(padding_mode=0)
        g.set_key(key, SM4_ENCRYPT)
        assert C.ecb_enc("sm4", key, C.pkcs7_pad(data)) == g.crypt_ecb(data)
        g = CryptSM4(padding_mode=0)
        g.set_key(key, SM4_ENCRYPT)
        ct = g.crypt_cbc(iv, data)
        assert C.cbc_enc("sm4", key, iv, C.pkcs7_pad(data)) == ct
        assert C.pkcs7_unpad(C.cbc_dec("sm4", key, iv, ct)) == data
        g = CryptSM4(padding_mode=0)
        g.set_key(key, SM4_DECRYPT)
        assert g.crypt_cbc(iv, C.cbc_enc("sm4", key, iv, C.pkcs7_pad(data))) == data


def test_sm4_tables_match_gmssl():
    import gmssl.sm4 as g
    assert C.SM4_SBOX == list(g.SM4_BOXES_TABLE)
    assert C.SM4_FK == list(g.SM4_FK) and C.SM4_CK == list(g.SM4_CK)


def test_pkcs7():
    assert C.pkcs7_pad(b"") == b"\x10" * 16
    assert C.pkcs7_pad(b"abc", 8) == b"abc\x05\x05\x05\x05\x05"
    assert C.pkcs7_unpad(b"abc\x05\x05\x05\x05\x05", 8) == b"abc"
    for bad in (b"abc\x05\x05\x05\x05\x04", b"a" * 15 + b"\x00", b"a" * 15 + b"\x11"):
        with pytest.raises(CalcError):
            C.pkcs7_unpad(bad)


def test_rc4_against_pycryptodome_and_rfc6229():
    # RFC 6229, key 0102030405, offset 0
    assert C.rc4(bytes.fromhex("0102030405"), bytes(16)).hex() == "b2396305f03dc027ccc3524a0a1118a8"
    for _ in range(5):
        key, data = rb(RNG.randrange(1, 40)), rb(300)
        assert C.rc4(key, data) == PARC4.new(key).encrypt(data)
    key, data = rb(16), rb(50)
    assert C.rc4(key, data, drop=256) == PARC4.new(key, drop=256).encrypt(data)


def test_chacha20_rfc8439_and_libraries():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    assert C.chacha20_block(key, 1, nonce).hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    for n in (1, 64, 65, 300):
        key, nonce, data = rb(32), rb(12), rb(n)
        e = Cipher(algorithms.ChaCha20(key, (5).to_bytes(4, "little") + nonce), None).encryptor()
        assert C.chacha20(key, nonce, data, counter=5) == e.update(data)
        n8 = rb(8)
        assert C.chacha20(key, n8, data) == PCHACHA.new(key=key, nonce=n8).encrypt(data)
    # reduced rounds and a changed constant are accepted and differ
    assert C.chacha20_block(key, 0, nonce, rounds=8) != C.chacha20_block(key, 0, nonce)
    assert C.chacha20_block(key, 0, nonce, sigma=b"expand 16-byte k") != C.chacha20_block(key, 0, nonce)


TEA_C = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
static void tea_e(uint32_t *v, const uint32_t *k) {
  uint32_t v0=v[0], v1=v[1], sum=0, i, delta=0x9E3779B9;
  for (i=0; i<32; i++) { sum += delta;
    v0 += ((v1<<4) + k[0]) ^ (v1 + sum) ^ ((v1>>5) + k[1]);
    v1 += ((v0<<4) + k[2]) ^ (v0 + sum) ^ ((v0>>5) + k[3]); }
  v[0]=v0; v[1]=v1; }
static void tea_d(uint32_t *v, const uint32_t *k) {
  uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i, delta=0x9E3779B9;
  for (i=0; i<32; i++) {
    v1 -= ((v0<<4) + k[2]) ^ (v0 + sum) ^ ((v0>>5) + k[3]);
    v0 -= ((v1<<4) + k[0]) ^ (v1 + sum) ^ ((v1>>5) + k[1]); sum -= delta; }
  v[0]=v0; v[1]=v1; }
static void xtea_e(unsigned r, uint32_t *v, const uint32_t *key) {
  uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9; unsigned i;
  for (i=0; i<r; i++) { v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    sum += delta; v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]); }
  v[0]=v0; v[1]=v1; }
static void xtea_d(unsigned r, uint32_t *v, const uint32_t *key) {
  uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*r; unsigned i;
  for (i=0; i<r; i++) { v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    sum -= delta; v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]); }
  v[0]=v0; v[1]=v1; }
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
static void btea(uint32_t *v, int n, uint32_t const key[4]) {
  uint32_t y, z, sum; unsigned p, rounds, e;
  if (n > 1) { rounds = 6 + 52/n; sum = 0; z = v[n-1];
    do { sum += DELTA; e = (sum >> 2) & 3;
      for (p=0; p<n-1; p++) { y = v[p+1]; z = v[p] += MX; }
      y = v[0]; z = v[n-1] += MX; } while (--rounds);
  } else if (n < -1) { n = -n; rounds = 6 + 52/n; sum = rounds*DELTA; y = v[0];
    do { e = (sum >> 2) & 3;
      for (p=n-1; p>0; p--) { z = v[p-1]; y = v[p] -= MX; }
      z = v[n-1]; y = v[0] -= MX; sum -= DELTA; } while (--rounds); } }
int main(void) {
  char op[16]; int n;
  while (scanf("%15s %d", op, &n) == 2) {
    uint32_t k[4], v[64]; int i;
    for (i=0;i<4;i++) scanf("%x", &k[i]);
    for (i=0;i<n;i++) scanf("%x", &v[i]);
    if (!strcmp(op,"tea_e")) tea_e(v,k); else if (!strcmp(op,"tea_d")) tea_d(v,k);
    else if (!strcmp(op,"xtea_e")) xtea_e(32,v,k); else if (!strcmp(op,"xtea_d")) xtea_d(32,v,k);
    else if (!strcmp(op,"xxtea_e")) btea(v,n,k); else if (!strcmp(op,"xxtea_d")) btea(v,-n,k);
    for (i=0;i<n;i++) printf("%08x ", v[i]); printf("\n"); }
  return 0; }
"""


@pytest.fixture(scope="module")
def tea_ref():
    cc = shutil.which("clang") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler for the reference TEA code")
    d = tempfile.mkdtemp()
    src, exe = os.path.join(d, "tea.c"), os.path.join(d, "tea")
    with open(src, "w") as fh:
        fh.write(TEA_C)
    subprocess.run([cc, "-O1", "-o", exe, src], check=True, capture_output=True)

    def run(lines):
        p = subprocess.run([exe], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
        return [[int(x, 16) for x in ln.split()] for ln in p.stdout.splitlines()]
    yield run
    shutil.rmtree(d)


def test_tea_family_against_reference_c(tea_ref):
    cases = []
    for _ in range(20):
        k = [RNG.getrandbits(32) for _ in range(4)]
        v = [RNG.getrandbits(32) for _ in range(2)]
        vv = [RNG.getrandbits(32) for _ in range(RNG.randrange(2, 12))]
        cases.append((k, v, vv))
    lines = []
    for k, v, vv in cases:
        for op in ("tea_e", "tea_d", "xtea_e", "xtea_d"):
            lines.append("%s 2 %s %s" % (op, " ".join("%x" % x for x in k), " ".join("%x" % x for x in v)))
        for op in ("xxtea_e", "xxtea_d"):
            lines.append("%s %d %s %s" % (op, len(vv), " ".join("%x" % x for x in k), " ".join("%x" % x for x in vv)))
    out = iter(tea_ref(lines))
    for k, v, vv in cases:
        assert C.tea_enc(k, v) == next(out)
        assert C.tea_dec(k, v) == next(out)
        assert C.xtea_enc(k, v) == next(out)
        assert C.xtea_dec(k, v) == next(out)
        assert C.xxtea_enc(k, vv) == next(out)
        assert C.xxtea_dec(k, vv) == next(out)
        assert C.tea_dec(k, C.tea_enc(k, v)) == v
        assert C.xxtea_dec(k, C.xxtea_enc(k, vv)) == vv


def test_tea_published_vectors_and_byte_order():
    # TEA, all-zero key and block (Wheeler & Needham reference output)
    assert C.tea_enc([0, 0, 0, 0], [0, 0]) == [0x41EA3A0A, 0x94BAA940]
    # bytes need an explicit word order
    with pytest.raises(CalcError):
        C.tea_enc(bytes(16), bytes(8))
    key, data = rb(16), rb(16)
    le = C.tea_enc(key, data, order="little")
    words = C.tea_enc(C._words(key, 4, "k", "little"), C._words(data, None, "d", "little"))
    assert le == b"".join(w.to_bytes(4, "little") for w in words)
    assert C.cbc_dec("xtea", key, data[:8], C.cbc_enc("xtea", key, data[:8], data, order="big"),
                     order="big") == data


def test_cipher_errors_through_the_language():
    err("aes_enc(b'short', bytes(16))")
    r = err("aes_enc(bytes(16), bytes(15))")
    assert "pkcs7_pad" in r["hint"]
    r = err("ctr('aes', bytes(16), bytes(12), b'x')")
    assert "block0" in r["error"]
    assert ok("rc4(b'Key', b'Plaintext').hex()")["result"] == "bbf316e8d940af0ad3"
