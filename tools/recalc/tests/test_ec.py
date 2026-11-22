"""Elliptic curves and SM2 against cryptography and gmssl."""

import hashlib
import random

import pytest
from cryptography.hazmat.primitives import hashes as chashes
from cryptography.hazmat.primitives.asymmetric import ec as cec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, \
    encode_dss_signature
from gmssl import sm2 as gsm2
from gmssl import sm3 as gsm3

from recalc import ec
from recalc.errors import CalcError
from conftest import err, ok

RNG = random.Random(7)
CRYPTO_CURVES = {"p256": cec.SECP256R1(), "secp256k1": cec.SECP256K1()}


@pytest.mark.parametrize("name", ["sm2", "p256", "secp256k1"])
def test_generator_and_order(name):
    cv = ec.curve(name)
    assert ec.on_curve(name, cv.G)
    assert ec.mul(name, cv.n) is None
    assert ec.mul(name, cv.n + 1) == cv.G
    assert ec.mul(name, cv.n - 1) == ec.neg(name, cv.G)
    a, b = RNG.randrange(cv.n), RNG.randrange(cv.n)
    assert ec.add(name, ec.mul(name, a), ec.mul(name, b)) == ec.mul(name, (a + b) % cv.n)
    assert ec.add(name, cv.G, cv.G) == ec.mul(name, 2)
    assert ec.add(name, cv.G, ec.neg(name, cv.G)) is None


@pytest.mark.parametrize("name", ["p256", "secp256k1"])
def test_scalar_mult_and_encoding_against_cryptography(name):
    for _ in range(5):
        priv = cec.generate_private_key(CRYPTO_CURVES[name])
        d = priv.private_numbers().private_value
        pub = priv.public_key().public_numbers()
        P = ec.mul(name, d)
        assert P == (pub.x, pub.y)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        comp = priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        unc = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        assert ec.encode(name, P, compressed=True) == comp
        assert ec.encode(name, P) == unc
        assert ec.decode_point(ec.curve(name), comp) == P
        assert ec.decompress(name, P[0], comp[0]) == P


@pytest.mark.parametrize("name", ["p256", "secp256k1"])
def test_ecdsa_against_cryptography(name):
    priv = cec.generate_private_key(CRYPTO_CURVES[name])
    pub = priv.public_key().public_numbers()
    msg = b"recalc ecdsa"
    e = hashlib.sha256(msg).digest()
    r, s = decode_dss_signature(priv.sign(msg, cec.ECDSA(chashes.SHA256())))
    assert ec.ecdsa_verify(name, (pub.x, pub.y), e, r, s)
    assert not ec.ecdsa_verify(name, (pub.x, pub.y), e, r, (s + 1) % ec.curve(name).n)
    d = priv.private_numbers().private_value
    r2, s2 = ec.ecdsa_sign(name, d, e, RNG.randrange(1, ec.curve(name).n))
    priv.public_key().verify(encode_dss_signature(r2, s2), e, cec.ECDSA(Prehashed(chashes.SHA256())))


def test_jacobian_and_projective_to_affine():
    cv = ec.curve("sm2")
    x, y = ec.mul("sm2", 12345)
    z = RNG.randrange(2, cv.p)
    X, Y, Z = x * z * z % cv.p, y * z * z * z % cv.p, z
    assert ec.affine("sm2", X, Y, Z) == (x, y)
    assert ec.affine("sm2", x * z % cv.p, y * z % cv.p, z, kind="projective") == (x, y)
    assert ec.affine("sm2", 1, 1, 0) is None


def test_custom_curve_and_tonelli_shanks():
    # p = 13 is 1 mod 4, so decompression takes the Tonelli-Shanks path
    c = {"p": 13, "a": 1, "b": 1}
    pts = [(x, y) for x in range(13) for y in range(13) if (y * y - x ** 3 - x - 1) % 13 == 0]
    for x, y in pts:
        assert ec.on_curve(c, (x, y))
        assert ec.decompress(c, x, y & 1) == (x, y)
    p = 2 ** 255 - 19              # 5 mod 8
    for _ in range(20):
        a = RNG.randrange(1, p)
        r = ec._sqrt(a * a, p)
        assert r * r % p == a * a % p


def _gm(d=None):
    cv = ec.curve("sm2")
    d = d or RNG.randrange(1, cv.n)
    P = ec.mul("sm2", d)
    pub = "%064x%064x" % P
    return d, P, gsm2.CryptSM2(private_key="%064x" % d, public_key=pub)


def test_sm2_za_matches_gmssl():
    d, P, g = _gm()
    # gmssl's _sm3_z(data) returns hex SM3(Z || data) with the default ID
    msg = b"abc"
    assert gsm3.sm3_hash(list(ec.sm2_za(P) + msg)) == g._sm3_z(msg)


def test_sm2_signatures_both_ways():
    d, P, g = _gm()
    msg = b"message digest"
    for _ in range(3):
        sig = g.sign_with_sm3(msg)
        r, s = int(sig[:64], 16), int(sig[64:], 16)
        assert ec.sm2_verify(P, msg, r, s)
        assert not ec.sm2_verify(P, msg + b"x", r, s)
        assert not ec.sm2_verify(P, msg, r, s ^ 1)
    r, s = ec.sm2_sign(d, msg, RNG.randrange(1, ec.curve("sm2").n))
    assert g.verify_with_sm3("%064x%064x" % (r, s), msg)
    # hashed=True takes e directly
    e = ec.hashes.sm3(ec.sm2_za(P) + msg)
    assert ec.sm2_verify(P, e, r, s, hashed=True)


def test_sm2_kdf_and_encryption_against_gmssl():
    z = bytes(range(64))
    assert ec.sm2_kdf(z, 100).hex() == gsm3.sm3_kdf(z.hex().encode(), 100)
    d, P, _ = _gm()
    msg = b"encryption standard"
    g1 = gsm2.CryptSM2(private_key="%064x" % d, public_key="%064x%064x" % P, mode=1)   # C1C3C2
    assert ec.sm2_decrypt(d, b"\x04" + g1.encrypt(msg)) == msg
    assert ec.sm2_decrypt(d, g1.encrypt(msg)) == msg                    # C1 without the 04 prefix
    g0 = gsm2.CryptSM2(private_key="%064x" % d, public_key="%064x%064x" % P, mode=0)   # C1C2C3
    assert ec.sm2_decrypt(d, g0.encrypt(msg), mode="c1c2c3") == msg
    ct = ec.sm2_encrypt(P, msg, RNG.randrange(1, ec.curve("sm2").n))
    assert g1.decrypt(ct[1:]) == msg
    with pytest.raises(CalcError):
        ec.sm2_decrypt(d, ct, mode="c1c2c3")


def test_ec_through_the_language():
    r = ok("G = (ec_curve('sm2')['Gx'], ec_curve('sm2')['Gy'])\nec_on_curve('sm2', G), ec_mul('sm2', 1) == G")
    assert r["result"] == {"tuple": [True, True]}
    r = err("ec_add('sm2', (1, 2), (3, 4))")
    assert "not on the curve" in r["error"]
    err("ec_mul('curve25519', 5)")
