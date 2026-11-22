"""The three checks from the benchmark that motivated recalc (also in the README)."""

import hashlib

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

from conftest import calc, cli
import json


def test_1_rotate_left_is_not_add():
    r = calc("right = pow(7, rotl(532, 4, 32) ^ 5, 1000003)\n"
             "wrong = pow(7, (532 + 4) ^ 5, 1000003)\n"
             "right, wrong, right == wrong")
    assert r["vars"]["right"] == "0x8e42a = 582698"
    assert r["vars"]["wrong"] != r["vars"]["right"]
    assert r["result"]["tuple"][2] is False
    # cross-check with plain Python
    rot = ((532 << 4) | (532 >> 28)) & 0xFFFFFFFF
    assert pow(7, rot ^ 5, 1000003) == 582698
    assert r["vars"]["wrong"] == "%#x = %d" % ((w := pow(7, (532 + 4) ^ 5, 1000003)), w)


def test_2_sha256_with_one_constant_changed():
    r = calc("std = sha256(b'abc')\n"
             "var = sha256(b'abc', K={13: 0x80deb5fe})\n"
             "back = sha256(b'abc', K={13: 0x80deb1fe})\n"
             "hexstr(var), var == std, back == std")
    assert r["vars"]["std"]["hex"] == hashlib.sha256(b"abc").hexdigest()
    hexvar, same, restored = r["result"]["tuple"]
    assert hexvar == "fd38a6ec8ff25682e16393a73c017dd75caf0aff7a492a9f23f322a162b2089d"
    assert same is False and restored is True
    # the same value from the independent FIPS 180-4 implementation in test_hashes
    from test_hashes import _K_FIPS, _ref_sha256
    k = list(_K_FIPS)
    k[13] = 0x80DEB5FE
    assert _ref_sha256(b"abc", k).hex() == hexvar


def test_3_sm4_cbc_pkcs7_round_trip():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes(range(16))
    msg = b"attack at dawn; bring snacks"
    g = CryptSM4(padding_mode=0)
    g.set_key(key, SM4_ENCRYPT)
    ct = g.crypt_cbc(iv, msg)                           # independent encryption (gmssl, PKCS#7)
    code = ("key = unhex('%s')\niv = unhex('%s')\nct = unhex('%s')\n"
            "pt = pkcs7_unpad(cbc_dec('sm4', key, iv, ct))\n"
            "again = cbc_enc('sm4', key, iv, pkcs7_pad(pt))\n"
            "pt, again == ct" % (key.hex(), iv.hex(), ct.hex()))
    r = calc(code)
    pt, same = r["result"]["tuple"]
    assert pt["ascii"] == msg.decode() and same is True
    # through the launcher as rekit uses it
    p = cli({"code": code})
    assert json.loads(p.stdout)["result"]["tuple"][0]["ascii"] == msg.decode()
