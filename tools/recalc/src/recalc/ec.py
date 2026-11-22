"""Short-Weierstrass elliptic curves (y^2 = x^3 + ax + b mod p) and SM2 helpers.

A point is a tuple (x, y); the point at infinity is None. A curve is a name
('sm2', 'p256', 'secp256k1') or a dict {p, a, b[, n, Gx, Gy]} for custom ones.
"""

from __future__ import annotations

from .errors import CalcError, short
from . import hashes

CURVES = {
    "sm2": dict(
        p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
        a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
        b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
        n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
        Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
        Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0),
    "p256": dict(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        Gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        Gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    "secp256k1": dict(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0, b=7,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
}
ALIASES = {"prime256v1": "p256", "secp256r1": "p256", "p-256": "p256", "sm2p256v1": "sm2"}
MAX_P_BITS = 1024
SM2_DEFAULT_ID = b"1234567812345678"


class Curve:
    def __init__(self, p, a, b, n=None, gx=None, gy=None, name="custom"):
        self.p, self.a, self.b, self.n, self.name = p, a % p, b % p, n, name
        self.G = (gx, gy) if gx is not None and gy is not None else None
        self.size = (p.bit_length() + 7) // 8


def curve(c):
    if isinstance(c, str):
        key = ALIASES.get(c.lower(), c.lower())
        if key not in CURVES:
            raise CalcError("unknown curve %s" % short(c), "one of: sm2, p256, secp256k1, or a dict {p, a, b, n, Gx, Gy}")
        d = CURVES[key]
        return Curve(d["p"], d["a"], d["b"], d["n"], d["Gx"], d["Gy"], key)
    if isinstance(c, dict):
        bad = set(c) - {"p", "a", "b", "n", "Gx", "Gy"}
        if bad or not {"p", "a", "b"} <= set(c):
            raise CalcError("a custom curve is a dict with keys p, a, b and optionally n, Gx, Gy")
        for k, v in c.items():
            if not isinstance(v, int) or isinstance(v, bool):
                raise CalcError("curve parameter %s must be an integer" % k)
        p = c["p"]
        if p < 3 or p.bit_length() > MAX_P_BITS:
            raise CalcError("curve p must be 3..%d bits" % MAX_P_BITS)
        return Curve(p, c["a"], c["b"], c.get("n"), c.get("Gx"), c.get("Gy"))
    raise CalcError("curve must be a name ('sm2', 'p256', 'secp256k1') or a parameter dict")


def curve_params(c):
    cv = curve(c)
    out = {"p": cv.p, "a": cv.a, "b": cv.b}
    if cv.n is not None:
        out["n"] = cv.n
    if cv.G is not None:
        out["Gx"], out["Gy"] = cv.G
    return out


def _pt(cv, P, what="point"):
    if P is None:
        return None
    if isinstance(P, (tuple, list)) and len(P) == 2 and all(isinstance(v, int) for v in P):
        return (P[0] % cv.p, P[1] % cv.p) if 0 <= P[0] < cv.p and 0 <= P[1] < cv.p else \
            _bad(what, "coordinates must be in 0..p-1")
    if isinstance(P, bytes):
        return decode_point(cv, P)
    raise CalcError("%s must be a tuple (x, y), None for infinity, or encoded bytes" % what)


def _bad(what, why):
    raise CalcError("%s: %s" % (what, why))


def on_curve(c, P):
    cv = curve(c)
    P = _pt(cv, P)
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + cv.a * x + cv.b)) % cv.p == 0


def _need_on(cv, P, what):
    P = _pt(cv, P, what)
    if P is not None:
        x, y = P
        if (y * y - (x * x * x + cv.a * x + cv.b)) % cv.p:
            raise CalcError("%s is not on the curve" % what,
                            "check with ec_on_curve; maybe x and y are swapped, little-endian, "
                            "or in Jacobian/Montgomery form (ec_affine)")
    return P


def neg(c, P):
    cv = curve(c)
    P = _pt(cv, P)
    return None if P is None else (P[0], (-P[1]) % cv.p)


def _add(cv, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    p = cv.p
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] + cv.a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def add(c, P, Q):
    cv = curve(c)
    return _add(cv, _need_on(cv, P, "P"), _need_on(cv, Q, "Q"))


def _jdouble(cv, X, Y, Z):
    p = cv.p
    if Y == 0 or Z == 0:
        return (1, 1, 0)
    YY = Y * Y % p
    S = 4 * X * YY % p
    M = (3 * X * X + cv.a * pow(Z, 4, p)) % p
    X3 = (M * M - 2 * S) % p
    return (X3, (M * (S - X3) - 8 * YY * YY) % p, 2 * Y * Z % p)


def _jadd(cv, P1, P2):
    X1, Y1, Z1 = P1
    X2, Y2, Z2 = P2
    if Z1 == 0:
        return P2
    if Z2 == 0:
        return P1
    p = cv.p
    Z1Z1, Z2Z2 = Z1 * Z1 % p, Z2 * Z2 % p
    U1, U2 = X1 * Z2Z2 % p, X2 * Z1Z1 % p
    S1, S2 = Y1 * Z2 * Z2Z2 % p, Y2 * Z1 * Z1Z1 % p
    if U1 == U2:
        return _jdouble(cv, X1, Y1, Z1) if S1 == S2 else (1, 1, 0)
    H, R = (U2 - U1) % p, (S2 - S1) % p
    HH = H * H % p
    HHH = H * HH % p
    V = U1 * HH % p
    X3 = (R * R - HHH - 2 * V) % p
    return (X3, (R * (V - X3) - S1 * HHH) % p, H * Z1 * Z2 % p)


def _to_affine(cv, X, Y, Z):
    if Z % cv.p == 0:
        return None
    zi = pow(Z, -1, cv.p)
    zi2 = zi * zi % cv.p
    return (X * zi2 % cv.p, Y * zi2 * zi % cv.p)


def _mul(cv, k, P):
    if P is None or k == 0:
        return None
    if k < 0:
        k, P = -k, (P[0], (-P[1]) % cv.p)
    R = (1, 1, 0)
    J = (P[0], P[1], 1)
    for bit in bin(k)[2:]:
        R = _jdouble(cv, *R)
        if bit == "1":
            R = _jadd(cv, R, J)
    return _to_affine(cv, *R)


def mul(c, k, P=None):
    """k * P (P defaults to the generator G)."""
    cv = curve(c)
    if not isinstance(k, int):
        raise CalcError("scalar must be an integer")
    if k.bit_length() > 2 * MAX_P_BITS:
        raise CalcError("scalar is %d bits; reduce it modulo n first" % k.bit_length())
    if P is None:
        if cv.G is None:
            raise CalcError("this curve has no generator; pass P")
        P = cv.G
    return _mul(cv, k, _need_on(cv, P, "P"))


def _sqrt(a, p):
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
        if z > 10000:
            raise CalcError("no quadratic non-residue found; is p prime?")
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % p, i + 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def decompress(c, x, parity):
    """The point with this x whose y has the given parity (0 even, 1 odd; 2/3
    prefix bytes are accepted too)."""
    cv = curve(c)
    if not isinstance(x, int) or not 0 <= x < cv.p:
        raise CalcError("x must be an integer 0..p-1")
    if parity in (2, 3):
        parity -= 2
    if parity not in (0, 1):
        raise CalcError("parity must be 0/1 (or the prefix byte 2/3)")
    y = _sqrt(x * x * x + cv.a * x + cv.b, cv.p)
    if y is None:
        raise CalcError("no point on the curve has this x (x^3+ax+b is not a square mod p)")
    if y & 1 != parity:
        y = (cv.p - y) % cv.p
    return (x, y)


def decode_point(c, data):
    cv = curve(c) if not isinstance(c, Curve) else c
    n = cv.size
    if len(data) == 2 * n + 1 and data[0] == 4:
        P = (int.from_bytes(data[1:n + 1], "big"), int.from_bytes(data[n + 1:], "big"))
    elif len(data) == 2 * n:
        P = (int.from_bytes(data[:n], "big"), int.from_bytes(data[n:], "big"))
    elif len(data) == n + 1 and data[0] in (2, 3):
        return decompress({"p": cv.p, "a": cv.a, "b": cv.b}, int.from_bytes(data[1:], "big"), data[0])
    else:
        raise CalcError("cannot decode a %d-byte point for a %d-byte curve" % (len(data), n),
                        "expected 04||x||y (%d), x||y (%d) or 02/03||x (%d) bytes, big-endian"
                        % (2 * n + 1, 2 * n, n + 1))
    return P


def encode(c, P, compressed=False):
    cv = curve(c)
    P = _need_on(cv, P, "P")
    if P is None:
        return b"\x00"
    n = cv.size
    if compressed:
        return bytes([2 + (P[1] & 1)]) + P[0].to_bytes(n, "big")
    return b"\x04" + P[0].to_bytes(n, "big") + P[1].to_bytes(n, "big")


def affine(c, X, Y, Z, kind="jacobian"):
    """Jacobian (x = X/Z^2, y = Y/Z^3) or projective (x = X/Z, y = Y/Z) to affine."""
    cv = curve(c)
    if kind == "jacobian":
        return _to_affine(cv, X % cv.p, Y % cv.p, Z % cv.p)
    if kind == "projective":
        if Z % cv.p == 0:
            return None
        zi = pow(Z, -1, cv.p)
        return (X * zi % cv.p, Y * zi % cv.p)
    raise CalcError("kind must be 'jacobian' or 'projective'")


# ---- ECDSA (for p256 / secp256k1 checks) ----------------------------------

def _e(cv, e):
    if isinstance(e, bytes):
        v = int.from_bytes(e, "big")
        excess = 8 * len(e) - cv.n.bit_length()
        return v >> excess if excess > 0 else v
    if isinstance(e, int):
        return e
    raise CalcError("e must be the message hash as bytes or an integer")


def ecdsa_verify(c, P, e, r, s):
    cv = curve(c)
    P = _need_on(cv, P, "public key")
    n = cv.n
    if not (0 < r < n and 0 < s < n):
        return False
    w = pow(s, -1, n)
    R = _add(cv, _mul(cv, _e(cv, e) * w % n, cv.G), _mul(cv, r * w % n, P))
    return R is not None and R[0] % n == r


def ecdsa_sign(c, d, e, k):
    cv = curve(c)
    n = cv.n
    R = _mul(cv, k, cv.G)
    r = R[0] % n
    s = pow(k, -1, n) * (_e(cv, e) + r * d) % n
    if r == 0 or s == 0:
        raise CalcError("degenerate signature; pick another k")
    return (r, s)


# ---- SM2 ---------------------------------------------------------------

def _id(uid):
    if uid is None:
        return SM2_DEFAULT_ID
    if isinstance(uid, str):
        return uid.encode()
    if isinstance(uid, bytes):
        if len(uid) * 8 > 0xFFFF:
            raise CalcError("SM2 id is too long")
        return uid
    raise CalcError("id must be bytes")


def sm2_za(P, id=None, c="sm2"):
    """Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)."""
    cv = curve(c)
    P = _need_on(cv, P, "public key")
    if P is None:
        raise CalcError("public key is the point at infinity")
    uid = _id(id)
    n = cv.size
    data = (len(uid) * 8).to_bytes(2, "big") + uid + b"".join(
        v.to_bytes(n, "big") for v in (cv.a, cv.b, cv.G[0], cv.G[1], P[0], P[1]))
    return hashes.sm3(data)


def sm2_kdf(z, klen):
    if not isinstance(z, bytes):
        raise CalcError("KDF input must be bytes (e.g. x2||y2 as 64 bytes)")
    if not isinstance(klen, int) or not 0 <= klen <= 1 << 20:
        raise CalcError("klen (bytes) must be 0..1048576")
    out = b""
    ct = 1
    while len(out) < klen:
        out += hashes.sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return out[:klen]


def _sm2_e(cv, P, msg, uid, hashed):
    if hashed:
        if isinstance(msg, bytes):
            return int.from_bytes(msg, "big")
        if isinstance(msg, int):
            return msg
        raise CalcError("with hashed=True, msg is e: 32 bytes or an integer")
    if not isinstance(msg, bytes):
        raise CalcError("msg must be bytes (or pass hashed=True with e)")
    return int.from_bytes(hashes.sm3(sm2_za(P, uid) + msg), "big")


def sm2_verify(P, msg, r, s, id=None, hashed=False):
    """True if (r, s) is a valid SM2 signature of msg by public key P.
    With hashed=True, msg is e itself (32 bytes or an integer)."""
    cv = curve("sm2")
    P = _need_on(cv, P, "public key")
    n = cv.n
    if not (isinstance(r, int) and isinstance(s, int) and 0 < r < n and 0 < s < n):
        return False
    e = _sm2_e(cv, P, msg, id, hashed)
    t = (r + s) % n
    if t == 0:
        return False
    R = _add(cv, _mul(cv, s, cv.G), _mul(cv, t, P))
    return R is not None and (e + R[0]) % n == r


def sm2_sign(d, msg, k, id=None, hashed=False):
    cv = curve("sm2")
    n = cv.n
    P = _mul(cv, d, cv.G)
    e = _sm2_e(cv, P, msg, id, hashed)
    x1 = _mul(cv, k, cv.G)[0]
    r = (e + x1) % n
    s = pow(1 + d, -1, n) * (k - r * d) % n
    if r == 0 or r + k == n or s == 0:
        raise CalcError("degenerate signature; pick another k")
    return (r, s)


def _order(mode):
    if mode not in ("c1c3c2", "c1c2c3"):
        raise CalcError("mode must be 'c1c3c2' (GB/T 32918 2012+) or 'c1c2c3' (old)")
    return mode


def sm2_encrypt(P, msg, k, mode="c1c3c2"):
    cv = curve("sm2")
    P = _need_on(cv, P, "public key")
    _order(mode)
    C1 = _mul(cv, k, cv.G)
    x2, y2 = _mul(cv, k, P)
    xy = x2.to_bytes(32, "big") + y2.to_bytes(32, "big")
    t = sm2_kdf(xy, len(msg))
    C2 = bytes(a ^ b for a, b in zip(msg, t))
    C3 = hashes.sm3(xy[:32] + msg + xy[32:])
    c1 = b"\x04" + C1[0].to_bytes(32, "big") + C1[1].to_bytes(32, "big")
    return c1 + (C3 + C2 if mode == "c1c3c2" else C2 + C3)


def sm2_decrypt(d, ct, mode="c1c3c2"):
    """Decrypt C1||C3||C2 (or C1||C2||C3); C1 may be 04||x||y or x||y."""
    cv = curve("sm2")
    _order(mode)
    if not isinstance(ct, bytes) or len(ct) < 96:
        raise CalcError("ciphertext must be bytes of at least 96 bytes")
    off = 65 if ct[0] == 4 and len(ct) >= 97 else 64
    C1 = _need_on(cv, decode_point(cv, ct[:off]), "C1")
    rest = ct[off:]
    C3, C2 = (rest[:32], rest[32:]) if mode == "c1c3c2" else (rest[-32:], rest[:-32])
    x2, y2 = _mul(cv, d, C1)
    xy = x2.to_bytes(32, "big") + y2.to_bytes(32, "big")
    msg = bytes(a ^ b for a, b in zip(C2, sm2_kdf(xy, len(C2))))
    if hashes.sm3(xy[:32] + msg + xy[32:]) != C3:
        raise CalcError("SM2 C3 check failed",
                        "wrong private key, wrong C1C3C2/C1C2C3 order (mode=), or a damaged ciphertext")
    return msg
