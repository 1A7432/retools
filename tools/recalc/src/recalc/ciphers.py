"""Pure-Python block and stream ciphers, written for clarity and for variant
testing (S-box, delta, rounds and constant overrides), not for speed."""

from __future__ import annotations

import struct

from .errors import CalcError, short

M32 = 0xFFFFFFFF


def _b(v, what):
    if isinstance(v, str):
        raise CalcError("%s must be bytes, not a string" % what,
                        'write b"...", unhex("...") or s.encode()')
    if not isinstance(v, bytes):
        raise CalcError("%s must be bytes, got %s" % (what, type(v).__name__))
    return v


def _blocks(data, size, what="data"):
    data = _b(data, what)
    if len(data) % size:
        raise CalcError("%s is %d bytes, not a multiple of the %d-byte block" % (what, len(data), size),
                        "pad first with pkcs7_pad(data, %d), or cut to whole blocks" % size)
    return data


def _sbox_arg(sbox, std):
    if sbox is None:
        return std
    if isinstance(sbox, bytes):
        sbox = list(sbox)
    if not isinstance(sbox, (list, tuple)) or len(sbox) != 256 or \
            not all(isinstance(x, int) and 0 <= x <= 255 for x in sbox):
        raise CalcError("sbox must be 256 byte values (a list or 256 bytes)")
    if sorted(sbox) != list(range(256)):
        raise CalcError("sbox is not a permutation of 0..255, so it cannot be inverted")
    return list(sbox)


# ---- AES ---------------------------------------------------------------

def _xt(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _make_aes_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    out = []
    for a in range(256):
        x = inv[a]
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        out.append(s ^ 0x63)
    return out


AES_SBOX = _make_aes_sbox()
_MUL = {c: [_gmul(x, c) for x in range(256)] for c in (2, 3, 9, 11, 13, 14)}


def _aes_expand(key, sbox):
    key = _b(key, "key")
    if len(key) not in (16, 24, 32):
        raise CalcError("AES key must be 16, 24 or 32 bytes, got %d" % len(key))
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [sbox[t[1]] ^ rcon, sbox[t[2]], sbox[t[3]], sbox[t[0]]]
            rcon = _xt(rcon)
        elif nk > 6 and i % nk == 4:
            t = [sbox[x] for x in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)], nr


def _aes_block_enc(rk, nr, blk, sb):
    s = [a ^ b for a, b in zip(blk, rk[0])]
    m2, m3 = _MUL[2], _MUL[3]
    for r in range(1, nr + 1):
        s = [sb[x] for x in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]       # ShiftRows
        if r != nr:
            t = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                t += [m2[a0] ^ m3[a1] ^ a2 ^ a3, a0 ^ m2[a1] ^ m3[a2] ^ a3,
                      a0 ^ a1 ^ m2[a2] ^ m3[a3], m3[a0] ^ a1 ^ a2 ^ m2[a3]]
            s = t
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


def _aes_block_dec(rk, nr, blk, isb):
    s = [a ^ b for a, b in zip(blk, rk[nr])]
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    for r in range(nr - 1, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]       # InvShiftRows
        s = [isb[x] for x in s]
        s = [a ^ b for a, b in zip(s, rk[r])]
        if r != 0:
            t = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                t += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3], m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                      m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3], m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
            s = t
    return bytes(s)


def _inv(sbox):
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv


def aes_enc(key, data, sbox=None):
    sb = _sbox_arg(sbox, AES_SBOX)
    rk, nr = _aes_expand(key, sb)
    data = _blocks(data, 16)
    return b"".join(_aes_block_enc(rk, nr, data[i:i + 16], sb) for i in range(0, len(data), 16))


def aes_dec(key, data, sbox=None):
    sb = _sbox_arg(sbox, AES_SBOX)
    rk, nr = _aes_expand(key, sb)
    isb = _inv(sb)
    data = _blocks(data, 16)
    return b"".join(_aes_block_dec(rk, nr, data[i:i + 16], isb) for i in range(0, len(data), 16))


# ---- SM4 ---------------------------------------------------------------

SM4_SBOX = list(bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa441326498606999c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa64707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89eeabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e31df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b08969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"))
SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
SM4_CK = [((((4 * i) * 7) & 0xFF) << 24) | ((((4 * i + 1) * 7) & 0xFF) << 16)
          | ((((4 * i + 2) * 7) & 0xFF) << 8) | (((4 * i + 3) * 7) & 0xFF) for i in range(32)]


def _rl(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _tau(x, sb):
    return (sb[x >> 24] << 24) | (sb[(x >> 16) & 0xFF] << 16) | (sb[(x >> 8) & 0xFF] << 8) | sb[x & 0xFF]


def _sm4_keys(key, sb, fk, ck):
    key = _b(key, "key")
    if len(key) != 16:
        raise CalcError("SM4 key must be 16 bytes, got %d" % len(key))
    k = [a ^ b for a, b in zip(struct.unpack(">4I", key), fk)]
    rk = []
    for i in range(32):
        t = _tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck[i], sb)
        k.append(k[i] ^ t ^ _rl(t, 13) ^ _rl(t, 23))
        rk.append(k[-1])
    return rk


def _sm4_block(rk, blk, sb):
    x = list(struct.unpack(">4I", blk))
    for i in range(32):
        t = _tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i], sb)
        x.append(x[i] ^ t ^ _rl(t, 2) ^ _rl(t, 10) ^ _rl(t, 18) ^ _rl(t, 24))
    return struct.pack(">4I", x[35], x[34], x[33], x[32])


def _sm4(key, data, sbox, FK, CK, decrypt):
    from .hashes import _table
    sb = _sbox_arg(sbox, SM4_SBOX)
    rk = _sm4_keys(key, sb, _table("FK", SM4_FK, FK, 32), _table("CK", SM4_CK, CK, 32))
    if decrypt:
        rk = rk[::-1]
    data = _blocks(data, 16)
    return b"".join(_sm4_block(rk, data[i:i + 16], sb) for i in range(0, len(data), 16))


def sm4_enc(key, data, sbox=None, FK=None, CK=None):
    return _sm4(key, data, sbox, FK, CK, False)


def sm4_dec(key, data, sbox=None, FK=None, CK=None):
    return _sm4(key, data, sbox, FK, CK, True)


# ---- TEA family ------------------------------------------------------------

def _words(v, n, what, order):
    """bytes (with an explicit byte order) or a list of n-or-more 32-bit words."""
    if isinstance(v, bytes):
        if order not in ("little", "big"):
            raise CalcError("%s is bytes, so the word byte order is needed" % what,
                            "pass order='little' or order='big' (how the program loads its 32-bit words)")
        if len(v) % 4:
            raise CalcError("%s is %d bytes, not a multiple of 4" % (what, len(v)))
        fmt = ("<" if order == "little" else ">") + "%dI" % (len(v) // 4)
        w = list(struct.unpack(fmt, v))
    elif isinstance(v, (list, tuple)):
        w = list(v)
        if not all(isinstance(x, int) and 0 <= x <= M32 for x in w):
            raise CalcError("%s words must be integers 0..0xffffffff" % what)
    else:
        raise CalcError("%s must be bytes or a list of 32-bit words" % what)
    if n is not None and len(w) != n:
        raise CalcError("%s must be %d words (%d bytes), got %d words" % (what, n, 4 * n, len(w)))
    return w


def _tea_like(key, data, order, rounds, delta, step):
    k = _words(key, 4, "key", order)
    as_bytes = isinstance(data, bytes)
    v = _words(data, None, "data", order)
    if len(v) % 2:
        raise CalcError("TEA data must be whole 8-byte blocks (an even number of words)")
    if not isinstance(rounds, int) or not 1 <= rounds <= 1024:
        raise CalcError("rounds must be 1..1024")
    out = []
    for i in range(0, len(v), 2):
        out += step(v[i], v[i + 1], k, rounds, delta & M32)
    if as_bytes:
        return struct.pack(("<" if order == "little" else ">") + "%dI" % len(out), *out)
    return out


def _tea_e(v0, v1, k, rounds, delta):
    s = 0
    for _ in range(rounds):
        s = (s + delta) & M32
        v0 = (v0 + ((((v1 << 4) + k[0]) & M32) ^ ((v1 + s) & M32) ^ (((v1 >> 5) + k[1]) & M32))) & M32
        v1 = (v1 + ((((v0 << 4) + k[2]) & M32) ^ ((v0 + s) & M32) ^ (((v0 >> 5) + k[3]) & M32))) & M32
    return [v0, v1]


def _tea_d(v0, v1, k, rounds, delta):
    s = (delta * rounds) & M32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) + k[2]) & M32) ^ ((v0 + s) & M32) ^ (((v0 >> 5) + k[3]) & M32))) & M32
        v0 = (v0 - ((((v1 << 4) + k[0]) & M32) ^ ((v1 + s) & M32) ^ (((v1 >> 5) + k[1]) & M32))) & M32
        s = (s - delta) & M32
    return [v0, v1]


def _xtea_e(v0, v1, k, rounds, delta):
    s = 0
    for _ in range(rounds):
        v0 = (v0 + (((((v1 << 4) & M32) ^ (v1 >> 5)) + v1) & M32 ^ ((s + k[s & 3]) & M32))) & M32
        s = (s + delta) & M32
        v1 = (v1 + (((((v0 << 4) & M32) ^ (v0 >> 5)) + v0) & M32 ^ ((s + k[(s >> 11) & 3]) & M32))) & M32
    return [v0, v1]


def _xtea_d(v0, v1, k, rounds, delta):
    s = (delta * rounds) & M32
    for _ in range(rounds):
        v1 = (v1 - (((((v0 << 4) & M32) ^ (v0 >> 5)) + v0) & M32 ^ ((s + k[(s >> 11) & 3]) & M32))) & M32
        s = (s - delta) & M32
        v0 = (v0 - (((((v1 << 4) & M32) ^ (v1 >> 5)) + v1) & M32 ^ ((s + k[s & 3]) & M32))) & M32
    return [v0, v1]


def tea_enc(key, data, order=None, rounds=32, delta=0x9E3779B9):
    return _tea_like(key, data, order, rounds, delta, _tea_e)


def tea_dec(key, data, order=None, rounds=32, delta=0x9E3779B9):
    return _tea_like(key, data, order, rounds, delta, _tea_d)


def xtea_enc(key, data, order=None, rounds=32, delta=0x9E3779B9):
    return _tea_like(key, data, order, rounds, delta, _xtea_e)


def xtea_dec(key, data, order=None, rounds=32, delta=0x9E3779B9):
    return _tea_like(key, data, order, rounds, delta, _xtea_d)


def _xxtea(key, data, order, delta, decrypt):
    k = _words(key, 4, "key", order)
    as_bytes = isinstance(data, bytes)
    v = _words(data, None, "data", order)
    n = len(v)
    if n < 2:
        raise CalcError("XXTEA needs at least 2 words (8 bytes)")
    delta &= M32
    rounds = 6 + 52 // n

    def mx(s, y, z, p, e):
        return ((((z >> 5) ^ ((y << 2) & M32)) + ((y >> 3) ^ ((z << 4) & M32))) & M32) ^ \
            (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & M32)

    if not decrypt:
        s, z = 0, v[n - 1]
        for _ in range(rounds):
            s = (s + delta) & M32
            e = (s >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                v[p] = (v[p] + mx(s, y, z, p, e)) & M32
                z = v[p]
    else:
        s, y = (rounds * delta) & M32, v[0]
        for _ in range(rounds):
            e = (s >> 2) & 3
            for p in range(n - 1, -1, -1):
                z = v[p - 1] if p > 0 else v[n - 1]
                v[p] = (v[p] - mx(s, y, z, p, e)) & M32
                y = v[p]
            s = (s - delta) & M32
    if as_bytes:
        return struct.pack(("<" if order == "little" else ">") + "%dI" % n, *v)
    return v


def xxtea_enc(key, data, order=None, delta=0x9E3779B9):
    return _xxtea(key, data, order, delta, False)


def xxtea_dec(key, data, order=None, delta=0x9E3779B9):
    return _xxtea(key, data, order, delta, True)


# ---- modes and padding -------------------------------------------------

def _cipher(name, key, decrypt, kw):
    """Return (block_size, block function) for a named block cipher."""
    if not isinstance(name, str):
        raise CalcError("cipher must be a name: 'aes', 'sm4', 'tea' or 'xtea'")
    n = name.lower()
    if n == "aes":
        if set(kw) - {"sbox"}:
            raise CalcError("unknown option(s) for aes: %s" % ", ".join(sorted(set(kw) - {"sbox"})),
                            "aes takes sbox")
        sb = _sbox_arg(kw.get("sbox"), AES_SBOX)
        rk, nr = _aes_expand(key, sb)
        if decrypt:
            isb = _inv(sb)
            return 16, lambda b: _aes_block_dec(rk, nr, b, isb)
        return 16, lambda b: _aes_block_enc(rk, nr, b, sb)
    if n == "sm4":
        from .hashes import _table
        bad = set(kw) - {"sbox", "FK", "CK"}
        if bad:
            raise CalcError("unknown option(s) for sm4: %s" % ", ".join(sorted(bad)), "sm4 takes sbox, FK, CK")
        sb = _sbox_arg(kw.get("sbox"), SM4_SBOX)
        rk = _sm4_keys(key, sb, _table("FK", SM4_FK, kw.get("FK"), 32), _table("CK", SM4_CK, kw.get("CK"), 32))
        if decrypt:
            rk = rk[::-1]
        return 16, lambda b: _sm4_block(rk, b, sb)
    if n in ("tea", "xtea"):
        if "order" not in kw:
            raise CalcError("%s in a mode needs order='little' or order='big'" % n,
                            "the byte order the program uses to load its 32-bit words")
        f = {"tea": (tea_enc, tea_dec), "xtea": (xtea_enc, xtea_dec)}[n][decrypt]
        return 8, lambda b: f(key, b, **kw)
    raise CalcError("unknown cipher %s" % short(name), "one of: aes, sm4, tea, xtea")


def ecb_enc(cipher, key, data, **kw):
    size, f = _cipher(cipher, key, False, kw)
    data = _blocks(data, size)
    return b"".join(f(data[i:i + size]) for i in range(0, len(data), size))


def ecb_dec(cipher, key, data, **kw):
    size, f = _cipher(cipher, key, True, kw)
    data = _blocks(data, size)
    return b"".join(f(data[i:i + size]) for i in range(0, len(data), size))


def cbc_enc(cipher, key, iv, data, **kw):
    size, f = _cipher(cipher, key, False, kw)
    iv = _b(iv, "iv")
    if len(iv) != size:
        raise CalcError("iv must be %d bytes for %s, got %d" % (size, cipher, len(iv)))
    data = _blocks(data, size)
    out, prev = [], iv
    for i in range(0, len(data), size):
        prev = f(bytes(a ^ b for a, b in zip(data[i:i + size], prev)))
        out.append(prev)
    return b"".join(out)


def cbc_dec(cipher, key, iv, data, **kw):
    size, f = _cipher(cipher, key, True, kw)
    iv = _b(iv, "iv")
    if len(iv) != size:
        raise CalcError("iv must be %d bytes for %s, got %d" % (size, cipher, len(iv)))
    data = _blocks(data, size, "ciphertext")
    out, prev = [], iv
    for i in range(0, len(data), size):
        blk = data[i:i + size]
        out.append(bytes(a ^ b for a, b in zip(f(blk), prev)))
        prev = blk
    return b"".join(out)


def ctr(cipher, key, block0, data, ctr_len=None, ctr_pos=None, order="big", **kw):
    """Counter mode. block0 is the whole first counter block (nonce and counter
    together). The counter is the ctr_len bytes at ctr_pos (default: the whole
    block), incremented by one per block in the given byte order, wrapping
    within those bytes; the other bytes stay fixed. Same call encrypts and decrypts."""
    size, f = _cipher(cipher, key, False, kw)
    block0 = _b(block0, "block0")
    data = _b(data, "data")
    if len(block0) != size:
        raise CalcError("block0 must be the full %d-byte first counter block, got %d bytes" % (size, len(block0)),
                        "for a 12-byte nonce and 32-bit big-endian counter starting at 1: "
                        "block0 = nonce + p32be(1), ctr_len=4")
    if ctr_len is None:
        ctr_len = size
    if not isinstance(ctr_len, int) or not 1 <= ctr_len <= size:
        raise CalcError("ctr_len must be 1..%d" % size)
    if ctr_pos is None:
        ctr_pos = size - ctr_len
    if not isinstance(ctr_pos, int) or not 0 <= ctr_pos <= size - ctr_len:
        raise CalcError("ctr_pos must be 0..%d for ctr_len=%d" % (size - ctr_len, ctr_len))
    if order not in ("big", "little"):
        raise CalcError("order must be 'big' or 'little'")
    head, tail = block0[:ctr_pos], block0[ctr_pos + ctr_len:]
    c = int.from_bytes(block0[ctr_pos:ctr_pos + ctr_len], order)
    mod = 1 << (8 * ctr_len)
    out = bytearray()
    for i in range(0, len(data), size):
        ks = f(head + ((c + i // size) % mod).to_bytes(ctr_len, order) + tail)
        out += bytes(a ^ b for a, b in zip(data[i:i + size], ks))
    return bytes(out)


def pkcs7_pad(data, block=16):
    data = _b(data, "data")
    if not isinstance(block, int) or not 1 <= block <= 255:
        raise CalcError("block must be 1..255")
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data, block=16):
    data = _b(data, "data")
    if not data or len(data) % block:
        raise CalcError("PKCS#7 data must be a non-empty multiple of %d bytes, got %d" % (block, len(data)))
    n = data[-1]
    if not 1 <= n <= block or data[-n:] != bytes([n]) * n:
        raise CalcError("bad PKCS#7 padding: last bytes are %s" % data[-min(len(data), block):].hex(),
                        "wrong key/IV/mode, or the plaintext is not PKCS#7 padded (try zero padding)")
    return data[:-n]


# ---- stream ciphers --------------------------------------------------------

def rc4(key, data, drop=0):
    key, data = _b(key, "key"), _b(data, "data")
    if not 1 <= len(key) <= 256:
        raise CalcError("RC4 key must be 1..256 bytes")
    if not isinstance(drop, int) or not 0 <= drop <= 1 << 20:
        raise CalcError("drop must be 0..1048576")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for n in range(drop + len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        if n >= drop:
            out.append(data[n - drop] ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


SIGMA = b"expand 32-byte k"


def chacha20_block(key, counter, nonce, rounds=20, sigma=None):
    """One 64-byte ChaCha block. nonce 12 bytes (RFC 8439, 32-bit counter) or
    8 bytes (original, 64-bit counter)."""
    key, nonce = _b(key, "key"), _b(nonce, "nonce")
    if len(key) != 32:
        raise CalcError("ChaCha20 key must be 32 bytes, got %d" % len(key))
    sigma = SIGMA if sigma is None else _b(sigma, "sigma")
    if len(sigma) != 16:
        raise CalcError("sigma must be 16 bytes")
    if not isinstance(rounds, int) or rounds < 2 or rounds % 2 or rounds > 64:
        raise CalcError("rounds must be even, 2..64")
    if len(nonce) == 12:
        if not 0 <= counter <= M32:
            raise CalcError("counter must fit 32 bits with a 12-byte nonce")
        tail = struct.pack("<I", counter) + nonce
    elif len(nonce) == 8:
        if not 0 <= counter < 1 << 64:
            raise CalcError("counter must fit 64 bits with an 8-byte nonce")
        tail = struct.pack("<Q", counter) + nonce
    else:
        raise CalcError("nonce must be 12 bytes (RFC 8439) or 8 bytes (original), got %d" % len(nonce))
    st = list(struct.unpack("<16I", sigma + key + tail))
    x = list(st)

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & M32
        x[d] = _rl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & M32
        x[b] = _rl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & M32
        x[d] = _rl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & M32
        x[b] = _rl(x[b] ^ x[c], 7)

    for _ in range(rounds // 2):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)  # noqa: E702
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)  # noqa: E702
    return struct.pack("<16I", *[(a + b) & M32 for a, b in zip(x, st)])


def chacha20(key, nonce, data, counter=0, rounds=20, sigma=None):
    data = _b(data, "data")
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce, rounds, sigma)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)
