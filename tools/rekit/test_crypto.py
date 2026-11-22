#!/usr/bin/env python3
"""Tests for _crypto.py's IDA-independent core. Run: python3 test_crypto.py"""

import json
import random
import struct
import sys
import time

import _crypto as c

REFS = json.load(open(c.REFS_PATH))
T = {t["id"]: t["values"] for t in REFS["tables"]}
B = {b["id"]: int(b["value"], 16) for b in REFS["bignums"]}
A = {a["id"]: a["text"] for a in REFS["alphabets"]}
K = T["sha256_k"]
RNG = random.Random(1)


def rnd(n):
    return RNG.randbytes(n)


def words(vals, fmt):
    return b"".join(struct.pack(fmt, v) for v in vals)


def only(hits, ref=None):
    return [h for h in hits if ref is None or h["ref"] == ref]


def run():
    bad = []

    def expect(label, cond):
        if not cond:
            bad.append(label)

    # ------------------------------------------------------------ reference data
    expect("SHA-256 K[0]", K[0] == 0x428A2F98 and K[13] == 0x80DEB1FE and len(K) == 64)
    expect("checks recorded", len(REFS["checks"]) > 40)
    expect("coverage", all(k in T for k in ("sha512_k", "md5_t", "sm3_iv", "sm4_sbox", "sm4_fk", "sm4_ck",
                                             "aes_te0", "aes_td3", "des_s1", "bf_p", "crc32c_tab_n",
                                             "chacha_sigma_w", "sha1_iv", "sha384_iv"))
           and all(k in B for k in ("sm2_p", "p256_gy", "secp256k1_n", "curve25519_gy")))

    # ------------------------------------------------------------ exact, each form
    pad = rnd(100)
    cases = [
        ("sha256_k", "u32le", words(K, "<I")),
        ("sha256_k", "u32be", words(K, ">I")),
        ("sha512_k", "u64le", words(T["sha512_k"], "<Q")),
        ("sha512_k", "u64be", words(T["sha512_k"], ">Q")),
        ("sha512_k", "u64hi.lo", b"".join(struct.pack("<II", v >> 32, v & 0xFFFFFFFF) for v in T["sha512_k"])),
        ("aes_sbox", "bytes", bytes(T["aes_sbox"])),
        ("sm4_sbox", "bytes>u32", words(T["sm4_sbox"], "<I")),
        ("crc32_tab_r", "u32le", words(T["crc32_tab_r"], "<I")),
        ("sm4_fk", "u32le", words(T["sm4_fk"], "<I")),
        ("sm2_n", "be", B["sm2_n"].to_bytes(32, "big")),
        ("sm2_n", "le", B["sm2_n"].to_bytes(32, "little")),
        ("sm2_gx", "u32msl", words(struct.unpack(">8I", B["sm2_gx"].to_bytes(32, "big")), "<I")),
        ("p256_gy", "u64msl", words(struct.unpack(">4Q", B["p256_gy"].to_bytes(32, "big")), "<Q")),
        ("sm2_p", "be", B["sm2_p"].to_bytes(32, "big")),          # low entropy: exact search
        ("chacha_sigma_w", "u32le", b"expand 32-byte k"),
        ("sm2_default_id", "bytes", b"1234567812345678"),
    ]
    for ref, form, blob in cases:
        hits = c.scan_bytes(pad + blob + pad, 0x1000)
        h = [x for x in hits if x["ref"] == ref]
        expect("exact %s %s" % (ref, form),
               len(h) == 1 and h[0]["form"] == form and h[0]["status"] == "exact"
               and h[0]["addr"] == 0x1000 + len(pad))
    # unaligned placement still found
    h = only(c.scan_bytes(rnd(3) + words(K, "<I") + rnd(5)), "sha256_k")
    expect("unaligned", len(h) == 1 and h[0]["addr"] == 3 and h[0]["status"] == "exact")
    # MD5 init sits inside SHA-1 IV: one hit, folded
    h = c.scan_bytes(pad + words(T["sha1_iv"], "<I") + pad)
    expect("SHA-1 IV folds MD5 init", len(h) == 1 and h[0]["ref"] == "sha1_iv"
           and h[0].get("contains") == ["MD5 init"])

    # ------------------------------------------------------------ one altered constant
    k2 = list(K)
    k2[13] = 0x80DEB5FE
    for fmt, form in (("<I", "u32le"), (">I", "u32be")):
        h = only(c.scan_bytes(pad + words(k2, fmt) + pad, 0x400000), "sha256_k")
        expect("near %s" % form, len(h) == 1 and h[0]["status"] == "near" and h[0]["match"] == "63 of 64"
               and h[0]["diff"] == [{"i": 13, "found": 0x80DEB5FE, "std": 0x80DEB1FE}])
    r = c.render_data_hit(h[0])
    expect("rendered diff", r["diff"] == ["[13] 0x80deb5fe, standard 0x80deb1fe (1 hex digit)"])
    # two altered S-box bytes
    sb = bytearray(T["sm4_sbox"])
    sb[7] ^= 1
    sb[200] ^= 0x80
    h = only(c.scan_bytes(pad + bytes(sb) + pad), "sm4_sbox")
    expect("near S-box", len(h) == 1 and h[0]["status"] == "near" and [d["i"] for d in h[0]["diff"]] == [7, 200])
    # a bignum with one digit changed
    n = bytearray(B["sm2_n"].to_bytes(32, "big"))
    n[20] ^= 0x10
    h = only(c.scan_bytes(pad + bytes(n) + pad), "sm2_n")
    expect("near bignum", len(h) == 1 and h[0]["status"] == "near" and h[0]["found_value"] == bytes(n).hex())
    # too many changes: not called a match
    k3 = list(K)
    for i in range(0, 64, 3):
        k3[i] ^= 0x01000000
    expect("weak not near", only(c.scan_bytes(pad + words(k3, "<I") + pad), "sha256_k") == [])

    # ------------------------------------------------------------ truncated table
    h = only(c.scan_bytes(pad + words(T["md5_t"][:20], "<I") + rnd(200)), "md5_t")
    expect("partial", len(h) == 1 and h[0]["status"] == "partial" and h[0]["match"] == "entries 0-19 of 64")
    h = only(c.scan_bytes(pad + words(T["aes_te0"][:200], "<I")), "aes_te0")     # cut by buffer end
    expect("partial at end", len(h) == 1 and h[0]["status"] == "partial" and h[0]["hi"] == 200)
    h = only(c.scan_bytes(pad + words(T["md5_t"][:5], "<I") + pad), "md5_t")
    expect("5 words too short", h == [])

    # ------------------------------------------------------------ immediates
    imms = [(v, 0x401000 + 8 * i) for i, v in enumerate(k2) if i not in (20, 21, 30, 40, 50, 60)]
    funcs = {
        "sha_fn": imms + [(0xFFFFFFFF, 0x402000)],
        "tea_fn": [(0x61C88647, 0x403000), (0x10, 0x403004)],                 # sum -= -delta
        "fnv_fn": [(0x811C9DC5, 0x404000), (0x01000193, 0x404008)],
        "noise_fn": [(0xFFFFFFFF, 0x405000), (0x80000000, 0x405004), (0x12345678, 0x405008)],
        "fk_fn": [(0xA0000000, 0x406000), (0x03B1BAC6, 0x406004),            # FK0 = a + b
                  (0x50000000, 0x406008), (0x06AA3350, 0x40600C)],           # FK1 = a + b
        "md5_fn": [(T["md5_init"][i], 0x407000 + i) for i in range(4)],
    }
    tabs, scal = c.match_immediates(funcs)
    sha = [t for t in tabs if t["fn"] == "sha_fn" and t["ref"] == "sha256_k"]
    expect("imm sha found", len(sha) == 1 and len(sha[0]["found"]) == 57)
    expect("imm sha missing", sha and sha[0]["missing"] == [13, 20, 21, 30, 40, 50, 60])
    expect("imm near miss", sha and [(d["i"], d["found"], d["nibbles"]) for d in sha[0]["near"]]
           == [(13, 0x80DEB5FE, 1)])
    r = c.render_imm_hit(sha[0])
    expect("imm render", r["match"] == "57 of 64" and r["missing"] == "13,20-21,30,40,50,60"
           and "0x80deb5fe" in r["near"][0] and "[13] 0x80deb1fe" in r["near"][0])
    names = {(s["ref"], tuple(sorted(s["fns"]))) for s in scal}
    expect("tea negated", ("tea_delta", ("tea_fn",)) in names
           and [s for s in scal if s["ref"] == "tea_delta"][0]["how"] == ["negated"])
    expect("fnv scalars", ("fnv32_basis", ("fnv_fn",)) in names and ("fnv32_prime", ("fnv_fn",)) in names)
    expect("noise fn silent", not [t for t in tabs if t["fn"] == "noise_fn"]
           and not [s for s in scal if "noise_fn" in s["fns"]])
    fk = [t for t in tabs if t["fn"] == "fk_fn" and t["ref"] == "sm4_fk"]
    expect("fk addends", len(fk) == 1 and sorted(fk[0]["paired"]) == [0, 1])
    md = [t for t in tabs if t["fn"] == "md5_fn"]
    expect("md5 init imm", len(md) == 1 and md[0]["ref"] == "md5_init"
           and len(md[0]["found"]) == 4)
    expect("no stray tables", {t["fn"] for t in tabs} <= {"sha_fn", "fk_fn", "md5_fn"})

    # ------------------------------------------------------------ two arrays combined
    fk = T["sm4_fk"]
    a_part = [RNG.getrandbits(32) for _ in fk]
    b_part = [(v - x) & 0xFFFFFFFF for v, x in zip(fk, a_part)]
    arrays = {0x5000: words(a_part, "<I") + rnd(32), 0x5010: words(b_part, "<I") + rnd(16),
              0x6000: words(K[:8], "<I"), 0x7000: rnd(64)}
    m = c.match_combined(arrays)
    expect("FK as two addends", [(x["ref"], x["a"], x["b"], x["op"], x["lo"], x["hi"]) for x in m]
           == [("sm4_fk", 0x5000, 0x5010, "+", 0, 4)])
    xa = [RNG.getrandbits(32) for _ in range(16)]
    m = c.match_combined({0x100: words([v ^ x for v, x in zip(K[8:24], xa)], "<I"), 0x200: words(xa, "<I")})
    expect("xor halves", len(m) == 1 and m[0]["op"] == "^" and (m[0]["lo"], m[0]["hi"]) == (8, 24))
    expect("random arrays combine to nothing",
           c.match_combined({i * 0x100: rnd(256) for i in range(12)}) == [])

    # ------------------------------------------------------------ callee walk
    graph = {"top": ["mid", "imp"], "mid": ["leaf", "top"], "leaf": ["deep"], "deep": ["deeper"],
             "imp": [], "deeper": []}
    order, capped = c.walk_callees("top", lambda f: graph[f], depth=3, cap=40)
    expect("walk depth 3", order == [("top", None), ("mid", "top"), ("imp", "top"), ("leaf", "mid"),
                                     ("deep", "leaf")] and not capped)
    order, capped = c.walk_callees("top", lambda f: graph[f], depth=3, cap=3)
    expect("walk cap", [f for f, _ in order] == ["top", "mid", "imp"] and capped)

    # ------------------------------------------------------------ alphabets
    alpha = list(A["base64"])
    RNG.shuffle(alpha)
    custom = "".join(alpha)
    buf = b"\0" * 10 + custom.encode() + b"\0" + A["base64"].encode() + b"\0hello world\0"
    h = c.scan_alphabets(buf, 0x2000)
    expect("custom base64", len(h) == 2 and h[0]["status"] == "permutation" and h[0]["text"] == custom
           and h[0]["addr"] == 0x200A)
    expect("standard base64", h[1:] and h[1]["status"] == "exact" and h[1]["text"] == A["base64"])
    h = c.scan_alphabets(b"x" + A["base32"].encode() + b"\0")
    expect("base32", len(h) == 1 and h[0]["status"] == "exact" and h[0]["name"] == "base32 alphabet")
    text = (b"The quick brown fox jumps over the lazy dog 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ "
            b"abcdefghijklmnopqrstuvwxyz" * 4)
    expect("plain text is no alphabet", c.scan_alphabets(text) == [])

    # ------------------------------------------------------------ noise
    noise = b"".join([
        bytes(4096), b"\xff" * 4096, bytes(range(256)) * 16, bytes(i & 15 for i in range(4096)),
        words(range(1024), "<I"), words([1 << (i % 32) for i in range(512)], "<I"),
        b"\x01\x02\x04\x08\x10\x20\x40\x80" * 64, text * 10, b"0123456789" * 50,
        words([0x01010101 * (i & 255) for i in range(512)], "<I"),
        words([i * 0x10001 for i in range(512)], "<I"),
    ])
    hits = c.scan_bytes(noise) + c.scan_alphabets(noise)
    expect("noise silent (%s)" % [h["name"] for h in hits][:5], hits == [])

    # ------------------------------------------------------------ speed on random data
    big = bytearray(rnd(4 << 20))
    plant = 3 << 20
    big[plant:plant + 256] = bytes(T["aes_inv_sbox"])
    t0 = time.time()
    hits = c.scan_bytes(bytes(big), 0x10000000) + c.scan_alphabets(bytes(big))
    dt = time.time() - t0
    expect("random: only the planted table (%s)" % [h["name"] for h in hits][:5],
           [(h["ref"], h["addr"]) for h in hits] == [("aes_inv_sbox", 0x10000000 + plant)])
    expect("random 4 MB in %.2fs" % dt, dt < 4.0)
    print("4 MB random scan: %.2fs" % dt)

    return bad


if __name__ == "__main__":
    t0 = time.time()
    c.db()
    failed = run()
    for f in failed:
        print("FAIL", f)
    n = open(__file__).read().count('expect("')
    print("%d checks, %d failed, %.1fs" % (n, len(failed), time.time() - t0))
    sys.exit(1 if failed else 0)
