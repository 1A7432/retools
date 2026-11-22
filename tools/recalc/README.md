# recalc

A restricted calculator for checking arithmetic and cryptographic hypotheses
while reverse engineering. It evaluates a few lines of a small Python subset
over integers and byte strings, with reference implementations of common
primitives to compare against, and returns one compact JSON object.

It exists so that a worker model can recompute what it claims: "is this
`rotl(x, 4)` or `x + 4`", "does this key and mode decrypt that buffer", "is this
SHA-256 with one constant changed". It answers in the same request.

**What it is not.** It cannot run arbitrary Python. There are no imports, no
files, no network, no processes, no classes, no lambdas, no attribute access
except a fixed table of methods, and no way to reach a Python object, type,
function or module. The code is interpreted by recalc's own tree walker over
the parsed syntax tree; it is never passed to `eval`, `exec` or `compile`.

## Running it

    recalc                       # request JSON on stdin, one JSON reply line on stdout
    recalc functions [--json]    # the function and method tables

`recalc` is a `/bin/sh` script that runs `.venv/bin/python -I -S
src/recalc_main.py` by absolute path under `/usr/bin/env -i` (empty
environment). It looks nothing up on PATH, so it works from IDA's worker. The
tool itself uses the standard library only; the virtualenv exists for the test
dependencies (`cryptography`, `pycryptodome`, `gmssl`, `pytest`). The exit code
is 0 whenever a JSON reply was written, including error replies.

Set-up (once, from this directory): `~/.local/bin/uv sync`. Tests: `uv run pytest`.

From IDA, `rekit/_calc.py` wraps it: `run(code, timeout=10, max_chars=4000)`
returns the reply dict and turns failures of the tool itself (missing, killed,
timed out, unreadable output) into `{"error", "hint"}`. It never raises.

Start-up is about 40 ms. Interpretation runs at roughly 5 million steps per
second; pure-Python SHA-256 or AES over 64 KB takes about 60 ms.

## Request

| key | meaning |
|---|---|
| `code` | the program text (required, at most 20 000 characters) |
| `timeout` | wall-clock seconds, default 10, clamped to 1..60 |
| `max_chars` | reply size budget, default 4000, clamped to 300..50 000 |
| `id` | echoed back (a short string or integer) |

Unknown keys are refused with the list of valid ones. The request itself may be
at most 256 KB.

## Reply

    {"steps": 11, "ms": 0, "result": "0x8e42a = 582698", "vars": {"x": 5}}

| key | meaning |
|---|---|
| `result` | value of the last line, present only when the last line is an expression |
| `vars` | every top-level name the code assigned (loop variables included) |
| `printed` | lines added by `print(...)` (at most 200; `print_dropped` counts the rest) |
| `steps`, `ms` | work done and time taken |
| `truncated` | present when anything was shortened; says what |

Errors:

    {"error": "unknown function 'rotll'", "hint": "did you mean: rotl, rotr?",
     "line": 2, "at": "y = rotll(x, 3)", "note": "...", "vars": {"x": 1}}

`line` and `at` give the offending line. `vars` and `printed` show the state
when the error happened. A limit error always starts with
`limit '<name>' exceeded:` so it can be told apart from a mistake in the code.

### How values are shown

Values are rendered for a reader who must copy them exactly:

| value | rendering |
|---|---|
| int, \|x\| < 10 | a JSON number: `5` |
| int up to 64 bits | `"0x8e42a = 582698"` (hex, then decimal) |
| larger int | `"0x..."` (hex only; very long ones are cut, with the bit count) |
| int inside a container of more than 16 items | `"0x..."` (hex only) |
| bytes | `{"bytes": 3, "hex": "616263", "ascii": "abc"}`; `ascii` only when every byte is printable |
| str | the string |
| list | a JSON array |
| tuple | `{"tuple": [...]}` |
| dict | `{"dict": [[key, value], ...]}` |
| range | `"range(0, 10, 1)"` |
| True/False/None | `true`/`false`/`null` |

Long values are cut in the middle only, with an explicit marker giving the
amount cut and the total: `"00010203...[cut 4992 of 5120 bytes]...f8f9fafbfcfdfeff"`,
`"...[cut 984 of 1000 items]..."`, `"...[cut 9880 of 10000 chars]..."`. When
the reply does not fit `max_chars`, values are shortened step by step (five
detail levels), then the largest variables are dropped, then printed lines,
then the result; `truncated` lists what happened, e.g.
`"values shortened (detail level 4 of 4); vars not shown: a, b"`. To see a cut
value in full, assign it and print slices of it.

## The language

A subset of Python 3 syntax with Python semantics, except where noted.

**Values**: `int` (arbitrary size up to the limit), `bool`, `bytes`, `str`,
`list`, `tuple`, `dict`, `None`, and `range` objects. No floats: `/` is refused
with a hint to use `//` or `divmod`.

**Literals**: integers in any base (`0x`, `0o`, `0b`, `_` separators), `b"..."`,
`"..."`, `[...]`, `(...)`, `{k: v}`, `True`, `False`, `None`.

**Statements**: assignment (`a = b = 1`, `a, b = b, a`, `x[i] = v`,
`x[i:j] = seq`, `d[k] = v`), augmented assignment (`+=`, `^=`, `<<=`, ... on
names and subscripts), `if`/`elif`/`else`, `for ... in ...` over lists, tuples,
ranges, bytes (giving ints), strings and dicts (giving keys), `while`, `break`,
`continue`, loop `else`, `pass`, `assert cond, "message"` (a failed comparison
shows both sides), and top-level `def` (see below).

**Expressions**: `+ - * // % ** << >> & | ^ ~`, unary `-`/`+`, comparisons
(chained, `in`, `not in`, `is`, `is not`), `and`/`or`/`not`, `a if c else b`,
indexing and slicing (negative indices, steps), list comprehensions (several
`for` and `if` clauses), dict comprehensions, generator expressions (evaluated
eagerly as lists, so `sum(x for x in xs)` works), and calls with positional and
keyword arguments.

`+` joins bytes, strings, lists and tuples of the same type. `^` on bytes is an
error that points to `xor(a, b)`. `%` on strings or bytes (formatting) is refused.

**Methods**: only these, called as `value.method(...)`:

- bytes: `hex`, `decode(encoding, errors)`, `find`, `rfind`, `index`, `count`,
  `startswith`, `endswith`, `split`, `strip`/`lstrip`/`rstrip`, `upper`, `lower`,
  `join`, `replace`, `ljust`, `rjust`, `isdigit`, `isalnum`, `isalpha`, `isascii`, `isspace`
- str: the same, with `encode(encoding, errors)` instead of `hex`/`decode`
- int: `to_bytes(length, byteorder, signed)`, `bit_length`, `bit_count`
- list: `append`, `extend`, `insert`, `pop`, `index`, `count`, `reverse`, `sort(reverse=)`, `copy`, `clear`
- tuple: `index`, `count`
- dict: `get`, `keys`, `values`, `items` (these three return lists), `pop`, `update`, `setdefault`, `copy`, `clear`
- static: `int.from_bytes(b, byteorder, signed)`, `bytes.fromhex(text)`

Encodings: utf-8, ascii, latin-1, utf-16(-le/-be), utf-32-le/-be, gbk, gb2312,
gb18030, cp936, big5, shift_jis, cp1252, cp437.

**def**: plain top-level functions with positional parameters and optional
defaults, called with positional or keyword arguments, `return` optional
(`None` otherwise). A function reads top-level names; names it assigns are
local (assigned at run time, so a name read before it is assigned falls back to
the top-level value rather than raising as Python would). No nested `def`, no
`*args`/`**kwargs`, no decorators, no recursion (direct or indirect: refused
with an error), at most 16 nested calls. Functions are not values: they cannot
be assigned, stored or passed.

**Names**: ASCII identifiers only (look-alike Unicode letters are refused
rather than normalised); nothing starting with `_`. A variable may shadow a
function name (`sum = 0` is allowed), but calling it then says so and suggests
renaming. An unknown name gets the closest matches as a hint.

**Left out**: floats, sets, classes, lambdas, `try`, `with`, `raise`, `del`,
`global`, imports, f-strings and all string formatting, `*`/`**` unpacking,
`:=`, generators, `match`, attribute reads, and all other Python built-ins
(`open`, `eval`, `getattr`, `type`, `map`, `iter`, `hash`, ...). Each of these
either reaches interpreter internals, has no bounded cost, or is not needed for
checking values; each is refused with a message naming the alternative.

## Limits

Enforced inside the evaluator, and again from outside:

| limit | value | name in the error |
|---|---|---|
| evaluation steps (one per syntax node, plus one per 16 elements of built-in arguments and of every sequence built) | 5 000 000 | `steps` |
| loop iterations in total (for, while, comprehensions) | 1 000 000 | `loop_iterations` |
| wall-clock time | `timeout`, default 10 s, at most 60 s | `time` |
| integer size | 65 536 bits | `int_bits` |
| length of any bytes, str, list, tuple or dict | 1 048 576 | `length` |
| modulus and exponent of `pow(b, e, m)` | 8 192 bits (about 0.8 s) | `powmod_bits` |
| elements visited when comparing or hashing nested containers | 1 000 000 | `structure` |
| container nesting for comparing or hashing | 64 | `nesting` |
| code nesting depth | 100 | `nesting` |
| code length | 20 000 characters | `code_length` |
| request size | 256 KB | `request_size` |
| nested user function calls | 16 (recursion refused) | `call_depth`, `recursion` |
| peak memory growth | 512 MB | `memory` |
| printed lines | 200 | (counted in `print_dropped`) |
| reply | `max_chars` | (`truncated`) |

Operations that can blow up are checked before they run: `**` and `pow`
without a modulus (estimated result size), `<<` (result bits), `*` on integers
(sum of bit lengths) and on sequences (result length), `+` on sequences,
`bytes(n)`, `to_bytes`, `ljust`/`rjust`, `join`, `replace`, `int(text)`,
`from_bytes`, `struct` formats, and anything that materialises a `range`
(`list`, `sorted`, `sum`, `zip`, ...). A `range` itself is lazy, so
`for i in range(10**18)` runs until the iteration limit (and `x in range(...)`
is False at once for a non-integer x instead of scanning). Comparisons, `in`,
dict keys, `sorted`/`min`/`max`/`index`/`count` first walk nested containers
with a bounded counter (one unit per element plus one per KB of text or
bytes), because CPython performs those in C, where the time limit cannot
interrupt them and where hashing a deeply nested tuple crashes the
interpreter. For the same reason `strip` takes at most 256 characters to
remove and `startswith`/`endswith` at most 64 alternatives. Error messages
never contain a full `repr` of a value, and are at most 400 characters.

From outside: the process runs with `python -I -S` and an empty environment;
stdin is replaced by `/dev/null` once the request is read; `SIGALRM` interrupts
long-running pure-Python built-ins at the timeout; and `setrlimit` sets CPU time
(timeout + 2 s), open files (3: no new file can be opened), processes (0: no
fork), file size (4 MB), core dumps (0), and address space and data size (2 GB,
which macOS does not enforce). The bridge kills the process 5 s after the
timeout and reports a CPU-limit kill as `limit 'cpu_time' exceeded`.

## Functions

The first argument of an elliptic-curve function is the curve: a name or a
parameter dict. Byte arguments must be `bytes`; passing a `str` is an error
with a hint (`b"..."`, `unhex("...")`, `s.encode()`).

### Integers and bits

| function | meaning |
|---|---|
| `rotl(x, n, width=32)`, `rotr(x, n, width=32)` | rotate within width bits (negative x as two's complement; x wider than width is an error) |
| `bswap(x, width=32)` | reverse byte order |
| `mask(width)` | `(1 << width) - 1` |
| `u8(x)` `u16(x)` `u32(x)` `u64(x)` | low bits, unsigned |
| `s8(x)` `s16(x)` `s32(x)` `s64(x)` | low bits read as signed |
| `unsigned(x, width)`, `signed(x, width)` | the same for any width |
| `pow(b, e, m=None)` | power; with m, modular (negative e: inverse power) |
| `inverse(a, m)`, `modinv(a, m)` | modular inverse, with the gcd in the error if there is none |
| `gcd(*xs)`, `lcm(*xs)`, `egcd(a, b)` | gcd, lcm, extended Euclid `(g, x, y)` |
| `crt(remainders, moduli)` | Chinese remainder theorem |
| `isqrt(x)`, `is_prime(n)` | integer square root; Miller-Rabin with 32 fixed bases |
| `popcount(x, width=None)`, `clz(x, width=32)`, `ctz(x, width=32)` | bit counts |
| `from_bytes(b, order='big', signed=False)` | bytes to int (`'little'`/`'le'`, `'big'`/`'be'`) |
| `to_bytes(x, n, order='big', signed=False)` | int to n bytes |
| `hex(x, bits=None)`, `bin(x, bits=None)` | text, optionally zero-padded to a bit width |
| `int(x, base)`, `abs(x)`, `divmod(a, b)` | as in Python (`int` takes text, not bytes) |

### Sequences

`len`, `range`, `sum` (integers only), `min`/`max` (sequence or arguments,
`default=`), `zip`, `enumerate`, `reversed`, `sorted(seq, reverse=False)`,
`list`, `tuple`, `dict`, `bool`, `any`, `all`, `chr`, `ord`, `str` (of int, bool,
None or str), `print(*values)`. `zip`, `enumerate` and `reversed` return lists.

### Bytes

| function | meaning |
|---|---|
| `bytes(n)`, `bytes(list)`, `bytes(text, encoding)` | construct |
| `unhex(text)` | hex to bytes, ignoring whitespace and a leading `0x` |
| `hexstr(b, sep='')` | bytes to hex |
| `xor(data, key)` | the key repeats over data; an int key is one byte; result has `len(data)` |
| `cat(*parts)` | concatenate bytes (lists of bytes are flattened) |
| `chunks(b, n)` | split into pieces of n |
| `u16le` `u16be` `u32le` `u32be` `u64le` `u64be` `(b)` | unpack bytes into a list of integers |
| `p16le` `p16be` `p32le` `p32be` `p64le` `p64be` `(xs)` | pack an int or a list of ints |
| `pack(fmt, *vals)`, `unpack(fmt, b)` | `struct` with integer and byte formats only |
| `b64enc(b, alphabet=None, pad=True)`, `b64dec(text, alphabet=None)` | base64; a custom alphabet is 64 characters plus an optional 65th pad character; decoding ignores whitespace and tolerates missing padding |

### Hashes (pure Python, constants overridable)

| function | meaning |
|---|---|
| `sha256(msg, K=None, IV=None)`, `sha224(...)` | `K`: 64 words or `{index: value}` patch; `IV`: 8 words or patch |
| `sha512(msg, K=None, IV=None)`, `sha384(...)` | `K`: 80 words or patch |
| `sha1(msg, K=None, IV=None)` | `K`: 4 words or patch; `IV`: 5 words |
| `md5(msg, K=None, IV=None)` | `K`: 64 sine constants or patch; `IV`: 4 words |
| `sm3(msg, IV=None, T=None)` | `T`: `[T0, T1]` or patch |
| `hmac(hash_name, key, msg, ipad=0x36, opad=0x5c, block=None)` | any hash above by name |
| `hash_consts(name)` | the standard tables, e.g. `hash_consts('sha256')['K']` |
| `hash_compress(name, state, block, K=None)` | one compression step without padding (md5, sha1, sha256, sha512, sm3) |
| `crc(data, width, poly, init=0, xorout=0, refin=False, refout=False)` | any CRC in the Rocksoft model, width 1..128 |
| `crc32(data)`, `adler32(data)` | zlib's |
| `fnv1a(data, width=32, prime=None, basis=None)`, `fnv1(...)` | 32 or 64 bit |

All return bytes except the CRC/Adler/FNV family (integers) and
`hash_compress` (a list of state words).

### Ciphers (pure Python)

| function | meaning |
|---|---|
| `aes_enc(key, data, sbox=None)`, `aes_dec(...)` | AES-128/192/256, one block or ECB over whole blocks; `sbox=` a modified S-box (inverse derived) |
| `sm4_enc(key, data, sbox=None, FK=None, CK=None)`, `sm4_dec(...)` | SM4 ECB |
| `ecb_enc(cipher, key, data, ...)`, `ecb_dec(...)` | ECB with `'aes'`, `'sm4'`, `'tea'`, `'xtea'` |
| `cbc_enc(cipher, key, iv, data, ...)`, `cbc_dec(...)` | CBC; no padding added or removed |
| `ctr(cipher, key, block0, data, ctr_len=None, ctr_pos=None, order='big', ...)` | CTR; `block0` is the whole first counter block; the counter is the `ctr_len` bytes at `ctr_pos` (default: the whole block), incremented per block in `order`, wrapping within those bytes; the same call decrypts |
| `pkcs7_pad(data, block=16)`, `pkcs7_unpad(data, block=16)` | with a clear error on bad padding |
| `rc4(key, data, drop=0)` | RC4, optionally dropping keystream bytes first |
| `chacha20_block(key, counter, nonce, rounds=20, sigma=None)` | one 64-byte block; nonce 12 bytes (RFC 8439, 32-bit counter) or 8 bytes (original, 64-bit counter) |
| `chacha20(key, nonce, data, counter=0, rounds=20, sigma=None)` | stream XOR |
| `tea_enc(key, data, order=None, rounds=32, delta=0x9e3779b9)`, `tea_dec`, `xtea_enc`, `xtea_dec` | key and data as lists of 32-bit words, or bytes with an explicit `order='little'`/`'big'` (refused without one) |
| `xxtea_enc(key, data, order=None, delta=0x9e3779b9)`, `xxtea_dec` | corrected block TEA over the whole buffer |

Examples: `ctr('aes', key, nonce12 + p32be(1), data, ctr_len=4)` (12-byte nonce,
32-bit big-endian counter from 1); `cbc_dec('xtea', key, iv8, ct, order='little')`.

### Elliptic curves and SM2

Points are tuples `(x, y)`; the point at infinity is `None`. Curves: `'sm2'`,
`'p256'` (also `'secp256r1'`, `'prime256v1'`), `'secp256k1'`, or a dict
`{p, a, b[, n, Gx, Gy]}` (p at most 1024 bits).

| function | meaning |
|---|---|
| `ec_curve(c)` | the parameters as a dict |
| `ec_on_curve(c, P)` | True/False |
| `ec_add(c, P, Q)`, `ec_neg(c, P)`, `ec_mul(c, k, P=None)` | arithmetic (`P` defaults to G); points off the curve are refused with a hint |
| `ec_decompress(c, x, parity)` | parity 0/1 or prefix byte 2/3 |
| `ec_decode(c, data)`, `ec_encode(c, P, compressed=False)` | `04‖x‖y`, `x‖y`, `02/03‖x` |
| `ec_affine(c, X, Y, Z, kind='jacobian')` | Jacobian (X/Z², Y/Z³) or `'projective'` (X/Z, Y/Z) to affine |
| `ecdsa_verify(c, P, e, r, s)`, `ecdsa_sign(c, d, e, k)` | e is the hash as bytes (truncated to the order) or an integer |
| `sm2_za(P, id=None, c='sm2')` | Z = SM3(ENTL‖ID‖a‖b‖Gx‖Gy‖Px‖Py), default ID `1234567812345678` |
| `sm2_kdf(z, klen)` | klen bytes, SM3 with a 32-bit big-endian counter from 1 |
| `sm2_verify(P, msg, r, s, id=None, hashed=False)` | e = SM3(Z‖msg); `hashed=True` passes e directly |
| `sm2_sign(d, msg, k, id=None, hashed=False)` | with a given nonce, for reproducing a signature |
| `sm2_encrypt(P, msg, k, mode='c1c3c2')`, `sm2_decrypt(d, ct, mode='c1c3c2')` | C1‖C3‖C2 or `'c1c2c3'`; C1 with or without the `04` prefix |

## Worked checks

These come from the benchmark that motivated the tool; each is also a test in
`tests/test_worked.py`.

**1. "rotate left by 4" is not "add 4".**

    right = pow(7, rotl(532, 4, 32) ^ 5, 1000003)
    wrong = pow(7, (532 + 4) ^ 5, 1000003)
    right, wrong, right == wrong

`right` is `"0x8e42a = 582698"`, the program's real output; `wrong` is a
different number, and the comparison is `false`.

**2. SHA-256 with one round constant changed.**

    std = sha256(b'abc')
    var = sha256(b'abc', K={13: 0x80deb5fe})
    back = sha256(b'abc', K={13: 0x80deb1fe})
    hexstr(var), var == std, back == std

The patched digest is
`fd38a6ec8ff25682e16393a73c017dd75caf0aff7a492a9f23f322a162b2089d` (standard:
`ba7816bf...f20015ad`); patching K[13] back to the standard `0x80deb1fe`
restores the standard digest. The test recomputes the patched value with an
independent FIPS 180-4 implementation.

**3. SM4-CBC decryption with PKCS#7 unpadding.**

    key = unhex('0123456789abcdeffedcba9876543210')
    iv = unhex('000102030405060708090a0b0c0d0e0f')
    ct = unhex('...')                     # produced by gmssl in the test
    pt = pkcs7_unpad(cbc_dec('sm4', key, iv, ct))
    again = cbc_enc('sm4', key, iv, pkcs7_pad(pt))
    pt, again == ct

`pt` comes back with its ASCII view (`"attack at dawn; bring snacks"`) and the
re-encryption equals the original ciphertext.

## How it is made safe

1. **Allow-listed syntax.** The code is parsed with `ast.parse` and every node
   is checked against an allow-list before anything runs; anything else is
   refused with a message. Identifiers must be ASCII and must not start with
   `_`; attribute syntax is only accepted as a call of a method name in the
   table.
2. **Closed value space.** Values are only int, bool, str, bytes, list, tuple,
   dict, None and range. Functions are looked up by name in a fixed table and
   methods by (type, name); the results of every built-in are checked to be of
   those types again. A Python object, function, type or module can never
   become a value, so there is nothing to walk from.
3. **Bounded work.** Every step is counted; everything that can grow a value is
   checked before it runs; C-level traversals of nested values are bounded
   first; time and memory are checked every 1024 steps; `SIGALRM` interrupts
   long pure-Python built-ins; process limits back everything up.

## Tests

`uv run pytest` (about 11 s): reference implementations against `hashlib`,
`hmac`, `zlib`, `cryptography`, `pycryptodome`, `gmssl`, published vectors
(FIPS 197, FIPS 180-4, GB/T 32905 and 32907, RFC 8439, RFC 6229, the CRC
catalogue, the FNV test suite) and, for TEA/XTEA/XXTEA, the reference C code
compiled at test time; every override path (patch changes the output, patching
back restores it); the language; rendering and the `max_chars` budget; the
launcher; the rekit bridge; breakout and resource-exhaustion attempts
(`tests/test_security.py`, including regressions for the findings of an
independent adversarial review: lone surrogates in output, `in` on a huge
range, O(n·m) string operations, unbounded error messages, unaccounted bulk
growth, slices leaking into values); and a fuzz run of random token sequences and
mutated programs that must only ever produce a result or a clean error.
