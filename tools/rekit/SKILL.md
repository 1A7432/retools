---
name: rekit
description: Compact, read-only views of an IDA database through ida-mcp execute_python. Use whenever you inspect a binary in IDA (decompile a function, list callers or callees, follow xrefs, search strings, names, bytes or constants, read disassembly) instead of hand-writing IDAPython for those lookups.
---

# rekit

`rekit` is a single Python module that runs inside the IDA worker behind the
ida-mcp `execute_python` tool. It answers the common reverse-engineering
lookups with small, predictable results, so you spend neither tokens on raw
dumps nor turns on guessing IDA API names.

Use it for every read-only lookup it covers. Write plain IDAPython only for
what it does not cover: renaming, commenting, applying types, patching, or
queries with no rekit call.

## Load it (once per database)

Globals persist across `execute_python` calls for the same database, so run
this once after `open_database`, and again for each further database you open:

```python
import os, sys
sys.path.insert(0, os.path.expanduser("~/.agents/skills/rekit"))
import rekit
rekit.help()
```

If `rekit` is reported as undefined later, the lease was renewed; run the
snippet again.

## Calls

End the snippet with the call so its dict becomes the tool result. Do not
`print` it.

| Call | Gives you |
|---|---|
| `rekit.info()` | file, architecture, function counts, segments |
| `rekit.fn(ea)` | function card: callers, callees, imports, strings, globals, notable constants, and trimmed pseudocode |
| `rekit.fn(ea, code="none")` | the card without code, about 1 KB; use it to triage |
| `rekit.code(ea, mode="trim", start=0)` | pseudocode only, paginated by line |
| `rekit.xrefs(ea, limit=20)` | references to a function or data address, grouped by referencing function |
| `rekit.calls(ea, depth=2, dir="out")` | call tree as indented text; `dir="in"` walks callers, and also lists functions that only take the address (`[addr X]`) and pointers stored in data (`[data]`) |
| `rekit.find(name=...)` | symbols by substring; imports first, then functions, then data |
| `rekit.find(string=...)` | strings by content, with the functions that use them |
| `rekit.find(bytes="FD 7B ?? A9")` | byte pattern with wildcards |
| `rekit.find(imm=0x9E3779B9)` | instructions using an immediate value |
| `rekit.disasm(ea, n=40)` | compact disassembly; continue from the returned `next` |
| `rekit.scan(ea)` | inside one function, or `[ea, end)` with `end=`: direct calls counted by target, plus the number of indirect calls |
| `rekit.scan(ea, show="imms", min=0x10000)` | the distinct immediates used there, with counts; `mnem=["MOV", "EOR"]` keeps only those instructions |
| `rekit.scan(ea, imm=0x5BD1E995)` | every use of one immediate there |
| `rekit.scan(ea, to="_syscall", reg="w0")` | every call site of one target, and the immediate moved into a register before each call |
| `rekit.decode(ea)` | strings the function builds at run time in its one-time initialisers, recovered by emulation |
| `rekit.batch([ea, ...])` | several cards in one call (at most 40) |
| `rekit.notes(ea)` | findings recorded earlier for this function, or for the whole database without `ea` |
| `rekit.emu(ea, args=[...], cc=...)` | run one function in an emulator: return value, buffers it changed, memory it wrote, API calls it made |
| `rekit.help("emu")` | the emulation request format |
| `rekit.run(args=[...], stdin=...)` | emulate the whole program on an input: exactly what it prints, how it exits |
| `rekit.crypto(ea=None, init=[...])` | known cryptographic tables, constants and curve parameters, and each place one differs from the standard |
| `rekit.calc("code")` | restricted scratchpad for arithmetic, hashes, ciphers and curve points; `rekit.help("calc")` lists its functions |

`find` takes exactly one criterion; add `regex=True` for a regular expression.
String search covers C strings, plus UTF-16 for Windows PE files; for other
formats pass `wide=True` to include UTF-16 (a miss tells you so). A pattern
with non-ASCII characters searches a separate, larger index built on first use.

## Code too big to decompile

A flattened or virtualised function of hundreds of thousands of instructions
cannot be decompiled, and a database-wide `find(imm=...)` runs out of time.
`rekit.scan` answers the questions that remain, limited to one function (all
its chunks) or to an address range with `end=`:

```python
rekit.scan("sub_1A2B3C0")                              # what it calls, by count
rekit.scan("sub_1A2B3C0", show="imms")                 # which constants it uses
rekit.scan("sub_1A2B3C0", imm=0x5BD1E995)              # where one constant is used
rekit.scan("sub_1A2B3C0", to="_syscall", reg="w0")     # which system calls it makes
```

The range is read once (a few seconds for 470,000 instructions) and kept for
later questions about the same range; `refresh=True` reads it again. Immediate
operands that IDA resolved to an address are not listed. A jump to the start
of another function counts as a call and is marked `tail`.

With `reg`, each site shows the immediate that the last write to that
register moved in, read backwards along the straight line into the call.
`values` is the distribution over all sites. A site shows `?` and the reason
when that write is not an immediate (`MOV X0, X19`), when a jump target
intervenes (another path may bring a different value) or when an earlier call
left its result there. Read those sites with `rekit.disasm`. It follows
registers only: arguments pushed on the stack (32-bit x86) are not found, and
on x86 a write to a sub-register (`al`) is not seen as a write to `eax`.

## Strings built at run time

Some strings are not in the file. The compiler splits a short literal into
integer constants, or an obfuscator stores it encrypted and decodes it on
first use; either way the code is a one-time initialiser guarded by a flag
byte: read the flag, skip if set, build the string, set the flag. A card finds
those initialisers (a writable byte the function both reads and writes),
emulates each one from the flag read to just after the flag write, and shows
what they wrote under `decoded`:

```
"decoded": {"total": 8, "top": [
    "0x81f2b4c \"FetchRemotePolicyForDevice\" | init 0x2f4dc4-0x2f4e38",
    "0x81f2a10 \"policy_manager.cc\" | init 0x2f50d8-0x2f5124 | loop"], ...}
```

The address is where the string is built, `init` is the code that builds it,
and `loop` means it was computed in a loop (an XOR decode, scalar or
vectorised) rather than stored piecewise. These strings come from running the
function's own code on the file's initial memory, so they are what the
program would have there; they are still not literals, so say "decoded" when
you quote one. `rekit.decode(ea)` lists all of them. `decode=False` on `fn`
and `batch` skips the emulation.

Related card fields:

- `consts` shows a constant's bytes as text when they are all printable
  (`0x6d65526863746546 "FetchRem"`). That is one fragment. Fragments are never
  joined by guesswork; the joined string is under `decoded` when the
  initialiser could be run.
- `strings` leaves out constant-pool entries that an initialiser reads a few
  bytes from and IDA mistook for a string; `decoded.replaces` counts them.
- `decoded.failed` counts initialisers that did not run to their end (they
  call into code that needs state the snapshot lacks); `decoded.unavailable`
  means emulation could not run at all. In both cases `strings` is unchanged.

Not covered: statics guarded by `__cxa_guard_acquire` (tried, and too few of
them run to the end to be worth showing), strings built on the stack with no
flag (only the `consts` fragments are marked), and decode routines that take
arguments: call those with `rekit.emu`.

## Emulation

`rekit.emu` answers "what does this function produce for this input" by
interpreting it in a separate process on a snapshot of the database. Nothing
runs natively and the database is not changed. Reach for it when a routine
decodes, hashes, formats or builds something and you would otherwise simulate
it by hand.

```python
rekit.emu(0x401000, args=[5, {"str": "abc"}, {"out": 64}])
rekit.emu("sub_434B9C", cc="delphi",
          args=[{"dstr": "MixedCase abc"}, {"out": 4, "name": "res"}],
          read=[{"addr": {"ref": "res"}, "deref": 1, "as": "dstr"}],
          replace={"0x407164": {"stub": "malloc", "cc": "delphi"}})
```

Read `stop.reason` first. `returned` means the function finished; anything else
says where and why it stopped, and is information rather than failure: an
`unmapped_read` inside a runtime allocator means the snapshot's memory manager
was never initialised, so replace that allocator with the `malloc` stub and run
again. Give the calling convention when it is not the platform default; Delphi
code (IDA shows `a1@<eax>, a2@<edx>, a3@<ecx>`) needs `cc="delphi"`. Imports
are modelled or logged, never executed: there is no file system, network,
threads or exception dispatch, so this suits single routines, not whole
programs. `rekit.help("emu")` lists every request key.

It emulates little-endian x86, x64 and arm64 code from PE, ELF and Mach-O
files; 32-bit ARM and MIPS are refused with an error. Functions in `replace`,
`func`, `start`, `until` and `init` may be given by name. In a statically linked ELF
the libc allocator ends in a raw system call, so a routine that allocates
stops with reason `syscall`: replace that `malloc` with the `malloc` stub, as
for Delphi.

Each run starts from the snapshot, so tables or keys the program builds at run
time (an S-box generated by a loop, a table decoded at start-up, a CRC table
filled on first use) are still zero, and a function that reads them returns
garbage that looks like a real answer. When a routine reads a global table, check
who writes it (`rekit.xrefs`); if that is a set-up call in `main` or an init
routine, run it first with `init=["sub_402000", ...]` rather than slicing `main`
with `start`/`until`. An entry can take arguments and name an output buffer
that later entries and the main call reference with `{"ref": name}`, which is
how a derived key is passed along. The reply's `init` lists each set-up call;
`stop.reason == "init_failed"` means one did not return and says why.

The first call on a database writes the snapshot (a fraction of a second for a
15 MB image); later calls take tens of milliseconds. Pass `refresh=True` after
the database bytes were patched.

## Whole-program run

`rekit.run(args=["hello"])` or `rekit.run(stdin="hello\n")` emulates the
database's input file from its entry point inside a no-network sandbox and
returns its output byte for byte, the exit code or stop reason, and the
highlights of what it did. Nothing executes natively. Use it for "what does
it print for this input", and to confirm an answer you derived (the accepted
password, the expected ciphertext) against the real program. It refuses to
run if the file on disk is not the one the database was made from. ELF
programs only for output and stdin: a Windows PE is emulated, but its console
output is not captured.

## Cryptographic constants

`rekit.crypto()` scans the database, `rekit.crypto(ea)` one function and what
it calls. It recognises the tables and constants of the common hashes,
ciphers, checksums and curves in the forms compilers and obfuscators store
them (word tables in either byte order, big numbers as bytes or limbs,
instruction immediates, a constant split into two addends, a permuted base64
alphabet). Read three things in each hit:

- `status` and `diff`: `near` with `63 of 64` and `[13] 0x80deb5fe, standard
  0x80deb1fe` means the algorithm is the standard one with that constant
  changed. Never call an algorithm standard while a `near` hit stands.
- `when`: a table marked `present only after init` does not exist in the file
  and appears once the set-up functions have run. Pass those functions as
  `init=[...]` (the calls at the top of `main`, or whatever writes the table);
  without them a masked S-box or masked curve parameters stay invisible.
- `used_by`: a table nobody references, or referenced only from a function
  without callers, is probably a decoy. When two candidates of the same kind
  exist (two curves, two keys), the reply says so.

It cannot see constants that the code computes on the fly (round constants
generated by a formula, values produced by SIMD arithmetic). No hit is not
proof of absence.

## Scratchpad

`rekit.calc(code)` evaluates a few lines of Python-like arithmetic over
integers and byte strings in a separate restricted interpreter: no files,
imports or attribute access, and hard limits on steps and sizes. The value of
the last expression is returned. Its reference implementations take the
standard constants as overridable arguments, which is how you test a
hypothesis instead of asserting it:

```python
rekit.calc("pow(7, rotl(532, 4, 32) ^ 5, 1000003)")          # does my formula give the observed 582698?
rekit.calc("sha256(b'abc', K={13: 0x80deb5fe})[:16].hex()")  # standard except K[13]?
rekit.calc("pkcs7_unpad(cbc_dec('sm4', unhex(k), unhex(iv), unhex(ct)))")
rekit.calc("ec_mul('sm2', k) == P")                          # is P really k*G?
```

Recompute every formula you are about to report against a value the program
actually produced (`rekit.run` or `rekit.emu`). A formula that was only read
off the code is a guess.

## Notes

Function cards include a `notes` entry when the findings ledger holds verified
conclusions that cite an address in that function. They are earlier
conclusions, not facts read from the binary: weigh them, and re-check the ones
you build on. `rekit.notes()` also lists unverified worker claims, marked as
such; cards leave those out so that an unchecked claim is not mistaken for
evidence.

## Reading the results

- **Addresses**: any `ea` argument accepts an int, `"0x1234"`, a symbol name, or
  a ref string copied from an earlier result.
- **Refs**: a function appears as `sub_3A44880` when the address is already in
  its name, otherwise as `name@0x3a44880`. A site inside a function is
  `sub_3A44880+0x1c`. `x3` after a ref is the number of call sites.
- **Budget**: every call takes `max_chars` (default 6000). A result that was
  cut says so in `more`, `capped`, or `truncated`, with the total and the call
  that fetches the rest. Nothing is dropped silently, so a result without
  those keys is complete.
- **Errors**: a failed call returns `{"error": ..., "hint": ...}`. Follow the
  hint; do not retry the same call unchanged.
- **Totals**: lists come as `{"total": N, "top": [...]}`. `total` counts
  everything, `top` is the part shown.

## What `trim` changes

`trim` regroups the local-variable block into `type a, b, *c;` lines without
the register and stack-slot comments, and removes pointer casts on a bare
identifier that is only assigned, returned, or passed to a call. Casts that
are dereferenced, indexed, offset, or that change width or signedness stay.
Statement lines keep their order and count.

Ask for `mode="raw"` when you need stack offsets, `BYREF` markers, or the exact
Hex-Rays text, for example before writing a patch or a struct definition.

## Working pattern

1. `rekit.info()` on a database you have not seen.
2. Find entry points with `rekit.find(string=...)` or `rekit.find(name=...)`.
3. Triage candidates with `rekit.batch([...])`; cards without code are cheap.
4. Read the interesting ones with `rekit.fn(ea)`; page long functions with
   `rekit.code(ea, start=...)`.
5. Widen with `rekit.calls(ea)` and `rekit.xrefs(ea)`.

Quote addresses from results as evidence when you report a finding. The cards
describe what is in the database; they do not interpret it, so names and
conclusions remain yours to justify.

## Limits

- Read-only towards the database by design. It never renames, comments,
  retypes, or patches. `rekit.emu`, `rekit.image` and the `decoded` field of
  cards write a snapshot to a cache directory outside the database; the first
  card of a function with initialisers pays for that export once.
- Function strings include Delphi literals and UTF-16 runs that IDA left
  untyped; a rare false string is possible there.
- Functions larger than 64 KB are not decompiled unless you pass `force=True`.
- The first `find(string=...)` on a database builds the string index: about
  5 seconds for a 14 MB PE, about 20 seconds for a 1.9 GB database.
- Stack-protector symbols are left out of the import and global lists.
- `rekit.selftest()` exercises every call on the open database and reports
  failures; run it after an IDA or ida-mcp upgrade.
