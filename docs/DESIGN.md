# Design, trade-offs and known problems

English | [简体中文](DESIGN.zh-CN.md)

## rekit

- One module plus a few optional companion files (`_emu.py`, `_notes.py`, `_crypto.py`, `_run.py`, `_calc.py`). It depends only on the standard library and IDAPython.
- Every call returns a dict. Addresses are always hex strings. Every call has a hard character budget; when output is truncated, the reply states the total and how to fetch the rest. Errors come back as "error plus hint", never as a traceback.
- Read-only with respect to the IDA database. Memory images for emulation are written to `tmp/rekit-images/`, not into the IDB.
- It is loaded by path from inside `execute_python` and is not installed into any Python environment, because ida-mcp's environment is rebuilt on upgrade.

## reworker

- **Guard proxy** (`guardproxy.py`): the MCP server the worker sees is this proxy, which in turn starts the real ida-mcp. The proxy filters the tool list, checks each call, enforces the call budget mechanically, and logs every call in full. On any internal error it exits, which leaves the worker with no tools.
- **Contract** (`contract.py`): a task has six fields. A result is `status / summary / findings / unknowns / needs`, and each finding carries evidence addresses and a confidence level.
- **Grounding check**: an evidence address must have appeared in the task or in the worker's own tool results; otherwise the finding is marked `grounded: false`. This shows only that the address was seen. It does not show that the conclusion is right.
- **Audit**: after each run, the worker process's event stream is compared with the proxy log. A non-IDA tool call, or a result that did not come through the proxy, voids the whole run (exit code 3).
- **Ledger** (`findings/<database name>.jsonl`): append-only. `rew verify` marks a finding verified or rejected. `rew note` records the orchestrator's own conclusions.
- **Exact-value back-references**: a worker writes `{{7.buffers.top[name=out].hex}}` in its answer, and `rew` replaces it with the original value from the result of call 7. Any long hex string left in the answer that cannot be found in any tool output is listed.

## remu

- Each request gets a fresh Unicorn instance. The image is written in, arguments are placed by calling convention or as explicit registers, and execution runs until it reaches a sentinel return address.
- Every import is intercepted. Common memory, string, heap and code-page functions are modelled. The rest record their arguments and return 0.
- `init=[...]` runs a list of initialisation functions in the same state before calling the target function. This handles tables that are only generated at run time.
- The reply contains the stop reason, the return value, argument buffers that were modified, other memory that was written and the strings in it, and the sequence of import calls.

## recalc

- A purpose-written restricted interpreter with no `eval`. No files, no imports, no attribute access. Step count, time, integer bit length and sequence length are all capped.
- It has built-in reference implementations of hashes, block ciphers and elliptic curves whose standard constants can be overridden. This is for checking claims of the form "a standard algorithm with one thing changed".

## rebox

- The outer process hashes the sample, creates the output directory, then restarts itself under `sandbox-exec`. The child first checks that the sandbox is actually in effect (connecting to the network and writing outside the directory must both be refused) and only then touches the sample.
- The summary is split into blocks by API category, indicators and dumps, and is held to a character budget.
- **ELF emulation** (`rebox run`, Qiling, in a separate environment `.venv-elf`): the same sandbox. All network system calls are replaced with rebox's own implementations: connections pretend to succeed, reads return nothing, and every hostname resolves to one fixed address. `execve` is recorded and ends that process. After `fork`, the child runs first and the parent is then resumed. Each run uses its own copy of the root filesystem, which is diffed afterwards for new and changed files.
- **Real execution** (`rebox live`, Docker): `--network none`, no mounts (the sample and the results both travel through `docker cp`), all capabilities dropped, `no-new-privileges`, and limits on process count, memory and CPU. Before starting the sample, a check inside the container confirms that only the loopback interface exists; if the check fails, nothing runs. ARM64 runs natively under `strace`. x86 and x86-64 run under QEMU user mode wrapped in `strace`. The optional `--fakenet` starts a fake service inside the container that answers DNS and accepts any TCP connection.

## Trade-offs

| Decision | Reason | Where to change it |
|---|---|---|
| The guard is an MCP proxy, not a hook in the worker's harness | A hook lets calls through when it crashes, times out, or cannot read its configuration, so it is unfit to be the only line of defence. A proxy is independent of the harness and carries over to another backend unchanged | — |
| The worker sees only 4 IDA tools, with no save and no close, and can open only the named database | Least privilege | `guard.py` |
| The worker's default reasoning effort is high | On the same task, high and low both answered correctly. Low was about 20% faster but made a slip in its summary | `rew --effort` |
| Workers may use function-level emulation | Emulation is interpreted in a separate process and makes no system calls. The cost is that IDA's main thread is occupied while it runs | `guard.py` |
| A worker's whole-program runs go only through `rebox run` | That is sandboxed emulation. It cannot reach real execution in a container | `rekit/_run.py` |
| Function cards show only verified notes | Otherwise an unverified worker finding would be cited back as evidence by the next worker | `rekit/_notes.py` |
| Free mode blocks write operations by name only and is not a sandbox | It can be bypassed deliberately, which is why strict is the default | `rew --mode` |
| Result budget: 6000 characters, at most 8 findings, at most 4 evidence addresses each | The orchestrator's context is limited | `rew --max-chars / --max-findings` |
| Numbers below 0x1000 do not count as addresses | A struct offset should not make a finding "grounded" | `contract.py` |
| `trim` removes only pointer casts whose value is merely passed along | Other casts take part in dereferences or arithmetic, and removing them would change the meaning | `rekit.code(mode="raw")` |
| The UTF-16 string index is on by default only for PE | On one 1.9 GB Mach-O library it took 86 seconds with the index on and 21 seconds with it off | `rekit.find(..., wide=True)` |
| Building the string index temporarily changes IDA's string-list settings and restores them afterwards | This is one concession on "read-only" | `rekit.py` |
| remu maps every segment readable, writable and executable | It is simple, and self-modifying code runs | `remu/src/remu/emu.py` |
| For x86 imports with no prototype, remu assumes the callee pops 0 bytes and warns | In the samples tested, more than half the imports had no prototype | override with `imports` in the request |
| The rebox sandbox restricts writes but not reads | Both the sample directory and the Python runtime have to be readable | `rebox/src/rebox/sandbox.py` |

Not done: offline indexing with a local small model (a small model behind an API was more accurate), rewriting pseudocode with a model specialised for reverse engineering (rewriting introduces semantic errors), 32-bit ARM and MIPS.

## Measurements

- A function card is about 50% fewer characters than "raw pseudocode plus a flat xref list". A triage card without code is about 90% fewer. An xref query on a hot function went from 935,000 characters to 1.4 KB.
- One function-level emulation call takes 30–70 ms. Exporting an image takes 0.2 s for 14 MB and 2.6 s for 171 MB.
- Whole-program emulation is of limited value for large GUI programs: one Delphi sample stopped during runtime-library initialisation. Function-level emulation does the real work on such targets.
- A narrow task costs a worker somewhat over 100,000 tokens. An open-ended task ("work out what this program does") costs 1.2–2.4 million and should be split into narrow ones.
- The kinds of worker errors seen: reading "never executed" as "unreachable from the dispatch table"; missing one hex digit when comparing 64 constants by eye; dropping characters when copying a long hex string; overstating what a function is for. The last three are covered by crypto-constant matching, exact-value back-references and orchestrator verification respectively.

## Known problems

- **Workers are slow.** Even a tiny question takes tens of seconds to minutes. For a single lookup the orchestrator is faster using rekit directly.
- **`grounded` is a weak signal.** It proves only that the address appeared. `confidence` also runs high and is no substitute for verification.
- **A worker will not ask when the task wording is ambiguous.** State exactly what is being counted, and ask for the call chain.
- **The worker backend is preview software.** After upgrading it, run `rew doctor` first. It starts the profile with a fake model and checks the tool list the worker actually receives.
- **The IDA database may get saved.** ida-mcp saves automatically when the last session releases a database. The tools changed nothing, but the modification time of the `.i64` changes.
- **Residual risk in `rebox live`.** A container is not an isolation boundary fit for hostile malware. See `tools/rebox/LIVE.md`.
- **Dynamically linked glibc ELFs cannot resolve hostnames under emulation.** The rootfs has no `libnss_dns`. The queried name is still recorded, but the sample itself sees a resolution failure. To observe behaviour after resolution, use `rebox live --fakenet`.
- `rekit.crypto` cannot find constants that are computed on the spot from a formula (SM4's CK, AES's Rcon) or derived from other data with SIMD.
- `rekit.run` cannot capture console output from a Windows PE and does not support standard input for one.
- The run-record directory `tmp/` is not cleaned automatically. Run `./gc --apply` by hand.
- The test frameworks are not uniform: `remu`, `recalc` and `rebox` use pytest, and the rest are `python3 test_x.py` scripts. `./test` chains them behind one entry point.
