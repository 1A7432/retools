# retools

English | [简体中文](README.zh-CN.md)

Local tools that let a large model direct cheap small-model workers through the legwork of reverse engineering in IDA. The orchestrating model splits the job into narrow tasks and verifies what comes back. Each worker reaches IDA only through a guard proxy, can call only a fixed read-only API, and returns JSON in which every finding carries evidence addresses.

The premise: when a general-purpose model does reverse engineering, the bottleneck is the interface, not the model. Small models guess IDAPython APIs wrong, so the interface is fixed, and what a worker can do is limited by mechanism instead of by instruction.

> **This is a snapshot of personal tooling, not a maintained project.** It has only run on the author's machine (macOS, Apple Silicon). Issues are closed, feature requests are not accepted, pull requests may go unread, there are no version numbers, and no interface is promised to stay stable. It is public so the design and the measurements can be read and cited. Fork it if you want to use it.

A write-up of the design, one blind benchmark run, and how often worker findings survived review on a real sample: [1A7432/writeups: An LLM worker harness for IDA reverse engineering](https://github.com/1A7432/writeups/tree/main/2026-11-llm-re-worker-harness).

## Components

| Component | What it does | Docs |
|---|---|---|
| `tools/rekit/` | Compact read-only views inside IDA: function cards, pseudocode, xrefs, call trees, search, disassembly, crypto-constant matching, plus entry points for function-level emulation, whole-program runs, and a calculator | `SKILL.md` |
| `tools/reworker/` | The `rew` command: hands one narrow task to a worker, validates the result, audits the calls, and records findings in a ledger | `SKILL.md` |
| `tools/remu/` | Function-level emulator (Unicorn) that runs on memory images exported by rekit | `README.md` |
| `tools/recalc/` | A restricted calculator: arithmetic, hashes, block ciphers, elliptic curves. No `eval` | `README.md` |
| `tools/rebox/` | Whole-program behaviour reports. `rebox run` emulates a PE (Speakeasy) or an ELF (Qiling) inside a macOS sandbox. `rebox live` really runs an ELF in a Docker container with no network | `README.md`, `LIVE.md`, `SKILL.md` |
| `tools/jsworker/` | The `jsw` command: the same worker pattern for JavaScript reverse engineering, with every tool executed inside a Docker container | `README.md` (Chinese) |

Data flow:

1. The orchestrator writes a task.
2. `rew` starts a headless worker process.
3. The worker can reach ida-mcp only through the guard proxy, and the proxy only lets rekit calls through.
4. The worker returns JSON.
5. `rew` validates it, audits the run, and appends the findings to the ledger.
6. The orchestrator spot-checks findings and marks each one verified or rejected.
7. Verified findings show up on function cards from then on. Unverified ones do not.

Design decisions, trade-offs and known problems are in [`docs/DESIGN.md`](docs/DESIGN.md).

## Scope

- Host: macOS on Apple Silicon. The sandbox uses `sandbox-exec`. Other systems are untested.
- Target architectures: x86, x86-64, ARM64. 32-bit ARM and MIPS are not supported.
- Target formats: PE, ELF and Mach-O for static analysis and function-level emulation. Whole-program runs support PE (emulated) and ELF (emulated, or really run in a container).

## Requirements

- IDA Pro and the Hex-Rays `ida-mcp` command (on `PATH`, or set `REW_IDA_MCP`)
- [uv](https://docs.astral.sh/uv/) and Python 3.12
- Worker backend: the `dsh` CLI from DeepSeek Harness (set its path with `REW_DSH`) and an OpenAI-compatible model endpoint
- Docker, for `rebox live` and `jsworker`

## Install

```sh
git clone https://github.com/1A7432/retools && cd retools

# 1. Each tool's own environment
for t in remu recalc rebox; do uv sync --frozen --project tools/$t; done
tools/rebox/rebox setup-elf          # optional: ELF emulation environment and Linux runtime libraries; needs network
tools/rebox/rebox live-setup         # optional: the image for really running ELFs

# 2. Link the skills to where your agent looks for them
mkdir -p ~/.agents/skills
for s in rekit reworker rebox; do ln -sfn "$PWD/tools/$s" ~/.agents/skills/$s; done

# 3. The worker's model endpoint
cp tools/reworker/profile/provider.example.yml tools/reworker/profile/provider.local.yml
$EDITOR tools/reworker/profile/provider.local.yml    # your endpoint, the name of the key variable, the model
tools/reworker/rew setup
tools/reworker/rew doctor            # every line must say ok before you dispatch a worker
```

`provider.local.yml` is not tracked by git. The three `SKILL.md` files write paths as `~/.agents/skills/<name>`, so keep the link location from step 2, or edit the paths in the skills.

## Usage

```sh
# Dispatch one worker
tools/reworker/rew --db <sample or .i64> --goal "..." --target 0x401000 --out r.json
# Whole-program emulation (PE or ELF; nothing runs natively)
tools/rebox/rebox run <sample>
# Really run an ELF in a container with no network
tools/rebox/rebox live <sample.elf> [--fakenet]
```

Inside IDA (through ida-mcp's `execute_python`):

```python
import sys; sys.path.insert(0, "<checkout>/tools/rekit")
import rekit; rekit.help()
```

Run records go to `tmp/` and the ledger goes to `findings/`. Neither is tracked by git.

## Tests

```sh
./test
```

One entry point runs every suite. Suites that need Docker or a real `dsh` are skipped, with the reason shown, when those are not available.

`./gc` lists old run data under `tmp/` that can be removed. It deletes only with `--apply`.

## Benchmarks

`bench/` holds three blind question sets. They test the whole workflow, not just the worker.

| Directory | Contents |
|---|---|
| `bench/obf1/` | 6 stripped ELFs and 58 questions: control-flow flattening, opaque predicates, bytecode virtual machines, and SM2/SM3/SM4/SHA-256/AES programs with decoy keys and altered constants |
| `bench/obf2/` | A second set of obfuscated programs: 6 stripped ELFs (x86-64 and ARM64) |
| `bench/jsvm1/` | 6 protected web front ends; the task is to recover the request-signing or encryption logic |

Every program is pure computation and pure obfuscation. None does anything malicious. The repository contains only `public/` (the questions and the binaries). Sources, answers, graders and setter notes are not published, because the sets would then stop being blind.

Scores on `obf1` (the 53 machine-graded questions):

| Configuration | Score |
|---|---|
| Workers alone | 47 |
| After fixing the tool bug the benchmark exposed | 48 |
| After also adding crypto-constant matching, whole-program runs, the calculator, and exact-value back-references | 52 |
| Whole workflow (workers plus orchestrator verification) | 52; the one miss is an answer spelling the grader does not accept |

Each configuration was run once. The limits of these numbers are spelled out in the write-up linked above.

## Safety notes

- `rebox run` does not execute the sample's native code. The outer process first checks that the sandbox is actually in effect, and only then touches the sample.
- `rebox live` does execute the sample. The container has no network, no mounts and no capabilities, but a container is not an isolation boundary fit for hostile malware. See `tools/rebox/LIVE.md`.
- Neither mode has a switch that gives the sample real network access.
- A worker's statement about what a function is *for* must be verified. In practice the facts workers list are mostly reliable, and their characterisations are not.

## License

The code in this repository is released under the MIT license. See [`LICENSE`](LICENSE).

Runtime dependencies are installed by the user and carry their own licenses: Unicorn and Qiling are GPL-2.0, Speakeasy is MIT. The Linux runtime libraries (glibc and others) that `rebox setup-elf` downloads are not distributed with this repository.
