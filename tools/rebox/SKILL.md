---
name: rebox
description: Whole-program behaviour reports for suspicious binaries, as compact JSON - `rebox run` emulates a Windows PE (Speakeasy) or a Linux ELF (Qiling) inside a no-network macOS sandbox without running it natively; `rebox live` really executes a Linux ELF under strace in a network-less Docker container. Reports API calls or syscalls by category, files, registry, hosts, connections, command lines and dropped payloads. Use for a first behavioural look at a sample, to find unpacking or dynamically resolved APIs, or to see what a program does before its code is reached statically. Not for single functions (use rekit.emu) and not for Mach-O.
---

# rebox

Two ways to watch a whole program, both printing one JSON summary (schema
`rebox.summary/1`) and keeping the full detail in an output directory.

| | `rebox run` | `rebox live` |
|---|---|---|
| Input | Windows PE (x86, x64), Linux ELF (x86, x86-64, ARM64) | Linux ELF (x86, x86-64, ARM64) |
| How | CPU emulator; the sample is interpreted, never executed | the sample really runs, in a container, under `strace` |
| Containment | `sandbox-exec`: no network, writes only to the output directory | Docker `--network none`, no mounts, no capabilities, resource limits |
| Gets far when | code is simple and single-threaded | the program needs threads, `fork`, a real kernel, a Go runtime |
| Cost | under a second, nothing to clean up | a few seconds; needs Docker running |

Start with `run`. Use `live` when emulation stops early or the sample is the
kind emulators handle badly. `live` executes the sample; that is a deliberate
step, so say in your report that you took it.

```bash
R=~/.agents/skills/rebox/rebox
$R run  <sample> [--timeout 60] [--arg VALUE]... [--max-chars 6000]
$R live <sample.elf> [--timeout 60] [--fakenet] [--user] [--arg VALUE]...
$R summarize <out dir>         # re-render a run;  live-summarize for live runs
```

Neither mode has an option that gives the sample a real network. Exit code 0
means a report was produced, whatever the sample did; 3 means the containment
could not be established and the sample was not run; 5 means unsupported
input. One-time setup: `rebox setup-elf` (Qiling environment and Linux
libraries) and `rebox live-setup` (container image); both need network.

## Reading a summary

Lists are `{"total": N, "top": [...]}`. Anything cut to fit the budget is named
under `truncated`. Empty indicator kinds are listed under `empty`.

**`run`** (`emulation`, `api`, `indicators`, `payloads`):

- `emulation.runs`: each entry point or process that ran, how many calls it
  made and why it stopped. Read this first. A PE that stops with
  `unsupported_api` or a fault after a few hundred calls ended inside start-up
  code, and the report covers only that prefix.
- `api`: for PE, Windows API calls; for ELF (`"kind": "syscalls"`), system
  calls. `categories` groups the notable ones with a call-site address you can
  open in IDA. For ELF, `unsupported` lists syscalls the emulator answered with
  ENOSYS: the program may have taken a different path because of them.
- `indicators`: files, registry keys, hosts, connections, command lines,
  mutexes. The network is faked: connects are reported to the sample as
  successful and reads return nothing, so indicators are what the sample asked
  for, not what a server answered. Every name resolves to one canned address,
  which is left out of `ips`.
- `payloads`: dropped files and memory that was written and then executed,
  saved as non-executable dumps with sha256.
- ELF specifics: `execve` is recorded and ends that process (stop `execve`);
  the target is not emulated. After `fork` the child runs first, then the
  parent continues. Sleeps return at once.

**`live`** (`"mode": "live"`, `execution`, `syscalls`, `indicators`,
`fs_changes`, `output`):

- `execution`: how it ended (`exited` with a code, a signal, or `timeout`),
  the processes it spawned, and `container_removed`.
- `syscalls.failed`: errors the sample saw. Without `--fakenet` every connect
  fails with ENETUNREACH and name lookups fail; the attempts are still listed
  under `indicators`. With `--fakenet` a sink inside the container answers DNS
  and accepts TCP on any port, so the sample goes one step further and what it
  sent appears under `data_out`.
- For x86 and x86-64 samples the trace is of QEMU running the program, so
  counts include QEMU's own `mmap`, signal and `futex` calls; trust the
  indicators and categories more than the raw histogram.
- `fs_changes` and `payloads`: files added, changed or deleted in the
  container, copied out as non-executable dumps.
- Default is root without capabilities, because much persistence code only
  runs as uid 0; `--user` runs as uid 1000.

## What they cannot tell you

A short run with empty indicators says nothing about the sample. Emulation
stops at the first unimplemented API, unsupported instruction or fault; large
GUI programs often stop during runtime initialisation (a 14 MB Delphi sample
ended after 830 calls in its RTL start-up). Qiling handles threads weakly and
Go programs may not get far. Samples can detect an emulator, a container, or
the lack of a network and behave differently. Drivers, .NET and Mach-O are out
of reach.

When the whole program does not get far, go function by function: find the
routine of interest in IDA and run it with `rekit.emu`.

Details: `README.md` (emulation, sandbox, ELF backend) and `LIVE.md`
(container isolation, what it does and does not protect against) next to the
launcher.
