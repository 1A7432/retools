# rebox

Runs a Windows PE sample through whole-program user-mode **emulation** with
[Mandiant Speakeasy](https://github.com/mandiant/speakeasy) inside a macOS
`sandbox-exec` jail, and prints one compact JSON behaviour summary that an LLM
agent can read cheaply. The sample is never executed natively; the complete raw
Speakeasy report and every memory dump stay on disk for follow-up.

Linux ELF samples (x86-64, x86, ARM64) are emulated with
[Qiling](https://github.com/qilingframework/qiling) under the same sandbox and
produce the same kind of summary; see [Linux ELF](#linux-elf) (one-time setup:
`rebox setup-elf`).

## Versions (verified on macOS 26.6 / Apple Silicon, 2026-11-14)

| component | version | note |
|---|---|---|
| Python | 3.12.14 (uv-managed) | `requires-python = ">=3.12,<3.13"`, `.python-version` |
| speakeasy-emulator | 2.0.0b9 (PyPI wheel, same as GitHub tag v2.0.0b9) | 1.x pins Unicorn 1.0.2, which bus-errors on arm64 |
| unicorn | 2.1.4 (`macosx_11_0_arm64` wheel) | |
| capstone 5.0.9, pefile 2024.8.26, pydantic 2.14.3 | from `uv.lock` | |
| pytest 9.2.0 | dev group | |

Speakeasy 2.0.0b9 was verified by running it here (pip launcher stubs, the
Speakeasy repo's test binaries and a synthetic PE), not just by reading.

## Usage

```
tools/rebox/rebox run <sample> [options]
    --timeout N      emulation time budget in seconds (default 60)
    --out DIR        output directory, must be new or empty
                     (default tmp/rebox-runs/<sha256[:12]>-<YYYYmmdd-HHMMSS>)
    --max-chars N    size limit of the printed summary (default 6000)
    --arg ARG        argument for the emulated process, repeatable (--arg=-x for dash values)
    --env KEY=VALUE  ELF only: environment variable for the emulated process, repeatable
    --stdin TEXT     ELF only: standard input, this text as UTF-8, taken literally (no escapes,
                     no newline added; use --stdin=-x for dash values), then end-of-file
    --stdin-hex HEX  ELF only: standard input as hex bytes, spaces allowed (any byte values)
    --stdin-file P   ELF only: standard input read from file P
                     (the three are mutually exclusive; at most 1 MiB; see "Standard input")
    --max-api N      stop a run after N API calls (PE) / N syscalls (ELF); default 10000
    --trace-mem      PE only: per-region R/W/X counters + instruction counts (much slower)
    --children       PE only: also emulate child processes the sample creates
    --no-sandbox     PE only: run without sandbox-exec (prints a warning; do not use on live samples)

rebox summarize <out_dir> [--max-chars N]   re-render the summary of an earlier run (PE or ELF)
rebox setup-elf [--force] [--venv-only | --rootfs-only]
                                            build .venv-elf and fetch elf-rootfs (needs network)
```

No activation step: the launcher uses the project's `.venv` (and creates it
with `uv sync --frozen` if it is missing). Tests: `uv run pytest` in this directory.

stdout is always exactly one JSON object; diagnostics go to stderr.

| exit | meaning |
|---|---|
| 0 | emulation produced a report (even if the sample crashed or hit a limit inside the emulator) |
| 2 | usage error (bad arguments, sample missing, `--out` not empty) |
| 3 | sandbox unavailable, failed to apply, or failed its self-check: sample was **not** run |
| 4 | tool failure (emulator stage crashed without a report) |
| 5 | unsupported input (not PE/ELF, .NET, non-x86/x64 PE, ELF of another architecture), or the ELF backend / rootfs is not set up (the error names `rebox setup-elf`) |
| 6 | emulator process killed by the hard wall-clock backstop (`timeout + max(60, timeout)` s) |

On a non-zero exit the JSON is `{"schema", "ok": false, "exit", "error", "out_dir"?}`.

### Output directory

```
report.json        complete Speakeasy report (unmodified, v2 report format 5.x)
run.json           rebox metadata: PE identity, sandbox self-check, dumps, errors, true API call counts
summary.json       the summary that was printed
speakeasy.log      Speakeasy's per-API log
dumps/*.bin        memory dumps, dropped files, injected buffers (mode 0600, never executable)
sandbox.sb         the sandbox profile that was applied
inner.stderr.txt   stderr of the sandboxed stage, if any
tmp/               TMPDIR/HOME of the sandboxed stage
```

## Summary schema (`rebox.summary/1`)

Conventions: every list is `{"total": N, "top": [...]}`; addresses are hex
strings; strings longer than 160 chars end in `…[+N]`; nothing is cut
silently. If the full summary exceeds `--max-chars`, all lists are refilled
round-robin (higher-value lists first: payloads, indicators, runs; then
categories; strings and the histogram last), each keeping a prefix of its
items, and `truncated` names what was shortened. `total` always stays exact.
If even the skeleton does not fit, whole sections are dropped (listed in
`truncated.dropped`) and below roughly 1100 chars `truncated.over_budget` is
`true` and the limit is exceeded.

| key | content |
|---|---|
| `sample` | name, sha256, size, arch, pe_type (exe/dll/driver/dotnet), subsystem, PE timestamp, image_base, entry_rva, imphash, import count, `sections` as `"name perms vsz=.. H=entropy"` |
| `emulation` | engine versions, sandbox state, wall/emulation seconds, timeout, `runs` (one per entry point: type, start, `api_calls` = true count, `api_events` = logged events, instrs (only with `--trace-mem`), `stop` = `returned` or the Speakeasy error type such as `unsupported_api`, `timeout`, `max_api_count`, `invalid_read`; `pc`, `detail`, `ret`, `dyn_code`), `errors` |
| `api` | `calls` (true), `events` (logged), `unique`, `histogram` `[[api, n]]`, `categories` (process_thread, file, registry, network, crypto, memory, services, anti_analysis, dynamic_resolution, timing_checks) as `[[api, n, first_call_pc]]`, `resolved` (names passed to GetProcAddress) |
| `indicators` | hosts, urls, ips, conns, ports, files_written, files_read, files_deleted, registry_written, registry_read, mutexes, cmdlines, services, injections, modules_loaded; `empty` lists the keys with nothing |
| `payloads` | `{kind, file (relative to out_dir), size, sha256, base/name/emu_path/pid/target}`; kinds: `dyncode` (sample-allocated memory that executed), `protexec` (non-image memory the sample made executable), `imgmod` (main-image section that changed and is executable), `dropped` (file written in the emulated FS), `inject` (cross-process WriteProcessMemory buffer) |
| `payloads_not_saved` | dumps skipped (64 MiB per dump / 512 MiB per run cap, or content missing from the report) |
| `strings` | `api_args`: string arguments not already shown as indicators; `runtime_only`: strings found in emulated memory but not in the file (decoded at run time), minus the emulator's own environment strings |
| `out_dir`, `raw_report` | where the full data is |
| `truncated` | `null`, or `{why, cut: [paths], dropped?, over_budget?}` |

`ips` excludes the canned addresses Speakeasy's DNS emulation returned (the
default config answers every unknown name with 10.1.2.3), so only addresses the
sample itself used are listed.

### Real example

A synthetic test program built by `tests/pebuild.py` (hand-assembled x86; it
only ever runs in the emulator), default options, 4227 chars (`rebox summarize` of that run):

```json
{"schema":"rebox.summary/1","ok":true,"sample":{"name":"behave.exe","sha256":"e99080e3d503247addc223090e881458e698a6001486330dfd54446f03de23d2","size":3584,"arch":"x86","pe_type":"exe","subsystem":"console","timestamp":1600000000,"image_base":"0x400000","entry_rva":"0x1000","imphash":"07db20889804c6896a224ee012b88906","imports":20,"sections":{"total":3,"top":[".text r-x vsz=0x1af H=3.07",".data rw- vsz=0x30d H=2.56",".idata rw- vsz=0x27b H=2.87"]}},"emulation":{"engine":"speakeasy 2.0.0b9 / unicorn 2.1.4","sandbox":"sandbox-exec: no network, writes only to out_dir","wall_s":0.62,"emu_s":0.027,"timeout_s":60,"instrs":null,"runs":{"total":1,"top":[{"type":"module_entry","start":"0x401000","api_calls":21,"api_events":21,"instrs":null,"stop":"returned","ret":"0x1337","dyn_code":1}]},"errors":{"total":0,"top":[]}},"api":{"calls":21,"events":21,"unique":20,"note":"counts below are logged events; Speakeasy collapses an API call that repeats one of the last few events (same pc, args, result)","histogram":{"total":20,"top":[["kernel32.OutputDebugStringA",2],["kernel32.GetCommandLineA",1],["kernel32.IsDebuggerPresent",1],["kernel32.CreateMutexA",1],["kernel32.CreateFileA",1],["kernel32.WriteFile",1],["kernel32.CloseHandle",1],["advapi32.RegCreateKeyExA",1],["advapi32.RegSetValueExA",1],["ws2_32.WSAStartup",1],["ws2_32.gethostbyname",1],["ws2_32.socket",1],["ws2_32.connect",1],["ws2_32.send",1],["wininet.InternetOpenA",1],["wininet.InternetOpenUrlA",1],["kernel32.WinExec",1],["kernel32.VirtualAlloc",1],["kernel32.Sleep",1],["kernel32.ExitProcess",1]]},"categories":{"process_thread":{"total":1,"top":[["kernel32.WinExec",1,"0x401177"]]},"file":{"total":2,"top":[["kernel32.CreateFileA",1,"0x401051"],["kernel32.WriteFile",1,"0x40106e"]]},"registry":{"total":2,"top":[["advapi32.RegCreateKeyExA",1,"0x4010a8"],["advapi32.RegSetValueExA",1,"0x4010cd"]]},"network":{"total":7,"top":[["ws2_32.WSAStartup",1,"0x4010dd"],["ws2_32.gethostbyname",1,"0x4010e8"],["ws2_32.socket",1,"0x4010fd"],["ws2_32.connect",1,"0x401110"],["ws2_32.send",1,"0x401126"],["wininet.InternetOpenA",1,"0x401145"],["wininet.InternetOpenUrlA",1,"0x401167"]]},"memory":{"total":1,"top":[["kernel32.VirtualAlloc",1,"0x401191"]]},"anti_analysis":{"total":3,"top":[["kernel32.OutputDebugStringA",2,"0x40100d"],["kernel32.IsDebuggerPresent",1,"0x401013"],["kernel32.Sleep",1,"0x50008"]]}},"resolved":{"total":0,"top":[]}},"indicators":{"hosts":{"total":2,"top":["beacon.rebox-test.invalid","dl.rebox-test.invalid"]},"urls":{"total":1,"top":["http://dl.rebox-test.invalid/stage2.bin"]},"ips":{"total":1,"top":["198.51.100.7"]},"conns":{"total":3,"top":["tcp connect 198.51.100.7:4444","tcp data_out 198.51.100.7:4444","tcp.http dl.rebox-test.invalid:80"]},"ports":{"total":2,"top":["4444","80"]},"files_written":{"total":1,"top":["C:\\Users\\Public\\rebox_drop.txt"]},"registry_written":{"total":2,"top":["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ReboxTest"]},"mutexes":{"total":1,"top":["Global\\rebox-test-mutex"]},"cmdlines":{"total":1,"top":["cmd.exe /c echo rebox-test"]},"empty":["files_read","files_deleted","registry_read","services","injections","modules_loaded"]},"payloads":{"total":2,"top":[{"kind":"dyncode","file":"dumps/dyncode_0x50000_8cdba47e8042.bin","size":4096,"sha256":"8cdba47e8042d2d0568cc54017b2bb27bac2d4145c9d2d244d0bbae1a1b7e741","base":"0x50000"},{"kind":"dropped","file":"dumps/dropped_rebox_drop.txt_662cc73584cd.bin","size":20,"sha256":"662cc73584cda3335c71ed60378073f4a575e61b88056ee394ada9f4e39b796d","name":"rebox_drop.txt","emu_path":"C:\\Users\\Public\\rebox_drop.txt"}]},"payloads_not_saved":{"total":0,"top":[]},"strings":{"api_args":{"total":11,"top":["C:\\Users\\Public\\rebox_drop.exe","rebox-test-agent/1.0","Software\\Microsoft\\Windows\\CurrentVersion\\Run","198.51.100.7:4444","0x402038 (7265626f782074657374207061796c6f)","HKEY_CURRENT_USER","ReboxTest","SOCK_STREAM","HELLO rebox-test","rebox stage2 running","AF_INET"]},"runtime_only":{"total":0,"top":[]}},"out_dir":"/Users/darthvader/ClaudeCode/wechat-hook/tmp/rebox-runs/e99080e3d503-20261114-053048","raw_report":"report.json","truncated":null}
```

## Isolation model

`rebox run` (outer stage, unsandboxed) only hashes the sample, creates the
output directory and reads back JSON. Everything that parses or emulates sample
bytes (pefile, Speakeasy, the dumps) runs in a child that re-executes
`python -I -B -m rebox _inner` under `/usr/bin/sandbox-exec` with this profile
(paths passed as `-D` parameters, never spliced into the text):

```
(version 1)
(allow default)
(deny network*)
(deny mach-lookup)
(deny iokit-open)
(deny process-fork)
(deny process-exec*)
(allow process-exec (literal (param "PYTHON")) (literal (param "PYTHON_REAL")))
(deny file-write*)
(allow file-write* (subpath (param "OUT")) (literal "/dev/null"))
```

* **Network**: all sockets (TCP, UDP, unix) are denied; `mach-lookup` is denied
  too, which closes the mDNSResponder route, so a DNS lookup cannot be
  delegated to a system daemon either.
* **Files**: writes only inside the run's output directory (and `/dev/null`).
  The child's `TMPDIR` and `HOME` point at `out_dir/tmp`. CPython needs no
  other writable path when started with `-B`.
* **Processes**: no fork, no exec of anything but the interpreter itself.
* **Fail closed**: missing `sandbox-exec` → exit 3 before anything runs. A
  profile that fails to apply → `sandbox-exec` exits before Python starts, no
  `run.json` → exit 3. Before touching the sample, the child proves the sandbox
  is active: a TCP connect to 127.0.0.1 and a file create in the parent of the
  output directory must both fail with **EPERM** (the sandbox's errno, unlike
  EACCES/ECONNREFUSED), a DNS lookup must fail, and a write inside the output
  directory must succeed. Otherwise it refuses (exit 3). `--no-sandbox` skips
  all of this and warns on stderr.
* **Artefacts**: dumps are created with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600,
  `.bin` suffix, under a 0700 directory (process umask 077). Nothing is ever
  marked executable or run natively.

Tests (`tests/test_sandbox.py`) run a probe inside the same profile against a
real local TCP listener (an unsandboxed control run reaches it; the sandboxed
run gets EPERM and the listener sees no connection), plus TCP to 1.1.1.1:443,
UDP to 8.8.8.8:53, `getaddrinfo`, writes outside/inside/`$HOME`, and
`subprocess`; and they check the three fail-closed paths.

### How Speakeasy treats network APIs

Read in the 2.0.0b9 source and confirmed by the synthetic test: the
winsock/wininet/winhttp/urlmon/dnsapi handlers never open host sockets. The
only `socket.socket` use in the package is the optional GDB stub
(`gdb.py`, only when `gdb_port` is set; rebox never sets it); `ws2_32.py`
imports only `inet_aton/htons`-style helpers. DNS (`gethostbyname`,
`getaddrinfo`, `DnsQuery`) is answered from `network.dns.names` in the config
(default: `10.1.2.3` for any unknown name, a few fixed entries); `recv` and
HTTP responses come from bundled files (`resources/web/*.bin`), and
`connect`/`send`/HTTP requests are only recorded as `net_*` events. The emulated
file system is in-memory: no handler writes, renames or deletes host files.
The sandbox is the backstop regardless.

### Limits of the isolation

* `(allow default)` leaves file **reads** open: the emulator can read any file
  the user can (needed for CPython/Unicorn). Speakeasy itself mounts the
  sample's sibling files (same directory, no recursion) read-only into the
  emulated current directory, so an emulated sample can read files next to it.
  No read can leave the machine, but content can end up in the report.
* The sandbox stops the emulator process, not bugs in it: a Unicorn/Speakeasy
  memory-safety bug triggered by a crafted sample would run with the sandbox's
  rights (no network, writes only to `out_dir`). Shared memory, signals to
  other processes and most IPC other than Mach lookups are not denied.
* `sandbox-exec` is deprecated by Apple (still present and working on macOS 26).
* The outer stage parses the inner stage's JSON (`report.json`, `run.json`)
  with the stdlib `json` module outside the sandbox.

## Known limitations of the emulation

* **Anti-emulation / environment checks**: Speakeasy's environment (user
  `speakeasy_user`, host names, process list, registry, files, canned network
  replies) is generic. Samples that look for a real environment, timing,
  CPUID quirks, or specific files/keys may take a different path or stop.
* **Unimplemented APIs**: documented Win32 APIs without a handler run as
  stubs from their signature (no side effects, zeroed out-params); unknown
  APIs (C runtime, third-party DLLs) stop the run with `unsupported_api`
  (`runs[].detail` names the API). The pip launcher stub, for example, stops
  at `user32.MessageBoxTimeoutA` in its x64 build.
* **Threads** are run one after another as separate runs, not concurrently;
  synchronisation-dependent logic can diverge.
* **Drivers** run in Speakeasy's kernel emulator (entry point plus IRP
  handlers); coverage of kernel APIs is thinner.
* **.NET** assemblies are refused (exit 5): Speakeasy does not emulate managed code.
* **Counts**: the report de-duplicates an API event that repeats one of the
  last few (same pc, args, result). `api_calls`/`api.calls` are the true counts
  from Speakeasy's profiler; the histogram and categories count logged events.
  Instruction counts need `--trace-mem`.
* **Unpacking detection** without `--trace-mem` is by construction:
  `dyncode` (Speakeasy's hook on executed VirtualAlloc/VirtualAllocEx/
  NtAllocateVirtualMemory memory, dumped at first execution and again at the
  end if it changed), `protexec` (VirtualProtect to an executable protection
  outside the image), `imgmod` (an executable section of the main image whose
  bytes changed; whether it was executed after the change is not known).
  Heap or stack shellcode that is never made executable through an API is not
  dumped.
* `keep_memory_on_free` is enabled so freed unpack buffers can still be
  dumped; a sample that relies on a fault after `VirtualFree` behaves
  differently.
* The emulated command line is `<emulated image path> <--arg values>` for EXEs,
  instead of Speakeasy's default `svchost.exe myarg1 myarg2` (whose fake
  arguments can steer a sample, and whose `argv[0]` became `ntoskrnl.exe` when
  arguments were given).
* Default `--max-api 10000` (Speakeasy's default) ends API-hammering loops
  quickly; raise it if a run stops with `max_api_count` too early.

## Linux ELF

`rebox run` detects an ELF by its magic and emulates it with Qiling 1.4.10
(Linux user-mode: the CPU is emulated by Unicorn, syscalls are answered in
Python) inside the same `sandbox-exec` profile and self-check as the PE path.
The output is a `rebox.summary/1` object of the same shape;
`emulation.engine` says `qiling …` and `sample.format` is `elf`.

| architecture | static | dynamic (glibc, libraries from the Qiling rootfs) |
|---|---|---|
| x86-64 | tested | tested |
| ARM64 (AArch64) | tested | tested |
| x86 (i386) | tested | libraries fetched, not tested |
| 32-bit ARM, MIPS | code path present, **untested, not a goal**; no rootfs is fetched | no |

### Setup

```
tools/rebox/rebox setup-elf     # ~40 s, needs network, idempotent
    --force         delete and rebuild .venv-elf and elf-rootfs
    --venv-only / --rootfs-only
```

It prints one JSON line (`rebox.setup-elf/1`) and creates, inside this directory only:

* `.venv-elf/`: a second Python 3.12 venv, separate from the Speakeasy `.venv`
  (whose `uv.lock` is unchanged). The recipe, encoded in
  `src/rebox/elfsetup.py`: `cmake<4`, setuptools and wheel into the venv;
  `keystone-engine==0.9.2` built from source with `--no-build-isolation` (so it
  uses that CMake 3.31; the Homebrew CMake 4 rejects keystone's CMakeLists) and
  `--no-cache` (uv's cache can hold a broken keystone wheel without
  `libkeystone.dylib`); Qiling from git tag 1.4.10 (commit `da210f07`) with
  `unicorn==2.1.4` as an override (Qiling pins 2.1.3, which has no arm64 macOS
  wheel and does not compile here). Other versions are pinned by
  `elf-constraints.txt`. A `.pth` file lets that venv import this source tree;
  `rebox-elf-ready.json` records the versions and `uv pip freeze`.
* `elf-rootfs/`: a sparse, shallow checkout of
  [qilingframework/rootfs](https://github.com/qilingframework/rootfs) at commit
  `df3fa4df`, only `lib/` and `lib64/` of `x8664_linux`, `x86_linux` and
  `arm64_linux` (18 MB; the repository's test programs and kernel modules are
  not fetched). Runs never write here and never download anything.

Qiling's `open`/`openat` fail on an arm64 macOS host ("flags were not defined
for hosting ARM64 MACOS"); `rebox.elfemu.patch_qiling` maps that host to the
x86-64 macOS flag table at run time (same values). site-packages is not edited.

Without `.venv-elf`, an ELF run exits 5 and the error names `rebox setup-elf`.
A static ELF needs no rootfs. A dynamically linked ELF whose rootfs is missing
exits 5 with the same hint.

### Isolation (ELF specifics)

* The outer stage reads only the first four bytes of the sample (the ELF
  magic) to pick the interpreter; all parsing (pyelftools) and emulation
  happen in the sandboxed child, which is `.venv-elf/bin/python -I -B -m rebox
  _inner-elf`. The profile is unchanged: it allows exec of exactly that
  interpreter (`PYTHON`/`PYTHON_REAL`), no fork, no network, writes only to
  `out_dir`. The self-check runs first, as for PE. `--no-sandbox` is refused
  for ELF.
* **Network is faked, never real** (`src/rebox/elfnet.py`). Qiling's own socket
  syscalls open host sockets, so rebox replaces all of them (`socket`,
  `socketpair`, `socketcall`, `connect`, `bind`, `listen`, `accept[4]`,
  `send*`, `recv*`, `[gs]etsockopt`, `get{sock,peer}name`, `shutdown`, `poll`,
  `ppoll`, `select`, `pselect6`, `epoll_*`); sockets are Python objects and no
  emulated socket ever becomes a host socket. There is no option to change
  this. `connect` (TCP, UDP, IPv4/6, raw and packet sockets) is recorded and
  succeeds; sends are recorded and reported as fully sent (the first 1 MiB per
  connection is kept: inline in `report.json` up to 256 bytes, otherwise a
  `netsend` dump); reads on a connected stream return end of stream. A DNS
  query sent to port 53 (UDP or TCP) is parsed, the name recorded as a host, and
  answered with the canned address **203.0.113.10** for A queries (no records
  for others); that address and the fake resolver 192.168.1.1 are excluded from
  `indicators.ips`, and a connection to the canned address is labelled with the
  name it was resolved from. `bind`/`listen` are recorded; a non-blocking
  `accept` returns EAGAIN, a blocking one ends that process with stop
  `blocked` (no client ever arrives). AF_UNIX `connect` returns ENOENT (no
  local services; e.g. nscd), netlink sockets EAFNOSUPPORT. HTTP requests in
  sent data become `urls`.
* **Files**: each run gets `out_dir/rootfs`, an APFS `clonefile(2)` copy of the
  pristine rootfs (a plain copy if the output directory is on another volume),
  or a minimal tree for static samples. A small fake system is written into it
  before a baseline snapshot; after the run the tree is diffed, and created or
  modified files become `files_written` and `dropped` dumps (0600, `.bin`),
  removed ones `files_deleted`. All files in the per-run rootfs are made 0600
  (dirs 0700) before and after the run; `chmod` by the sample is recorded but
  not applied to the host file, and `link` makes a copy. Qiling resolves
  paths inside the rootfs; the sandbox blocks writes elsewhere regardless.
* **Processes are recorded, never created.** `fork`/`vfork`/`clone` never call
  the host's fork (the sandbox would refuse it anyway). See below.

### Process model

* **fork/vfork/clone without CLONE_VM: child first.** The parent's registers,
  TLS, memory (unless shared, as with vfork/CLONE_VM), fd table and brk/mmap
  state are saved; the child runs until it exits, execs, is killed by a signal
  to itself, or blocks; then the parent resumes with the child's pid and
  `wait4` reports the child's status. This follows a daemonising sample into
  its child (where the work happens; a child that never ends keeps the rest of
  the run and its parent shows `not_resumed`) and still lets a
  `system()`/`posix_spawn` caller continue after the command.
* **execve: recorded, then the calling process ends** with stop `execve`
  (`indicators.cmdlines` has the shell-quoted path and argv). This reflects
  what really happens (the image is replaced) and, for the usual fork+exec,
  the parent then continues. Returning an error instead would send the sample
  down a failure path that does not exist on a real machine. The target is not
  emulated.
* **Threads (clone with CLONE_VM): parent first, cooperative.** The new thread
  is queued and runs when the current thread blocks on a futex, sleeps,
  yields, waits in poll/select, or exits; a futex wait resumes as a (permitted)
  spurious wake-up. Threads that never ran when `exit_group` is called are run
  first, then the exit takes effect. One thread runs at a time; there is no
  preemption.
* `kill`/`tgkill` to another pid are recorded (`signals`); a fatal signal to
  itself ends the process (stop `signal`). Signal handlers are never invoked
  (no SIGALRM, SIGCHLD delivery). `ptrace(PTRACE_TRACEME)` succeeds and is
  recorded under `anti_analysis`.

### Limits, stop reasons, logging

* `--timeout` is wall-clock time for the emulation, enforced by a watchdog
  thread that stops Unicorn (also inside a CPU loop without syscalls) and by a
  check on every syscall. The outer hard backstop is unchanged.
* `--max-api N` is the **syscall budget** for ELF (default 10000; exact count
  over all processes and threads). There is no instruction limit and no
  instruction count (`instrs` is `null`); `--trace-mem` and `--children` are
  PE-only and rejected for ELF with exit 2.
* Sleeps (`nanosleep`, `clock_nanosleep`, poll/select timeouts) return at once
  and advance a virtual clock that `time`/`clock_gettime`/`gettimeofday` add
  (`emulation.virtual_sleep_s`).
* `emulation.stop`: `exited`, `execve`, `signal`, `blocked` (would wait
  forever: blocking accept, recv on a socket that never receives, pause, a
  futex nobody can wake, poll without timeout and nothing ready),
  `max_syscalls`, `timeout`, `returned`, CPU faults `invalid_read`,
  `invalid_write`, `invalid_fetch`, `invalid_insn`, `cpu_exception`,
  `cpu_error`, and `emulator_error` (Qiling raised; traceback in `run.json`).
  Per-process `runs[].stop` may also be `not_resumed`, `not_run`, `waiting` or
  `killed`.
* **Unsupported syscalls are information, not failures**: the program gets
  `-ENOSYS` and `api.unsupported` lists each name with its count and first pc.
  An exception inside a Qiling handler is treated the same way (listed as
  `name (handler error)`, message in `emulation.errors`). rebox implements the
  `*at` file calls Qiling 1.4.10 lacks (`mkdirat`, `fchmodat`, `renameat[2]`,
  `symlinkat`, `linkat`, ...), which ARM64 libcs use exclusively.
* **Logging is bounded**: per-syscall counts (`api.histogram`) are always exact.
  `syscalls.log` / `report.json["events"]` keep at most 20000 events and 300
  per syscall name; identical consecutive calls collapse into one line with
  `xN`; strings are capped at 512 chars. A sample that loops on a syscall ends
  at the syscall budget with a log of a few lines.

### What the sample sees

* argv[0] is `/tmp/<sample name>` (the sample is copied there, so
  `/proc/self/exe` works); `--arg` values follow. cwd `/tmp`, uid/gid 0 (root),
  pid 2148, ppid 2101 (`-bash`).
* Environment: `PATH`, `HOME=/root`, `USER`/`LOGNAME=root`, `SHELL=/bin/bash`,
  `TERM=xterm-256color`, `LANG=C.UTF-8`, `SHLVL=1`, `PWD=/tmp`, `_`; `--env
  KEY=VALUE` adds or overrides (ELF only).
* `uname`: Linux `web01` `5.15.0-91-generic` `#101-Ubuntu SMP …`, machine per
  architecture. `/etc`: Ubuntu 22.04 `passwd`, `group`, `shadow` (locked),
  `hostname`, `hosts`, `resolv.conf`, `nsswitch.conf`, `os-release`, `crontab`,
  `rc.local`, `/root/.bashrc`, empty `/root/.ssh/authorized_keys`, empty
  placeholders for `/bin/sh`, `busybox`, `wget`, `curl` and others.
  `/proc`: `version`, `cpuinfo` (2-core Xeon, no `hypervisor` flag, or a
  Neoverse-style ARM64), `meminfo`, `uptime`, `loadavg`, `stat`, `mounts`,
  `net/{route,tcp,udp,dev,arp}`, `sys/kernel/*`, entries for pid 1
  (systemd), the shell and the sample, `/proc/self` (cmdline/environ/exe/maps
  served by Qiling or rebox). `/dev/null`, `zero`, `urandom`. stdin is empty
  unless `--stdin*` gives it content (next section).

### Standard input

`--stdin TEXT`, `--stdin-hex HEX` or `--stdin-file PATH` (ELF only) give the
emulated program's fd 0 that content followed by end-of-file, as with
`printf ... | prog`: `read`, `readv` and stdio input see the bytes (tested
with `read` and `fgets`, musl and glibc), then a read returns 0. fd 0 looks like a pipe (`isatty` is false, so stdio
fully buffers stdout as it would in a pipeline). Child processes share the one
read offset, as an inherited stdin does. The outer stage writes the bytes to
`out_dir/stdin.bin` (0600) and the sandboxed stage reads them from there, so
any byte value works and nothing goes through a shell. `--stdin TEXT` is taken
literally: write `--stdin $'benchmark\n'` in a shell for a trailing newline.
`report.json["stdin"]` records `bytes`, `consumed` (how many the program read),
`reads` (read calls on it), `eof_reads` and `sha256`; the summary has
`emulation.stdin` (`bytes`, `consumed`, `reads`) when input was given or the
program read fd 0.

For PE samples the options are refused (exit 2): Speakeasy 2.0.0b9 has no
console-input model (`ReadFile` on the stdin handle and the CRT's
`fgets`/`scanf` are not emulated), so the input could not reach the program.

### Program output, exactly

`stdout.txt` and `stderr.txt` hold the exact bytes the program wrote (every
process, in write order per stream, first 1 MiB each). `report.json["stdout"]`
and `["stderr"]` give `bytes` (written), `saved` (in the file), `file`,
`sha256` of the saved bytes and a `head` preview (lossy UTF-8; do not quote it).
`report.json["output_order"]["runs"]` is the interleaving across the two
streams as `[stream, bytes]` runs at write-syscall granularity (consecutive
writes to one stream merged, at most 20000 runs, `complete` false beyond), e.g.
`[["stdout", 8], ["stderr", 11], ["stdout", 20]]`; with the two files it
rebuilds the combined output exactly. The summary's `strings.output` is only a
de-duplicated list of lines.

### Output directory (ELF)

```
report.json     rebox ELF report (format rebox.elf-report/1): identity, processes, exact syscall
                counts, unsupported syscalls, network (connections, DNS, listeners), fs diff,
                exec regions, program output (sizes, hashes, heads, stdout/stderr write order),
                stdin use, bounded syscall events
run.json        metadata as for PE (sandbox self-check, rootfs source, dumps, errors, env, command line)
summary.json    the summary that was printed
syscalls.log    "pid pc name(args) = ret  # note" per logged event, bounded
qiling.log      Qiling's warnings (capped at 4 MiB)
stdout.txt / stderr.txt   what the program printed, exact bytes (capped at 1 MiB each)
stdin.bin       the standard input given with --stdin* (only then)
rootfs/         the run's private root file system, as the sample left it (0600 files)
dumps/*.bin     dropped (created/modified files), protexec (anonymous memory mapped or
                mprotect-ed executable, e.g. an unpacked UPX image), netsend (sent data > 256 B)
```

Summary differences from PE: `sample` has ELF fields (`bits`, `endian`,
`elf_type`, `linkage`, `interp`, `pie`, `entry`, `stripped`, `upx`, `needed`,
`sections` or load segments); `emulation.runs` has one entry per process or
thread (`pid`, `tid`, `ppid`, `type` main/fork/vfork/clone/thread, `syscalls`,
`stop`, `detail`, `exit_code`, `name` from `PR_SET_NAME`); `api` counts
syscalls, categories are process, file, network, memory, anti_analysis,
timing, discovery, and `api.unsupported` replaces `api.resolved`; extra
indicator kinds are `listening`, `files_probed` (stat/access/readlink and
failed opens), `chmod`, `persistence_paths` (writes under cron, systemd, init,
profile, ssh, ld.so.preload and similar), `process_names`, `signals`,
`raw_sockets`, `anti_analysis`, `modules_loaded` (libraries the dynamic
loader opened); `strings` has `output` (program stdout/stderr lines) and
`net_sent` (printable previews of sent data). Truncation is the same.

Real example: `tests/elfsrc/behave.c` (harmless; reserved addresses and
`.invalid` names) built static for x86-64, default options, 4874 chars
(`out_dir` shortened):

```json
{"schema":"rebox.summary/1","ok":true,"sample":{"name":"behave-x86_64.elf","sha256":"30b1074c71a88a6ae7e058556eeaee5e6264136380e3533754831d827e61d736","size":72600,"format":"elf","arch":"x86-64","bits":64,"endian":"little","elf_type":"exec","linkage":"static","interp":null,"pie":false,"entry":"0x10048d0","stripped":true,"upx":false,"needed":{"total":0,"top":[]},"sections":{"total":7,"top":[".rodata r-- size=0x13c0 H=4.9",".eh_frame_hdr r-- size=0x624 H=4.65",".eh_frame r-- size=0x1d10 H=4.67",".text r-x size=0xdebf H=6.46",".tbss rw- size=0x4 H=0.0",".data rw- size=0x100 H=0.95",".bss rw- size=0x8788 H=0.0"]}},"emulation":{"engine":"qiling 1.4.10 / unicorn 2.1.4","backend":"qiling (Linux user-mode syscall emulation)","sandbox":"sandbox-exec: no network, writes only to out_dir","wall_s":0.41,"emu_s":0.01,"timeout_s":60,"stop":"exited","stop_detail":"exit_group(7)","virtual_sleep_s":0.0,"syscall_budget":10000,"instrs":null,"runs":{"total":2,"top":[{"pid":2148,"ppid":2101,"type":"main","start":"0x10048d0","syscalls":67,"stop":"exited","exit_code":7,"pc":"0x100555e","name":"kworker/0:1","detail":"exit_group(7)"},{"pid":2149,"ppid":2148,"type":"fork","start":"0x100998c","syscalls":4,"stop":"execve","pc":"0x10120d5","detail":"/bin/sh -c 'echo rebox-test > /tmp/.rebox-exec'"}]},"errors":{"total":0,"top":[]}},"api":{"kind":"syscalls","calls":71,"events":71,"unique":32,"note":"syscall counts are exact; `events` is the bounded per-call log in syscalls.log (0 calls not logged); unsupported syscalls returned -ENOSYS","histogram":{"total":32,"top":[["close",10],["open",6],["rt_sigprocmask",6],["read",5],["socket",4],["write",3],["fcntl",3],["clock_gettime",3],["sendto",3],["set_tid_address",2],["writev",2],["bind",2],["munmap",2],["connect",2],["arch_prctl",1],["uname",1],["ioctl",1],["mkdir",1],["chmod",1],["unlink",1],["poll",1],["recvmsg",1],["sched_getaffinity",1],["mmap",1],["recvfrom",1],["listen",1],["accept",1],["prctl",1],["fork",1],["execve",1],["wait4",1],["exit_group",1]]},"categories":{"file":{"total":4,"top":[["open",6,"0x100d6ec"],["mkdir",1,"0x1009a9f"],["chmod",1,"0x1009a89"],["unlink",1,"0x1012105"]]},"network":{"total":8,"top":[["socket",4,"0x1009580"],["sendto",3,"0x100d6ec"],["bind",2,"0x10059fc"],["connect",2,"0x100d6ec"],["recvmsg",1,"0x100d6ec"],["recvfrom",1,"0x100d6ec"],["listen",1,"0x100642a"],["accept",1,"0x100d6ec"]]},"discovery":{"total":2,"top":[["uname",1,"0x1012095"],["sched_getaffinity",1,"0x1012198"]]},"process":{"total":4,"top":[["prctl",1,"0x100599c"],["fork",1,"0x100998c"],["execve",1,"0x10120d5"],["wait4",1,"0x100d6ec"]]}},"unsupported":{"total":0,"top":[]}},"indicators":{"hosts":{"total":1,"top":["beacon.rebox-test.invalid"]},"urls":{"total":1,"top":["http://beacon.rebox-test.invalid/stage2.bin"]},"ips":{"total":1,"top":["198.51.100.7"]},"conns":{"total":4,"top":["udp dns 192.168.1.1:53 sent=43B","tcp connect 203.0.113.10:80 (beacon.rebox-test.invalid via canned DNS) sent=89B","tcp.http GET http://beacon.rebox-test.invalid/stage2.bin","tcp connect 198.51.100.7:4444 sent=16B"]},"ports":{"total":3,"top":["80","4444","2323"]},"listening":{"total":1,"top":["tcp 0.0.0.0:2323"]},"files_written":{"total":4,"top":["/tmp/.rebox-drop.txt","/tmp/.rebox-dir/","/tmp/.rebox-gone.txt","/tmp/.rebox-after-fork.txt"]},"files_read":{"total":3,"top":["/etc/passwd","/etc/hosts","/etc/resolv.conf"]},"files_deleted":{"total":1,"top":["/tmp/.rebox-gone.txt"]},"chmod":{"total":1,"top":["/tmp/.rebox-drop.txt 0755"]},"cmdlines":{"total":1,"top":["/bin/sh -c 'echo rebox-test > /tmp/.rebox-exec'"]},"process_names":{"total":1,"top":["kworker/0:1"]},"empty":["files_probed","persistence_paths","signals","raw_sockets","anti_analysis","modules_loaded"]},"payloads":{"total":2,"top":[{"kind":"dropped","file":"dumps/dropped_.rebox-after-fork.txt_d62072918fea.bin","size":15,"sha256":"d62072918fea8347cc595222b75506de0982803b705497e43daaad14302151ae","name":".rebox-after-fork.txt","emu_path":"/tmp/.rebox-after-fork.txt","change":"created"},{"kind":"dropped","file":"dumps/dropped_.rebox-drop.txt_95d06740e515.bin","size":19,"sha256":"95d06740e5152ae6e21ad8d0376b699e2985ef9a32265f433827980a0b4670f5","name":".rebox-drop.txt","emu_path":"/tmp/.rebox-drop.txt","change":"created"}]},"payloads_not_saved":{"total":0,"top":[]},"strings":{"output":{"total":7,"top":["hello from Linux web01 x86_64","passwd bytes=255","resolved beacon.rebox-test.invalid -> 203.0.113.10","connect=0","sent=16 recv=0","accept=-1 errno=11","child 2149 status=0"]},"net_sent":{"total":2,"top":["203.0.113.10:80 GET /stage2.bin HTTP/1.1..Host: beacon.rebox-test.invalid..User-Agent: rebox-test/1.0....","198.51.100.7:4444 HELLO rebox-test"]}},"out_dir":"/private/tmp/…/ex","raw_report":"report.json","truncated":null}
```

### Known limits (ELF)

* **No kernel.** Syscalls are emulated individually; there is no scheduler,
  no signal delivery, no real `/proc` beyond the files listed above, no
  `memfd_create` (recorded under `anti_analysis`, returns ENOSYS), and many
  ioctls are missing. Programs that depend on these take other paths or stop.
* **Multi-threaded programs** run cooperatively, one thread at a time; code
  that spins waiting for another thread without a syscall hits the timeout,
  and futex-based waits can ping-pong until the syscall budget. **Go
  binaries** (own scheduler, many threads, signals) are not expected to get
  far.
* **A sample can detect the emulator**: timing, missing syscalls, CPU feature
  quirks, `/proc` contents, the fixed environment above.
* **glibc-dynamic name resolution**: the rootfs has no `libnss_dns`/
  `libnss_files`, so glibc's `getaddrinfo`/`gethostbyname` fail before any
  DNS packet. rebox hooks those libc functions to record the queried name
  (`report.json` `network.libc_lookups` and `hosts`), but the sample sees the
  failure. Static musl and other libcs that query DNS themselves get the canned
  answer.
* The rootfs glibc is old (2.2x); dynamic samples that need newer symbol
  versions fail in the dynamic loader (visible in `strings.output`).
* Output still buffered in the program when a process ends without
  `exit` (blocked, killed, timeout) is lost.
* Fake sockets have no host fd: `fstat` on one reports a socket, other
  fd-level operations on them are minimal.
* ARM and MIPS (32-bit) are not a goal: the code path exists, nothing is
  tested, and no rootfs is fetched for them.
