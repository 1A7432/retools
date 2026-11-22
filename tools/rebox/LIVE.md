# rebox live

`rebox live` **executes** a Linux ELF sample for real, under a syscall tracer,
inside a locked-down Docker container that has no network, and prints one
compact JSON behaviour summary (same conventions as `rebox run`). It is the
high-fidelity complement to emulation: threads, `fork`/`execve`, Go runtimes
and real libc behaviour all work, because nothing is emulated except the CPU
for non-ARM64 samples.

This is real execution of hostile code. The owner has accepted the residual
risk of Docker containment; what Docker does and does not contain here is
spelled out under [Isolation](#isolation) and [What remains](#what-remains).
Use `rebox run` (emulation) first when it is good enough.

Verified on macOS 26 / Apple Silicon, OrbStack (Docker server 29.8.2,
linux/arm64, kernel 7.2.12-orbstack), 2026-11-14.

## Usage

```
rebox live-setup [--no-cache]          build the image rebox-live:1 (needs network, once)
rebox live <sample> [options]          run a sample
    --timeout N      seconds the sample may run (default 60)
    --out DIR        output directory, must be new or empty
                     (default tmp/rebox-runs/<sha256[:12]>-live-<YYYYmmdd-HHMMSS>)
    --max-chars N    size limit of the printed summary (default 6000)
    --arg ARG        argument for the sample, repeatable (--arg=-x for dash values)
    --user           run as uid 1000 instead of root-without-capabilities
    --fakenet        answer DNS / accept TCP inside the container (still no route out)
    --memory 1g  --cpus 2  --pids 256          container limits
    --max-output 1m  bytes kept of stdout and of stderr
    --max-file 512m  RLIMIT_FSIZE for every process in the container
    --max-disk 2g    stop the run when the container has used this much disk
    --max-dump 256m  total size of changed files copied out
    --strsize 4096   strace -s (bytes shown per string / buffer)
rebox live --cleanup                   remove leftover rebox-live containers
rebox live-summarize <out_dir> [--max-chars N]
```

Until the subcommands are mounted in `cli.py`, the same works as
`.venv/bin/python -I -B -m rebox.live <sample> ...` (`setup`, `summarize`,
`--cleanup` likewise; the word `live` may be omitted). For the CLI:
`live.add_parsers(subparsers)` adds `live`, `live-setup`, `live-summarize`;
`live.main(args)` runs whichever was chosen (dispatch via `args._live_cmd`).

stdout is always exactly one JSON object; diagnostics go to stderr.

| exit | meaning |
|---|---|
| 0 | the sample ran and a summary was produced (whatever the sample did, including a timeout) |
| 2 | usage error |
| 3 | isolation unavailable or not verified: Docker not running, image missing or not a rebox-live image, `docker inspect` shows a weaker configuration than requested, or the in-container self-check failed. The sample was **not** run |
| 4 | tool failure (Docker command failed, in-container runner error, collection failed) |
| 5 | unsupported input: not ELF, not an executable, or an architecture other than aarch64 / x86_64 / x86. Refused before any container is created |
| 6 | the container outlived the host backstop (`timeout + max(30, timeout)` s) and was killed from the host; `summary.json` is still written |
| 130 | interrupted (Ctrl-C, SIGTERM, SIGHUP); the container was removed |

On a non-zero exit the JSON is `{"schema", "ok": false, "mode": "live", "exit", "error", "out_dir"?}`.

### Output directory

```
run.json             metadata: sample identity, image id + package versions, the exact docker create
                     arguments, inspect check, runner/container state, fs changes, dumps, errors
summary.json         the printed summary
container/trace/t.N  strace -ff output, one file per process/thread id (the full raw trace)
container/netcheck.json   the in-container isolation self-check
container/status.json     how the run ended (runner's view)
container/stdout.bin, stderr.bin   the sample's output (first --max-output bytes each)
container/fakenet.jsonl   fake network sink log (--fakenet)
fs_changes.json      every change Docker reports for the container file system
dumps/*.bin          created/modified files copied out (0600, never executable)
```

## Summary (`rebox.summary/1`, `"mode": "live"`)

Conventions as in README.md: lists are `{"total", "top"}`, strings longer than
160 chars end in `…[+N]`, lists are shortened round-robin to fit
`--max-chars` and `truncated` names what was cut (weights: indicators,
payloads, processes first; the syscall histogram last).

| key | content |
|---|---|
| `sample` | name, sha256, size, arch, bits, endian, elf_type, linkage (`static`/`dynamic`/`static-pie`), interp, go, stripped, entry |
| `execution` | engine (`strace … (native arm64)` or `strace … over qemu-x86_64 (qemu-user …)`), image tag + id, isolation, run_as, fakenet, wall_s, sample_s, timeout_s, `stop` (`exited`, `timeout`, `disk_limit`, `oom_killed`, `backstop_kill`, `runner_error`), exit_code / signal of the first process, `processes` (`pid<-ppid command [exit …] emu=…`), `alive_at_stop`, container_removed, errors |
| `syscalls` | calls, unique, `histogram`, `failed` (`connect ENETUNREACH` …), `categories` (file, network, process, memory, anti_analysis, privilege) |
| `indicators` | hosts (names in DNS queries, HTTP Host, TLS SNI), ips, conns (`tcp connect 198.51.100.7:4444 ENETUNREACH`), ports, urls, data_out, listening, unix_sockets, cmdlines (execve argv, shell-quoted), files_written, files_deleted, files_renamed, files_chmod, persistence (writes to cron/systemd/rc/profile/ld.so.preload/authorized_keys/system bin dirs …), etc_changed, proc_names (`prctl(PR_SET_NAME)`), memfd, privilege, anti_analysis (ptrace, /proc/self/status, /.dockerenv, DMI …), signals_sent, files_read (loader/libc noise removed); `empty` lists keys with nothing. A failed attempt carries its errno: `/etc/cron.d/x [EACCES]` |
| `fakenet` | (only with `--fakenet`) DNS questions and TCP sessions the sink saw, with the first bytes, HTTP request line and TLS SNI |
| `fs_changes` | added / changed / deleted paths from Docker (rebox's own files and runtime injections removed) |
| `payloads` | files copied out: `{kind: added/modified/etc_modified, file, size, sha256, path, mode}` |
| `payloads_not_saved` | changed files not copied (budget, links, special files) |
| `output` | byte counts and the first 300 printable chars of stdout/stderr |

Without `--fakenet`, connects fail with `ENETUNREACH` and DNS lookups get no
answer; the attempts are the indicators. The container's resolver is set to
`127.0.0.1` (`--dns 127.0.0.1`) so that a lookup turns into a visible DNS
query on loopback (the name is parsed from the packet in the trace) instead of
an early connect error to an unreachable resolver.

## Trace mechanism per architecture

Only aarch64, x86_64 and x86 (i386) are supported (owner's scope). Everything
is traced by **`strace -f -ff -ttt -q -s 4096 --kill-on-exit`** (strace
6.13, Debian trixie) running inside the container; `-f` follows every
`fork`/`clone`/`vfork` and every `execve`, `-ff` writes one file per thread so
no line is ever interleaved, `--kill-on-exit` (`PTRACE_O_EXITKILL`) kills all
tracees if strace dies.

| sample | how it runs | observed |
|---|---|---|
| aarch64 (static or dynamic) | natively, directly under strace | full fidelity; works with all capabilities dropped (tracing one's own children needs none; Docker's default seccomp profile allows ptrace on this kernel; Yama ptrace_scope is 0) |
| x86_64 | `strace … qemu-x86_64 -L / <sample>` (qemu-user 10.0.13, static build) | the trace shows QEMU's host syscalls: every guest syscall QEMU forwards (x86 `open`/`fork` appear as `openat`/`clone`), with buffers, sockaddrs and argv fully decoded, plus QEMU's own startup and `mmap`/signal/futex traffic and one helper thread per process. Dynamically linked programs use the multiarch `libc6:amd64` in the image |
| x86 (i386) | same with `qemu-i386` and `libc6:i386` | verified with a static program |

Why not QEMU's own `-strace`: tried; its log decodes less (`connect(3,0xb5e4ed3c,16)`
without the address, buffers as pointers), lines of different processes
interleave mid-line after `fork`, and with `-D` its unbuffered log writes show
up in the outer trace. The outer strace view is strictly more useful, so it is
the only mechanism.

Why not Rosetta: OrbStack registers a binfmt handler for x86-64 in its VM,
visible inside containers (an x86-64 ELF exec'd from an arm64 container just
runs; whether it is Rosetta or OrbStack's own QEMU is not visible from
inside). It works under strace too, but it is OrbStack's configuration, not
ours, so rebox starts the sample explicitly under the image's QEMU.
Consequence (observed): when an emulated x86-64 sample `execve`s **another
x86-64 binary** (a dropped payload, or itself), QEMU passes the `execve` to the
kernel, so the new image runs under OrbStack's handler, not under rebox's
QEMU. strace still follows it (its file/network/exec activity is traced), but
the handler adds thousands of its own `mmap` calls to the histogram. Native
children (`/bin/sh`, `/bin/busybox` …) run natively and are traced normally.

## Isolation

All of the following are mandatory; there is no flag that weakens them and no
flag that gives the sample a real network. If one cannot be applied or
verified, the run stops with exit 3 before the sample starts.

The exact `docker create` arguments (also stored in `run.json`):

```
docker create --name rebox-live-<sha12>-<pid>-<rand>
  --label rebox-live=run --label rebox-live.pid=<pid> --label rebox-live.host=<host>
  --label rebox-live.sha256=<sha256> --label rebox-live.deadline=<epoch>
  --network none --dns 127.0.0.1 --hostname debian
  --cap-drop ALL                    (--fakenet: --cap-add NET_ADMIN --cap-add SETPCAP,
                                     --user --fakenet: also SETUID SETGID; all dropped before exec)
  --security-opt no-new-privileges
  --pids-limit 256 --memory 1073741824 --memory-swap 1073741824 --cpus 2
  --ulimit core=0 --ulimit nofile=4096:4096 --ulimit fsize=536870912:536870912
  --ipc private --cgroupns private --log-driver none --stop-timeout 1
  [--user 1000:1000]                (--user without --fakenet)
  sha256:<image id>
```

| measure | protects against | does not protect against |
|---|---|---|
| `--network none`, verified twice: `docker inspect` (NetworkMode `none`, no networks) and, inside, before the sample: only `lo` in `/proc/net/dev` and `/sys/class/net`, every IPv4/IPv6 route in every table on `lo` (`ip -j route show table all`), TCP/UDP to 198.51.100.1 and TCP to 2001:db8::1 fail with `ENETUNREACH`, DNS fails | any packet leaving the container: C2, downloads, scanning, exfiltration, lateral movement | nothing on the network side; but see "kernel" below |
| no bind mounts, volumes, tmpfs, devices; the sample goes in and results come out through `docker cp` tar streams. Verified by inspect (Mounts/Binds/Tmpfs/Devices/VolumesFrom empty, image declares no VOLUME) and inside (no virtiofs/9p/fuse/nfs/cifs/fakeowner mount, no bind mount except Docker's own `/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, which live in the OrbStack VM's per-container directory) | reading or writing Mac files through a shared path, which is the main way a container reaches the host | — |
| no Docker/containerd/OrbStack socket inside (checked) | the sample driving Docker to start a privileged container | — |
| `--cap-drop ALL` + `no-new-privileges` (verified by inspect and from the sample's own `/proc/self/status`: CapInh/Prm/Eff/Bnd/Amb all zero, NoNewPrivs 1) | mount, raw sockets, module loading, ptrace of other users, setuid binaries regaining privilege, most kernel attack surface that needs a capability | kernel bugs reachable without capabilities |
| Docker's default seccomp profile (kept) and private pid/ipc/uts/cgroup namespaces | many rarely used syscalls; seeing or signalling host processes | — |
| `--pids-limit`, `--memory` (= swap), `--cpus`, `nofile`, `core=0` | fork bombs, memory exhaustion, CPU starvation of the Mac | — |
| `RLIMIT_FSIZE` (`--max-file`) + in-container disk watch (`--max-disk`, stops the run) + timeout | filling the OrbStack VM disk with one file / quickly | a hard quota: overlayfs here ignores `--storage-opt size` (tested), so the watch is a 0.25 s poll of free space and other VM activity can blur it |
| timeout inside (runner kills strace, `--kill-on-exit` kills every tracee) + host backstop (`docker kill`) + always `docker rm -f`, also on Ctrl-C/SIGTERM/errors; containers carry labels (owner pid, host, deadline) and every run, or `--cleanup`, removes leftovers whose owner is gone or whose deadline has passed | runaway or daemonised samples, crashed rebox runs | — |
| host side treats everything from the container as hostile: tar members are never extracted with `tarfile.extract`; only regular files with the exact names the runner writes are accepted from `/rebox/out` (no `..`, absolute paths, links or devices are ever written), dumps are first members of single-file `docker cp` streams, written `O_EXCL|O_NOFOLLOW`, 0600, `.bin`, names sanitised, sizes bounded; the trace parser masks every string literal before matching, so file names or buffers cannot forge strace syntax; diff paths come from the Engine API as JSON (a newline in a file name cannot add entries) | path traversal, symlink tricks, parser confusion on the Mac | bugs in the `docker` CLI's own tar handling (it streams the archive the daemon produced; rebox never asks it to extract on the host) |

### Root or not

Default: the sample runs as **root (uid 0) with no capabilities**. Many
Linux samples branch on `geteuid() == 0` and only then write their real
persistence (`/etc/cron.d`, systemd units, `/etc/rc.local`,
`/etc/ld.so.preload`, replacing binaries in `/usr/bin`); uid 0 owns those
files, so these writes succeed and are visible even without capabilities.
Cost: container uid 0 is uid 0 of the OrbStack VM (no user-namespace
remapping), which matters only after a kernel escape. `--user` runs it as uid
1000 instead (cheaper escape impact, less behaviour; also protects the trace
files from the sample when combined with `--fakenet`, see below).

### What remains

* **Shared kernel.** The container shares the OrbStack VM's Linux kernel. A
  kernel exploit reachable without capabilities under the default seccomp
  profile escapes the container as root of that VM. **The OrbStack VM can
  reach the Mac's files** (OrbStack shares the macOS file system into its VM)
  and the Mac's network, so an escape is close to compromising the user's Mac
  account. This is the main residual risk; keep OrbStack updated.
* **Evidence integrity.** Everything in the container (trace files,
  `status.json`, stdout) is writable by the sample when it runs with the
  tracer's uid (the default, and `--user` without `--fakenet`). A sample
  that looks for and rewrites `/rebox/out` can falsify its own record. The
  host treats it as untrusted data; it cannot be trusted as complete. The
  isolation self-check runs before the sample starts, so tampering cannot
  bypass it.
* **Detectability.** The sample can see it is traced (`ptrace(TRACEME)`
  fails, `TracerPid` in `/proc/self/status`), emulated (QEMU), in a container
  (`/.dockerenv`-like signs, cgroups, hostname `debian`, Docker-generated
  `/etc/hosts`), and without network. Evasive samples may do nothing.
* **Not covered by docker diff.** `/etc/hosts`, `/etc/resolv.conf`,
  `/etc/hostname` are bind-mounted by Docker; rebox compares them with a
  baseline the runner records before the sample starts (`etc_changed`).
  OrbStack injects `/usr/local/share/ca-certificates/orbstack-root.crt` into
  every container at start; the runner lists paths not in the image manifest
  before the sample runs, and unchanged ones are left out of `fs_changes`.
* **Time and resources.** A sample can use its full CPU/memory allowance for
  `--timeout` seconds and write up to `--max-disk` (approximately).
* The image contains Python 3, iproute2 and nftables (runner, self-check,
  fake network); the sample can use them like any other program in the image.
* AppArmor is enabled in OrbStack; whether Docker's default AppArmor profile
  is applied to these containers was not checked.

## `--fakenet`

Keeps `--network none` and the self-check (which runs first, unchanged). Then,
still before the sample starts and with the only two capabilities added for
this purpose, the runner:

1. adds `local 0.0.0.0/0 dev lo table local`: every IPv4 address becomes local
   to the loopback interface, so nothing can be routed anywhere;
2. adds one nftables rule: TCP not aimed at 127.0.0.0/8 is redirected to port
   65000;
3. re-checks: still only `lo`, every route on `lo`;
4. removes every capability from its bounding set (`PR_CAPBSET_DROP`), starts
   the sink with no capabilities, starts strace whose child clears ambient /
   effective / permitted sets (and for `--user` switches to uid 1000) and
   refuses to exec if any capability remains; the runner then drops its own.

The sink (`docker/fakenet.py`) answers every DNS A query on UDP 0.0.0.0:53 with
203.0.113.1 (other types: empty answer), accepts TCP on any port, records the
original destination (`SO_ORIGINAL_DST`) and up to 4 KiB of what the client
sends, and never sends anything back. Verified with static musl, dynamic glibc
x86-64 and native arm64 programs (DNS answered, connect to 198.51.100.7:4444
accepted, `HELLO rebox` recorded) and from the sample's own view (capabilities
all zero, only `lo`). Limits: IPv4 only (IPv6 connects still fail with
`ENETUNREACH`); UDP other than DNS is not answered; a sample waiting for a
server greeting or TLS handshake sees silence and may give up; with root (the
default) the sample can kill the sink.

## Image

`docker/Dockerfile`: `debian:trixie-slim` pinned by digest
(`sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`),
`strace`, `qemu-user` (static), `python3`, `iproute2`, `nftables`,
`libc6`/`libgcc-s1`/`libstdc++6`/`zlib1g` for amd64 and i386. Package versions
cannot be pinned without a snapshot mirror; the installed versions
(`/opt/rebox-live/packages.txt`) and the image id are stored in every
`run.json`. Versions at build time: strace 6.13+ds-1, qemu-user
1:10.0.13+ds-0+deb13u1, libc6 2.41-12+deb13u4, python3 3.13.5-1. The image is
labelled `rebox-live=image`; rebox refuses an image without that label or with
volumes. Building needs network; nothing at run time does. Helpers in the
image: `runner.py` (PID 1: self-check, fakenet setup, strace, limits, status),
`netcheck.py` (the self-check, also runnable alone), `fakenet.py`.

## Tests

`tests/test_live_unit.py` (no Docker): trace parsing incl. forged syntax in
file names, DNS/HTTP/SNI parsing, tar extraction with traversal, links,
devices and oversize members, dump naming, `docker create` flags, the inspect
check accepting the right and refusing weaker configurations, refusal of other
architectures before Docker is contacted, fail-closed when Docker or the image
is missing, the summary budget.

`tests/test_live_docker.py` (skipped with the reason when Docker is down, the
image is not built or zig is missing): the behaviour program (writes a file,
resolves `c2.rebox-test.invalid`, connects to 198.51.100.7:4444, forks,
execs `/bin/sh -c "echo …"`, exits 42) as arm64 static, x86-64 static, x86-64
dynamic and i386 static; a probe program that reports its own view
(capabilities, interfaces, mounts, connect result, Docker socket, uid) in the
default, `--user`, `--fakenet` and `--user --fakenet` modes; a program that
sleeps forever killed at `--timeout 3` with `stop: timeout` (x86-64 and
arm64); container removal after a normal run, a timeout, a simulated
collection failure and Ctrl-C; leftover detection and `--cleanup`. All test
programs are small C sources in the test file, compiled with zig.
