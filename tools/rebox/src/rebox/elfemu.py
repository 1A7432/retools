"""Inner stage for Linux ELF samples: Qiling under the sandbox.

Runs with the separate Qiling environment (.venv-elf), started by the outer
stage as `python -I -B -m rebox _inner-elf ...` inside sandbox-exec. Like the
PE inner stage it proves the sandbox is active before it touches the sample.

Output directory layout (in addition to run.json / dumps/ like the PE path):
    report.json    rebox ELF report (format rebox.elf-report/1): identity,
                   processes, exact per-syscall counts, unsupported syscalls,
                   network, file-system diff, bounded syscall event list
    syscalls.log   one line per logged syscall event (bounded, see MAX_EVENTS)
    qiling.log     Qiling's own warnings (bounded)
    stdout.txt / stderr.txt   what the program printed, exact bytes (bounded);
                   report.json "output_order" interleaves them
    stdin.bin      written by the outer stage when --stdin* was given; fd 0
                   serves it, then end-of-file (StdinInput)
    rootfs/        the run's private root file system (cloned from the
                   pristine rootfs, which is never written)

Design decisions (also in the README):
* Every syscall goes through ElfEmu.syscall(), which replaces Qiling's
  dispatcher: exact counts, a bounded event log, the syscall budget
  (--max-api) and the time budget are enforced there. Syscalls Qiling does not
  implement return -ENOSYS to the program and are listed as unsupported.
* Network: rebox.elfnet; nothing reaches a host socket.
* Processes: fork/vfork/clone run the child first ("child-first"): the
  parent's registers (and, unless memory is shared, its memory, fd table and
  brk/mmap state) are saved, the child runs until it exits, execs, or blocks,
  and then the parent resumes with the child's pid, as if the child had
  finished. A child that never ends (a daemon's main loop) keeps the rest of
  the run; its parent is not resumed. Threads (clone with CLONE_VM) are run
  the same way, sequentially. No host process is ever created (and the
  sandbox denies fork/exec anyway).
* execve: recorded (path, argv, env count) and the calling process ends with
  stop reason `execve` (its image would have been replaced). In a fork child
  that means the parent then resumes and wait4() reports exit status 0.
* Sleeps return at once and advance a virtual clock seen by time syscalls.
"""

from __future__ import annotations

import ctypes
import hashlib
import inspect
import io
import json
import os
import shlex
import shutil
import stat
import struct
import threading
import time
import traceback
from collections import Counter
from pathlib import Path

from . import elfnet, sandbox
from .elfnet import LINUX_ERRNO, LE
from .emulate import DumpWriter, _write_private

FORMAT = "rebox.elf-report/1"
MAX_EVENTS = 20000          # syscall events kept in report.json / syscalls.log
MAX_EVENTS_PER_NAME = 300   # per syscall name; further calls are only counted
MAX_LOG_BYTES = 4 << 20     # qiling.log
MAX_OUTPUT_BYTES = 1 << 20  # stdout.txt / stderr.txt each
MAX_ORDER_RUNS = 20000      # stdout/stderr interleaving runs kept in report.json
MAX_STDIN_BYTES = 1 << 20   # --stdin* content
MAX_PROCESSES = 64          # fork/clone beyond this returns EAGAIN
MAX_DEPTH = 16              # nested child-first contexts
STR_CAP = 512

# -- the fake system the sample sees ---------------------------------------------------------
HOSTNAME = "web01"
KERNEL_RELEASE = "5.15.0-91-generic"
KERNEL_VERSION = "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
MAIN_PID = 2148
PPID = 2101                 # a login shell
UPTIME = 386412.53
MACHINE = {"x86-64": "x86_64", "x86": "i686", "arm64": "aarch64", "arm": "armv7l", "mips": "mips", "mipsel": "mips"}
DEFAULT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root", "USER": "root", "LOGNAME": "root", "SHELL": "/bin/bash",
    "TERM": "xterm-256color", "LANG": "C.UTF-8", "SHLVL": "1", "PWD": "/tmp",
}
SUPPORTED = ("x86-64", "x86", "arm64")          # tested
UNTESTED = ("arm", "mips", "mipsel")            # code path exists, not a goal

# syscall name -> indexes of C-string arguments worth decoding
STR_ARGS = {
    "open": (0,), "creat": (0,), "openat": (1,), "openat2": (1,), "unlink": (0,), "unlinkat": (1,),
    "rename": (0, 1), "renameat": (1, 3), "renameat2": (1, 3), "mkdir": (0,), "mkdirat": (1,), "rmdir": (0,),
    "chmod": (0,), "fchmodat": (1,), "chown": (0,), "lchown": (0,), "fchownat": (1,), "chown32": (0,),
    "lchown32": (0,), "stat": (0,), "stat64": (0,), "lstat": (0,), "lstat64": (0,), "newfstatat": (1,),
    "fstatat64": (1,), "statx": (1,), "access": (0,), "faccessat": (1,), "faccessat2": (1,), "readlink": (0,),
    "readlinkat": (1,), "chdir": (0,), "symlink": (0, 1), "symlinkat": (0, 2), "link": (0, 1), "linkat": (1, 3),
    "truncate": (0,), "truncate64": (0,), "utimensat": (1,), "statfs": (0,), "statfs64": (0,), "mknod": (0,),
    "mknodat": (1,), "execve": (0,), "execveat": (1,), "chroot": (0,), "mount": (0, 1, 2), "umount2": (0,),
    "swapon": (0,), "delete_module": (0,), "sethostname": (0,), "memfd_create": (0,), "inotify_add_watch": (1,),
    "utime": (0,), "utimes": (0,), "setxattr": (0, 1), "getxattr": (0, 1), "listxattr": (0,),
}
WRITE_OPS = {"unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chmod",
             "fchmodat", "chown", "lchown", "fchownat", "symlink", "symlinkat", "link", "linkat", "truncate",
             "truncate64", "mknod", "mknodat", "utimensat", "utime", "utimes", "setxattr"}
PROBE_OPS = {"stat", "stat64", "lstat", "lstat64", "newfstatat", "fstatat64", "statx", "access", "faccessat",
             "faccessat2", "readlink", "readlinkat", "statfs", "statfs64", "getxattr", "listxattr"}
CLONE_VM, CLONE_FILES, CLONE_VFORK, CLONE_THREAD = 0x100, 0x400, 0x4000, 0x10000
CLONE_SETTLS, CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID = 0x80000, 0x100000, 0x200000, 0x1000000
FATAL_SIGNALS = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 15: "SIGTERM"}
SIGNAMES = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 10: "SIGUSR1", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM",
            17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 0: "0", **FATAL_SIGNALS}


def patch_qiling():
    """Runtime fix: Qiling has no open(2) flag table for an arm64 macOS host.

    Its open/openat raise NotImplementedError ("flags were not defined for
    hosting ARM64 MACOS"). The macOS flag values are the same on arm64 and
    x86-64, so the x86-64 macOS table is used. Applied in-process; nothing in
    site-packages is edited.
    """
    from qiling.const import QL_ARCH, QL_OS
    from qiling.os.posix import const_mapping as cm

    if getattr(cm.get_open_flags_class, "_rebox", False):
        return
    orig = cm.get_open_flags_class

    def patched(archtype, ostype):
        if ostype == QL_OS.MACOS and archtype == QL_ARCH.ARM64:
            archtype = QL_ARCH.X8664
        return orig(archtype, ostype)

    patched._rebox = True
    cm.get_open_flags_class = patched
    # fcntl.py imported the name directly
    import qiling.os.posix.syscall.fcntl as fcntl_mod
    if getattr(fcntl_mod, "get_open_flags_class", None) is orig:
        fcntl_mod.get_open_flags_class = patched


# ---------------------------------------------------------------------------------------------
# ELF identity (runs inside the sandbox; the outer stage only checks the magic)
# ---------------------------------------------------------------------------------------------

def elf_header_arch(data: bytes) -> tuple[str | None, str]:
    """Fixed-offset ELF header check -> (rebox arch or None, description)."""
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None, "not an ELF file"
    cls, enc = data[4], data[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return None, f"bad ELF class/encoding {cls}/{enc}"
    machine = struct.unpack("<H" if enc == 1 else ">H", data[18:20])[0]
    bits = 32 if cls == 1 else 64
    little = enc == 1
    arch = {(62, 64): "x86-64", (3, 32): "x86", (183, 64): "arm64", (40, 32): "arm"}.get((machine, bits))
    if machine == 8 and bits == 32:
        arch = "mipsel" if little else "mips"
    if arch == "arm" and not little:
        arch = None
    if arch in ("x86-64", "x86", "arm64") and not little:
        arch = None
    return arch, f"e_machine {machine:#x}, {bits}-bit, {'little' if little else 'big'}-endian"


def _entropy(data: bytes) -> float:
    from .emulate import _entropy as e

    return e(data)


def elf_identity(path: str) -> dict:
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as f:
        raw = f.read()
    arch, desc = elf_header_arch(raw[:64])
    ident: dict = {"format": "elf", "arch": arch, "header": desc}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        ident["bits"] = elf.elfclass
        ident["endian"] = "little" if elf.little_endian else "big"
        etype = elf["e_type"]
        ident["elf_type"] = {"ET_EXEC": "exec", "ET_DYN": "dyn", "ET_REL": "rel", "ET_CORE": "core"}.get(etype, etype)
        ident["os_abi"] = elf["e_ident"]["EI_OSABI"]
        ident["entry"] = hex(elf["e_entry"])
        interp = None
        needed = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_INTERP":
                interp = seg.get_interp_name()
            elif seg["p_type"] == "PT_DYNAMIC":
                try:
                    needed = [t.needed for t in seg.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
                except Exception:
                    pass
        ident["interp"] = interp
        ident["linkage"] = "dynamic" if interp else "static"
        ident["pie"] = etype == "ET_DYN"
        ident["needed"] = needed
        ident["stripped"] = elf.get_section_by_name(".symtab") is None
        secs = []
        for s in elf.iter_sections():
            if not s["sh_flags"] & 0x2 or not s.name:  # SHF_ALLOC
                continue
            fl = s["sh_flags"]
            perms = "r" + ("w" if fl & 0x1 else "-") + ("x" if fl & 0x4 else "-")
            data = b"" if s["sh_type"] == "SHT_NOBITS" else s.data()
            secs.append({"name": s.name, "perms": perms, "size": hex(s["sh_size"]),
                         "entropy": round(_entropy(data), 2) if data else 0.0})
        if not secs:  # section headers stripped (packers): show load segments
            for i, seg in enumerate(elf.iter_segments()):
                if seg["p_type"] != "PT_LOAD":
                    continue
                fl = seg["p_flags"]
                perms = ("r" if fl & 4 else "-") + ("w" if fl & 2 else "-") + ("x" if fl & 1 else "-")
                secs.append({"name": f"LOAD{i}", "perms": perms, "size": hex(seg["p_memsz"]),
                             "entropy": round(_entropy(seg.data()), 2)})
        ident["sections"] = secs
    ident["upx"] = b"UPX!" in raw
    return ident


# ---------------------------------------------------------------------------------------------
# rootfs
# ---------------------------------------------------------------------------------------------

def clone_tree(src: Path, dst: Path) -> str:
    """APFS clonefile(2) of a whole directory tree; plain copy if that is not possible."""
    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        libc.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
        if libc.clonefile(os.fsencode(src), os.fsencode(dst), 0x1) == 0:  # CLONE_NOFOLLOW
            return "clonefile"
        err = ctypes.get_errno()
    except Exception as e:  # pragma: no cover
        err = str(e)
    shutil.copytree(src, dst, symlinks=True)
    return f"copy (clonefile failed: {err})"


def _w(root: Path, rel: str, text: str | bytes, mode: int = 0o600) -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink() or p.exists():
        p.unlink()
    p.write_bytes(text.encode() if isinstance(text, str) else text)
    os.chmod(p, mode)


def _cpuinfo(arch: str) -> str:
    if arch in ("x86-64", "x86"):
        one = ("processor\t: {n}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 79\n"
               "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\nstepping\t: 1\ncpu MHz\t\t: 2399.996\n"
               "cache size\t: 35840 KB\nphysical id\t: 0\nsiblings\t: 2\ncore id\t\t: {n}\ncpu cores\t: 2\n"
               "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr "
               "sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq "
               "ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm abm "
               "3dnowprefetch fsgsbase bmi1 hle avx2 smep bmi2 erms invpcid rtm rdseed adx smap xsaveopt\n"
               "bogomips\t: 4799.99\naddress sizes\t: 46 bits physical, 48 bits virtual\n\n")
    else:
        one = ("processor\t: {n}\nBogoMIPS\t: 50.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics "
               "fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs\nCPU implementer\t: 0x41\nCPU architecture: 8\n"
               "CPU variant\t: 0x3\nCPU part\t: 0xd0c\nCPU revision\t: 1\n\n")
    return "".join(one.format(n=n) for n in range(2))


def build_fake_system(root: Path, arch: str, sample_vpath: str, argv: list[str]) -> None:
    """Files that make the emulated machine look like a small Ubuntu server, written
    into the run's rootfs before the baseline snapshot (so they are not reported)."""
    for d in ("tmp", "root/.ssh", "home/ubuntu", "var/tmp", "var/run", "var/log", "var/spool/cron/crontabs",
              "etc/cron.d", "etc/init.d", "etc/systemd/system", "etc/profile.d", "usr/bin", "usr/sbin", "bin",
              "sbin", "dev/shm", "proc/net", "proc/sys/kernel", "run", "lib/systemd"):
        (root / d).mkdir(parents=True, exist_ok=True)
    passwd = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
              "bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
              "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
              "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n")
    files = {
        "etc/passwd": passwd,
        "etc/group": "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:syslog,ubuntu\nsudo:x:27:ubuntu\n"
                     "www-data:x:33:\nnogroup:x:65534:\nubuntu:x:1000:\n",
        "etc/shadow": "".join(f"{ln.split(':')[0]}:*:19500:0:99999:7:::\n" for ln in passwd.splitlines()),
        "etc/hostname": HOSTNAME + "\n",
        "etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {HOSTNAME}\n::1 localhost ip6-localhost ip6-loopback\n",
        "etc/resolv.conf": f"nameserver {elfnet.NAMESERVER}\noptions edns0 trust-ad\nsearch .\n",
        "etc/nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n",
        "etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                          'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n',
        "etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n\n",
        "etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                       "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n",
        "etc/rc.local": "#!/bin/sh -e\nexit 0\n",
        "etc/shells": "/bin/sh\n/bin/bash\n/usr/bin/bash\n",
        "root/.bashrc": "# ~/.bashrc\n[ -z \"$PS1\" ] && return\nHISTCONTROL=ignoreboth\n",
        "root/.profile": "if [ -f ~/.bashrc ]; then . ~/.bashrc; fi\n",
        "root/.ssh/authorized_keys": "",
        "proc/version": f"Linux version {KERNEL_RELEASE} (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) "
                        f"11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) {KERNEL_VERSION}\n",
        "proc/cpuinfo": _cpuinfo(arch),
        "proc/meminfo": "MemTotal:        4028536 kB\nMemFree:          612344 kB\nMemAvailable:    2901132 kB\n"
                        "Buffers:          104512 kB\nCached:          2034876 kB\nSwapTotal:             0 kB\n"
                        "SwapFree:              0 kB\n",
        "proc/uptime": f"{UPTIME:.2f} {UPTIME * 3.8:.2f}\n",
        "proc/loadavg": "0.08 0.03 0.01 1/187 2148\n",
        "proc/stat": "cpu  1024213 1201 301234 74123412 23412 0 4123 0 0 0\nbtime 1699580000\nprocesses 31244\n",
        "proc/mounts": "/dev/vda1 / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
                       "tmpfs /run tmpfs rw,nosuid,nodev,size=402856k,mode=755 0 0\n",
        "proc/net/route": "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                          "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                          "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
        "proc/net/tcp": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18213 1\n",
        "proc/net/udp": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
        "proc/net/dev": "Inter-|   Receive                            |  Transmit\n face |bytes    packets errs drop|bytes    packets errs drop\n"
                        "    lo:  412312    3121    0    0   412312    3121    0    0\n"
                        "  eth0: 912384123 812341    0    0 41231231  341234    0    0\n",
        "proc/net/arp": "IP address       HW type     Flags       HW address            Mask     Device\n"
                        f"{elfnet.NAMESERVER:<17}0x1         0x2         52:54:00:12:35:02     *        eth0\n",
        "proc/sys/kernel/hostname": HOSTNAME + "\n",
        "proc/sys/kernel/osrelease": KERNEL_RELEASE + "\n",
        "proc/sys/kernel/ostype": "Linux\n",
        "proc/1/cmdline": "/sbin/init\0splash\0",
        "proc/1/comm": "systemd\n",
        "proc/1/status": "Name:\tsystemd\nState:\tS (sleeping)\nPid:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\n",
        "proc/2101/cmdline": "-bash\0",
        "proc/2101/comm": "bash\n",
        "proc/2101/status": "Name:\tbash\nState:\tS (sleeping)\nPid:\t2101\nPPid:\t2087\nUid:\t0\t0\t0\t0\n",
        f"proc/{MAIN_PID}/cmdline": "\0".join([sample_vpath, *argv]) + "\0",
        f"proc/{MAIN_PID}/comm": os.path.basename(sample_vpath)[:15] + "\n",
        f"proc/{MAIN_PID}/status": f"Name:\t{os.path.basename(sample_vpath)[:15]}\nState:\tR (running)\n"
                                   f"Pid:\t{MAIN_PID}\nPPid:\t{PPID}\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n",
        "lib/systemd/systemd": "",
    }
    for rel, text in files.items():
        _w(root, rel, text)
    for rel in ("bin/sh", "bin/bash", "bin/busybox", "bin/ls", "bin/ps", "usr/bin/wget", "usr/bin/curl",
                "usr/bin/python3", "usr/bin/crontab", "usr/sbin/sshd", "sbin/init", "dev/null", "dev/zero",
                "dev/urandom", "dev/random", "dev/tty"):
        _w(root, rel, "")
    for name, target in (("proc/1/exe", "/lib/systemd/systemd"), ("proc/2101/exe", "/bin/bash"),
                         (f"proc/{MAIN_PID}/exe", sample_vpath), ("proc/self", f"/proc/{MAIN_PID}")):
        p = root / name
        if not p.is_symlink():
            p.symlink_to(target)


def privatise_tree(root: Path) -> None:
    """Per-run copy: owner-only, no file executable (dirs keep search permission)."""
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o700)
        for n in filenames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                os.chmod(p, 0o600)


def snapshot_tree(root: Path) -> dict:
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            kind = "l" if stat.S_ISLNK(st.st_mode) else "d" if stat.S_ISDIR(st.st_mode) else "f"
            snap["/" + os.path.relpath(p, root)] = (kind, st.st_size, st.st_mtime_ns, st.st_ino,
                                                     stat.S_IMODE(st.st_mode))
    return snap


# ---------------------------------------------------------------------------------------------
# small stream objects for the fd table
# ---------------------------------------------------------------------------------------------

class OutputOrder:
    """Write order across stdout and stderr: runs of [stream, bytes], consecutive
    writes to the same stream merged, so the two files can be re-interleaved
    exactly as the program wrote them (at write-syscall granularity)."""

    def __init__(self, cap: int = MAX_ORDER_RUNS):
        self.runs: list[list] = []
        self.cap, self.complete = cap, True

    def add(self, stream: str, n: int) -> None:
        if not n:
            return
        if self.runs and self.runs[-1][0] == stream:
            self.runs[-1][1] += n
        elif len(self.runs) < self.cap:
            self.runs.append([stream, n])
        else:
            self.complete = False


class CappedOutput:
    """stdout/stderr of the emulated program, saved to a bounded file."""

    def __init__(self, path: Path, cap: int = MAX_OUTPUT_BYTES, name: str = "", order: OutputOrder | None = None):
        self.f = open(path, "wb")
        self.cap, self.n, self.dropped = cap, 0, 0
        self.head = bytearray()
        self.name, self.order = name or path.stem, order
        self.sha = hashlib.sha256()

    def write(self, data) -> int:
        data = bytes(data)
        room = self.cap - self.n
        if room > 0:
            self.f.write(data[:room])
            self.f.flush()
            self.sha.update(data[:room])
        if len(self.head) < 8192:
            self.head += data[:8192 - len(self.head)]
        self.dropped += max(0, len(data) - max(room, 0))
        self.n += len(data)
        if self.order is not None:
            self.order.add(self.name, len(data))
        return len(data)

    def info(self) -> dict:
        """report.json entry; `head` is a lossy UTF-8 preview, the file holds the exact bytes."""
        return {"bytes": self.n, "saved": self.n - self.dropped, "file": f"{self.name}.txt",
                "sha256": self.sha.hexdigest(), "head": self.head.decode("utf-8", "replace")}

    def read(self, n):
        return b""

    def fileno(self):
        return self.f.fileno()

    def fstat(self):
        return elfnet._stat_like(0o010600)  # a pipe

    def close(self):
        pass

    def flush(self):
        pass

    def dup(self):
        return self

    def ioctl(self, cmd, arg):
        raise OSError(LE.ENOTTY, "not a tty")

    def fcntl(self, cmd, arg):
        return 0


class StdinInput(CappedOutput):
    """fd 0 of the emulated program: the bytes given with --stdin* (default none),
    then end-of-file. A pipe, like `printf ... | prog`; one shared read offset, as a
    real inherited stdin has across fork/dup."""

    def __init__(self, data: bytes = b""):
        self.f = None
        self.data, self.pos, self.reads, self.eof_reads = bytes(data), 0, 0, 0

    def read(self, n):
        self.reads += 1
        n = max(0, int(n))
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        if n and not chunk:
            self.eof_reads += 1
        return chunk

    def readline(self, end=b"\n"):
        i = self.data.find(end, self.pos)
        stop = len(self.data) if i < 0 else i + len(end)
        return self.read(stop - self.pos)

    def write(self, data):
        return len(data)

    def fileno(self):
        return -1

    def info(self) -> dict:
        return {"bytes": len(self.data), "consumed": self.pos, "reads": self.reads, "eof_reads": self.eof_reads,
                "sha256": hashlib.sha256(self.data).hexdigest()}


EmptyInput = StdinInput  # older name


class DevFile:
    """/dev/null, /dev/zero, /dev/urandom as mapped objects."""

    def __init__(self, kind: str):
        self.kind = kind

    def read(self, n):
        n = min(n, 1 << 20)
        if self.kind == "null":
            return b""
        return bytes(n) if self.kind == "zero" else os.urandom(n)

    def write(self, data):
        return len(data)

    def fileno(self):
        return -1

    def lseek(self, off, whence):
        return 0

    def tell(self):
        return 0

    def close(self):
        pass

    def fstat(self):
        return elfnet._stat_like(0o020666)

    def dup(self):
        return self

    def readline(self, end=b"\n"):
        return b""

    def ioctl(self, cmd, arg):
        raise OSError(LE.ENOTTY, "not a tty")

    @property
    def name(self):
        return f"/dev/{self.kind}"


class BytesFile(io.BytesIO):
    def __init__(self, name: str, data: bytes):
        super().__init__(data)
        self._name = name

    @property
    def name(self):
        return self._name

    def fileno(self):
        return -1

    def lseek(self, off, whence):
        return self.seek(off, whence)

    def fstat(self):
        return elfnet._stat_like(0o100444)

    def dup(self):
        return self


class CappedLog(io.TextIOBase):
    def __init__(self, path: Path, cap: int = MAX_LOG_BYTES):
        self.f = open(path, "w", encoding="utf-8")
        self.cap, self.n = cap, 0

    def write(self, s):
        if self.n < self.cap:
            self.f.write(s[: self.cap - self.n])
            self.n += len(s)
            if self.n >= self.cap:
                self.f.write("\n[rebox: qiling.log truncated]\n")
            self.f.flush()
        return len(s)

    def flush(self):
        self.f.flush()


def _signed(v: int, bits: int) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


# ---------------------------------------------------------------------------------------------
# the emulation
# ---------------------------------------------------------------------------------------------

class Stop(Exception):
    pass


class ElfEmu:
    def __init__(self, sample: str, out: Path, timeout: int, max_syscalls: int, args: list[str],
                 env: dict[str, str], rootfs_cache: str | None, meta: dict, stdin: bytes = b""):
        self.sample, self.out, self.timeout, self.max_syscalls = sample, out, timeout, max_syscalls
        self.args, self.meta = args, meta
        self.stdin_data = bytes(stdin)
        self.env = {**DEFAULT_ENV, **env}
        self.rootfs_cache = Path(rootfs_cache) if rootfs_cache else None
        self.counts: Counter = Counter()
        self.first_pc: dict[str, str] = {}
        self.unsupported: Counter = Counter()
        self.unsupported_pc: dict[str, str] = {}
        self.handler_errors: dict[str, str] = {}
        self.events: list[dict] = []
        self.events_dropped = 0
        self.logged_per_name: Counter = Counter()
        self.total = 0
        self.skew = 0.0
        self.finished = False
        self.stop_reason = None
        self.stop_detail = None
        self.deadline = None
        self.procs: list[dict] = []
        self.stack: list[dict] = []
        self.child_exits: list[tuple[int, int, int]] = []  # (parent pid, child pid, wait status)
        self.next_pid = MAIN_PID + 1
        self.n_spawned = 0
        self.pending_ret = None
        self.cur_name = ""
        self.cur_detail = None
        self.ev_info = None
        self.in_loader = False
        self.ind = {k: {} for k in ("files_written", "files_read", "files_deleted", "files_probed", "cmdlines",
                                    "process_names", "listening", "signals", "modules_loaded", "raw_sockets",
                                    "anti_analysis", "hosts", "urls", "persistence_paths", "chmod")}
        self.exec_regions: dict[int, tuple[int, str]] = {}
        self.dns_names: list[str] = []
        self.libc_lookups: list[dict] = []
        self.runq: dict[int, list] = {}      # pid -> queued thread contexts
        self.exiting: dict[int, tuple] = {}  # pid -> deferred exit_group

    # ---- indicators -----------------------------------------------------------------------
    def note(self, key: str, value: str) -> None:
        if value is None:
            return
        value = str(value)[:STR_CAP]
        d = self.ind[key]
        d[value] = d.get(value, 0) + 1

    def note_dns(self, name: str) -> None:
        self.note("hosts", name.lower())
        self.dns_names.append(name.lower())

    def note_url(self, url: str) -> None:
        self.note("urls", url)

    def note_listen(self, s: str) -> None:
        self.note("listening", s)

    def note_raw(self, s: str) -> None:
        self.note("raw_sockets", s)

    def dns_name_for(self, ip):
        return self.dns_names[-1] if ip == elfnet.CANNED_IP and self.dns_names else None

    # ---- memory / strings ---------------------------------------------------------------------
    def cstr(self, addr: int, cap: int = STR_CAP) -> str | None:
        if not addr:
            return None
        out = bytearray()
        try:
            while len(out) < cap:
                chunk = bytes(self.ql.mem.read(addr + len(out), min(64, cap - len(out))))
                z = chunk.find(b"\0")
                if z >= 0:
                    out += chunk[:z]
                    break
                out += chunk
        except Exception:
            if not out:
                return None
        return out.decode("utf-8", "replace")

    def str_array(self, addr: int, cap: int = 64) -> list[str]:
        out = []
        ps = self.ql.arch.pointersize
        try:
            while addr and len(out) < cap:
                p = self.ql.mem.read_ptr(addr, ps)
                if not p:
                    break
                out.append(self.cstr(p) or "")
                addr += ps
        except Exception:
            pass
        return out

    def ts64_for(self, _name: str) -> bool:
        return self.ql.arch.bits == 64 or self.cur_name.endswith("time64")

    def read_timespec(self, ptr: int, ts64: bool):
        if not ptr:
            return None
        try:
            if ts64:
                s, ns = struct.unpack(self.endian + "qq", bytes(self.ql.mem.read(ptr, 16)))
            else:
                s, ns = struct.unpack(self.endian + "ii", bytes(self.ql.mem.read(ptr, 8)))
        except Exception:
            return None
        return max(0.0, s + ns / 1e9)

    def read_timeval(self, ptr: int):
        if not ptr:
            return None
        n = self.ql.arch.pointersize
        fmt = "qq" if n == 8 else "ii"
        try:
            s, us = struct.unpack(self.endian + fmt, bytes(self.ql.mem.read(ptr, 2 * n)))
        except Exception:
            return None
        return max(0.0, s + us / 1e6)

    def write_time(self, ptr: int, t: float, sub: int, ts64: bool) -> None:
        s, frac = int(t), int((t - int(t)) * sub)
        fmt = "qq" if ts64 else "ii"
        self.ql.mem.write(ptr, struct.pack(self.endian + fmt, s, frac))

    # ---- process control ----------------------------------------------------------------------
    def new_proc(self, kind: str, ppid: int, pid: int | None = None, tid: int | None = None) -> dict:
        pid = pid if pid is not None else self.next_pid
        if pid == self.next_pid:
            self.next_pid += 1
        rec = {"pid": pid, "tid": tid or pid, "ppid": ppid, "type": kind, "start": hex(self.ql.arch.regs.arch_pc),
               "syscalls": 0, "stop": None}
        self.procs.append(rec)
        return rec

    def mem_snapshot(self) -> list:
        snap = []
        for lo, hi, perm, label, mmio in self.ql.mem.map_info:
            if mmio is None:
                snap.append((lo, hi, perm, label, bytes(self.ql.mem.read(lo, hi - lo))))
        return snap

    def mem_restore(self, snap: list) -> None:
        mem = self.ql.mem
        want = {(lo, hi): (perm, label, data) for lo, hi, perm, label, data in snap}
        for lo, hi, perm, label, mmio in list(mem.map_info):
            if mmio is None and (lo, hi) not in want:
                mem.unmap(lo, hi - lo)
        have = {(lo, hi): perm for lo, hi, perm, label, mmio in mem.map_info}
        for (lo, hi), (perm, label, data) in want.items():
            if (lo, hi) not in have:
                if not mem.is_available(lo, hi - lo):
                    for a, b, p, lab, m in list(mem.map_info):
                        if m is None and a < hi and lo < b:
                            mem.unmap(a, b - a)
                mem.map(lo, hi - lo, perm, label)
            elif have[(lo, hi)] != perm:
                mem.protect(lo, hi - lo, perm)
            if bytes(mem.read(lo, hi - lo)) != data:
                mem.write(lo, data)

    def tls_save(self) -> dict:
        arch = self.arch
        if arch == "x86-64":
            return {"fsbase": self.ql.arch.msr.read(0xC0000100)}
        if arch == "x86":
            return {"gdt": {i: self.ql.os.gdtm.get_entry(i) for i in (12, 13, 14)}}
        if arch == "arm64":
            return {"tpidr_el0": self.ql.arch.cpr.TPIDR_EL0}
        return {}

    def tls_restore(self, t: dict) -> None:
        if "fsbase" in t:
            self.ql.arch.msr.write(0xC0000100, t["fsbase"])
        for i, e in (t.get("gdt") or {}).items():
            self.ql.os.gdtm.set_entry(i, e)
        if "tpidr_el0" in t:
            self.ql.arch.cpr.TPIDR_EL0 = t["tpidr_el0"]

    def tls_set(self, tls: int) -> None:
        arch = self.arch
        if arch == "x86-64":
            self.ql.arch.msr.write(0xC0000100, tls)
        elif arch == "arm64":
            self.ql.arch.cpr.TPIDR_EL0 = tls
        elif arch == "x86":
            from qiling.os.linux.syscall import ql_syscall_set_thread_area
            ql_syscall_set_thread_area(self.ql, tls)
        elif arch == "arm":
            from qiling.os.linux.syscall import ql_syscall_set_tls
            r0 = self.ql.arch.regs.r0
            ql_syscall_set_tls(self.ql, tls)
            self.ql.arch.regs.r0 = r0
        elif arch in ("mips", "mipsel"):
            self.ql.arch.regs.cp0_userlocal = tls

    def spawn(self, kind: str, flags: int, child_stack: int = 0, ptid: int = 0, ctid: int = 0, tls: int = 0):
        """fork/vfork/clone.

        Processes run child-first: the parent is saved and the child continues
        until it exits, execs or blocks; then the parent resumes (end_process).
        Threads (CLONE_VM without CLONE_VFORK) run parent-first instead: the new
        thread is queued and runs when the current thread blocks, sleeps,
        yields or exits (see switch_thread). A thread created child-first would
        deadlock on locks its suspended parent holds (libc holds the thread-list
        lock across clone).
        """
        thread = bool(flags & CLONE_VM) and not flags & CLONE_VFORK and kind == "clone"
        if self.n_spawned >= MAX_PROCESSES or (not thread and len(self.stack) >= MAX_DEPTH):
            self.ev_info = "refused: process limit"
            return -LE.EAGAIN
        self.n_spawned += 1
        child_id = self.next_pid
        if flags & CLONE_PARENT_SETTID and ptid:
            self.ql.mem.write_ptr(ptid, child_id, 4)
        if thread:
            return self.queue_thread(flags, child_stack, ctid, tls)
        share_mem = bool(flags & CLONE_VM) or kind == "vfork"
        ctx = {"proc": self.cur, "regs": self.ql.save(reg=True, mem=False), "tls": self.tls_save(), "kind": kind,
               "loader": {k: getattr(self.ql.loader, k) for k in ("brk_address", "mmap_address")
                          if hasattr(self.ql.loader, k)}}
        if not share_mem:
            ctx["mem"] = self.mem_snapshot()
        if not flags & CLONE_FILES:
            parent_fds = [self.ql.os.fd[i] for i in range(len(self.ql.os.fd))]
            ctx["fds"] = parent_fds
            for i, f in enumerate(parent_fds):
                if f is not None and hasattr(f, "dup") and not isinstance(f, (CappedOutput, DevFile)):
                    try:
                        self.ql.os.fd[i] = f.dup()
                    except Exception:
                        pass
        self.stack.append(ctx)
        rec = self.new_proc(kind, self.cur["pid"])
        if child_stack:
            self.ql.arch.regs.arch_sp = child_stack
        if flags & CLONE_SETTLS:
            self.tls_set(tls)
        if flags & CLONE_CHILD_SETTID and ctid:
            self.ql.mem.write_ptr(ctid, child_id, 4)
        ctx["child"] = rec
        self.cur = rec
        self.ev_info = f"child-first: now running {kind} {child_id}"
        return 0

    def queue_thread(self, flags, child_stack, ctid, tls) -> int:
        regs0, tls0 = self.ql.save(reg=True, mem=False), self.tls_save()
        if child_stack:
            self.ql.arch.regs.arch_sp = child_stack
        if flags & CLONE_SETTLS:
            self.tls_set(tls)
        ctx = {"regs": self.ql.save(reg=True, mem=False), "tls": self.tls_save(), "ret": 0, "started": False}
        self.tls_restore(tls0)
        self.ql.restore(regs0)
        self.tls_restore(tls0)
        rec = self.new_proc("thread", self.cur["ppid"], pid=self.cur["pid"], tid=self.next_pid)
        self.next_pid += 1
        rec["created_by"] = self.cur["tid"]
        rec["ctid"] = ctid if flags & CLONE_CHILD_CLEARTID else 0
        if flags & CLONE_CHILD_SETTID and ctid:
            self.ql.mem.write_ptr(ctid, rec["tid"], 4)
        ctx["rec"] = rec
        self.runq.setdefault(self.cur["pid"], []).append(ctx)
        self.ev_info = f"thread {rec['tid']} queued (runs when this thread blocks, sleeps or exits)"
        return rec["tid"]

    def switch_thread(self, ret_for_current, current_done: bool = False) -> bool:
        """Cooperative switch to the next queued thread of this process.

        The current thread is re-queued (to resume with `ret_for_current`) unless
        it is done. Returns False if there is nothing to switch to."""
        q = self.runq.get(self.cur["pid"])
        if not q:
            return False
        if not current_done:
            q.append({"rec": self.cur, "regs": self.ql.save(reg=True, mem=False), "tls": self.tls_save(),
                      "ret": ret_for_current, "started": True})
        nxt = q.pop(0)
        if nxt["rec"] is self.cur:
            return False
        self.tls_restore(nxt["tls"])
        self.ql.restore(nxt["regs"])
        self.tls_restore(nxt["tls"])
        self.cur = nxt["rec"]
        if not nxt["started"]:
            self.cur["start"] = hex(self.ql.arch.regs.arch_pc)
        self.pending_ret = nxt["ret"]
        self.ev_info = (self.ev_info + "; " if self.ev_info else "") + f"switched to thread {self.cur['tid']}"
        return True

    def thread_done(self, stop: str, detail: str | None, code: int | None = None) -> bool:
        """The current thread ends but other threads of the process can run."""
        if not self.runq.get(self.cur["pid"]):
            return False
        rec = self.cur
        rec.update({"stop": stop, "pc": hex(self.ql.arch.regs.arch_pc)})
        if detail:
            rec["detail"] = detail[:STR_CAP]
        if code is not None:
            rec["exit_code"] = code
        if rec.get("ctid"):
            try:
                self.ql.mem.write_ptr(rec["ctid"], 0, 4)  # what pthread_join waits for
            except Exception:
                pass
        exiting = self.exiting.get(rec["pid"])
        q = self.runq[rec["pid"]]
        if exiting and not any(not c["started"] for c in q):
            return False
        return self.switch_thread(None, current_done=True)

    def end_process(self, stop: str, detail: str | None = None, code: int | None = None,
                    status: int = 0) -> None:
        """The current process ends; resume its parent if one is waiting (child-first)."""
        rec = self.cur
        rec["stop"] = stop
        rec["pc"] = hex(self.ql.arch.regs.arch_pc)
        if detail:
            rec["detail"] = detail[:STR_CAP]
        if code is not None:
            rec["exit_code"] = code
        exiting = self.exiting.pop(rec["pid"], None)
        if exiting:  # exit_group was deferred while queued threads ran; report it on the main record
            stop, detail, code, status = exiting
        for c in self.runq.pop(rec["pid"], []):
            r = c["rec"]
            if r.get("stop") is None:
                r["stop"] = "killed" if c["started"] else "not_run"
                r["detail"] = "process exited while this thread waited"
        self.dump_exec_regions()
        if not self.stack:
            self.finish(stop, detail)
            return
        ctx = self.stack.pop()
        child = ctx["child"]
        if "mem" in ctx:
            self.mem_restore(ctx["mem"])
        self.tls_restore(ctx["tls"])
        self.ql.restore(ctx["regs"])
        self.tls_restore(ctx["tls"])
        for k, v in ctx["loader"].items():
            setattr(self.ql.loader, k, v)
        if "fds" in ctx:
            for i, f in enumerate(ctx["fds"]):
                self.ql.os.fd[i] = f
        self.cur = ctx["proc"]
        self.child_exits.append((self.cur["pid"], child["pid"], status))
        self.pending_ret = child["pid"]

    def finish(self, reason: str, detail: str | None = None) -> None:
        if not self.finished:
            self.finished = True
            self.stop_reason = reason
            self.stop_detail = detail
        self.ql.emu_stop()

    def block(self, detail: str) -> None:
        """The current thread would wait forever: run another thread, or end the process."""
        if self.thread_done("blocked", detail):
            return
        self.end_process("blocked", detail)

    def nothing_ready(self, name: str, timeout_s):
        if timeout_s is None:
            self.block(f"{name}() waits forever: no fake fd ever becomes ready")
            return None
        self.skew += timeout_s
        return None if self.switch_thread(0) else 0

    def dump_exec_regions(self) -> None:
        for base, (size, why) in list(self.exec_regions.items()):
            try:
                data = bytes(self.ql.mem.read(base, size))
            except Exception:
                continue
            if data.strip(b"\0"):
                self.dumps.add("protexec", data, base=hex(base), tag=why, pid=self.cur["pid"])

    # ---- syscall handlers (rebox's own) -------------------------------------------------------
    def sys_fork(self, ql):
        return self.spawn("fork", 0)

    def sys_vfork(self, ql):
        return self.spawn("vfork", CLONE_VM | CLONE_VFORK)

    def sys_clone(self, ql, flags, child_stack, ptid, a4, a5):
        # x86-64: (flags, stack, ptid, ctid, tls); others: (flags, stack, ptid, tls, ctid)
        ctid, tls = (a4, a5) if self.arch == "x86-64" else (a5, a4)
        kind = "vfork" if flags & CLONE_VFORK else "clone"
        if not flags & CLONE_VM:
            kind = "fork"
        return self.spawn(kind, flags, child_stack, ptid, ctid, tls)

    def sys_clone3(self, ql, args, size):
        return -LE.ENOSYS  # libc falls back to clone()

    def _exec(self, path: str | None, argv_addr: int, envp_addr: int):
        argv = self.str_array(argv_addr)
        envc = len(self.str_array(envp_addr, cap=256))
        path = path or "?"
        cmd = shlex.join([path, *argv[1:]])
        if argv and os.path.basename(path) != argv[0]:
            cmd += f"  [argv0={argv[0]}]"
        self.note("cmdlines", cmd)
        self.ev_info = f"argv={argv} envc={envc}"
        self.end_process("execve", cmd, status=0)
        return None

    def sys_execve(self, ql, path, argv, envp):
        return self._exec(self.cstr(path), argv, envp)

    def sys_execveat(self, ql, dirfd, path, argv, envp, flags):
        return self._exec(self.cstr(path), argv, envp)

    def sys_exit(self, ql, code):
        # SYS_exit ends only the calling thread
        code = _signed(code, 32) & 0xFF
        if self.thread_done("exited", f"exit({code})", code):
            return None
        self.end_process("exited", f"exit({code})", code, status=code << 8)
        return None

    def sys_exit_group(self, ql, code):
        code = _signed(code, 32) & 0xFF
        detail = f"exit_group({code})"
        q = self.runq.get(self.cur["pid"]) or []
        if any(not c["started"] for c in q):
            # Threads that were created but never got to run: run them before the
            # process exit takes effect (a real scheduler would usually have run them).
            self.exiting[self.cur["pid"]] = ("exited", detail, code, code << 8)
            if self.thread_done("exited", detail, code):
                return None
        self.end_process("exited", detail, code, status=code << 8)
        return None

    def sys_wait4(self, ql, pid, status, options, rusage):
        pid = _signed(pid, 32)
        for i, (ppid, cpid, st) in enumerate(self.child_exits):
            if ppid == self.cur["pid"] and (pid in (-1, 0) or pid == cpid or pid < -1):
                self.child_exits.pop(i)
                if status:
                    ql.mem.write_ptr(status, st, 4)
                return cpid
        return -LE.ECHILD

    def sys_waitid(self, ql, idtype, id_, infop, options, rusage):
        return -LE.ECHILD

    def sys_getpid(self, ql):
        return self.cur["pid"]

    def sys_getppid(self, ql):
        return self.cur["ppid"]

    def sys_gettid(self, ql):
        return self.cur["tid"]

    def sys_setsid(self, ql):
        return self.cur["pid"]

    def sys_getpgrp(self, ql):
        return self.cur["pid"]

    def _signal(self, target: int, sig: int, how: str):
        name = SIGNAMES.get(sig, str(sig))
        me = target in (self.cur["pid"], self.cur["tid"], 0)
        if not me:
            self.note("signals", f"{how}({target}, {name})")
            return 0
        if sig in FATAL_SIGNALS:
            self.end_process("signal", f"{how} to itself: {name}", status=sig)
            return None
        return 0

    def sys_kill(self, ql, pid, sig):
        return self._signal(_signed(pid, 32), sig, "kill")

    def sys_tkill(self, ql, tid, sig):
        return self._signal(_signed(tid, 32), sig, "tkill")

    def sys_tgkill(self, ql, tgid, tid, sig):
        return self._signal(_signed(tid, 32), sig, "tgkill")

    def sys_pause(self, ql):
        self.block("pause(): waits for a signal that never comes")
        return None

    def sys_rt_sigsuspend(self, ql, mask, size):
        self.block("rt_sigsuspend(): waits for a signal that never comes")
        return None

    def sys_futex(self, ql, uaddr, op, val, timeout, uaddr2, val3):
        cmd = op & 0x7F
        if cmd in (0, 9):  # FUTEX_WAIT, FUTEX_WAIT_BITSET
            try:
                cur = ql.mem.read_ptr(uaddr, 4)
            except Exception:
                return -LE.EFAULT
            if cur != (val & 0xFFFFFFFF):
                return -LE.EAGAIN
            # it would block: let another thread run (it resumes with 0, a permitted
            # spurious wake-up), else time out or, without a timeout, block for good
            if self.switch_thread(0):
                return None
            if timeout:
                return -LE.ETIMEDOUT
            self.block(f"futex wait at {uaddr:#x} that no other thread can wake")
            return None
        return 0

    def sys_sched_yield(self, ql):
        return None if self.switch_thread(0) else 0

    def sys_set_robust_list(self, ql, head, ln):
        return 0

    def sys_prctl(self, ql, option, a2, a3, a4, a5):
        if option == 15:  # PR_SET_NAME
            name = self.cstr(a2, 16)
            self.note("process_names", name)
            self.cur["name"] = name
            self.ev_info = f"PR_SET_NAME {name!r}"
        elif option == 16:  # PR_GET_NAME
            name = (self.cur.get("name") or os.path.basename(self.sample_vpath))[:15]
            ql.mem.write(a2, name.encode() + b"\0")
        elif option == 4:   # PR_SET_DUMPABLE
            self.note("anti_analysis", "prctl(PR_SET_DUMPABLE)")
        elif option == 1:   # PR_SET_PDEATHSIG
            pass
        return 0

    def sys_ptrace(self, ql, req, pid, addr, data):
        if req == 0:
            self.note("anti_analysis", "ptrace(PTRACE_TRACEME)")
        else:
            self.note("anti_analysis", f"ptrace(request={req}, pid={_signed(pid, 32)})")
        return 0

    def sys_uname(self, ql, buf):
        fields = ("Linux", HOSTNAME, KERNEL_RELEASE, KERNEL_VERSION, MACHINE.get(self.arch, "x86_64"), "(none)")
        for i, f in enumerate(fields):
            ql.mem.write(buf + i * 65, f.encode().ljust(65, b"\0"))
        return 0

    def sys_sethostname(self, ql, name, ln):
        self.note("anti_analysis", f"sethostname({self.cstr(name, min(ln, 64))!r})")
        return 0

    def sys_nanosleep(self, ql, req, rem):
        t = self.read_timespec(req, self.ts64_for("")) or 0.0
        self.skew += t
        self.ev_info = f"slept {t:g}s (virtual)"
        if rem:
            try:
                self.write_time(rem, 0.0, 10 ** 9, self.ts64_for(""))
            except Exception:
                pass
        return None if self.switch_thread(0) else 0

    def sys_clock_nanosleep(self, ql, clk, flags, req, rem):
        t = self.read_timespec(req, self.ts64_for("")) or 0.0
        if flags & 1:  # TIMER_ABSTIME
            t = max(0.0, t - self._now(clk))
        self.skew += t
        self.ev_info = f"slept {t:g}s (virtual)"
        return None if self.switch_thread(0) else 0

    def _now(self, clk: int) -> float:
        if clk in (0, 5, 8, 11):  # REALTIME, REALTIME_COARSE, REALTIME_ALARM, TAI
            return time.time() + self.skew
        return UPTIME + (time.monotonic() - self.t0) + self.skew

    def sys_clock_gettime(self, ql, clk, tp):
        if tp:
            self.write_time(tp, self._now(clk), 10 ** 9, self.ts64_for(""))
        return 0

    def sys_gettimeofday(self, ql, tv, tz):
        if tv:
            n = ql.arch.pointersize
            self.write_time(tv, self._now(0), 10 ** 6, n == 8)
        return 0

    def sys_time(self, ql, tloc):
        t = int(self._now(0))
        if tloc:
            ql.mem.write_ptr(tloc, t)
        return t

    def sys_alarm(self, ql, secs):
        return 0

    def sys_readlink(self, ql, path, buf, size):
        return self._readlink(self.cstr(path), buf, size, -100)

    def sys_readlinkat(self, ql, dirfd, path, buf, size):
        return self._readlink(self.cstr(path), buf, size, _signed(dirfd, 32))

    def _readlink(self, vpath, buf, size, dirfd):
        if vpath is None:
            return -LE.EFAULT
        if not vpath.startswith("/") and dirfd != -100:
            return -LE.EINVAL
        absv = self.ql.os.path.virtual_abspath(vpath)
        if absv in ("/proc/self/exe", f"/proc/{self.cur['pid']}/exe"):
            target = self.sample_vpath
        elif absv == "/proc/self/cwd":
            target = self.ql.os.path.cwd
        else:
            host = Path(self.rootfs) / absv.lstrip("/")
            if not host.is_symlink():
                return -LE.EINVAL if host.exists() else -LE.ENOENT
            target = os.readlink(host)
        data = target.encode()[:size]
        self.ql.mem.write(buf, data)
        self.ev_info = f"-> {target}"
        return len(data)

    def sys_ioctl(self, ql, fd, cmd, arg):
        f = ql.os.fd[fd] if 0 <= fd < len(ql.os.fd) else None
        if isinstance(f, elfnet.FakeSocket):
            return self.net.sys_ioctl_socket(f, cmd, arg)
        if isinstance(f, (CappedOutput, DevFile)):
            return -LE.ENOTTY
        from qiling.os.posix.syscall.ioctl import ql_syscall_ioctl
        return ql_syscall_ioctl(ql, fd, cmd, arg)

    def sys_fcntl(self, ql, fd, cmd, arg):
        f = ql.os.fd[fd] if 0 <= fd < len(ql.os.fd) else None
        if isinstance(f, (elfnet.FakeSocket, elfnet.FakeEpoll)):
            if cmd == 3:   # F_GETFL (Linux values; Qiling would map them to host flags)
                return 2 | (elfnet.O_NONBLOCK if getattr(f, "nonblock", False) else 0)
            if cmd == 4:   # F_SETFL
                if isinstance(f, elfnet.FakeSocket):
                    f.nonblock = bool(arg & elfnet.O_NONBLOCK)
                return 0
            if cmd == 1:   # F_GETFD
                return int(getattr(f, "close_on_exec", False))
            if cmd == 2:   # F_SETFD
                f.close_on_exec = bool(arg & 1)
                return 0
        impl = self._qiling_impl(self.cur_name)
        return impl(ql, fd, cmd, arg) if impl else -LE.EINVAL

    # -- *at file syscalls Qiling 1.4.10 lacks (arm64 has no mkdir/chmod/rename/symlink) ---------
    def _host_at(self, dirfd: int, path_addr: int):
        """-> (virtual abspath, host path) or a negative errno."""
        from qiling.os.posix.syscall.unistd import virtual_abspath_at

        vpath = self.cstr(path_addr)
        if vpath is None:
            return -LE.EFAULT
        absv = virtual_abspath_at(self.ql, vpath, dirfd)
        if isinstance(absv, int):
            return absv
        host = self.ql.os.path.virtual_to_host_path(absv)
        if not self.ql.os.path.is_safe_host_path(host):
            return -LE.EACCES
        return absv, host

    @staticmethod
    def _oserr(e: OSError) -> int:
        import errno as host_errno

        name = host_errno.errorcode.get(e.errno or 0, "EIO")
        return -getattr(LE, name, LE.EINVAL) if hasattr(LE, name) else -5

    def sys_mkdirat(self, ql, dirfd, path, mode):
        r = self._host_at(dirfd, path)
        if isinstance(r, int):
            return r
        try:
            os.mkdir(r[1], 0o700)
        except OSError as e:
            return self._oserr(e)
        return 0

    def sys_mkdir(self, ql, path, mode):
        return self.sys_mkdirat(ql, 0xFFFFFF9C, path, mode)

    def sys_fchmodat(self, ql, dirfd, path, mode):
        r = self._host_at(dirfd, path)
        if isinstance(r, int):
            return r
        if not os.path.lexists(r[1]):
            return -LE.ENOENT
        return 0  # recorded as an indicator; host modes stay private (no exec bits in out_dir)

    def sys_chmod(self, ql, path, mode):
        return self.sys_fchmodat(ql, 0xFFFFFF9C, path, mode)

    def sys_fchmod(self, ql, fd, mode):
        return 0 if 0 <= fd < len(ql.os.fd) and ql.os.fd[fd] is not None else -LE.EBADF

    def sys_fchownat(self, ql, dirfd, path, uid, gid, flags):
        r = self._host_at(dirfd, path)
        if isinstance(r, int):
            return r
        return 0 if os.path.lexists(r[1]) else -LE.ENOENT

    def sys_renameat2(self, ql, olddirfd, oldpath, newdirfd, newpath, flags):
        a, b = self._host_at(olddirfd, oldpath), self._host_at(newdirfd, newpath)
        for r in (a, b):
            if isinstance(r, int):
                return r
        try:
            os.rename(a[1], b[1])
        except OSError as e:
            return self._oserr(e)
        return 0

    def sys_renameat(self, ql, olddirfd, oldpath, newdirfd, newpath):
        return self.sys_renameat2(ql, olddirfd, oldpath, newdirfd, newpath, 0)

    def sys_symlinkat(self, ql, target, newdirfd, linkpath):
        t = self.cstr(target)
        r = self._host_at(newdirfd, linkpath)
        if isinstance(r, int):
            return r
        if t is None:
            return -LE.EFAULT
        try:
            os.symlink(t, r[1])  # the target stays a virtual path, resolved inside rootfs by Qiling
        except OSError as e:
            return self._oserr(e)
        return 0

    def sys_symlink(self, ql, target, linkpath):
        return self.sys_symlinkat(ql, target, 0xFFFFFF9C, linkpath)

    def sys_linkat(self, ql, olddirfd, oldpath, newdirfd, newpath, flags):
        a, b = self._host_at(olddirfd, oldpath), self._host_at(newdirfd, newpath)
        for r in (a, b):
            if isinstance(r, int):
                return r
        try:
            shutil.copyfile(a[1], b[1], follow_symlinks=False)  # a copy, not a hard link
            os.chmod(b[1], 0o600)
        except OSError as e:
            return self._oserr(e)
        return 0

    def sys_link(self, ql, oldpath, newpath):
        return self.sys_linkat(ql, 0xFFFFFF9C, oldpath, 0xFFFFFF9C, newpath, 0)

    def sys_sched_getaffinity(self, ql, pid, size, mask):
        n = min(size, 128)
        if n < 8:
            return -LE.EINVAL
        ql.mem.write(mask, (3).to_bytes(8, "little" if self.endian == "<" else "big") + bytes(n - 8))
        return 8

    def sys_set_tid_address(self, ql, tidptr):
        return self.cur["tid"]

    def sys_memfd_create(self, ql, name, flags):
        self.note("anti_analysis", f"memfd_create({self.cstr(name, 64)!r}) (fileless execution pattern)")
        return -LE.ENOSYS

    def handlers(self) -> dict:
        h = {}
        for name in dir(self):
            if name.startswith("sys_") and name not in ("sys_ioctl",):
                h[name[4:]] = getattr(self, name)
        h["ioctl"] = self.sys_ioctl
        h["fcntl64"] = self.sys_fcntl
        h["clock_gettime64"] = self.sys_clock_gettime
        h["clock_nanosleep_time64"] = self.sys_clock_nanosleep
        h["waitpid"] = lambda ql, pid, status, options: self.sys_wait4(ql, pid, status, options, 0)
        h.update(self.net.handlers())
        return h

    # ---- dispatcher -------------------------------------------------------------------------------
    def _params(self, fn) -> list[str]:
        cached = self._sig_cache.get(fn)
        if cached is None:
            ps = list(inspect.signature(fn).parameters.values())[1:]
            cached = [p.name for p in ps if p.kind == p.POSITIONAL_OR_KEYWORD]
            self._sig_cache[fn] = cached
        return cached

    def _qiling_impl(self, name: str):
        if name not in self._impl_cache:
            fn = getattr(self._os_mod, "ql_syscall_" + name, None) or getattr(self._posix_mod, "ql_syscall_" + name, None)
            self._impl_cache[name] = fn
        return self._impl_cache[name]

    def syscall(self) -> None:
        ql = self.ql
        if self.finished:
            ql.emu_stop()
            return
        abi = ql.os.syscall_abi
        nr = abi.get_id()
        try:
            name = ql.os.syscall_mapper(nr)[len("ql_syscall_"):]
        except Exception:
            name = f"nr_{nr}"
        pc = ql.arch.regs.arch_pc
        self.total += 1
        self.counts[name] += 1
        self.cur["syscalls"] += 1
        if name not in self.first_pc:
            self.first_pc[name] = hex(pc)
        if self.total > self.max_syscalls:
            self.cur["stop"] = "max_syscalls"
            self.cur["pc"] = hex(pc)
            self.finish("max_syscalls", f"syscall budget of {self.max_syscalls} reached at {name}")
            return
        if time.monotonic() > self.deadline:
            self.cur["stop"] = "timeout"
            self.cur["pc"] = hex(pc)
            self.finish("timeout", f"time budget of {self.timeout}s reached")
            return

        fn = self.my.get(name)
        if fn is None:
            fn = self._qiling_impl(name)
        self.cur_name, self.ev_info, self.pending_ret = name, None, None
        self.cur_detail = None
        proc_before = self.cur
        if fn is None:
            self.unsupported[name] += 1
            self.unsupported_pc.setdefault(name, hex(pc))
            params, pnames, ret = abi.get_params(3), ["a0", "a1", "a2"], -LE.ENOSYS
            self.ev_info = "unsupported: -ENOSYS"
        else:
            pnames = self._params(fn)
            params = abi.get_params(len(pnames))
            try:
                ret = fn(ql, *params)
            except Stop:
                raise
            except Exception as e:
                err = f"{type(e).__name__}: {e}"[:200]
                self.handler_errors.setdefault(name, err)
                self.unsupported[f"{name} (handler error)"] += 1
                self.unsupported_pc.setdefault(f"{name} (handler error)", hex(pc))
                ret = -LE.EACCES if isinstance(e, PermissionError) else -LE.ENOSYS
                self.ev_info = f"handler error: {err}"
        if self.pending_ret is not None:
            ret = self.pending_ret
        self.observe(name, params, ret, proc_before)
        self.log_event(name, pnames, params, ret, pc, proc_before)
        if self.finished:
            return
        if ret is not None:
            abi.set_return_value(ret)

    def _disp(self, name, idx, v) -> str:
        if idx in STR_ARGS.get(name, ()):
            s = self.cstr(v, 256)
            return json.dumps(s) if s is not None else "NULL"
        for bits in (self.ql.arch.bits, 32):
            if (1 << bits) - 4096 < v < (1 << bits):
                return str(v - (1 << bits))
        return str(v) if v < 0x10000 else hex(v)

    def log_event(self, name, pnames, params, ret, pc, proc) -> None:
        if self.logged_per_name[name] >= MAX_EVENTS_PER_NAME or len(self.events) >= MAX_EVENTS:
            self.events_dropped += 1
            return
        args = [self._disp(name, i, v) for i, v in enumerate(params)]
        if isinstance(ret, int):
            r = ret if ret >= 0 else f"{ret} ({LINUX_ERRNO.get(-ret, '?')})"
            if isinstance(r, int) and r >= 0x10000:
                r = hex(r)
        else:
            r = None
        ev = {"pid": proc["tid"], "pc": hex(pc), "sys": name, "args": args, "ret": r}
        if self.in_loader:
            ev["loader"] = True
        if self.ev_info:
            ev["info"] = self.ev_info[:STR_CAP]
        last = self.events[-1] if self.events else None
        if last and all(last.get(k) == ev.get(k) for k in ("pid", "pc", "sys", "args", "ret", "info")):
            last["rep"] = last.get("rep", 1) + 1
            return
        self.logged_per_name[name] += 1
        self.events.append(ev)

    def observe(self, name: str, p: list, ret, proc) -> None:
        """Turn syscalls into indicators (exact, independent of the event log bound)."""
        ok = isinstance(ret, int) and ret >= 0
        if name in ("open", "creat", "openat", "openat2"):
            i = 1 if name.startswith("openat") else 0
            path = self.cstr(p[i])
            if path is None:
                return
            path = self._abs(path, p[0] if i else None)
            flags = 0o1101 if name == "creat" else (p[i + 1] if name != "openat2" else 0)
            if self.in_loader:
                if ok and not path.startswith(("/etc/ld.so", "/proc", "/dev")):
                    self.note("modules_loaded", path)
                return
            writing = (flags & 3) != 0 or flags & self.o_creat or flags & self.o_trunc
            if writing:
                self.note("files_written", path)
            elif ok:
                self.note("files_read", path)
            else:
                self.note("files_probed", path)
            self._persistence(path, writing)
        elif name in STR_ARGS and not self.in_loader:
            idx = STR_ARGS[name]
            paths = [self.cstr(p[i]) for i in idx]
            if name in ("unlink", "unlinkat", "rmdir"):
                if paths[0]:
                    self.note("files_deleted", self._abs(paths[0], p[0] if name == "unlinkat" else None))
            elif name in ("rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"):
                if len(paths) == 2 and paths[1]:
                    src = paths[0] if name.startswith("symlink") else self._abs(paths[0] or "?")
                    self.note("files_written", f"{self._abs(paths[1])} ({name} from {src})")
                    self._persistence(self._abs(paths[1]), True)
            elif name in ("chmod", "fchmodat"):
                mode = p[1] if name == "chmod" else p[2]
                if paths[0]:
                    self.note("chmod", f"{self._abs(paths[0])} {mode & 0o7777:04o}")
            elif name in WRITE_OPS:
                if paths[0]:
                    d = "/" if name in ("mkdir", "mkdirat") else ""
                    self.note("files_written", self._abs(paths[0], p[0] if name.endswith("at") else None) + d)
                    self._persistence(self._abs(paths[0]), True)
            elif name in PROBE_OPS:
                if paths[0]:
                    self.note("files_probed", self._abs(paths[0], p[0] if name.endswith("at") or name == "statx" else None))
            elif name == "chdir" and paths[0]:
                self.note("files_probed", self._abs(paths[0]))
            elif name in ("mount", "umount2", "chroot", "swapon", "delete_module"):
                self.note("anti_analysis", f"{name}({', '.join(str(x) for x in paths)})")
        elif name in ("mmap", "mmap2") and ok and not self.in_loader:
            prot, flags, fd = p[2], p[3], _signed(p[4], 32)
            if prot & 4 and (flags & self.map_anon or fd < 0):
                self.exec_regions[ret] = (p[1], f"{name} anonymous PROT_EXEC")
        elif name == "mprotect" and ok and not self.in_loader:
            if p[2] & 4 and not self._is_image(p[0]):
                self.exec_regions.setdefault(p[0], (p[1], "mprotect PROT_EXEC"))
        elif name in ("init_module", "finit_module"):
            self.note("anti_analysis", f"{name} (kernel module load)")

    def _abs(self, path: str, dirfd=None) -> str:
        if path.startswith("/"):
            return os.path.normpath(path) if path != "/" else "/"
        if dirfd is not None and _signed(dirfd, 32) != -100:
            return f"<fd {_signed(dirfd, 32)}>/{path}"
        return os.path.normpath(os.path.join(self.ql.os.path.cwd, path))

    PERSIST = ("/etc/cron", "/var/spool/cron", "/etc/init.d", "/etc/rc", "/etc/systemd", "/lib/systemd",
               "/usr/lib/systemd", "/etc/profile", "/root/.bashrc", "/root/.profile", "/root/.ssh",
               "/home/", "/etc/ld.so.preload", "/etc/xdg/autostart", "/etc/inittab", "/etc/passwd", "/etc/shadow",
               "/etc/sudoers", "/etc/hosts")

    def _persistence(self, path: str, writing: bool) -> None:
        if writing and path.startswith(self.PERSIST):
            self.note("persistence_paths", path)

    def _is_image(self, addr: int) -> bool:
        for img in getattr(self.ql.loader, "images", []):
            if img.base <= addr < img.end:
                return True
        return False

    # ---- run -------------------------------------------------------------------------------------
    def prepare(self) -> int:
        out = self.out
        with open(self.sample, "rb") as f:
            arch, desc = elf_header_arch(f.read(64))
        if arch is None:
            self.meta["identity"] = {"format": "elf", "arch": None, "header": desc}
            self.meta["errors"].append({"stage": "load", "error": f"ELF samples are not supported for this input: "
                                        f"{desc} (supported: {', '.join(SUPPORTED)})"})
            return 5
        ident = elf_identity(self.sample)
        self.meta["identity"] = ident
        arch = ident["arch"]
        self.arch = arch
        if arch is None:
            self.meta["errors"].append({"stage": "load", "error": f"ELF samples are not supported for this input: "
                                        f"{ident['header']} (supported: {', '.join(SUPPORTED)})"})
            return 5
        if ident["elf_type"] not in ("exec", "dyn"):
            self.meta["errors"].append({"stage": "load", "error": f"ELF samples are not supported for this input: "
                                        f"type {ident['elf_type']} (only executables and PIE/shared objects)"})
            return 5
        if arch in UNTESTED:
            self.meta["warnings"].append(f"{arch} is untested and not a goal; results may be wrong")
        root = out / "rootfs"
        src = None
        if ident["linkage"] == "dynamic":
            from .elfsetup import ROOTFS_DIRS, SETUP_HINT

            name = ROOTFS_DIRS.get(arch)
            cand = self.rootfs_cache / name if (self.rootfs_cache and name) else None
            if cand is None or not (cand / "lib").is_dir():
                self.meta["errors"].append({"stage": "rootfs", "error": (
                    f"ELF samples are not supported without the Linux rootfs: this {arch} ELF is dynamically linked "
                    f"(interpreter {ident['interp']}) and its libraries are missing; run `{SETUP_HINT}` "
                    f"(fetches {', '.join(ROOTFS_DIRS.values())})" if name else
                    f"ELF samples are not supported without a rootfs: no rootfs is provided for dynamically linked "
                    f"{arch} ELFs (static ones may work)")})
                return 5
            src = cand
        if src is not None:
            self.meta["rootfs"] = {"source": str(src), "method": clone_tree(src, root)}
        else:
            root.mkdir(mode=0o700)
            self.meta["rootfs"] = {"source": None, "method": "minimal (static ELF)"}
        privatise_tree(root)
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(self.sample).name)[:64] or "sample"
        self.sample_vpath = f"/tmp/{safe}"
        build_fake_system(root, arch, self.sample_vpath, self.args)
        shutil.copyfile(self.sample, root / "tmp" / safe)
        os.chmod(root / "tmp" / safe, 0o600)
        self.rootfs = str(root)
        self.baseline = snapshot_tree(root)
        return 0

    def run(self) -> int:
        patch_qiling()
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        from qiling.utils import ql_get_module

        import qiling
        import unicorn

        self.meta["qiling_version"] = qiling.__version__
        self.meta["unicorn_version"] = unicorn.__version__
        self.dumps = DumpWriter(self.out)
        self.net = elfnet.FakeNet(self)
        self._sig_cache, self._impl_cache = {}, {}
        self._os_mod = ql_get_module(".os.linux.syscall")
        self._posix_mod = ql_get_module(".os.posix.syscall")

        host_sample = str(Path(self.rootfs) / self.sample_vpath.lstrip("/"))
        env = dict(self.env)
        env.setdefault("_", self.sample_vpath)
        profile = {"KERNEL": {"uid": "0", "gid": "0", "pid": str(MAIN_PID)},
                   "MISC": {"current_path": "/tmp"},
                   "NETWORK": {"ifrname_override": "eth0", "bindtolocalhost": "True", "ipv6": "False"}}
        self.qlog = CappedLog(self.out / "qiling.log")
        vpath = self.sample_vpath

        # argv[0] must be the emulated path, not the host path Qiling loads from.
        from qiling.loader.elf import QlLoaderELF
        orig_lwl = QlLoaderELF.load_with_ld

        def load_with_ld(loader, elffile, stack_addr, load_address, argv=(), env=None):
            argv = [vpath, *list(argv)[1:]]
            return orig_lwl(loader, elffile, stack_addr, load_address, argv, env or {})

        QlLoaderELF.load_with_ld = load_with_ld
        try:
            ql = Qiling([host_sample, *self.args], self.rootfs, env=env, verbose=QL_VERBOSE.DEFAULT,
                        profile=profile, console=False, log_devices=[self.qlog], log_plain=True)
        finally:
            QlLoaderELF.load_with_ld = orig_lwl
        self.ql = ql
        self.endian = "<" if ql.arch.endian.name == "EL" else ">"
        mips = self.arch in ("mips", "mipsel")
        self.o_creat, self.o_trunc = (0x100, 0x200) if mips else (0x40, 0x200)
        self.map_anon = 0x800 if mips else 0x20
        self.meta["command_line"] = shlex.join([vpath, *self.args])
        self.meta["env"] = env

        self.order = OutputOrder()
        self.stdout = CappedOutput(self.out / "stdout.txt", name="stdout", order=self.order)
        self.stderr = CappedOutput(self.out / "stderr.txt", name="stderr", order=self.order)
        self.stdin = StdinInput(self.stdin_data)
        ql.os.stdin = self.stdin
        ql.os.stdout = self.stdout
        ql.os.stderr = self.stderr
        for dev in ("null", "zero", "urandom", "random"):
            ql.add_fs_mapper(f"/dev/{dev}", DevFile(dev if dev != "random" else "urandom"))
        ql.add_fs_mapper("/proc/self/cmdline", BytesFile("/proc/self/cmdline",
                                                         ("\0".join([vpath, *self.args]) + "\0").encode()))
        ql.add_fs_mapper("/proc/self/environ", BytesFile("/proc/self/environ",
                                                         ("\0".join(f"{k}={v}" for k, v in env.items()) + "\0").encode()))

        self.my = self.handlers()
        ql.os.load_syscall = self.syscall

        self.in_loader = bool(self.meta["identity"]["interp"])
        elf_entry = ql.loader.elf_entry
        orig_emu_start = ql.emu_start

        def emu_start(begin, end, timeout=0, count=0):
            if self.finished:
                return
            if begin == elf_entry and self.in_loader:
                self.in_loader = False
                self.hook_resolvers()
            return orig_emu_start(begin, end, 0, count)

        ql.emu_start = emu_start
        self.t0 = time.monotonic()
        self.deadline = self.t0 + self.timeout
        self.cur = self.new_proc("main", PPID, pid=MAIN_PID)
        self.cur["start"] = hex(elf_entry)

        done = threading.Event()

        def watchdog():
            if done.wait(self.timeout):
                return
            if not self.finished:
                self.finished = True
                self.stop_reason = "timeout"
                self.stop_detail = f"time budget of {self.timeout}s reached (no syscall for a while: CPU loop)"
                if self.cur.get("stop") is None:
                    self.cur["stop"] = "timeout"
            while not done.wait(0.1):
                ql.emu_stop()
            ql.emu_stop()

        wd = threading.Thread(target=watchdog, daemon=True)
        wd.start()
        crash = None
        try:
            ql.run()
        except Exception as e:
            crash = e
        finally:
            done.set()
        self.emu_s = time.monotonic() - self.t0
        if crash is not None:
            kind = type(crash).__name__
            msg = str(crash)
            if kind == "UcError":
                reason = {"UC_ERR_READ_UNMAPPED": "invalid_read", "UC_ERR_WRITE_UNMAPPED": "invalid_write",
                          "UC_ERR_FETCH_UNMAPPED": "invalid_fetch", "UC_ERR_INSN_INVALID": "invalid_insn",
                          "UC_ERR_READ_PROT": "invalid_read", "UC_ERR_WRITE_PROT": "invalid_write",
                          "UC_ERR_FETCH_PROT": "invalid_fetch", "UC_ERR_EXCEPTION": "cpu_exception"}
                reason = next((v for k, v in reason.items() if k in msg), "cpu_error")
            else:
                reason = "emulator_error"
                self.meta["errors"].append({"stage": "qiling", "error": f"{kind}: {msg}"[:500],
                                            "traceback": traceback.format_exc(limit=6)})
            self.cur["stop"] = reason
            self.cur["pc"] = hex(ql.arch.regs.arch_pc)
            self.cur["detail"] = f"{kind}: {msg}"[:200]
            self.dump_exec_regions()
            if not self.finished:
                self.finished = True
                self.stop_reason, self.stop_detail = reason, self.cur["detail"]
        elif not self.finished:
            # emulation ended without exit_group (returned to the exit point)
            self.cur["stop"] = self.cur.get("stop") or "returned"
            self.cur["pc"] = hex(ql.arch.regs.arch_pc)
            self.dump_exec_regions()
            self.finished = True
            self.stop_reason = "returned"
        # processes still waiting for a child that never ended
        for ctx in reversed(self.stack):
            p = ctx["proc"]
            if p.get("stop") is None:
                p["stop"] = "not_resumed"
                p["detail"] = f"waiting for {ctx['kind']} {ctx['child']['tid']}, which did not end"
        for q in self.runq.values():
            for c in q:
                if c["rec"].get("stop") is None:
                    c["rec"]["stop"] = "waiting" if c["started"] else "not_run"
        for p in self.procs:
            if p.get("stop") is None:
                p["stop"] = self.stop_reason
        return 0

    RESOLVERS = ("getaddrinfo", "gethostbyname", "gethostbyname2", "gethostbyname_r", "gethostbyname2_r")

    def hook_resolvers(self) -> None:
        """Dynamic glibc samples resolve names through NSS modules (libnss_dns) that the
        Qiling rootfs lacks, so no DNS query ever reaches a socket. Hook libc's resolver
        entry points to record the names anyway (the call itself then fails)."""
        from elftools.elf.elffile import ELFFile

        # ld.so maps libraries with mmap; Qiling labels those regions "[mmap] <file name>".
        bases: dict[str, int] = {}
        for lo, hi, perm, label, mmio in self.ql.mem.map_info:
            if label.startswith("[mmap] libc.so") or label.startswith("[mmap] libc-"):
                bases[label[7:]] = min(lo, bases.get(label[7:], lo))
        for fname, base in bases.items():
            host = next((str(p) for p in Path(self.rootfs).glob(f"**/{fname}") if p.is_file()), None)
            if host is None:
                continue
            try:
                with open(host, "rb") as f:
                    dynsym = ELFFile(f).get_section_by_name(".dynsym")
                    syms = {n: dynsym.get_symbol_by_name(n) for n in self.RESOLVERS} if dynsym else {}
            except Exception as e:
                self.meta["warnings"].append(f"resolver hooks: {e}")
                continue
            for name, found in syms.items():
                if not found or not found[0]["st_value"]:
                    continue
                addr = base + found[0]["st_value"]
                if self.arch == "arm":
                    addr &= ~1

                def cb(ql, name=name):
                    host = self.cstr(ql.os.fcall.cc.getRawParam(0), 256)
                    if host:
                        self.note_dns(host)
                        self.libc_lookups.append({"function": name, "name": host, "pid": self.cur["pid"]})

                self.ql.hook_address(cb, addr)

    # ---- results -------------------------------------------------------------------------------
    def fs_diff(self) -> dict:
        root = Path(self.rootfs)
        after = snapshot_tree(root)
        created, modified, deleted, modes = [], [], [], []
        for path, a in after.items():
            b = self.baseline.get(path)
            if b is None:
                created.append(path)
            elif a[0] == "f" and (a[1], a[2], a[3]) != (b[1], b[2], b[3]):
                modified.append(path)
            elif a[4] != b[4]:
                modes.append(f"{path} {b[4]:04o}->{a[4]:04o}")
        deleted = [p for p in self.baseline if p not in after]
        for path in created + modified:
            kind = after[path][0]
            host = root / path.lstrip("/")
            if kind == "l":
                self.note("files_written", f"{path} -> {os.readlink(host)} (symlink)")
                continue
            if kind == "d":
                self.note("files_written", path + "/")
                continue
            self.note("files_written", path)
            try:
                if host.stat().st_size > 64 << 20:
                    self.dumps.skipped.append({"kind": "dropped", "emu_path": path, "size": host.stat().st_size,
                                               "reason": "size cap"})
                    continue
                with open(host, "rb") as f:
                    data = f.read()
            except OSError as e:
                self.meta["errors"].append({"stage": "fs_diff", "error": f"{path}: {e}"})
                continue
            self.dumps.add("dropped", data, name=os.path.basename(path), emu_path=path,
                           change="created" if path in created else "modified")
        for path in deleted:
            self.note("files_deleted", path)
        privatise_tree(root)  # files the sample created with exec bits become 0600 too
        return {"created": created, "modified": modified, "deleted": deleted, "mode_changed": modes}

    def net_report(self) -> list[dict]:
        out = []
        for c in self.net.conns:
            data = bytes(c.pop("data"))
            entry = {k: v for k, v in c.items() if k != "sock"}
            if data:
                entry["sha256"] = hashlib.sha256(data).hexdigest()
                entry["preview"] = elfnet.printable_preview(data)
                if len(data) <= elfnet.INLINE_MAX:
                    entry["data_hex"] = data.hex()
                else:
                    label = f"{c['ip']}_{c['port']}"
                    d = self.dumps.add("netsend", data, name=label, target=f"{c['proto']} {c['ip']}:{c['port']}")
                    entry["dump"] = d["path"] if d else None
                entry["kept"] = len(data)
            out.append(entry)
        return out

    def write_outputs(self) -> None:
        diff = self.fs_diff()
        conns = self.net_report()
        self.meta["dumps"] = self.dumps.entries
        self.meta["dumps_skipped"] = self.dumps.skipped
        report = {
            "format": FORMAT,
            "identity": self.meta.get("identity"),
            "engine": {"qiling": self.meta.get("qiling_version"), "unicorn": self.meta.get("unicorn_version")},
            "emulation": {"stop": self.stop_reason, "detail": self.stop_detail, "emu_s": round(self.emu_s, 3),
                          "virtual_sleep_s": round(self.skew, 3), "syscalls": self.total,
                          "max_syscalls": self.max_syscalls, "timeout_s": self.timeout},
            "command_line": self.meta.get("command_line"),
            "env": self.meta.get("env"),
            "sample_path": self.sample_vpath,
            "processes": self.procs,
            "syscall_counts": dict(self.counts.most_common()),
            "syscall_first_pc": self.first_pc,
            "unsupported": dict(self.unsupported.most_common()),
            "unsupported_first_pc": self.unsupported_pc,
            "handler_errors": self.handler_errors,
            "indicators": {k: v for k, v in self.ind.items()},
            "network": {"connections": conns, "dns": self.net.dns, "listening": self.net.listens,
                        "unix": self.net.unix, "refused": self.net.refused,
                        "libc_lookups": self.libc_lookups,
                        "canned_dns_answer": elfnet.CANNED_IP, "nameserver": elfnet.NAMESERVER,
                        "local_ip": elfnet.LOCAL_IP},
            "fs_diff": diff,
            "exec_regions": [{"base": hex(b), "size": hex(s), "why": w} for b, (s, w) in self.exec_regions.items()],
            "stdout": self.stdout.info(),
            "stderr": self.stderr.info(),
            "output_order": {"runs": self.order.runs, "complete": self.order.complete,
                             "note": "write order of stdout/stderr bytes, consecutive writes to one stream "
                                     "merged; the exact bytes are in stdout.txt / stderr.txt"},
            "stdin": self.stdin.info(),
            "events": self.events,
            "events_dropped": self.events_dropped,
            "event_limits": {"max_events": MAX_EVENTS, "max_per_syscall": MAX_EVENTS_PER_NAME},
        }
        _write_private(self.out / "report.json", json.dumps(report, indent=1, ensure_ascii=False).encode())
        lines = []
        for ev in self.events:
            rep = f"  x{ev['rep']}" if ev.get("rep") else ""
            info = f"  # {ev['info']}" if ev.get("info") else ""
            ld = " [ld]" if ev.get("loader") else ""
            lines.append(f"{ev['pid']} {ev['pc']}{ld} {ev['sys']}({', '.join(ev['args'])}) = {ev['ret']}{rep}{info}")
        if self.events_dropped:
            lines.append(f"[rebox: {self.events_dropped} further syscall events not logged "
                         f"(limits: {MAX_EVENTS} total, {MAX_EVENTS_PER_NAME} per syscall); counts in report.json are exact]")
        _write_private(self.out / "syscalls.log", ("\n".join(lines) + "\n").encode())


def run_inner(sample: str, out_dir: str, timeout: int, args: list[str], env: list[str], sandboxed: bool,
              max_syscalls: int, rootfs_cache: str | None, stdin_file: str | None = None) -> int:
    out = Path(out_dir)
    (out / "tmp").mkdir(mode=0o700, exist_ok=True)
    meta: dict = {"sample": sample, "backend": "qiling", "sandbox": None, "identity": None, "errors": [],
                  "warnings": [], "dumps": [], "dumps_skipped": []}
    t0 = time.monotonic()
    status = 0
    try:
        if sandboxed:
            meta["sandbox"] = sandbox.self_check(out)
            if not meta["sandbox"]["verified"]:
                meta["errors"].append({"stage": "sandbox", "error": "sandbox self-check failed; refusing to emulate"})
                return 3
        else:
            meta["sandbox"] = {"verified": False, "disabled": True}
        envd = {}
        for kv in env:
            k, sep, v = kv.partition("=")
            if not sep or not k:
                meta["errors"].append({"stage": "args", "error": f"--env needs KEY=VALUE, got {kv!r}"})
                return 2
            envd[k] = v
        stdin = b""
        if stdin_file:
            with open(stdin_file, "rb") as f:
                stdin = f.read(MAX_STDIN_BYTES + 1)
            if len(stdin) > MAX_STDIN_BYTES:
                meta["errors"].append({"stage": "args", "error": f"stdin is over {MAX_STDIN_BYTES} bytes"})
                return 2
        meta["stdin"] = {"bytes": len(stdin), "sha256": hashlib.sha256(stdin).hexdigest()} if stdin_file else None
        emu = ElfEmu(sample, out, timeout, max_syscalls, args, envd, rootfs_cache, meta, stdin)
        status = emu.prepare()
        if status:
            return status
        emu.run()
        emu.write_outputs()
    except Exception as e:
        meta["errors"].append({"stage": "inner", "error": f"{type(e).__name__}: {e}",
                               "traceback": traceback.format_exc(limit=8)})
        status = 4
    finally:
        meta["inner_wall_time"] = round(time.monotonic() - t0, 3)
        (out / "run.json").write_text(json.dumps(meta, indent=1, default=str))
        os.chmod(out / "run.json", 0o600)
    return status
