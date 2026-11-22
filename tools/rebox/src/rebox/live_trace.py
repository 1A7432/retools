"""Parse `strace -f -ff -ttt -q` output of a rebox live run into behaviour facts.

Everything in the trace is hostile input: file names, buffers and argv are
controlled by the sample. The parser relies on strace's quoting only: inside a
string literal every `"` and `\\` is escaped and every non-printable byte is an
escape sequence, so one record is one line and a literal can always be
delimited exactly. Before any pattern matching the literals are masked out
(`mask`), so sample-controlled text can never look like strace's own syntax
(a file named `sin_addr=inet_addr("1.2.3.4")` stays a file name). Unknown or
malformed lines are counted, never fatal.
"""

from __future__ import annotations

import posixpath
import re
import shlex
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

LINE_RE = re.compile(r"^(\d+\.\d+) (.*)$")
CALL_RE = re.compile(r"^([a-z_][a-z0-9_]*)\((.*)$")
EXIT_RE = re.compile(r"^\+\+\+ exited with (-?\d+) \+\+\+$")
KILLED_RE = re.compile(r"^\+\+\+ killed by (SIG[A-Z0-9]+)( \(core dumped\))? \+\+\+$")
SIGNAL_RE = re.compile(r"^--- (SIG[A-Z0-9]+) ")
STR_REF = re.compile(r'"#(\d+)"')
RESULT_RE = re.compile(r"\) *= ")
MAX_LINES_PER_FILE = 2_000_000

OPEN_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
FD_NAMES = {"AT_FDCWD"}

CATEGORIES = {
    "file": {"open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
             "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat", "mkdir",
             "mkdirat", "rmdir", "link", "linkat", "symlink", "symlinkat", "truncate", "ftruncate", "mknod",
             "mknodat", "utimensat", "utimes", "futimesat", "getdents64", "getdents", "readlink", "readlinkat",
             "statx", "newfstatat", "access", "faccessat", "faccessat2", "chdir", "fchdir", "chroot", "inotify_add_watch"},
    "network": {"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom",
                "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "getsockopt", "setsockopt", "getpeername",
                "getsockname", "shutdown"},
    "process": {"execve", "execveat", "clone", "clone3", "fork", "vfork", "kill", "tkill", "tgkill", "wait4",
                "waitid", "setsid", "setpgid", "prctl", "setuid", "setgid", "setresuid", "setresgid", "setreuid",
                "setregid", "unshare", "setns", "pidfd_open", "pidfd_send_signal", "exit_group"},
    "memory": {"mprotect", "memfd_create", "process_vm_writev", "process_vm_readv", "pkey_mprotect"},
    "anti_analysis": {"ptrace", "uname", "sysinfo", "getppid", "nanosleep", "clock_nanosleep", "personality",
                      "seccomp"},
    "privilege": {"capset", "capget", "setuid", "setgid", "setresuid", "setresgid", "init_module",
                  "finit_module", "delete_module", "mount", "umount2", "pivot_root", "bpf", "perf_event_open",
                  "keyctl", "add_key", "request_key", "iopl", "ioperm", "reboot", "swapon", "sethostname"},
}

PERSISTENCE_RE = re.compile(
    r"^(/etc/cron[^/]*(/|$)|/etc/crontab$|/etc/anacrontab$|/var/spool/(cron|at)/|/etc/systemd/|/lib/systemd/|"
    r"/usr/lib/systemd/|/etc/init\.d/|/etc/rc[^/]*\.d/|/etc/rc\.local$|/etc/inittab$|/etc/profile$|"
    r"/etc/profile\.d/|/etc/bash\.bashrc$|/etc/environment$|/etc/ld\.so\.preload$|/etc/ld\.so\.conf|"
    r"/etc/passwd$|/etc/shadow$|/etc/group$|/etc/sudoers|/etc/update-motd\.d/|/etc/xdg/autostart/|"
    r"/etc/udev/rules\.d/|/lib/udev/rules\.d/|/usr/lib/udev/rules\.d/|/etc/modules|/etc/modprobe\.d/|"
    r"/etc/pam\.d/|/etc/hosts$|/etc/resolv\.conf$|/etc/motd$|/etc/ssh/|/etc/init/|/etc/network/if-up\.d/|"
    r"/etc/NetworkManager/dispatcher\.d/|/etc/apt/apt\.conf\.d/|/usr/local/bin/|/usr/bin/|/usr/sbin/|/bin/|/sbin/|"
    r".*/\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|bash_logout)$|.*/\.config/autostart/|"
    r".*/\.config/systemd/|.*/\.ssh/authorized_keys)"
)
ANTI_ANALYSIS_PATHS = re.compile(
    r"^(/proc/self/status|/proc/\d+/status|/proc/self/exe|/proc/cpuinfo|/proc/1/cgroup|/proc/self/cgroup|"
    r"/proc/self/mountinfo|/proc/self/maps|/proc/modules|/proc/scsi/scsi|/proc/version|/proc/uptime|"
    r"/\.dockerenv|/run/\.containerenv|/sys/class/dmi/id/.*|/sys/devices/virtual/dmi/.*|/proc/net/(route|tcp|arp)|"
    r"/proc/1/(comm|cmdline|environ|sched)|/proc/self/environ|/sys/class/net.*|/etc/machine-id|/var/lib/dbus/machine-id|"
    r"/proc/sys/kernel/yama/ptrace_scope|/proc/self/stat|/proc/self/cmdline)$"
)
READ_NOISE_RE = re.compile(
    r"^(/lib/|/lib64/|/lib32/|/usr/lib/|/usr/lib64/|/usr/lib32/|/usr/libx32/|/etc/ld\.so\.cache$|"
    r"/usr/share/locale|/usr/lib/locale|/usr/share/zoneinfo|/etc/localtime$|/dev/null$|/dev/tty$|"
    r"/etc/nsswitch\.conf$|/etc/host\.conf$|/etc/gai\.conf$|/usr/share/terminfo|/etc/terminfo|/usr/lib/gconv|"
    r"/usr/bin/qemu-|/proc/sys/vm/mmap_min_addr$|/etc/ld\.so\.preload$)"
)
UNIX_NOISE = {"/var/run/nscd/socket", "/run/nscd/socket"}


# ---- low level ------------------------------------------------------------------------

def unescape(s: str) -> bytes:
    """Decode the body of a strace string literal (without the quotes)."""
    out = bytearray()
    i, n = 0, len(s)
    simple = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, "e": 27, "\\": 92, '"': 34, "'": 39}
    while i < n:
        c = s[i]
        if c != "\\" or i + 1 >= n:
            out += c.encode("utf-8", "surrogateescape") if ord(c) > 127 else bytes([ord(c)])
            i += 1
            continue
        d = s[i + 1]
        if d == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 2:i + 4]):
            out.append(int(s[i + 2:i + 4], 16))
            i += 4
        elif d in "01234567":
            j = i + 1
            while j < n and j < i + 4 and s[j] in "01234567":
                j += 1
            out.append(int(s[i + 1:j], 8) & 0xFF)
            i = j
        elif d in simple:
            out.append(simple[d])
            i += 2
        else:
            out.append(ord(d) & 0xFF if ord(d) < 256 else 63)
            i += 2
    return bytes(out)


def mask(text: str) -> tuple[str, list[tuple[bytes, bool]]]:
    """Replace every string literal with "#<n>"; return (masked, [(bytes, truncated)])."""
    out, strings = [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c != '"':
            out.append(c)
            i += 1
            continue
        j = i + 1
        while j < n and text[j] != '"':
            j += 2 if text[j] == "\\" else 1
        body = text[i + 1:min(j, n)]
        trunc = text.startswith("...", j + 1)
        strings.append((unescape(body), trunc))
        out.append(f'"#{len(strings) - 1}"')
        i = j + 1 + (3 if trunc else 0)
    return "".join(out), strings


def split_top(s: str) -> list[str]:
    """Split a masked argument list at top-level commas."""
    parts, depth, cur = [], 0, []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if cur or parts:
        parts.append("".join(cur).strip())
    return parts


@dataclass
class Call:
    ts: float
    tid: int
    name: str
    args: list[str]  # masked
    strings: list[tuple[bytes, bool]]
    ret: str
    err: str | None
    masked: str

    def s(self, token: str) -> str | None:
        """Decoded text of a token that is exactly one string literal."""
        m = re.fullmatch(r'@?"#(\d+)"', token.strip())
        if not m:
            return None
        b, trunc = self.strings[int(m.group(1))]
        return b.decode("utf-8", "backslashreplace") + ("…" if trunc else "")

    def b(self, token: str) -> bytes | None:
        m = re.fullmatch(r'"#(\d+)"', token.strip())
        return self.strings[int(m.group(1))][0] if m else None

    def strlist(self, token: str) -> list[str]:
        token = token.strip()
        if not (token.startswith("[") and token.endswith("]")):
            return []
        out = []
        for part in split_top(token[1:-1]):
            v = self.s(part)
            if v is not None:
                out.append(v)
            elif part.strip() == "...":
                out.append("…")
        return out

    @property
    def ok(self) -> bool:
        return self.err is None and self.ret not in ("?",)


def parse_line(tid: int, line: str):
    """Return ('call', Call) | ('exit', ts, code) | ('killed', ts, sig) | ('signal', ts, sig) | None."""
    m = LINE_RE.match(line)
    if not m:
        return None
    ts, rest = float(m.group(1)), m.group(2)
    if rest.startswith("+++"):
        e = EXIT_RE.match(rest)
        if e:
            return ("exit", ts, int(e.group(1)))
        k = KILLED_RE.match(rest)
        if k:
            return ("killed", ts, k.group(1))
        return None
    if rest.startswith("---"):
        sm = SIGNAL_RE.match(rest)
        return ("signal", ts, sm.group(1)) if sm else None
    cm = CALL_RE.match(rest)
    if not cm:
        return None
    name = cm.group(1)
    masked, strings = mask(cm.group(2))
    # The last top-level ") = " separates arguments and result.
    depth, cut = 0, -1
    for i, c in enumerate(masked):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                m = RESULT_RE.match(masked, i)
                if m:
                    cut, res_at = i, m.end()
                    break
            depth -= 1
    if cut < 0:
        # "<unfinished ...>", or a line cut short because strace was stopped mid-call
        body = masked[:-16] if masked.endswith("<unfinished ...>") else masked
        return ("call", Call(ts, tid, name, split_top(body.rstrip().rstrip(",")), strings, "?", "UNFINISHED", masked))
    args = split_top(masked[:cut]) if cut > 0 else []
    result = masked[res_at:].strip()
    parts = result.split(" ", 2)
    ret = parts[0]
    err = parts[1] if ret.startswith("-") and len(parts) > 1 and re.fullmatch(r"E[A-Z0-9]+", parts[1]) else None
    return ("call", Call(ts, tid, name, args, strings, ret, err, masked))


# ---- sockaddr / payload helpers ---------------------------------------------------------

def sockaddr(call: Call, token: str) -> dict | None:
    """Decode a masked sockaddr token produced by strace."""
    if not token:
        return None
    fam = re.match(r"\{sa_family=(AF_[A-Z0-9]+)", token.strip())
    if not fam:
        return None
    family = fam.group(1)
    if family == "AF_INET":
        port = re.search(r"sin_port=htons\((\d+)\)", token)
        addr = re.search(r'sin_addr=inet_addr\("#(\d+)"\)', token)
        ip = call.strings[int(addr.group(1))][0].decode("ascii", "replace") if addr else None
        return {"family": "inet", "ip": ip, "port": int(port.group(1)) if port else None}
    if family == "AF_INET6":
        port = re.search(r"sin6_port=htons\((\d+)\)", token)
        addr = re.search(r'inet_pton\(AF_INET6, "#(\d+)"', token)
        ip = call.strings[int(addr.group(1))][0].decode("ascii", "replace") if addr else None
        if ip and ip.startswith("::ffff:") and "." in ip:
            return {"family": "inet", "ip": ip[7:], "port": int(port.group(1)) if port else None}
        return {"family": "inet6", "ip": ip, "port": int(port.group(1)) if port else None}
    if family == "AF_UNIX":
        p = re.search(r'sun_path=(@?)"#(\d+)"', token)
        path = call.strings[int(p.group(2))][0].decode("utf-8", "backslashreplace") if p else ""
        return {"family": "unix", "path": ("@" if p and p.group(1) else "") + path}
    if family == "AF_NETLINK":
        return {"family": "netlink"}
    if family == "AF_PACKET":
        return {"family": "packet"}
    return {"family": family.lower()}


def iov_buffers(call: Call, token: str) -> list[bytes]:
    return [call.strings[int(i)][0] for i in re.findall(r'iov_base="#(\d+)"', token)]


def dns_names(buf: bytes, tcp: bool = False) -> list[tuple[str, int]]:
    """(qname, qtype) of every question in a DNS query packet; [] if it is not one."""
    if tcp:
        if len(buf) < 2:
            return []
        buf = buf[2:2 + struct.unpack("!H", buf[:2])[0]]
    if len(buf) < 12:
        return []
    flags, qd = struct.unpack("!HH", buf[2:6])
    if flags & 0x8000 or not 0 < qd <= 16:
        return []
    out, i = [], 12
    for _ in range(qd):
        labels = []
        while True:
            if i >= len(buf):
                return out
            n = buf[i]
            if n == 0:
                i += 1
                break
            if n & 0xC0 or i + 1 + n > len(buf) or len(labels) > 127:
                return out
            labels.append(buf[i + 1:i + 1 + n].decode("ascii", "backslashreplace"))
            i += 1 + n
        if i + 4 > len(buf):
            out.append((".".join(labels), 0))
            return out
        out.append((".".join(labels), struct.unpack("!H", buf[i:i + 2])[0]))
        i += 4
    return out


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def http_request(buf: bytes) -> tuple[str, str | None] | None:
    """(request line, Host header) if buf starts like an HTTP request."""
    if not buf.startswith(HTTP_METHODS):
        return None
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    host = None
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        if k.strip().lower() == "host":
            host = v.strip()
    return lines[0][:300], host


def tls_sni(buf: bytes) -> str | None:
    """Server name from a TLS ClientHello, defensively."""
    try:
        if len(buf) < 43 or buf[0] != 0x16 or buf[5] != 0x01:
            return None
        i = 9 + 2 + 32  # record hdr 5 + handshake hdr 4, version, random
        sid = buf[i]
        i += 1 + sid
        cs = struct.unpack("!H", buf[i:i + 2])[0]
        i += 2 + cs
        cm = buf[i]
        i += 1 + cm
        ext_total = struct.unpack("!H", buf[i:i + 2])[0]
        i += 2
        end = min(len(buf), i + ext_total)
        while i + 4 <= end:
            et, el = struct.unpack("!HH", buf[i:i + 4])
            i += 4
            if et == 0 and i + 5 <= end:
                nl = struct.unpack("!H", buf[i + 3:i + 5])[0]
                return buf[i + 5:i + 5 + nl].decode("ascii", "backslashreplace")
            i += el
    except (IndexError, struct.error):
        return None
    return None


def printable(buf: bytes, cap: int = 80) -> str:
    s = buf[:cap].decode("latin-1")
    s = "".join(c if 32 <= ord(c) < 127 else "." for c in s)
    return s + (f"…[+{len(buf) - cap}]" if len(buf) > cap else "")


# ---- the analysis ------------------------------------------------------------------------

@dataclass
class Proc:
    pid: int
    ppid: int | None = None
    execs: list = field(default_factory=list)  # (ts, path, argv, result)
    exit: str | None = None
    threads: set = field(default_factory=set)
    emulator: str | None = None
    first_ts: float | None = None


class Analysis:
    def __init__(self, sample_path: str, fakenet_answer: str | None = None):
        self.sample_path = sample_path
        self.fakenet_answer = fakenet_answer
        self.hist: Counter = Counter()
        self.failed: Counter = Counter()
        self.cats: dict[str, Counter] = {k: Counter() for k in CATEGORIES}
        self.procs: dict[int, Proc] = {}
        self.tgid: dict[int, int] = {}
        self.fds: dict[int, dict] = {}
        self.cwd: dict[int, str] = {}
        self.ind: dict[str, Counter] = {k: Counter() for k in (
            "hosts", "ips", "conns", "ports", "urls", "data_out", "listening", "unix_sockets", "files_written",
            "files_read", "files_deleted", "files_renamed", "files_chmod", "persistence", "cmdlines",
            "proc_names", "memfd", "anti_analysis", "signals_sent", "privilege")}
        self.unparsed = 0
        self.lines = 0
        self.files = 0
        self.root: int | None = None
        self.notes: list[str] = []

    # -- input
    def load_dir(self, trace_dir: Path, max_files: int = 4096) -> None:
        files = sorted((p for p in trace_dir.glob("t.*") if p.suffix[1:].isdigit() and p.is_file()),
                       key=lambda p: int(p.suffix[1:]))
        if len(files) > max_files:
            self.notes.append(f"{len(files)} trace files, only the first {max_files} parsed")
            files = files[:max_files]
        events = []
        for p in files:
            tid = int(p.suffix[1:])
            self.files += 1
            with open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
                for n, line in enumerate(f):
                    if n >= MAX_LINES_PER_FILE:
                        self.notes.append(f"trace file t.{tid} cut at {MAX_LINES_PER_FILE} lines")
                        break
                    self.lines += 1
                    ev = parse_line(tid, line.rstrip("\n"))
                    if ev is None:
                        if line.strip():
                            self.unparsed += 1
                        continue
                    events.append((ev[1].ts if ev[0] == "call" else ev[1], tid, n, ev))
        events.sort(key=lambda e: (e[0], e[1], e[2]))
        self._relations(events)
        for _ts, tid, _n, ev in events:
            self._event(tid, ev)

    def _relations(self, events) -> None:
        """Thread/process relations from clone results, before replaying in time order."""
        children = set()
        for _ts, tid, _n, ev in events:
            if ev[0] != "call":
                continue
            c = ev[1]
            if c.name in ("clone", "clone3", "fork", "vfork") and c.ret.isdigit() and c.ret != "0":
                child = int(c.ret)
                children.add(child)
                if c.name in ("clone", "clone3") and "CLONE_THREAD" in c.masked:
                    self.tgid[child] = self.tgid.get(tid, tid)
        tids = sorted({e[1] for e in events})
        roots = [t for t in tids if t not in children]
        self.root = roots[0] if roots else (tids[0] if tids else None)
        if len(roots) > 1:
            self.notes.append(f"several trace roots {roots[:5]}; using {self.root}")

    def _g(self, tid: int) -> int:
        return self.tgid.get(tid, tid)

    def _proc(self, pid: int) -> Proc:
        p = self.procs.get(pid)
        if p is None:
            p = self.procs[pid] = Proc(pid)
            self.fds.setdefault(pid, {})
            self.cwd.setdefault(pid, "/tmp")
        return p

    # -- replay
    def _event(self, tid: int, ev) -> None:
        pid = self._g(tid)
        proc = self._proc(pid)
        kind = ev[0]
        if kind == "exit":
            if tid == pid or proc.exit is None:
                proc.exit = f"exit {ev[2]}"
            return
        if kind == "killed":
            proc.exit = f"signal {ev[2]}"
            return
        if kind == "signal":
            return
        c: Call = ev[1]
        if proc.first_ts is None:
            proc.first_ts = c.ts
        self.hist[c.name] += 1
        for cat, names in CATEGORIES.items():
            if c.name in names:
                self.cats[cat][c.name] += 1
        if c.err and c.err != "UNFINISHED":
            self.failed[f"{c.name} {c.err}"] += 1
        handler = getattr(self, "_c_" + c.name, None)
        if handler:
            try:
                handler(pid, proc, c)
            except (IndexError, ValueError, KeyError, struct.error) as e:
                self.unparsed += 1
                if len(self.notes) < 20:
                    self.notes.append(f"could not interpret {c.name} in t.{tid}: {type(e).__name__}")

    # -- helpers
    def _path(self, pid: int, dirfd: str | None, token: str, c: Call) -> str | None:
        p = c.s(token)
        if p is None:
            return None
        if p.startswith("/"):
            return posixpath.normpath(p)
        base = self.cwd.get(pid, "/")
        if dirfd and dirfd not in FD_NAMES:
            ent = self.fds.get(pid, {}).get(_fdnum(dirfd))
            base = ent.get("path") if ent and ent.get("path") else f"<fd {dirfd}>"
        return posixpath.normpath(posixpath.join(base, p))

    def _suffix(self, c: Call) -> str:
        return "" if c.err is None else f" [{c.err}]"

    def _wrote(self, path: str, c: Call, what: str = "files_written") -> None:
        self.ind[what][path + self._suffix(c)] += 1
        if PERSISTENCE_RE.match(path):
            self.ind["persistence"][f"{c.name} {path}{self._suffix(c)}"] += 1

    def _emulated(self, proc: Proc) -> bool:
        return proc.emulator is not None

    # -- files
    def _open(self, pid, proc, c, dirfd, ptoken, flags):
        path = self._path(pid, dirfd, ptoken, c)
        if path is None:
            return
        if any(f in flags for f in OPEN_WRITE_FLAGS):
            self._wrote(path, c)
        else:
            if ANTI_ANALYSIS_PATHS.match(path):
                self.ind["anti_analysis"][f"open {path}{self._suffix(c)}"] += 1
            if not READ_NOISE_RE.match(path) and path != self.sample_path:
                self.ind["files_read"][path + self._suffix(c)] += 1
        if c.ok and c.ret.isdigit():
            self.fds[pid][int(c.ret)] = {"kind": "file", "path": path}

    def _c_open(self, pid, proc, c):
        self._open(pid, proc, c, None, c.args[0], c.args[1] if len(c.args) > 1 else "")

    def _c_openat(self, pid, proc, c):
        self._open(pid, proc, c, c.args[0], c.args[1], c.args[2] if len(c.args) > 2 else "")

    def _c_openat2(self, pid, proc, c):
        self._open(pid, proc, c, c.args[0], c.args[1], c.args[2] if len(c.args) > 2 else "")

    def _c_creat(self, pid, proc, c):
        self._open(pid, proc, c, None, c.args[0], "O_CREAT")

    def _c_unlink(self, pid, proc, c):
        p = self._path(pid, None, c.args[0], c)
        if p:
            self._wrote(p, c, "files_deleted")

    def _c_unlinkat(self, pid, proc, c):
        p = self._path(pid, c.args[0], c.args[1], c)
        if p:
            self._wrote(p, c, "files_deleted")

    _c_rmdir = _c_unlink

    def _rename(self, pid, c, d1, t1, d2, t2):
        a, b = self._path(pid, d1, t1, c), self._path(pid, d2, t2, c)
        if a and b:
            self.ind["files_renamed"][f"{a} -> {b}{self._suffix(c)}"] += 1
            if PERSISTENCE_RE.match(b):
                self.ind["persistence"][f"{c.name} {a} -> {b}{self._suffix(c)}"] += 1

    def _c_rename(self, pid, proc, c):
        self._rename(pid, c, None, c.args[0], None, c.args[1])

    def _c_renameat(self, pid, proc, c):
        self._rename(pid, c, c.args[0], c.args[1], c.args[2], c.args[3])

    _c_renameat2 = _c_renameat

    def _c_link(self, pid, proc, c):
        a, b = self._path(pid, None, c.args[0], c), self._path(pid, None, c.args[1], c)
        if a and b:
            self._wrote(f"{b} (hard link to {a})", c)

    def _c_linkat(self, pid, proc, c):
        a, b = self._path(pid, c.args[0], c.args[1], c), self._path(pid, c.args[2], c.args[3], c)
        if a and b:
            self._wrote(f"{b} (hard link to {a})", c)

    def _c_symlink(self, pid, proc, c):
        target, b = c.s(c.args[0]), self._path(pid, None, c.args[1], c)
        if b is not None:
            self._wrote(f"{b} (symlink to {target})", c)
            if PERSISTENCE_RE.match(b) and not c.err:
                self.ind["persistence"][f"symlink {b} -> {target}"] += 1

    def _c_symlinkat(self, pid, proc, c):
        target, b = c.s(c.args[0]), self._path(pid, c.args[1], c.args[2], c)
        if b is not None:
            self._wrote(f"{b} (symlink to {target})", c)
            if PERSISTENCE_RE.match(b) and not c.err:
                self.ind["persistence"][f"symlink {b} -> {target}"] += 1

    def _chmod(self, pid, c, dirfd, ptoken, mode):
        p = self._path(pid, dirfd, ptoken, c)
        if p:
            self.ind["files_chmod"][f"{p} {mode}{self._suffix(c)}"] += 1

    def _c_chmod(self, pid, proc, c):
        self._chmod(pid, c, None, c.args[0], c.args[1] if len(c.args) > 1 else "?")

    def _c_fchmodat(self, pid, proc, c):
        self._chmod(pid, c, c.args[0], c.args[1], c.args[2] if len(c.args) > 2 else "?")

    _c_fchmodat2 = _c_fchmodat

    def _c_fchmod(self, pid, proc, c):
        ent = self.fds[pid].get(_fdnum(c.args[0]))
        if ent and ent.get("path"):
            self.ind["files_chmod"][f"{ent['path']} {c.args[1]}{self._suffix(c)}"] += 1

    def _c_truncate(self, pid, proc, c):
        p = self._path(pid, None, c.args[0], c)
        if p:
            self._wrote(p, c)

    def _c_chdir(self, pid, proc, c):
        p = self._path(pid, None, c.args[0], c)
        if p and c.ok:
            self.cwd[pid] = p

    def _c_fchdir(self, pid, proc, c):
        ent = self.fds[pid].get(_fdnum(c.args[0]))
        if ent and ent.get("path") and c.ok:
            self.cwd[pid] = ent["path"]

    def _c_readlinkat(self, pid, proc, c):
        p = self._path(pid, c.args[0], c.args[1], c)
        if p and ANTI_ANALYSIS_PATHS.match(p) and not (self._emulated(proc) and p == "/proc/self/exe"):
            self.ind["anti_analysis"][f"readlink {p}"] += 1

    def _c_readlink(self, pid, proc, c):
        p = self._path(pid, None, c.args[0], c)
        if p and ANTI_ANALYSIS_PATHS.match(p):
            self.ind["anti_analysis"][f"readlink {p}"] += 1

    def _stat_like(self, pid, proc, c, dirfd, token):
        p = self._path(pid, dirfd, token, c)
        if p and ANTI_ANALYSIS_PATHS.match(p):
            self.ind["anti_analysis"][f"{c.name} {p}{self._suffix(c)}"] += 1

    def _c_newfstatat(self, pid, proc, c):
        self._stat_like(pid, proc, c, c.args[0], c.args[1])

    _c_statx = _c_newfstatat
    _c_faccessat = _c_newfstatat
    _c_faccessat2 = _c_newfstatat

    def _c_access(self, pid, proc, c):
        self._stat_like(pid, proc, c, None, c.args[0])

    _c_stat = _c_access

    # -- fds
    def _c_close(self, pid, proc, c):
        self.fds[pid].pop(_fdnum(c.args[0]), None)

    def _dup(self, pid, old, new):
        ent = self.fds[pid].get(_fdnum(old))
        if ent is not None and new is not None:
            self.fds[pid][new] = ent

    def _c_dup(self, pid, proc, c):
        if c.ok and c.ret.isdigit():
            self._dup(pid, c.args[0], int(c.ret))

    _c_dup2 = _c_dup
    _c_dup3 = _c_dup

    def _c_fcntl(self, pid, proc, c):
        if len(c.args) > 1 and c.args[1].startswith("F_DUPFD") and c.ok and c.ret.isdigit():
            self._dup(pid, c.args[0], int(c.ret))

    # -- network
    def _c_socket(self, pid, proc, c):
        if c.ok and c.ret.isdigit():
            typ = c.args[1] if len(c.args) > 1 else ""
            proto = "tcp" if "SOCK_STREAM" in typ else "udp" if "SOCK_DGRAM" in typ else "raw" if "SOCK_RAW" in typ else typ
            self.fds[pid][int(c.ret)] = {"kind": "socket", "domain": c.args[0], "proto": proto, "peer": None}
            if c.args[0] in ("AF_PACKET",) or "SOCK_RAW" in typ:
                self.ind["privilege"][f"socket {c.args[0]} {typ}"] += 1

    def _sock(self, pid, fd_token):
        ent = self.fds[pid].get(_fdnum(fd_token))
        return ent if ent and ent.get("kind") == "socket" else None

    def _remote(self, sa: dict) -> bool:
        if sa.get("family") == "inet":
            return not (sa.get("ip") or "").startswith("127.")
        if sa.get("family") == "inet6":
            return sa.get("ip") not in ("::1", None)
        return False

    def _note_peer(self, proto, sa, c, verb="connect"):
        fam = sa.get("family")
        if fam in ("inet", "inet6"):
            ip, port = sa.get("ip"), sa.get("port")
            hostport = f"[{ip}]:{port}" if fam == "inet6" else f"{ip}:{port}"
            res = "ok" if c.ok else (c.err or "?")
            if res == "EINPROGRESS":
                res = "in progress"
            if port == 53 and not self._remote(sa):
                return  # the resolver; queries are reported as hosts
            self.ind["conns"][f"{proto} {verb} {hostport} {res}"] += 1
            if self._remote(sa) and ip and ip != self.fakenet_answer:
                self.ind["ips"][ip] += 1
            if port is not None:
                self.ind["ports"][str(port)] += 1
        elif fam == "unix":
            if sa.get("path") not in UNIX_NOISE:
                self.ind["unix_sockets"][f"{verb} {sa.get('path')}{self._suffix(c)}"] += 1

    def _c_connect(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        sa = sockaddr(c, c.args[1]) if len(c.args) > 1 else None
        if not sa:
            return
        proto = ent["proto"] if ent else "?"
        if ent is not None and (c.ok or c.err == "EINPROGRESS"):
            ent["peer"] = sa
        self._note_peer(proto, sa, c)

    def _c_bind(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        sa = sockaddr(c, c.args[1]) if len(c.args) > 1 else None
        if not sa:
            return
        if sa.get("family") in ("inet", "inet6") and sa.get("port"):
            self.ind["listening"][f"{ent['proto'] if ent else '?'} bind {sa.get('ip')}:{sa.get('port')}{self._suffix(c)}"] += 1
            self.ind["ports"][str(sa.get("port"))] += 1
        elif sa.get("family") == "unix":
            self.ind["unix_sockets"][f"bind {sa.get('path')}{self._suffix(c)}"] += 1
        if ent is not None:
            ent["local"] = sa

    def _c_accept(self, pid, proc, c):
        if c.ok and c.ret.isdigit():
            ent = self._sock(pid, c.args[0])
            self.fds[pid][int(c.ret)] = {"kind": "socket", "proto": ent["proto"] if ent else "tcp", "peer": None,
                                         "accepted": True}
            self.ind["listening"][f"accept on fd {c.args[0]}"] += 1

    _c_accept4 = _c_accept

    def _payload(self, pid, c, ent, sa, bufs: list[bytes]):
        if not bufs:
            return
        sa = sa or (ent.get("peer") if ent else None)
        if not sa or sa.get("family") not in ("inet", "inet6"):
            return
        proto = ent["proto"] if ent else "?"
        if sa.get("port") == 53:
            for buf in bufs:
                for name, qtype in dns_names(buf, tcp=(proto == "tcp")):
                    if name:
                        self.ind["hosts"][name.lower()] += 1
            if self._remote(sa):
                self._note_peer(proto, sa, c, "send")
            return
        if not self._remote(sa) and not self.fakenet_answer:
            return
        data = b"".join(bufs)
        hostport = f"{sa.get('ip')}:{sa.get('port')}"
        req = http_request(data)
        if req:
            line, host = req
            parts = line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            self.ind["urls"][f"http://{host or hostport}{path}"] += 1
            if host:
                self.ind["hosts"][host.split(":")[0].lower()] += 1
        sni = tls_sni(data)
        if sni:
            self.ind["hosts"][sni.lower()] += 1
            self.ind["urls"][f"tls sni={sni} -> {hostport}"] += 1
        self.ind["data_out"][f"{proto} {hostport} {len(data)}B {printable(data)!r}{self._suffix(c)}"] += 1
        if c.name in ("sendto", "sendmsg", "sendmmsg") and sa is not (ent or {}).get("peer"):
            self._note_peer(proto, sa, c, "send")

    def _c_sendto(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        sa = sockaddr(c, c.args[4]) if len(c.args) > 4 and c.args[4] != "NULL" else None
        buf = c.b(c.args[1])
        self._payload(pid, c, ent, sa, [buf] if buf is not None else [])

    def _c_sendmsg(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        token = c.args[1] if len(c.args) > 1 else ""
        m = re.match(r"\{msg_name=(\{.*?\})", token)
        sa = sockaddr(c, m.group(1)) if m else None
        self._payload(pid, c, ent, sa, iov_buffers(c, token))

    def _c_sendmmsg(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        token = c.args[1] if len(c.args) > 1 else ""
        m = re.search(r"msg_name=(\{sa_family=.*?\})", token)
        sa = sockaddr(c, m.group(1)) if m else None
        for buf in iov_buffers(c, token):
            self._payload(pid, c, ent, sa, [buf])

    def _c_write(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        if ent:
            buf = c.b(c.args[1])
            self._payload(pid, c, ent, None, [buf] if buf is not None else [])

    _c_send = _c_write

    def _c_writev(self, pid, proc, c):
        ent = self._sock(pid, c.args[0])
        if ent:
            self._payload(pid, c, ent, None, [b"".join(iov_buffers(c, c.args[1]))])

    # -- processes
    def _c_execve(self, pid, proc, c, dirfd=None, ptoken=None, atoken=None):
        ptoken = ptoken or c.args[0]
        atoken = atoken or (c.args[1] if len(c.args) > 1 else "")
        path = self._path(pid, dirfd, ptoken, c) or "?"
        argv = c.strlist(atoken)
        first = not proc.execs and pid == self.root
        proc.execs.append((c.ts, path, argv, "ok" if c.ok else c.err))
        if c.ok:
            m = re.fullmatch(r"/usr/bin/(qemu-[a-z0-9_]+)", path)
            proc.emulator = m.group(1) if m else None
        if first:
            return  # rebox's own launch of the sample
        cmd = _join(argv) if argv else path
        if argv and posixpath.basename(path) != posixpath.basename(argv[0]):
            cmd = f"{cmd}  (file {path})"
        self.ind["cmdlines"][cmd + self._suffix(c)] += 1
        if path.startswith("/proc/self/fd/") or path.startswith("/dev/fd/") or "memfd:" in path:
            self.ind["memfd"][f"exec {path}"] += 1

    def _c_execveat(self, pid, proc, c):
        self._c_execve(pid, proc, c, c.args[0], c.args[1], c.args[2] if len(c.args) > 2 else "")

    def _fork(self, pid, proc, c):
        if not (c.ok and c.ret.isdigit()):
            return
        child = int(c.ret)
        if c.name in ("clone", "clone3") and "CLONE_THREAD" in c.masked:
            if proc.emulator is None:
                proc.threads.add(child)  # QEMU's own helper thread is not the sample's
            return
        cp = self._proc(child)
        cp.ppid = pid
        cp.emulator = proc.emulator
        if c.name in ("clone", "clone3") and "CLONE_FILES" in c.masked:
            self.fds[child] = self.fds[pid]
        else:
            self.fds[child] = {k: dict(v) for k, v in self.fds[pid].items()}
        self.cwd[child] = self.cwd.get(pid, "/tmp")

    _c_clone = _fork
    _c_clone3 = _fork
    _c_fork = _fork
    _c_vfork = _fork

    def _c_kill(self, pid, proc, c):
        if len(c.args) > 1 and c.args[1] not in ("0", "SIGCHLD"):
            self.ind["signals_sent"][f"kill({c.args[0]}, {c.args[1]}){self._suffix(c)}"] += 1

    def _c_prctl(self, pid, proc, c):
        if c.args and c.args[0] == "PR_SET_NAME" and len(c.args) > 1:
            name = c.s(c.args[1])
            if name is not None:
                self.ind["proc_names"][name] += 1
        elif c.args and c.args[0] in ("PR_SET_DUMPABLE", "PR_SET_PTRACER", "PR_SET_SECCOMP"):
            self.ind["anti_analysis"][f"prctl {', '.join(c.args[:2])}"] += 1

    def _c_ptrace(self, pid, proc, c):
        self.ind["anti_analysis"][f"ptrace {c.args[0] if c.args else '?'} = {c.ret}{self._suffix(c)}"] += 1

    def _c_memfd_create(self, pid, proc, c):
        self.ind["memfd"][f"memfd_create {c.s(c.args[0]) if c.args else '?'}{self._suffix(c)}"] += 1
        if c.ok and c.ret.isdigit():
            self.fds[pid][int(c.ret)] = {"kind": "memfd", "path": f"memfd:{c.s(c.args[0])}"}

    def _priv(self, pid, proc, c):
        self.ind["privilege"][f"{c.name}({', '.join(a[:40] for a in c.args[:3])}){self._suffix(c)}"] += 1

    # -- results
    def processes(self) -> list[dict]:
        out = []
        for pid in sorted(self.procs):
            p = self.procs[pid]
            if self._g(pid) != pid:
                continue
            ex = [e for e in p.execs if e[3] == "ok"]
            if ex:
                ts, path, argv, _ = ex[-1]
                if argv and posixpath.basename(argv[0]).startswith("qemu-") and path.startswith("/usr/bin/qemu-"):
                    argv = _strip_qemu(argv)
                cmd = _join(argv) if argv else path
            else:
                cmd = "(fork, no exec)"
            emu = None
            for _ts, path, _argv, res in p.execs:
                if res == "ok":
                    m = re.fullmatch(r"/usr/bin/(qemu-[a-z0-9_]+)", path)
                    emu = m.group(1) if m else None
            if not p.execs and p.emulator:
                emu = p.emulator
            out.append({"pid": pid, "ppid": p.ppid, "cmd": cmd, "exit": p.exit or "not seen",
                        "emulated": emu, "threads": len(p.threads), "execs": len(p.execs)})
        return out

    def root_exit(self) -> str | None:
        p = self.procs.get(self.root) if self.root is not None else None
        return p.exit if p else None


for _n in ("init_module", "finit_module", "delete_module", "mount", "umount2", "pivot_root", "unshare",
           "setns", "setuid", "setgid", "setresuid", "setresgid", "capset", "bpf", "iopl", "ioperm",
           "reboot", "sethostname", "chroot", "keyctl"):
    setattr(Analysis, "_c_" + _n, Analysis._priv)
del _n


def _fdnum(token: str) -> int | None:
    token = token.strip()
    return int(token) if token.lstrip("-").isdigit() else None


def _strip_qemu(argv: list[str]) -> list[str]:
    """['qemu-x86_64', '-L', '/', '/tmp/x', 'a'] -> ['/tmp/x', 'a']."""
    i = 1
    while i < len(argv) and argv[i].startswith("-"):
        i += 2 if argv[i] in ("-L", "-0", "-cpu", "-E", "-U", "-s", "-R", "-B", "-d", "-D") else 1
    return argv[i:]


def _join(argv: list[str]) -> str:
    try:
        return shlex.join(argv)
    except (TypeError, ValueError):
        return " ".join(argv)
