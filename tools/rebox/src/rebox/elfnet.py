"""Fake network for the Qiling backend: no emulated socket ever becomes a host socket.

Qiling's own socket syscalls open real host sockets (a connect() reaches the
host network stack). rebox replaces every socket-related syscall with the
handlers below, which keep sockets as plain Python objects:

* connect (TCP/UDP, IPv4/IPv6, raw, packet): recorded, reported as succeeded.
* send/sendto/sendmsg/sendmmsg/write: recorded (first CONN_KEEP bytes per
  connection kept for a dump) and reported as fully sent.
* recv/read on a connected stream: end of stream (0 bytes).
* DNS: a query sent to UDP or TCP port 53 is parsed, the name recorded, and a
  reply queued on the socket: CANNED_IP for A queries, no records for others.
* bind/listen: recorded. accept: no peer ever arrives. Non-blocking accept
  returns EAGAIN; a blocking accept ends the emulated process with stop reason
  `blocked` (the program would wait forever), see ElfEmu.block().
* AF_UNIX connect: ENOENT (no local services exist); AF_NETLINK: EAFNOSUPPORT.
* poll/ppoll/select/pselect6/epoll_*: answered from the fake sockets' state.

The sandbox (no network at all) stays the backstop: even a bug here cannot
reach a real network.
"""

from __future__ import annotations

import os
import struct

AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET = 1, 2, 10, 16, 17
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW = 1, 2, 3
SOCK_TYPE_MASK = 0xF
SOCK_NONBLOCK = 0o4000
O_NONBLOCK = 0o4000

EPERM, ENOENT, EINTR, EBADF, EAGAIN, EFAULT, EINVAL = 1, 2, 4, 9, 11, 14, 22
ENOSYS, ENOTSOCK, EDESTADDRREQ, EAFNOSUPPORT, ECHILD = 38, 88, 89, 97, 10

# Linux errno values (the host's errno module has macOS values).
LINUX_ERRNO = {1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO", 7: "E2BIG", 8: "ENOEXEC",
               9: "EBADF", 10: "ECHILD", 11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 16: "EBUSY",
               17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL", 23: "ENFILE",
               24: "EMFILE", 25: "ENOTTY", 26: "ETXTBSY", 27: "EFBIG", 28: "ENOSPC", 29: "ESPIPE", 30: "EROFS",
               32: "EPIPE", 34: "ERANGE", 36: "ENAMETOOLONG", 38: "ENOSYS", 39: "ENOTEMPTY", 40: "ELOOP",
               61: "ENODATA", 75: "EOVERFLOW", 88: "ENOTSOCK", 89: "EDESTADDRREQ", 95: "EOPNOTSUPP",
               97: "EAFNOSUPPORT", 98: "EADDRINUSE", 99: "EADDRNOTAVAIL", 101: "ENETUNREACH", 104: "ECONNRESET",
               106: "EISCONN", 107: "ENOTCONN", 110: "ETIMEDOUT", 111: "ECONNREFUSED", 113: "EHOSTUNREACH",
               115: "EINPROGRESS"}
LE = type("LE", (), {v: k for k, v in LINUX_ERRNO.items()})

CANNED_IP = "203.0.113.10"        # every DNS A answer (TEST-NET-3, never routed)
NAMESERVER = "192.168.1.1"        # /etc/resolv.conf of the fake system
LOCAL_IP = "192.168.1.23"         # address of the fake host's eth0
CONN_KEEP = 1 << 20               # bytes of outgoing data kept per connection
INLINE_MAX = 256                  # sends up to this size stay inline in the report

POLLIN, POLLPRI, POLLOUT, POLLERR, POLLHUP, POLLNVAL = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20
POLLRDNORM, POLLWRNORM = 0x40, 0x100


def _stat_like(mode: int):
    """An os.stat_result for objects without a host file (Qiling packs it by index)."""
    st = os.stat("/dev/null")
    seq = list(st[:10])
    seq[0], seq[6] = mode, 0  # st_mode, st_size
    extra = {k: getattr(st, k) for k in ("st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns",
                                         "st_ctime_ns", "st_blksize", "st_blocks", "st_rdev") if hasattr(st, k)}
    from qiling.os.posix.stat import StatBase

    return StatBase(os.stat_result(seq, extra))


class FakeSocket:
    """A socket that exists only in the emulator."""

    _next_id = 1

    def __init__(self, family: int, stype: int, proto: int, nonblock: bool):
        self.id = FakeSocket._next_id
        FakeSocket._next_id += 1
        self.family, self.type, self.proto = family, stype, proto
        self.nonblock = nonblock
        self.peer = None          # (ip, port) or unix path
        self.bound = None
        self.listening = False
        self.queue: list[tuple[bytes, tuple]] = []
        self.conn = None          # connection record (dict) once connected / sent
        self.closed = False
        self.refs = 1
        self.pair = None          # socketpair partner
        self.net = None           # owning FakeNet

    # --- file-like interface used by Qiling's generic fd syscalls -------------------
    def read(self, n: int) -> bytes:
        return self.net.recv(self, n)[0] if self.net else b""

    def write(self, data) -> int:
        if self.net:
            self.net.send(self, bytes(data), None, "write")
        return len(data)

    def fileno(self) -> int:
        return -1

    def fstat(self):
        return _stat_like(0o140777)

    def close(self) -> None:
        self.refs -= 1
        if self.refs <= 0:
            self.closed = True

    def dup(self):
        self.refs += 1
        return self

    def fcntl(self, cmd, arg):
        if cmd == 3:  # F_GETFL
            return 2 | (O_NONBLOCK if self.nonblock else 0)
        if cmd == 4:  # F_SETFL
            self.nonblock = bool(arg & O_NONBLOCK)
        return 0

    def ioctl(self, cmd, arg):
        return 0

    def readable(self) -> bool:
        if self.queue:
            return True
        # a connected stream whose peer "closed": read returns 0 at once
        return self.type == SOCK_STREAM and self.peer is not None


class FakeEpoll:
    def __init__(self):
        self.interest: dict[int, tuple[int, int]] = {}
        self.refs = 1

    def read(self, n):
        return b""

    def write(self, data):
        return len(data)

    def fileno(self):
        return -1

    def fstat(self):
        return _stat_like(0o100600)

    def close(self):
        self.refs -= 1

    def dup(self):
        self.refs += 1
        return self

    def fcntl(self, cmd, arg):
        return 0


# --- DNS ------------------------------------------------------------------------------

def parse_dns_query(data: bytes):
    """-> (id, name, qtype, question bytes) or None."""
    if len(data) < 17:
        return None
    qid, flags, qd = struct.unpack(">HHH", data[:6])
    if flags & 0x8000 or qd < 1:
        return None
    pos, labels = 12, []
    while pos < len(data):
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 or pos + 1 + n > len(data):
            return None
        labels.append(data[pos + 1:pos + 1 + n].decode("latin-1"))
        pos += 1 + n
    else:
        return None
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
    return qid, ".".join(labels), qtype, data[12:pos + 4]


def build_dns_reply(qid: int, qtype: int, question: bytes, answer_ip: str) -> bytes:
    answers = b""
    if qtype == 1:
        answers = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + bytes(int(x) for x in answer_ip.split("."))
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1 if answers else 0, 0, 0) + question + answers


QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def http_url(data: bytes, dst: str, port: int):
    if not data.startswith(HTTP_METHODS):
        return None
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    parts = head[0].split(" ")
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]
    host = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("host:")), None)
    if path.startswith("http://") or path.startswith("https://"):
        return method, path
    authority = host or (dst if port == 80 else f"{dst}:{port}")
    return method, f"http://{authority}{path}"


def printable_preview(data: bytes, cap: int = 120) -> str:
    s = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:cap])
    return s + (f"…[+{len(data) - cap}]" if len(data) > cap else "")


# --- the network model ------------------------------------------------------------------

class FakeNet:
    def __init__(self, emu):
        self.emu = emu
        self.conns: list[dict] = []
        self.dns: list[dict] = []
        self.listens: list[str] = []
        self.unix: list[str] = []
        self.refused: list[str] = []
        self.next_port = 40000

    @property
    def ql(self):
        return self.emu.ql

    # ---- helpers -------------------------------------------------------------------
    def sock(self, fd: int):
        if not 0 <= fd < len(self.ql.os.fd):
            return -EBADF
        s = self.ql.os.fd[fd]
        if s is None:
            return -EBADF
        if not isinstance(s, FakeSocket):
            return -ENOTSOCK
        return s

    def new_fd(self, obj) -> int:
        fds = self.ql.os.fd
        for i in range(len(fds)):
            if fds[i] is None:
                fds[i] = obj
                return i
        return -24  # EMFILE

    def u16(self, b: bytes) -> int:
        return int.from_bytes(b[:2], "little" if self.ql.arch.endian.name == "EL" else "big")

    def parse_sockaddr(self, addr: int, alen: int):
        if not addr or alen < 2:
            return None
        alen = min(alen, 128)
        try:
            data = bytes(self.ql.mem.read(addr, alen))
        except Exception:
            return None
        fam = self.u16(data)
        if fam == AF_INET and len(data) >= 8:
            return AF_INET, ".".join(str(x) for x in data[4:8]), int.from_bytes(data[2:4], "big")
        if fam == AF_INET6 and len(data) >= 24:
            import ipaddress
            ip = ipaddress.IPv6Address(data[8:24])
            ip = str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)
            return AF_INET6, ip, int.from_bytes(data[2:4], "big")
        if fam == AF_UNIX:
            path = data[2:].split(b"\0", 1)[0] if data[2:3] != b"\0" else b"@" + data[3:].split(b"\0", 1)[0]
            return AF_UNIX, path.decode("latin-1"), None
        return fam, None, None

    def write_sockaddr(self, addr: int, lenptr: int, ip: str, port: int) -> None:
        if not addr:
            return
        endian = "little" if self.ql.arch.endian.name == "EL" else "big"
        if ":" in ip:
            import ipaddress
            raw = AF_INET6.to_bytes(2, endian) + port.to_bytes(2, "big") + b"\0" * 4 + \
                ipaddress.IPv6Address(ip).packed + b"\0" * 4
        else:
            raw = AF_INET.to_bytes(2, endian) + port.to_bytes(2, "big") + bytes(int(x) for x in ip.split(".")) + b"\0" * 8
        try:
            room = self.ql.mem.read_ptr(lenptr, 4) if lenptr else len(raw)
            self.ql.mem.write(addr, raw[:room])
            if lenptr:
                self.ql.mem.write_ptr(lenptr, len(raw), 4)
        except Exception:
            pass

    def conn_for(self, s: FakeSocket, dst, how: str) -> dict:
        proto = {SOCK_STREAM: "tcp", SOCK_DGRAM: "udp", SOCK_RAW: "raw"}.get(s.type, f"type{s.type}")
        if s.family == AF_PACKET:
            proto = "packet"
        ip, port = dst if dst else (None, None)
        for c in self.conns:
            if c["sock"] == s.id and c["ip"] == ip and c["port"] == port:
                return c
        c = {"sock": s.id, "proto": proto, "ip": ip, "port": port, "how": how, "pid": self.emu.cur["pid"],
             "pc": hex(self.ql.arch.regs.arch_pc), "sent": 0, "sends": 0, "data": bytearray(), "dns": None,
             "http": [], "host": self.emu.dns_name_for(ip)}
        self.conns.append(c)
        return c

    # ---- core operations ------------------------------------------------------------------
    def send(self, s: FakeSocket, data: bytes, dst, how: str) -> int:
        if s.pair is not None:
            s.pair.queue.append((data, ("", 0)))
            return len(data)
        if dst is None:
            dst = s.peer
        if dst is None or not isinstance(dst, tuple):
            if s.family in (AF_INET, AF_INET6) and s.type == SOCK_DGRAM:
                return -EDESTADDRREQ
            dst = (None, None) if dst is None else (str(dst), None)
        c = self.conn_for(s, dst, "send" if s.peer is None else "connect")
        c["sent"] += len(data)
        c["sends"] += 1
        room = CONN_KEEP - len(c["data"])
        if room > 0:
            c["data"] += data[:room]
        ip, port = dst
        if port == 53 and s.type in (SOCK_DGRAM, SOCK_STREAM):
            payload = data[2:] if s.type == SOCK_STREAM else data
            q = parse_dns_query(payload)
            if q:
                qid, name, qtype, question = q
                c["dns"] = True
                self.dns.append({"name": name, "type": QTYPES.get(qtype, str(qtype)), "server": ip,
                                 "pid": self.emu.cur["pid"]})
                self.emu.note_dns(name)
                reply = build_dns_reply(qid, qtype, question, CANNED_IP)
                if s.type == SOCK_STREAM:
                    reply = len(reply).to_bytes(2, "big") + reply
                s.queue.append((reply, (ip, 53)))
        elif s.type == SOCK_STREAM:
            u = http_url(data, ip or "?", port or 0)
            if u and len(c["http"]) < 50:
                c["http"].append(f"{u[0]} {u[1]}")
                self.emu.note_url(u[1])
        return len(data)

    def recv(self, s: FakeSocket, n: int):
        if s.queue:
            data, src = s.queue[0]
            if len(data) > n and s.type == SOCK_STREAM:
                s.queue[0] = (data[n:], src)
                return data[:n], src
            s.queue.pop(0)
            return data[:n], src
        if s.type == SOCK_STREAM or s.peer is not None or s.nonblock:
            return (b"" if s.type == SOCK_STREAM else None), None
        return None, None

    # ---- syscalls ------------------------------------------------------------------------
    def sys_socket(self, ql, domain, stype, proto):
        base = stype & SOCK_TYPE_MASK
        if domain == AF_NETLINK:
            self.refused.append("netlink socket")
            return -EAFNOSUPPORT
        if domain not in (AF_UNIX, AF_INET, AF_INET6, AF_PACKET):
            self.refused.append(f"socket family {domain}")
            return -EAFNOSUPPORT
        s = FakeSocket(domain, base, proto, bool(stype & SOCK_NONBLOCK))
        s.net = self
        if base == SOCK_RAW or domain == AF_PACKET:
            self.emu.note_raw(f"{'packet' if domain == AF_PACKET else 'raw'} socket proto={proto}")
        return self.new_fd(s)

    def sys_socketpair(self, ql, domain, stype, proto, sv):
        a = FakeSocket(domain, stype & SOCK_TYPE_MASK, proto, bool(stype & SOCK_NONBLOCK))
        b = FakeSocket(domain, stype & SOCK_TYPE_MASK, proto, bool(stype & SOCK_NONBLOCK))
        a.net = b.net = self
        a.pair, b.pair = b, a
        fa, fb = self.new_fd(a), self.new_fd(b)
        try:
            ql.mem.write_ptr(sv, fa, 4)
            ql.mem.write_ptr(sv + 4, fb, 4)
        except Exception:
            return -EFAULT
        return 0

    def sys_connect(self, ql, fd, addr, alen):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        sa = self.parse_sockaddr(addr, alen)
        if sa is None:
            return -EFAULT
        fam, ip, port = sa
        if fam == AF_UNIX:
            self.unix.append(f"connect {ip}")
            return -ENOENT
        if ip is None:
            return -EAFNOSUPPORT
        s.peer = (ip, port)
        c = self.conn_for(s, (ip, port), "connect")
        c["how"] = "connect"
        return 0

    def sys_bind(self, ql, fd, addr, alen):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        sa = self.parse_sockaddr(addr, alen)
        if sa is None:
            return -EFAULT
        fam, ip, port = sa
        if fam == AF_UNIX:
            self.unix.append(f"bind {ip}")
            s.bound = (ip, 0)
            return 0
        if ip is None:
            return 0
        if port == 0:
            port = self.next_port
            self.next_port += 1
        s.bound = (ip, port)
        return 0

    def sys_listen(self, ql, fd, backlog):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        s.listening = True
        b = s.bound or ("0.0.0.0", 0)
        proto = "tcp" if s.type == SOCK_STREAM else "udp"
        self.listens.append(f"{proto} {b[0]}:{b[1]}")
        self.emu.note_listen(f"{proto} {b[0]}:{b[1]}")
        return 0

    def sys_accept(self, ql, fd, addr, lenptr):
        return self.sys_accept4(ql, fd, addr, lenptr, 0)

    def sys_accept4(self, ql, fd, addr, lenptr, flags):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        if s.nonblock:
            return -EAGAIN
        b = s.bound or ("0.0.0.0", 0)
        self.emu.block(f"accept() on {b[0]}:{b[1]}: no client ever connects")
        return None

    def sys_getsockname(self, ql, fd, addr, lenptr):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        if s.family not in (AF_INET, AF_INET6):
            return 0
        ip, port = s.bound or ((LOCAL_IP if s.peer else "0.0.0.0"), 0)
        if port == 0:
            port = self.next_port
            self.next_port += 1
            s.bound = (ip, port)
        self.write_sockaddr(addr, lenptr, ip, port)
        return 0

    def sys_getpeername(self, ql, fd, addr, lenptr):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        if not isinstance(s.peer, tuple):
            return -107  # ENOTCONN
        self.write_sockaddr(addr, lenptr, s.peer[0], s.peer[1])
        return 0

    def sys_setsockopt(self, ql, fd, level, opt, val, vlen):
        s = self.sock(fd)
        return s if isinstance(s, int) else 0

    def sys_getsockopt(self, ql, fd, level, opt, val, lenptr):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        try:
            if val:
                ql.mem.write_ptr(val, 0, 4)
            if lenptr:
                ql.mem.write_ptr(lenptr, 4, 4)
        except Exception:
            return -EFAULT
        return 0

    def sys_shutdown(self, ql, fd, how):
        s = self.sock(fd)
        return s if isinstance(s, int) else 0

    def _read_buf(self, buf, n):
        n = min(n, 64 << 20)
        return bytes(self.ql.mem.read(buf, n)) if n else b""

    def sys_send(self, ql, fd, buf, n, flags):
        return self.sys_sendto(ql, fd, buf, n, flags, 0, 0)

    def sys_sendto(self, ql, fd, buf, n, flags, addr, alen):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        try:
            data = self._read_buf(buf, n)
        except Exception:
            return -EFAULT
        dst = None
        if addr and s.type != SOCK_STREAM:
            sa = self.parse_sockaddr(addr, alen)
            if sa and sa[1] is not None and sa[0] != AF_UNIX:
                dst = (sa[1], sa[2])
            elif sa and sa[0] == AF_UNIX:
                self.unix.append(f"sendto {sa[1]}")
                return len(data)
        return self.send(s, data, dst, "sendto")

    def _iov(self, iov, iovlen):
        ps = self.ql.arch.pointersize
        out = []
        for i in range(min(iovlen, 1024)):
            base = self.ql.mem.read_ptr(iov + i * 2 * ps, ps)
            ln = self.ql.mem.read_ptr(iov + i * 2 * ps + ps, ps)
            out.append((base, ln))
        return out

    def _msghdr(self, msg):
        ps = self.ql.arch.pointersize
        rp = self.ql.mem.read_ptr
        if ps == 8:
            return rp(msg, 8), rp(msg + 8, 4), rp(msg + 16, 8), rp(msg + 24, 8)
        return rp(msg, 4), rp(msg + 4, 4), rp(msg + 8, 4), rp(msg + 12, 4)

    def sys_sendmsg(self, ql, fd, msg, flags):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        try:
            name, namelen, iov, iovlen = self._msghdr(msg)
            data = b"".join(self._read_buf(b, n) for b, n in self._iov(iov, iovlen))
        except Exception:
            return -EFAULT
        dst = None
        if name and s.type != SOCK_STREAM:
            sa = self.parse_sockaddr(name, namelen)
            if sa and sa[1] is not None and sa[0] != AF_UNIX:
                dst = (sa[1], sa[2])
        return self.send(s, data, dst, "sendmsg")

    def _mmsg_size(self):
        return 64 if self.ql.arch.pointersize == 8 else 32

    def sys_sendmmsg(self, ql, fd, vec, vlen, flags):
        n = 0
        for i in range(min(vlen, 64)):
            m = vec + i * self._mmsg_size()
            r = self.sys_sendmsg(ql, fd, m, flags)
            if r is None or r < 0:
                return r if n == 0 else n
            ql.mem.write_ptr(m + self._mmsg_size() - 8 if ql.arch.pointersize == 8 else m + 28, r, 4)
            n += 1
        return n

    def sys_recv(self, ql, fd, buf, n, flags):
        return self.sys_recvfrom(ql, fd, buf, n, flags, 0, 0)

    def sys_recvfrom(self, ql, fd, buf, n, flags, addr, lenptr):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        data, src = self.recv(s, n)
        if data is None:
            if s.nonblock or flags & 0x40:  # MSG_DONTWAIT
                return -EAGAIN
            self.emu.block(f"recv() on a {('udp' if s.type == SOCK_DGRAM else 'socket')} that never receives data")
            return None
        try:
            ql.mem.write(buf, data)
        except Exception:
            return -EFAULT
        if src and src[0] and addr:
            self.write_sockaddr(addr, lenptr, src[0], src[1])
        return len(data)

    def sys_recvmsg(self, ql, fd, msg, flags):
        s = self.sock(fd)
        if isinstance(s, int):
            return s
        try:
            name, namelen, iov, iovlen = self._msghdr(msg)
            vecs = self._iov(iov, iovlen)
        except Exception:
            return -EFAULT
        data, src = self.recv(s, sum(n for _, n in vecs))
        if data is None:
            if s.nonblock or flags & 0x40:
                return -EAGAIN
            self.emu.block("recvmsg() on a socket that never receives data")
            return None
        pos = 0
        for b, n in vecs:
            chunk = data[pos:pos + n]
            if chunk:
                ql.mem.write(b, chunk)
            pos += len(chunk)
        if src and src[0] and name:
            ps = ql.arch.pointersize
            self.write_sockaddr(name, msg + (8 if ps == 8 else 4), src[0], src[1])
        return len(data)

    def sys_recvmmsg(self, ql, fd, vec, vlen, flags, timeout):
        n = 0
        for i in range(min(vlen, 64)):
            m = vec + i * self._mmsg_size()
            s = self.sock(fd)
            if isinstance(s, int):
                return s
            if not s.queue and n:
                break
            r = self.sys_recvmsg(ql, fd, m, flags | (0x40 if n else 0))
            if r is None or r < 0:
                return r if n == 0 else n
            ql.mem.write_ptr(m + self._mmsg_size() - 8 if ql.arch.pointersize == 8 else m + 28, r, 4)
            n += 1
        return n

    def sys_socketcall(self, ql, call, args):
        table = {1: (self.sys_socket, 3), 2: (self.sys_bind, 3), 3: (self.sys_connect, 3), 4: (self.sys_listen, 2),
                 5: (self.sys_accept, 3), 6: (self.sys_getsockname, 3), 7: (self.sys_getpeername, 3),
                 8: (self.sys_socketpair, 4), 9: (self.sys_send, 4), 10: (self.sys_recv, 4),
                 11: (self.sys_sendto, 6), 12: (self.sys_recvfrom, 6), 13: (self.sys_shutdown, 2),
                 14: (self.sys_setsockopt, 5), 15: (self.sys_getsockopt, 5), 16: (self.sys_sendmsg, 3),
                 17: (self.sys_recvmsg, 3), 18: (self.sys_accept4, 4), 19: (self.sys_recvmmsg, 5),
                 20: (self.sys_sendmmsg, 4)}
        if call not in table:
            return -EINVAL
        fn, n = table[call]
        ps = ql.arch.pointersize
        params = [ql.mem.read_ptr(args + i * ps, ps) for i in range(n)]
        self.emu.cur_detail = fn.__name__[4:]
        return fn(ql, *params)

    # ---- readiness ---------------------------------------------------------------------------
    def ready(self, fd: int, want_in: bool, want_out: bool):
        """-> (readable, writable, invalid)"""
        fds = self.ql.os.fd
        f = fds[fd] if 0 <= fd < len(fds) else None
        if f is None:
            return False, False, True
        if isinstance(f, FakeSocket):
            return want_in and f.readable(), want_out and not f.listening, False
        return want_in, want_out, False

    def sys_poll(self, ql, fds, nfds, timeout):
        to = timeout if timeout < 0x80000000 else -1
        return self._poll(fds, nfds, None if to < 0 else to / 1000.0)

    def sys_ppoll(self, ql, fds, nfds, tsp, sigmask, sigsetsize=8):
        return self._poll(fds, nfds, self.emu.read_timespec(tsp, self.emu.ts64_for("ppoll")))

    def _poll(self, fds, nfds, timeout_s):
        n = 0
        for i in range(min(nfds, 4096)):
            a = fds + 8 * i
            fd = self.ql.mem.read_ptr(a, 4)
            fd = fd - (1 << 32) if fd & 0x80000000 else fd
            ev = int.from_bytes(self.ql.mem.read(a + 4, 2), "little" if self.ql.arch.endian.name == "EL" else "big")
            rev = 0
            if fd >= 0:
                r, w, bad = self.ready(fd, bool(ev & (POLLIN | POLLRDNORM)), bool(ev & (POLLOUT | POLLWRNORM)))
                rev = POLLNVAL if bad else (ev & (POLLIN | POLLRDNORM) if r else 0) | (ev & (POLLOUT | POLLWRNORM) if w else 0)
            self.ql.mem.write(a + 6, rev.to_bytes(2, "little" if self.ql.arch.endian.name == "EL" else "big"))
            n += bool(rev)
        return n if n else self.emu.nothing_ready("poll", timeout_s)

    def _fdset_fds(self, ptr, nfds):
        if not ptr:
            return []
        raw = bytes(self.ql.mem.read(ptr, (nfds + 7) // 8)) if nfds else b""
        ws = self.ql.arch.pointersize
        out = []
        little = self.ql.arch.endian.name == "EL"
        for wi in range(0, len(raw), ws):
            word = int.from_bytes(raw[wi:wi + ws].ljust(ws, b"\0"), "little" if little else "big")
            for bit in range(ws * 8):
                fd = wi * 8 + bit
                if fd < nfds and word >> bit & 1:
                    out.append(fd)
        return out

    def _write_fdset(self, ptr, nfds, fds):
        if not ptr:
            return
        ws = self.ql.arch.pointersize
        size = ((nfds + ws * 8 - 1) // (ws * 8)) * ws
        words = [0] * (size // ws)
        for fd in fds:
            words[fd // (ws * 8)] |= 1 << (fd % (ws * 8))
        little = self.ql.arch.endian.name == "EL"
        self.ql.mem.write(ptr, b"".join(w.to_bytes(ws, "little" if little else "big") for w in words))

    def _select(self, nfds, rp, wp, ep, timeout_s, name):
        nfds = min(nfds, 1024)
        rs, ws = self._fdset_fds(rp, nfds), self._fdset_fds(wp, nfds)
        rr = [fd for fd in rs if self.ready(fd, True, False)[0]]
        wr = [fd for fd in ws if self.ready(fd, False, True)[1]]
        self._write_fdset(rp, nfds, rr)
        self._write_fdset(wp, nfds, wr)
        self._write_fdset(ep, nfds, [])
        n = len(rr) + len(wr)
        return n if n else self.emu.nothing_ready(name, timeout_s)

    def sys_select(self, ql, nfds, rp, wp, ep, tvp):
        return self._select(nfds, rp, wp, ep, self.emu.read_timeval(tvp), "select")

    def sys_pselect6(self, ql, nfds, rp, wp, ep, tsp, sig):
        return self._select(nfds, rp, wp, ep, self.emu.read_timespec(tsp, self.emu.ts64_for("pselect6")), "pselect6")

    # epoll ------------------------------------------------------------------------------------
    def sys_epoll_create(self, ql, size):
        return self.new_fd(FakeEpoll())

    def sys_epoll_create1(self, ql, flags):
        return self.new_fd(FakeEpoll())

    def _epoll(self, epfd):
        fds = self.ql.os.fd
        e = fds[epfd] if 0 <= epfd < len(fds) else None
        return e if isinstance(e, FakeEpoll) else None

    def _ev_size(self):
        return 12 if self.ql.arch.type.name == "X8664" else 16

    def sys_epoll_ctl(self, ql, epfd, op, fd, event):
        e = self._epoll(epfd)
        if e is None:
            return -EBADF
        if op == 2:  # DEL
            e.interest.pop(fd, None)
            return 0
        ev = ql.mem.read_ptr(event, 4)
        data = int.from_bytes(ql.mem.read(event + (4 if self._ev_size() == 12 else 8), 8),
                              "little" if ql.arch.endian.name == "EL" else "big")
        e.interest[fd] = (ev, data)
        return 0

    def sys_epoll_wait(self, ql, epfd, events, maxev, timeout):
        return self.sys_epoll_pwait(ql, epfd, events, maxev, timeout, 0)

    def sys_epoll_pwait(self, ql, epfd, events, maxev, timeout, sigmask):
        e = self._epoll(epfd)
        if e is None:
            return -EBADF
        n = 0
        little = ql.arch.endian.name == "EL"
        for fd, (ev, data) in list(e.interest.items()):
            if n >= maxev:
                break
            r, w, bad = self.ready(fd, bool(ev & POLLIN), bool(ev & POLLOUT))
            rev = (POLLIN if r else 0) | (POLLOUT if w else 0) | (POLLERR if bad else 0)
            if rev:
                a = events + n * self._ev_size()
                ql.mem.write(a, rev.to_bytes(4, "little" if little else "big"))
                ql.mem.write(a + (4 if self._ev_size() == 12 else 8), data.to_bytes(8, "little" if little else "big"))
                n += 1
        to = timeout if timeout < 0x80000000 else -1
        return n if n else self.emu.nothing_ready("epoll_wait", None if to < 0 else to / 1000.0)

    def sys_ioctl_socket(self, s: FakeSocket, cmd: int, arg: int):
        if cmd == 0x5421:  # FIONBIO
            try:
                s.nonblock = bool(self.ql.mem.read_ptr(arg, 4))
            except Exception:
                return -EFAULT
            return 0
        if cmd == 0x541B:  # FIONREAD
            n = len(s.queue[0][0]) if s.queue else 0
            self.ql.mem.write_ptr(arg, n, 4)
            return 0
        return -EINVAL

    def handlers(self) -> dict:
        names = ["socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "getsockname",
                 "getpeername", "setsockopt", "getsockopt", "shutdown", "send", "sendto", "sendmsg", "sendmmsg",
                 "recv", "recvfrom", "recvmsg", "recvmmsg", "socketcall", "poll", "ppoll", "select",
                 "pselect6", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait"]
        h = {n: getattr(self, "sys_" + n) for n in names}
        h["_newselect"] = self.sys_select
        h["ppoll_time64"] = self.sys_ppoll
        h["pselect6_time64"] = self.sys_pselect6
        return h
