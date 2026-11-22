"""Fake network sink for `rebox live --fakenet` (runs inside the container).

The container still has --network none: the only interface is `lo`. The
runner adds `local 0.0.0.0/0 dev lo` (every IPv4 address is local, so nothing
can be routed anywhere) and an nftables rule that redirects every TCP
connection not aimed at 127.0.0.0/8 to TCP_PORT here; then it drops all
capabilities and starts this sink without any.

  * UDP 0.0.0.0:53: DNS. A queries get ANSWER_V4, every other type an empty
    NOERROR answer (so a sample falls back to IPv4). Queries are logged.
  * TCP 0.0.0.0:TCP_PORT: accepts, records the original destination
    (SO_ORIGINAL_DST) and up to MAX_BYTES of what the client sends, closes
    after IDLE seconds of silence. Nothing is ever sent back.

Every event is one JSON line in the log file given as argv[1]. "ready" is
written once both sockets are bound.
"""

from __future__ import annotations

import base64
import json
import select
import signal
import socket
import struct
import sys
import time

ANSWER_V4 = "203.0.113.1"  # TEST-NET-3
TCP_PORT = 65000
MAX_BYTES = 4096
IDLE = 3.0
MAX_EVENTS = 2000
SO_ORIGINAL_DST = 80


def qname(pkt: bytes) -> tuple[str | None, int, int]:
    """(name, qtype, end offset) of the first question, defensively."""
    if len(pkt) < 12:
        return None, 0, 0
    i, labels = 12, []
    while i < len(pkt) and len(labels) < 128:
        n = pkt[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 or i + 1 + n > len(pkt):
            return None, 0, 0
        labels.append(pkt[i + 1:i + 1 + n].decode("latin-1"))
        i += 1 + n
    if i + 4 > len(pkt):
        return None, 0, 0
    qtype = struct.unpack("!H", pkt[i:i + 2])[0]
    return ".".join(labels), qtype, i + 4


def dns_reply(pkt: bytes) -> bytes | None:
    name, qtype, end = qname(pkt)
    if name is None:
        return None
    tid = pkt[:2]
    question = pkt[12:end]
    if qtype == 1:
        hdr = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ANSWER_V4)
        return hdr + question + ans
    return tid + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question


def main() -> int:
    log = open(sys.argv[1], "a", buffering=1)
    n_events = 0

    def emit(**ev):
        nonlocal n_events
        n_events += 1
        if n_events <= MAX_EVENTS:
            ev["t"] = round(time.time(), 3)
            log.write(json.dumps(ev) + "\n")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 53))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", TCP_PORT))
    tcp.listen(64)
    emit(event="ready", answer=ANSWER_V4, tcp_port=TCP_PORT)

    conns: dict[socket.socket, dict] = {}
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        _loop(udp, tcp, conns, emit)
    finally:  # the runner sends SIGTERM when the run ends: flush open connections
        for c, st in list(conns.items()):
            _close(c, st, conns, emit)
        log.flush()
    return 0


def _loop(udp, tcp, conns, emit):
    while True:
        now = time.monotonic()
        for c, st in list(conns.items()):
            if now - st["last"] > IDLE:
                _close(c, st, conns, emit)
        r, _, _ = select.select([udp, tcp, *conns], [], [], 0.5)
        for s in r:
            if s is udp:
                try:
                    pkt, peer = udp.recvfrom(4096)
                except OSError:
                    continue
                name, qtype, _ = qname(pkt)
                emit(event="dns", name=name, qtype=qtype, src=f"{peer[0]}:{peer[1]}",
                     raw=base64.b64encode(pkt[:512]).decode() if name is None else None)
                rep = dns_reply(pkt)
                if rep:
                    try:
                        udp.sendto(rep, peer)
                    except OSError:
                        pass
            elif s is tcp:
                try:
                    c, peer = tcp.accept()
                except OSError:
                    continue
                try:
                    raw = c.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                    port, ip = struct.unpack("!2xH4s8x", raw)
                    dst = f"{socket.inet_ntoa(ip)}:{port}"
                except OSError:
                    dst = None
                if len(conns) >= 200:
                    c.close()
                    emit(event="tcp_dropped", dst=dst, src=f"{peer[0]}:{peer[1]}")
                    continue
                conns[c] = {"dst": dst, "src": f"{peer[0]}:{peer[1]}", "data": b"", "total": 0,
                            "last": time.monotonic(), "start": time.time()}
                emit(event="tcp_accept", dst=dst, src=f"{peer[0]}:{peer[1]}")
            else:
                st = conns[s]
                try:
                    chunk = s.recv(65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    _close(s, st, conns, emit)
                    continue
                st["total"] += len(chunk)
                if len(st["data"]) < MAX_BYTES:
                    st["data"] += chunk[:MAX_BYTES - len(st["data"])]
                st["last"] = time.monotonic()


def _close(c, st, conns, emit):
    emit(event="tcp_data", dst=st["dst"], src=st["src"], bytes=st["total"],
         data=base64.b64encode(st["data"]).decode())
    try:
        c.close()
    except OSError:
        pass
    conns.pop(c, None)


if __name__ == "__main__":
    sys.exit(main())
