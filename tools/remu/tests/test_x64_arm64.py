"""x64 (Windows and System V) and arm64 (AAPCS64)."""

import pytest

from remu import stubs
from test_x86 import rc4_model, ret

SUM10 = sum(k * k for k in range(1, 11))


# ---- x64 -------------------------------------------------------------------

def test_x64_ms64_default_for_pe(x64img):
    assert ret(x64img.call({"func": x64img["ms6"], "args": [1, 2, 3, 4, 5, 6]})) == 91


def test_x64_sysv_stack_args(x64img):
    # f10 was compiled for System V: rdi..r9 then 4 on the stack
    assert ret(x64img.call({"func": x64img["f10"], "cc": "sysv", "args": list(range(1, 11))})) == SUM10
    # the ms64 default puts them elsewhere, so the result differs
    assert ret(x64img.call({"func": x64img["f10"], "args": list(range(1, 11))})) != SUM10


def test_x64_sysv_default_for_elf(x64elf):
    assert ret(x64elf.call({"func": x64elf["f10"], "args": list(range(1, 11))})) == SUM10


def test_x64_explicit_registers(x64img):
    r = x64img.call({"func": x64img["add3"], "cc": "usercall",
                     "args": [{"int": 1, "reg": "rdi"}, {"int": 2, "reg": "rsi"}, {"int": 3, "reg": "rdx"}]})
    assert ret(r) == 14


def test_x64_teb_peb_through_gs(x64img):
    assert ret(x64img.call({"func": x64img["gs_image"]})) == 0x400000


def test_x64_imports_iat_and_thunk(x64img):
    r = x64img.call({"func": x64img["x64_imports"], "args": [{"out": 16, "name": "dst"}]})
    assert r["stop"]["reason"] == "returned"
    assert r["buffers"]["top"][0]["text"] == "A" * 16
    assert [c["fn"] for c in r["imports"]["top"]] == ["msvcrt!memset", "msvcrt!memcpy"]


def test_x64_rc4(x64img):
    key, plain = b"k3y", b"sixty-four bit"
    r = x64img.call({"func": x64img["rc4"], "cc": "sysv",
                     "args": [{"bytes": key.hex()}, 3, {"bytes": rc4_model(key, plain).hex()}, len(plain)]})
    assert bytes.fromhex(r["buffers"]["top"][0]["hex"]) == plain


def test_x64_unmapped_high_address(x64img):
    r = x64img.call({"func": x64img["bad_read64"]})
    assert r["stop"]["reason"] == "unmapped_read" and r["stop"]["addr"] == "0x123456789"


# ---- arm64 -----------------------------------------------------------------

def test_a64_args_in_registers_and_stack(a64img):
    assert ret(a64img.call({"func": a64img["add3"], "args": [1, 2, 3]})) == 14
    assert ret(a64img.call({"func": a64img["f10"], "args": list(range(1, 11))})) == SUM10


def test_a64_explicit_registers(a64img):
    r = a64img.call({"func": a64img["add3"], "cc": "usercall",
                     "args": [{"int": 3, "reg": "x0"}, {"int": 2, "reg": "x1"}, {"int": 1, "reg": "x2"}]})
    assert ret(r) == 10


def test_a64_buffers_and_decrypt(a64img):
    key = 0x33
    plain = b"arm64 says hi"
    enc = bytes(c ^ ((key + i) & 0xFF) for i, c in enumerate(plain))
    r = a64img.call({"func": a64img["xor_dec"],
                     "args": [{"bytes": enc.hex()}, {"out": 16, "name": "out"}, len(enc), key]})
    assert r["buffers"]["top"][0]["cstr"] == plain.decode()
    r = a64img.call({"func": a64img["sum_nested"],
                     "args": [{"struct": [{"u32": 3}, {"zero": 4},
                                          {"ptr": {"struct": [{"u32": 2}, {"zero": 4},
                                                              {"ptr": {"struct": [{"i32": 4}, {"i32": 5}]}}]}}]}]})
    assert ret(r) == 27


def test_a64_imports_extern_address_and_thunk(a64img):
    r = a64img.call({"func": a64img["a64_imports"], "args": [{"out": 8}]})
    assert r["stop"]["reason"] == "returned"
    assert [c["fn"] for c in r["imports"]["top"]] == ["libc.so.6!memset", "libc.so.6!malloc"]
    assert r["ret_points_to"]["cstr"] == "BBBBBBBB"


def test_a64_tls_register(a64img):
    r = a64img.call({"func": a64img["tls_self"]})
    assert ret(r) != 0


def test_a64_stop_reasons(a64img):
    r = a64img.call({"func": a64img["bad_read_a64"]})
    assert r["stop"]["reason"] == "unmapped_read" and r["stop"]["addr"] == "0x12345678"
    r = a64img.call({"func": a64img["udf_a64"]})
    assert r["stop"]["reason"] == "invalid_insn" and r["stop"]["at"] == hex(a64img.syms["udf_a64"] + 4)
    r = a64img.call({"func": a64img["brk_a64"]})
    assert r["stop"]["reason"] == "interrupt"


MOCK_COMMAND = b"mock.boundary.submit"
MOCK_RETURN = 0x13579BDF
COMMAND_ADDR = 0x20000100
PAYLOAD_ADDR = 0x20001000
PAYLOAD_LIMIT = 4096
GUARD_LEFT = b"\xa5" * 8
GUARD_RIGHT = b"\x5a" * 8


# This envelope is synthetic, not QQ's report format.
def _mock_payload(*records):
    return b"MOCK\x01" + bytes([len(records)]) + b"".join(
        bytes([len(tag), len(note)]) + tag + note for tag, note in records)


def _mock_note_offset(data):
    if len(data) < 6 or data[:5] != b"MOCK\x01":
        return None
    pos, records = 6, []
    for _ in range(data[5]):
        if pos + 2 > len(data):
            return None
        tag_len, note_len = data[pos:pos + 2]
        pos += 2
        end = pos + tag_len + note_len
        if end > len(data):
            return None
        records.append((data[pos:pos + tag_len], pos + tag_len, note_len))
        pos = end
    if pos != len(data) or len(records) != 1:
        return None
    tag, note_off, note_len = records[0]
    if tag == b"msg" and note_len == 2 and data[note_off:note_off + 2] == b"hi":
        return note_off
    return None


class MockBoundary:
    def __init__(self):
        self.mode = "pass"
        self.captured = []
        self.sinks = []

    def dispatch(self, call):
        argv = tuple(call.args(4))
        command = call.cstr(argv[0], 64)
        if len(command) == 64:
            call.stop("mock_invalid", "unterminated command")
            return 0
        size = argv[2] & 0xFFFFFFFF
        if size > PAYLOAD_LIMIT:
            call.stop("mock_invalid", "payload exceeds mock limit")
            return 0
        payload = call.read(argv[1], size)
        captured = {"argv": argv, "command": command, "payload": payload,
                    "length": size, "parameter": call.signed(argv[3], 64)}
        self.captured.append(captured)
        if self.mode == "observe":
            call.stop("import_stop", "mock_observe")
            return 0
        note_off = _mock_note_offset(payload) if command == MOCK_COMMAND else None
        if note_off is not None and self.mode == "drop":
            call.stop("mock_drop", "synthetic single record")
            return 0
        if note_off is not None and self.mode == "rewrite":
            call.write(argv[1] + note_off, b"yo")
        self.sinks.append({**captured, "payload": call.read(argv[1], size)})
        return MOCK_RETURN


@pytest.fixture
def mock_boundary(monkeypatch):
    boundary = MockBoundary()
    monkeypatch.setitem(stubs.STUBS, "MockBoundary",
                        stubs.Stub("MockBoundary", boundary.dispatch, 4, "c"))
    return boundary


def _boundary_request(a64img, payload=None, command=None, length=None, parameter=-1):
    payload = _mock_payload((b"msg", b"hi")) if payload is None else payload
    command = MOCK_COMMAND + b"\0" if command is None else command
    return {"func": a64img["boundary_forward"], "cc": "aapcs64",
            "args": [COMMAND_ADDR, PAYLOAD_ADDR,
                     len(payload) if length is None else length, parameter],
            "mem": [{"name": "command", "addr": COMMAND_ADDR, "bytes": command.hex()},
                    {"name": "guarded_payload", "addr": PAYLOAD_ADDR - len(GUARD_LEFT),
                     "bytes": (GUARD_LEFT + payload + GUARD_RIGHT).hex()}],
            "read": [{"addr": COMMAND_ADDR, "size": len(command), "name": "command"},
                     {"addr": PAYLOAD_ADDR - len(GUARD_LEFT),
                      "size": len(GUARD_LEFT) + len(payload) + len(GUARD_RIGHT),
                      "name": "guarded_payload"}], "max_chars": 20000}


def _boundary_reads(result):
    return {item["name"]: bytes.fromhex(item["hex"]) for item in result["reads"]}


@pytest.mark.parametrize("mode,reason,sinks", [
    ("observe", "import_stop", 0), ("drop", "mock_drop", 0),
    ("rewrite", "returned", 1), ("pass", "returned", 1),
])
def test_a64_mock_boundary_modes(a64img, mock_boundary, mode, reason, sinks):
    mock_boundary.mode = mode
    payload = _mock_payload((b"msg", b"hi"))
    assert len(payload) == 13
    result = a64img.call(_boundary_request(a64img, payload))
    assert result["stop"]["reason"] == reason
    assert len(mock_boundary.captured) == 1
    captured = mock_boundary.captured[0]
    assert captured == {"argv": (COMMAND_ADDR, PAYLOAD_ADDR, 13, 2 ** 64 - 1),
                        "command": MOCK_COMMAND, "payload": payload,
                        "length": 13, "parameter": -1}
    assert len(mock_boundary.sinks) == sinks
    expected = payload[:11] + b"yo" if mode == "rewrite" else payload
    reads = _boundary_reads(result)
    assert reads["command"] == MOCK_COMMAND + b"\0"
    assert reads["guarded_payload"] == GUARD_LEFT + expected + GUARD_RIGHT
    if sinks:
        assert ret(result) == MOCK_RETURN
        assert mock_boundary.sinks[0] == {**captured, "payload": expected}
    else:
        assert "ret" not in result
        assert result["stop"]["ret_to"] == hex(a64img.syms["boundary_forward"] + 16)
    if mode == "rewrite":
        original = GUARD_LEFT + payload + GUARD_RIGHT
        assert [i for i, (a, b) in enumerate(zip(original, reads["guarded_payload"]))
                if a != b] == [19, 20]


@pytest.mark.parametrize("mode", ["drop", "rewrite", "pass"])
@pytest.mark.parametrize("payload", [
    b"", b"MOCK", b"MOCK\x02\x01\x03\x02msghi",
    _mock_payload(), _mock_payload((b"log", b"hi")),
    _mock_payload((b"msg", b"hi"), (b"log", b"no")),
    _mock_payload((b"msg", b"hi"), (b"msg", b"hi")),
    _mock_payload((b"msg", b"hi"))[:-1],
    _mock_payload((b"msg", b"hi")) + b"\0",
    _mock_payload((b"msg", b"h\0")),
    b"MOCK\x01\x02\x03\x02msghi",
    b"\x0a\x0b0df00071646",
    b"verify_file\0MOCK\x01\x01\x03\x02msghi",
])
def test_a64_mock_boundary_unknown_or_mixed_passes(a64img, mock_boundary, mode, payload):
    mock_boundary.mode = mode
    result = a64img.call(_boundary_request(a64img, payload))
    assert result["stop"]["reason"] == "returned"
    assert len(mock_boundary.sinks) == 1
    assert mock_boundary.sinks[0]["payload"] == payload
    assert _boundary_reads(result)["guarded_payload"] == GUARD_LEFT + payload + GUARD_RIGHT


@pytest.mark.parametrize("mode", ["drop", "rewrite", "pass"])
@pytest.mark.parametrize("command", [b"other.submit\0", b"mock.boundary.submit.extra\0",
                                      b"trpc.o3.report.Report.SsoReport\0",
                                      b"other\0mock.boundary.submit\0"])
def test_a64_mock_boundary_other_command_passes(a64img, mock_boundary, mode, command):
    mock_boundary.mode = mode
    result = a64img.call(_boundary_request(a64img, command=command))
    assert result["stop"]["reason"] == "returned"
    assert len(mock_boundary.sinks) == 1
    assert mock_boundary.sinks[0]["command"] == command.split(b"\0", 1)[0]
    assert mock_boundary.sinks[0]["payload"] == _mock_payload((b"msg", b"hi"))
    assert _boundary_reads(result)["command"] == command


def test_a64_mock_boundary_override_stop_precedes_stub_and_write(a64img, mock_boundary):
    request = _boundary_request(a64img)
    request["imports"] = {"MockBoundary": {"stop": True,
                           "write": [{"arg": 1, "off": 11, "bytes": b"yo".hex()}]}}
    result = a64img.call(request)
    assert result["stop"]["reason"] == "import_stop"
    assert not mock_boundary.captured and not mock_boundary.sinks
    assert _boundary_reads(result)["guarded_payload"] == (
        GUARD_LEFT + _mock_payload((b"msg", b"hi")) + GUARD_RIGHT)


def test_a64_mock_boundary_override_write_follows_sink(a64img, mock_boundary):
    request = _boundary_request(a64img)
    request["imports"] = {"MockBoundary": {
        "write": [{"arg": 1, "off": 11, "bytes": b"yo".hex()}]}}
    result = a64img.call(request)
    assert result["stop"]["reason"] == "returned"
    assert mock_boundary.sinks[0]["payload"] == _mock_payload((b"msg", b"hi"))
    assert _boundary_reads(result)["guarded_payload"] == (
        GUARD_LEFT + _mock_payload((b"msg", b"yo")) + GUARD_RIGHT)


@pytest.mark.parametrize("mode", ["observe", "drop", "rewrite", "pass"])
@pytest.mark.parametrize("bad_arg", [0, 1])
def test_a64_mock_boundary_invalid_pointer_stops(a64img, mock_boundary, mode, bad_arg):
    mock_boundary.mode = mode
    request = _boundary_request(a64img)
    request["args"][bad_arg] = 0x12345678
    result = a64img.call(request)
    assert result["stop"]["reason"] == "unmapped_read"
    assert result["stop"]["addr"] == "0x12345678"
    assert not mock_boundary.sinks and "ret" not in result


@pytest.mark.parametrize("mode", ["observe", "drop", "rewrite", "pass"])
def test_a64_mock_boundary_mapping_end_stops(a64img, mock_boundary, mode):
    mock_boundary.mode = mode
    request = _boundary_request(a64img)
    request["args"][1] = 0x405FF8
    result = a64img.call(request)
    assert result["stop"]["reason"] == "unmapped_read"
    assert result["stop"]["addr"] == "0x406000"
    assert not mock_boundary.sinks and "ret" not in result


@pytest.mark.parametrize("length", [PAYLOAD_LIMIT + 1, 0xFFFFFFFF])
def test_a64_mock_boundary_oversized_length_stops(a64img, mock_boundary, length):
    result = a64img.call(_boundary_request(a64img, length=length))
    assert result["stop"]["reason"] == "mock_invalid"
    assert not mock_boundary.sinks and "ret" not in result


def test_a64_mock_boundary_unterminated_command_stops(a64img, mock_boundary):
    result = a64img.call(_boundary_request(a64img, command=b"x" * 64))
    assert result["stop"]["reason"] == "mock_invalid"
    assert not mock_boundary.sinks and "ret" not in result


@pytest.mark.parametrize("parameter", [-1, 0, 1, -(2 ** 63), 2 ** 63 - 1])
def test_a64_mock_boundary_u32_length_i64_parameter(a64img, mock_boundary, parameter):
    result = a64img.call(_boundary_request(a64img, length=2 ** 32 + 13,
                                         parameter=parameter))
    assert result["stop"]["reason"] == "returned"
    captured = mock_boundary.captured[0]
    assert captured["length"] == 13 and captured["parameter"] == parameter
    assert mock_boundary.sinks[0]["argv"][2] == 2 ** 32 + 13


def test_a64_mock_boundary_repeated_requests_are_isolated(a64img, mock_boundary):
    mock_boundary.mode = "rewrite"
    request = _boundary_request(a64img)
    first, second = a64img.call(request), a64img.call(request)
    assert first["stop"]["reason"] == second["stop"]["reason"] == "returned"
    assert [c["payload"] for c in mock_boundary.captured] == [
        _mock_payload((b"msg", b"hi"))] * 2
    assert [c["payload"] for c in mock_boundary.sinks] == [
        _mock_payload((b"msg", b"yo"))] * 2
    assert _boundary_reads(first) == _boundary_reads(second)


@pytest.mark.parametrize("mode", ["drop", "rewrite"])
@pytest.mark.parametrize("size", range(13))
def test_a64_mock_boundary_every_truncation_passes(a64img, mock_boundary, mode, size):
    mock_boundary.mode = mode
    payload = _mock_payload((b"msg", b"hi"))[:size]
    result = a64img.call(_boundary_request(a64img, payload))
    assert result["stop"]["reason"] == "returned"
    assert mock_boundary.sinks[0]["payload"] == payload
    assert _boundary_reads(result)["guarded_payload"] == GUARD_LEFT + payload + GUARD_RIGHT


def test_a64_mock_boundary_exact_limits_pass(a64img, mock_boundary):
    payload, command = b"x" * PAYLOAD_LIMIT, b"x" * 63 + b"\0"
    result = a64img.call(_boundary_request(a64img, payload, command))
    assert result["stop"]["reason"] == "returned"
    assert mock_boundary.sinks[0]["payload"] == payload
    reads = _boundary_reads(result)
    assert reads["command"] == command
    assert reads["guarded_payload"] == GUARD_LEFT + payload + GUARD_RIGHT


def test_a64_mock_boundary_empty_payload_needs_no_pointer(a64img, mock_boundary):
    request = _boundary_request(a64img, payload=b"")
    request["args"][1] = 0
    result = a64img.call(request)
    assert result["stop"]["reason"] == "returned"
    assert mock_boundary.sinks[0]["payload"] == b""
    assert _boundary_reads(result)["guarded_payload"] == GUARD_LEFT + GUARD_RIGHT
