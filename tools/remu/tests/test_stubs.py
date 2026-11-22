"""The import stubs, called directly through generated thunks (32-bit image)."""

from test_x86 import ret


def call(img, name, args, cc="stdcall", **kw):
    req = {"func": img["thunk_" + name], "cc": cc, "args": args}
    req.update(kw)
    return img.call(req)


def test_memcpy_cdecl(x86img):
    r = call(x86img, "memcpy", [{"out": 8, "name": "d"}, {"bytes": "01020304"}, 4], cc="cdecl")
    assert r["popped"] == 0 and r["buffers"]["top"][0]["hex"] == "0102030400000000"


def test_memset_memcmp(x86img):
    r = call(x86img, "memset", [{"out": 4}, 0x41, 3], cc="cdecl")
    assert r["buffers"]["top"][0]["hex"] == "41414100"
    assert ret(call(x86img, "memcmp", [{"bytes": "0102"}, {"bytes": "0102"}, 2], cc="cdecl")) == 0
    r = call(x86img, "memcmp", [{"bytes": "0101"}, {"bytes": "0102"}, 2], cc="cdecl")
    assert r["ret_signed"] < 0


def test_string_lengths_and_compare(x86img):
    assert ret(call(x86img, "strlen", [{"str": "abcd"}], cc="cdecl")) == 4
    assert ret(call(x86img, "wcslen", [{"wstr": "abcde"}], cc="cdecl")) == 5
    assert ret(call(x86img, "lstrlenA", [{"str": "abc"}])) == 3
    assert ret(call(x86img, "lstrlenW", [{"wstr": "ab"}])) == 2
    assert ret(call(x86img, "lstrcmpiA", [{"str": "ABC"}, {"str": "abc"}])) == 0
    assert call(x86img, "strcmp", [{"str": "a"}, {"str": "b"}], cc="cdecl")["ret_signed"] == -1


def test_stdcall_cleanup_from_stub_table(x86img):
    # no prototype in the image: the stub's own argument count decides the clean-up
    r = call(x86img, "lstrcpyA", [{"out": 8, "name": "d"}, {"str": "hi"}])
    assert r["popped"] == 8 and r["buffers"]["top"][0]["cstr"] == "hi"
    r = call(x86img, "RtlMoveMemory", [{"out": 4}, {"bytes": "aabb"}, 2])
    assert r["popped"] == 12


def test_wide_string_stubs(x86img):
    r = call(x86img, "lstrcatW", [{"wstr": "ab", "size": 16, "name": "d"}, {"wstr": "cd"}])
    assert r["buffers"]["top"][0]["wstr"] == "abcd"
    r = call(x86img, "lstrcpynW", [{"out": 16, "name": "d"}, {"wstr": "abcdef"}, 4])
    assert r["buffers"]["top"][0]["wstr"] == "abc"


def test_wsprintf(x86img):
    r = call(x86img, "wsprintfA",
             [{"out": 32, "name": "d"}, {"str": "%s-%d-%04x|%5s|%c"}, {"str": "ab"}, -5, 0x1F,
              {"str": "r"}, ord("Z")], cc="cdecl")
    assert r["buffers"]["top"][0]["cstr"] == "ab--5-001f|    r|Z"
    assert ret(r) == len("ab--5-001f|    r|Z")


def test_heap_family(x86img):
    r = call(x86img, "malloc", [100], cc="cdecl")
    a = ret(r)
    assert 0x30000000 <= a < 0x34000000 and a % 16 == 0
    r = call(x86img, "HeapAlloc", [{"ref": "heap"}, 8, 0x20])
    assert ret(r) and r["popped"] == 12
    assert ret(call(x86img, "GetProcessHeap", [])) != 0
    assert ret(call(x86img, "calloc", [4, 4], cc="cdecl"))
    assert ret(call(x86img, "realloc", [0, 8], cc="cdecl"))
    assert ret(call(x86img, "free", [0], cc="cdecl")) == 0
    assert ret(call(x86img, "HeapFree", [0, 0, 0])) == 1
    assert ret(call(x86img, "LocalAlloc", [0x40, 10])) and ret(call(x86img, "GlobalAlloc", [0, 10]))
    v = ret(call(x86img, "VirtualAlloc", [0, 0x1800, 0x3000, 4]))
    assert v % 0x1000 == 0
    r = call(x86img, "VirtualProtect", [v, 0x1000, 0x40, {"out": 4, "name": "old"}])
    assert ret(r) == 1 and r["buffers"]["top"][0]["hex"] == "40000000"
    r = call(x86img, "malloc", [0x7FFFFFFF], cc="cdecl")
    assert ret(r) == 0


def test_code_pages(x86img):
    r = call(x86img, "MultiByteToWideChar", [65001, 0, {"str": "中文"}, -1, 0, 0])
    assert ret(r) == 3
    r = call(x86img, "MultiByteToWideChar", [65001, 0, {"str": "中文"}, -1, {"out": 2}, 1])
    assert ret(r) == 0
    r = call(x86img, "WideCharToMultiByte", [936, 0, {"wstr": "中文"}, -1, {"out": 8, "name": "d"}, 8, 0, 0])
    assert ret(r) == 5 and r["buffers"]["top"][0]["hex"].startswith("d6d0cec400")
    r = call(x86img, "WideCharToMultiByte", [0, 0, {"wstr": "é"}, 1, {"out": 4, "name": "d"}, 4, 0, 0],
             acp=1252)
    assert ret(r) == 1 and r["buffers"]["top"][0]["hex"].startswith("e9")


def test_last_error_lives_in_teb(x86img):
    r = call(x86img, "SetLastError", [0x57], read=[{"addr": {"ref": "teb+0x34"}, "as": "u32"}])
    assert r["reads"][0]["value"] == "0x57" and r["popped"] == 4
    assert ret(call(x86img, "GetLastError", [])) == 0     # fresh state per request


def test_bstr_and_tls(x86img):
    r = call(x86img, "SysAllocStringLen", [{"wstr": "abc"}, 3],
             read=[{"ret": True, "off": -4, "as": "u32"}, {"ret": True, "as": "wstr"}])
    assert r["reads"][0]["value"] == "0x6" and r["reads"][1]["wstr"] == "abc"
    assert ret(call(x86img, "TlsAlloc", [])) == 0
    r = call(x86img, "TlsSetValue", [1, 0x1234], read=[{"addr": {"ref": "teb+0xe14"}, "as": "u32"}])
    assert ret(r) == 1 and r["reads"][0]["value"] == "0x1234"
    assert ret(call(x86img, "TlsGetValue", [1])) == 0


def test_tick_count_is_deterministic(x86img):
    a = ret(call(x86img, "GetTickCount", []))
    b = ret(call(x86img, "GetTickCount", []))
    assert a == b != 0


def test_unmodelled_import_logs_and_returns_zero(x86img):
    r = call(x86img, "Unmodelled", [1, 2])
    assert ret(r) == 0
    assert r["imports"]["top"][0]["model"].startswith("none")
    assert any("Unmodelled" in w for w in r["warnings"]["top"])


def test_case_and_compare(x86img):
    r = call(x86img, "CharUpperBuffW", [{"wstr": "abc 中é", "name": "s"}, 5])
    assert ret(r) == 5 and r["buffers"]["top"][0]["wstr"] == "ABC 中é"
    assert ret(call(x86img, "CompareStringW", [0, 1, {"wstr": "ABC"}, -1, {"wstr": "abc"}, -1])) == 2
    assert ret(call(x86img, "CompareStringW", [0, 0, {"wstr": "abc"}, 2, {"wstr": "abd"}, 3])) == 1


def test_lookup_sees_through_elf_symbol_versions():
    from remu import stubs
    plain = stubs.lookup("strlen")
    assert plain is not None
    assert stubs.lookup("strlen@@GLIBC_2.2.5") is plain
    assert stubs.lookup("strlen@GLIBC_2.2.5") is plain
    assert stubs.lookup(".dynsym!strlen@@GLIBC_2.2.5") is plain
    assert stubs.lookup(".strlen") is plain
    assert stubs.lookup("no_such_api@@GLIBC_2.2.5") is None
