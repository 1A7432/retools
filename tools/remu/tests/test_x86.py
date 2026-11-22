"""32-bit x86: calling conventions, buffers, imports, environment, stop reasons."""

import json


def rc4_model(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 255])
    return bytes(out)


def ret(r):
    assert r["stop"]["reason"] == "returned", json.dumps(r)
    return int(r["ret"], 16)


# ---- calling conventions --------------------------------------------------

def test_cdecl(x86img):
    r = x86img.call({"func": x86img["add3"], "args": [1, 2, 3]})
    assert ret(r) == 14 and r["popped"] == 0


def test_cdecl_ten_stack_args(x86img):
    r = x86img.call({"func": x86img["f10"], "args": list(range(1, 11))})
    assert ret(r) == sum(k * k for k in range(1, 11))


def test_stdcall_pops(x86img):
    r = x86img.call({"func": x86img["sub_std"], "cc": "stdcall", "args": [10, 3]})
    assert ret(r) == 7 and r["popped"] == 8


def test_negative_return(x86img):
    r = x86img.call({"func": x86img["sub_std"], "cc": "stdcall", "args": [3, 10]})
    assert r["ret"] == "0xfffffff9" and r["ret_signed"] == -7


def test_fastcall(x86img):
    r = x86img.call({"func": x86img["fast3"], "cc": "fastcall", "args": [1, 2, 3]})
    assert ret(r) == 123 and r["popped"] == 4


def test_thiscall(x86img):
    r = x86img.call({"func": x86img["this2"], "cc": "thiscall",
                     "args": [{"struct": [{"u32": 4}]}, 2]})
    assert ret(r) == 42 and r["popped"] == 4


def test_delphi_register_convention(x86img):
    # a4 and a5 go on the stack in Pascal order; swapping them would give 54.
    r = x86img.call({"func": x86img["delphi5"], "cc": "delphi", "args": [1, 2, 3, 4, 5]})
    assert ret(r) == 55 and r["popped"] == 8


def test_explicit_registers_and_stack(x86img):
    r = x86img.call({"func": x86img["user_esi"], "cc": "usercall",
                     "args": [{"int": 7, "reg": "esi"}, {"int": 5, "stack": 0}]})
    assert ret(r) == 75 and r["popped"] == 4


def test_regs_preset_and_usercall_requires_locations(x86img):
    r = x86img.call({"func": x86img["user_esi"], "regs": {"esi": 3}, "args": [{"int": 1, "stack": 0}]})
    assert ret(r) == 31
    r = x86img.call({"func": x86img["user_esi"], "cc": "usercall", "args": [1]})
    assert "error" in r and "reg" in r["error"]


# ---- buffers and strings ---------------------------------------------------

def test_string_argument(x86img):
    r = x86img.call({"func": x86img["count_char"], "args": [{"str": "banana"}, ord("a")]})
    assert ret(r) == 3
    assert r["unchanged"]["top"] == ["a1"]


def test_utf16_argument(x86img):
    r = x86img.call({"func": x86img["wlen"], "args": [{"wstr": "中文abc"}]})
    assert ret(r) == 5


def test_in_place_buffer_reported(x86img):
    r = x86img.call({"func": x86img["upcase"], "args": [{"str": "hello, world", "name": "s"}]})
    b = r["buffers"]["top"][0]
    assert b["name"] == "s" and b["cstr"] == "HELLO, WORLD" and b["changed"] == "+0x0..+0xb"


def test_xor_decrypt_to_output_buffer(x86img):
    plain = b"decrypted string!"
    key = 0x5A
    enc = bytes(c ^ ((key + i) & 0xFF) for i, c in enumerate(plain))
    r = x86img.call({"func": x86img["xor_dec"],
                     "args": [{"bytes": enc.hex()}, {"out": len(plain) + 1, "name": "out"}, len(enc), key]})
    out = [b for b in r["buffers"]["top"] if b["name"] == "out"][0]
    assert bytes.fromhex(out["hex"])[:len(plain)] == plain
    assert out["cstr"] == plain.decode()


def test_rc4_in_place(x86img):
    key, plain = b"Secret", b"Attack at dawn, bring snacks"
    enc = rc4_model(key, plain)
    r = x86img.call({"func": x86img["rc4"],
                     "args": [{"bytes": key.hex()}, len(key), {"bytes": enc.hex(), "name": "buf"}, len(enc)]})
    assert r["stop"]["reason"] == "returned"
    buf = r["buffers"]["top"][0]
    assert bytes.fromhex(buf["hex"]) == plain


def test_nested_structures_with_refs(x86img):
    req = {"func": x86img["sum_nested"],
           "mem": [{"name": "vals", "struct": [{"i32": 5}, {"i32": 6}, {"i32": -1}]},
                   {"name": "inner", "struct": [{"u32": 3}, {"ptr": {"ref": "vals"}}]}],
           "args": [{"struct": [{"u32": 10}, {"ptr": {"ref": "inner"}}]}]}
    assert ret(x86img.call(req)) == 100
    # the same through inline nested specs, placed at a caller-chosen scratch address
    req = {"func": x86img["sum_nested"],
           "args": [{"addr": "0x20000100", "struct": [
               {"u32": 2}, {"ptr": {"struct": [{"u32": 2}, {"ptr": {"struct": [{"i32": 7}, {"i32": 8}]}}]}}]}]}
    assert ret(x86img.call(req)) == 30


def test_read_back_and_ret_views(x86img):
    r = x86img.call({"func": x86img["heap_dec"], "args": [{"str": "ABC"}], "ret": "cstr",
                     "read": [{"addr": "0x406100", "size": 4}, {"ret": True, "as": "u32"},
                              {"addr": {"ref": "a1"}, "as": "cstr"}]})
    assert r["ret_view"]["cstr"] == "abc"
    assert r["reads"][0]["hex"] == "61626300"
    assert r["reads"][1]["value"] == "0x636261"
    assert r["reads"][2]["cstr"] == "ABC"


def test_delphi_strings(x86img):
    # UnicodeString: the pointer goes to the chars, length at -4, refcount -1.
    r = x86img.call({"func": x86img["wlen"], "args": [{"dstr": "hello"}],
                     "read": [{"addr": {"ref": "a1-4"}, "as": "u32"},
                              {"addr": {"ref": "a1"}, "as": "dstr"}]})
    assert ret(r) == 5
    assert r["reads"][0]["value"] == "0x5" and r["reads"][1]["dstr"] == "hello"


# ---- imports ---------------------------------------------------------------

def test_imports_iat_thunk_and_cleanup(x86img):
    r = x86img.call({"func": x86img["heap_dec"], "args": [{"str": "HELLO"}]})
    assert ret(r) >= 0x30000000            # a pointer into the heap arena
    assert r["ret_points_to"]["cstr"] == "hello"
    calls = r["imports"]["top"]
    assert [c["fn"] for c in calls] == ["kernel32!lstrlenA", "kernel32!GetProcessHeap",
                                        "kernel32!HeapAlloc", "msvcrt!memcpy", "user32!MysteryStd"]
    assert calls[0]["args"][0].endswith('"HELLO"')
    assert calls[4]["args"] == ["0x1", "0x2"] and calls[4]["model"].startswith("none")
    # the run only returns cleanly if every import popped the right amount
    assert r["popped"] == 0
    regions = {w["in"].split()[0]: w for w in r["writes"]["top"]}
    assert ".data+0x100" in regions and regions[".data+0x100"]["strings"]["top"][0].endswith('"hello"')
    assert "heap" in regions


def test_import_without_prototype_warns(x86img):
    r = x86img.call({"func": x86img["noproto_call"]})
    assert r["stop"]["reason"] == "returned"
    call = r["imports"]["top"][0]
    assert call["fn"] == "foo!NoProto" and call["purge"].startswith("unknown")
    assert "nargs" in call and any("NoProto" in w for w in r["warnings"]["top"])


def test_import_override_and_stop(x86img):
    r = x86img.call({"func": x86img["noproto_call"],
                     "imports": {"NoProto": {"ret": 0x99, "nargs": 2}}})
    assert ret(r) == 0x99 and "warnings" not in r
    r = x86img.call({"func": x86img["noproto_call"], "on_unknown_import": "stop"})
    assert r["stop"]["reason"] == "unknown_import" and r["stop"]["fn"] == "foo!NoProto"
    r = x86img.call({"func": x86img["heap_dec"], "args": [{"str": "x"}],
                     "imports": {"HeapAlloc": {"stop": True}}})
    assert r["stop"]["reason"] == "import_stop" and r["stop"]["fn"] == "kernel32!HeapAlloc"


def test_override_write_to_pointer_argument(x86img):
    r = x86img.call({"func": x86img["mb2wc"],
                     "args": [{"str": "x"}, {"out": 16, "name": "dst"}, 8],
                     "imports": {"MultiByteToWideChar": {"ret": 3, "write": [{"arg": 4, "wstr": "ok"}]}}})
    assert ret(r) == 3
    assert r["buffers"]["top"][0]["wstr"] == "ok"


def test_multibyte_to_widechar_stub(x86img):
    r = x86img.call({"func": x86img["mb2wc"],
                     "args": [{"str": "héllo 中"}, {"out": 32, "name": "dst"}, 16]})
    assert ret(r) == 8   # 7 chars + NUL
    assert r["buffers"]["top"][0]["wstr"] == "héllo 中"


def test_getprocaddress_dynamic_stub(x86img):
    r = x86img.call({"func": x86img["dyn_call"]})
    assert r["stop"]["reason"] == "returned"
    fns = [c["fn"] for c in r["imports"]["top"]]
    assert fns == ["kernel32!GetModuleHandleA", "kernel32!GetProcAddress", "kernel32.dll!GetTickCount"]
    assert int(r["ret"], 16) > 0


def test_raise_exception_stops(x86img):
    r = x86img.call({"func": x86img["raise_fn"]})
    assert r["stop"]["reason"] == "exception" and "0xe0434352" in r["stop"]["detail"]


def test_replace_internal_function(x86img):
    # Pretend add3 is an internal helper and replace it by a fixed result.
    r = x86img.call({"func": x86img["calls_leaf"], "replace": {x86img["leaf"]: {"ret": 7}},
                     "regs": {"eax": 0}})
    assert ret(r) == 7
    # two call sites, so two log entries; the counts table sums them
    assert [c["fn"] for c in r["imports"]["top"]] == ["sub_%X" % x86img.syms["leaf"]] * 2
    assert r["imports"]["total"] == 2


# ---- environment -----------------------------------------------------------

def test_teb_peb_through_fs(x86img):
    assert ret(x86img.call({"func": x86img["teb_image"]})) == 0x400000


def test_seh_frame(x86img):
    assert ret(x86img.call({"func": x86img["seh_frame"]})) == 0xFFFFFFFF


# ---- stop reasons ----------------------------------------------------------

def test_unmapped_read(x86img):
    r = x86img.call({"func": x86img["bad_read"]})
    s = r["stop"]
    assert s["reason"] == "unmapped_read" and s["addr"] == "0x12345678"
    assert s["at"] == x86img["bad_read"] and "mov" in s["insn"] and r["insns"] == 0
    assert "regs" in r


def test_unmapped_write(x86img):
    r = x86img.call({"func": x86img["bad_write"]})
    assert r["stop"]["reason"] == "unmapped_write" and r["stop"]["addr"] == "0x12345678"


def test_unmapped_fetch(x86img):
    r = x86img.call({"func": x86img["bad_fetch"]})
    assert r["stop"]["reason"] == "unmapped_fetch" and r["stop"]["at"] == "0x13370000"
    assert r["stop"]["from"] == hex(x86img.syms["bad_fetch"] + 5)


def test_map_on_demand(x86img):
    r = x86img.call({"func": x86img["bad_read"], "map_on_demand": True})
    assert ret(r) == 0 and r["mapped_on_demand"]["top"] == ["0x12345000-0x12346000"]


def test_invalid_instruction(x86img):
    r = x86img.call({"func": x86img["bad_insn"]})
    assert r["stop"]["reason"] == "invalid_insn" and r["stop"]["at"] == hex(x86img.syms["bad_insn"] + 1)
    assert r["insns"] == 1 and r["stop"]["insn"].startswith("ud2")


def test_breakpoint_interrupt(x86img):
    r = x86img.call({"func": x86img["int3_fn"]})
    assert r["stop"]["reason"] == "interrupt" and r["stop"]["name"] == "breakpoint"


def test_instruction_cap(x86img):
    r = x86img.call({"func": x86img["spin"], "max_insns": 1000})
    assert r["stop"]["reason"] == "max_insns" and r["insns"] == 1000
    assert int(r["regs"]["eax"], 16) == 500


def test_timeout(x86img):
    r = x86img.call({"func": x86img["spin"], "max_insns": 10 ** 12, "timeout": 0.3})
    assert r["stop"]["reason"] == "timeout" and r["ms"] < 3000


def test_fragment_until(x86img):
    base = x86img.syms["delphi5"]
    r = x86img.call({"start": hex(base), "until": [hex(base + 10)], "regs": {"eax": 1, "edx": 2, "ecx": 3}})
    assert r["stop"]["reason"] == "until" and r["stop"]["at"] == hex(base + 10)
    assert int(r["regs"]["eax"], 16) == 1 + 4 + 9 and r["insns"] == 4


def test_call_trace(x86img):
    r = x86img.call({"func": x86img["calls_leaf"], "trace": True})
    t = r["trace"]
    assert t["total"] == 2 and t["top"][0]["to"] == x86img["leaf"]


# ---- requests and errors ---------------------------------------------------

def test_bad_requests_give_error_and_hint(x86img):
    for req in ({"func": "0x401000", "bogus": 1}, {"args": []}, {"func": "nope"},
                {"func": "0x999999"}, {"func": x86img["add3"], "cc": "ms64"},
                {"func": x86img["add3"], "args": [{"ref": "missing"}]},
                {"func": x86img["add3"], "args": ["text"]}):
        r = x86img.call(req)
        assert "error" in r and "hint" in r, (req, r)


def test_batch_runs_start_clean(x86img):
    reqs = [{"func": x86img["write_global"], "read": [{"addr": "0x406100", "as": "cstr"}]},
            {"func": x86img["add3"], "args": [0, 0, 0], "read": [{"addr": "0x406100", "size": 4}]}]
    r = x86img.call(reqs)
    assert r["total"] == 2 and r["reasons"] == {"returned": 2}
    assert r["results"][0]["reads"][0]["cstr"] == "SECRET"
    assert r["results"][1]["reads"][0]["hex"] == "00000000"
    assert [x["id"] for x in r["results"]] == [0, 1]


def test_batch_with_defaults_sweep(x86img):
    reqs = {"defaults": {"func": x86img["add3"], "fields": ["ret"]},
            "requests": [{"args": [i, 0, 0]} for i in range(50)]}
    r = x86img.call(reqs)
    assert [int(x["ret"], 16) for x in r["results"]] == list(range(50))
    assert len(json.dumps(r)) <= 6000
