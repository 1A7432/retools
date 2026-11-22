"""init: calls made first, in the same machine, before the request's own call.
Runs on x86, x64 and arm64 (the tblimg fixture is parametrised)."""

from test_x86 import ret

SBOX = [(7 * i + 3) & 0xFF for i in range(256)]
DATA = b"\x00\x01\x02\x10\x7f\x80\xfe\xff"


def apply_req(img, **extra):
    req = {"func": img["sbox_apply"],
           "args": [{"bytes": DATA.hex()}, {"out": len(DATA), "name": "out"}, len(DATA)]}
    req.update(extra)
    return req


def out_bytes(r, name="out"):
    for b in r.get("buffers", {}).get("top", []):
        if b["name"] == name:
            return bytes.fromhex(b["hex"])
    return None


def alloc_replace(img):
    rep = {"stub": "malloc"}
    if img.arch.name == "x86":
        rep["cc"] = "stdcall"       # the fixture's allocator is stdcall on i386
    return {img["alloc_table"]: rep}


def test_table_reader_needs_init(tblimg):
    r = tblimg.call(apply_req(tblimg))
    assert r["stop"]["reason"] == "returned"
    assert out_bytes(r) is None and "out" in r["unchanged"]["top"]   # table still zero
    r = tblimg.call(apply_req(tblimg, init=[tblimg["build_sbox"]]))
    assert r["stop"]["reason"] == "returned"
    assert out_bytes(r) == bytes(SBOX[b] for b in DATA)
    (entry,) = r["init"]
    assert set(entry) == {"func", "stop", "ret", "insns"}
    assert entry["func"] == tblimg["build_sbox"] and entry["stop"] == "returned"
    assert entry["insns"] > 256 and r["insns"] < entry["insns"]


def test_main_reply_excludes_init(tblimg):
    # build_sbox writes 256 bytes of .data; the main call writes only its buffer
    r = tblimg.call(apply_req(tblimg, init=[tblimg["build_sbox"]]))
    assert "writes" not in r and "imports" not in r
    alone = tblimg.call({"func": tblimg["build_sbox"]})
    assert alone["writes"]["bytes"] == 256
    # heap block and allocator call made by init are not the main call's
    n = 64
    r = tblimg.call({"func": tblimg["heap_table_sum"], "args": [n],
                     "init": [{"func": tblimg["build_heap_table"], "args": [n]}],
                     "replace": alloc_replace(tblimg)})
    assert ret(r) == sum(i ^ 0x5A for i in range(n))
    assert "writes" not in r and "imports" not in r


def test_chained_named_buffer(tblimg):
    seed, n = 3, 8
    key = bytes(SBOX[(seed + 13 * i) & 0xFF] for i in range(n))
    r = tblimg.call({
        "func": tblimg["sbox_apply"],
        "args": [{"ref": "key"}, {"out": n, "name": "out"}, n],
        "init": [tblimg["build_sbox"],
                 {"func": tblimg["derive_key"], "args": [seed, {"out": n, "name": "key"}, n]}],
        "read": [{"addr": {"ref": "key"}, "size": n}]})
    assert r["stop"]["reason"] == "returned"
    assert int(r["init"][1]["ret"], 16) == sum(key)
    assert bytes.fromhex(r["reads"][0]["hex"]) == key
    assert out_bytes(r) == bytes(SBOX[b] for b in key)
    # init's buffer is neither "changed" nor "unchanged" for the main call
    assert [b["name"] for b in r["buffers"]["top"]] == ["out"] and "unchanged" not in r
    # an unnamed init buffer is reachable by its prefixed automatic name
    r = tblimg.call({
        "func": tblimg["sbox_apply"],
        "args": [{"ref": "init1.a2"}, {"out": n, "name": "out"}, n],
        "init": [tblimg["build_sbox"],
                 {"func": tblimg["derive_key"], "args": [seed, {"out": n}, n]}]})
    assert out_bytes(r) == bytes(SBOX[b] for b in key)


def test_failing_init_stops_request(tblimg):
    r = tblimg.call(apply_req(tblimg, init=[tblimg["build_sbox"], tblimg["never_returns"]]))
    stop = r["stop"]
    assert stop["reason"] == "init_failed" and stop["entry"] == 1
    assert stop["func"] == tblimg["never_returns"]
    assert stop["cause"]["reason"] == "unmapped_read" and stop["cause"]["addr"] == "0x20"
    assert "init[1]" in stop["detail"] and "unmapped_read" in stop["detail"]
    assert [e["stop"] for e in r["init"]] == ["returned", "unmapped_read"]
    assert "ret" not in r and "regs" in r
    # an allocator the snapshot never set up: fails until replaced, top level or per entry
    init = [{"func": tblimg["build_heap_table"], "args": [16]}]
    r = tblimg.call({"func": tblimg["heap_table_sum"], "args": [16], "init": init})
    assert r["stop"]["reason"] == "init_failed"
    assert r["stop"]["cause"]["reason"] == "unmapped_read" and r["stop"]["cause"]["addr"] == "0x10"
    init[0]["replace"] = alloc_replace(tblimg)
    r = tblimg.call({"func": tblimg["heap_table_sum"], "args": [16], "init": init})
    assert ret(r) == sum(i ^ 0x5A for i in range(16))
    # each init call has its own instruction cap
    r = tblimg.call(apply_req(tblimg, init=[{"func": tblimg["build_sbox"], "max_insns": 50}]))
    assert r["stop"]["reason"] == "init_failed" and r["stop"]["cause"]["reason"] == "max_insns"


def test_batch_requests_start_pristine(tblimg):
    want = bytes(SBOX[b] for b in DATA)
    r = tblimg.call({"requests": [apply_req(tblimg, init=[tblimg["build_sbox"]]),
                                  apply_req(tblimg),
                                  apply_req(tblimg, init=[tblimg["build_sbox"]])]})
    a, b, c = r["results"]
    assert out_bytes(a) == want and out_bytes(b) is None and out_bytes(c) == want
    # init in defaults runs again for every request
    r = tblimg.call({"defaults": {"init": [tblimg["build_sbox"]]},
                     "requests": [apply_req(tblimg), apply_req(tblimg)]})
    assert [out_bytes(x) for x in r["results"]] == [want, want]


def test_init_validation(tblimg):
    f = tblimg["build_sbox"]
    r = tblimg.call(apply_req(tblimg, init=[{"func": f, "read": [{"addr": 0}]}]))
    assert "not allowed" in r["error"] and "read" in r["error"] and "max_insns" in r["hint"]
    r = tblimg.call(apply_req(tblimg, init=f))
    assert "list" in r["error"]
    r = tblimg.call(apply_req(tblimg, init=[{"args": [1]}]))
    assert "func" in r["error"]
    r = tblimg.call(apply_req(tblimg, init=["0x10"]))
    assert r["error"].startswith("init[0]: 0x10 is not in the image")
    r = tblimg.call(apply_req(tblimg, init=[{"func": f, "imports": {"x": {"bogus": 1}}}]))
    assert r["error"].startswith("init[0].imports")
    # an explicit name may not be reused by a later call
    r = tblimg.call({"func": tblimg["sbox_apply"], "args": [{"out": 8, "name": "k"}, {"out": 8}, 8],
                     "init": [{"func": tblimg["derive_key"], "args": [1, {"out": 8, "name": "k"}, 8]}]})
    assert "used twice" in r["error"]


def test_x86_pe_globals_and_top_level_imports(x86img):
    main = {"func": x86img["count_char"], "args": ["0x406100", ord("E")]}
    assert ret(x86img.call(main)) == 0
    # write_global stores "SECRET" in .data; dyn_call reaches GetTickCount through
    # GetProcAddress, and the request's imports override applies to it too
    r = x86img.call(dict(main, init=[x86img["write_global"], x86img["dyn_call"]],
                         imports={"GetTickCount": {"ret": 1234}}))
    assert ret(r) == 2
    assert r["init"][1]["ret"] == "0x4d2"
    assert "imports" not in r and "writes" not in r


def test_dump_after_init(tblimg, tmp_path):
    """dump writes the memory the run changed: the .data table init built, the
    heap and the named buffers, each with its changed ranges."""
    import json
    import os
    n = 64
    d = str(tmp_path / "dump")
    r = tblimg.call({"func": tblimg["heap_table_sum"], "args": [n],
                     "init": [tblimg["build_sbox"], {"func": tblimg["build_heap_table"], "args": [n]}],
                     "replace": alloc_replace(tblimg), "dump": d})
    assert r["stop"]["reason"] == "returned" and r["dump"]["dir"] == d
    meta = json.load(open(os.path.join(d, "dump.json")))
    kinds = {x["kind"]: x for x in meta["regions"]}
    data = kinds["segment"]
    assert data["name"] == ".data" and int(data["start"], 16) == 0x406000
    blob = open(os.path.join(d, data["file"]), "rb").read()
    runs = [(int(a, 16) - 0x406000, int(b, 16) - 0x406000) for a, b in data["changed"]]
    assert blob[0x800:0x900] == bytes(SBOX)
    covered = {i for a, b in runs for i in range(a, b)}
    # SBOX (its one zero byte, SBOX[219], is unchanged), then TABLE_PTR at 0x900
    assert covered >= set(range(0x800, 0x900)) - {0x800 + 219} and 0x900 in covered
    assert 0x800 + 219 not in covered and min(covered) == 0x800
    heap = kinds["heap"]
    hb = open(os.path.join(d, heap["file"]), "rb").read()
    blk = int(heap["blocks"][0]["addr"], 16) - int(heap["start"], 16)
    assert hb[blk:blk + n] == bytes(i ^ 0x5A for i in range(n))
    assert all(x["kind"] != "segment" or x["changed"] for x in meta["regions"])
    # no dump key, no dump; a bad value is refused
    assert "dump" not in tblimg.call(apply_req(tblimg))
    assert "error" in tblimg.call(apply_req(tblimg, dump=5))
