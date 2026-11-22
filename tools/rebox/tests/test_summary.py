"""Summary builder against a saved raw report, plus the --max-chars budget."""

import copy
import json

import pytest
from conftest import FIXTURES

from rebox import summary as sm

OUT = "/FIXTURE/out"


def load():
    report = json.loads((FIXTURES / "behave_report.json").read_text())
    meta = json.loads((FIXTURES / "behave_run.json").read_text())
    return report, meta


def build(report=None, meta=None):
    r, m = load()
    return sm.build_summary(report or r, meta or m, sample_name="behave.exe", sha256="ab" * 32, size=3584,
                            out_dir=OUT, raw_report_path=OUT + "/report.json", wall_time=0.5, timeout=60,
                            sandbox_state="test", noise_strings=sm.emulator_noise_strings())


def walk(obj, path=""):
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")


def test_indicators_from_fixture():
    s = build()
    ind = s["indicators"]
    top = lambda k: ind[k]["top"]  # noqa: E731
    assert "beacon.rebox-test.invalid" in top("hosts")
    assert top("urls") == ["http://dl.rebox-test.invalid/stage2.bin"]
    assert top("ips") == ["198.51.100.7"]  # the emulator's canned DNS answer 10.1.2.3 is excluded
    assert "tcp connect 198.51.100.7:4444" in top("conns")
    assert "4444" in top("ports")
    assert top("files_written") == ["C:\\Users\\Public\\rebox_drop.txt"]
    assert "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ReboxTest" in top("registry_written")
    assert top("mutexes") == ["Global\\rebox-test-mutex"]
    assert top("cmdlines") == ["cmd.exe /c echo rebox-test"]
    assert "services" in ind["empty"]


def test_api_runs_payloads_from_fixture():
    s = build()
    assert s["api"]["calls"] == 21
    cats = s["api"]["categories"]
    assert [x[0] for x in cats["network"]["top"]][:2] == ["ws2_32.WSAStartup", "ws2_32.gethostbyname"]
    assert any(x[0] == "kernel32.IsDebuggerPresent" for x in cats["anti_analysis"]["top"])
    assert cats["memory"]["top"][0][:2] == ["kernel32.VirtualAlloc", 1]
    run = s["emulation"]["runs"]["top"][0]
    assert run["stop"] == "returned" and run["ret"] == "0x1337" and run["dyn_code"] == 1
    kinds = {p["kind"]: p for p in s["payloads"]["top"]}
    assert kinds["dyncode"]["file"].startswith("dumps/") and kinds["dyncode"]["file"].endswith(".bin")
    assert kinds["dyncode"]["base"] == "0x50000"
    assert kinds["dropped"]["emu_path"] == "C:\\Users\\Public\\rebox_drop.txt"
    assert "rebox stage2 running" in s["strings"]["api_args"]["top"]
    assert s["raw_report"] == "report.json"
    assert s["truncated"] is None


def test_conventions_lists_and_hex():
    s = build()
    for path, node in walk(s):
        if isinstance(node, list) and not path.endswith(".top") and "].top" not in path:
            # bare lists are allowed only as tuple-like rows inside "top" and for indicators.empty / truncated
            assert ".top[" in path or path in ("indicators.empty",), path
        if isinstance(node, dict) and "top" in node:
            assert set(node) >= {"total", "top"} and node["total"] >= len(node["top"]), path
    hex_keys = ("start", "pc", "ret", "base", "image_base", "entry_rva")
    for path, node in walk(s):
        if path.rsplit(".", 1)[-1] in hex_keys and node is not None:
            assert isinstance(node, str) and node.startswith("0x"), (path, node)


def test_fits_default_budget_without_cutting():
    s = sm.fit_budget(build(), 6000)
    assert len(sm.dumps(s)) <= 6000
    assert s["truncated"] is None


@pytest.mark.parametrize("budget", [1800, 2500, 3500])
def test_budget_cuts_are_recorded_and_prefixes(budget):
    full = build()
    s = sm.fit_budget(copy.deepcopy(full), budget)
    text = sm.dumps(s)
    assert len(text) <= budget
    json.loads(text)
    assert s["truncated"] and s["truncated"]["cut"]
    assert "raw_report" in s["truncated"]["why"]
    full_lists = dict(sm._tlists(full))
    for path, t in sm._tlists(s):
        f = full_lists[path]
        assert t["total"] == f["total"], path  # totals stay exact
        assert t["top"] == f["top"][: len(t["top"])], path  # a prefix, nothing reordered
        if len(t["top"]) < f["total"]:
            parent = path.rsplit(".", 1)[0]
            assert path in s["truncated"]["cut"] or f"{parent}.*" in s["truncated"]["cut"], path


def test_budget_impossible_is_flagged():
    s = sm.fit_budget(build(), 300)
    assert s["truncated"]["over_budget"] is True
    assert s["truncated"]["dropped"]
    json.loads(sm.dumps(s))


def test_large_report_is_cut_to_budget():
    report, meta = load()
    ep = report["entry_points"][0]
    tmpl = next(e for e in ep["events"] if e["event"] == "api")
    for i in range(400):
        e = copy.deepcopy(tmpl)
        e["api_name"] = f"wininet.InternetConnectA"
        e["args"] = [{"name": "hInternet", "type": "handle", "value": 1, "display": "0x1"},
                     {"name": "lpszServerName", "type": "str", "value": 2, "display": f"c2-{i}.example.invalid"}]
        ep["events"].append(e)
        ep["events"].append({"pos": tmpl["pos"], "event": "net_http", "server": f"c2-{i}.example.invalid",
                             "port": 8080, "proto": "tcp.http", "headers": f"GET /gate{i}.php HTTP/1.1\n"})
    s = sm.fit_budget(build(report, meta), 6000)
    assert len(sm.dumps(s)) <= 6000
    assert s["indicators"]["hosts"]["total"] == 402
    assert 0 < len(s["indicators"]["hosts"]["top"]) < 402
    assert s["indicators"]["urls"]["total"] == 401
    assert any(c.startswith("indicators") for c in s["truncated"]["cut"])


def test_long_strings_are_marked_not_silently_cut():
    assert sm.clip("x" * 200, 160) == "x" * 160 + "…[+40]"
    assert sm.clip("short") == "short"


def test_api_name_normalisation():
    assert sm.bare_api("kernel32.CreateFileW") == "createfile"
    assert sm.bare_api("advapi32.RegOpenKeyExA") == "regopenkey"
    assert sm.bare_api("kernel32.VirtualAllocEx") == "virtualallocex"
    assert sm.bare_api("kernel32.CreateMutexW") == "createmutex"
    assert sm.categorize("ws2_32.recv") == "network"
    assert sm.categorize("advapi32.CryptDecrypt") == "crypto"
    assert sm.categorize("kernel32.GetLastError") is None


def test_runtime_only_strings_filter():
    report = {"strings": {"static": {"ansi": ["static one"], "unicode": []},
                          "in_memory": {"ansi": ["static one", "decoded-secret-config", "abcdefghijkl", "short"],
                                        "unicode": ["windir=C:\\Windows"]}}}
    assert sm.runtime_only_strings(report, {"windir=C:\\Windows"}) == ["decoded-secret-config"]
    report["strings"]["in_memory"]["ansi"].append("C:\\Windows\\Temp\\dropped.exe")
    noise = sm.emulator_noise_strings()
    assert "C:\\Windows\\Temp\\dropped.exe" in sm.runtime_only_strings(report, noise)
