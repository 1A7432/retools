"""Inner stage: runs inside the sandbox, emulates the sample, writes artefacts.

Everything that parses or emulates sample bytes happens here. The outer stage
only hashes the file and reads the JSON this stage writes.

Output directory layout:
    report.json   complete Speakeasy report (unmodified)
    run.json      rebox metadata: identity, sandbox self-check, dumps, errors
    dumps/*.bin   memory dumps, dropped files and injected buffers (mode 0600)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import subprocess
import time
import traceback
import zlib
from pathlib import Path

from . import sandbox

MAX_DUMP_BYTES = 64 * 1024 * 1024
MAX_TOTAL_DUMP_BYTES = 512 * 1024 * 1024
PERM_EXEC = 0x10
PERM_WRITE = 0x04


def _write_private(path: Path, data: bytes) -> None:
    """Create a new file with mode 0600; never overwrite, never executable."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class DumpWriter:
    def __init__(self, out_dir: Path):
        self.dir = out_dir / "dumps"
        self.dir.mkdir(mode=0o700, exist_ok=True)
        self.entries: list[dict] = []
        self.seen: set[tuple] = set()
        self.total = 0
        self.skipped: list[dict] = []

    def add(self, kind: str, data: bytes, **info) -> dict | None:
        sha = hashlib.sha256(data).hexdigest()
        label = info.get("base") or info.get("name") or "x"
        key = (kind, str(label), sha)
        if key in self.seen:
            return None
        self.seen.add(key)
        existing = next((e["path"] for e in self.entries if e["sha256"] == sha), None)
        if existing is None:
            if len(data) > MAX_DUMP_BYTES or self.total + len(data) > MAX_TOTAL_DUMP_BYTES:
                self.skipped.append({"kind": kind, "size": len(data), "sha256": sha, "reason": "size cap", **info})
                return None
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(label))[:40]
            existing = str(self.dir / f"{kind}_{safe}_{sha[:12]}.bin")
            _write_private(Path(existing), data)
            self.total += len(data)
        entry = {"kind": kind, "path": existing, "size": len(data), "sha256": sha, **info}
        self.entries.append(entry)
        return entry


def pe_identity(path: str) -> dict:
    import pefile

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ]
    )
    machine = pe.FILE_HEADER.Machine
    arch = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "armnt"}.get(machine, hex(machine))
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    is_driver = subsystem == 1
    is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
    pe_type = "dotnet" if is_dotnet else "driver" if is_driver else "dll" if is_dll else "exe"
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("latin-1")
        c = s.Characteristics
        perms = ("r" if c & 0x40000000 else "-") + ("w" if c & 0x80000000 else "-") + ("x" if c & 0x20000000 else "-")
        data = s.get_data()
        sections.append(
            {
                "name": name,
                "rva": hex(s.VirtualAddress),
                "vsize": hex(s.Misc_VirtualSize),
                "rawsize": hex(s.SizeOfRawData),
                "perms": perms,
                "entropy": round(_entropy(data), 2),
            }
        )
    imports = sum(len(d.imports) for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    ident = {
        "arch": arch,
        "pe_type": pe_type,
        "subsystem": {1: "native", 2: "gui", 3: "console", 9: "wince"}.get(subsystem, str(subsystem)),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "imports": imports,
        "sections": sections,
    }
    try:
        ident["imphash"] = pe.get_imphash() or None
    except Exception:
        ident["imphash"] = None
    pe.close()
    return ident


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def run_inner(sample: str, out_dir: str, timeout: int, args: list[str], sandboxed: bool,
              trace_mem: bool, children: bool, max_api: int = 10000) -> int:
    out = Path(out_dir)
    (out / "tmp").mkdir(mode=0o700, exist_ok=True)
    meta: dict = {"sample": sample, "sandbox": None, "identity": None, "errors": [], "dumps": [],
                  "dumps_skipped": [], "speakeasy_version": None, "unicorn_version": None}
    log_handler = _setup_logging(out)
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

        with open(sample, "rb") as f:
            magic = f.read(4)
        if magic[:2] != b"MZ":
            if magic == b"\x7fELF":
                from . import elf

                return elf.run_elf(sample, out, timeout, args, meta)
            meta["errors"].append({"stage": "load", "error": "not a PE (no MZ header) and not ELF"})
            return 5

        meta["identity"] = pe_identity(sample)
        if meta["identity"]["pe_type"] == "dotnet":
            meta["errors"].append({"stage": "load", "error": ".NET assembly: Speakeasy cannot emulate managed code"})
            return 5
        if meta["identity"]["arch"] not in ("x86", "x64"):
            meta["errors"].append({"stage": "load", "error": f"unsupported PE machine {meta['identity']['arch']}"})
            return 5

        status = _emulate_pe(sample, out, timeout, args, trace_mem, children, max_api, meta)
    except Exception as e:
        meta["errors"].append({"stage": "inner", "error": f"{type(e).__name__}: {e}",
                               "traceback": traceback.format_exc(limit=8)})
        status = 4
    finally:
        meta["inner_wall_time"] = round(time.monotonic() - t0, 3)
        log_handler.close()
        (out / "run.json").write_text(json.dumps(meta, indent=1))
        os.chmod(out / "run.json", 0o600)
    return status


def _setup_logging(out: Path) -> logging.Handler:
    # Speakeasy logs every API call at INFO; keep that out of stderr and in a file.
    handler = logging.FileHandler(out / "speakeasy.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger("speakeasy")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    root.propagate = False
    return handler


def _emulate_pe(sample: str, out: Path, timeout: int, args: list[str], trace_mem: bool,
                children: bool, max_api: int, meta: dict) -> int:
    import speakeasy
    import unicorn
    from speakeasy.config import get_default_config_dict

    meta["speakeasy_version"] = getattr(speakeasy, "__version__", None) or _dist_version("speakeasy-emulator")
    meta["unicorn_version"] = unicorn.__version__

    cfg = get_default_config_dict()
    cfg["timeout"] = timeout
    cfg["max_total_time"] = timeout
    cfg["max_api_count"] = max_api
    cfg["analysis"]["strings"] = True
    cfg["analysis"]["memory_tracing"] = bool(trace_mem)
    cfg["keep_memory_on_free"] = True  # freed unpack buffers stay readable for the end-of-run dump

    dumps = DumpWriter(out)
    se = speakeasy.Speakeasy(config=cfg)

    def on_dyn_code(mm):
        # Fires the first time code runs inside memory the sample allocated.
        try:
            data = se.mem_read(mm.base, mm.size)
        except Exception as e:
            meta["errors"].append({"stage": "dump", "error": f"read {mm.tag}: {e}"})
            return
        dumps.add("dyncode", data, base=hex(mm.base), tag=mm.tag, when="first_exec", executed=True)

    se.add_dyn_code_hook(on_dyn_code)
    module = se.load_module(sample)

    # Speakeasy's default command line is "svchost.exe myarg1 myarg2" (fake
    # arguments can steer a sample down an unusual path), and with argv given
    # it takes argv[0] from the last loaded exe, which is ntoskrnl.exe. Use the
    # sample's own emulated path plus exactly the --arg values instead.
    # DLLs and drivers keep Speakeasy's defaults unless --arg was given.
    if module.is_exe() or args:
        argv = [module.emu_path, *args]
        se.emu.command_line = subprocess.list2cmdline(argv)
        se.emu.get_argv = lambda: list(argv)
    meta["command_line"] = getattr(se.emu, "command_line", None)

    # Hash executable (or writable) sections of the main image so in-place
    # unpacking (UPX-style) can be detected by comparing at the end.
    before = {}
    for sect in module.sections:
        addr = module.base + sect.virtual_address
        try:
            before[sect.name, addr] = (sect, hashlib.sha256(se.mem_read(addr, sect.virtual_size)).hexdigest())
        except Exception:
            pass

    run_error = None
    try:
        se.run_module(module, all_entrypoints=True, emulate_children=children)
    except Exception as e:
        run_error = f"{type(e).__name__}: {e}"
        meta["errors"].append({"stage": "run_module", "error": run_error, "traceback": traceback.format_exc(limit=8)})

    report_text = se.get_json_report()
    report_path = out / "report.json"
    _write_private(report_path, report_text.encode("utf-8"))
    report = json.loads(report_text)
    # The report only keeps de-duplicated API events; the true per-run call count
    # lives on the profiler's run objects (same order as report entry_points).
    try:
        meta["run_api_calls"] = [int(r.num_apis) for r in se.emu.get_profiler().runs]
    except Exception as e:
        meta["errors"].append({"stage": "stats", "error": f"api call counts unavailable: {e}"})

    _end_of_run_dumps(se, module, before, report, dumps, meta)
    _dropped_and_injected(se, report, dumps, meta)

    meta["dumps"] = dumps.entries
    meta["dumps_skipped"] = dumps.skipped
    try:
        se.shutdown()
    except Exception:
        pass
    return 0


def _end_of_run_dumps(se, module, before, report, dumps: DumpWriter, meta: dict) -> None:
    # Final contents of every dynamic code region Speakeasy saw executing.
    for ep in report.get("entry_points") or []:
        for seg in ep.get("dynamic_code_segments") or []:
            base, size = int(seg["base"], 16), int(seg["size"], 16)
            try:
                data = se.mem_read(base, size)
            except Exception:
                continue
            dumps.add("dyncode", data, base=seg["base"], tag=seg.get("tag"), when="end", executed=True)

    # Regions the sample made executable with VirtualProtect & co. outside its image.
    img_lo, img_hi = module.base, module.base + module.image_size
    for ep in report.get("entry_points") or []:
        for ev in ep.get("events") or []:
            if ev.get("event") != "mem_protect" or "EXECUTE" not in str(ev.get("protect") or ""):
                continue
            base = int(ev["base"], 16)
            if img_lo <= base < img_hi:
                continue
            try:
                mm = se.get_address_map(base)
                data = se.mem_read(mm.base, mm.size) if mm else None
            except Exception:
                data = None
            if data:
                dumps.add("protexec", data, base=hex(mm.base), tag=mm.tag, when="end", executed=None)

    # Main-image sections whose bytes changed and that are executable, either by
    # section flags or because the sample later protected part of them executable.
    # (Speakeasy maps the whole image as one region, so region perms say nothing.)
    made_exec = []
    for ep in report.get("entry_points") or []:
        for ev in ep.get("events") or []:
            if ev.get("event") == "mem_protect" and ev.get("pid") is None and "EXECUTE" in str(ev.get("protect") or ""):
                made_exec.append((int(ev["base"], 16), int(ev["size"], 16)))
    for (name, addr), (sect, h0) in before.items():
        try:
            data = se.mem_read(addr, sect.virtual_size)
        except Exception:
            continue
        if hashlib.sha256(data).hexdigest() == h0:
            continue
        end = addr + sect.virtual_size
        executable = bool(sect.perms & PERM_EXEC) or any(b < end and addr < b + n for b, n in made_exec)
        if executable:
            dumps.add("imgmod", data, base=hex(addr), name=name, when="end", executed=None)


def _dropped_and_injected(se, report, dumps: DumpWriter, meta: dict) -> None:
    store = report.get("data") or {}
    live = {}
    try:
        live = {str(f.path).lower(): f for f in se.get_dropped_files() or []}
    except Exception:
        pass
    for ep in report.get("entry_points") or []:
        for df in ep.get("dropped_files") or []:
            path = str(df.get("path") or "")
            data = _decode_blob(store.get(df.get("data_ref") or ""))
            if data is None and path.lower() in live:
                try:
                    data = live[path.lower()].get_data()
                except Exception:
                    data = None
            name = path.replace("\\", "/").rsplit("/", 1)[-1]
            if data:
                dumps.add("dropped", data, name=name, emu_path=path)
            else:
                dumps.skipped.append({"kind": "dropped", "emu_path": path, "size": df.get("size"),
                                      "sha256": df.get("sha256"), "reason": "content not in report"})

    store = report.get("data") or {}
    for ep in report.get("entry_points") or []:
        for ev in ep.get("events") or []:
            if ev.get("event") != "mem_write" or ev.get("pid") is None or not ev.get("data_ref"):
                continue
            blob = store.get(ev["data_ref"])
            data = _decode_blob(blob)
            if data:
                dumps.add("inject", data, base=ev.get("base"), pid=ev.get("pid"), target=ev.get("path"))


def _decode_blob(blob) -> bytes | None:
    if not isinstance(blob, dict) or "data" not in blob:
        return None
    try:
        raw = base64.b64decode(blob["data"])
        return zlib.decompress(raw) if blob.get("compression") == "zlib" else raw
    except Exception:
        return None


def _dist_version(name: str) -> str | None:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return None
