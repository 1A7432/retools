"""Command line: `remu call --image DIR` (request JSON on stdin), `remu info`, `remu stubs`."""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback

from . import __version__
from .errors import RemuError
from .reply import size

DEFAULT_BUDGET = 6000


def _emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_one(image, arch, req, budget=None):
    from .emu import Emu
    try:
        if budget is not None and isinstance(req, dict):
            req = dict(req)
            req["max_chars"] = min(int(req.get("max_chars", budget)), budget)
        emu = Emu(image, arch, req)
        return emu.run()
    except RemuError as exc:
        out = exc.reply()
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON reply, never a traceback
        traceback.print_exc(file=sys.stderr)
        out = {"error": "internal error: %s: %s" % (type(exc).__name__, exc),
               "hint": "a remu bug; the traceback is on stderr. Try a simpler request or "
                       "analyse statically."}
    if isinstance(req, dict) and "id" in req:
        out = dict({"id": req["id"]}, **out)
    return out


def handle(image, arch, payload):
    """One request object, a list of requests, or {"requests": [...], "defaults": {...}}."""
    if isinstance(payload, dict) and "requests" not in payload:
        return run_one(image, arch, payload)
    if isinstance(payload, list):
        reqs, defaults, budget = payload, {}, DEFAULT_BUDGET
    elif isinstance(payload, dict):
        reqs = payload.get("requests")
        defaults = payload.get("defaults") or {}
        budget = int(payload.get("max_chars", DEFAULT_BUDGET))
        extra = set(payload) - {"requests", "defaults", "max_chars"}
        if extra:
            raise RemuError("unknown batch keys: %s" % ", ".join(sorted(extra)),
                            "a batch is {\"requests\": [...], \"defaults\": {...}, \"max_chars\": N}")
    else:
        raise RemuError("the request must be a JSON object or a list of objects")
    if not isinstance(reqs, list) or not reqs or not isinstance(defaults, dict):
        raise RemuError("requests must be a non-empty list and defaults an object")
    share = max(budget // len(reqs), 150)
    results, reasons = [], {}
    for i, req in enumerate(reqs):
        merged = dict(defaults, **req) if isinstance(req, dict) else req
        if isinstance(merged, dict) and "id" not in merged:
            merged["id"] = i
        res = run_one(image, arch, merged, share)
        results.append(res)
        key = res.get("stop", {}).get("reason") if "stop" in res else "error"
        reasons[key] = reasons.get(key, 0) + 1
    out = {"total": len(results), "reasons": reasons, "results": results}
    if size(out) > budget:
        while len(results) > 1 and size(out) > budget - 200:
            results.pop()
        out["more"] = ("%d of %d results shown; split the batch, pass fields "
                       "(e.g. [\"ret\", \"buffers\"]) or raise max_chars" % (len(results), out["total"]))
    return out


def cmd_call(ns):
    try:
        from .arch import for_image
        from .image import Image
        if ns.request:
            with open(ns.request, encoding="utf-8") as fh:
                text = fh.read()
        else:
            text = sys.stdin.read()
        try:
            payload = json.loads(text)
        except ValueError as exc:
            raise RemuError("the request is not valid JSON: %s" % exc,
                            "send one JSON object (or a list of them) on stdin")
        image = Image(ns.image)
        arch = for_image(image)
        _emit(handle(image, arch, payload))
    except RemuError as exc:
        _emit(exc.reply())
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc(file=sys.stderr)
        _emit({"error": "internal error: %s: %s" % (type(exc).__name__, exc),
               "hint": "a remu bug; the traceback is on stderr"})
    return 0


def cmd_info(ns):
    from .arch import for_image
    from .emu import Emu
    from .image import Image
    from . import stubs as S
    try:
        image = Image(ns.image)
        arch = for_image(image)
        emu = Emu(image, arch, {"func": hex(image.entry)})
        layout = emu._layout()
    except RemuError as exc:
        _emit(exc.reply())
        return 0
    mods = {}
    stubbed = []
    for rec in image.imports.values():
        mods[rec.get("module") or "?"] = mods.get(rec.get("module") or "?", 0) + 1
        if S.lookup(rec.get("name")):
            stubbed.append(rec.get("name"))
    info = {
        "file": image.meta.get("file"), "sha256": image.meta.get("sha256"),
        "arch": image.arch, "bits": image.bits, "filetype": image.filetype,
        "base": "%#x" % image.base, "entry": "%#x" % image.entry,
        "default_cc": arch.default_cc,
        "segments": [{"name": s.name, "start": "%#x" % s.start, "end": "%#x" % s.end,
                      "perm": s.perm, "extern": s.extern, "initialised": len(s.data)}
                     for s in image.segments],
        "imports": {"total": len(image.imports), "with_prototype": sum(
            1 for r in image.imports.values() if "purge" in r), "stubbed": len(stubbed),
            "modules": dict(sorted(mods.items(), key=lambda kv: -kv[1]))},
        "thunks": len(image.thunks),
        "layout": {k: "%#x-%#x" % v for k, v in layout.items()},
    }
    if ns.json:
        _emit(info)
        return 0
    p = print
    p("%s  %s/%d-bit %s  base %s  entry %s  default cc %s" % (
        info["file"], info["arch"], info["bits"], info["filetype"], info["base"], info["entry"],
        info["default_cc"]))
    p("sha256 %s" % info["sha256"])
    p("\nsegments:")
    for s in info["segments"]:
        p("  %-10s %12s-%-12s %s%s  %d bytes initialised" % (
            s["name"], s["start"], s["end"], s["perm"], " extern" if s["extern"] else "",
            s["initialised"]))
    imp = info["imports"]
    p("\nimports: %d (%d with prototype, %d with a remu stub), thunks: %d" % (
        imp["total"], imp["with_prototype"], imp["stubbed"], info["thunks"]))
    p("  " + ", ".join("%s %d" % kv for kv in list(imp["modules"].items())[:15]))
    p("\nemulation layout:")
    for k, v in info["layout"].items():
        p("  %-8s %s" % (k, v))
    return 0


def cmd_stubs(ns):
    from . import stubs as S
    seen = {}
    for name, s in S.STUBS.items():
        seen.setdefault(id(s), (s, []))[1].append(name)
    rows = sorted(seen.values(), key=lambda x: x[1][0].lower())
    if ns.json:
        _emit({"total": len(S.STUBS), "stubs": {names[0]: {"aliases": names[1:], "nargs": s.nargs,
                                                           "kind": s.kind} for s, names in rows}})
        return 0
    for s, names in rows:
        print("%-28s nargs=%d %s  %s" % (names[0], s.nargs, "winapi" if s.kind == "w" else "crt   ",
                                        " ".join(names[1:])))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="remu", description="function-level emulator for IDA images")
    ap.add_argument("--version", action="version", version="remu %s" % __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("call", help="run request(s) from stdin; one JSON reply on stdout")
    c.add_argument("--image", required=True)
    c.add_argument("--request", help="read the request from this file instead of stdin")
    i = sub.add_parser("info", help="summarise an image")
    i.add_argument("--image", required=True)
    i.add_argument("--json", action="store_true")
    s = sub.add_parser("stubs", help="list the modelled imports")
    s.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    t0 = time.monotonic()
    rc = {"call": cmd_call, "info": cmd_info, "stubs": cmd_stubs}[ns.cmd](ns)
    if ns.cmd == "call":
        print("remu: %.0f ms" % ((time.monotonic() - t0) * 1000), file=sys.stderr)
    return rc
