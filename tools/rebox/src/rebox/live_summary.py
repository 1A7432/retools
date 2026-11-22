"""Compact JSON summary of a `rebox live` run (schema rebox.summary/1, mode "live").

Same conventions as summary.py: every list is {"total": N, "top": [...]},
strings are clipped with a "…[+N]" tail, nothing is cut silently and the
printed object fits --max-chars (see fit_budget, a copy of summary.fit_budget
with weights for this layout).
"""

from __future__ import annotations

import base64
import json
import math
from pathlib import Path

from . import live_trace
from .summary import SCHEMA, _compact_paths, _drop, _size, _tlists, clip, dumps, tl

INDICATOR_ORDER = ["hosts", "ips", "conns", "ports", "urls", "data_out", "listening", "unix_sockets",
                   "cmdlines", "files_written", "files_deleted", "files_renamed", "files_chmod", "persistence",
                   "etc_changed", "proc_names", "memfd", "privilege", "anti_analysis", "signals_sent", "files_read"]


def _load_json(path: Path, cap: int = 8 << 20):
    try:
        with open(path, "rb") as f:
            data = f.read(cap + 1)
        if len(data) > cap:
            return None
        return json.loads(data)
    except (OSError, ValueError):
        return None


def _head(path: Path, cap: int = 300) -> str | None:
    try:
        with open(path, "rb") as f:
            data = f.read(cap + 1)
    except OSError:
        return None
    return live_trace.printable(data[:cap], cap) + ("…" if len(data) > cap else "")


def fakenet_events(path: Path, max_events: int = 2000) -> dict:
    dns, tcp = [], []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f):
                if n >= max_events:
                    break
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                if ev.get("event") == "dns" and ev.get("name"):
                    dns.append(f"{clip(ev.get('name'), 120)} type={ev.get('qtype')}")
                elif ev.get("event") == "tcp_data":
                    try:
                        data = base64.b64decode(str(ev.get("data") or ""), validate=False)[:4096]
                    except ValueError:
                        data = b""
                    item = f"{clip(ev.get('dst'), 60)} {ev.get('bytes')}B {live_trace.printable(data)!r}"
                    sni = live_trace.tls_sni(data)
                    req = live_trace.http_request(data)
                    if sni:
                        item += f" sni={clip(sni, 80)}"
                    if req:
                        item += f" http={clip(req[0], 80)!r} host={clip(req[1], 80)}"
                    tcp.append(item)
    except OSError:
        pass
    return {"dns": dns, "tcp": tcp}


def build(out_dir: Path) -> dict:
    meta = _load_json(out_dir / "run.json") or {}
    cdir = out_dir / "container"
    status = _load_json(cdir / "status.json") or {}
    ident = meta.get("identity") or {}
    fakenet = bool(meta.get("fakenet"))
    an = live_trace.Analysis(meta.get("sample_in_container") or "?",
                             fakenet_answer="203.0.113.1" if fakenet else None)
    if (cdir / "trace").is_dir():
        an.load_dir(cdir / "trace")

    sample = {
        "name": meta.get("sample_name"),
        "sha256": meta.get("sha256"),
        "size": meta.get("size"),
        "arch": ident.get("arch"),
        "bits": ident.get("class"),
        "endian": ident.get("endian"),
        "elf_type": ident.get("elf_type"),
        "linkage": ident.get("linkage"),
        "interp": ident.get("interp"),
        "go": ident.get("go"),
        "stripped": ident.get("stripped"),
        "entry": ident.get("entry"),
    }

    # ---- indicators
    ind = {}
    empty = []
    extra = {"etc_changed": meta.get("etc_changed") or []}
    for key in INDICATOR_ORDER:
        vals = list(extra[key]) if key in extra else list(an.ind.get(key, {}))
        if vals:
            ind[key] = tl([clip(v) for v in vals])
        else:
            empty.append(key)
    ind["empty"] = empty

    # ---- syscalls
    hist = [[n, c] for n, c in an.hist.most_common()]
    cats = {}
    for cat, counter in an.cats.items():
        if counter:
            cats[cat] = tl([[n, c] for n, c in counter.most_common()])
    syscalls = {
        "calls": sum(an.hist.values()),
        "unique": len(an.hist),
        "histogram": tl(hist),
        "failed": tl([[k, c] for k, c in an.failed.most_common()]),
        "categories": cats,
    }
    if meta.get("mode") == "qemu":
        syscalls["note"] = ("host syscalls of the QEMU user-mode process: the guest's syscalls as QEMU issued them "
                            "(x86 open/fork appear as openat/clone) plus QEMU's own mmap/signal/futex traffic")

    # ---- processes and stop reason
    procs = an.processes()
    stop = meta.get("stop") or status.get("stop") or "unknown"
    for p in procs:
        if p["exit"] == "not seen" and stop != "exited":
            p["exit"] = f"running at {stop}, killed"
    proc_items = [f"{p['pid']}<-{p['ppid'] if p['ppid'] is not None else '-'} {clip(p['cmd'], 120)} [{p['exit']}]"
                  + (f" emu={p['emulated']}" if p["emulated"] else "")
                  + (f" threads={p['threads']}" if p["threads"] else "") for p in procs]
    root_exit = an.root_exit()
    exit_code = signal = None
    if root_exit and root_exit.startswith("exit "):
        exit_code = int(root_exit[5:])
    elif root_exit and root_exit.startswith("signal "):
        signal = root_exit[7:]
    errors = [clip(e, 200) for e in (meta.get("errors") or [])]
    errors += [clip(f"[runner] {e}", 200) for e in (status.get("errors") or []) if isinstance(e, str)]
    errors += [clip(f"[trace] {n}", 200) for n in an.notes]
    if an.unparsed:
        errors.append(f"[trace] {an.unparsed} trace lines not understood (kept in raw trace)")
    survivors = status.get("survivors") if isinstance(status.get("survivors"), list) else []
    execution = {
        "engine": meta.get("engine"),
        "image": meta.get("image_short"),
        "isolation": meta.get("isolation"),
        "run_as": meta.get("run_as"),
        "fakenet": fakenet,
        "wall_s": meta.get("wall_s"),
        "sample_s": _sample_s(status),
        "timeout_s": meta.get("timeout"),
        "stop": stop,
        "exit_code": exit_code,
        "signal": signal,
        "processes": tl(proc_items),
        "alive_at_stop": tl([clip(f"{s.get('pid')} {s.get('cmdline') or s.get('comm')}", 120)
                             for s in survivors if isinstance(s, dict)]),
        "container_removed": meta.get("container_removed"),
        "errors": tl(errors),
    }

    # ---- file system changes and payloads
    fs = meta.get("fs_changes") or {}
    fs_changes = {k: tl([clip(p) for p in fs.get(k) or []]) for k in ("added", "changed", "deleted")}
    payloads = [{k: (clip(v, 120) if isinstance(v, str) else v) for k, v in d.items()} for d in meta.get("dumps") or []]
    skipped = [clip(s, 160) for s in meta.get("dumps_skipped") or []]

    out = {
        "schema": SCHEMA,
        "ok": True,
        "mode": "live",
        "sample": sample,
        "execution": execution,
        "syscalls": syscalls,
        "indicators": ind,
    }
    if fakenet:
        fe = fakenet_events(cdir / "fakenet.jsonl")
        out["fakenet"] = {"dns": tl(fe["dns"]), "tcp": tl(fe["tcp"])}
    out.update({
        "fs_changes": fs_changes,
        "payloads": tl(payloads),
        "payloads_not_saved": tl(skipped),
        "output": {
            "stdout": {"bytes": status.get("stdout_bytes"), "head": _head(cdir / "stdout.bin")},
            "stderr": {"bytes": status.get("stderr_bytes"), "head": _head(cdir / "stderr.bin")},
        },
        "out_dir": str(out_dir),
        "raw_trace": "container/trace/",
        "truncated": None,
    })
    return out


def _sample_s(status: dict):
    try:
        return round(float(status["end_of_sample"]) - float(status["start"]), 2)
    except (KeyError, TypeError, ValueError):
        return None


# ---- budget (summary.fit_budget with this layout's weights) ------------------------------------

WEIGHTS = {"indicators": 5, "payloads": 4, "fakenet": 4, "execution.processes": 4, "execution.errors": 3,
           "execution.alive_at_stop": 3, "fs_changes": 3, "syscalls.categories": 2, "syscalls.failed": 2,
           "payloads_not_saved": 2, "syscalls.histogram": 1.5, "indicators.files_read": 1.5}
DROP_ORDER = ["syscalls.histogram", "syscalls.categories", "syscalls.failed", "output", "fs_changes",
              "execution.processes", "indicators", "payloads", "fakenet"]


def _weight(path: str) -> float:
    best, w = -1, 2.0
    for prefix, val in WEIGHTS.items():
        if (path == prefix or path.startswith(prefix + ".")) and len(prefix) > best:
            best, w = len(prefix), val
    return w


def fit_budget(summary: dict, max_chars: int) -> dict:
    summary["truncated"] = None
    if _size(summary) <= max_chars:
        return summary
    full = {path: (t, list(t["top"])) for path, t in _tlists(summary)}
    dropped: list[str] = []
    reserve = 0
    for _ in range(64):
        live = [(p, t, items) for p, (t, items) in full.items()
                if not any(p == d or p.startswith(d + ".") for d in dropped)]
        live.sort(key=lambda x: -_weight(x[0]))
        for _p, t, _items in live:
            t["top"] = []
        summary["truncated"] = None
        size = _size(summary)
        budget = max_chars - reserve
        pos = {p: 0 for p, _, _ in live}
        open_lists = {p for p, _, items in live if items}
        while open_lists:
            for p, t, items in live:
                for _ in range(math.ceil(_weight(p))):
                    if p not in open_lists:
                        break
                    i = pos[p]
                    if i >= len(items):
                        open_lists.discard(p)
                        break
                    cost = len(dumps(items[i])) + (1 if t["top"] else 0)
                    if size + cost > budget:
                        open_lists.discard(p)
                        break
                    t["top"].append(items[i])
                    pos[p] = i + 1
                    size += cost
        cuts = _compact_paths([p for p, t, items in live if len(t["top"]) < len(items)])
        summary["truncated"] = {
            "why": f"lists shortened to fit {max_chars} chars; each keeps its exact total; full data in out_dir",
            "cut": cuts,
        }
        if dropped:
            summary["truncated"]["dropped"] = dropped
        over = _size(summary) - max_chars
        if over <= 0:
            return summary
        if any(t["top"] for _, t, _ in live):
            reserve += over
            continue
        nxt = next((d for d in DROP_ORDER if d not in dropped and _drop(summary, d)), None)
        if nxt is None:
            summary["truncated"]["over_budget"] = True
            return summary
        dropped.append(nxt)
        reserve = 0
    summary["truncated"]["over_budget"] = True
    return summary


def render(out_dir: Path, max_chars: int) -> str:
    s = build(out_dir)
    fit_budget(s, max_chars)
    return dumps(s)
