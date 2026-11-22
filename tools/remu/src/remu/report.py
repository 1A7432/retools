"""Turning a finished run into the compact JSON reply."""

from __future__ import annotations

import re

from .errors import RemuError
from .image import parse_int
from .reply import fit
from .text import clip, find_strings, guess_string, render
from .values import codec_for_cp

PREVIEW = 256          # bytes of a buffer shown before the budget cuts in
MAX_WRITES = 50
STRINGS_SCAN = 64 << 10


def _h(v):
    return "%#x" % v


def disasm(emu, addr):
    data = emu.safe_read(addr, 16)
    if not data:
        return None
    import capstone
    if emu.arch.name == "arm64":
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_32 if emu.arch.name == "x86" else capstone.CS_MODE_64)
    for ins in md.disasm(data, addr):
        return ("%s %s" % (ins.mnemonic, ins.op_str)).strip()
    return "(undecodable: %s)" % data[:8].hex(" ")


def _decode_a(emu, data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(codec_for_cp(emu.acp), errors="replace")


def view(emu, addr, as_, size=None):
    """Read memory at addr the way `as_` says; returns a dict for the reply."""
    out = {"addr": _h(addr)}
    if not emu.is_mapped(addr):
        out["error"] = "not mapped"
        return out
    try:
        if as_ in ("hex", "bytes"):
            n = size or 64
            data = emu.safe_read(addr, n)
            if len(data) < n:
                out["note"] = "memory ends after %d bytes" % len(data)
            out["hex"] = data.hex()
            out.update(render(data))
        elif as_ == "cstr":
            data = emu.read_cstr(addr, size or 4096, 1)
            out.update(cstr=_decode_a(emu, data), len=len(data))
        elif as_ == "wstr":
            data = emu.read_cstr(addr, size or 4096, 2)
            out.update(wstr=data.decode("utf-16le", errors="replace"), len=len(data) // 2)
        elif as_ in ("dstr", "dastr"):
            n = int.from_bytes(emu.read(addr - 4, 4), "little")
            unit = 2 if as_ == "dstr" else 1
            if n > (size or 1 << 20):
                out["error"] = "length prefix %#x is implausible; not a Delphi string?" % n
                return out
            data = emu.read(addr, n * unit)
            out["len"] = n
            out[as_] = data.decode("utf-16le", errors="replace") if unit == 2 else _decode_a(emu, data)
        elif as_ in ("u8", "u16", "u32", "u64", "i32", "i64", "ptr", "int"):
            n = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "i32": 4, "i64": 8}.get(as_, emu.word)
            v = int.from_bytes(emu.read(addr, n), "little")
            if as_.startswith("i") and v >> (8 * n - 1):
                out["value"] = v - (1 << (8 * n))
            else:
                out["value"] = _h(v)
        else:
            raise RemuError("unknown read type %r" % as_,
                            "use hex, cstr, wstr, dstr, dastr, u8, u16, u32, u64, i32, i64 or ptr")
    except Exception as exc:  # StubFault from a read past mapped memory
        if isinstance(exc, RemuError):
            raise
        out["error"] = "unreadable memory at %#x" % getattr(exc, "addr", addr)
    return out


def peek(emu, ptr):
    """A short description of what a pointer points to, or None."""
    if ptr < 0x10000 or not emu.is_mapped(ptr):
        return None
    data = emu.safe_read(ptr, 128)
    g = guess_string(data)
    out = {"addr": _h(ptr)}
    if g:
        out["wstr" if g[0] == "w" else "cstr"] = clip(g[1], 120)
    else:
        out["hex"] = data[:32].hex()
    if emu.is_mapped(ptr - 4, 4):
        n = int.from_bytes(emu.safe_read(ptr - 4, 4), "little")
        if g and 0 < n == len(g[1]):
            out["len_prefix"] = n      # looks like a Delphi string or BSTR-like layout
    return out


def _regs(emu, names):
    out = {}
    for n in names:
        v = emu.uc.reg_read(emu.arch.reg(n))
        if emu.arch.name == "arm64" and v == 0 and n.startswith("x"):
            continue
        out[n] = _h(v & emu.mask)
    out["pc"] = _h(emu.uc.reg_read(emu.arch.pc))
    return out


def _subtract(runs, holes):
    out = []
    holes = sorted(holes)
    for a, b in runs:
        cur = a
        for h0, h1 in holes:
            if h1 <= cur or h0 >= b:
                continue
            if h0 > cur:
                out.append((cur, h0))
            cur = max(cur, h1)
        if cur < b:
            out.append((cur, b))
    return out


def _runs(dirty, merge_gap=16):
    runs = []
    for p in sorted(dirty):
        base = p << 12
        for m in re.finditer(rb"\x01+", dirty[p]):
            a, b = base + m.start(), base + m.end()
            if runs and a - runs[-1][1] <= merge_gap:
                runs[-1][1] = b
            else:
                runs.append([a, b])
    return [tuple(r) for r in runs]


def _where(emu, addr):
    lab = emu.image.label(addr)
    if lab:
        return lab
    for name, (lo, hi) in emu.layout.items():
        if lo <= addr < hi:
            if name == "heap":
                blk = emu.heap.block_at(addr)
                if blk:
                    a, n, who, freed = blk
                    return "heap block %#x+%#x (%#x bytes from %s%s)" % (
                        a, addr - a, n, who, ", freed" if freed else "")
            return "%s+%#x" % (name, addr - lo)
    for lo, hi in emu.on_demand_all:
        if lo <= addr < hi:
            return "on-demand page"
    return None


def _strings(emu, data, base, cap=12, minlen=4):
    pad = base & 3                    # align so pointer checks see whole dwords
    found = find_strings(b"\0" * pad + data[:STRINGS_SCAN], minlen,
                         lambda v: v >= 0x10000 and emu.is_mapped(v))
    found = [(off - pad, k, t) for off, k, t in found]
    top = ["%#x %s\"%s\"" % (base + off, "L" if k == "w" else "", clip(t, 160))
           for off, k, t in found[:cap]]
    out = {"total": len(found), "top": top}
    if len(data) > STRINGS_SCAN:
        out["scanned"] = "first %d KB of %d KB" % (STRINGS_SCAN >> 10, len(data) >> 10)
    return out


def _stop(emu):
    stop = {"reason": emu.reason, "at": _h(emu.stop_at)}
    for k, v in emu.stop_detail.items():
        stop[k] = _h(v) if isinstance(v, int) and k not in ("intno", "size") else v
    if emu.reason != "returned":
        ins = disasm(emu, emu.stop_at)
        if ins:
            stop["insn"] = ins
        lab = emu.image.label(emu.stop_at)
        if lab:
            stop["in"] = lab
    return stop


def _imports(emu, r):
    if emu.import_total:
        r["imports"] = {"total": emu.import_total, "top": emu.calls}
        if emu.calls_dropped or len(emu.import_counts) > 1:
            r["imports"]["counts"] = dict(sorted(emu.import_counts.items(), key=lambda kv: -kv[1]))


def _trace(emu, r):
    if emu.trace_cap:
        r["trace"] = {"total": emu.trace_total, "top": [
            dict({"to": _h(a), "from": _h(f)}, **({"n": n} if n > 1 else {}),
                 **({"fn": name} if name else {}))
            for a, f, n, name in emu.trace]}


def _warnings(emu, r):
    if emu.warnings:
        seen = {}
        for w in emu.warnings:
            seen[w] = seen.get(w, 0) + 1
        r["warnings"] = {"total": len(seen), "top": [w if n == 1 else "%s (x%d)" % (w, n)
                                                     for w, n in seen.items()]}


def build_init_failure(emu, i):
    """Init entry i did not return, so the main call never ran. The reply says
    which entry, with that call's own stop, registers, imports and trace."""
    req = emu.req
    r = {}
    if "id" in req:
        r["id"] = req["id"]
    cause = _stop(emu)
    r["stop"] = {"reason": "init_failed", "at": cause["at"], "entry": i,
                 "func": _h(emu.init[i]["func"]), "cause": cause,
                 "detail": "init[%d] (%#x) stopped with %s, so the main call did not run"
                           % (i, emu.init[i]["func"], emu.reason)}
    r["init"] = emu.init_results
    r["insns"] = emu.n
    r["regs"] = _regs(emu, _gprs(emu))
    _imports(emu, r)
    _trace(emu, r)
    _warnings(emu, r)
    r["ms"] = int(emu.elapsed * 1000)
    if getattr(emu, "dump_info", None):
        r["dump"] = emu.dump_info
    fields = req.get("fields")
    if fields:
        keep = set(fields) | {"id", "stop", "init", "dump"}
        r = {k: v for k, v in r.items() if k in keep}
    return fit(r, emu.max_chars)


def build_reply(emu):
    req = emu.req
    r = {}
    if "id" in req:
        r["id"] = req["id"]
    r["stop"] = _stop(emu)
    r["insns"] = emu.n

    if emu.reason == "returned":
        ret = emu.uc.reg_read(emu.ret_reg) & emu.mask
        r["ret"] = _h(ret)
        if ret >> (emu.arch.bits - 1):
            r["ret_signed"] = ret - (1 << emu.arch.bits)
        if emu.arch.name == "x86" and emu.call_mode:
            r["popped"] = emu.uc.reg_read(emu.arch.sp) - emu.sp_entry - 4
        _ret_view(emu, r, ret)
    else:
        r["regs"] = _regs(emu, _gprs(emu))
    if req.get("regs_out"):
        r["regs_out"] = {n: _h(emu.uc.reg_read(emu.arch.reg(n)) & emu.reg_mask(n)) for n in req["regs_out"]}
    if emu.init_results:
        r["init"] = emu.init_results

    _buffers(emu, r)
    if req.get("read"):
        r["reads"] = [_read(emu, item, i, r) for i, item in enumerate(req["read"])]
    _imports(emu, r)
    _writes(emu, r)
    _stack_strings(emu, r)
    _trace(emu, r)
    if emu.on_demand:
        r["mapped_on_demand"] = {"total": len(emu.on_demand),
                                 "top": ["%#x-%#x" % p for p in emu.on_demand]}
    unused = [k for k, v in list(emu.ov_by_name.items()) + list(emu.ov_by_addr.items())
              if id(v) not in emu.ov_used and k not in (req.get("replace") or {})]
    for k in unused:
        emu.warn("imports override %r matched no import that was called or exists" % (k,))
    if emu.layout["scratch"][0] != 0x20000000:
        emu.warn("the image overlaps the usual scratch base; scratch is at %#x this time"
                 % emu.layout["scratch"][0])
    _warnings(emu, r)
    r["ms"] = int(emu.elapsed * 1000)
    if getattr(emu, "dump_info", None):
        r["dump"] = emu.dump_info

    fields = req.get("fields")
    if fields:
        keep = set(fields) | {"id", "stop", "dump"}
        r = {k: v for k, v in r.items() if k in keep}
    return fit(r, emu.max_chars)


def _gprs(emu):
    from .emu import GPRS
    return GPRS[emu.arch.name]


def _ret_view(emu, r, ret):
    as_ = emu.ret_as
    if as_ in (None, "int"):
        p = peek(emu, ret)
        if p and ("cstr" in p or "wstr" in p):
            r["ret_points_to"] = p
        return
    m = re.match(r"^(bytes|hex):(\d+|0x[0-9a-fA-F]+)$", str(as_))
    if m:
        r["ret_view"] = view(emu, ret, "hex", int(m.group(2), 0))
    else:
        r["ret_view"] = view(emu, ret, as_)


def _read(emu, item, i, r):
    if not isinstance(item, dict):
        raise RemuError("read[%d] must be an object" % i,
                        '{"addr": "0x20000000", "size": 32} or {"addr": {"ref": "a2"}, "as": "wstr"}')
    if "reg" in item:
        base = emu.uc.reg_read(emu.arch.reg(item["reg"])) & emu.mask
    elif item.get("ret"):
        base = emu.uc.reg_read(emu.ret_reg) & emu.mask
    elif "addr" in item:
        base = emu.builder.scalar(item["addr"], "read[%d].addr" % i)
    else:
        raise RemuError("read[%d] needs addr, reg or ret" % i)
    chain = []
    for _ in range(int(item.get("deref", 0))):
        if not emu.is_mapped(base, emu.word):
            return {"addr": _h(base), "error": "cannot dereference unmapped %#x" % base}
        chain.append(_h(base))
        base = emu.read_word(base)
    base = (base + parse_int(item.get("off", 0), "read.off")) & emu.mask
    size = parse_int(item["size"], "read.size") if "size" in item else None
    if size is not None and size > 1 << 20:
        raise RemuError("read[%d]: size over 1 MB" % i)
    out = view(emu, base, item.get("as", "hex"), size)
    if chain:
        out["via"] = chain
    if "name" in item:
        out = dict({"name": item["name"]}, **out)
    return out


def _buffers(emu, r):
    changed, unchanged = [], []
    for blk in emu.builder.blocks:
        now = emu.safe_read(blk.addr, blk.size)
        if now == blk.initial:
            if blk.origin is None:      # init buffers the main call left alone are not news
                unchanged.append(blk.name)
            continue
        n = min(len(now), len(blk.initial))
        first = next((i for i in range(n) if now[i] != blk.initial[i]), n)
        last = next((i for i in range(n - 1, -1, -1) if now[i] != blk.initial[i]), first)
        e = {"name": blk.name, "addr": _h(blk.ptr), "size": blk.size,
             "changed": "+%#x..+%#x" % (first, last)}
        lo = 0 if blk.size <= PREVIEW else (first // 16) * 16
        data = now[lo:lo + PREVIEW]
        if lo or len(now) > lo + PREVIEW:
            e["shown"] = "+%#x..+%#x of %#x bytes" % (lo, lo + len(data) - 1, blk.size)
        e["hex"] = data.hex()
        e.update(render(data))
        if blk.kind in ("dstr", "dastr"):
            e.update({k: v for k, v in view(emu, blk.ptr, blk.kind).items() if k != "addr"})
        if blk.size in (4, 8) and blk.size == emu.word:
            p = peek(emu, int.from_bytes(now, "little"))
            if p:
                e["points_to"] = p
        changed.append(e)
    if changed:
        r["buffers"] = {"total": len(changed), "top": changed}
    if unchanged:
        r["unchanged"] = {"total": len(unchanged), "top": unchanged}


def _writes(emu, r):
    holes = [(b.addr, b.addr + b.size) for b in emu.builder.blocks]
    runs = _subtract(_runs(emu.dirty), holes)
    if not runs:
        return
    runs.sort(key=lambda ab: ab[0] - ab[1])
    top = []
    for a, b in runs[:MAX_WRITES]:
        data = emu.safe_read(a, b - a)
        e = {"addr": _h(a), "size": b - a}
        where = _where(emu, a)
        if where:
            e["in"] = where
        e["hex"] = data[:64].hex() + ("..." if len(data) > 64 else "")
        s = _strings(emu, data, a)
        if s["total"]:
            e["strings"] = s
        elif b - a >= 4:
            e["text"] = render(data[:64])["text"]
        top.append(e)
    r["writes"] = {"total": len(runs), "bytes": sum(b - a for a, b in runs), "top": top}


def _stack_strings(emu, r):
    lo, hi = emu.layout["stack"]
    data = emu.safe_read(lo, hi - lo)
    start = len(data) - len(data.lstrip(b"\0"))
    if start >= len(data):
        return
    # The stack is full of addresses; a longer minimum keeps them out.
    s = _strings(emu, data[start:], lo + start, minlen=5)
    if s["total"]:
        r["stack_strings"] = s
