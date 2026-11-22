"""rekit emulation bridge: export the database as a memory image and hand
function-level emulation requests to the out-of-process `remu` tool.

Nothing here writes to the IDA database. The image is a snapshot written to a
cache directory; emulation happens in a separate process (Unicorn), so the
code under analysis is interpreted there and never runs natively.

Image format 1 (a directory):
    meta.json     see export() for the fields
    seg<N>.bin    initialised bytes of segment N from its start; the emulator
                  zero-fills the rest of the segment
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_ida
import ida_nalt
import ida_segment
import ida_typeinf

FORMAT = 1
# Bumped whenever the exporter's output changes without a format change, so
# that images cached by an older exporter are rebuilt (2: segments lost their
# final byte before).
REV = 2
TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
REMU = os.environ.get("REKIT_REMU") or os.path.join(TOOLS, "remu", "remu")
IMAGES = os.environ.get("REKIT_IMAGES") or os.path.join(
    os.path.dirname(TOOLS), "tmp", "rekit-images")
MAX_BYTES = 768 << 20
BADADDR = idaapi.BADADDR

_FILETYPES = {ida_ida.f_PE: "pe", ida_ida.f_ELF: "elf", ida_ida.f_MACHO: "macho"}


class EmuError(Exception):
    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.msg, self.hint = msg, hint


def _arch():
    proc = ida_ida.inf_get_procname().lower()
    is64 = ida_ida.inf_is_64bit()
    if proc == "metapc":
        return "x64" if is64 else "x86"
    if proc.startswith("arm"):
        return "arm64" if is64 else "arm"
    return proc


def _sha():
    raw = ida_nalt.retrieve_input_file_sha256()
    return raw.hex() if isinstance(raw, (bytes, bytearray)) else ""


def image_dir():
    name = ida_nalt.get_root_filename() or "image"
    return os.path.join(IMAGES, "%s.%s" % (name, (_sha() or "nohash")[:12]))


def _imports():
    out = {}
    for i in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(i) or ""

        def visit(ea, name, ordinal, module=module):
            rec = {"name": name or "ord_%d" % ordinal, "module": module}
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, ea):
                if tif.is_ptr():
                    tif = tif.get_pointed_object()
                if tif.is_func():
                    rec["nargs"] = tif.get_nargs()
                    rec["purge"] = tif.calc_purged_bytes()
            out["%#x" % ea] = rec
            return True

        ida_nalt.enum_import_names(i, visit)
    return out


def _thunks(imports):
    out = {}
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f.flags & ida_funcs.FUNC_THUNK:
            continue
        res = ida_funcs.calc_thunk_func_target(f)
        target = res[0] if isinstance(res, (tuple, list)) else res
        if target == BADADDR:
            continue
        key = "%#x" % target
        if key in imports:
            out["%#x" % ea] = key
    return out


def export(refresh=False):
    """Write the image if it is missing (or refresh=True); return its summary."""
    path = image_dir()
    meta_path = os.path.join(path, "meta.json")
    if os.path.exists(meta_path) and not refresh:
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta.get("format") == FORMAT and meta.get("rev") == REV:
            return {"dir": path, "cached": True, "segments": len(meta["segments"]),
                    "bytes": meta["bytes"], "exported": meta["exported"]}
    plan, total = [], 0
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        # prev_inited() looks strictly below ea - 1, so asking from end_ea skips
        # the segment's final byte; test that byte directly first.
        if ida_bytes.is_loaded(seg.end_ea - 1):
            last = seg.end_ea - 1
        else:
            last = ida_bytes.prev_inited(seg.end_ea - 1, seg.start_ea)
            if last != BADADDR and ida_bytes.is_loaded(last + 1):
                last += 1
        if ida_bytes.is_loaded(seg.start_ea):
            last = max(last, seg.start_ea) if last != BADADDR else seg.start_ea
        size = 0 if (last == BADADDR or seg.type == ida_segment.SEG_XTRN) \
            else last + 1 - seg.start_ea
        plan.append((seg, size))
        total += size
    if total > MAX_BYTES:
        raise EmuError("image would be %d MB, over the %d MB limit"
                       % (total >> 20, MAX_BYTES >> 20),
                       "this database is too large to snapshot for emulation")
    os.makedirs(path, exist_ok=True)
    segments = []
    for n, (seg, size) in enumerate(plan):
        rec = {"name": ida_segment.get_segm_name(seg),
               "start": "%#x" % seg.start_ea, "end": "%#x" % seg.end_ea,
               "perm": "".join(c if seg.perm & bit else "-"
                               for c, bit in (("r", 4), ("w", 2), ("x", 1))),
               "extern": seg.type == ida_segment.SEG_XTRN, "file": None, "size": size}
        if size:
            data = ida_bytes.get_bytes(seg.start_ea, size) or b""
            rec["file"] = "seg%d.bin" % n
            rec["size"] = len(data)
            with open(os.path.join(path, rec["file"]), "wb") as fh:
                fh.write(data)
        segments.append(rec)
    imports = _imports()
    meta = {
        "format": FORMAT,
        "rev": REV,
        "file": ida_nalt.get_root_filename(),
        "sha256": _sha(),
        "arch": _arch(),
        "bits": 64 if ida_ida.inf_is_64bit() else 32,
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "filetype": _FILETYPES.get(ida_ida.inf_get_filetype(), "other"),
        "base": "%#x" % ida_nalt.get_imagebase(),
        "entry": "%#x" % ida_ida.inf_get_start_ea(),
        "segments": segments,
        "imports": imports,
        "thunks": _thunks(imports),
        "bytes": total,
        "exported": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    tmp = meta_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh)
    os.replace(tmp, meta_path)
    return {"dir": path, "cached": False, "segments": len(segments),
            "bytes": total, "exported": meta["exported"]}


def run(request, timeout=30, refresh=False):
    """Export if needed, run one remu request, return its JSON reply."""
    if not os.path.exists(REMU):
        raise EmuError("the remu emulator is not installed at %s" % REMU,
                       "emulation is unavailable; analyse statically instead")
    image = export(refresh)
    try:
        proc = subprocess.run([REMU, "call", "--image", image["dir"]],
                              input=json.dumps(request), capture_output=True,
                              text=True, timeout=timeout + 15)
    except subprocess.TimeoutExpired:
        raise EmuError("emulation did not finish within %ds" % (timeout + 15),
                       "lower max_insns or emulate a smaller piece")
    text = proc.stdout.strip()
    try:
        reply = json.loads(text)
    except ValueError:
        tail = (proc.stderr or text or "no output").strip()[-400:]
        raise EmuError("remu failed (exit %d): %s" % (proc.returncode, tail))
    if not isinstance(reply, dict):
        raise EmuError("remu returned something that is not a JSON object")
    return reply
