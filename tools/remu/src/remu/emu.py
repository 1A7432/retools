"""One emulation run: set up memory and registers, interpret, describe the result."""

from __future__ import annotations

import bisect
import re
import time

from unicorn import (UC_ERR_EXCEPTION, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNMAPPED,
                     UC_ERR_INSN_INVALID, UC_ERR_READ_PROT, UC_ERR_READ_UNMAPPED,
                     UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNMAPPED, UC_HOOK_CODE, UC_HOOK_INSN,
                     UC_HOOK_INTR, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE,
                     UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED,
                     UC_PROT_ALL, Uc, UcError)
import unicorn.arm64_const as A
import unicorn.x86_const as X

from . import stubs as S
from .errors import RemuError
from .image import PAGE, page_down, page_up, parse_int
from .text import clip, guess_string
from .values import Builder, pointer_kind

MB = 1 << 20
DEFAULT_MAX_INSNS = 2_000_000
DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_CHARS = 6000

DEFAULT_INIT_MAX_INSNS = 2_000_000

REQUEST_KEYS = {
    "id", "func", "start", "until", "cc", "args", "regs", "mem", "imports", "replace",
    "ret", "ret_reg", "read", "regs_out", "max_insns", "timeout", "max_chars",
    "on_unknown_import", "map_on_demand", "trace", "acp", "heap_size", "stack_size", "fields",
    "init", "dump",
}
# Keys an init entry may carry. Everything about the machine (timeout, heap,
# acp, map_on_demand, on_unknown_import) comes from the request, and what an
# init call produced is read back with the request's own read.
INIT_KEYS = {"func", "args", "cc", "regs", "mem", "replace", "imports", "max_insns"}
IMPORT_OV_KEYS = {"ret", "nargs", "purge", "stub", "stop", "write"}
REPLACE_KEYS = {"ret", "nargs", "purge", "stub", "cc", "write", "stop", "name"}

# Preferred bases of the regions remu adds around the image. If the image
# occupies one, the region moves up in 16 MB steps; the reply's "layout"
# (and `remu info`) shows where everything went.
PREFERRED = [
    ("kuser", 0x7FFE0000),      # KUSER_SHARED_DATA, Windows images only
    ("stubs", 0x7FC00000),      # import stubs and the return sentinel
    ("env", 0x7FD00000),        # TEB, PEB, loader data, TLS, GDT
    ("stack", 0x7E000000),
    ("scratch", 0x20000000),    # the caller's: put mem blocks here with "addr"
    ("args", 0x21000000),       # remu's: auto-allocated argument buffers
    ("heap", 0x30000000),       # malloc/HeapAlloc/VirtualAlloc arena
]
STUB_SLOT = 16
DYNAMIC_SLOTS = 4096
ENV_SIZE = 0x20000

# Windows TEB/PEB field offsets for 32 and 64-bit
TEB = {
    4: dict(seh=0x0, stack_base=0x4, stack_limit=0x8, self=0x18, pid=0x20, tid=0x24,
            tls_ptr=0x2C, peb=0x30, last_error=0x34, tls_slots=0xE10),
    8: dict(seh=None, stack_base=0x8, stack_limit=0x10, self=0x30, pid=0x40, tid=0x48,
            tls_ptr=0x58, peb=0x60, last_error=0x68, tls_slots=0x1480),
}
PEB = {
    4: dict(image=0x8, ldr=0xC, heap=0x18, ncpu=0x64, os_major=0xA4, os_minor=0xA8, os_build=0xAC),
    8: dict(image=0x10, ldr=0x18, heap=0x30, ncpu=0xB8, os_major=0x118, os_minor=0x11C, os_build=0x120),
}
LDR_LISTS = {4: (0xC, 0x14, 0x1C), 8: (0x10, 0x20, 0x30)}
ENV_TEB, ENV_PEB, ENV_LDR, ENV_TLSARR, ENV_TLS, ENV_GDT = 0x0, 0x3000, 0x4000, 0x5000, 0x6000, 0x18000
ENV_ERRNO = 0x1F000

INTR_NAMES_X86 = {0: "divide_error", 1: "debug", 3: "breakpoint", 4: "overflow",
                  5: "bound", 6: "invalid_opcode", 13: "general_protection", 14: "page_fault",
                  0x29: "fastfail", 0x2C: "assertion", 0x2D: "debug_service",
                  0x2E: "syscall", 0x80: "syscall"}
GPRS = {
    "x86": ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"],
    "x64": ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
    "arm64": ["x%d" % i for i in range(29)] + ["x29", "x30", "sp"],
}


class StubFault(Exception):
    def __init__(self, kind, addr):
        super().__init__(kind)
        self.kind, self.addr = kind, addr


class ImportEntry:
    __slots__ = ("name", "module", "nargs", "purge", "slot", "stub", "override", "kind",
                 "cc", "addr")

    def __init__(self, name, module, nargs=None, purge=None, slot=None, kind="import"):
        self.name, self.module, self.nargs, self.purge = name, module, nargs, purge
        self.slot, self.kind = slot, kind
        self.stub = self.override = self.cc = self.addr = None

    @property
    def full(self):
        return "%s!%s" % (self.module, self.name) if self.module else self.name


class Heap:
    """A bump allocator: nothing is reused, so stale pointers stay inspectable."""

    def __init__(self, base, size):
        self.base, self.end = base, base + size
        self.cur = base + 0x10
        self.blocks = {}
        self.starts = []

    def alloc(self, n, align, who):
        n = max(int(n), 1)
        a = (self.cur + align - 1) & ~(align - 1)
        if a + n > self.end:
            return 0
        self.cur = a + n + 16      # small gap so overruns show up as separate writes
        self.blocks[a] = [n, who, False]
        self.starts.append(a)
        return a

    def block_at(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return None
        a = self.starts[i]
        n, who, freed = self.blocks[a]
        return (a, n, who, freed) if addr < a + max(n, 1) + 16 else None


class Call:
    """What a stub sees: its arguments and the emulated machine."""

    def __init__(self, emu, entry, nargs, cc):
        self.emu, self.entry, self.nargs, self.cc = emu, entry, nargs, cc
        self.name = entry.name
        self.word = emu.arch.word
        self.mask = emu.mask
        self.notes = []
        self.sp = emu.uc.reg_read(emu.arch.sp)

    def arg(self, i):
        return self.emu.stub_arg(self.cc, i, self.nargs, self.sp)

    def args(self, n):
        return [self.arg(i) for i in range(n)]

    def read(self, addr, n):
        return self.emu.read(addr, n)

    def write(self, addr, data):
        self.emu.write(addr, data)

    def r32(self, addr):
        return int.from_bytes(self.read(addr, 4), "little")

    def w32(self, addr, v):
        self.write(addr, (v & 0xFFFFFFFF).to_bytes(4, "little"))

    def w64(self, addr, v):
        self.write(addr, (v & (2 ** 64 - 1)).to_bytes(8, "little"))

    def rptr(self, addr):
        return int.from_bytes(self.read(addr, self.word), "little")

    def wptr(self, addr, v):
        self.write(addr, (v & self.mask).to_bytes(self.word, "little"))

    def cstr(self, addr, limit=None):
        return self.emu.read_cstr(addr, limit, 1)

    def wstr(self, addr, limit=None):
        return self.emu.read_cstr(addr, limit, 2)

    def alloc(self, n, align=16):
        if n > self.emu.heap.end - self.emu.heap.base:
            self.note("allocation of %#x bytes refused (heap arena is %#x)"
                      % (n, self.emu.heap.end - self.emu.heap.base))
            return 0
        a = self.emu.heap.alloc(n, align, self.name)
        if not a:
            self.emu.warn("heap arena exhausted; %s returned NULL (raise heap_size)" % self.name)
        return a

    def free(self, p):
        b = self.emu.heap.blocks.get(p)
        if b is not None:
            b[2] = True

    def size_of(self, p):
        b = self.emu.heap.blocks.get(p)
        return b[0] if b else 0

    def realloc(self, p, n):
        if not p:
            return self.alloc(n)
        new = self.alloc(n)
        if new:
            old = self.size_of(p)
            if old:
                self.write(new, self.read(p, min(old, n)))
            self.free(p)
        return new

    @staticmethod
    def signed(v, bits):
        v &= (1 << bits) - 1
        return v - (1 << bits) if v >> (bits - 1) else v

    def ret_signed(self, v):
        return v & self.mask

    def get_last_error(self):
        return self.emu.get_last_error()

    def set_last_error(self, v):
        self.emu.set_last_error(v)

    def note(self, msg):
        self.notes.append(msg)

    def stop(self, reason, detail):
        self.emu.stop_request = (reason, detail)


class Emu:
    def __init__(self, image, arch, req):
        self.image, self.arch = image, arch
        self.word = arch.word
        self.mask = (1 << arch.bits) - 1
        self.req = req
        self.warnings = []
        self._parse(req)

    # ------------------------------------------------------------------ request

    def _parse(self, req):
        if not isinstance(req, dict):
            raise RemuError("a request must be a JSON object", 'e.g. {"func": "0x401000", "args": [1]}')
        unknown = set(req) - REQUEST_KEYS
        if unknown:
            raise RemuError("unknown request keys: %s" % ", ".join(sorted(unknown)),
                            "valid keys: %s" % ", ".join(sorted(REQUEST_KEYS)))
        if ("func" in req) == ("start" in req):
            raise RemuError("give exactly one of func (call a function) or start (run a fragment)",
                            '{"func": "0x401000"} or {"start": "0x401010", "until": ["0x401040"]}')
        self.call_mode = "func" in req
        self.begin = parse_int(req["func"] if self.call_mode else req["start"],
                               "func" if self.call_mode else "start")
        until = req.get("until", [])
        if not isinstance(until, list):
            until = [until]
        self.until = {parse_int(u, "until") for u in until}
        self.cc = self.arch.cc(req.get("cc"))
        self.max_insns = parse_int(req.get("max_insns", DEFAULT_MAX_INSNS), "max_insns")
        self.timeout = float(req.get("timeout", DEFAULT_TIMEOUT))
        if self.max_insns <= 0 or self.timeout <= 0:
            raise RemuError("max_insns and timeout must be positive")
        self.max_chars = parse_int(req.get("max_chars", DEFAULT_MAX_CHARS), "max_chars")
        policy = req.get("on_unknown_import", "log")
        if policy not in ("log", "stop"):
            raise RemuError("on_unknown_import must be \"log\" or \"stop\"")
        self.stop_unknown = policy == "stop"
        mod = req.get("map_on_demand", False)
        self.on_demand_cap = 256 if mod is True else (0 if mod is False else parse_int(mod, "map_on_demand"))
        tr = req.get("trace", False)
        if isinstance(tr, dict):
            tr = tr.get("calls", 200)
        self.trace_cap = 200 if tr is True else (0 if tr is False else parse_int(tr, "trace"))
        self.acp = parse_int(req.get("acp", 1252), "acp")
        self.heap_size = page_up(parse_int(req.get("heap_size", 64 * MB), "heap_size"))
        self.stack_size = page_up(parse_int(req.get("stack_size", 1 * MB), "stack_size"))
        if not (16 * PAGE <= self.stack_size <= 64 * MB) or not (PAGE <= self.heap_size <= 1024 * MB):
            raise RemuError("stack_size must be 64 KB..64 MB and heap_size 4 KB..1 GB")
        for key, typ in (("args", list), ("mem", list), ("regs", dict), ("imports", dict),
                         ("replace", dict), ("read", list), ("regs_out", list)):
            if key in req and not isinstance(req[key], typ):
                raise RemuError("%s must be a JSON %s" % (key, "list" if typ is list else "object"))
        if (req.get("cc") or "").lower() == "fastcall" and self.arch.name == "x86" and \
                any(seg.name in (".itext", ".didata") for seg in self.image.segments):
            self.warn("this looks like a Delphi binary; with IDA's compiler set to Delphi, "
                      "__fastcall denotes the Borland register convention (EAX, EDX, ECX, rest "
                      "pushed left to right, callee pops), while remu's fastcall is Microsoft's "
                      "(ECX, EDX). Use cc \"delphi\" for Delphi register-convention code")
        self.ret_as = req.get("ret", "int")
        self.ret_reg = self.arch.reg(req["ret_reg"]) if "ret_reg" in req else self.arch.ret_reg
        top_imports, top_replace = req.get("imports") or {}, req.get("replace") or {}
        self._check_overrides(top_imports, top_replace, "")
        self.main_call = {
            "func": self.begin, "cc": self.cc, "max_insns": self.max_insns, "until": self.until,
            "args": req.get("args") or [], "regs": req.get("regs") or {},
            "mem": req.get("mem") or [], "imports": top_imports, "replace": top_replace,
            "prefix": "", "origin": None,
        }
        self.init = self._parse_init(req.get("init"), top_imports, top_replace)
        self.dump_dir = req.get("dump")
        if self.dump_dir is not None and (not isinstance(self.dump_dir, str) or not self.dump_dir):
            raise RemuError("dump must be a directory path (a string)",
                            '"dump": "/tmp/after-init" writes the writable memory there after the run')

    def _parse_init(self, init, top_imports, top_replace):
        """Normalise the init list into call dicts like main_call."""
        if init is None:
            return []
        example = '"init": ["0x401000", {"func": "0x401200", "args": [3, {"out": 8, "name": "key"}]}]'
        if not isinstance(init, list):
            raise RemuError("init must be a list of calls", example)
        calls = []
        for i, ent in enumerate(init):
            what = "init[%d]" % i
            if not isinstance(ent, dict):
                if isinstance(ent, bool) or not isinstance(ent, (int, str)):
                    raise RemuError("%s must be an address or an object with func" % what, example)
                ent = {"func": ent}
            bad = set(ent) - INIT_KEYS
            if bad:
                raise RemuError("%s: keys not allowed in an init entry: %s" % (what, ", ".join(sorted(bad))),
                                "an init entry takes %s. timeout, heap_size, acp, map_on_demand "
                                "and on_unknown_import come from the request; read init results "
                                "with the request's read (refs to init buffers work); fragments "
                                "(start/until) only for the main call" % ", ".join(sorted(INIT_KEYS)))
            if "func" not in ent:
                raise RemuError("%s needs func (the address to call)" % what, example)
            for key, typ in (("args", list), ("mem", list), ("regs", dict), ("imports", dict),
                             ("replace", dict)):
                if key in ent and not isinstance(ent[key], typ):
                    raise RemuError("%s.%s must be a JSON %s" % (what, key, "list" if typ is list else "object"))
            max_insns = parse_int(ent.get("max_insns", DEFAULT_INIT_MAX_INSNS), what + ".max_insns")
            if max_insns <= 0:
                raise RemuError("%s.max_insns must be positive" % what)
            self._check_overrides(ent.get("imports") or {}, ent.get("replace") or {}, what + ".")
            imports, replace = dict(top_imports), dict(top_replace)
            imports.update(ent.get("imports") or {})
            replace.update(ent.get("replace") or {})
            calls.append({
                "func": parse_int(ent["func"], what + ".func"), "cc": self.arch.cc(ent.get("cc")),
                "max_insns": max_insns, "until": set(),
                "args": ent.get("args") or [], "regs": ent.get("regs") or {},
                "mem": ent.get("mem") or [], "imports": imports, "replace": replace,
                "prefix": "init%d." % i, "origin": i,
            })
        return calls

    def _check_overrides(self, imports, replace, where):
        for k, v in imports.items():
            if not isinstance(v, dict):
                raise RemuError("%simports[%r] must be an object" % (where, k),
                                'e.g. {"GetTickCount": {"ret": 1000}}')
            bad = set(v) - IMPORT_OV_KEYS
            if bad:
                raise RemuError("%simports[%r]: unknown keys %s" % (where, k, ", ".join(sorted(bad))),
                                "use ret, nargs, purge, stub, stop, write")
            if "stub" in v and S.lookup(v["stub"]) is None:
                raise RemuError("%simports[%r]: no stub named %r" % (where, k, v["stub"]),
                                "run `remu stubs` for the list")
        for k, v in replace.items():
            parse_int(k, where + "replace key")
            if not isinstance(v, dict):
                raise RemuError("%sreplace[%r] must be an object" % (where, k),
                                'e.g. {"0x405000": {"stub": "malloc", "cc": "delphi"}}')
            bad = set(v) - REPLACE_KEYS
            if bad:
                raise RemuError("%sreplace[%r]: unknown keys %s" % (where, k, ", ".join(sorted(bad))))
            if "stub" in v and S.lookup(v["stub"]) is None:
                raise RemuError("%sreplace[%r]: no stub named %r" % (where, k, v["stub"]),
                                "run `remu stubs` for the list")
            self.arch.cc(v.get("cc"))

    # ------------------------------------------------------------------ layout

    def _layout(self):
        taken = [tuple(r) for r in self.image.regions]
        limit = 1 << 32 if self.word == 4 else 1 << 47
        sizes = {
            "kuser": PAGE, "env": ENV_SIZE, "stack": self.stack_size, "scratch": 16 * MB,
            "args": 16 * MB, "heap": self.heap_size,
            "stubs": page_up(STUB_SLOT * (len(self.image.imports) + DYNAMIC_SLOTS + 2)),
        }
        layout = {}
        for name, pref in PREFERRED:
            size = sizes[name]
            if name == "kuser":
                if self.image.filetype != "pe" or self._overlaps(pref, size, taken):
                    continue
                layout[name] = (pref, pref + size)
                taken.append(layout[name])
                continue
            a = pref
            while a + size <= limit and self._overlaps(a, size, taken):
                a += 16 * MB
            if a + size > limit:
                a = 0x01000000
                while a + size <= limit and self._overlaps(a, size, taken):
                    a += 16 * MB
            if a + size > limit:
                raise RemuError("no room for the %s region (%#x bytes)" % (name, size),
                                "lower heap_size or stack_size")
            layout[name] = (a, a + size)
            taken.append(layout[name])
        return layout

    @staticmethod
    def _overlaps(a, size, taken):
        return any(a < hi and lo < a + size for lo, hi in taken)

    def builtin_refs(self):
        L = self.layout
        refs = {"scratch": L["scratch"][0], "args_region": L["args"][0], "heap": L["heap"][0],
                "stack_top": L["stack"][1], "image": self.image.base, "sentinel": self.sentinel}
        if self.image.filetype == "pe":
            refs.update(teb=self.teb, peb=self.peb)
        return refs

    # ------------------------------------------------------------------ memory

    def is_mapped(self, addr, size=1):
        end = addr + max(size, 1)
        for lo, hi in self.mapped:
            if lo <= addr < hi:
                if end <= hi:
                    return True
                addr = hi
                if addr >= end:
                    return True
        return False

    def _readable_len(self, addr, want):
        n = 0
        while n < want:
            hit = None
            for lo, hi in self.mapped:
                if lo <= addr + n < hi:
                    hit = hi
                    break
            if hit is None:
                break
            n = min(want, hit - addr)
        return n

    def safe_read(self, addr, n):
        """Up to n bytes from addr, shorter if memory ends; never raises."""
        k = self._readable_len(addr, n)
        return bytes(self.uc.mem_read(addr, k)) if k > 0 else b""

    def read(self, addr, n):
        if n < 0 or n > 256 * MB:
            raise StubFault("read", addr)
        if n == 0:
            return b""
        if not self.is_mapped(addr, n):
            raise StubFault("read", addr if not self.is_mapped(addr) else addr + self._readable_len(addr, n))
        return bytes(self.uc.mem_read(addr, n))

    def write(self, addr, data):
        if not data:
            return
        if not self.is_mapped(addr, len(data)):
            raise StubFault("write", addr if not self.is_mapped(addr) else addr + self._readable_len(addr, len(data)))
        self.uc.mem_write(addr, bytes(data))
        # Stubs write through here, which the CPU write hook never sees. The stack
        # and the environment block are left out, as they are for CPU writes.
        if not (self.untracked[0][0] <= addr < self.untracked[0][1]
                or self.untracked[1][0] <= addr < self.untracked[1][1]):
            self._mark(addr, len(data))

    def read_cstr(self, addr, limit, unit):
        """Bytes up to (not including) the NUL unit; limit counts units."""
        cap = (limit if limit is not None else 1 << 20) * unit
        out = bytearray()
        while len(out) < cap:
            chunk_len = min(PAGE - ((addr + len(out)) & (PAGE - 1)), cap - len(out))
            chunk = self.read(addr + len(out), chunk_len)
            out += chunk
            for i in range(len(out) - len(chunk) - (len(out) - len(chunk)) % unit, len(out) - unit + 1, unit):
                if out[i:i + unit] == b"\0" * unit:
                    return bytes(out[:i])
        return bytes(out[:cap])

    def read_word(self, addr):
        return int.from_bytes(self.uc.mem_read(addr, self.word), "little")

    def write_word(self, addr, v):
        self.uc.mem_write(addr, (v & self.mask).to_bytes(self.word, "little"))

    def args_alloc(self, size, align):
        lo, hi = self.layout["args"]
        a = (self.args_cur + align - 1) & ~(align - 1)
        if a + size > hi:
            raise RemuError("argument buffers exceed the 16 MB args region",
                            "pass smaller buffers or place them with addr in scratch")
        self.args_cur = a + size + 16
        return a

    def _mark(self, addr, size):
        end = addr + size
        dirty = self.dirty
        while addr < end:
            p, off = addr >> 12, addr & 0xFFF
            n = min(end - addr, PAGE - off)
            d = dirty.get(p)
            if d is None:
                d = dirty[p] = bytearray(PAGE)
            d[off:off + n] = b"\x01" * n
            addr += n

    def warn(self, msg):
        self.warnings.append(msg)

    # ------------------------------------------------------------------ setup

    def setup(self):
        arch, image = self.arch, self.image
        self.layout = self._layout()
        uc = self.uc = Uc(arch.uc_arch, arch.uc_mode)
        if arch.name == "arm64":
            uc.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX)
        else:
            # Skylake gates SSSE3/SSE4/AES-NI on; CPUID is answered by remu below
            # so the code never sees AVX/AVX2, which the emulator cannot run.
            uc.ctl_set_cpu_model(X.UC_CPU_X86_SKYLAKE_CLIENT)
        self.mapped = []
        for lo, hi in image.regions:
            uc.mem_map(lo, hi - lo, UC_PROT_ALL)
            self.mapped.append((lo, hi))
        for seg in image.segments:
            if seg.data:
                uc.mem_write(seg.start, seg.data)
        for name, (lo, hi) in self.layout.items():
            uc.mem_map(lo, hi - lo, UC_PROT_ALL)
            self.mapped.append((lo, hi))
        self.mapped.sort()
        self.dirty = {}
        self.untracked = (self.layout["stack"], self.layout["env"])
        self.args_cur = self.layout["args"][0]
        self.heap = Heap(*self._span("heap"))
        self.heap_handle = self.layout["heap"][0]
        self.ticks = 0x10000
        self.rand_state = 1
        self.last_error = 0
        self.tls_values = {}
        self.tls_next = 0
        self.modules = {}
        self.stop_request = None
        self.sentinel = self.layout["stubs"][0]
        self._setup_env()
        self._setup_stubs()
        # One builder for the whole request: buffers named by an init call stay
        # referable by later calls and by the main call.
        self.builder = Builder(self)

    def _span(self, name):
        lo, hi = self.layout[name]
        return lo, hi - lo

    def _setup_env(self):
        uc, w = self.uc, self.word
        env = self.layout["env"][0]
        self.teb = self.peb = None
        self.errno_cell = env + ENV_ERRNO
        stack_lo, stack_hi = self.layout["stack"]
        if self.image.filetype == "pe":
            t, p = TEB[w], PEB[w]
            teb, peb, ldr = env + ENV_TEB, env + ENV_PEB, env + ENV_LDR
            self.teb, self.peb = teb, peb
            if t["seh"] is not None:
                self.write_word(teb + t["seh"], self.mask)   # end of the SEH chain
            self.write_word(teb + t["stack_base"], stack_hi)
            self.write_word(teb + t["stack_limit"], stack_lo)
            self.write_word(teb + t["self"], teb)
            self.write_word(teb + t["pid"], 0x1000)
            self.write_word(teb + t["tid"], 0x1004)
            self.write_word(teb + t["tls_ptr"], env + ENV_TLSARR)
            self.write_word(teb + t["peb"], peb)
            for i in range(64):   # every static TLS index points at one zeroed block
                self.write_word(env + ENV_TLSARR + i * w, env + ENV_TLS)
            self.write_word(peb + p["image"], self.image.base)
            self.write_word(peb + p["ldr"], ldr)
            self.write_word(peb + p["heap"], self.heap_handle)
            uc.mem_write(peb + p["ncpu"], (4).to_bytes(4, "little"))
            uc.mem_write(peb + p["os_major"], (10).to_bytes(4, "little"))
            uc.mem_write(peb + p["os_build"], (19045).to_bytes(2, "little"))
            uc.mem_write(ldr + 4, b"\x01")                 # Initialized
            for off in LDR_LISTS[w]:                       # empty module lists
                self.write_word(ldr + off, ldr + off)
                self.write_word(ldr + off + w, ldr + off)
            seg_base = teb
        else:
            tls = env + ENV_TLS
            self.write_word(tls, tls)  # %fs:0 / %gs:0 self pointer
            seg_base = tls
        if self.arch.name == "x86":
            self._gdt(env + ENV_GDT, seg_base)
        elif self.arch.name == "x64":
            uc.reg_write(X.UC_X86_REG_GS_BASE if self.image.filetype in ("pe", "macho")
                         else X.UC_X86_REG_FS_BASE, seg_base)
            if self.image.filetype == "macho":
                uc.reg_write(X.UC_X86_REG_FS_BASE, seg_base)
        else:
            if self.image.filetype == "pe":
                uc.reg_write(A.UC_ARM64_REG_X18, seg_base)
            uc.reg_write(A.UC_ARM64_REG_TPIDR_EL0, seg_base)
            uc.reg_write(A.UC_ARM64_REG_TPIDRRO_EL0, seg_base)

    def _gdt(self, gdt, base):
        def desc(base, limit, access, flags):
            d = limit & 0xFFFF
            d |= (base & 0xFFFFFF) << 16
            d |= (access & 0xFF) << 40
            d |= ((limit >> 16) & 0xF) << 48
            d |= (flags & 0xF) << 52
            d |= ((base >> 24) & 0xFF) << 56
            return d.to_bytes(8, "little")
        # Descriptor 2: flat data; 3: data based at the TEB/TLS block. Both read/write,
        # present, ring 0, 4 KB granular, 32-bit.
        self.uc.mem_write(gdt + 2 * 8, desc(0, 0xFFFFF, 0x93, 0xC))
        self.uc.mem_write(gdt + 3 * 8, desc(base, 0xFFFFF, 0x93, 0xC))
        self.uc.reg_write(X.UC_X86_REG_GDTR, (0, gdt, 8 * 8 - 1, 0))
        seg = X.UC_X86_REG_FS if self.image.filetype == "pe" else X.UC_X86_REG_GS
        self.uc.reg_write(seg, 3 << 3)
        # Loading a selector makes the emulator re-derive the stack size from SS's
        # cached descriptor, which is 16-bit until SS is loaded too (pushes would
        # then wrap at 64 KB). Load SS, DS and ES with the flat 32-bit descriptor.
        for r in (X.UC_X86_REG_SS, X.UC_X86_REG_DS, X.UC_X86_REG_ES):
            self.uc.reg_write(r, 2 << 3)

    def _setup_stubs(self):
        """Give every import a stub address; point IAT slots / extern symbols at it."""
        uc = self.uc
        trap = b"\xcc" if self.arch.name != "arm64" else b"\x00\x00\x20\xd4"   # int3 / brk #0
        lo, hi = self.layout["stubs"]
        uc.mem_write(lo, trap * ((hi - lo) // len(trap)))
        self.special = {self.sentinel: "sentinel"}
        self.stub_next = lo + STUB_SLOT
        self.by_slot = {}
        self.imports_seen = set()
        for slot, rec in sorted(self.image.imports.items()):
            e = ImportEntry(rec.get("name") or "?", rec.get("module") or "",
                            rec.get("nargs"), rec.get("purge"), slot)
            e.addr = self._new_stub(e)
            self.by_slot[slot] = e
            if self.is_mapped(slot, self.word):
                self.write_word(slot, e.addr)
            self.special.setdefault(slot, e)
        for thunk, target in self.image.thunks.items():
            e = self.by_slot.get(target)
            if e is not None:
                self.special[thunk] = e
        # What every call starts from; overrides, replacements and until
        # addresses are layered on per call by _apply_overrides.
        self.base_special = dict(self.special)

    def _apply_overrides(self, imports, replace, until):
        """Install one call's import overrides, function replacements and until addresses."""
        self.special = dict(self.base_special)
        self.ov_by_name, self.ov_by_addr = {}, {}
        for k, v in imports.items():
            try:
                self.ov_by_addr[parse_int(k)] = v
            except RemuError:
                self.ov_by_name[k] = v
        self.ov_used = set()
        for k, v in replace.items():
            addr = parse_int(k, "replace key")
            e = ImportEntry(v.get("name") or "sub_%X" % addr, "", v.get("nargs"), v.get("purge"),
                            kind="replace")
            e.cc = self.arch.cc(v.get("cc"))
            e.override = v
            e.addr = addr
            self.special[addr] = e
        for e in self.by_slot.values():
            e.override = None
            ov = self.ov_by_addr.get(e.slot) or self.ov_by_name.get(e.name)
            if ov is not None:
                e.override = ov
                self.ov_used.add(id(ov))
        for t, target in self.image.thunks.items():
            if t in self.ov_by_addr and target in self.by_slot:
                self.by_slot[target].override = self.ov_by_addr[t]
                self.ov_used.add(id(self.ov_by_addr[t]))
        for e in self.base_special.values():
            if isinstance(e, ImportEntry) and e.kind == "dynamic":
                e.override = self.ov_by_name.get(e.name)
                if e.override is not None:
                    self.ov_used.add(id(e.override))
        for a in until:
            self.special[a] = "until"

    def _new_stub(self, e):
        a = self.stub_next
        if a + STUB_SLOT > self.layout["stubs"][1]:
            return 0
        self.stub_next += STUB_SLOT
        self.special[a] = e
        return a

    def dynamic_import(self, name, module):
        """GetProcAddress result: a fresh stub that is intercepted like an import."""
        for e in self.special.values():
            if isinstance(e, ImportEntry) and e.kind == "dynamic" and e.name == name:
                return e.addr
        e = ImportEntry(name, module, kind="dynamic")
        ov = self.ov_by_name.get(name)
        if ov is not None:
            e.override = ov
            self.ov_used.add(id(ov))
        e.addr = self._new_stub(e)
        if not e.addr:
            self.warn("too many GetProcAddress results; returning NULL for %s" % name)
        else:
            self.base_special[e.addr] = e     # an init call's result stays callable later
        return e.addr

    def module_handle(self, name):
        key = name.lower().rsplit("\\", 1)[-1]
        if key and key == (self.image.meta.get("file") or "").lower():
            return self.image.base
        if key not in self.modules:
            # A fake, unmapped handle: code that parses the module's headers will fault.
            self.modules[key] = 0x6F000000 - 0x10000 * len(self.modules)
        return self.modules[key]

    def module_name(self, handle):
        for k, v in self.modules.items():
            if v == handle:
                return k
        return "image" if handle == self.image.base else "?"

    # ------------------------------------------------------------------ frame

    def _setup_frame(self, call):
        """Plan and write this call's buffers, then its arguments, stack frame and registers.
        Auto-generated buffer names of init calls carry an "initN." prefix."""
        arch, uc = self.arch, self.uc
        b = self.builder
        b.origin = call["origin"]
        pre = call["prefix"]
        mem = call["mem"]
        for i, spec in enumerate(mem):
            if not pointer_kind(spec):
                raise RemuError("%smem[%d] must be a buffer spec (bytes, str, wstr, out, dstr, "
                                "dastr or struct)" % (pre, i), 'e.g. {"name": "key", "bytes": "0011"}')
            b.plan(spec, spec.get("name") or "%smem%d" % (pre, i))
        args = call["args"]
        regs = call["regs"]
        for i, spec in enumerate(args):
            if pointer_kind(spec):
                b.plan(spec, "%sa%d" % (pre, i + 1))
        for name, spec in regs.items():
            if pointer_kind(spec):
                b.plan(spec, pre + name)
        for table in (call["imports"], call["replace"]):
            for k, ov in table.items():
                if isinstance(ov, dict) and pointer_kind(ov.get("ret")):
                    b.plan(ov["ret"], "%s%s.ret" % (pre, k))
        b.fill()

        stack_lo, stack_hi = self.layout["stack"]
        sp = stack_hi - 0x1000 - arch.ret_on_stack
        self.sp_entry = sp
        cc = call["cc"]
        positional = []
        for i, spec in enumerate(args):
            what = "%sa%d" % (pre, i + 1)
            if isinstance(spec, dict) and ("reg" in spec or "stack" in spec):
                if not (pointer_kind(spec) or "ref" in spec or "int" in spec):
                    raise RemuError("%s: an argument with reg/stack also needs a value "
                                    "(int, ref or buffer spec)" % what,
                                    'e.g. {"int": 5, "reg": "eax"} or {"str": "x", "stack": 0}')
                v = b.scalar(spec, what)
                if "reg" in spec:
                    uc.reg_write(arch.reg(spec["reg"]), v & self.reg_mask(spec["reg"]))
                else:
                    off = parse_int(spec["stack"], "%s.stack" % what)
                    self.write_word(sp + arch.ret_on_stack + off, v)
            else:
                positional.append((what, spec))
        if cc.regs is None and positional:
            raise RemuError("cc usercall: every argument needs \"reg\" or \"stack\"",
                            'e.g. {"int": 5, "reg": "eax"} or {"int": 5, "stack": 0}')
        nreg = len(cc.regs or [])
        on_stack = positional[nreg:]
        for (what, spec), r in zip(positional, cc.regs or []):
            uc.reg_write(arch.reg(r), b.scalar(spec, what) & self.mask)
        for j, (what, spec) in enumerate(on_stack):
            self.write_word(sp + arch.stack_slot(cc, len(on_stack), j), b.scalar(spec, what))
        if len(on_stack) * self.word > 0xC00:
            raise RemuError("too many stack arguments")
        if arch.name == "arm64":
            uc.reg_write(arch.lr, self.sentinel)
        else:
            self.write_word(sp, self.sentinel)
        uc.reg_write(arch.sp, sp)
        uc.reg_write(arch.fp, stack_hi - 0x100)
        for name, spec in regs.items():
            uc.reg_write(arch.reg(name), b.scalar(spec, pre + name) & self.reg_mask(name))

    def _fresh_cpu(self):
        """Between calls: zero the general registers and the stack, so each call
        starts with a clean frame (memory elsewhere carries over)."""
        for name in GPRS[self.arch.name]:
            self.uc.reg_write(self.arch.reg(name), 0)
        lo, hi = self.layout["stack"]
        self.uc.mem_write(lo, bytes(hi - lo))

    def reg_mask(self, name):
        # vector registers (xmm0, q0, v0) take 128-bit values; everything else is word-sized
        n = name.strip().lower()
        if n.startswith(("xmm", "q", "v")) and n[-1].isdigit():
            return (1 << 128) - 1
        return self.mask

    def stub_arg(self, cc, i, nargs, sp):
        regs = cc.regs or []
        if i < len(regs):
            return self.uc.reg_read(self.arch.reg(regs[i])) & self.mask
        j = i - len(regs)
        if cc.stack_reversed and nargs is not None:
            j = (nargs - len(regs)) - 1 - j
        off = self.arch.ret_on_stack + cc.shadow + j * self.word
        try:
            return int.from_bytes(self.read(sp + off, self.word), "little")
        except StubFault:
            return 0

    # ------------------------------------------------------------------ hooks

    def _install_hooks(self):
        uc = self.uc
        uc.hook_add(UC_HOOK_CODE, self._hook_code_trace if self.trace_cap else self._hook_code)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)
        uc.hook_add(UC_HOOK_INTR, self._hook_intr)
        tracked = [tuple(r) for r in self.image.regions] + [
            self.layout[k] for k in ("scratch", "args", "heap")]
        for lo, hi in tracked:
            uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_write, None, lo, hi - 1)
        if self.arch.name != "arm64":
            uc.hook_add(UC_HOOK_INSN, self._hook_cpuid, None, 1, 0, X.UC_X86_INS_CPUID)
            if self.arch.name == "x64":
                uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, X.UC_X86_INS_SYSCALL)
            else:
                uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, X.UC_X86_INS_SYSENTER)

    def _stop(self, reason, at, undo=True, **detail):
        if self.reason is None:
            self.reason, self.stop_at, self.stop_detail = reason, at, detail
            if undo:
                self.n -= 1     # the instruction at `at` did not execute
        self.uc.emu_stop()

    def _hook_code(self, uc, addr, size, _):
        self.prev = self.cur
        self.cur = addr
        n = self.n = self.n + 1
        if n > self.max_insns:
            self._stop("max_insns", addr)
        elif not n & 0xFFF and time.monotonic() > self.deadline:
            self._stop("timeout", addr)
        elif addr in self.special:
            self._special(addr, self.special[addr])

    def _hook_code_trace(self, uc, addr, size, _):
        if addr != self.next_seq and self.n:
            self._trace_transfer(addr)
        self.next_seq = addr + size
        self._hook_code(uc, addr, size, _)

    def _trace_transfer(self, addr):
        ret = self.next_seq
        if self.arch.name == "arm64":
            called = self.uc.reg_read(A.UC_ARM64_REG_X30) == ret
        else:
            try:
                called = self.read_word(self.uc.reg_read(self.arch.sp)) == ret
            except UcError:
                called = False
        if not called:
            return
        self.trace_total += 1
        e = self.special.get(addr)
        name = e.full if isinstance(e, ImportEntry) else None
        if self.trace and self.trace[-1][0] == addr and self.trace[-1][1] == self.cur:
            self.trace[-1][2] += 1
        elif len(self.trace) < self.trace_cap:
            self.trace.append([addr, self.cur, 1, name])
        else:
            self.trace_dropped += 1

    def _special(self, addr, e):
        if e == "sentinel":
            self._stop("returned", self.prev, undo=True)
        elif e == "until":
            if self.n > 1:
                self._stop("until", addr)
        else:
            try:
                self._do_import(e, addr)
            except RemuError:
                raise
            except Exception as exc:  # noqa: BLE001 - a stub bug ends the run, not the process
                import traceback
                traceback.print_exc()
                self._stop("error", addr, undo=False, fn=e.full,
                           detail="the %s model failed: %s: %s" % (e.name, type(exc).__name__, exc))

    def _hook_write(self, uc, access, addr, size, value, _):
        p, off = addr >> 12, addr & 0xFFF
        d = self.dirty.get(p)
        if d is None:
            d = self.dirty[p] = bytearray(PAGE)
        if off + size <= PAGE:
            d[off:off + size] = b"\x01" * size
        else:
            self._mark(addr, size)

    def _hook_unmapped(self, uc, access, addr, size, value, _):
        kind = {UC_MEM_READ_UNMAPPED: "read", UC_MEM_WRITE_UNMAPPED: "write",
                UC_MEM_FETCH_UNMAPPED: "fetch"}.get(access, "access")
        if kind in ("read", "write") and self.on_demand_left > 0 and addr >= 0x10000 \
                and addr + size <= self.mask + 1:
            lo, hi = page_down(addr), page_up(addr + size)
            try:
                uc.mem_map(lo, hi - lo, UC_PROT_ALL)
            except UcError:
                pass
            else:
                self.on_demand_left -= (hi - lo) // PAGE
                self.on_demand.append((lo, hi))
                self.on_demand_all.append((lo, hi))
                self.mapped.append((lo, hi))
                self.mapped.sort()
                try:
                    uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_write, None, lo, hi - 1)
                except UcError:
                    self.warn("writes to on-demand page %#x are not tracked" % lo)
                if kind == "write":
                    self._mark(addr, size)
                return True
        if self.reason is None:
            self.reason = "unmapped_" + kind
            self.stop_at = addr if kind == "fetch" else self.cur
            if kind == "fetch":
                # the fetch fails before the code hook runs: nothing to undo
                self.stop_detail = {"from": self.cur}
            else:
                self.stop_detail = {"addr": addr, "size": size}
                self.n -= 1
        return False

    def _hook_intr(self, uc, intno, _):
        at = self.cur
        if self.arch.name == "arm64":
            if intno == 2:
                self._stop("syscall", at, undo=False, intno=intno)
            elif intno == 1:
                self._stop("invalid_insn", at, intno=intno)
            else:
                self._stop("interrupt", at, undo=False, intno=intno,
                           name={7: "breakpoint"}.get(intno, "exception %d" % intno))
            return
        name = INTR_NAMES_X86.get(intno, "int %#x" % intno)
        if name == "syscall":
            self._stop("syscall", at, undo=False, intno=intno)
        else:
            self._stop("interrupt", at, undo=False, intno=intno, name=name)

    def _hook_syscall(self, uc, _):
        self._stop("syscall", self.cur, undo=False)

    def _hook_cpuid(self, uc, _):
        leaf = uc.reg_read(X.UC_X86_REG_EAX) & 0xFFFFFFFF
        a = b = c = d = 0
        if leaf == 0:
            a, b, d, c = 7, 0x756E6547, 0x49656E69, 0x6C65746E      # GenuineIntel
        elif leaf == 1:
            a, b = 0x000306C3, 0x00010800
            c = 0x02980203        # SSE3 PCLMUL SSSE3 SSE4.1 SSE4.2 POPCNT AES; no AVX/XSAVE
            d = 0x07808111        # FPU TSC CX8 CMOV MMX FXSR SSE SSE2
        elif leaf == 0x80000000:
            a = 0x80000001
        elif leaf == 0x80000001:
            c = 1
            d = (1 << 29 | 1 << 20 | 1 << 11) if self.arch.name == "x64" else 1 << 20
        for reg, v in ((X.UC_X86_REG_RAX, a), (X.UC_X86_REG_RBX, b), (X.UC_X86_REG_RCX, c),
                       (X.UC_X86_REG_RDX, d)) if self.arch.name == "x64" else (
                (X.UC_X86_REG_EAX, a), (X.UC_X86_REG_EBX, b), (X.UC_X86_REG_ECX, c),
                (X.UC_X86_REG_EDX, d)):
            uc.reg_write(reg, v)
        return 1  # skip the emulator's own CPUID

    # ------------------------------------------------------------------ imports

    def _do_import(self, e, addr):
        arch, uc = self.arch, self.uc
        ov = e.override or {}
        if e.kind == "replace":
            cc = e.cc
        elif arch.name == "x86":
            cc = arch.ccs["stdcall"]
        else:
            cc = arch.cc(None)
        stubdef = S.lookup(ov["stub"]) if "stub" in ov else (
            None if e.kind == "replace" else S.lookup(e.name))
        nargs = ov.get("nargs", e.nargs)
        if nargs is None and stubdef is not None:
            nargs = stubdef.nargs
        ret_to = (uc.reg_read(arch.lr) if arch.name == "arm64"
                  else self.read_word(uc.reg_read(arch.sp)))
        call = Call(self, e, nargs, cc)
        shown = nargs if nargs is not None else 4
        rec = {"fn": e.full, "from": "%#x" % ret_to,
               "args": [self._render_arg(call.arg(i), e.name) for i in range(min(shown, 16))]}
        if nargs is None:
            rec["nargs"] = "unknown; first 4 slots shown"
        if stubdef is not None and stubdef.variadic:
            rec["variadic"] = True
        self.import_total += 1
        self.import_counts[e.full] = self.import_counts.get(e.full, 0) + 1
        if ov.get("stop"):
            rec["stopped"] = True
            self._log_call(rec)
            self._stop("import_stop", addr, undo=False, fn=e.full, ret_to="%#x" % ret_to)
            return
        if stubdef is None and "ret" not in ov and e.kind != "replace" and self.stop_unknown:
            rec["stopped"] = True
            self._log_call(rec)
            self._stop("unknown_import", addr, undo=False, fn=e.full, ret_to="%#x" % ret_to)
            return
        value = 0
        try:
            if "ret" in ov:
                value = self.builder.scalar(ov["ret"], "%s.ret" % e.name)
                rec["model"] = "override"
            elif stubdef is not None:
                value = stubdef.fn(call) or 0
                rec["model"] = "stub"
            else:
                rec["model"] = "none, returned 0"
            for w in ov.get("write") or []:
                self._override_write(call, w, e.name)
        except StubFault as f:
            rec["fault"] = "%s at %#x" % (f.kind, f.addr)
            self._log_call(rec)
            self._stop("unmapped_" + f.kind, addr, undo=False, addr=f.addr,
                       fn=e.full, note="inside the %s stub" % e.name)
            return
        if call.notes:
            rec["notes"] = call.notes
        purge = self._purge(e, ov, stubdef, cc, nargs, rec)
        rec["ret"] = "%#x" % (value & self.mask)
        self._log_call(rec)
        if self.stop_request:
            reason, detail = self.stop_request
            self._stop(reason, addr, undo=False, fn=e.full, detail=detail, ret_to="%#x" % ret_to)
            return
        if arch.name != "arm64":
            sp = uc.reg_read(arch.sp)
            uc.reg_write(arch.sp, sp + self.word + purge)
        uc.reg_write(arch.ret_reg, value & self.mask)
        if arch.name == "x86" and value >> 32:
            uc.reg_write(X.UC_X86_REG_EDX, (value >> 32) & 0xFFFFFFFF)
        uc.reg_write(arch.pc, ret_to)
        if ret_to == self.sentinel:
            self._stop("returned", addr, undo=False)

    def _purge(self, e, ov, stubdef, cc, nargs, rec):
        if self.arch.name != "x86":
            return 0
        if "purge" in ov:
            return parse_int(ov["purge"], "purge")
        if e.kind == "replace":
            if not cc.callee_pops or nargs is None:
                return 0
            return max(0, nargs - len(cc.regs or [])) * 4
        if e.purge is not None:
            return int(e.purge)
        if stubdef is not None:
            return 4 * stubdef.nargs if stubdef.kind == "w" else 0
        if "nargs" in ov and not _is_crt(e.module):
            return 4 * int(ov["nargs"])
        if not _is_crt(e.module):
            key = "purge:" + e.full
            if key not in self.warned:
                self.warned.add(key)
                self.warn("%s: no prototype, so the stack clean-up is unknown and was taken as 0; "
                          "if it is stdcall, pass imports {\"%s\": {\"nargs\": N}}" % (e.full, e.name))
            rec["purge"] = "unknown, assumed 0"
        return 0

    def _override_write(self, call, w, name):
        if not isinstance(w, dict) or "arg" not in w:
            raise RemuError("%s.write items need \"arg\" (argument index, 0-based) plus one field "
                            "like {\"u32\": 5} or {\"wstr\": \"text\"}" % name)
        item = {k: v for k, v in w.items() if k not in ("arg", "off")}
        target = call.arg(parse_int(w["arg"], "write.arg")) + parse_int(w.get("off", 0), "write.off")
        size = self.builder._item(item, 0, name, None)
        buf = bytearray(size)
        self.builder._item(item, 0, name, buf)
        self.write(target, bytes(buf))

    def _log_call(self, rec):
        last = self.calls[-1] if self.calls else None
        if last is not None and all(last.get(k) == rec.get(k) for k in ("fn", "from", "args", "ret")) \
                and set(last) - {"n"} == set(rec):
            last["n"] = last.get("n", 1) + 1
        elif len(self.calls) < 400:
            self.calls.append(rec)
        else:
            self.calls_dropped += 1

    def _render_arg(self, v, fname):
        s = "%#x" % v
        if v >= 0x10000 and self.is_mapped(v):
            g = guess_string(self.safe_read(v, 160))
            if g:
                kind, text = g
                s += " %s\"%s\"" % ("L" if kind == "w" else "", clip(text, 60))
        return s

    def get_last_error(self):
        if self.teb is not None:
            return int.from_bytes(self.uc.mem_read(self.teb + TEB[self.word]["last_error"], 4), "little")
        return self.last_error

    def set_last_error(self, v):
        if self.teb is not None:
            self.uc.mem_write(self.teb + TEB[self.word]["last_error"], (v & 0xFFFFFFFF).to_bytes(4, "little"))
        self.last_error = v

    def tls_alloc(self):
        i = self.tls_next
        self.tls_next += 1
        return i

    def tls_get(self, i):
        if self.teb is not None and i < 64:
            return self.read_word(self.teb + TEB[self.word]["tls_slots"] + i * self.word)
        return self.tls_values.get(i, 0)

    def tls_set(self, i, v):
        if self.teb is not None and i < 64:
            self.write_word(self.teb + TEB[self.word]["tls_slots"] + i * self.word, v)
        self.tls_values[i] = v
        return 1

    def tick(self):
        self.ticks += 16
        return self.ticks

    # ------------------------------------------------------------------ run

    def run(self):
        try:
            return self._run()
        finally:
            self.close()

    def _run(self):
        t0 = time.monotonic()
        self.setup()
        self.warned = set()
        self.on_demand_left, self.on_demand, self.on_demand_all = self.on_demand_cap, [], []
        self.init_results = []
        for i, call in enumerate(self.init + [self.main_call]):
            if not self.is_mapped(call["func"]):
                raise RemuError("%s%#x is not in the image" % (
                                    "init[%d]: " % i if i < len(self.init) else "", call["func"]),
                                "check the address; segments span %s" % ", ".join(
                                    "%#x-%#x" % r for r in self.image.regions[:6]))
        self._install_hooks()
        self.deadline = time.monotonic() + self.timeout
        from .report import build_init_failure, build_reply
        for i, call in enumerate(self.init):
            nwarn = len(self.warnings)
            self._call(call, fresh=i > 0)
            self.warnings[nwarn:] = ["init[%d]: %s" % (i, w) for w in self.warnings[nwarn:]]
            rec = {"func": "%#x" % call["func"], "stop": self.reason}
            if self.reason == "returned":
                rec["ret"] = "%#x" % (self.uc.reg_read(self.arch.ret_reg) & self.mask)
            rec["insns"] = self.n
            self.init_results.append(rec)
            if self.reason != "returned":
                self.elapsed = time.monotonic() - t0
                self._dump()
                return build_init_failure(self, i)
        # The main call is described against the state init left behind.
        for blk in self.builder.blocks:
            blk.initial = self.safe_read(blk.addr, blk.size)
        self._call(self.main_call, fresh=bool(self.init))
        self.elapsed = time.monotonic() - t0
        self._dump()
        return build_reply(self)

    def _call(self, call, fresh):
        """Run one call (an init entry or the main request) in the shared machine."""
        self.begin, self.cc, self.max_insns = call["func"], call["cc"], call["max_insns"]
        self.until = call["until"]
        self._apply_overrides(call["imports"], call["replace"], self.until)
        if fresh:
            self._fresh_cpu()
        self.dirty = {}
        self.stop_request = None
        self._setup_frame(call)
        self.reason = None
        self.stop_at = self.begin
        self.stop_detail = {}
        self.n = 0
        self.cur = self.prev = self.begin
        self.next_seq = self.begin
        self.trace, self.trace_total, self.trace_dropped = [], 0, 0
        self.calls, self.calls_dropped = [], 0
        self.import_total, self.import_counts = 0, {}
        self.on_demand = []
        left = self.deadline - time.monotonic()
        if left <= 0:
            self.reason, self.stop_at = "timeout", self.begin
            return
        uc_error = None
        try:
            self.uc.emu_start(self.begin, self.sentinel, timeout=int((left + 1) * 1e6), count=0)
        except UcError as exc:
            uc_error = exc
        pc = self.uc.reg_read(self.arch.pc)
        if self.reason is None:
            if uc_error is not None:
                self._classify_error(uc_error, pc)
            elif pc == self.sentinel:
                self.reason, self.stop_at = "returned", self.cur
            elif self.arch.name != "arm64" and self.safe_read(self.cur, 1) == b"\xf4":
                self.reason, self.stop_at = "halt", self.cur    # hlt ends emulation
            elif time.monotonic() >= self.deadline:
                self.reason, self.stop_at = "timeout", pc
            else:
                self.reason, self.stop_at = "stopped", pc

    def _dump(self):
        """Write the memory the run can have changed to self.dump_dir (request key
        "dump"): every image segment whose bytes differ from the image, the used
        part of the heap, the used part of the args region and any named block
        placed elsewhere, one .bin file each, described by dump.json."""
        self.dump_info = None
        if not self.dump_dir:
            return
        import json
        import os
        try:
            os.makedirs(self.dump_dir, exist_ok=True)
        except OSError as exc:
            self.warn("dump: cannot create %s: %s" % (self.dump_dir, exc.strerror))
            return
        regions = []

        def changed(cur, orig, base):
            runs, n, i = [], len(cur), 0
            while i < n:
                j = min(n, i + PAGE)
                if cur[i:j] != orig[i:j]:
                    k = i
                    while k < j:
                        if cur[k] != orig[k]:
                            e = k + 1
                            while e < j and cur[e] != orig[e]:
                                e += 1
                            if runs and runs[-1][1] == base + k:
                                runs[-1][1] = base + e
                            else:
                                runs.append([base + k, base + e])
                            k = e
                        else:
                            k += 1
                i = j
            return runs

        def add(kind, name, start, cur, orig, **extra):
            runs = changed(cur, orig, start)
            if kind == "segment" and not runs:
                return
            fname = "r%d.bin" % len(regions)
            with open(os.path.join(self.dump_dir, fname), "wb") as fh:
                fh.write(cur)
            rec = {"kind": kind, "name": name, "start": "%#x" % start, "size": len(cur),
                   "file": fname, "changed": [["%#x" % a, "%#x" % b] for a, b in runs]}
            rec.update(extra)
            regions.append(rec)

        for seg in self.image.segments:
            if seg.extern or seg.end <= seg.start:
                continue
            size = seg.end - seg.start
            cur = self.safe_read(seg.start, size)
            orig = (seg.data + bytes(size))[:len(cur)]
            add("segment", seg.name, seg.start, cur, orig)
        heap = self.heap
        if heap.cur > heap.base + 0x10:
            cur = self.safe_read(heap.base, heap.cur - heap.base)
            blocks = [{"addr": "%#x" % a, "size": heap.blocks[a][0], "from": heap.blocks[a][1]}
                      for a in heap.starts[:1000]]
            add("heap", "heap", heap.base, cur, bytes(len(cur)), blocks=blocks)
        lo, _ = self.layout["args"]
        named = [{"name": b.name, "addr": "%#x" % b.addr, "size": b.size} for b in self.builder.blocks]
        if self.args_cur > lo:
            cur = self.safe_read(lo, self.args_cur - lo)
            add("args", "args", lo, cur, bytes(len(cur)),
                buffers=[b for b, blk in zip(named, self.builder.blocks)
                         if lo <= blk.addr < self.args_cur])
        alo, ahi = self.layout["args"]
        for b, blk in zip(named, self.builder.blocks):
            if not alo <= blk.addr < ahi and self.image.segment_at(blk.addr) is None and blk.size:
                cur = self.safe_read(blk.addr, blk.size)
                add("buffer", blk.name, blk.addr, cur, bytes(len(cur)))
        total = sum(r["size"] for r in regions)
        meta = {"format": 1, "regions": regions, "bytes": total,
                "init": [ "%#x" % c["func"] for c in self.init], "func": "%#x" % self.main_call["func"]}
        with open(os.path.join(self.dump_dir, "dump.json"), "w") as fh:
            json.dump(meta, fh)
        self.dump_info = {"dir": self.dump_dir, "regions": len(regions), "bytes": total,
                          "changed": sum(int(b, 16) - int(a, 16) for r in regions for a, b in r["changed"])}

    def close(self):
        """Drop the emulator now: its hooks point back at us, so leaving it to the
        cycle collector would keep every request's memory alive during a batch."""
        uc, self.uc = getattr(self, "uc", None), None
        # The binding frees the engine from a weakref finalizer; run it now
        # (uc_close) instead of waiting for the cycle collector.
        fin = getattr(uc, "_Uc__finalizer", None)
        if fin is not None:
            fin()

    def _classify_error(self, exc, pc):
        err = exc.errno
        if err == UC_ERR_INSN_INVALID:
            self.reason, self.stop_at = "invalid_insn", pc
            self.n -= 1
        elif err in (UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_FETCH_UNMAPPED):
            self.reason = {UC_ERR_READ_UNMAPPED: "unmapped_read", UC_ERR_WRITE_UNMAPPED: "unmapped_write",
                           UC_ERR_FETCH_UNMAPPED: "unmapped_fetch"}[err]
            self.stop_at = pc
        elif err in (UC_ERR_READ_PROT, UC_ERR_WRITE_PROT, UC_ERR_FETCH_PROT):
            self.reason, self.stop_at = "protected_access", pc
        elif err == UC_ERR_EXCEPTION:
            self.reason, self.stop_at = "cpu_exception", pc
            self.stop_detail = {"detail": str(exc)}
        else:
            self.reason, self.stop_at = "error", pc
            self.stop_detail = {"detail": str(exc)}


def _is_crt(module):
    m = (module or "").lower()
    return bool(re.match(r"(msvcr|msvcp|ucrtbase|vcruntime|api-ms-win-crt|libc|libsystem|crtdll|msvcrt)", m))
