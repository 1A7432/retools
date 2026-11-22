"""Per-architecture facts: registers, calling conventions, how a stub returns."""

from __future__ import annotations

from unicorn import UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_MODE_ARM
import unicorn.arm64_const as A
import unicorn.x86_const as X

from .errors import RemuError


class CC:
    """A calling convention: which registers carry the first arguments and
    where the remaining ones go on the stack."""

    def __init__(self, name, regs, stack_reversed=False, shadow=0, callee_pops=False):
        self.name = name
        self.regs = regs                    # registers for positional args, in order
        self.stack_reversed = stack_reversed  # Delphi/Pascal: first stack arg pushed first
        self.shadow = shadow                # bytes of home space above the return address
        self.callee_pops = callee_pops


def _regmap(module, prefix):
    out = {}
    for k in dir(module):
        if k.startswith(prefix) and not k.endswith("_ENDING"):
            out[k[len(prefix):].lower()] = getattr(module, k)
    return out


class Arch:
    name = ""
    bits = 0

    @property
    def word(self):
        return self.bits // 8

    def reg(self, name):
        key = name.strip().lower()
        key = self.aliases.get(key, key)
        if key not in self.regs:
            raise RemuError("unknown %s register %r" % (self.name, name),
                            "use names like %s" % ", ".join(self.example_regs))
        return self.regs[key]

    def cc(self, name):
        if name is None:
            return self.ccs[self.default_cc]
        key = self.cc_aliases.get(name.lower(), name.lower())
        if key not in self.ccs:
            raise RemuError("calling convention %r is not available for %s" % (name, self.name),
                            "choose one of: %s" % ", ".join(sorted(self.ccs)))
        return self.ccs[key]

    def stack_slot(self, cc, n_stack, i):
        """Byte offset (from SP at function entry) of positional stack arg i of n_stack."""
        j = (n_stack - 1 - i) if cc.stack_reversed else i
        return self.ret_on_stack + cc.shadow + j * self.word


class X86(Arch):
    name, bits = "x86", 32
    uc_arch, uc_mode = UC_ARCH_X86, UC_MODE_32
    sp, pc, ret_reg, fp = X.UC_X86_REG_ESP, X.UC_X86_REG_EIP, X.UC_X86_REG_EAX, X.UC_X86_REG_EBP
    ret_on_stack = 4
    example_regs = ("eax", "ecx", "edx", "esi")
    regs = _regmap(X, "UC_X86_REG_")
    aliases = {}
    ccs = {
        "cdecl": CC("cdecl", []),
        "stdcall": CC("stdcall", [], callee_pops=True),
        "fastcall": CC("fastcall", ["ecx", "edx"], callee_pops=True),
        "thiscall": CC("thiscall", ["ecx"], callee_pops=True),
        "delphi": CC("delphi", ["eax", "edx", "ecx"], stack_reversed=True, callee_pops=True),
        "usercall": CC("usercall", None),
    }
    cc_aliases = {"register": "delphi", "borland": "delphi", "pascal_register": "delphi",
                  "winapi": "stdcall", "c": "cdecl", "userpurge": "usercall"}
    default_cc = "cdecl"


class X64(Arch):
    name, bits = "x64", 64
    uc_arch, uc_mode = UC_ARCH_X86, UC_MODE_64
    sp, pc, ret_reg, fp = X.UC_X86_REG_RSP, X.UC_X86_REG_RIP, X.UC_X86_REG_RAX, X.UC_X86_REG_RBP
    ret_on_stack = 8
    example_regs = ("rcx", "rdx", "r8", "rdi")
    regs = _regmap(X, "UC_X86_REG_")
    aliases = {}
    ccs = {
        "ms64": CC("ms64", ["rcx", "rdx", "r8", "r9"], shadow=32),
        "sysv": CC("sysv", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
        "usercall": CC("usercall", None),
    }
    cc_aliases = {"win64": "ms64", "microsoft": "ms64", "fastcall": "ms64",
                  "sysv64": "sysv", "amd64": "sysv", "userpurge": "usercall"}
    default_cc = "sysv"

    def cc(self, name):
        if name and name.lower() in ("cdecl", "stdcall", "thiscall"):
            # On x64 these keywords all mean the platform convention.
            return self.ccs[self.default_cc]
        return Arch.cc(self, name)


class ARM64(Arch):
    name, bits = "arm64", 64
    uc_arch, uc_mode = UC_ARCH_ARM64, UC_MODE_ARM
    sp, pc, ret_reg, fp = A.UC_ARM64_REG_SP, A.UC_ARM64_REG_PC, A.UC_ARM64_REG_X0, A.UC_ARM64_REG_X29
    lr = A.UC_ARM64_REG_X30
    ret_on_stack = 0
    example_regs = ("x0", "x1", "x8", "x19")
    regs = _regmap(A, "UC_ARM64_REG_")
    aliases = {"lr": "x30", "fp": "x29", "ip0": "x16", "ip1": "x17"}
    ccs = {
        "aapcs64": CC("aapcs64", ["x%d" % i for i in range(8)]),
        "usercall": CC("usercall", None),
    }
    cc_aliases = {"aapcs": "aapcs64", "arm64": "aapcs64", "cdecl": "aapcs64", "c": "aapcs64",
                  "userpurge": "usercall"}
    default_cc = "aapcs64"


def for_image(image):
    if image.arch == "x86":
        return X86()
    if image.arch == "x64":
        a = X64()
        a.default_cc = "ms64" if image.filetype == "pe" else "sysv"
        return a
    return ARM64()
