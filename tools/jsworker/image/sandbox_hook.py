"""Audit hook shared by pyrun.py (worker's py_run) and grade_runner.py (grader).

The container (no network, read-only root, only /task mounted) is the real
boundary. This hook is a second line: it makes subprocesses, sockets and
loading arbitrary native libraries fail loudly inside Python, so a script
cannot reach tools the benchmark does not offer. Audit hooks cannot be removed
once installed.
"""
import os
import sys

_SITE = tuple(os.path.realpath(p) + os.sep for p in sys.path if p.endswith(("site-packages", "dist-packages")))

_BLOCKED_PREFIXES = (
    "subprocess.", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
    "os.forkpty", "os.startfile", "pty.", "socket.", "os.kill", "os.killpg", "signal.pthread_kill",
)

# Symbols that would reach a shell, another program or the network through ctypes.
_BLOCKED_SYMBOLS = {
    "system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execlp", "execle",
    "fork", "vfork", "clone", "posix_spawn", "posix_spawnp", "socket", "connect", "dlopen",
    "syscall", "ptrace",
}


class SandboxViolation(PermissionError):
    # A PermissionError (an OSError) so that library code which already handles
    # "command not available" -- e.g. platform.architecture() probing `file`,
    # called by pycryptodome at import -- falls back instead of crashing.
    pass


def _hook(event, args):
    if event.startswith(_BLOCKED_PREFIXES):
        raise SandboxViolation("jsre sandbox: %s is not allowed" % event)
    if event == "ctypes.dlopen":
        # pycryptodome loads its own compiled modules from site-packages; nothing else.
        # ctypes itself opens the main program (name None) when it is imported.
        name = args[0] if args else None
        if name is not None and not (isinstance(name, str) and os.path.realpath(name).startswith(_SITE)):
            raise SandboxViolation("jsre sandbox: loading native library %r is not allowed" % (name,))
    if event == "ctypes.dlsym":
        sym = args[1] if len(args) > 1 else None
        if isinstance(sym, bytes):
            sym = sym.decode("ascii", "replace")
        if isinstance(sym, str) and sym in _BLOCKED_SYMBOLS:
            raise SandboxViolation("jsre sandbox: native symbol %r is not allowed" % sym)


def install():
    sys.addaudithook(_hook)
