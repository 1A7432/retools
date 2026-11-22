"""Entry point for the worker's py_run tool.

    python3 -I -X utf8 /opt/jsre/pyrun.py SCRIPT [ARGS...]
    python3 -I -X utf8 /opt/jsre/pyrun.py -c CODE [ARGS...]

Installs the sandbox audit hook, then runs the script as __main__ with its own
directory on sys.path (as plain `python3 SCRIPT` would).
"""
import os
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sandbox_hook  # noqa: E402

sys.path.pop(0)
sandbox_hook.install()


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: pyrun.py SCRIPT|-c CODE [ARGS...]")
    if sys.argv[1] == "-c":
        if len(sys.argv) < 3:
            sys.exit("usage: pyrun.py -c CODE [ARGS...]")
        code = sys.argv[2]
        sys.argv = ["-c"] + sys.argv[3:]
        glb = {"__name__": "__main__", "__builtins__": __builtins__}
        exec(compile(code, "<py_run>", "exec"), glb)
        return
    script = os.path.abspath(sys.argv[1])
    sys.argv = sys.argv[1:]
    sys.path.insert(0, os.path.dirname(script))
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main()
