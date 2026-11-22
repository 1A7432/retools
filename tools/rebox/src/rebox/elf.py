"""ELF samples in the PE inner stage.

`rebox run` sends ELF samples to the Qiling backend (`_inner-elf`, module
rebox.elfemu, run with the separate .venv-elf interpreter); see README,
"Linux ELF". The Speakeasy inner stage (rebox.emulate) only reaches this
function if it is invoked directly with an ELF file, which the CLI never does.
"""

from __future__ import annotations

MESSAGE = ("ELF samples are not supported by the Speakeasy stage; `rebox run` emulates them with the Qiling "
           "backend (run `rebox setup-elf` once if it reports the environment missing)")


def run_elf(sample, out, timeout, args, meta) -> int:
    meta["errors"].append({"stage": "load", "error": MESSAGE})
    return 5
