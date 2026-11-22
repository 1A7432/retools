"""Compact summary of an ELF run (Qiling backend), same top-level shape as the PE one.

`rebox.summary/1` keys are kept: sample, emulation, api, indicators, payloads,
payloads_not_saved, strings, out_dir, raw_report, truncated. Differences:
`api` counts syscalls (exact counts, not de-duplicated events), `api.resolved`
is replaced by `api.unsupported`, and `emulation.runs` has one entry per
emulated process or thread. `emulation.engine` names the backend.
Truncation uses the same fit_budget as the PE path.
"""

from __future__ import annotations

import ipaddress

from .summary import SCHEMA, clip, tl

CATEGORIES: dict[str, set[str]] = {
    "process": {"fork", "vfork", "clone", "clone3", "execve", "execveat", "kill", "tkill", "tgkill", "wait4",
                "waitid", "waitpid", "setsid", "setpgid", "prctl", "pause", "rt_sigsuspend",
                "setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid"},
    "file": {"open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir",
             "mkdirat", "rmdir", "chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat", "chown32",
             "fchown32", "lchown32", "symlink", "symlinkat", "link", "linkat", "truncate", "ftruncate",
             "truncate64", "ftruncate64", "getdents", "getdents64", "readlink", "readlinkat", "chdir", "fchdir",
             "utimensat", "mknod", "mknodat", "flock", "inotify_add_watch", "inotify_init", "inotify_init1"},
    "network": {"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "send", "sendto",
                "sendmsg", "sendmmsg", "recv", "recvfrom", "recvmsg", "recvmmsg", "socketcall", "getsockname",
                "getpeername", "setsockopt", "getsockopt", "shutdown"},
    "memory": {"mprotect", "mremap", "memfd_create", "process_vm_readv", "process_vm_writev", "remap_file_pages"},
    "anti_analysis": {"ptrace", "sethostname", "setdomainname", "personality", "init_module", "finit_module",
                      "delete_module", "mount", "umount2", "chroot", "pivot_root", "unshare", "setns", "seccomp",
                      "reboot", "syslog", "iopl", "ioperm"},
    "timing": {"nanosleep", "clock_nanosleep", "clock_nanosleep_time64", "alarm", "setitimer", "timer_create",
               "timer_settime", "timerfd_create", "timerfd_settime"},
    "discovery": {"uname", "sysinfo", "getuid", "geteuid", "getgid", "getegid", "getuid32", "geteuid32",
                  "getgid32", "getegid32", "getppid", "sched_getaffinity", "getrlimit", "prlimit64", "statfs",
                  "statfs64", "getcpu", "times", "getrusage"},
}
CAT_OF = {n: c for c, ns in CATEGORIES.items() for n in ns}
NOT_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", None}


def _items(d: dict | None) -> list[str]:
    return list((d or {}).keys())


def _is_ip(s) -> bool:
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


def build_summary(report: dict, meta: dict, *, sample_name: str, sha256: str | None, size: int | None,
                  out_dir: str, wall_time: float | None, timeout: int | None, sandbox_state: str) -> dict:
    ident = report.get("identity") or meta.get("identity") or {}
    em = report.get("emulation") or {}
    eng = report.get("engine") or {}
    net = report.get("network") or {}
    ind_raw = report.get("indicators") or {}

    sample = {
        "name": sample_name, "sha256": sha256, "size": size, "format": "elf",
        "arch": ident.get("arch"), "bits": ident.get("bits"), "endian": ident.get("endian"),
        "elf_type": ident.get("elf_type"), "linkage": ident.get("linkage"), "interp": ident.get("interp"),
        "pie": ident.get("pie"), "entry": ident.get("entry"), "stripped": ident.get("stripped"),
        "upx": ident.get("upx"), "needed": tl(ident.get("needed") or []),
        "sections": tl([f"{s['name']} {s['perms']} size={s['size']} H={s['entropy']}"
                        for s in ident.get("sections") or []]),
    }

    runs = []
    for p in report.get("processes") or []:
        r = {"pid": p["pid"]}
        if p.get("tid") != p["pid"]:
            r["tid"] = p.get("tid")
        r.update({"ppid": p.get("ppid"), "type": p.get("type"), "start": p.get("start"),
                  "syscalls": p.get("syscalls"), "stop": p.get("stop")})
        for k in ("exit_code", "pc", "name"):
            if p.get(k) is not None:
                r[k] = p[k]
        if p.get("detail"):
            r["detail"] = clip(p["detail"], 120)
        runs.append(r)

    errors = [clip(f"[rebox:{e.get('stage')}] {e.get('error')}", 200) for e in meta.get("errors") or []]
    errors += [clip(f"[rebox:warning] {w}", 200) for w in meta.get("warnings") or []]
    for name, err in (report.get("handler_errors") or {}).items():
        errors.append(clip(f"[qiling:{name}] {err}", 200))

    emulation = {
        "engine": f"qiling {eng.get('qiling')} / unicorn {eng.get('unicorn')}",
        "backend": "qiling (Linux user-mode syscall emulation)",
        "sandbox": sandbox_state,
        "wall_s": round(wall_time, 2) if wall_time is not None else None,
        "emu_s": em.get("emu_s"),
        "timeout_s": timeout,
        "stop": em.get("stop"),
        "stop_detail": clip(em.get("detail"), 160) if em.get("detail") else None,
        "virtual_sleep_s": em.get("virtual_sleep_s"),
        "syscall_budget": em.get("max_syscalls"),
        "instrs": None,
        "runs": tl(runs),
        "errors": tl(errors),
    }
    st = report.get("stdin") or {}
    if st.get("bytes") or st.get("reads"):   # only when input was given or the program read fd 0
        emulation["stdin"] = {k: st.get(k) for k in ("bytes", "consumed", "reads")}

    counts = report.get("syscall_counts") or {}
    first = report.get("syscall_first_pc") or {}
    cats: dict[str, list] = {}
    for name, n in counts.items():
        c = CAT_OF.get(name)
        if c:
            cats.setdefault(c, []).append([name, n, first.get(name)])
    categories = {c: tl(sorted(v, key=lambda x: -x[1])) for c, v in cats.items()}
    ufirst = report.get("unsupported_first_pc") or {}
    api = {
        "kind": "syscalls",
        "calls": em.get("syscalls"),
        "events": len(report.get("events") or []),
        "unique": len(counts),
        "note": "syscall counts are exact; `events` is the bounded per-call log in syscalls.log "
                f"({report.get('events_dropped', 0)} calls not logged); unsupported syscalls returned -ENOSYS",
        "histogram": tl([[k, v] for k, v in counts.items()]),
        "categories": categories,
        "unsupported": tl([[k, v, ufirst.get(k)] for k, v in (report.get("unsupported") or {}).items()]),
    }

    canned, resolver = net.get("canned_dns_answer"), net.get("nameserver")
    conns, ips, ports, sent_previews = [], [], [], []
    for c in net.get("connections") or []:
        ip, port = c.get("ip"), c.get("port")
        label = f"{c.get('proto')} {'dns' if c.get('dns') else c.get('how')} {ip}:{port}"
        if c.get("host"):
            label += f" ({c['host']} via canned DNS)"
        if c.get("sent"):
            label += f" sent={c['sent']}B"
        conns.append(label)
        for h in c.get("http") or []:
            conns.append(f"{c.get('proto')}.http {h}")
        if ip not in NOT_IPS and ip != canned and not (c.get("dns") and ip == resolver) and _is_ip(ip):
            ips.append(ip)
        if port is not None and not (c.get("dns") and ip == resolver):
            ports.append(str(port))
        if c.get("preview") and not c.get("dns"):
            sent_previews.append(clip(f"{ip}:{port} {c['preview']}", 160))
    urls = _items(ind_raw.get("urls"))
    for u in urls:
        host = u.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0]
        if _is_ip(host) and host != canned:
            ips.append(host)
    listening = _items(ind_raw.get("listening"))
    ports += [x.rsplit(":", 1)[-1] for x in listening]

    keys = ["hosts", "urls", "ips", "conns", "ports", "listening", "files_written", "files_read", "files_deleted",
            "files_probed", "chmod", "persistence_paths", "cmdlines", "process_names", "signals", "raw_sockets",
            "anti_analysis", "modules_loaded"]
    values = {k: _items(ind_raw.get(k)) for k in keys}
    values.update({"ips": list(dict.fromkeys(ips)), "conns": list(dict.fromkeys(conns)),
                   "ports": list(dict.fromkeys(ports)), "urls": urls})
    values["anti_analysis"] = values["anti_analysis"] + [f"unix socket {u}" for u in net.get("unix") or []]
    indicators, empty = {}, []
    for k in keys:
        if values[k]:
            indicators[k] = tl([clip(v) for v in values[k]])
        else:
            empty.append(k)
    indicators["empty"] = empty

    payloads = []
    for d in meta.get("dumps") or []:
        p = {"kind": d["kind"], "file": _rel(d["path"], out_dir), "size": d["size"], "sha256": d["sha256"]}
        for k in ("base", "name", "emu_path", "change", "pid", "target", "tag"):
            if d.get(k) is not None:
                p[k] = clip(d[k], 80) if isinstance(d[k], str) else d[k]
        payloads.append(p)
    skipped = [clip(f"{d.get('kind')} {d.get('emu_path') or d.get('base') or ''} size={d.get('size')}: "
                    f"{d.get('reason')}", 120) for d in meta.get("dumps_skipped") or []]

    out_lines = []
    for stream in ("stdout", "stderr"):
        head = ((report.get(stream) or {}).get("head") or "")
        for ln in head.splitlines():
            if ln.strip():
                out_lines.append(clip(ln if stream == "stdout" else f"[stderr] {ln}", 160))
    strings = {"output": tl(out_lines), "net_sent": tl(sent_previews)}

    return {
        "schema": SCHEMA,
        "ok": True,
        "sample": sample,
        "emulation": emulation,
        "api": api,
        "indicators": indicators,
        "payloads": tl(payloads),
        "payloads_not_saved": tl(skipped),
        "strings": strings,
        "out_dir": out_dir,
        "raw_report": "report.json",
        "truncated": None,
    }


def _rel(path: str, out_dir: str) -> str:
    if path and out_dir and path.startswith(out_dir.rstrip("/") + "/"):
        return path[len(out_dir.rstrip("/")) + 1:]
    return path
