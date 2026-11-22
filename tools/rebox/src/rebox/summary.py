"""Turn a raw Speakeasy report (+ rebox run metadata) into a compact summary.

Conventions shared with the rest of the toolchain:
  * every list is {"total": N, "top": [...]}, so the reader sees how much was cut;
  * nothing is cut silently: lists shrink only through `fit_budget`, which
    records every cut under "truncated", and long strings carry a "…[+N]" tail;
  * the serialized object stays within max_chars;
  * addresses are hex strings.
"""

from __future__ import annotations

import ipaddress
import json
import math
import ntpath
import re
from collections import Counter
from urllib.parse import urlsplit

SCHEMA = "rebox.summary/1"
STR_CAP = 160


URL_RE = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s\"'<>]+")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
def looks_like_junk(s: str) -> bool:
    """Character tables, runs like 'stuvwxyz' or '((((((', and mostly unprintable text."""
    if not s:
        return True
    printable = sum(1 for c in s if c.isprintable())
    if printable < 0.9 * len(s):
        return True
    run = 1
    for a, b in zip(s, s[1:]):
        run = run + 1 if ord(b) - ord(a) in (0, 1) else 1
        if run >= 6:
            return True
    return False

NETWORK_MODULES = {"ws2_32", "wsock32", "mswsock", "wininet", "winhttp", "urlmon", "dnsapi", "iphlpapi", "netapi32"}
CRYPTO_MODULES = {"bcrypt", "ncrypt", "crypt32", "cryptsp", "rsaenh"}

# Matched against the bare API name with any trailing A/W/Ex/ExA/ExW removed, lower case.
CATEGORIES: dict[str, set[str]] = {
    "process_thread": {
        "createprocess", "createprocessasuser", "createprocesswithlogon", "createprocesswithtoken", "winexec",
        "shellexecute", "createthread", "createremotethread", "ntcreatethread", "ntcreatethreadex",
        "rtlcreateuserthread", "openprocess", "openthread", "terminateprocess", "ntterminateprocess",
        "queueuserapc", "ntqueueapcthread", "resumethread", "suspendthread", "ntresumethread",
        "setthreadcontext", "getthreadcontext", "ntsetcontextthread", "ntgetcontextthread",
        "ntunmapviewofsection", "zwunmapviewofsection", "createtoolhelp32snapshot", "process32first",
        "process32next", "thread32first", "thread32next", "module32first", "module32next", "enumprocesses",
        "writeprocessmemory", "readprocessmemory", "ntwritevirtualmemory", "ntreadvirtualmemory",
        "ntcreateuserprocess", "ntcreateprocess",
    },
    "file": {
        "createfile", "ntcreatefile", "ntopenfile", "writefile", "ntwritefile", "deletefile", "copyfile",
        "movefile", "findfirstfile", "findnextfile", "gettempfilename", "gettemppath", "setfileattributes",
        "createdirectory", "removedirectory", "urldownloadtofile", "setfiletime", "ntsetinformationfile",
        "replacefile", "createhardlink", "createsymboliclink", "getfileattributes",
    },
    "registry": {
        "regopenkey", "regcreatekey", "regsetvalue", "regsetkeyvalue", "regqueryvalue", "regdeletekey",
        "regdeletevalue", "regenumkey", "regenumvalue", "regdeletetree", "ntopenkey", "ntcreatekey",
        "ntsetvaluekey", "ntqueryvaluekey", "ntdeletekey", "ntdeletevaluekey", "zwopenkey", "zwcreatekey",
        "zwsetvaluekey", "zwqueryvaluekey", "shsetvalue", "shgetvalue", "shdeletekey", "shdeletevalue",
    },
    "crypto": {
        "cryptacquirecontext", "cryptcreatehash", "crypthashdata", "cryptderivekey", "cryptdecrypt",
        "cryptencrypt", "cryptimportkey", "cryptexportkey", "cryptgenkey", "cryptgenrandom",
        "cryptstringtobinary", "cryptbinarytostring", "cryptunprotectdata", "cryptprotectdata",
        "rtldecompressbuffer", "rtlcompressbuffer", "rtldecompressbufferex",
    },
    "memory": {
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex", "ntallocatevirtualmemory",
        "ntprotectvirtualmemory", "zwallocatevirtualmemory", "zwprotectvirtualmemory", "mapviewoffile",
        "ntmapviewofsection", "zwmapviewofsection", "createfilemapping", "ntcreatesection", "heapcreate",
        "virtualfree",
    },
    "services": {
        "openscmanager", "createservice", "openservice", "startservice", "controlservice",
        "changeserviceconfig", "changeserviceconfig2", "deleteservice", "startservicectrldispatcher",
        "registerservicectrlhandler", "enumservicesstatus", "queryservicestatus",
    },
    "anti_analysis": {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "zwqueryinformationprocess", "outputdebugstring", "ntsetinformationthread", "zwsetinformationthread",
        "ntquerysysteminformation", "zwquerysysteminformation", "findwindow", "getcursorpos",
        "getsystemfirmwaretable", "setunhandledexceptionfilter", "unhandledexceptionfilter",
        "addvectoredexceptionhandler", "getlastinputinfo",
        "globalmemorystatus", "getdiskfreespace", "getdrivetype", "getvolumeinformation", "ntdelayexecution",
        "sleep", "getadaptersinfo", "getadaptersaddresses", "enumwindows", "getforegroundwindow",
        "getcomputername", "getusername",
    },
    "dynamic_resolution": {
        "loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress", "getmodulehandle",
        "ldrgetdllhandle",
    },
}
# Too common in CRT start-up to mean anything on their own.
TIMING_APIS = {"gettickcount", "gettickcount64", "queryperformancecounter", "timegettime", "getsystemtimeasfiletime"}
NOISY_IN_CATEGORY = {"closehandle", "virtualfree", "getmodulehandle"}

CATEGORY_LOOKUP = {name: cat for cat, names in CATEGORIES.items() for name in names}
# Names the indicator extraction looks for, beyond the category sets.
EXTRA_KNOWN = {"createmutex", "openmutex", "internetconnect", "winhttpconnect", "gethostbyname", "getaddrinfo",
               "dnsquery_", "dnsquery", "internetopenurl", "winhttpopenrequest", "closehandle"}
KNOWN = set(CATEGORY_LOOKUP) | TIMING_APIS | EXTRA_KNOWN


def bare_api(api_name: str) -> str:
    """'kernel32.CreateFileW' -> 'createfile' (case-folded, A/W/Ex suffixes dropped)."""
    name = api_name.split(".", 1)[-1].lower()
    if name in KNOWN:
        return name
    for suffix in ("exa", "exw", "ex", "a", "w"):
        stem = name[: -len(suffix)]
        if name.endswith(suffix) and stem in KNOWN:
            return stem
    return name


def categorize(api_name: str) -> str | None:
    module = api_name.split(".", 1)[0].lower() if "." in api_name else ""
    bare = bare_api(api_name)
    if bare in CATEGORY_LOOKUP:
        return CATEGORY_LOOKUP[bare]
    if module in NETWORK_MODULES:
        return "network"
    if module in CRYPTO_MODULES or (module == "advapi32" and bare.startswith("crypt")):
        return "crypto"
    return None


def clip(s, cap: int = STR_CAP) -> str:
    s = "" if s is None else str(s)
    s = s.replace("\x00", "")
    if len(s) <= cap:
        return s
    return s[:cap] + f"…[+{len(s) - cap}]"


def tl(items) -> dict:
    items = list(items)
    return {"total": len(items), "top": items}


class Ordered:
    """Insertion-ordered set of strings, counting repeats."""

    def __init__(self):
        self.c: Counter = Counter()

    def add(self, v):
        if v is None:
            return
        v = str(v).strip().replace("\x00", "")
        if v:
            self.c[v] += 1

    def __iter__(self):
        return iter(self.c)

    def __len__(self):
        return len(self.c)

    def __contains__(self, v):
        return v in self.c


def _args(ev) -> list[dict]:
    return ev.get("args") or []


def _arg(ev, *names, index=None):
    wanted = {n.lower() for n in names}
    for a in _args(ev):
        if (a.get("name") or "").lower() in wanted:
            return a.get("display")
    if index is not None:
        args = _args(ev)
        if index < len(args):
            return args[index].get("display")
    return None


def _str_args(ev):
    for a in _args(ev):
        if a.get("type") in ("str", "text") and a.get("display"):
            yield a["display"]


def _host_of(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def build_summary(report: dict | None, meta: dict, *, sample_name: str, sha256: str, size: int,
                  out_dir: str, raw_report_path: str | None, wall_time: float | None,
                  timeout: int | None, sandbox_state: str, noise_strings: set[str] | None = None) -> dict:
    report = report or {}
    eps = report.get("entry_points") or []
    ident = meta.get("identity") or {}

    sections = [
        f"{s['name'] or '?'} {s['perms']} vsz={s['vsize']} H={s['entropy']}" for s in ident.get("sections") or []
    ]
    sample = {
        "name": sample_name,
        "sha256": sha256,
        "size": size,
        "arch": ident.get("arch") or report.get("arch"),
        "pe_type": ident.get("pe_type") or report.get("filetype"),
        "subsystem": ident.get("subsystem"),
        "timestamp": ident.get("timestamp"),
        "image_base": ident.get("image_base") or report.get("image_base"),
        "entry_rva": ident.get("entry_rva"),
        "imphash": ident.get("imphash"),
        "imports": ident.get("imports"),
        "sections": tl(sections),
    }

    # ---- pass over all events -------------------------------------------------
    api_counter: Counter = Counter()
    first_pc: dict[str, int] = {}
    cat_counts: dict[str, Counter] = {}
    resolved = Ordered()
    runs = []
    ind = {k: Ordered() for k in (
        "hosts", "urls", "ips", "conns", "ports", "files_written", "files_read", "files_deleted",
        "registry_written", "registry_read", "mutexes", "cmdlines", "services", "injections", "modules_loaded")}
    dns_answers: set[str] = set()
    arg_strings = Ordered()

    true_calls = meta.get("run_api_calls") or []
    if len(true_calls) != len(eps):
        true_calls = []
    for n_ep, ep in enumerate(eps):
        events = ep.get("events") or []
        n_api = 0
        for ev in events:
            kind = ev.get("event")
            if kind == "api":
                n_api += 1
                _api_event(ev, api_counter, first_pc, cat_counts, resolved, ind, arg_strings)
            else:
                _other_event(ev, ind, dns_answers)
        err = ep.get("error")
        if err:
            stop = err.get("type") or "error"
            detail = err.get("api_name") or err.get("context_summary") or err.get("msg")
        else:
            stop, detail = "returned", None
        run = {
            "type": ep.get("ep_type"),
            "start": ep.get("start_addr"),
            "api_calls": true_calls[n_ep] if true_calls else None,
            "api_events": n_api,
            "instrs": ep.get("instr_count"),
            "stop": stop,
        }
        if err and err.get("pc"):
            run["pc"] = err.get("pc")
        if detail:
            run["detail"] = clip(detail, 120)
        if ep.get("ret_val") is not None:
            run["ret"] = ep.get("ret_val")
        if ep.get("dynamic_code_segments"):
            run["dyn_code"] = len(ep["dynamic_code_segments"])
        runs.append(run)
        for df in ep.get("dropped_files") or []:
            ind["files_written"].add(df.get("path"))

    # Speakeasy answers every DNS query with a canned address; those are not indicators.
    ips = [ip for ip in ind["ips"] if ip not in dns_answers and ip not in ("0.0.0.0", "127.0.0.1")]
    for url in ind["urls"]:
        host = _host_of(url)
        if host and not _is_ip(host):
            ind["hosts"].add(host.lower())
        elif host and host not in dns_answers:
            ips.append(host)
    ips = list(dict.fromkeys(ips))

    # ---- API section --------------------------------------------------------------
    histogram = [[name, n] for name, n in api_counter.most_common()]
    categories = {}
    for cat in ("process_thread", "file", "registry", "network", "crypto", "memory", "services",
                "anti_analysis", "dynamic_resolution"):
        c = cat_counts.get(cat)
        if not c:
            continue
        items = [[name, n, hex(first_pc[name]) if name in first_pc else None] for name, n in c.most_common()]
        categories[cat] = tl(items)
    timing = {name: n for name, n in api_counter.items() if bare_api(name) in TIMING_APIS}
    if sum(timing.values()) > 6:
        items = [[name, n, hex(first_pc[name]) if name in first_pc else None]
                 for name, n in Counter(timing).most_common()]
        categories["timing_checks"] = tl(items)

    api = {
        "calls": sum(true_calls) if true_calls else None,
        "events": sum(api_counter.values()),
        "unique": len(api_counter),
        "note": "counts below are logged events; Speakeasy collapses an API call that repeats one of the "
                "last few events (same pc, args, result)",
        "histogram": tl(histogram),
        "categories": categories,
        "resolved": tl([clip(r) for r in resolved]),
    }

    # ---- indicators ------------------------------------------------------------------
    indicators = {}
    empty = []
    order = ["hosts", "urls", "ips", "conns", "ports", "files_written", "files_read", "files_deleted",
             "registry_written", "registry_read", "mutexes", "cmdlines", "services", "injections",
             "modules_loaded"]
    urls = list(ind["urls"])
    ind["urls"] = [u for u in urls if not any(o != u and o.startswith(u) for o in urls)]
    for key in order:
        vals = ips if key == "ips" else list(ind[key])
        if vals:
            indicators[key] = tl([clip(v) for v in vals])
        else:
            empty.append(key)
    indicators["empty"] = empty

    # ---- payloads ------------------------------------------------------------------------
    payloads = []
    for d in meta.get("dumps") or []:
        p = {"kind": d["kind"], "file": _rel(d["path"], out_dir), "size": d["size"], "sha256": d["sha256"]}
        for k in ("base", "name", "emu_path", "pid", "target"):
            if d.get(k) is not None:
                p[k] = clip(d[k], 80) if isinstance(d[k], str) else d[k]
        payloads.append(p)
    payload_section = tl(payloads)
    skipped = [clip(f"{d.get('kind')} {d.get('emu_path') or d.get('base') or ''} size={d.get('size')}: {d.get('reason')}", 120)
               for d in meta.get("dumps_skipped") or []]

    # ---- strings -----------------------------------------------------------------------
    shown = set()
    for key in order:
        for v in (ips if key == "ips" else ind[key]):
            shown.add(v)
    noise = set(noise_strings or ())
    if meta.get("command_line"):  # the command line rebox gave the sample, and its image path
        noise.add(meta["command_line"])
        noise.add(meta["command_line"].split(" ")[0].strip('"'))
    api_strs = [clip(s) for s in arg_strings
                if s not in shown and len(s) >= 4 and s not in resolved and s not in noise and not looks_like_junk(s)]
    api_strs.sort(key=_string_score, reverse=True)
    rt = runtime_only_strings(report, noise)
    strings = {
        "api_args": tl(api_strs),
        "runtime_only": tl([clip(s) for s in rt]),
    }

    # ---- emulation ---------------------------------------------------------------------
    errors = []
    for e in report.get("errors") or []:
        errors.append(clip(f"{e.get('type')} pc={e.get('pc')} {e.get('instr') or ''}".strip(), 200))
    for e in meta.get("errors") or []:
        errors.append(clip(f"[rebox:{e.get('stage')}] {e.get('error')}", 200))
    total_instrs = [r["instrs"] for r in runs if r.get("instrs") is not None]
    emulation = {
        "engine": f"speakeasy {meta.get('speakeasy_version')} / unicorn {meta.get('unicorn_version')}",
        "sandbox": sandbox_state,
        "wall_s": round(wall_time, 2) if wall_time is not None else None,
        "emu_s": report.get("emulation_total_runtime"),
        "timeout_s": timeout,
        "instrs": sum(total_instrs) if total_instrs else None,
        "runs": tl(runs),
        "errors": tl(errors),
    }

    return {
        "schema": SCHEMA,
        "ok": True,
        "sample": sample,
        "emulation": emulation,
        "api": api,
        "indicators": indicators,
        "payloads": payload_section,
        "payloads_not_saved": tl(skipped),
        "strings": strings,
        "out_dir": out_dir,
        "raw_report": _rel(raw_report_path, out_dir) if raw_report_path else None,
        "truncated": None,
    }


def _rel(path: str, out_dir: str) -> str:
    if path and out_dir and path.startswith(out_dir.rstrip("/") + "/"):
        return path[len(out_dir.rstrip("/")) + 1:]
    return path


def _string_score(s: str) -> int:
    score = 0
    if "://" in s:
        score += 4
    if "\\" in s or "/" in s:
        score += 2
    if "." in s or "=" in s or "%" in s:
        score += 1
    if len(s) >= 8:
        score += 1
    return score


def _api_event(ev, api_counter, first_pc, cat_counts, resolved, ind, arg_strings):
    name = ev.get("api_name") or "?"
    api_counter[name] += 1
    pc = (ev.get("pos") or {}).get("pc")
    if name not in first_pc and isinstance(pc, int):
        first_pc[name] = pc
    cat = categorize(name)
    bare = bare_api(name)
    if cat and bare not in NOISY_IN_CATEGORY:
        cat_counts.setdefault(cat, Counter())[name] += 1

    for s in _str_args(ev):
        arg_strings.add(s)
        for url in URL_RE.findall(s):
            ind["urls"].add(url.rstrip(").,;"))
        for ip in IP_RE.findall(s):
            ind["ips"].add(ip)

    if bare in ("getprocaddress", "ldrgetprocedureaddress"):
        proc = _arg(ev, "lpProcName", "ProcedureName", index=1)
        if proc and not proc.startswith("0x"):
            resolved.add(proc)
    elif bare in ("loadlibrary", "ldrloaddll"):
        lib = _arg(ev, "lpLibFileName", "DllName", index=0)
        if lib:
            ind["modules_loaded"].add(lib)
    elif bare in ("internetconnect", "winhttpconnect"):
        ind["hosts"].add(_arg(ev, "lpszServerName", "pswzServerName", index=1))
    elif bare in ("gethostbyname", "getaddrinfo", "dnsquery_", "dnsquery"):
        ind["hosts"].add(_arg(ev, "name", "pNodeName", "pszName", index=0))
    elif bare in ("createmutex", "openmutex"):
        ind["mutexes"].add(_arg(ev, "lpName", index=2 if bare == "createmutex" else 2))
    elif bare == "winexec":
        ind["cmdlines"].add(_arg(ev, "lpCmdLine", index=0))
    elif bare == "shellexecute":
        f, p = _arg(ev, "lpFile", index=2), _arg(ev, "lpParameters", index=3)
        if f and not str(f).startswith("0x"):
            ind["cmdlines"].add(f"{f} {p}" if p and not str(p).startswith("0x") else f)
    elif bare in ("createprocess", "createprocessasuser"):
        cmd = _arg(ev, "lpCommandLine") or _arg(ev, "lpApplicationName")
        if cmd and not str(cmd).startswith("0x"):
            ind["cmdlines"].add(cmd)
    elif bare == "deletefile":
        ind["files_deleted"].add(_arg(ev, "lpFileName", index=0))
    elif bare in ("copyfile", "movefile"):
        ind["files_written"].add(_arg(ev, "lpNewFileName", index=1))
    elif bare == "urldownloadtofile":
        ind["files_written"].add(_arg(ev, "szFileName", index=2))
    elif bare in ("createservice",):
        svc = _arg(ev, "lpServiceName", index=1)
        binpath = _arg(ev, "lpBinaryPathName", index=7)
        ind["services"].add(f"{svc} -> {binpath}" if binpath else svc)
    elif bare in ("openservice",):
        ind["services"].add(_arg(ev, "lpServiceName", index=1))
    elif bare in ("regdeletekey", "regdeletevalue", "regdeletetree"):
        ind["registry_written"].add("DELETE " + str(_arg(ev, "lpSubKey", "lpValueName", index=1)))


WRITE_FLAGS = ("GENERIC_WRITE", "GENERIC_ALL", "FILE_WRITE", "FILE_APPEND", "DELETE")
CREATE_FLAGS = ("CREATE_ALWAYS", "CREATE_NEW", "TRUNCATE_EXISTING", "FILE_SUPERSEDE", "FILE_OVERWRITE")


def _other_event(ev, ind, dns_answers):
    kind = ev.get("event")
    if kind == "file_create":
        ind["files_written"].add(ev.get("path"))
    elif kind == "file_open":
        flags = " ".join((ev.get("access_flags") or []) + (ev.get("open_flags") or []))
        if any(f in flags for f in WRITE_FLAGS + CREATE_FLAGS):
            ind["files_written"].add(ev.get("path"))
        else:
            ind["files_read"].add(ev.get("path"))
    elif kind == "file_write":
        ind["files_written"].add(ev.get("path"))
    elif kind == "file_read":
        ind["files_read"].add(ev.get("path"))
    elif kind == "reg_create_key":
        ind["registry_written"].add(ev.get("path"))
    elif kind == "reg_write_value":
        ind["registry_written"].add(f"{ev.get('path')}\\{ev.get('value_name') or '(default)'}")
    elif kind in ("reg_open_key", "reg_list_subkeys"):
        ind["registry_read"].add(ev.get("path"))
    elif kind == "reg_read_value":
        ind["registry_read"].add(f"{ev.get('path')}\\{ev.get('value_name') or '(default)'}")
    elif kind == "net_dns":
        if ev.get("query"):
            ind["hosts"].add(str(ev["query"]).lower())
        if ev.get("response"):
            for ip in IP_RE.findall(str(ev["response"])):
                dns_answers.add(ip)
    elif kind == "net_traffic":
        server, port = ev.get("server"), ev.get("port")
        ind["conns"].add(f"{ev.get('proto')} {ev.get('type')} {server}:{port}")
        if server and _is_ip(str(server)):
            ind["ips"].add(server)
        elif server:
            ind["hosts"].add(str(server).lower())
        if port is not None:
            ind["ports"].add(str(port))
    elif kind == "net_http":
        server, port = ev.get("server"), ev.get("port")
        headers = ev.get("headers") or ""
        first = headers.splitlines()[0] if headers else ""
        parts = first.split(" ")
        path = parts[1] if len(parts) >= 2 else ""
        scheme = "https" if "https" in str(ev.get("proto") or "") else "http"
        if server:
            ind["urls"].add(f"{scheme}://{server}{'' if port in (80, 443, None) else ':' + str(port)}{path}")
            ind["conns"].add(" ".join(x for x in (str(ev.get("proto")), first[:60], f"{server}:{port}") if x))
        if port is not None:
            ind["ports"].add(str(port))
    elif kind == "process_create":
        ind["cmdlines"].add(ev.get("cmdline") or ev.get("path"))
    elif kind in ("thread_inject", "mem_write") and ev.get("pid") is not None:
        target = ntpath.basename(str(ev.get("path") or "?"))
        where = ev.get("start_addr") or ev.get("base")
        ind["injections"].add(f"{kind} -> pid {ev.get('pid')} {target} @{where}")
    elif kind == "thread_create" and ev.get("pid") is not None:
        ind["injections"].add(f"remote thread -> pid {ev.get('pid')} @{ev.get('start_addr')}")


def runtime_only_strings(report: dict, noise: set[str]) -> list[str]:
    """Strings found in emulated memory that were not in the file: decoded at run time."""
    s = report.get("strings") or {}
    static = set((s.get("static") or {}).get("ansi") or []) | set((s.get("static") or {}).get("unicode") or [])
    mem = list((s.get("in_memory") or {}).get("ansi") or []) + list((s.get("in_memory") or {}).get("unicode") or [])
    out = []
    seen = set()
    for x in mem:
        if x in static or x in seen or len(x) < 6 or x in noise:
            continue
        # Substring match only for environment entries ("windir=C:\Windows"), so a decoded
        # path that merely contains C:\Windows is kept.
        if looks_like_junk(x) or any(n in x for n in noise if "=" in n):
            continue
        seen.add(x)
        out.append(x)
    return out


def emulator_noise_strings() -> set[str]:
    """Strings the emulator itself places in memory (environment, fake command line)."""
    noise: set[str] = set()
    try:
        from speakeasy.config import get_default_config_dict

        cfg = get_default_config_dict()
    except Exception:
        return noise
    for k, v in (cfg.get("env") or {}).items():
        noise.add(f"{k}={v}")
        noise.add(str(v))
    for key in ("command_line", "current_dir", "hostname", "domain"):
        if cfg.get(key):
            noise.add(str(cfg[key]))
            noise.update(str(cfg[key]).split())
    user = cfg.get("user") or {}
    if user.get("name"):
        noise.add(user["name"])
    for p in cfg.get("processes") or []:
        for key in ("name", "path", "command_line"):
            if p.get(key):
                noise.add(str(p[key]))
    return {n for n in noise if n}


# ---- budget ---------------------------------------------------------------------------

def _size(obj) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def _tlists(obj, path=""):
    """Yield (path, dict) for every {"total","top"} list inside obj."""
    if isinstance(obj, dict):
        if set(obj.keys()) >= {"total", "top"} and isinstance(obj.get("top"), list):
            yield path, obj
        for k, v in obj.items():
            if k != "top":
                yield from _tlists(v, f"{path}.{k}" if path else k)


# Dropped whole, in this order, if shrinking every list to zero is still not enough.
DROP_ORDER = ["strings", "sample.sections", "api.categories", "api.resolved", "api.histogram",
              "indicators", "payloads", "emulation.runs", "emulation.errors"]


# Larger weight = more valuable per character, cut later.
WEIGHTS = {"indicators": 4, "payloads": 5, "emulation.runs": 4, "emulation.errors": 3, "api.categories": 3,
           "api.resolved": 2, "api.histogram": 1.5, "sample.sections": 1, "strings": 1}


def _weight(path: str) -> float:
    for prefix, w in WEIGHTS.items():
        if path == prefix or path.startswith(prefix + "."):
            return w
    return 2


def fit_budget(summary: dict, max_chars: int) -> dict:
    """Make the serialized summary fit max_chars, recording every cut.

    If everything fits, nothing changes. Otherwise all lists are emptied and
    refilled round-robin (higher-weight lists take more items per round), each
    list keeping a prefix of its items, until the next item would not fit.
    Whole sections are dropped (DROP_ORDER) only if even the empty skeleton is
    too large.
    """
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
                        open_lists.discard(p)  # keep a strict prefix: never skip to a smaller item
                        break
                    t["top"].append(items[i])
                    pos[p] = i + 1
                    size += cost
        cuts = _compact_paths([p for p, t, items in live if len(t["top"]) < len(items)])
        summary["truncated"] = {
            "why": f"lists shortened to fit {max_chars} chars; each keeps its exact total; full data in raw_report",
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


def _compact_paths(paths: list[str]) -> list[str]:
    """['api.categories.file', 'api.categories.network', 'payloads'] -> ['api.categories.*', 'payloads']."""
    by_parent: dict[str, list[str]] = {}
    for p in paths:
        parent = p.rsplit(".", 1)[0] if "." in p else ""
        by_parent.setdefault(parent, []).append(p)
    out = []
    for parent, ps in by_parent.items():
        out.extend([f"{parent}.*"] if parent and len(ps) > 2 else ps)
    return out


def _drop(obj: dict, path: str) -> bool:
    parts = path.split(".")
    for p in parts[:-1]:
        obj = obj.get(p)
        if not isinstance(obj, dict):
            return False
    if parts[-1] in obj and obj[parts[-1]] is not None:
        del obj[parts[-1]]
        return True
    return False


def dumps(summary: dict) -> str:
    return json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
