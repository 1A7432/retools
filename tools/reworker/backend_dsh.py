"""DeepSeek Harness (dsh) backend for rew.

Everything that knows about dsh lives here: where the CLI and the profile are,
the per-run --patch overlay, the headless command line, the --json event
stream, and the profile checks behind `rew setup` and `rew doctor`. rew talks
to it through a small interface (problems, setup, run, doctor) so another
backend could sit beside it.

run() returns a backend-neutral outcome dict:
    session, final, reason, exit, timed_out, seconds, texts, calls, usage,
    steps, steps_without_usage, errors, stderr, bad_lines, events_path
where each call is {id, tool, input, status, result, error} and tool names
are as the model saw them (mcp__ida__execute_python).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import guard  # noqa: E402

DSH = os.environ.get("REW_DSH") or \
    "/Applications/DeepSeek Harness.app/Contents/Resources/runtime/cli/bin/dsh"
IDA_MCP = os.environ.get("REW_IDA_MCP") or shutil.which("ida-mcp") or \
    os.path.expanduser("~/.local/bin/ida-mcp")
PROXY = os.path.join(HERE, "guardproxy.py")
REPO_PATCH = os.path.join(HERE, "profile", "cordis.patch.yml")
# Provider rows are kept out of the tracked patch: provider.local.yml (not in
# git) when present, else the example. jsworker uses the same file.
PROVIDER_LOCAL = os.path.join(HERE, "profile", "provider.local.yml")
PROVIDER_EXAMPLE = os.path.join(HERE, "profile", "provider.example.yml")
PROFILE = "re-worker"
TEMPLATE = "headless"
TEMPLATE_BUNDLES = ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-headless"]
SERVER = "ida"
AGENT_NAME = "dsh-worker"


def provider_file():
    return PROVIDER_LOCAL if os.path.exists(PROVIDER_LOCAL) else PROVIDER_EXAMPLE


def provider_rows():
    """(yaml text, default provider key, default model id) from the provider file."""
    path = provider_file()
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    found = {}
    for key in ("provider", "model"):
        m = re.search(r"^#\s*default-%s:\s*(\S+)\s*$" % key, text, re.M)
        if not m:
            raise RuntimeError("%s has no `# default-%s: ...` line" % (path, key))
        found[key] = m.group(1)
    return text, found["provider"], found["model"]


_, PROVIDER, MODEL = provider_rows()
EFFORT = "high"
EFFORTS = ("low", "high", "max")
TOOL_TIMEOUT_MS = 180000
TERM_GRACE = 25          # seconds between SIGTERM and SIGKILL on timeout

IDA_TOOL_NAMES = {"mcp__%s__%s" % (SERVER, t) for t in guard.ALLOWED_TOOLS}

# Rows that put tools in front of the model and must be disabled. doctor also
# flags any enabled row that looks like a tool row but is not listed here.
TOOL_ROWS = ["tool-bash", "tool-pwsh", "tool-jobs", "tool-fs", "tool-fs-search",
             "tool-working-directory", "tool-skill", "plan-mode", "tool-agent-team",
             "tool-subagent-control", "tool-subagent", "tool-subagent-fork",
             "tool-workflow", "tool-todo", "tool-goal", "tool-web", "mcp-resources",
             "tool-plugin-manager"]
TOOL_INFRA = {"tools", "tool-executor-native", "tool-executor-ptc", "tool-result-pruner",
              "timeout-policy"}
TOOL_PACKAGES = {"@deepseek-ai/dsh-plan-mode", "@deepseek-ai/dsh-mcp-resources",
                 "@deepseek-ai/dsh-plugin-manager/tools"}
MCP_CLIENT = "@deepseek-ai/dsh-mcp-client"


def render_patch(repo_patch, proxy):
    """The profile patch as installed: the tracked template with the provider
    rows and this checkout's paths filled in. Nothing here depends on the
    environment, so the readiness check gives the same answer everywhere."""
    with open(repo_patch, encoding="utf-8") as fh:
        text = fh.read()
    rows, provider, model = provider_rows()
    if "# @PROVIDER_ROWS@\n" not in text:
        raise RuntimeError("%s has no `# @PROVIDER_ROWS@` line" % repo_patch)
    text = text.replace("# @PROVIDER_ROWS@\n", rows.rstrip("\n") + "\n")
    # <checkout>/tools/<tool>/profile/cordis.patch.yml
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(repo_patch)),
                                         "..", "..", ".."))
    for token, value in (("@PROVIDER@", provider), ("@MODEL@", model), ("@PROXY@", proxy),
                         ("@ROOT@", root)):
        text = text.replace(token, value)
    return text.encode("utf-8")


def dsh_home():
    return os.environ.get("DSH_HOME") or os.path.expanduser("~/.dsh")


def profile_dir(profile=None):
    return os.path.join(dsh_home(), "profiles", profile or PROFILE)


def _y(value):
    """A YAML scalar. JSON strings and numbers are valid YAML."""
    return json.dumps(value, ensure_ascii=False)


def _yaml_list(items, indent):
    pad = " " * indent
    return "\n".join("%s- %s" % (pad, _y(i)) for i in items)


# --------------------------------------------------------------------------
# per-run overlay
# --------------------------------------------------------------------------

def proxy_command(mode, max_calls, log, db=None, server=None):
    """args for the mcp-ida row: the proxy's own options, then the real server."""
    args = ["--mode", mode, "--max-calls", str(max_calls), "--log", log]
    if db:
        args += ["--db", db]
    return args + ["--"] + (server or [IDA_MCP, "stdio", "--agent=%s" % AGENT_NAME])


def overlay_text(settings, server=None, provider_rows=""):
    """The --patch overlay for one run.

    settings: mode, max_calls, log, db, run_dir, and optionally model, effort.
    """
    state = os.path.join(settings["run_dir"], "dsh")
    rows = [
        "# rew per-run overlay; generated, do not edit",
        "- id: mcp-ida",
        "  name: %s" % _y(MCP_CLIENT),
        "  config:",
        "    serverName: %s" % _y(SERVER),
        "    transport: stdio",
        "    command: %s" % _y(PROXY),
        "    args:",
        _yaml_list(proxy_command(settings["mode"], settings["max_calls"],
                                 settings["log"], settings.get("db"), server), 6),
        "    toolCallTimeoutMs: %d" % TOOL_TIMEOUT_MS,
        "    failOnStartupError: true",
        "    reconnect:",
        "      enabled: false",
        # Keep this run's session log and caches with the run, not in ~/.dsh.
        "- id: session-persistence-jsonl",
        "  name: \"@deepseek-ai/dsh-session-persistence-jsonl\"",
        "  config:",
        "    root: %s" % _y(os.path.join(state, "sessions")),
        "    compression: none",
        "- id: storage-json",
        "  name: \"@deepseek-ai/dsh-storage-json\"",
        "  config:",
        "    root: %s" % _y(os.path.join(state, "storages")),
    ]
    if settings.get("model") or settings.get("effort"):
        rows += [
            "- id: agent-default-model",
            "  name: \"@deepseek-ai/dsh-agent-default-model\"",
            "  config:",
            "    provider: %s" % _y(settings.get("provider") or PROVIDER),
            "    model: %s" % _y(settings.get("model") or MODEL),
            "    reasoningEffort: %s" % _y(settings.get("effort") or EFFORT),
        ]
    if provider_rows:
        rows.append(provider_rows.rstrip("\n"))
    return "\n".join(rows) + "\n"


def fake_provider_rows(port, model="fake-model"):
    """Overlay rows that point the worker at fake_llm_server.py (doctor, tests)."""
    return "\n".join([
        "- id: llm-pi-ai",
        "  name: \"@deepseek-ai/dsh-llm-pi-ai\"",
        "  config:",
        "    providers:",
        "      fakeai:",
        "        displayName: fake",
        "        apiKeyEnv: REW_FAKE_LLM_KEY",
        "        api: openai-completions",
        "        baseURL: %s" % _y("http://127.0.0.1:%d/v1" % port),
        "        compat: {thinkingFormat: deepseek, supportsReasoningEffort: true}",
        "        defaultInput: [text]",
        "        models:",
        "          - id: %s" % _y(model),
        "            name: Fake",
        "            contextWindow: 100000",
        "            maxTokens: 8000",
        "            input: [text]",
        "            reasoningEfforts: {low: low, high: high, max: max}",
        "- id: agent-default-model",
        "  name: \"@deepseek-ai/dsh-agent-default-model\"",
        "  config:",
        "    provider: fakeai",
        "    model: %s" % _y(model),
        "    reasoningEffort: high",
    ]) + "\n"


# --------------------------------------------------------------------------
# event stream
# --------------------------------------------------------------------------

USAGE_KEYS = ("inputTokens", "outputTokens", "totalTokens", "cacheReadTokens",
              "cacheWriteTokens", "reasoningTokens")


def parse_events(lines):
    """Fold a dsh --json event stream into the outcome fields."""
    out = {"session": None, "final": None, "reason": None, "texts": [], "calls": [],
           "usage": {}, "steps": 0, "steps_without_usage": 0, "errors": [],
           "bad_lines": 0, "turn_end": None}
    by_id = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            out["bad_lines"] += 1
            continue
        if not isinstance(ev, dict):
            out["bad_lines"] += 1
            continue
        kind = ev.get("type")
        if kind == "session":
            out["session"] = out["session"] or ev.get("sessionId")
        elif kind == "text":
            out["texts"].append(ev.get("text") or "")
        elif kind == "tool_call":
            call = {"id": ev.get("callId"), "tool": ev.get("tool"),
                    "input": ev.get("input"), "status": None, "result": None,
                    "error": None}
            out["calls"].append(call)
            by_id[call["id"]] = call
        elif kind == "tool_result":
            call = by_id.get(ev.get("callId"))
            if call is None:            # result without a call: keep it visible
                call = {"id": ev.get("callId"), "tool": None, "input": None}
                out["calls"].append(call)
                by_id[call["id"]] = call
            call.update(status=ev.get("status"), result=ev.get("result"),
                        error=ev.get("error"))
        elif kind == "status":
            if ev.get("phase") == "step_end":
                out["steps"] += 1
                usage = ev.get("usage")
                if isinstance(usage, dict):
                    for key in USAGE_KEYS:
                        if isinstance(usage.get(key), (int, float)):
                            out["usage"][key] = out["usage"].get(key, 0) + usage[key]
                else:
                    out["steps_without_usage"] += 1
            elif ev.get("phase") == "turn_end":
                out["turn_end"] = ev.get("reason")
        elif kind == "final":
            out["final"] = ev.get("text")
            out["reason"] = ev.get("reason")
            out["session"] = ev.get("sessionId") or out["session"]
        elif kind == "error":
            out["errors"].append(ev.get("message") or json.dumps(ev))
    return out


# --------------------------------------------------------------------------
# composed config (dsh --dump-config)
# --------------------------------------------------------------------------

def parse_dump(text):
    """Rows of a --dump-config listing: {id: {"name", "disabled", "body"}}.

    The dump is YAML with one top-level `- id:` item per row. Only the fields
    the checks need are read; values stay as their YAML source text.
    """
    rows = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^- id: (\S+)\s*$", line)
        if m:
            current = {"name": None, "disabled": None, "body": []}
            rows[m.group(1)] = current
            continue
        if line.startswith("#") or line.startswith("- "):
            current = None
            continue
        if current is None:
            continue
        current["body"].append(line)
        m = re.match(r"^  (name|disabled): (.*)$", line)
        if m:
            current[m.group(1)] = m.group(2).strip().strip("'\"")
    for row in rows.values():
        row["body"] = "\n".join(row["body"])
    return rows


def config_problems(rows, expect_log=None, proxy=None, server=None, mcp_row="mcp-ida",
                    tool_rows=None):
    """What is wrong with a composed worker config.

    The defaults describe rew's profile; jsworker passes its own MCP row,
    server command and tool-row list.
    """
    proxy = proxy or PROXY
    server = server or SERVER
    tool_rows = TOOL_ROWS if tool_rows is None else tool_rows
    problems = []
    for rid in tool_rows:
        row = rows.get(rid)
        if row is not None and row["disabled"] != "true":
            problems.append("tool row %s is not disabled (disabled: %s)"
                            % (rid, row["disabled"]))
    for rid, row in rows.items():
        if rid in tool_rows or rid in TOOL_INFRA or row["disabled"] == "true":
            continue
        name = row["name"] or ""
        looks_like_tool = (rid.startswith("tool-") or "/dsh-tool-" in name
                           or name in TOOL_PACKAGES)
        if looks_like_tool:
            problems.append("row %s (%s) looks like a model-facing tool and is "
                            "enabled; add it to the profile patch and TOOL_ROWS"
                            % (rid, name))
        if name == MCP_CLIENT and rid != mcp_row:
            problems.append("extra MCP server row %s would give the worker more tools"
                            % rid)
    ida = rows.get(mcp_row)
    if ida is None:
        problems.append("no %s row" % mcp_row)
    else:
        body = ida["body"]
        if ida["disabled"] == "true":
            problems.append("%s row is disabled" % mcp_row)
        if not re.search(r"^\s+command: ['\"]?%s['\"]?\s*$" % re.escape(proxy), body, re.M):
            problems.append("%s does not start the guard proxy %s" % (mcp_row, proxy))
        if "serverName: %s" % server not in body and 'serverName: "%s"' % server not in body:
            problems.append("%s serverName is not %s" % (mcp_row, server))
        if expect_log and expect_log not in body.replace("\n", " "):
            problems.append("%s does not log to this run's log" % mcp_row)
    model = rows.get("agent-default-model")
    if model is None or "provider: %s" % PROVIDER not in model["body"] \
            or "model: %s" % MODEL not in model["body"]:
        problems.append("agent-default-model is not %s / %s" % (PROVIDER, MODEL))
    cred = rows.get("credentials")
    if cred is None or cred["disabled"] == "true":
        problems.append("the credentials store is disabled; the API key cannot resolve")
    return problems


# --------------------------------------------------------------------------
# the backend
# --------------------------------------------------------------------------

class DshBackend:
    name = "dsh"

    def __init__(self, dsh=None, profile=None, repo_patch=None, proxy=None, server=None,
                 tool_names=None, cli="rew", runs_dir=None):
        """The defaults are rew's; jsworker passes its own profile and MCP server."""
        self.dsh = dsh or DSH
        self.profile = profile or PROFILE
        self.repo_patch = repo_patch or REPO_PATCH
        self.proxy = proxy or PROXY
        self.server = server or SERVER
        self.tool_names = IDA_TOOL_NAMES if tool_names is None else set(tool_names)
        self.cli = cli
        self.runs_dir = runs_dir or os.path.join(os.path.dirname(HERE), "..", "tmp",
                                                 "rew-runs")

    # -- profile ---------------------------------------------------------------

    def wanted_patch(self):
        return render_patch(self.repo_patch, self.proxy)

    def version(self):
        try:
            p = subprocess.run([self.dsh, "--version"], capture_output=True, text=True,
                               timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, str(exc)
        if p.returncode != 0:
            return None, (p.stderr or p.stdout).strip()[-500:]
        return p.stdout.strip(), ""

    def problems(self):
        """Fast readiness check used before every run."""
        out = []
        if not os.access(self.dsh, os.X_OK):
            out.append("dsh not found at %s" % self.dsh)
        pdir = profile_dir(self.profile)
        if not os.path.isdir(pdir):
            return out + ["profile %s does not exist; run `%s setup`" % (pdir, self.cli)]
        try:
            with open(os.path.join(pdir, "package.json")) as fh:
                bundles = json.load(fh)["dsh"]["profile"]["bundles"]
        except (OSError, ValueError, KeyError, TypeError):
            bundles = None
        if bundles != TEMPLATE_BUNDLES:
            out.append("profile %s is not a %s profile (bundles %s); run `%s setup`"
                       % (pdir, TEMPLATE, bundles, self.cli))
        try:
            with open(os.path.join(pdir, "cordis.patch.yml"), "rb") as fh:
                installed = fh.read()
        except OSError:
            installed = None
        wanted = self.wanted_patch()
        if installed != wanted:
            out.append("profile patch %s differs from %s; run `%s setup`"
                       % (os.path.join(pdir, "cordis.patch.yml"), self.repo_patch, self.cli))
        if not os.access(self.proxy, os.X_OK):
            out.append("guard proxy %s is not executable" % self.proxy)
        return out

    def setup(self):
        """Create or refresh the profile from the repo patch. Idempotent."""
        actions = []
        pdir = profile_dir(self.profile)
        try:
            with open(os.path.join(pdir, "package.json")) as fh:
                bundles = json.load(fh)["dsh"]["profile"]["bundles"]
        except (OSError, ValueError, KeyError, TypeError):
            bundles = None
        if bundles != TEMPLATE_BUNDLES:
            # dsh's own initializer: a fresh copy of the shipped template.
            # --dump-config keeps it from booting anything.
            p = subprocess.run([self.dsh, self.profile, "--from-default-profile", TEMPLATE,
                                "--dump-config"], capture_output=True, text=True,
                               timeout=120)
            if p.returncode != 0:
                return {"ok": False, "actions": actions, "problems": [
                    "dsh could not create the profile: %s" % (p.stderr or p.stdout)[-800:]]}
            actions.append("created %s from the %s template" % (pdir, TEMPLATE))
        target = os.path.join(pdir, "cordis.patch.yml")
        wanted = self.wanted_patch()
        try:
            with open(target, "rb") as fh:
                current = fh.read()
        except OSError:
            current = None
        if current != wanted:
            tmp = target + ".rew-tmp"
            with open(tmp, "wb") as fh:
                fh.write(wanted)
            os.replace(tmp, target)
            actions.append("installed %s" % target)
        os.makedirs(self.runs_dir, exist_ok=True)
        problems = self.problems()
        return {"ok": not problems, "profile": pdir,
                "actions": actions or ["already up to date"], "problems": problems}

    def dump_config(self, patches=()):
        cmd = [self.dsh, self.profile]
        for patch in patches:
            cmd += ["--patch", patch]
        cmd.append("--dump-config")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout, p.stderr

    # -- running ---------------------------------------------------------------

    def write_overlay(self, settings, **kw):
        path = os.path.join(settings["run_dir"], "overlay.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(overlay_text(settings, **kw))
        return path

    def run(self, prompt, settings, timeout, session=None, tag="1", env=None):
        """One headless invocation. A resumed session must use the same work dir.

        dsh runs in settings["cwd"] when given, else in <run_dir>/work.
        """
        run_dir = settings["run_dir"]
        work = settings.get("cwd") or os.path.join(run_dir, "work")
        os.makedirs(work, exist_ok=True)
        overlay = os.path.join(run_dir, "overlay.yml")
        if not os.path.exists(overlay):
            self.write_overlay(settings)
        events_path = os.path.join(run_dir, "events-%s.jsonl" % tag)
        stderr_path = os.path.join(run_dir, "stderr-%s.txt" % tag)
        cmd = [self.dsh, self.profile, "--patch", overlay]
        # Test hook: extra overlays after the run's own (test_integration.py uses
        # it to swap in a fake model). The audit still checks what ran.
        for extra in filter(None, os.environ.get("REW_EXTRA_PATCH", "").split(os.pathsep)):
            cmd += ["--patch", extra]
        cmd += ["--json", "--permission-mode", "read-only", "--approval-policy", "never"]
        if session:
            cmd += ["--session-id", session]
        cmd.append("-")
        child_env = dict(os.environ if env is None else env,
                         DSH_PERMISSION_MODE="read-only", DSH_TELEMETRY_DISABLED="1")
        started = time.time()
        timed_out = False
        with open(events_path, "wb") as out, open(stderr_path, "wb") as err:
            try:
                p = subprocess.Popen(cmd, cwd=work, stdin=subprocess.PIPE, stdout=out,
                                     stderr=err, env=child_env, start_new_session=True)
            except OSError as exc:
                return self._outcome([], started, None, False, str(exc), events_path)

            def feed():
                try:
                    p.stdin.write(prompt.encode("utf-8"))
                    p.stdin.close()
                except OSError:
                    pass
            threading.Thread(target=feed, daemon=True).start()
            try:
                rc = p.wait(timeout=max(1, timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                rc = self._kill_group(p)
        with open(stderr_path, "rb") as fh:
            stderr = fh.read().decode("utf-8", "replace")
        with open(events_path, "rb") as fh:
            lines = fh.read().decode("utf-8", "replace").splitlines()
        return self._outcome(lines, started, rc, timed_out, stderr, events_path)

    @staticmethod
    def _kill_group(p):
        """Stop dsh and everything it started (the proxy, ida-mcp).

        SIGTERM first so ida-mcp can release its database lease; managed idalib
        workers run in their own session and are not touched.
        """
        for sig, grace in ((signal.SIGTERM, TERM_GRACE), (signal.SIGKILL, 10)):
            try:
                os.killpg(p.pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                return p.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                continue
        return p.poll()

    @staticmethod
    def _outcome(lines, started, rc, timed_out, stderr, events_path):
        out = parse_events(lines)
        out.update(exit=rc, timed_out=timed_out, seconds=round(time.time() - started, 1),
                   stderr=(stderr or "")[-2000:], events_path=events_path)
        return out

    # -- doctor ----------------------------------------------------------------

    def exposure_check(self):
        """Boot the real worker profile against a fake model and a fake ida
        server, and report which tools dsh offered the model and whether a
        call went through the proxy. No network, no IDA."""
        tmp = tempfile.mkdtemp(prefix="rew-doctor-")
        server = None
        try:
            script = os.path.join(tmp, "script.json")
            with open(script, "w") as fh:
                json.dump([
                    {"tool_calls": [{"name": "mcp__ida__execute_python",
                                     "arguments": {"code": "rekit.info()"}},
                                    {"name": "mcp__ida__execute_python",
                                     "arguments": {"code": "import os"}}]},
                    {"text": '{"status": "ok", "summary": "s", "findings": []}'}], fh)
            port_file = os.path.join(tmp, "port")
            server = subprocess.Popen([sys.executable, os.path.join(HERE, "fake_llm_server.py"),
                                       "--script", script, "--record", os.path.join(tmp, "llm"),
                                       "--port-file", port_file])
            for _ in range(100):
                if os.path.exists(port_file):
                    break
                time.sleep(0.05)
            with open(port_file) as fh:
                port = int(fh.read())
            settings = {"mode": "strict", "max_calls": 3, "run_dir": tmp,
                        "log": os.path.join(tmp, "guard.jsonl")}
            fake_mcp = [sys.executable, os.path.join(HERE, "fake_mcp_server.py")]
            self.write_overlay(settings, server=fake_mcp,
                               provider_rows=fake_provider_rows(port))
            env = dict(os.environ, REW_FAKE_LLM_KEY="fake")
            outcome = self.run("doctor exposure check", settings, 120, env=env)
            req = os.path.join(tmp, "llm", "request-000.json")
            offered = []
            if os.path.exists(req):
                with open(req) as fh:
                    body = json.load(fh)
                offered = sorted(t.get("function", {}).get("name")
                                 for t in body.get("tools") or [])
            log = []
            if os.path.exists(settings["log"]):
                with open(settings["log"]) as fh:
                    log = [json.loads(l) for l in fh if l.strip()]
            calls = [r for r in log if r.get("event") == "call"]
            problems = []
            if offered != sorted(self.tool_names):
                problems.append("dsh offered the model %s" % offered)
            if [c.get("allowed") for c in calls] != [True, False]:
                problems.append("proxy decisions %s, expected [true, false]"
                                % [c.get("allowed") for c in calls])
            if outcome["exit"] != 0:
                problems.append("dsh exit %s: %s" % (outcome["exit"],
                                                     outcome["stderr"][-300:]))
            return {"ok": not problems, "offered": offered, "problems": problems}
        except Exception as exc:
            return {"ok": False, "problems": ["%s: %s" % (type(exc).__name__, exc)]}
        finally:
            if server is not None:
                server.terminate()
                server.wait(5)
            shutil.rmtree(tmp, ignore_errors=True)

    def doctor(self):
        checks = []

        def add(name, ok, detail):
            checks.append({"check": name, "ok": bool(ok), "detail": detail})

        version, err = self.version()
        add("dsh", version is not None, version or err or "not found: %s" % self.dsh)
        problems = self.problems()
        add("profile", not problems, problems or profile_dir(self.profile))
        if os.path.isdir(profile_dir(self.profile)):
            with tempfile.TemporaryDirectory(prefix="rew-doctor-") as tmp:
                settings = {"mode": "strict", "max_calls": 25, "run_dir": tmp,
                            "log": os.path.join(tmp, "guard.jsonl"),
                            "db": "/nonexistent/doctor.bin"}
                overlay = self.write_overlay(settings)
                rc, out, err = self.dump_config([overlay])
                if rc != 0:
                    add("composed config", False, "dump-config exit %s: %s" % (rc, err[-500:]))
                else:
                    cp = config_problems(parse_dump(out), expect_log=settings["log"],
                                         proxy=self.proxy, server=self.server)
                    add("composed config", not cp, cp or "%d tool rows disabled; "
                        "mcp-ida -> guard proxy" % len(TOOL_ROWS))
        try:
            p = subprocess.run([sys.executable, self.proxy, "--self-test"], capture_output=True,
                               text=True, timeout=60)
            res = json.loads(p.stdout or "{}")
            add("proxy self-test", p.returncode == 0 and res.get("ok"),
                res.get("failures") or "ok")
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            add("proxy self-test", False, str(exc))
        if not any(c["check"] == "composed config" and not c["ok"] for c in checks) \
                and os.path.isdir(profile_dir(self.profile)):
            exp = self.exposure_check()
            add("tools offered to the model", exp["ok"],
                exp["problems"] or exp.get("offered"))
        add("ida-mcp", os.access(IDA_MCP, os.X_OK), IDA_MCP)
        return checks
