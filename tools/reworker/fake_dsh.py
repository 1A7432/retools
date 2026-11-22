#!/usr/bin/env python3
"""A stand-in for the dsh CLI, for testing rew without a model or IDA.

    REW_DSH=fake_dsh.py FAKE_DSH_SCENARIO=scenario.json rew run ...

It understands `--version`, `<profile> --from-default-profile T --dump-config`
(creates the profile directory under $DSH_HOME the way dsh does), and a
headless run. A run plays the next attempt of the scenario:

    {"attempts": [
      {"steps": [
         {"call": "mcp__ida__execute_python", "input": {...}, "result": "text",
          "proxy": "allowed" | "refused" | "none" | "leak",
          "status": "completed" | "error", "error": {...}},
         {"text": "the reply"}],
       "exit": 0, "sleep": 0, "usage": true}]}

`proxy` says what the fake writes to the guard log named in the overlay:
allowed (relayed and answered; execute_python gets the next `call_no`),
refused (answered by the guard), none (no record, as if the proxy were
bypassed) or leak (refused yet answered by ida-mcp). Every invocation is
appended to <scenario>.calls.jsonl.
"""

import json
import os
import sys
import time


def overlay_args(path):
    """The mcp-ida args list of a rew overlay (one JSON scalar per line)."""
    args, inside = [], False
    with open(path) as fh:
        for line in fh:
            if line.strip() == "args:":
                inside = True
                continue
            if inside:
                if line.lstrip().startswith("- "):
                    args.append(json.loads(line.strip()[2:]))
                else:
                    break
    return args


def main():
    argv = sys.argv[1:]
    if argv == ["--version"]:
        print("0.0.0-fake")
        return 0
    profile = argv[0]
    home = os.environ.get("DSH_HOME") or os.path.expanduser("~/.dsh")
    if "--from-default-profile" in argv:
        pdir = os.path.join(home, "profiles", profile)
        os.makedirs(pdir, exist_ok=True)
        with open(os.path.join(pdir, "package.json"), "w") as fh:
            json.dump({"name": "dsh-profile-" + profile, "private": True, "dependencies": {},
                       "dsh": {"profile": {"bundles": ["@deepseek-ai/dsh-base",
                                                       "@deepseek-ai/dsh-headless"]}}}, fh)
        with open(os.path.join(pdir, "cordis.patch.yml"), "w") as fh:
            fh.write("[]\n")
        print("# fake dump")
        return 0
    if "--dump-config" in argv:
        print("# fake dump")
        return 0

    scenario_path = os.environ["FAKE_DSH_SCENARIO"]
    with open(scenario_path) as fh:
        scenario = json.load(fh)
    counter = scenario_path + ".count"
    n = int(open(counter).read()) if os.path.exists(counter) else 0
    with open(counter, "w") as fh:
        fh.write(str(n + 1))
    prompt = sys.stdin.read()
    session = argv[argv.index("--session-id") + 1] if "--session-id" in argv else "session-fake-1"
    overlay = argv[argv.index("--patch") + 1]
    with open(scenario_path + ".calls.jsonl", "a") as fh:
        fh.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "cwd_files": os.listdir("."),
                             "prompt": prompt,
                             "perm": os.environ.get("DSH_PERMISSION_MODE"),
                             "overlay": open(overlay).read()}) + "\n")
    args = overlay_args(overlay)
    log = args[args.index("--log") + 1]
    mode = args[args.index("--mode") + 1]
    max_calls = int(args[args.index("--max-calls") + 1])
    attempt = scenario["attempts"][min(n, len(scenario["attempts"]) - 1)]

    def emit(ev):
        sys.stdout.write(json.dumps(ev) + "\n")
        sys.stdout.flush()

    def proxy_log(rec):
        with open(log, "a") as fh:
            fh.write(json.dumps(rec) + "\n")

    proxy_log({"event": "start", "mode": attempt.get("proxy_mode", mode),
               "max_calls": max_calls})
    emit({"type": "session", "sessionId": session, "cwd": os.getcwd()})
    print("this line is not JSON")
    emit({"type": "status", "phase": "turn_start", "turn": n + 1})
    reply = ""
    for i, step in enumerate(attempt["steps"]):
        emit({"type": "status", "phase": "step_start", "turn": n + 1, "step": i + 1})
        if "call" in step:
            cid = "call_%d_%d" % (n, i)
            tool = step["call"]
            emit({"type": "tool_call", "callId": cid, "tool": tool,
                  "input": step.get("input", {})})
            raw = tool.split("__")[-1]
            behaviour = step.get("proxy", "allowed")
            result = step.get("result", "ok")
            if behaviour == "allowed":
                rec = {"event": "call", "tool": raw, "arguments": step.get("input", {}),
                       "allowed": True, "reason": "", "result": result,
                       "is_error": step.get("status") == "error", "source": "ida-mcp"}
                if raw == "execute_python":      # numbered like the real proxy
                    with open(log) as fh:
                        rec["call_no"] = 1 + sum(
                            1 for l in fh if '"execute_python"' in l and '"allowed": true' in l)
                proxy_log(rec)
            elif behaviour in ("refused", "leak"):
                proxy_log({"event": "call", "tool": raw, "arguments": step.get("input", {}),
                           "allowed": False, "reason": "refused: test", "result": result,
                           "is_error": True,
                           "source": "guard" if behaviour == "refused" else "ida-mcp"})
            res = {"type": "tool_result", "callId": cid,
                   "status": step.get("status", "completed"),
                   "result": result[:8192]}
            if step.get("error"):
                res["error"] = step["error"]
            emit(res)
        else:
            reply = step["text"]
            emit({"type": "text", "text": reply})
        if attempt.get("sleep") and i == len(attempt["steps"]) - 1:
            time.sleep(attempt["sleep"])
        end = {"type": "status", "phase": "step_end", "turn": n + 1, "step": i + 1}
        if attempt.get("usage", True):
            end["usage"] = {"inputTokens": 1000, "outputTokens": 50, "totalTokens": 1050,
                            "reasoningTokens": 20}
        emit(end)
    code = attempt.get("exit", 0)
    reason = {"kind": "completed" if code == 0 else "error"}
    emit({"type": "status", "phase": "turn_end", "turn": n + 1, "reason": reason})
    if not attempt.get("no_final"):
        emit({"type": "final", "sessionId": session, "reason": reason, "text": reply})
    return code


if __name__ == "__main__":
    sys.exit(main())
