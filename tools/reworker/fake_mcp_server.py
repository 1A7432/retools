#!/usr/bin/env python3
"""A stand-in for `ida-mcp stdio`, for testing guardproxy.py and rew offline.

It speaks newline-delimited JSON-RPC, lists the six ida-mcp tools, and answers
tools/call with canned text that contains a few addresses. Options:

    --record PATH        append every frame it receives to PATH
    --die-after N        exit abruptly after answering N tools/call requests
    --garbage-after N    write a non-JSON line after answering N tools/call
    --answer-id ID       also send an unsolicited result for request id ID
                         (to check that the proxy refuses to relay it)
    --big N              make execute_python results N characters long
"""

import argparse
import json
import sys

TOOLS = ["open_database", "execute_python", "reference", "list_databases",
         "save_database", "close_database"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record")
    ap.add_argument("--die-after", type=int)
    ap.add_argument("--garbage-after", type=int)
    ap.add_argument("--answer-id")
    ap.add_argument("--big", type=int, default=0)
    opts, _ = ap.parse_known_args()   # accepts ida-mcp's `stdio --agent=...`
    calls = 0

    def send(msg):
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        if opts.record:
            with open(opts.record, "a") as fh:
                fh.write(json.dumps(msg) + "\n")
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-ida", "version": "0"}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": n, "description": "fake " + n,
                 "inputSchema": {"type": "object", "properties": {}}} for n in TOOLS]}})
        elif method == "tools/call":
            calls += 1
            name = msg["params"]["name"]
            args = msg["params"].get("arguments") or {}
            if name == "execute_python":
                # shaped like ida-mcp: the snippet's value under "result"
                text = json.dumps({"result": {
                    "code": args.get("code"), "fn": "sub_401000",
                    "callees": ["sub_402A10", "0x40f3c0"],
                    "buffers": {"total": 1, "top": [{"name": "out", "hex":
                                                     "00112233445566778899aabbccddeeff"}]}},
                    "stdout": "", "stderr": ""})
                if opts.big:
                    text += " " + "A" * opts.big + " sub_4BEEF0"
            elif name == "open_database":
                text = json.dumps({"opened": args.get("path"), "instance_id": "fake-1"})
            else:
                text = "%s ok" % name
            result = {"content": [{"type": "text", "text": text}], "isError": False}
            if name == "execute_python" and not opts.big:
                result["structuredContent"] = json.loads(text)
            send({"jsonrpc": "2.0", "id": mid, "result": result})
            if opts.answer_id is not None:
                send({"jsonrpc": "2.0", "id": json.loads(opts.answer_id), "result": {
                    "content": [{"type": "text", "text": "leaked"}]}})
            if opts.garbage_after is not None and calls >= opts.garbage_after:
                sys.stdout.write("this is not json\n")
                sys.stdout.flush()
            if opts.die_after is not None and calls >= opts.die_after:
                sys.exit(3)
        elif mid is not None and method is not None:
            send({"jsonrpc": "2.0", "id": mid, "result": {}})


if __name__ == "__main__":
    main()
