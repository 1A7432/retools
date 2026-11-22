#!/usr/bin/env python3
"""A scripted OpenAI-compatible chat-completions endpoint, for offline dsh runs.

    fake_llm_server.py --script SCRIPT.json --record DIR [--port-file FILE]

SCRIPT.json is a list of replies, used in order, one per request:
    {"text": "...", "reasoning": "..."}                      a final answer
    {"tool_calls": [{"name": "mcp__ida__execute_python",
                     "arguments": {"code": "rekit.info()"}}]}  tool calls
When the script runs out, the last reply is repeated. Each request body is
saved to DIR/request-NNN.json so a test can inspect the tools and messages dsh
sent. The chosen port is written to --port-file once the server listens.
"""

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", required=True)
    ap.add_argument("--record", required=True)
    ap.add_argument("--port-file", required=True)
    opts = ap.parse_args()
    with open(opts.script) as fh:
        script = json.load(fh)
    os.makedirs(opts.record, exist_ok=True)
    state = {"n": 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"object": "list", "data": [
                {"id": "fake-model", "object": "model"}]}).encode())

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            with lock:
                n = state["n"]
                state["n"] += 1
            with open(os.path.join(opts.record, "request-%03d.json" % n), "wb") as fh:
                fh.write(body)
            reply = script[min(n, len(script) - 1)] if script else {"text": "{}"}
            req = json.loads(body or b"{}")
            chunks = []
            base = {"id": "fake-%d" % n, "object": "chat.completion.chunk",
                    "created": 0, "model": req.get("model", "fake")}

            def chunk(delta, finish=None, usage=None):
                c = dict(base, choices=[{"index": 0, "delta": delta,
                                         "finish_reason": finish}])
                if usage:
                    c["usage"] = usage
                chunks.append(c)

            chunk({"role": "assistant", "content": ""})
            if reply.get("reasoning"):
                chunk({"reasoning_content": reply["reasoning"]})
            if reply.get("tool_calls"):
                for i, call in enumerate(reply["tool_calls"]):
                    chunk({"tool_calls": [{"index": i, "id": "call_%d_%d" % (n, i),
                                           "type": "function", "function": {
                                               "name": call["name"],
                                               "arguments": json.dumps(call.get("arguments", {}))}}]})
                finish = "tool_calls"
            else:
                chunk({"content": reply.get("text", "")})
                finish = "stop"
            chunk({}, finish)
            usage = {"prompt_tokens": 100 + n, "completion_tokens": 10,
                     "total_tokens": 110 + n}
            chunks.append(dict(base, choices=[], usage=usage))
            if not req.get("stream"):
                self.send_response(500)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for c in chunks:
                self.wfile.write(b"data: " + json.dumps(c).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(opts.port_file + ".tmp", "w") as fh:
        fh.write(str(server.server_address[1]))
    os.rename(opts.port_file + ".tmp", opts.port_file)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
