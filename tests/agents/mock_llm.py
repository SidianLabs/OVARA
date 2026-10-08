"""A scripted stand-in for an LLM, speaking the OpenAI chat-completions API.

Real agents need a model to drive them. This returns, one per turn, the next
shell command from a script as a tool call, so a REAL agent (opencode, ...) runs
those commands with ITS OWN tool execution and ITS OWN network stack, and the
results it gets back are logged. That exercises exactly what matters for Ovara:
how the real agent's traffic and subprocesses behave behind the proxy.

  python3 mock_llm.py PORT COMMANDS_FILE LOG_FILE
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
cmds = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")]
log = open(sys.argv[3], "a", buffering=1)
state = {"i": 0, "seen_tools": False}


def emit(obj):
    log.write(json.dumps(obj) + "\n")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._json(200, {"object": "list", "data": [{"id": "m", "object": "model"}]})

    def _sse(self, chunks):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        for c in chunks:
            self.wfile.write(b"data: " + json.dumps(c).encode() + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    @staticmethod
    def _chunk(delta, finish=None):
        return {"id": "mock", "object": "chat.completion.chunk", "created": 0, "model": "m",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}

    def text(self, body, content):
        if body.get("stream"):
            self._sse([self._chunk({"role": "assistant", "content": content}),
                       self._chunk({}, "stop")])
        else:
            self._json(200, {"id": "mock", "object": "chat.completion", "created": 0, "model": "m",
                             "choices": [{"index": 0, "finish_reason": "stop",
                                          "message": {"role": "assistant", "content": content}}]})

    def tool(self, body, name, args):
        call = {"id": "call_%d" % state["i"], "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)}}
        if body.get("stream"):
            self._sse([
                self._chunk({"role": "assistant", "tool_calls": [dict(call, index=0, function={"name": name, "arguments": ""})]}),
                self._chunk({"tool_calls": [{"index": 0, "function": {"arguments": json.dumps(args)}}]}),
                self._chunk({}, "tool_calls"),
            ])
        else:
            self._json(200, {"id": "mock", "object": "chat.completion", "created": 0, "model": "m",
                             "choices": [{"index": 0, "finish_reason": "tool_calls",
                                          "message": {"role": "assistant", "content": None, "tool_calls": [call]}}]})

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        msgs = body.get("messages", [])
        tools = body.get("tools") or []
        if not state["seen_tools"] and tools:
            state["seen_tools"] = True
            emit({"tools": [t.get("function", {}).get("name") for t in tools]})
        last = msgs[-1] if msgs else {}
        if last.get("role") == "tool":
            emit({"result_of": state["i"] - 1, "output": last.get("content")})
        if not tools:                       # helper calls (titles, summaries)
            return self.text(body, "ok")
        if state["i"] < len(cmds):
            cmd = cmds[state["i"]]
            state["i"] += 1
            names = [t.get("function", {}).get("name") for t in tools]
            name = "bash" if "bash" in names else next((x for x in names if x and "bash" in x.lower()), "bash")
            emit({"turn": state["i"] - 1, "command": cmd})
            return self.tool(body, name, {"command": cmd, "description": "run"})
        emit({"finished": True})
        return self.text(body, "DONE")


ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
