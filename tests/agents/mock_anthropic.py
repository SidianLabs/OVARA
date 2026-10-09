"""A scripted stand-in for an LLM, speaking the Anthropic Messages API.

The Anthropic's agent CLI counterpart of mock_llm.py, with the same contract: one turn
per scripted shell command, returned as a tool_use for the agent's own shell
tool (Bash), and every tool_result the agent sends back is logged as
{"result_of": n, "output": ...}. The real agent runs the commands with ITS OWN
tool execution and ITS OWN network stack.

  python3 mock_anthropic.py PORT COMMANDS_FILE LOG_FILE
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
cmds = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")]
log = open(sys.argv[3], "a", buffering=1)
state = {"i": 0, "seen_tools": False, "logged": set()}
lock = threading.Lock()


def emit(obj):
    log.write(json.dumps(obj) + "\n")


def flatten(content):
    """tool_result content is a string or a list of blocks."""
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if isinstance(b, dict) and b.get("type") == "text":
            out.append(b.get("text", ""))
    return "\n".join(out)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

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
        self._json(200, {"data": [{"id": "mock", "type": "model", "display_name": "mock"}],
                         "has_more": False, "first_id": "mock", "last_id": "mock"})

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def _sse(self, events):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        for ev in events:
            self.wfile.write(("event: %s\ndata: %s\n\n" % (ev["type"], json.dumps(ev))).encode())
            self.wfile.flush()
        self.close_connection = True

    @staticmethod
    def _message(model, content, stop):
        return {"id": "msg_mock_%d" % state["i"], "type": "message", "role": "assistant", "model": model,
                "content": content, "stop_reason": stop, "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1}}

    def reply(self, body, block, stop):
        model = body.get("model", "mock")
        if not body.get("stream"):
            return self._json(200, self._message(model, [block], stop))
        start = dict(block)
        if block["type"] == "tool_use":
            start["input"] = {}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
        else:
            start["text"] = ""
            delta = {"type": "text_delta", "text": block["text"]}
        self._sse([
            {"type": "message_start", "message": self._message(model, [], None)},
            {"type": "content_block_start", "index": 0, "content_block": start},
            {"type": "content_block_delta", "index": 0, "delta": delta},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
             "usage": {"output_tokens": 1}},
            {"type": "message_stop"},
        ])

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path.split("?")[0].endswith("/count_tokens"):
            return self._json(200, {"input_tokens": 1})
        tools = body.get("tools") or []
        names = [t.get("name") for t in tools]
        if "Bash" not in names:              # helper calls (titles, topic checks, quota probes)
            return self.reply(body, {"type": "text", "text": "ok"}, "end_turn")
        with lock:
            if not state["seen_tools"]:
                state["seen_tools"] = True
                emit({"tools": names})
            msgs = body.get("messages", [])
            last = msgs[-1] if msgs else {}
            if last.get("role") == "user" and isinstance(last.get("content"), list):
                for b in last["content"]:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        tid = b.get("tool_use_id", "")
                        if tid not in state["logged"]:
                            state["logged"].add(tid)
                            emit({"result_of": int(tid.rsplit("_", 1)[-1]) if tid.rsplit("_", 1)[-1].isdigit() else tid,
                                  "output": flatten(b.get("content"))})
            # the turn comes from the history, so a retried request gets the
            # same command again instead of skipping one
            answered = sum(1 for m in msgs if m.get("role") == "assistant"
                           and any(isinstance(c, dict) and c.get("type") == "tool_use" for c in (m.get("content") or [])))
            state["i"] = answered
            if state["i"] < len(cmds):
                i = state["i"]
                state["i"] += 1
                emit({"turn": i, "command": cmds[i]})
                block = {"type": "tool_use", "id": "toolu_mock_%d" % i, "name": "Bash",
                         "input": {"command": cmds[i], "description": "run", "timeout": 120000}}
                return self.reply(body, block, "tool_use")
            emit({"finished": True})
        return self.reply(body, {"type": "text", "text": "DONE"}, "end_turn")


ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
