"""A scripted stand-in for an LLM, speaking the OpenAI Responses API.

The Codex CLI counterpart of mock_llm.py, with the same contract: one turn per
scripted shell command, returned as a call to the agent's own shell tool, and
every tool output the agent sends back is logged as
{"result_of": n, "output": ...}. The real agent runs the commands with ITS OWN
tool execution and ITS OWN network stack.

  python3 mock_responses.py PORT COMMANDS_FILE LOG_FILE
"""
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
cmds = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")]
log = open(sys.argv[3], "a", buffering=1)
state = {"seen_tools": False, "logged": set()}
lock = threading.Lock()

# The shell tool the agent offers, in order of preference, and how to call it.
SHELLS = [
    ("shell_command", lambda c: {"command": c, "timeout_ms": 120000}),
    ("shell", lambda c: {"command": ["bash", "-lc", c], "timeout_ms": 120000}),
    ("exec_command", lambda c: {"cmd": c, "yield_time_ms": 120000}),
]


def emit(obj):
    log.write(json.dumps(obj) + "\n")


def text_of(output):
    """A function_call_output is a string, a JSON-encoded {"output": ...}, or a
    list of content parts."""
    if isinstance(output, list):
        return "\n".join(p.get("text", "") for p in output if isinstance(p, dict))
    if isinstance(output, str):
        try:
            o = json.loads(output)
            if isinstance(o, dict) and isinstance(o.get("output"), str):
                return o["output"]
        except ValueError:
            pass
        return output
    return json.dumps(output)


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
        self._json(200, {"object": "list", "data": [{"id": "m", "object": "model"}], "models": []})

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

    def reply(self, body, item):
        rid = "resp_mock_%d" % len(state["logged"])
        resp = {"id": rid, "object": "response", "status": "completed", "model": body.get("model", "m"),
                "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                                            "input_tokens_details": {"cached_tokens": 0},
                                            "output_tokens_details": {"reasoning_tokens": 0}}}
        if not body.get("stream"):
            return self._json(200, resp)
        self._sse([
            {"type": "response.created", "response": dict(resp, status="in_progress", output=[])},
            {"type": "response.output_item.added", "output_index": 0, "item": item},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": resp},
        ])

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        tools = body.get("tools") or []
        names = [t.get("name") or t.get("type") for t in tools]
        shell = next(((nm, mk) for nm, mk in SHELLS if nm in names), None)
        if shell is None:                     # helper calls (titles, summaries)
            return self.reply(body, {"type": "message", "id": "msg_mock", "role": "assistant", "status": "completed",
                                     "content": [{"type": "output_text", "text": "ok", "annotations": []}]})
        with lock:
            if not state["seen_tools"]:
                state["seen_tools"] = True
                emit({"tools": names, "using": shell[0]})
            items = [it for it in (body.get("input") or []) if isinstance(it, dict)]
            calls = 0                         # shell calls the agent has made so far
            total = 0                         # every function call, for unique ids
            for it in items:
                if it.get("type") == "function_call":
                    total += 1
                    if it.get("name") == shell[0]:
                        calls += 1
                if it.get("type") == "function_call_output":
                    cid = it.get("call_id", "")
                    if cid not in state["logged"]:
                        state["logged"].add(cid)
                        parts = cid.split("_")
                        idx = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else cid
                        emit({"result_of": idx, "output": text_of(it.get("output"))})
            # A command still running after the yield window (Codex's
            # exec_command) is polled through write_stdin until it exits.
            last = items[-1] if items else {}
            if last.get("type") == "function_call_output":
                m = re.search(r"Process running with session ID (\d+)", text_of(last.get("output")))
                if m and "write_stdin" in names:
                    item = {"type": "function_call", "id": "fc_mock_%d_%d" % (calls - 1, total),
                            "call_id": "call_mock_%d_%d" % (calls - 1, total), "name": "write_stdin",
                            "arguments": json.dumps({"session_id": int(m.group(1)), "chars": "", "yield_time_ms": 30000}),
                            "status": "completed"}
                    return self.reply(body, item)
            # the turn comes from the history, so a retried request gets the
            # same command again instead of skipping one
            i = calls
            if i < len(cmds):
                emit({"turn": i, "command": cmds[i]})
                item = {"type": "function_call", "id": "fc_mock_%d_%d" % (i, total), "call_id": "call_mock_%d_%d" % (i, total),
                        "name": shell[0], "arguments": json.dumps(shell[1](cmds[i])), "status": "completed"}
                return self.reply(body, item)
            emit({"finished": True})
        return self.reply(body, {"type": "message", "id": "msg_mock_done", "role": "assistant", "status": "completed",
                                 "content": [{"type": "output_text", "text": "DONE", "annotations": []}]})


ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
