"""A scripted stand-in for an LLM for Aider, speaking the OpenAI chat API.

Aider does not call tools: it reads shell commands out of fenced ```bash
blocks in the model's reply and runs each line after a person says yes. So
the first reply holds the whole battery in one block; any later request gets
"Done.". The commands run through Aider's own shell runner and network stack
behind Ovara; their printed output is turned into the battery's result log
by aider.sh.

  python3 mock_aider.py PORT COMMANDS_FILE LOG_FILE
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
cmds = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")]
log = open(sys.argv[3], "a", buffering=1)
state = {"n": 0}


def emit(obj):
    log.write(json.dumps(obj) + "\n")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = json.dumps({"object": "list", "data": [{"id": "gpt-4o", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        state["n"] += 1
        if state["n"] == 1:
            emit({"turn": 0, "commands": len(cmds)})
            text = "Running the checks.\n\n```bash\n" + "\n".join(cmds) + "\n```\n"
        else:
            emit({"finished": True})
            text = "Done."
        now = int(time.time())
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            chunk = {"id": "m", "object": "chat.completion.chunk", "created": now, "model": "gpt-4o",
                     "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]}
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            chunk["choices"][0]["delta"] = {}
            chunk["choices"][0]["finish_reason"] = "stop"
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\ndata: [DONE]\n\n")
            return
        b = json.dumps({"id": "m", "object": "chat.completion", "created": now, "model": "gpt-4o",
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
