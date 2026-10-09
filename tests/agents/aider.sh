set -u
# Real Aider, driven by a scripted mock model (OpenAI chat API,
# mock_aider.py), behind a real Ovara. The commands and checks are in
# battery.sh, the same ones the other agents run.
#
# Aider proposes shell commands in its reply and runs them only after a
# person says yes (--yes-always deliberately does not cover shell commands),
# so a simulated person answers yes to every question. Each command's
# printed output is read back as the battery's results.
#   MODE=coop|enforced|box|box2 as in battery.sh
AGENT=aider

prepare_agent() { :; }

launch_agent() {
  start_mock mock_aider.py
  # no repo map, no git changes, history outside the project: Aider leaves
  # the workspace as it found it, so there is nothing to bring back
  run_agent "export OPENAI_API_KEY=placeholder OPENAI_API_BASE=http://127.0.0.1:9100/v1 LITELLM_LOCAL_MODEL_COST_MAP=True; \
yes y | timeout 900 aider --model openai/gpt-4o --message 'run the checks' --no-pretty --no-stream \
  --no-check-update --no-show-model-warnings --no-analytics --no-auto-commits --no-git --map-tokens 0 \
  --chat-history-file /tmp/aider.chat.md --input-history-file /tmp/aider.input --no-restore-chat-history"
  python3 - <<'PY' >> /tmp/mock.log
import json, re
out = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', open('/tmp/agent.out', errors='replace').read())
lines = [l.strip() for l in out.splitlines() if re.match(r'^\s*[A-Z]\d+ \S', l)]
print(json.dumps({"output": "\n".join(lines)}))
PY
}

source <(tr -d '\r' < /repo/tests/agents/battery.sh)
