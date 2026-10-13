set -u
# Real Codex CLI, driven by a scripted mock model (OpenAI Responses API,
# mock_responses.py), behind a real Ovara. The commands and checks are in
# battery.sh, the same ones opencode and Anthropic's agent CLI run.
#   MODE=coop       cooperative: the agent is only ASKED to use the proxy
#   MODE=enforced   netns boundary, agent runs as an unprivileged user inside it
AGENT=codex

prepare_agent() {
  # In a box every program is checked, and Ovara's default policy pauses an
  # agent started with its own approvals and sandbox turned off. This test
  # starts Codex that way on purpose (above all of it is Ovara), so it says
  # so in the policy, as an operator would: Codex with that flag may start.
  if [ "$MODE" = box ] || [ "$MODE" = box2 ]; then
    python3 - <<'PY'
import json
p = json.load(open('/tmp/d/policy.json'))
p['rules'].insert(0, {"action_type": "shell", "environment": "*",
    "resource": "shell:*codex*--dangerously-bypass-approvals-and-sandbox*", "allow": True,
    "description": "test harness: Codex is started with its own sandbox off, on purpose"})
json.dump(p, open('/tmp/d/policy.json', 'w'), indent=2)
PY
  fi
  mkdir -p /tmp/home/.codex
  cat > /tmp/home/.codex/config.toml <<'EOF'
model = "m"
model_provider = "mock"
check_for_update_on_startup = false

[model_providers.mock]
name = "mock"
base_url = "http://127.0.0.1:9100/v1"
wire_api = "responses"
env_key = "MOCK_API_KEY"
EOF
}

launch_agent() {
  start_mock mock_responses.py
  # Codex's own sandbox is turned off: this measures what Ovara does, so the
  # agent's commands must actually be allowed to try.
  run_agent "export CODEX_HOME=\$HOME/.codex MOCK_API_KEY=x; \
timeout 900 codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox 'run the commands'"
}

source <(tr -d '\r' < /repo/tests/agents/battery.sh)
