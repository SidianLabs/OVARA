set -u
# Real opencode, driven by a scripted mock model (OpenAI chat-completions,
# mock_llm.py), behind a real Ovara. The commands and checks are in battery.sh.
#   MODE=coop       cooperative: the agent is only ASKED to use the proxy
#   MODE=enforced   netns boundary, agent runs as an unprivileged user inside it
AGENT=opencode

prepare_agent() {
  mkdir -p /tmp/proj/.opencode
  cat > /tmp/proj/opencode.json <<'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "autoupdate": false,
  "share": "disabled",
  "permission": { "bash": "allow", "edit": "allow", "external_directory": "allow" },
  "provider": { "mock": { "npm": "@ai-sdk/openai-compatible", "name": "Mock",
    "options": { "baseURL": "http://127.0.0.1:9100/v1", "apiKey": "x" },
    "models": { "m": { "name": "m" } } } },
  "model": "mock/m"
}
EOF
}

launch_agent() {
  start_mock mock_llm.py
  run_agent "timeout 600 opencode run -m mock/m 'run the commands'"
}

source <(tr -d '\r' < /repo/tests/agents/battery.sh)
