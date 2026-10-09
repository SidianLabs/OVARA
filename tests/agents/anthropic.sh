set -u
# Real Anthropic's agent CLI, driven by a scripted mock model (Anthropic Messages API,
# mock_anthropic.py, via ANTHROPIC_BASE_URL), behind a real Ovara. The commands
# and checks are in battery.sh, the same ones opencode runs.
#   MODE=coop       cooperative: the agent is only ASKED to use the proxy
#   MODE=enforced   netns boundary, agent runs as an unprivileged user inside it
AGENT=anthropic

prepare_agent() {
  # skip the first-run onboarding; the key is a placeholder the mock ignores
  echo '{"hasCompletedOnboarding": true}' > /tmp/home/.claude.json
}

launch_agent() {
  start_mock mock_anthropic.py
  # IS_SANDBOX lets bypassPermissions run as root in cooperative mode; in
  # enforced mode the agent is an unprivileged user anyway. Nonessential
  # traffic (telemetry, update checks) is off so the run is deterministic.
  run_agent "export ANTHROPIC_BASE_URL=http://127.0.0.1:9100 ANTHROPIC_API_KEY=sk-ant-mock IS_SANDBOX=1 \
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1 BASH_DEFAULT_TIMEOUT_MS=120000; \
timeout 900 claude -p 'run the commands' --model mock --permission-mode bypassPermissions --max-turns 100"
}

source <(tr -d '\r' < /repo/tests/agents/battery.sh)
