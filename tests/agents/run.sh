#!/usr/bin/env bash
# Run real agents behind a real Ovara, driven by a scripted mock model.
#
#   tests/agents/run.sh coop [AGENT]      cooperative mode (ovara env only)
#   tests/agents/run.sh enforced [AGENT]  inside a netns boundary as an
#                                         unprivileged user (needs --privileged)
#   tests/agents/run.sh box [AGENT]       through `ovara box` (needs --privileged)
#   tests/agents/run.sh harness           a custom agent harness against the
#                                         gateway's decision API (SDK + agent token)
#
# AGENT is opencode (default), anthropic or codex.
#
# Needs Docker and outbound internet. It builds the checked-out commit inside
# a Linux container, so it tests what is committed, not your working tree
# (the test scripts themselves are read from the working tree).
set -euo pipefail
what="${1:-coop}"
agent="${2:-opencode}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# Git Bash on Windows: hand Docker a Windows path and stop MSYS rewriting /repo.
if command -v cygpath >/dev/null 2>&1; then repo="$(cygpath -w "$repo")"; here="$(cygpath -w "$here")"; export MSYS_NO_PATHCONV=1; fi

case "$what" in
  coop|enforced|box)
    case "$agent" in opencode|anthropic|codex) ;; *) echo "unknown agent: $agent" >&2; exit 2 ;; esac
    script=$agent.sh; expect='^RESULT\[.*\]: [0-9]+ passed, 0 failed' ;;
  harness)       script=harness.sh;  expect='^HARNESS_RESULT [0-9]+ passed 0 failed' ;;
  *) echo "usage: $0 coop|enforced|box|harness [opencode|anthropic|codex]" >&2; exit 2 ;;
esac
flags=()
[ "$what" = enforced ] || [ "$what" = box ] && flags+=(--privileged)

docker build -q -t ovara-agents "$here" >/dev/null
out="$(docker run --rm ${flags[@]+"${flags[@]}"} -e MODE="$what" -v "$repo:/repo:ro" ovara-agents \
  bash -c "tr -d '\r' < /repo/tests/agents/$script > /tmp/t.sh && bash /tmp/t.sh" 2>&1)" || true
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -Eq "$expect" || { echo "agent test ($what${script:+ $script}) failed" >&2; exit 1; }
