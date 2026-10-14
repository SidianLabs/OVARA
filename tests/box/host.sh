#!/usr/bin/env bash
# Tier 2 (`ovara box -tier 2`) tests. They need Docker, so they run on the
# host as root rather than in a test container, and they CHANGE THIS
# MACHINE: a /repo link, /work, /tmp/proj, /var/lib/ovara/runs, docker
# images, networks and iptables rules. Run them on a disposable machine (CI
# does) and say so with OVARA_TEST_ON_HOST=1.
#
#   OVARA_TEST_ON_HOST=1 tests/box/host.sh box              the box test (tests/box/box.sh, TIER=2)
#   OVARA_TEST_ON_HOST=1 tests/box/host.sh redteam          the boundary red team inside a tier 2 box
#   OVARA_TEST_ON_HOST=1 tests/box/host.sh redteam-docker   the boundary red team in docker mode
#   OVARA_TEST_ON_HOST=1 tests/box/host.sh agent opencode|anthropic|codex|aider
#
# SKIP_IMAGE_BUILD=1 uses ovara-box / ovara-box-test as they are.
set -euo pipefail
what="${1:-}"; agent="${2:-}"
[ "${OVARA_TEST_ON_HOST:-}" = 1 ] || { echo "these tests change this machine; run them on a disposable one with OVARA_TEST_ON_HOST=1" >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
case "$what" in
  box|redteam|redteam-docker) ;;
  agent) case "$agent" in opencode|anthropic|codex|aider) ;; *) echo "agent: opencode, anthropic, codex or aider" >&2; exit 2;; esac ;;
  *) sed -n '2,15p' "$0" >&2; exit 2 ;;
esac
[ "$(readlink -f /repo 2>/dev/null)" = "$repo" ] || $SUDO ln -sfn "$repo" /repo
(cd "$repo/proxy" && CGO_ENABLED=0 go build -o /tmp/ovara-host-bin ./cmd/ovara)
$SUDO install -m 0755 /tmp/ovara-host-bin /usr/local/bin/ovara
# the agents run from the per-agent images users get (box/agents/Dockerfile);
# the box and red-team tests use ovara-box-test (sudo, nft, ping, ... to probe with)
img_agent=$agent; [ "$agent" = anthropic ] && img_agent=claude
if [ "$what" != redteam-docker ] && [ "${SKIP_IMAGE_BUILD:-}" != 1 ]; then
  docker build -q -t ovara-box "$repo/box" >/dev/null
  if [ "$what" = agent ]; then
    docker build -q --build-arg AGENT="$img_agent" -t "ovara-box-$img_agent" "$repo/box/agents" >/dev/null
  else
    docker build -q -t ovara-box-test "$repo/tests/box" >/dev/null
  fi
fi
run() { $SUDO env "PATH=$PATH" "$@"; }
case "$what" in
  box)
    out="$(run TIER=2 bash "$repo/tests/box/box.sh" 2>&1)" || true
    echo "$out" | grep -v '^go: downloading'
    echo "$out" | grep -q '^RESULT: .* 0 failed' || { echo "tier 2 box test failed" >&2; exit 1; } ;;
  redteam)        run bash "$repo/tests/redteam/boundary/box-tier2.sh" ;;
  redteam-docker) run bash "$repo/tests/redteam/boundary/docker.sh" ;;
  agent)
    out="$(run MODE=box2 BOX_IMAGE="ovara-box-$img_agent" bash -c "tr -d '\r' < '$repo/tests/agents/$agent.sh' > /tmp/agent-t.sh && bash /tmp/agent-t.sh" 2>&1)" || true
    echo "$out" | grep -v '^go: downloading'
    echo "$out" | grep -Eq '^RESULT\[.*\]: [0-9]+ passed, 0 failed' || { echo "agent test (tier 2, $agent) failed" >&2; exit 1; } ;;
esac
