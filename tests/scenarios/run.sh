#!/usr/bin/env bash
# Run Ovara the way a person uses it: real tools (pip, npm, git, Node fetch,
# curl) through the proxy, a human approving and denying, a real injected
# key, live policy edits, the approval page, tampering and a restart.
#
# Needs Docker and outbound internet. It builds the checked-out commit inside
# a Linux container, so it tests what is committed, not your working tree.
#
#   tests/scenarios/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# Git Bash on Windows: hand Docker a Windows path and stop MSYS rewriting /repo.
if command -v cygpath >/dev/null 2>&1; then repo="$(cygpath -w "$repo")"; export MSYS_NO_PATHCONV=1; fi
docker build -q -t ovara-scenarios "$here" >/dev/null
out="$(docker run --rm -v "$repo:/repo:ro" ovara-scenarios \
  bash -c "tr -d '\r' < /repo/tests/scenarios/scenarios.sh > /tmp/t.sh && bash /tmp/t.sh" 2>&1)"
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -q '^RESULT: .* 0 failed' || { echo "scenario failures" >&2; exit 1; }
