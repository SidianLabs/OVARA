#!/usr/bin/env bash
# The agent attacks Ovara from a different unprivileged OS user.
#
# Ovara runs as one user, the agent as another, on the same Linux host. The
# agent tries to read the keys, edit the policy, forge or delete receipts,
# approve its own requests and kill the process. Every attack must fail while
# the agent can still do its job through the proxy.
#
# Needs Docker and outbound internet. Tests the checked-out commit.
#   tests/redteam/separate-user/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
ctx="$repo/tests/scenarios"
# Git Bash on Windows: hand Docker Windows paths and stop MSYS rewriting /repo.
if command -v cygpath >/dev/null 2>&1; then repo="$(cygpath -w "$repo")"; ctx="$(cygpath -w "$ctx")"; export MSYS_NO_PATHCONV=1; fi
docker build -q -t ovara-scenarios "$ctx" >/dev/null
out="$(docker run --rm -v "$repo:/repo:ro" ovara-scenarios \
  bash -c "tr -d '\r' < /repo/tests/redteam/separate-user/attacks.sh > /tmp/a.sh && bash /tmp/a.sh" 2>&1)"
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -q '^RESULT: .* 0 failed' || { echo "an attack succeeded" >&2; exit 1; }
