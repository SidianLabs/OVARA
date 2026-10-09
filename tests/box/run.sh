#!/usr/bin/env bash
# `ovara box` end to end in a privileged container (the box needs a network
# namespace). Builds the checked-out commit; reads the test script from the
# working tree.
#
#   tests/box/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
ctx="$repo/tests/agents"
if command -v cygpath >/dev/null 2>&1; then repo="$(cygpath -w "$repo")"; ctx="$(cygpath -w "$ctx")"; export MSYS_NO_PATHCONV=1; fi
docker build -q -t ovara-agents "$ctx" >/dev/null
out="$(docker run --rm --privileged -v "$repo:/repo:ro" ovara-agents \
  bash -c "tr -d '\r' < /repo/tests/box/box.sh > /tmp/t.sh && bash /tmp/t.sh" 2>&1)" || true
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -q '^RESULT: .* 0 failed' || { echo "box test failed" >&2; exit 1; }
