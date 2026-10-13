#!/usr/bin/env bash
# `ovara box` end to end in a privileged container (the box needs a network
# namespace). Builds the checked-out commit; reads the test script from the
# working tree.
#
#   tests/box/run.sh           the box (tests/box/box.sh)
#   tests/box/run.sh strict    strict installs (tests/box/strict.sh)
#   tests/box/run.sh boundary  the boundary script on its own (tests/box/boundary.sh)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
ctx="$repo/tests/agents"
if command -v cygpath >/dev/null 2>&1; then repo="$(cygpath -w "$repo")"; ctx="$(cygpath -w "$ctx")"; export MSYS_NO_PATHCONV=1; fi
docker build -q -t ovara-agents "$ctx" >/dev/null
script=box.sh; [ "${1:-}" = strict ] && script=strict.sh; [ "${1:-}" = boundary ] && script=boundary.sh
# the container is the disposable machine the boundary test asks for
out="$(docker run --rm --privileged -v "$repo:/repo:ro" ovara-agents \
  bash -c "tr -d '\r' < /repo/tests/box/$script > /tmp/t.sh && OVARA_TEST_ON_HOST=1 REPO=/repo bash /tmp/t.sh" 2>&1)" || true
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -q '^RESULT: .* 0 failed' || { echo "box test failed" >&2; exit 1; }
