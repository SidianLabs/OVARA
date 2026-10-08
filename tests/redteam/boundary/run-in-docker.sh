#!/usr/bin/env bash
# Run the egress-boundary red-team suite against a real `ovara run --boundary
# netns`, inside a privileged Linux container (so it needs no spare Linux host).
# The firewall rules and network namespace live and die with the container.
#
# Needs Docker and outbound internet. Tests the checked-out commit.
#   tests/redteam/boundary/run-in-docker.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
ctx="$repo/tests/scenarios"
if command -v cygpath >/dev/null 2>&1; then repo="$(cygpath -w "$repo")"; ctx="$(cygpath -w "$ctx")"; export MSYS_NO_PATHCONV=1; fi
docker build -q -t ovara-scenarios "$ctx" >/dev/null
out="$(docker run --rm --privileged -v "$repo:/repo:ro" ovara-scenarios \
  bash -c "tr -d '\r' < /repo/tests/redteam/boundary/inner.sh > /tmp/i.sh && bash /tmp/i.sh" 2>&1)"
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -q '^=== 0 unexpected result' || { echo "boundary suite reported unexpected results" >&2; exit 1; }
