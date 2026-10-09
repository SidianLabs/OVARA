#!/usr/bin/env bash
# The boundary red team from INSIDE an `ovara box -tier 2` box, as the agent.
# The command gate is off for this run, so every probe tests the container's
# own boundary (no network but the relay, no capabilities), not the gate.
#
# Runs on the host as root, with Docker and the ovara-box-test image
# (tests/box/Dockerfile). It changes this machine (a deployment in
# /tmp/rt-box, a run under /var/lib/ovara): use a disposable one (CI).
#   sudo env PATH=$PATH bash tests/redteam/boundary/box-tier2.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
image="${BOX_IMAGE:-ovara-box-test}"
command -v ovara >/dev/null || { echo "ovara is not on PATH (build proxy/cmd/ovara first)"; exit 1; }
rm -rf /tmp/rt-box /tmp/rt-proj; mkdir -p /tmp/rt-proj
(cd /tmp/rt-proj && git init -q -b main && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m init)
cp "$here/run.sh" /tmp/rt-redteam.sh; chmod 644 /tmp/rt-redteam.sh
ovara init /tmp/rt-box >/dev/null 2>&1
GW_PORT=$(python3 -c "import json,urllib.parse as u;print(u.urlparse(json.load(open('/tmp/rt-box/proxy.json'))['gateway_url']).port)")
out="$(timeout 600 ovara box -tier 2 -image "$image" -dir /tmp/rt-box -ui off -no-command-gate -no-commit-back \
  -mount /tmp/rt-redteam.sh:/tmp/redteam.sh /tmp/rt-proj -- \
  bash -c "MODE=inside GATEWAY_PORT=$GW_PORT bash /tmp/redteam.sh" 2>&1)"
echo "$out" | grep -v '^go: downloading'
echo "$out" | grep -q '^=== 0 unexpected result' || { echo "boundary suite (inside a tier 2 box) reported unexpected results" >&2; exit 1; }
echo REDTEAM_TIER2_OK
