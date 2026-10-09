#!/usr/bin/env bash
# The boundary red team in docker mode: `ovara run --boundary docker` sets
# up the internal network and the host firewall (setup-egress-boundary.sh
# docker), then each probe runs in a fresh container on that network, as the
# script's recipe tells people to run their agent.
#
# Runs on the host as root, with Docker and iptables. It changes this
# machine (a docker network, iptables rules in INPUT and DOCKER-USER, a
# deployment in /tmp/rt-docker): use a disposable one (CI).
#   sudo env PATH=$PATH bash tests/redteam/boundary/docker.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
command -v ovara >/dev/null || { echo "ovara is not on PATH (build proxy/cmd/ovara first)"; exit 1; }
docker build -q -t ovara-redteam "$here" >/dev/null || { echo "could not build the probe image"; exit 1; }
rm -rf /tmp/rt-docker; ovara init /tmp/rt-docker >/dev/null 2>&1
ovara run -dir /tmp/rt-docker --boundary docker --boundary-name ovara-egress -ui off >/tmp/rt-docker-run.log 2>&1 &
RUNPID=$!
trap 'kill $RUNPID 2>/dev/null; wait $RUNPID 2>/dev/null' EXIT
# wait on loopback: the boundary's INPUT rules drop packets from the bridge
# subnet, and that includes the host's own replies to itself on 172.30.0.1
for i in $(seq 1 120); do timeout 2 bash -c '(echo > /dev/tcp/127.0.0.1/9443)' 2>/dev/null && break; sleep 0.5; done
timeout 2 bash -c '(echo > /dev/tcp/127.0.0.1/9443)' 2>/dev/null || { echo "ovara run did not come up"; tail -30 /tmp/rt-docker-run.log; exit 1; }
PTOK=$(python3 -c "import json;print(json.load(open('/tmp/rt-docker/proxy.json'))['agent_token'])")
GW_PORT=$(python3 -c "import json,urllib.parse as u;print(u.urlparse(json.load(open('/tmp/rt-docker/proxy.json'))['gateway_url']).port)")
CA=$(python3 -c "import json,os;p=json.load(open('/tmp/rt-docker/proxy.json'))['ca_cert_file'];print(p if os.path.isabs(p) else os.path.join('/tmp/rt-docker',p))")
PROXY_TOKEN="$PTOK" MODE=docker NET=ovara-egress DOCKER_PROXY_IP=172.30.0.1 PROXY_PORT=9443 \
  GATEWAY_PORT="$GW_PORT" CA="$CA" REDTEAM_IMAGE=ovara-redteam bash "$here/run.sh"
code=$?
[ $code = 0 ] && echo REDTEAM_DOCKER_OK
exit $code
