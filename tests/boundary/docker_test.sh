#!/usr/bin/env bash
#
# docker_test.sh — live verification of the I1 egress boundary (docker mode).
#
# Drives proxy/scripts/setup-egress-boundary.sh docker, runs a throwaway
# agent container on the internal bridge, and asserts:
#   1. the proxy port on the bridge gateway is reachable     (allowed path)
#   2. a listener on ANY OTHER gateway port is unreachable   (INPUT DROP)
#   3. a direct external TCP connection fails                (no NAT route)
#
# Prerequisites: root (iptables rules), docker daemon access, and an image
# with python3 (default ubuntu:24.04; override with --image / $BTEST_IMAGE).
# Exit codes: 0 pass, 1 boundary violation, 77 prerequisites missing (SKIP).
# SKIP is not PASS.

set -uo pipefail

NET="ovara-btest-net"
SUBNET="172.30.0.0/24"          # hardcoded in the setup script's rules
GW="172.30.0.1"
PROXY_PORT=19445
OTHER_PORT=19446
IMAGE="${BTEST_IMAGE:-ubuntu:24.04}"
SETUP="$(cd "$(dirname "$0")" && pwd)/../../proxy/scripts/setup-egress-boundary.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*" >&2; exit 77; }
note() { echo "  $*"; }

[[ $EUID -eq 0 ]] || skip "requires root (host iptables rules)"
command -v docker >/dev/null 2>&1 || skip "docker client missing"
docker info >/dev/null 2>&1     || skip "docker daemon unreachable"
command -v iptables >/dev/null 2>&1 || skip "iptables missing"
command -v python3 >/dev/null 2>&1  || skip "python3 missing (host listener)"
[[ -f "$SETUP" ]] || fail "boundary setup script not found: $SETUP"
docker network inspect "$NET" >/dev/null 2>&1 \
  && skip "network $NET already exists — refusing to touch a live deployment"

LISTENER_PID=""
cleanup() {
  [[ -n "$LISTENER_PID" ]] && kill "$LISTENER_PID" 2>/dev/null
  docker network rm "$NET" >/dev/null 2>&1
  for r in \
    "-s ${SUBNET} -j DROP" \
    "-s ${SUBNET} -d ${GW} -p udp -m multiport --dports 53,5353 -j ACCEPT" \
    "-s ${SUBNET} -d ${GW} -p tcp -m multiport --dports 53,5353 -j ACCEPT" \
    "-s ${SUBNET} -d ${GW} -p tcp --dport ${PROXY_PORT} -j ACCEPT"; do
    iptables -D INPUT ${r} 2>/dev/null
  done
  for r in \
    "-s ${SUBNET} -j DROP" \
    "-s ${SUBNET} -d ${GW} -p udp --dport 53 -j ACCEPT" \
    "-s ${SUBNET} -d ${GW} -p tcp --dport 53 -j ACCEPT" \
    "-s ${SUBNET} -d ${GW} -p tcp --dport ${PROXY_PORT} -j ACCEPT"; do
    iptables -D DOCKER-USER ${r} 2>/dev/null
  done
}
trap cleanup EXIT

echo "== I1 boundary test (docker) =="

"$SETUP" docker --net "$NET" --proxy-ip "$GW" --proxy-port "$PROXY_PORT" \
  --resolver "$GW" >/dev/null || fail "setup-egress-boundary.sh docker failed"
note "boundary up: net=${NET} gw=${GW} proxy=${PROXY_PORT}"

python3 - "$GW" "$PROXY_PORT" "$OTHER_PORT" <<'PY' &
import socket, sys
socks = []
for port in (int(sys.argv[2]), int(sys.argv[3])):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(4)
    socks.append(s)
print("listeners ready", flush=True)
while True:
    for s in socks:
        try:
            c, _ = s.accept()
            c.close()
        except Exception:
            pass
PY
LISTENER_PID=$!
sleep 1

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null \
  || skip "image $IMAGE unavailable and pull failed"

# bash /dev/tcp: no interpreter dependency beyond bash (present in the
# default image). timeout 5 bounds the DROP case (silent discard hangs).
run_agent() {  # $1=host $2=port -> 0 connected, nonzero refused/dropped
  docker run --rm --network "$NET" --cap-drop ALL --security-opt no-new-privileges \
    "$IMAGE" timeout 5 bash -c "</dev/tcp/$1/$2" >/dev/null 2>&1
}

run_agent "$GW" "$PROXY_PORT" || fail "proxy port unreachable from agent container"
note "proxy path reachable: PASS"

run_agent "$GW" "$OTHER_PORT" && fail "reached gateway port $OTHER_PORT — INPUT DROP not enforced"
note "non-proxy gateway port unreachable: PASS"

run_agent "1.1.1.1" "443" && fail "direct external egress succeeded — internal network leaked"
note "direct external egress blocked: PASS"

echo "RESULT: I1 docker boundary LIVE VERIFIED (3/3 assertions)"
exit 0
