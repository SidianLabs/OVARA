#!/usr/bin/env bash
# Ovara redteam boundary suite — live verification that the egress
# boundary actually holds. Three modes:
#   MODE=netns   NS=name: a running `ovara run --boundary netns` (root)
#   MODE=docker  NET=name: a docker network made by setup-egress-boundary.sh
#                (`ovara run --boundary docker`), checks run in fresh
#                containers from REDTEAM_IMAGE (tests/redteam/boundary/Dockerfile)
#   MODE=inside  run from INSIDE an `ovara box -tier 2` box, as the agent
#                (box-tier2.sh); the proxy is the box's loopback relay
#
# Every check prints: ATTACK | EXPECTED | ACTUAL | VERDICT
# Exit code = number of FAIL verdicts (0 = all expected results observed).

MODE="${MODE:-netns}"
NS="${NS:-audit-ns}"
NET="${NET:-audit-egress}"
PROXY_IP="${PROXY_IP:-10.200.188.1}"
PROXY_PORT="${PROXY_PORT:-9443}"
DOCKER_PROXY_IP="${DOCKER_PROXY_IP:-172.30.0.1}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"
CA="${CA:-/tmp/cleanroom/env/var/ca.pem}"
FAIL=0
# The proxy requires its token. Without it every CONNECT is refused with 407, so
# an "allowed path" check would fail and every "CONNECT denied" check would pass
# for the wrong reason. Set PROXY_TOKEN to the deployment's agent token.
PXY="http://${PROXY_TOKEN:+agent:$PROXY_TOKEN@}"

# HIP: an address of the host as seen from the agent (host services must be
# unreachable there); GWIP: where the gateway port is probed.
if [ "$MODE" = "netns" ]; then
  RUN() { sudo -n ip netns exec "$NS" "$@"; }
  PIP="$PROXY_IP"; HIP="$PIP"; GWIP="$PIP"
elif [ "$MODE" = "docker" ]; then
  RUN() { sudo -n docker run --rm --network "$NET" --cap-drop ALL \
          --security-opt no-new-privileges -v "$CA:$CA:ro" "${REDTEAM_IMAGE:-ovara-redteam}" "$@"; }
  PIP="$DOCKER_PROXY_IP"; HIP="$PIP"; GWIP="$PIP"
else
  # inside the box: the proxy is the loopback relay, the token is in the
  # agent's own environment, the host is the Docker bridge's gateway
  RUN() { "$@"; }
  PIP=127.0.0.1; HIP="${HOST_IP:-172.17.0.1}"; GWIP=127.0.0.1
  CA="${SSL_CERT_FILE:-/etc/ovara/ca.pem}"
  PROXY_TOKEN="$(printf '%s' "${HTTPS_PROXY:-}" | sed -n 's#^http://agent:\([^@]*\)@.*#\1#p')"
fi

check() { # name expected actual
  local name="$1" expected="$2" actual="$3"
  local verdict=PASS
  [ "$actual" != "$expected" ] && { verdict=FAIL; FAIL=$((FAIL+1)); }
  printf "%-46s | %-8s | %-8s | %s\n" "$name" "$expected" "$actual" "$verdict"
}

tcp() { RUN timeout 4 bash -c "</dev/tcp/$1/$2" >/dev/null 2>&1 && echo OPEN || echo BLOCKED; }
# tcps distinguishes refused (path open, no service) from timeout (filtered).
tcps() { RUN timeout 4 bash -c "</dev/tcp/$1/$2" >/dev/null 2>&1 && echo OPEN || echo REFUSED_OR_BLOCKED; }
httpc() { RUN curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$1" 2>/dev/null; }
prox() { RUN curl -s -o /dev/null -w "%{http_code}" --max-time 8 -x "${PXY}$PIP:$PROXY_PORT" --cacert "$CA" "$1" 2>/dev/null; }

echo "=== boundary suite: mode=$MODE ns=$NS net=$NET proxy=$PIP:$PROXY_PORT ==="

# --- allowed path ---
P=$(prox https://api.github.com/); case "$P" in 000|""|407) echo "proxy CONNECT                  | 2xx/4xx | $P     | FAIL"; FAIL=$((FAIL+1));; *) echo "proxy CONNECT                  | 2xx/4xx | $P     | PASS";; esac

# --- direct egress (must fail) ---
check "direct IPv4 https"            "BLOCKED" "$(tcp 1.1.1.1 443)"
check "direct IPv4 http"             "BLOCKED" "$(tcp 1.1.1.1 80)"
check "direct IP-literal https"      "BLOCKED" "$(tcp 140.82.121.4 443)"
check "ssh port 22"                  "BLOCKED" "$(tcp 140.82.121.4 22)"
check "socks port 1080"              "BLOCKED" "$(tcp 1.1.1.1 1080)"
check "arbitrary tcp 6379"           "BLOCKED" "$(tcp 1.1.1.1 6379)"
check "udp arbitrary"                "BLOCKED" "$(RUN timeout 3 bash -c 'echo x >/dev/udp/1.1.1.1/1234' >/dev/null 2>&1 && echo OPEN || echo BLOCKED)"
check "icmp"                         "BLOCKED" "$(RUN ping -c1 -W2 8.8.8.8 >/dev/null 2>&1 && echo OPEN || echo BLOCKED)"

# --- DNS (an answer for an outside name is a channel out) ---
check "DNS lookup of an outside name" "BLOCKED" "$(RUN timeout 6 getent hosts example.com >/dev/null 2>&1 && echo OPEN || echo BLOCKED)"

# --- host services (must fail) ---
check "gateway port"                 "BLOCKED" "$(tcp $GWIP $GATEWAY_PORT)"
[ "$MODE" = inside ] && check "gateway port on the host"  "BLOCKED" "$(tcp $HIP $GATEWAY_PORT)"
check "host ssh"                     "BLOCKED" "$(tcp $HIP 22)"
check "host http :80"                "BLOCKED" "$(tcp $HIP 80)"
check "host random :9999"            "BLOCKED" "$(tcp $HIP 9999)"
check "docker api :2375"             "BLOCKED" "$(tcp $HIP 2375)"
check "kubelet :10250"               "BLOCKED" "$(tcp $HIP 10250)"
check "host metadata 169.254.x"      "BLOCKED" "$(tcp 169.254.169.254 80)"

# --- resolver (path deliberately allowed; informational — OPEN means a
# resolver service is actually listening, REFUSED_OR_BLOCKED means the
# packet path is open but nothing answers) ---
R=$(tcps $PIP 5353); printf "%-46s | %-8s | %-8s | %s\n" "resolver port path" "ALLOWED" "$R" "INFO"

# --- capability enforcement ---
# netns: the agent is root's child dropped to a user; docker/inside: the
# container itself has no capabilities, so the commands run as they are
if [ "$MODE" = netns ]; then
  AS() { RUN setpriv --bounding-set=-net_admin,-net_raw --reuid 1000 --regid 1000 --clear-groups bash -c "$1"; }
else
  AS() { RUN bash -c "$1"; }
fi
check "nft flush as dropped-cap"     "BLOCKED" "$(AS 'nft flush ruleset' >/dev/null 2>&1 && echo FLUSHED || echo BLOCKED)"
check "route add as dropped-cap"     "BLOCKED" "$(AS 'ip route add default via 10.200.188.1' >/dev/null 2>&1 && echo ADDED || echo BLOCKED)"
check "iface create as dropped-cap"  "BLOCKED" "$(AS 'ip link add dummy0 type dummy' >/dev/null 2>&1 && echo CREATED || echo BLOCKED)"
check "raw socket (crafted packets)" "BLOCKED" "$(AS "python3 -c 'import socket;socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)'" >/dev/null 2>&1 && echo OPENED || echo BLOCKED)"

# --- denied CONNECTs through the proxy (deny + receipt expected) ---
check "CONNECT :22 denied"           "000"     "$(RUN curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x ${PXY}$PIP:$PROXY_PORT https://github.com:22/ 2>/dev/null)"
check "CONNECT private denied"       "000"     "$(RUN curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x ${PXY}$PIP:$PROXY_PORT https://192.168.1.1/ 2>/dev/null)"
check "CONNECT loopback denied"      "000"     "$(RUN curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x ${PXY}$PIP:$PROXY_PORT https://127.0.0.1/ 2>/dev/null)"
check "CONNECT metadata denied"      "000"     "$(RUN curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x ${PXY}$PIP:$PROXY_PORT https://169.254.169.254/ 2>/dev/null)"
check "CONNECT cgnat denied"         "000"     "$(RUN curl -s -o /dev/null -w '%{http_code}' --max-time 5 -x ${PXY}$PIP:$PROXY_PORT https://100.64.0.1/ 2>/dev/null)"

# --- docker-only: L2 isolation ---
if [ "$MODE" = "docker" ]; then
  check "agent->172.30.0.2 L2"       "BLOCKED" "$(tcp 172.30.0.2 22)"
  check "agent->172.30.0.99 L2"      "BLOCKED" "$(tcp 172.30.0.99 9999)"
fi

# --- ipv6 ---
check "ipv6 external"                "BLOCKED" "$(RUN timeout 4 bash -c '</dev/tcp/2606:4700:4700::1111/443' >/dev/null 2>&1 && echo OPEN || echo BLOCKED)"

echo "=== $FAIL unexpected result(s) ==="
exit $FAIL
