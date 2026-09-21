#!/usr/bin/env bash
#
# netns_test.sh — live verification of the I1 egress boundary (netns mode).
#
# Drives proxy/scripts/setup-egress-boundary.sh, then asserts INSIDE the
# namespace:
#   1. the proxy port on the host veth is reachable          (allowed path)
#   2. a listener on ANY OTHER host port is unreachable      (INPUT DROP)
#   3. a direct external TCP connection fails                (default-deny)
#   4. IPv6 is disabled inside the namespace                 (sysctl)
#
# Prerequisites: root (CAP_NET_ADMIN), ip, nft, python3.
# Exit codes: 0 pass, 1 boundary violation, 77 prerequisites missing (SKIP).
# SKIP is not PASS — an environment that cannot run this test cannot
# reproduce the I1 claim.

set -uo pipefail

NS="ovara-btest"
IDX=200
BASE="10.200.${IDX}"
HOST_IP="${BASE}.1"
PROXY_PORT=19443
OTHER_PORT=19444
SETUP="$(cd "$(dirname "$0")" && pwd)/../../proxy/scripts/setup-egress-boundary.sh"

# Same derivation as setup-egress-boundary.sh: tr -cd alnum, cut -c1-9.
short="$(echo "${NS}" | tr -cd '[:alnum:]' | cut -c1-9)"
VETH_HOST="vo-${short}-h"

fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*" >&2; exit 77; }
note() { echo "  $*"; }

[[ $EUID -eq 0 ]] || skip "requires root (CAP_NET_ADMIN)"
for c in ip nft python3 iptables; do
  command -v "$c" >/dev/null 2>&1 || skip "missing prerequisite: $c"
done
[[ -f "$SETUP" ]] || fail "boundary setup script not found: $SETUP"

LISTENER_PID=""
cleanup() {
  [[ -n "$LISTENER_PID" ]] && kill "$LISTENER_PID" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  # Remove the host INPUT rules the setup script installed for this veth.
  for r in \
    "-i ${VETH_HOST} -j DROP" \
    "-i ${VETH_HOST} -d ${HOST_IP} -p udp -m multiport --dports 53,5353 -j ACCEPT" \
    "-i ${VETH_HOST} -d ${HOST_IP} -p tcp -m multiport --dports 53,5353 -j ACCEPT" \
    "-i ${VETH_HOST} -p tcp --dport ${PROXY_PORT} -j ACCEPT"; do
    iptables -D INPUT ${r} 2>/dev/null
  done
  ip link del "$VETH_HOST" 2>/dev/null
}
trap cleanup EXIT

echo "== I1 boundary test (netns) =="

# 1. Build the boundary.
"$SETUP" netns --name "$NS" --subnet-idx "$IDX" --proxy-port "$PROXY_PORT" >/dev/null \
  || fail "setup-egress-boundary.sh netns failed"
note "boundary up: ns=${NS} proxy=${HOST_IP}:${PROXY_PORT}"

# 2. Host-side listeners: one on the proxy port (allowed), one on another
#    port (must be unreachable — INPUT DROP is port-scoped).
python3 - "$HOST_IP" "$PROXY_PORT" "$OTHER_PORT" <<'PY' &
import socket, sys, time
socks = []
for port in (int(sys.argv[2]), int(sys.argv[3])):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], port))
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

ns_exec() { ip netns exec "$NS" timeout 5 python3 -c "$1"; }

# 3. Allowed path: proxy port reachable from inside the boundary.
ns_exec "import socket;socket.create_connection(('${HOST_IP}',${PROXY_PORT}),3).close()" \
  || fail "proxy port ${HOST_IP}:${PROXY_PORT} unreachable — boundary blocks the allowed path"
note "proxy path reachable: PASS"

# 4. Unauthorized host service: another port on the SAME address must drop.
ns_exec "import socket;socket.create_connection(('${HOST_IP}',${OTHER_PORT}),3).close()" \
  && fail "reached host port ${OTHER_PORT} — INPUT DROP not enforced"
note "non-proxy host port unreachable: PASS"

# 5. Direct external egress: default-deny must kill it (timeout or refused).
ns_exec "import socket;socket.create_connection(('1.1.1.1',443),3).close()" \
  && fail "direct external TCP egress succeeded — boundary is not default-deny"
note "direct external egress blocked: PASS"

# 6. IPv6 must be hard-disabled inside the namespace.
v6="$(ip netns exec "$NS" cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)"
[[ "$v6" == "1" ]] || fail "IPv6 not disabled in namespace (got: ${v6:-unreadable})"
note "IPv6 disabled: PASS"

echo "RESULT: I1 netns boundary LIVE VERIFIED (4/4 assertions)"
exit 0
