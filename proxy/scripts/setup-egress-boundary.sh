#!/usr/bin/env bash
#
# setup-egress-boundary.sh — build a default-deny egress boundary for an agent
# so that the *only* reachable endpoint is the Ovara executor proxy.
#
# MUST be run on the host (root / CAP_NET_ADMIN). Running this inside the
# agent environment is useless — the agent would control its own boundary.
#
# Two modes:
#
#   netns    — raw `ip netns` mode. Creates (or reuses) a dedicated network
#              namespace, wires a veth pair to the host, applies nftables
#              default-deny inside the namespace.
#
#   docker   — prints/applies a `docker run` recipe: dedicated bridge network
#              with no NAT/internet route, container can only reach the
#              proxy host, capabilities dropped.
#
# Honest limits (read these — the boundary is only as strong as this list):
#   * QUIC/HTTP3 bypasses TCP-only rules. We block UDP/443 outright to force
#     TCP. If you need UDP/443 for something real, this script is wrong for you.
#   * DNS tunneling: we redirect all :53 traffic to a resolver you choose, but
#     a resolver that answers arbitrary TXT queries is still an exfil channel.
#     Use a deny-by-default resolver (see proxy/scripts/resolver.md).
#   * Direct-IP egress is closed by default-deny, but only if the agent cannot
#     modify the rules — hence CAP_NET_ADMIN/CAP_NET_RAW must be dropped.
#   * This script is idempotent-ish: rerunning it reuses the netns/veth and
#     reloads the nft ruleset. It does NOT track partial state; if it fails
#     halfway, re-run it or tear down manually.
#
# Usage:
#   ./setup-egress-boundary.sh netns  [--name agent0] [--proxy-ip 10.200.0.1] [--proxy-port 9443] [--resolver 10.200.0.2]
#   ./setup-egress-boundary.sh docker [--net ovara-egress] [--proxy-ip 172.30.0.1] [--proxy-port 9443] [--resolver 172.30.0.2] [--image yourimage]

set -euo pipefail

# ---- defaults -------------------------------------------------------------
MODE="${1:-}"
NS_NAME="agent0"
PROXY_IP=""
PROXY_PORT="9443"
RESOLVER=""
DOCKER_NET="ovara-egress"
DOCKER_IMAGE="ubuntu:24.04"
VETH_HOST="veth-ova-h"
VETH_NS="veth-ova-n"
NS_ADDR_BASE="10.200.0"   # /24 inside the netns; host takes .1, ns takes .10
# Derived after arg parsing: veth names and the /24 subnet are per-netns so
# multiple boundaries can coexist on one host. IFNAMSIZ limit is 15 chars.
SUBNET_IDX=""           # --subnet-idx N -> NS_ADDR_BASE=10.200.N

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)       NS_NAME="$2"; shift 2;;
    --net)        DOCKER_NET="$2"; shift 2;;
    --proxy-ip)   PROXY_IP="$2"; shift 2;;
    --proxy-port) PROXY_PORT="$2"; shift 2;;
    --resolver)   RESOLVER="$2"; shift 2;;
    --image)      DOCKER_IMAGE="$2"; shift 2;;
    --subnet-idx) SUBNET_IDX="$2"; shift 2;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

# Per-netns veth names + subnet: a second boundary must not collide with the
# first (hardcoded names used to leave new netns with no interface at all).
# Octet is a stable hash of the name (1..250) unless --subnet-idx overrides.
if [[ "${MODE}" == "netns" ]]; then
  short="$(echo "${NS_NAME}" | tr -cd '[:alnum:]' | cut -c1-9)"
  VETH_HOST="vo-${short}-h"
  VETH_NS="vo-${short}-n"
  if [[ -n "${SUBNET_IDX}" ]]; then
    NS_ADDR_BASE="10.200.${SUBNET_IDX}"
  else
    h=$(echo -n "${NS_NAME}" | cksum | cut -d' ' -f1)
    NS_ADDR_BASE="10.200.$(( h % 250 + 1 ))"
  fi
fi

warn() { echo "WARNING: $*" >&2; }

[[ $EUID -eq 0 ]] || { echo "must run as root (needs CAP_NET_ADMIN)" >&2; exit 1; }

case "$MODE" in
  netns)  : "${PROXY_IP:=${NS_ADDR_BASE}.1}"; : "${RESOLVER:=${NS_ADDR_BASE}.1}" ;;
  docker) : "${PROXY_IP:=172.30.0.1}";       : "${RESOLVER:=172.30.0.1}" ;;
  *) echo "usage: $0 {netns|docker} [flags]" >&2; exit 2;;
esac

# ---- shared nft ruleset ----------------------------------------------------
# Rendered to a file and loaded either inside the netns or shipped to the
# docker host network. Default-deny OUTPUT; allow only proxy, redirected DNS,
# and established return traffic.
render_nft() {
  cat <<EOF
table inet egress_boundary {
  # DNAT all DNS (TCP+UDP :53) to the policy-enforcing resolver. ('redirect'
  # would deliver to THIS stack's :5353, blackholing DNS — the resolver is
  # a different host/address.) It MUST be deny-by-default or this is an
  # exfil tunnel.
  chain nat_output {
    type nat hook output priority -100; policy accept;
    udp dport 53 dnat ip to ${RESOLVER}:5353
    tcp dport 53 dnat ip to ${RESOLVER}:5353
  }

  chain output {
    type filter hook output priority 0; policy drop;

    # Loopback and return traffic for allowed flows.
    oifname "lo" accept
    ct state established,related accept

    # The only thing the agent may reach: the executor proxy.
    ip daddr ${PROXY_IP} tcp dport ${PROXY_PORT} accept

    # DNAT'd DNS egresses toward the resolver on :5353; also allow :53 in
    # case the resolver listens on the standard port.
    ip daddr ${RESOLVER} udp dport {53, 5353} accept
    ip daddr ${RESOLVER} tcp dport {53, 5353} accept

    # QUIC/HTTP3 would bypass TCP-only interception. Force TCP.
    udp dport 443 drop

    # Everything else — direct IP egress, IPv6, other ports — falls to
    # policy drop. IPv6 is also hard-disabled at the sysctl level below.
  }
}
EOF
}

# ===========================================================================
# Mode: raw ip netns
# ===========================================================================
do_netns() {
  echo "==> netns mode: ${NS_NAME}, proxy ${PROXY_IP}:${PROXY_PORT}, resolver ${RESOLVER}"

  if ip netns list | grep -qw "${NS_NAME}"; then
    echo "    netns ${NS_NAME} already exists, reusing"
  else
    ip netns add "${NS_NAME}"
    ip link add "${VETH_HOST}" type veth peer name "${VETH_NS}"
    ip link set "${VETH_NS}" netns "${NS_NAME}"
    ip addr add "${NS_ADDR_BASE}.1/24" dev "${VETH_HOST}"
    ip link set "${VETH_HOST}" up
    ip netns exec "${NS_NAME}" ip addr add "${NS_ADDR_BASE}.10/24" dev "${VETH_NS}"
    ip netns exec "${NS_NAME}" ip link set "${VETH_NS}" up
    ip netns exec "${NS_NAME}" ip link set lo up
    ip netns exec "${NS_NAME}" ip route add default via "${NS_ADDR_BASE}.1"
  fi

  # Hard-disable IPv6 inside the namespace. Simpler than mirroring every
  # rule into ip6tables; honest about the tradeoff.
  ip netns exec "${NS_NAME}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  ip netns exec "${NS_NAME}" sysctl -qw net.ipv6.conf.default.disable_ipv6=1

  # Host-side INPUT: two-direction hardening, idempotent.
  # (a) Many hosts end INPUT with a catch-all REJECT — open the proxy port
  #     and the resolver's DNS ports before it.
  # (b) Defense in depth: the in-ns nft ruleset is the primary boundary, but
  #     if it is ever weakened (bug, misapply, or a privileged agent), the
  #     host must not give the veth a free pass to every host service
  #     (sshd, docker.sock HTTP, kubelet :10250). DROP everything else from
  #     this interface. Inserted in reverse order so ACCEPTs end up first.
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -i "${VETH_HOST}" -j DROP 2>/dev/null \
      || iptables -I INPUT 1 -i "${VETH_HOST}" -j DROP
    iptables -C INPUT -i "${VETH_HOST}" -d "${RESOLVER}" -p udp -m multiport --dports 53,5353 -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -i "${VETH_HOST}" -d "${RESOLVER}" -p udp -m multiport --dports 53,5353 -j ACCEPT
    iptables -C INPUT -i "${VETH_HOST}" -d "${RESOLVER}" -p tcp -m multiport --dports 53,5353 -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -i "${VETH_HOST}" -d "${RESOLVER}" -p tcp -m multiport --dports 53,5353 -j ACCEPT
    iptables -C INPUT -i "${VETH_HOST}" -p tcp --dport "${PROXY_PORT}" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -i "${VETH_HOST}" -p tcp --dport "${PROXY_PORT}" -j ACCEPT
  fi

  # Host-side: NAT is deliberately NOT configured here. The host's default
  # posture should not masquerade agent traffic at all; the nft rules inside
  # the ns already deny everything except the proxy. If you add MASQUERADE
  # for the agent subnet, you've reopened the hole this script exists to close.

  local rules; rules="$(mktemp)"
  render_nft > "${rules}"
  # Drop any previous ruleset before loading (idempotent-ish).
  ip netns exec "${NS_NAME}" nft flush ruleset 2>/dev/null || true
  ip netns exec "${NS_NAME}" nft -f "${rules}"
  rm -f "${rules}"

  cat <<EOF

Done. Run the agent inside with capabilities dropped — e.g.:

  ip netns exec ${NS_NAME} setpriv \\
    --bounding-set=-net_admin,-net_raw \\
    --reuid 1000 --regid 1000 --clear-groups \\
    your-agent-command

Caveats:
  * 'setpriv --bounding-set' drops caps for the exec'd process; it does not
    survive a setuid binary. Prefer a container runtime for real isolation.
  * QUIC/UDP-443 is blocked; HTTPS falls back to TCP. Confirm your agent's
    HTTP stack actually falls back (most do; Go's http3-enabled clients may
    need explicit config).
  * DNS tunneling: :53 is DNAT'd to ${RESOLVER}:5353. If that resolver
    answers arbitrary queries, the agent can exfiltrate through TXT.
    See proxy/scripts/resolver.md.
  * This ran on the host. If you ran it inside the agent env, it did nothing.
EOF
}

# ===========================================================================
# Mode: docker
# ===========================================================================
do_docker() {
  echo "==> docker mode: network ${DOCKER_NET}, proxy ${PROXY_IP}:${PROXY_PORT}"

  # Dedicated bridge network with NO outbound NAT route. 'internal: true'
  # means docker does not attach a NAT masquerade — containers can only talk
  # to the bridge gateway and each other. The proxy lives on the bridge
  # (as a container or on the host gateway IP).
  if docker network inspect "${DOCKER_NET}" >/dev/null 2>&1; then
    echo "    network ${DOCKER_NET} already exists, reusing"
  else
    docker network create \
      --internal \
      --driver bridge \
      -o com.docker.network.bridge.enable_icc=false \
      --subnet 172.30.0.0/24 \
      "${DOCKER_NET}"
  fi

  # Host-side DOCKER-USER rules: the agent can still reach the bridge
  # gateway (${PROXY_IP}) on EVERY port — including any other host services
  # bound there. Restrict bridge-subnet traffic to exactly the proxy port
  # and the resolver's DNS port. Idempotent like the netns INPUT fix.
  if command -v iptables >/dev/null 2>&1; then
    for rule in \
      "-s 172.30.0.0/24 -d ${PROXY_IP} -p tcp --dport ${PROXY_PORT} -j ACCEPT" \
      "-s 172.30.0.0/24 -d ${RESOLVER} -p udp --dport 53 -j ACCEPT" \
      "-s 172.30.0.0/24 -d ${RESOLVER} -p tcp --dport 53 -j ACCEPT" \
      "-s 172.30.0.0/24 -j DROP"; do
      iptables -C DOCKER-USER ${rule} 2>/dev/null || iptables -A DOCKER-USER ${rule}
    done
    # DOCKER-USER only sees FORWARDED traffic. Packets to the bridge gateway
    # IP (${PROXY_IP} = the host itself) go through INPUT — and on a
    # default-ACCEPT host the agent would reach EVERY host-bound service:
    # sshd, docker.sock, kubelet :10250, and the gateway's approval API (an
    # agent that can reach the gateway can approve its own escalations).
    # Open only the proxy port and resolver DNS, then DROP the rest from the
    # bridge subnet. DROP is inserted first so the ACCEPTs land above it.
    iptables -C INPUT -s 172.30.0.0/24 -j DROP 2>/dev/null \
      || iptables -I INPUT 1 -s 172.30.0.0/24 -j DROP
    iptables -C INPUT -s 172.30.0.0/24 -d ${RESOLVER} -p udp -m multiport --dports 53,5353 -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -s 172.30.0.0/24 -d ${RESOLVER} -p udp -m multiport --dports 53,5353 -j ACCEPT
    iptables -C INPUT -s 172.30.0.0/24 -d ${RESOLVER} -p tcp -m multiport --dports 53,5353 -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -s 172.30.0.0/24 -d ${RESOLVER} -p tcp -m multiport --dports 53,5353 -j ACCEPT
    iptables -C INPUT -s 172.30.0.0/24 -d ${PROXY_IP} -p tcp --dport ${PROXY_PORT} -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -s 172.30.0.0/24 -d ${PROXY_IP} -p tcp --dport ${PROXY_PORT} -j ACCEPT
  else
    warn "iptables not found — DOCKER-USER restrictions NOT applied; the agent can hit the bridge gateway on all ports"
  fi

  cat <<EOF

Docker boundary recipe. Two pieces; neither is optional.

1) The proxy itself must be reachable on this network. Either run it as a
   container attached to ${DOCKER_NET}, or bind it on the bridge gateway
   address (${PROXY_IP}) on the host.

2) Run the agent like this:

  docker run --rm -it \\
    --network ${DOCKER_NET} \\
    --cap-drop ALL \\
    --security-opt no-new-privileges \\
    --read-only \\
    --dns ${RESOLVER} \\
    --dns-search . \\
    -e HTTPS_PROXY=http://${PROXY_IP}:${PROXY_PORT} \\
    -e HTTP_PROXY=http://${PROXY_IP}:${PROXY_PORT} \\
    -e NO_PROXY=localhost,127.0.0.1 \\
    ${DOCKER_IMAGE}

Why each flag exists:
  --internal network     no NAT masquerade -> no route to the internet at all.
  --cap-drop ALL         agent cannot touch nftables, raw sockets, or the
                         interface config. NET_RAW alone would permit crafted
                         packets that skip TCP entirely.
  --dns ${RESOLVER}      docker injects this as the container's resolver.
                         Point it at your deny-by-default forwarder
                         (see proxy/scripts/resolver.md). Docker's embedded
                         DNS at 127.0.0.11 is bypassed for external names.
  --read-only            agent can't rewrite /etc/hosts or drop a resolver
                         config. (Caveat: /tmp still writable — mount tmpfs
                         if you care.)
  HTTPS_PROXY env        only works for cooperative clients. The *real*
                         guarantee is the internal network — env vars are a
                         convenience for tools that respect them.

Honest gaps:
  * DOCKER-USER rules (applied above) restrict bridge-subnet egress to
    ${PROXY_IP}:${PROXY_PORT} and ${RESOLVER}:53 — the gateway can no longer
    be hit on other ports. They apply to routed traffic; same-bridge
    container-to-container traffic is switched L2 and bypasses iptables, so
    still keep the bridge to exactly: agent + proxy + resolver.
  * If you reused an existing ${DOCKER_NET} with a different subnet, the
    hardcoded 172.30.0.0/24 DOCKER-USER rules will not match it — re-create
    the network or adjust the rules.
  * QUIC/UDP-443: the internal network has no NAT, so UDP 443 goes nowhere
    anyway. No explicit rule needed here — unlike the netns path.
  * An agent with a cooperative-but-buggy client that ignores HTTPS_PROXY
    still can't reach anything — the network does it, not the env var.
  * IPv6: docker bridge is IPv4-only by default. If you enabled IPv6 on the
    daemon, pass --ipv6=false to the network create and verify.
EOF
}

case "$MODE" in
  netns)  do_netns ;;
  docker) do_docker ;;
esac
