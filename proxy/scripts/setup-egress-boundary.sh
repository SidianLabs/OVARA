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
#   * DNS: the agent reaches the proxy by IP and needs no DNS, so :53 is
#     DROPPED by default. OVARA_BOUNDARY_DNS=1 (or --allow-dns) instead
#     redirects all :53 traffic to a resolver you choose; a resolver that
#     answers arbitrary TXT queries is then an exfil channel, so use a
#     deny-by-default one (see proxy/scripts/resolver.md).
#   * The host side (what the agent can reach on the host's boundary
#     address) is firewalled with iptables, or nft when there is no
#     iptables. With neither, the script stops (exit 3) unless
#     OVARA_ALLOW_UNHARDENED=1.
#   * Direct-IP egress is closed by default-deny, but only if the agent cannot
#     modify the rules — hence CAP_NET_ADMIN/CAP_NET_RAW must be dropped.
#   * This script is idempotent-ish: rerunning it reuses the netns/veth and
#     reloads the nft ruleset. It does NOT track partial state; if it fails
#     halfway, re-run it or tear down manually.
#
# Usage:
#   ./setup-egress-boundary.sh netns  [--name agent0] [--proxy-ip 10.200.0.1] [--proxy-port 9443] [--allow-dns] [--resolver 10.200.0.2]
#   ./setup-egress-boundary.sh docker [--net ovara-egress] [--proxy-ip 172.30.0.1] [--proxy-port 9443] [--allow-dns] [--resolver 172.30.0.2] [--image yourimage]

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
DNS_ON=0                # 1: :53 goes to RESOLVER (OVARA_BOUNDARY_DNS=1 / --allow-dns)
[[ "${OVARA_BOUNDARY_DNS:-}" == 1 ]] && DNS_ON=1
ALLOW_UNHARDENED=0      # 1: go on when the host side cannot be firewalled
[[ "${OVARA_ALLOW_UNHARDENED:-}" == 1 ]] && ALLOW_UNHARDENED=1

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
    --agent-token) AGENT_TOKEN="$2"; shift 2;;
    --allow-dns)  DNS_ON=1; shift;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

# Proxy client credential: the proxy authenticates clients when agent_token
# is configured in proxy.json. Pick it up automatically so the recipe prints
# a working proxy URL; --agent-token / OVARA_AGENT_TOKEN override.
: "${AGENT_TOKEN:=${OVARA_AGENT_TOKEN:-}}"
if [[ -z "${AGENT_TOKEN}" && -f proxy.json ]]; then
  AGENT_TOKEN=$(sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' proxy.json | head -1)
fi
PROXY_USERINFO=""
[[ -n "${AGENT_TOKEN}" ]] && PROXY_USERINFO="agent:${AGENT_TOKEN}@"

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
# docker host network. Default-deny OUTPUT; allow only the proxy (and, when
# DNS is turned on, the redirected resolver) and established return traffic.
render_nft() {
  echo "table inet egress_boundary {"
  if [[ "${DNS_ON}" == 1 ]]; then
    cat <<EOF
  # DNAT all DNS (TCP+UDP :53) to the policy-enforcing resolver. ('redirect'
  # would deliver to THIS stack's :5353, blackholing DNS — the resolver is
  # a different host/address.) It MUST be deny-by-default or this is an
  # exfil tunnel.
  chain nat_output {
    type nat hook output priority -100; policy accept;
    udp dport 53 dnat ip to ${RESOLVER}:5353
    tcp dport 53 dnat ip to ${RESOLVER}:5353
  }

EOF
  fi
  cat <<EOF
  chain output {
    type filter hook output priority 0; policy drop;

    # Loopback and return traffic for allowed flows.
    oifname "lo" accept
    ct state established,related accept

    # The only thing the agent may reach: the executor proxy.
    ip daddr ${PROXY_IP} tcp dport ${PROXY_PORT} accept

EOF
  if [[ "${DNS_ON}" == 1 ]]; then
    cat <<EOF
    # DNAT'd DNS egresses toward the resolver on :5353; also allow :53 in
    # case the resolver listens on the standard port.
    ip daddr ${RESOLVER} udp dport {53, 5353} accept
    ip daddr ${RESOLVER} tcp dport {53, 5353} accept

EOF
  else
    cat <<EOF
    # No DNS: the agent reaches the proxy by IP. (The policy drops it
    # anyway; said here so no later accept can open it by accident.)
    udp dport 53 drop
    tcp dport 53 drop

EOF
  fi
  cat <<EOF
    # QUIC/HTTP3 would bypass TCP-only interception. Force TCP.
    udp dport 443 drop

    # Everything else — direct IP egress, IPv6, other ports — falls to
    # policy drop. IPv6 is also hard-disabled at the sysctl level below.
  }
}
EOF
}

# ---- host side ---------------------------------------------------------------
# What the agent may reach on the HOST through the boundary link: the proxy
# port, and the resolver when DNS is on; nothing else. iptables when the
# host has it, else an nft table of our own. With neither, stop: without
# this the agent reaches every service bound on the host's boundary address.
#   host_harden <nft-table-name> <iptables-match...>
#     where the match selects the agent's traffic (-i VETH or -s SUBNET),
#     and NFT_MATCH holds the same in nft syntax.
host_harden() {
  local table="$1"; shift
  if command -v iptables >/dev/null 2>&1; then
    # (a) Many hosts end INPUT with a catch-all REJECT — open the proxy port
    #     (and the resolver's DNS ports) before it.
    # (b) Defense in depth: DROP everything else from the agent. Inserted
    #     in reverse order so the ACCEPTs end up first.
    iptables -C INPUT "$@" -j DROP 2>/dev/null \
      || iptables -I INPUT 1 "$@" -j DROP
    if [[ "${DNS_ON}" == 1 ]]; then
      for proto in udp tcp; do
        iptables -C INPUT "$@" -d "${RESOLVER}" -p "${proto}" -m multiport --dports 53,5353 -j ACCEPT 2>/dev/null \
          || iptables -I INPUT 1 "$@" -d "${RESOLVER}" -p "${proto}" -m multiport --dports 53,5353 -j ACCEPT
      done
    fi
    iptables -C INPUT "$@" -d "${PROXY_IP}" -p tcp --dport "${PROXY_PORT}" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 "$@" -d "${PROXY_IP}" -p tcp --dport "${PROXY_PORT}" -j ACCEPT
    echo "    host side: iptables INPUT rules for the agent's traffic"
    return 0
  fi
  if command -v nft >/dev/null 2>&1; then
    local dns=""
    if [[ "${DNS_ON}" == 1 ]]; then
      dns="${NFT_MATCH} ip daddr ${RESOLVER} meta l4proto { udp, tcp } th dport { 53, 5353 } accept"
    fi
    nft delete table inet "${table}" 2>/dev/null || true
    nft -f - <<EOF
table inet ${table} {
  chain input {
    type filter hook input priority -1; policy accept;
    ${NFT_MATCH} ct state established,related accept
    ${NFT_MATCH} ip daddr ${PROXY_IP} tcp dport ${PROXY_PORT} accept
    ${dns}
    ${NFT_MATCH} drop
  }
  chain forward {
    type filter hook forward priority -1; policy accept;
    ${NFT_MATCH} drop
  }
}
EOF
    echo "    host side: nft table inet ${table}"
    return 0
  fi
  if [[ "${ALLOW_UNHARDENED}" == 1 ]]; then
    warn "neither iptables nor nft on the host: the host side is NOT firewalled; the agent can reach every service on ${PROXY_IP} (OVARA_ALLOW_UNHARDENED=1)"
    return 0
  fi
  echo "ERROR: neither iptables nor nft on the host, so the host side of the boundary cannot be firewalled: the agent could reach every service on ${PROXY_IP}. Install one, or set OVARA_ALLOW_UNHARDENED=1 (ovara run -allow-unhardened-boundary) to go on without it." >&2
  exit 3
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
  # rule into ip6tables; honest about the tradeoff. A kernel built without
  # IPv6 has no such sysctl and no IPv6 egress to close, so that is not an
  # error; anything else that stops the sysctl still is.
  if ip netns exec "${NS_NAME}" test -d /proc/sys/net/ipv6; then
    ip netns exec "${NS_NAME}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "${NS_NAME}" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  else
    echo "    kernel has no IPv6; nothing to disable"
  fi

  # Host side, idempotent: the in-ns nft ruleset is the primary boundary,
  # but if it is ever weakened (bug, misapply, or a privileged agent), the
  # host must not give the veth a free pass to every host service (sshd,
  # docker.sock HTTP, kubelet :10250).
  NFT_MATCH="iifname \"${VETH_HOST}\"" host_harden "ovara_host_${short}" -i "${VETH_HOST}"

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
  * DNS: off (:53 dropped) unless OVARA_BOUNDARY_DNS=1 / --allow-dns,
    which DNATs it to ${RESOLVER}:5353. If that resolver answers arbitrary
    queries, the agent can exfiltrate through TXT. See
    proxy/scripts/resolver.md.
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
  # (and the resolver's DNS port when DNS is on). Idempotent like the netns
  # INPUT fix.
  if command -v iptables >/dev/null 2>&1; then
    local rules=("-s 172.30.0.0/24 -d ${PROXY_IP} -p tcp --dport ${PROXY_PORT} -j ACCEPT")
    if [[ "${DNS_ON}" == 1 ]]; then
      rules+=("-s 172.30.0.0/24 -d ${RESOLVER} -p udp --dport 53 -j ACCEPT" "-s 172.30.0.0/24 -d ${RESOLVER} -p tcp --dport 53 -j ACCEPT")
    fi
    rules+=("-s 172.30.0.0/24 -j DROP")
    for rule in "${rules[@]}"; do
      iptables -C DOCKER-USER ${rule} 2>/dev/null || iptables -A DOCKER-USER ${rule}
    done
  fi
  # DOCKER-USER only sees FORWARDED traffic. Packets to the bridge gateway
  # IP (${PROXY_IP} = the host itself) go through INPUT — and on a
  # default-ACCEPT host the agent would reach EVERY host-bound service:
  # sshd, docker.sock, kubelet :10250, and the gateway's approval API (an
  # agent that can reach the gateway can approve its own escalations).
  # Open only the proxy port (and resolver DNS), then DROP the rest from
  # the bridge subnet.
  NFT_MATCH="ip saddr 172.30.0.0/24" host_harden "ovara_host_docker" -s 172.30.0.0/24

  local DNS_FLAGS=""
  if [[ "${DNS_ON}" == 1 ]]; then
    DNS_FLAGS=$'    --dns '"${RESOLVER}"$' \\\n    --dns-search . \\\n'
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
${DNS_FLAGS}    -e HTTPS_PROXY=http://${PROXY_USERINFO}${PROXY_IP}:${PROXY_PORT} \\
    -e HTTP_PROXY=http://${PROXY_USERINFO}${PROXY_IP}:${PROXY_PORT} \\
    -e NO_PROXY=localhost,127.0.0.1 \\
    ${DOCKER_IMAGE}

Why each flag exists:
  --internal network     no NAT masquerade -> no route to the internet at all.
  --cap-drop ALL         agent cannot touch nftables, raw sockets, or the
                         interface config. NET_RAW alone would permit crafted
                         packets that skip TCP entirely.
  --dns ${RESOLVER}      (only with DNS on) docker injects this as the
                         container's resolver. Point it at your
                         deny-by-default forwarder (see
                         proxy/scripts/resolver.md). Without it the agent
                         has no DNS: it reaches the proxy by IP.
  --read-only            agent can't rewrite /etc/hosts or drop a resolver
                         config. (Caveat: /tmp still writable — mount tmpfs
                         if you care.)
  HTTPS_PROXY env        only works for cooperative clients. The *real*
                         guarantee is the internal network — env vars are a
                         convenience for tools that respect them.
  userinfo in the URL    is the proxy client credential (agent_token in
                         proxy.json). Without it the proxy returns 407.
                         The env var stays inside the agent env; the token
                         only buys proxy transit, never gateway privileges.

Honest gaps:
  * The host-side rules (applied above) restrict bridge-subnet egress to
    ${PROXY_IP}:${PROXY_PORT} (and ${RESOLVER}:53 with DNS on) — the gateway
    can no longer be hit on other ports. They apply to routed traffic; same-bridge
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
