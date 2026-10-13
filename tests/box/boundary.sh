#!/usr/bin/env bash
# The netns boundary script (proxy/scripts/setup-egress-boundary.sh) on its
# own: DNS is off unless turned on, the host side is firewalled with
# iptables or, without it, nft, and with neither the script stops.
#
# Needs root, ip, nft, iptables and python3. It CHANGES THIS MACHINE while it
# runs (a network namespace "ovtb", a veth, INPUT rules and an nft table for
# that veth) and removes all of it at the end. Run it on a disposable
# machine or in the privileged test container:
#
#   tests/box/run.sh boundary                    in the privileged test container
#   OVARA_TEST_ON_HOST=1 bash tests/box/boundary.sh   here (root)
set -u
[ "${OVARA_TEST_ON_HOST:-}" = 1 ] || { echo "this test changes this machine's network setup; run it on a disposable one with OVARA_TEST_ON_HOST=1" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$here/../..}"
NS=ovtb; VETH=vo-ovtb-h; IDX=77; HOST=10.200.$IDX.1; PORT=19443; OTHER=19922
work="$(mktemp -d)"
SCRIPT="$work/setup-egress-boundary.sh"
tr -d '\r' < "$REPO/proxy/scripts/setup-egress-boundary.sh" > "$SCRIPT"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $2, got $3"; fi; }

teardown() {
  ip netns del $NS 2>/dev/null; ip link del $VETH 2>/dev/null
  iptables -S INPUT 2>/dev/null | grep -- "$VETH" | sed 's/^-A /-D /' | while read -r rule; do iptables $rule; done
  nft delete table inet ovara_host_ovtb 2>/dev/null
  true
}
listeners=()
listen() { # addr port: accept and close, forever
  python3 -c "
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(16)
while True: s.accept()[0].close()" "$1" "$2" & listeners+=($!)
}
from_ns() { # addr port -> OPEN/BLOCKED, as the agent
  ip netns exec $NS timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null && echo OPEN || echo BLOCKED
}
setup() { # extra env... ; then the script's output in $work/out
  env "$@" bash "$SCRIPT" netns --name $NS --subnet-idx $IDX --proxy-port $PORT > "$work/out" 2>&1
}
cleanup() { teardown; for p in "${listeners[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$work"; }
trap cleanup EXIT
teardown

echo "=== default: no DNS; host side with iptables"
setup; check "setup succeeds" 0 $?
listen $HOST $PORT; listen $HOST $OTHER; listen $HOST 5353; sleep 0.5
check "the proxy port is reachable" OPEN "$(from_ns $HOST $PORT)"
check "another host service is not" BLOCKED "$(from_ns $HOST $OTHER)"
check "DNS to anywhere is not redirected to the resolver" BLOCKED "$(from_ns 9.9.9.9 53)"
check "DNS to the host's resolver port is not open" BLOCKED "$(from_ns $HOST 5353)"
rules="$(ip netns exec $NS nft list ruleset)"
grep -q 'dnat' <<<"$rules" && bad "no DNAT for :53" "$rules" || ok "no DNAT for :53"
grep -q 'udp dport 53 drop' <<<"$rules" && ok "udp :53 dropped" || bad "udp :53 dropped" "$rules"
iptables -C INPUT -i $VETH -j DROP 2>/dev/null && ok "host INPUT drops the rest from the veth" || bad "host INPUT drop" "$(iptables -S INPUT)"
iptables -S INPUT | grep -- "$VETH" | grep -q 'dports 53' && bad "no host INPUT rule for DNS" "$(iptables -S INPUT)" || ok "no host INPUT rule for DNS"
# the host side holds on its own
ip netns exec $NS nft flush ruleset
check "with the in-ns rules gone, another host service is still not reachable" BLOCKED "$(from_ns $HOST $OTHER)"
check "with the in-ns rules gone, the proxy port still is" OPEN "$(from_ns $HOST $PORT)"
teardown

echo "=== OVARA_BOUNDARY_DNS=1: :53 goes to the resolver"
setup OVARA_BOUNDARY_DNS=1; check "setup succeeds" 0 $?
check "DNS to anywhere reaches the resolver (DNAT to :5353)" OPEN "$(from_ns 9.9.9.9 53)"
check "the proxy port is reachable" OPEN "$(from_ns $HOST $PORT)"
check "another host service is not" BLOCKED "$(from_ns $HOST $OTHER)"
teardown

echo "=== no iptables: the host side with nft"
shim="$work/bin"; mkdir -p "$shim"
for c in bash ip nft test sysctl mktemp rm cat sed head cut tr cksum grep; do
  p="$(command -v $c)" && ln -s "$p" "$shim/$c"
done
setup PATH="$shim"; check "setup succeeds" 0 $?
grep -q 'nft table inet ovara_host_ovtb' "$work/out" && ok "the script says it used nft" || bad "nft host side" "$(cat "$work/out")"
nft list table inet ovara_host_ovtb >/dev/null 2>&1 && ok "host nft table is there" || bad "host nft table" ""
iptables -S INPUT | grep -q -- "$VETH" && bad "no iptables rules" "$(iptables -S INPUT)" || ok "no iptables rules"
ip netns exec $NS nft flush ruleset
check "with the in-ns rules gone, another host service is still not reachable" BLOCKED "$(from_ns $HOST $OTHER)"
check "with the in-ns rules gone, the proxy port still is" OPEN "$(from_ns $HOST $PORT)"
teardown

echo "=== neither iptables nor nft: the script stops (docker mode, docker faked)"
shim2="$work/bin2"; mkdir -p "$shim2"
for c in bash mktemp rm cat sed head cut tr cksum grep; do
  p="$(command -v $c)" && ln -s "$p" "$shim2/$c"
done
printf '#!%s\nexit 0\n' "$(command -v bash)" > "$shim2/docker"; chmod 755 "$shim2/docker"
env PATH="$shim2" bash "$SCRIPT" docker --proxy-port $PORT > "$work/out" 2>&1; code=$?
check "exit status 3" 3 $code
grep -q 'cannot be firewalled' "$work/out" && ok "it says why" || bad "message" "$(cat "$work/out")"
env PATH="$shim2" OVARA_ALLOW_UNHARDENED=1 bash "$SCRIPT" docker --proxy-port $PORT > "$work/out" 2>&1; code=$?
check "OVARA_ALLOW_UNHARDENED=1 goes on" 0 $code
grep -q 'NOT firewalled' "$work/out" && ok "with a warning" || bad "warning" "$(cat "$work/out")"
grep -qE -- '^ +--dns [0-9.]+ \\$' "$work/out" && bad "the recipe has no --dns without DNS" "$(grep -- --dns "$work/out")" || ok "the recipe has no --dns without DNS"
env PATH="$shim2" OVARA_ALLOW_UNHARDENED=1 OVARA_BOUNDARY_DNS=1 bash "$SCRIPT" docker --proxy-port $PORT > "$work/out" 2>&1
grep -qE -- '^ +--dns 172\.30\.0\.1 \\$' "$work/out" && ok "with DNS on, the recipe has --dns" || bad "recipe --dns" "$(sed -n '/docker run/,/NO_PROXY/p' "$work/out")"

echo; echo "RESULT: $pass passed, $fail failed"
[ $fail = 0 ]
