package vm

import (
	"fmt"
	"strings"
)

// lockdownTable is the nft table the guest's lockdown lives in; Verify
// looks for it by name.
const lockdownTable = "ovara_vm"

// LockdownRuleset is the guest's egress rule, the same shape as the netns
// boundary's (proxy/scripts/setup-egress-boundary.sh): every packet the
// guest sends is dropped unless it is loopback, the reply to a connection
// made to the guest (the driver's own control channel), or a TCP connection
// to the host's proxy or command-gate port. DNS and QUIC are dropped by
// name so no later rule can open them by accident. The inet family covers
// IPv6 as well: v6 egress falls to the drop policy.
//
// hostIP is the host as the guest reaches it. It may be a shell variable
// reference such as "${HOST_IP}" when the ruleset is rendered into the
// provisioning script, where the address is only known inside the guest.
func LockdownRuleset(hostIP string, proxyPort, gatePort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", lockdownTable)
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority 0; policy drop;\n")
	b.WriteString("    oifname \"lo\" accept\n")
	b.WriteString("    ct state established,related accept\n")
	fmt.Fprintf(&b, "    ip daddr %s tcp dport { %d, %d } accept\n", hostIP, proxyPort, gatePort)
	b.WriteString("    udp dport 53 drop\n")
	b.WriteString("    tcp dport 53 drop\n")
	b.WriteString("    udp dport 443 drop\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

// provisionScript is what the VM runs as root at every boot. It installs
// nft if the image lacks it (the only time the guest uses the network
// directly, and before any agent exists), then replaces whatever lockdown
// was there with the current one. It exits non-zero when the host cannot be
// resolved or the rules do not load, which leaves the VM without a verified
// lockdown, so Verify refuses it.
//
// hostName is how the guest names the host (Lima: host.lima.internal); it
// is resolved from the guest's hosts file, not DNS.
func provisionScript(hostName string, proxyPort, gatePort int) string {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	b.WriteString("# Ovara VM lockdown: the guest reaches the host's proxy and command gate, nothing else.\n")
	b.WriteString("set -eu\n")
	b.WriteString("command -v nft >/dev/null 2>&1 || { apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables; }\n")
	fmt.Fprintf(&b, "HOST_IP=\"$(getent ahostsv4 %s | awk 'NR==1{print $1}')\"\n", hostName)
	fmt.Fprintf(&b, "[ -n \"$HOST_IP\" ] || { echo 'ovara: cannot resolve %s' >&2; exit 1; }\n", hostName)
	fmt.Fprintf(&b, "nft delete table inet %s 2>/dev/null || true\n", lockdownTable)
	b.WriteString("nft -f - <<EOF\n")
	b.WriteString(LockdownRuleset("${HOST_IP}", proxyPort, gatePort))
	b.WriteString("EOF\n")
	// IPv6 is already dropped by the inet table's policy; turning it off
	// as well means nothing else on the guest can come to depend on it.
	b.WriteString("sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 || true\n")
	return b.String()
}
