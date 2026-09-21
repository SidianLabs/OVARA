# OVARA-SEC-0013 — Boundary posture gaps the script doesn't control: host FORWARD, docker IPv6, reused networks

**Severity:** MEDIUM
**Component:** proxy/scripts/setup-egress-boundary.sh
**Status:** CONFIRMED (reviewer + inspection; deployment-conditional)

## Evidence
- **FORWARD uncontrolled**: netns mode sets no FORWARD rules; if the host
  has forwarding enabled (common on routers/VMs), agent packets routed
  via the veth could reach other interfaces/WAN without touching INPUT.
  This host's FORWARD policy happened to be DROP — ambient luck again.
- **Docker IPv6**: the compose/network setup never disables or rules
  IPv6 on the bridge; where Docker v6 is enabled, v6 traffic may evade
  the v4 INPUT/DOCKER-USER rules entirely (nft `inet` covers it only
  inside the netns mode, not for docker's own chains).
- **Reused networks**: pointing the script at a pre-existing docker
  network skips validation — `enable_icc`, subnet, and resolver address
  assumptions are unchecked. A reused network with icc=true silently
  re-opens same-bridge L2.
- **No teardown/persistence story**: rules are inserted but nothing
  reconciles drift after the run (see SEC-0006).

## Root cause
The script configures the paths it knows about but doesn't assert the
complement (no other path exists) — security by enumeration, not by
deny-default.

## Security impact
On hosts with permissive FORWARD/v6/reused networks the agent gets
unenforced egress or lateral reach while setup reports success.

## Proposed fix
- Set FORWARD DROP for the managed subnets (and DOCKER-USER already
  does for docker) — assert it, don't assume.
- Explicitly disable IPv6 on created networks (`--ipv6=false`) or add
  v6 DOCKER-USER rules.
- Validate reused networks: fail if icc=true or resolver IP collides.
- `ovara doctor` audits actual posture (v4+v6+forward) at runtime.

## Regression test
Host with FORWARD ACCEPT → run setup → assert forwarded traffic from
agent subnet dies; docker run with v6 enabled → assert v6 egress dies.

## Residual risk
Hosts where the operator deliberately enables forwarding need a
scoped-forward design (only to upstream iface) — a policy decision, not
a bugfix.
