# OVARA-SEC-0006 — Position-blind idempotency: stale ACCEPTs shadowed by new DROP (and vice versa)

**Severity:** MEDIUM
**Component:** proxy/scripts/setup-egress-boundary.sh (INPUT section)
**Status:** CONFIRMED LIVE

## Reproduction (verified live)
Host had a stale rule `INPUT -s 172.30.0.0/24 -d 172.30.0.1 --dport 9443
ACCEPT` from a previous run. New run inserted `INPUT -s 172.30.0.0/24
DROP` at position 1; the `-C` existence check saw the 9443 ACCEPT exists
→ skipped re-insert → ACCEPT ended up BELOW the DROP → agent→proxy:9443
dropped → **proxy unreachable from the docker agent** (verified live:
`proxy:9443 BLOCKED` inside `audit-egress`).

Symmetric hazard: stale ACCEPTs for ports the operator *closed* persist
above the DROP — a re-run with `--proxy-port 8443` leaves 9443 reachable
from the agent (fail-OPEN direction).

## Root cause
`iptables -C <rule> || iptables -I INPUT 1 <rule>` checks existence, not
position. Rules accumulate forever; no teardown; DOCKER-USER appends
(`-A`) so re-runs place new ACCEPTs below an existing DROP → dead rules.

## Security impact
Fail-closed liveness break in the common case (redeploy/port change);
fail-open residual when stale accepts grant superseded access. Either
way the script reports success on a broken boundary — zero post-apply
verification.

## Proposed fix
- For each managed rule: delete all copies (`while iptables -D ...`),
  then `-I INPUT 1` — deterministic position every run.
- Insert managed rules as a marked block (comment match or dedicated
  chain `OVARA-INPUT` + jump) so teardown/reorder is safe.
- Post-apply self-test: `iptables -C` each rule AND verify order
  (DROP must be last among managed rules); probe the proxy port and a
  denied port; refuse to report success if wrong.

## Regression test
tests/redteam: pre-seed a stale ACCEPT below where the DROP will land →
run setup → assert agent→proxy works and DROP ordering is correct.

## Residual risk
Operator tooling inserting `iptables -I INPUT 1 -j ACCEPT` post-setup
still overrides everything — mitigated by the integrity monitor (P2),
not preventable by the script.
