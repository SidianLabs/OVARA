# OVARA-SEC-0015 — Resolver path open by design; no deny-by-default DNS shipped (DNS tunneling residual)

**Severity:** INFORMATIONAL (accepted residual, must be documented loudly)
**Component:** boundary design — resolver port 53/5353 to gateway IP
**Status:** CONFIRMED LIVE

## Evidence
The boundary intentionally permits UDP+TCP 53/5353 to the resolver
address (`10.200.188.1` / `172.30.0.1`). Verified live: the port path is
reachable from the agent (this environment had no resolver service
listening — path OPEN, service absent). All other DNS destinations are
dropped by the output policy.

## Threat
If a resolver (or any UDP/53 listener) is present, DNS-over-allowed-port
is a sanctioned low-bandwidth covert channel: the agent can exfiltrate
data in queries or receive data in responses — fully within policy,
receipted only as "DNS happened" if at all.

## Root cause
DNS is required for the proxy flow to be useful (hostnames), and the
chosen design delegates resolution to a host-side resolver that doesn't
ship with the repo — the *path* is enforced, the *resolver behavior* is
not.

## Security impact
Data exfiltration channel exists whenever a resolver is actually
deployed without query allowlisting/rate limits. Not a boundary bug —
a documented gap between "resolver reachable" and "resolver safe".

## Proposed fix (P1 — deny-by-default resolver)
- Ship a minimal resolver that: allowlists only names needed by bound
  creds/policy hosts, rate-limits, rejects TXT/ANY/odd qtypes, and
  logs every query as evidence.
- `ovara doctor` flags when the resolver path is open with no resolver
  or an unrestricted resolver present.

## Regression test
Agent queries `allowed-host.example` → resolves; `attacker.example` →
refused + event; TXT query → refused.

## Residual risk
Even an allowlisting resolver leaks "did the agent look up X" metadata;
acceptable at P1, revisit for P3 (protocol-aware filtering).
