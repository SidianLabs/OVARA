# OVARA-SEC-0010 — Resource matcher is raw substring glob: host/path/userinfo/case normalization bypasses

**Severity:** HIGH
**Component:** runtime/gateway/internal/policy MatchResource + the proxy's
resource-string construction
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)

## Evidence
`MatchResource` splits the pattern on `*` and does `strings.Index` on the
raw resource string `"METHOD scheme://host[:port]/path"`. No URL parsing,
no canonicalization, no component awareness.

Confirmed attack classes (app-sec reviewer + receipt inspection):
- **Explicit :443** — the MITM path emits `GET https://api.github.com:443/x`;
  the documented pattern `*https://api.github.com/*` does NOT match
  (the `*` after host is consumed by `:443`). Host-anchored patterns are
  broken on the *normal* HTTPS path — receipts show `"url": "...:443/"`.
- **Userinfo pivot** — `https://api.github.com@evil.com/` contains the
  substring `https://api.github.com` → matches `*api.github.com*` while
  dialing evil.com.
- **Suffix hosts** — `api.github.com.evil.com/` matches `*api.github.com*`.
- **Path embedding** — `https://evil.com/redir?u=api.github.com` matches.
- **Case** — host matching is case-sensitive in the matcher while creds
  binding is case-insensitive → `API.GITHUB.COM` bypasses host policy yet
  still receives credentials (reviewer F-verified).
- **Ports** — `api.github.com:444` matches `*api.github.com*` patterns.
- Method case variants bypass `GET`-prefixed patterns.

## Root cause
Authorization compares a rendered string, not the parsed/canonical
destination that will actually be dialed.

## Security impact
Every resource-scoped rule (once SEC-0005 is fixed) is bypassable by
adversarial URLs that *display* the allowed host while dialing an
attacker host — credentials injected into attacker infrastructure.

## Proposed fix
- Parse the request into components (scheme/host/port/path); match host
  on canonicalized (lowercase, trailing-dot-stripped) hostname with
  proper boundary semantics (`host == allowed` or suffix `.allowed`),
  match path separately, match method case-insensitively.
- Construct the policy resource string from the *parsed* CONNECT/URL
  target, never from raw request text; strip default ports (`:443` for
  https) before matching.
- Reject userinfo in upstream URLs for credentialed requests.

## Regression test
Attack matrix in this file (each row) must produce deny — see
`tests/redteam/policy` cases + the URL-normalization unit tests.

## Residual risk
DNS-rebinding between check and dial needs dial-time re-verification
(the SSRF check already re-checks; resource check should too).


## Remediation (P0.5 — VERIFIED)

`MatchResource` canonicalizes `METHOD scheme://host[:port]/path` resources:
lowercased host+method, trailing-dot stripped, default ports normalized
(`:443`==`https` no-port), userinfo rejected, exact host boundary unless the
pattern authority carries `*`, IP literals don't match hostname patterns.
Non-URL resources keep glob semantics. Proxy strips userinfo from receipts.

Regression tests: `policy/canonical_test.go` full attack matrix (suffix host,
userinfo both directions, case, ports, :443, IP literals, method case).
Live replay via /v1/policy/simulate: evil suffix→escalate, :443→allow,
userinfo→escalate, case→allow.

## Remediation addendum (red-team round 2)

- **Space-truncation smuggling**: `https://evil.com/?x=
  https://api.github.com/` placed the hostile URL in the "method" slot,
  which canonicalization discarded — the tail was authorized (live
  `allow` via agent-token `/v1/runtime/check`). Fixed: the pre-space
  segment must be a bare method token (letters only), and a post-URL
  segment must be a strict `refs/` git ref list — otherwise fail
  closed. Verified live: all crafted forms now escalate.
- **Git ref suffix**: the proxy appends `" refs/heads/x"` to git-push
  resources; canonicalization previously mangled it so
  `*git-receive-pack refs/heads/prod*` never matched (deny-bypass).
  Fixed: the ref suffix is preserved verbatim.
- Matcher held against ~60 independent evasion variants (userinfo,
  suffix/prefix hosts, percent/IDN homoglyphs, port tricks, IP literal
  forms, IPv6, bracket tricks, backslashes, scheme tricks).

Regression: `TestMatchResource_CanonicalAttacks` extended in
`internal/policy/canonical_test.go`. Status remains **VERIFIED**.
