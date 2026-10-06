# Spec: Action model and canonicalization (v0.9)

Goal: a **closed, versioned vocabulary** of consequential actions with
total, deterministic canonicalization. Fixes v1 audit-F5 (open string
`action_type`) and SEC-0010-class normalization bypasses.

## 1. Action record

```
Action := {
  type:       ActionType        # closed enum, versioned
  resource:   CanonicalResource # normalized per resource kind
  env:        "local"|"dev"|"staging"|"production"
  actor:      PrincipalID       # credential-derived, never request-supplied
  args_hash:  sha256            # over canonical arg form (see §3)
  taint:      TaintSet          # labels from provenance layer
  nonce:      128-bit           # replay protection
  issued_at:  timestamp         # ±Δ freshness window (v1 used 60s — keep, measure)
  min_epoch:  uint64            # revocation epoch bound
}
```

Differences from v1 `ActionRequest`: `actor` never crosses the wire as
a claim (derived from credential — keeps the SEC-0019 fix);
`args_hash` replaces free-form `metadata`; `taint` is new.

## 2. ActionType vocabulary (v2.0, closed)

From v1's 14, plus the seam's needs:

```
shell.exec        git.push        git.pull        git.fetch
git.checkout      git.force_push  github.push     github.pr
github.merge      github.delete_branch
ci.deploy         ci.build_trigger  ci.approval
fs.read           fs.write        fs.delete       fs.exec_spawn
net.egress        net.dns         mcp.call        pkg.install
proc.spawn        ipc.send        cred.inject     agent.message
```

Rules:
- Schema rejects unknown types outright (not "evaluate anyway" — v1's
  behavior). New types require spec version bump.
- `fs.exec_spawn`/`proc.spawn`/`net.egress` are the OS-seam types —
  mediation happens below the call layer for these.
- `mcp.call` carries tool name + server in resource (canonicalized).
- Unknown/unparseable → mapped to `raw.unknown` = highest risk class
  (never silently allowed; the mapping itself is logged).

## 3. Canonicalization (the bypass-critical part)

v1's SEC-0010 lesson: matching must happen on a **canonicalized
resource**, never the raw string.

### 3.1 Network resources
`net.egress` / `http.request` resources canonicalize to
`scheme://host[:port]/path-prefix`:
- lower-case scheme+host; IDNA→A-label; strip default port;
  reject userinfo (`user:pw@`) — informational only, denied at
  canonicalization time (v1 corpus: userinfo rows evaluated — v2
  rejects them as malformed).
- resolve DNS at decision time **and** enforcement time on the same
  resolution result (fixes the v1 TOCTOU window v1 closed in dial —
  keep that construction).
- suffix-match confusions (`api.github.com.evil.com`) eliminated by
  host-label-boundary matching only.

### 3.2 Shell commands (the hard case)
A `shell.exec` is canonicalized by **parsing**, not string-matching:
- tokenizer → command list (handles quoting, `|`, `&&`, `;`,
  subshells, `$(…)`, backticks).
- each command: resolved executable (PATH lookup against the sandbox
  image, not the requester env), argv array, redirects.
- env assignment prefixes and `alias`/`function` shadowing are
  resolved against a *known* shell baseline; unresolvable constructs
  (eval, dynamic source) → conservative class.
- equivalences: `sh -c X`, `bash -c X`, `python -c X` are ALL
  `exec_spawn` with interpreter-tagged argv — an agent can't
  downgrade enforcement by switching interpreters (v1 audit-F1:
  cooperative interceptor lets you run `python` instead of `sh`).

Canonical form = ordered list of {exe, argv[], redirects[], env_delta{}}.
`args_hash` = sha256 over its canonical JSON encoding.

### 3.3 FS paths
`fs.*` resources canonicalize via symlink-aware realpath **inside the
sandbox's mount view** — path traversal (`../../etc`) collapses to the
absolute path or is rejected. `~`, `$VAR`, globs are expanded/flagged
(globs → per-match decisions or class-level risk).

## 4. Determinism requirement (P11 hook)

canonicalize() is total, terminating, and pure: same bytes + same
baseline image ⇒ same Action. Property tests: idempotence
(canon∘canon = canon), injectivity where defined, total coverage of
the fuzz corpus (no parse panics — fuzz targets required).

## 5. Unknown→risk mapping

```
parseable & in-vocab      → normal evaluation
parseable & not in vocab  → deny (closed vocabulary)
unparseable               → raw.unknown → escalate-only risk class;
                              the parse failure itself is logged as a
                              spec-gap finding and contributes to a
                              sustained-failure self-test alarm
                              (F-SPEC-7: escalation must not become a
                              fuzzer-driven fatigue amplifier)
malformed resource        → reject at schema edge (fail-closed, P2)
```

## 6. Compat with v1

v1's 14 names map 1:1 to the v2 enum (kept verbatim except
`shell`/`exec` → `shell.exec`/`proc.spawn`). Migration table in
docs/migration.md; breaking changes (open vocabulary, advisory-only
fields) listed with reasons.
