# OVARA-SEC-0005 — `resource` field dropped on every production load path (resource matching is dead code)

**Severity:** HIGH
**Component:** runtime/gateway/internal/policy/file_store.go:14-21 (fileRule),
internal/handlers/policy.go (duplicate fileRule + parsePolicyJSON)
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)

## Reproduction (verified live)
1. Write policy.json with `{"action_type":"http.request","environment":"dev",
   "resource":"*https://api.github.com/*","allow":true}` + catch-all escalate.
2. Load via `POST /v1/policy/candidate/load` + `/promote` → version shows
   loaded, rules display WITHOUT resource field.
3. `POST /v1/runtime/check` resource=`GET https://evil.com/` → `allow`.
   The scoped rule matches everything — the field was silently dropped.

Confirmed statically: `fileRule` in `policy/file_store.go` and the
*duplicate* `fileRule` in `handlers/policy.go` both lack the field.
The only parser preserving it — `LoadStoreFromConfig` — has **zero
production callers** (grep-verified). Every real path drops the field:
startup file, watcher reload, candidate load/promote, simulate,
validate, policy-file writes, control-plane distribution.

## Root cause
Three parallel rule-parse paths; the Phase-0 fix edited exactly one
(the dead one). A shared `policy.Rule` unmarshal was not used — the
duplicated lite structs silently discard unknown fields.

## Security impact
An operator who writes `resource` restrictions believes egress is scoped;
the system applies the rule globally — silent permissiveness, the worst
failure mode for a security control. Compounds SEC-0013: even when the
field loads, the resource string itself needs canonicalization.

## Proposed fix
- Delete both lite structs; unmarshal directly into `policy.Rule`
  everywhere (single parse path).
- Add a load-time warning for unknown fields (typo'd field names should
  not silently become match-all).

## Regression test
`loadpaths_test.go` in the repo FAILS today
(`TestLoadStoreFromFile_PreservesResource`) — it must pass after the
fix, and a second test should load via `parsePolicyJSON`/`candidate_file`
to cover the handler path.

## Residual risk
None once unified — file/JSON parsing covers all callers.


## Remediation (P0.5 — VERIFIED)

`policy.ParseStore` (runtime/gateway/internal/policy/file_store.go) is now the
single canonical parser: `DisallowUnknownFields` into the shared `Rule` struct
— `resource`, `min_trust_score`, `min_trust_level`, `conditions`, `description`
all preserved. `fileRule` is a type alias, not a second struct. Every load path
(startup file, reload, candidate load/promote, simulate, validate, distribution)
routes through it. A failed initial load now fails startup closed instead of
silently falling back to the built-in default policy.

Regression tests: `policy/loadpaths_test.go`, `TestLoadStoreFromFile_PreservesResource`,
`canonical_test.go` — plus live replay (scoped candidate policy constrained egress).

## Remediation addendum (red-team round 2)

Independent review found the strict parser still erased two JSON edge
cases into silent scope-widening. Both fixed in `parseFilePolicyStrict`
(file_store.go), which now token-scans every rule before decoding:

- `"resource": null` decoded to `""` → match-everything. Now rejected
  with an explicit error. Verified live via candidate load.
- Duplicate `"resource"` keys last-wins silently
  (`{"resource":"*https://api.github.com/*","resource":""}` → global
  allow). Now rejected — any duplicate key fails the parse.
- `/v1/policy/validate` used non-strict `json.Unmarshal`; now shares
  `parseFilePolicyStrict` so validate == load.
- `LoadStoreFromConfig` (dead code) silently dropped non-string
  `resource` — deleted.

Regression test: `TestParseStore_Strictness` in
`internal/policy/file_store_test.go`. Status remains **VERIFIED**.
