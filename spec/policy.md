# C2 — Policy (spec 0.1)

A policy is the portable artifact: one document that says what an agent
may do without asking, what a person must decide, and what is refused. Two
implementations given the same policy and the same action must reach the
same decision. Schema: [`schemas/policy.schema.json`](schemas/policy.schema.json).

## 1. The document

```json
{
  "version": "2026-10",
  "precedence": "most-specific",
  "default": "escalate",
  "rules": [
    {"action_type": "http.request", "environment": "*", "resource": "GET https://pypi.org/*", "allow": true,
     "description": "package index reads"},
    {"action_type": "http.request", "environment": "*", "resource": "*://pastebin.com/*", "deny": true,
     "description": "data-dump site"},
    {"action_type": "shell", "environment": "*", "resource": "shell:*git push*", "escalate": true,
     "description": "pushes need a person"}
  ]
}
```

| Member | Meaning |
|---|---|
| `version` | a label; part of the policy hash that every receipt carries. |
| `precedence` | `most-specific` (what `ovara init` writes; §4) or `order` (legacy; §5). Absent means `order`. |
| `default` | the decision when no rule matches: `escalate` (absent) or `deny`. |
| `rules` | the rules; order is irrelevant under `most-specific`. |

A rule has `action_type`, `environment`, an optional `resource` pattern,
exactly one effect (`allow`, `deny` or `escalate`), an optional
`description` (which names the rule in decisions and receipts), and the
legacy members `min_trust_score`, `min_trust_level`, `require_lease`,
`conditions` for SDK callers.

## 2. Loading: what is refused

The parser is strict and the same on every path (file, candidate, simulate,
distribution):

- an unknown member, in the document or a rule (a typo can never widen a rule silently);
- a rule without `action_type` or without `environment`: it would match nothing, and a deny that matches nothing is a deny the author believes in;
- a `precedence` or `default` outside the enumerations;
- a `conditions` key other than `depends_on` and `ref`: the gateway evaluates no condition, so such a rule would apply to every request.

Two rules with the same `action_type`, `environment` and `resource` but
different effects are reported (not refused); under `most-specific` the
tie-break decides between them (§4).

The policy in force has a hash, `sha256:<hex>` over its canonical JSON. It
is returned with every decision (`receipt_stub.policy_hash`) and written
into every receipt, so a receipt names the policy it was decided under.

## 3. Matching

A rule matches an action when all of these hold:

1. `action_type` equals the action's, or is `*`;
2. `environment` equals the action's, or is `*`;
3. `resource` is empty, or matches the resource:
   - a **URL-shaped** pattern is matched against the canonical form
     (`resource-model.md` §2) with the host-boundary check; a resource
     that is not canonical matches no URL-shaped pattern;
   - any other pattern is a glob over the resource string: `*` matches any
     run of characters, everything else is literal.

**Ports.** A `deny` or `escalate` rule whose URL-shaped pattern names no
port matches the resource on any port (`*://pastebin.com/*` also refuses
`https://pastebin.com:8443/x`; an escalate on a host asks on every port of
it). An `allow` rule matches the port exactly: an allow for
`https://github.com/*` does not cover `https://github.com:8443/`. Widening
is reserved for the effects that can only make a decision stricter.

**Several refs.** A push resource naming several refs is matched once per
ref; the strictest per-ref decision is the push's (`resource-model.md` §2.2).

**Deletions.** An `allow` whose pattern names refs (` refs/...`) covers
deleting a ref only if it says so with `(delete)`: `refs/heads/feature/*`
allows pushing feature branches, not deleting them. A `deny` or `escalate`
that names refs covers the ref with or without the marker: `deny ...
refs/heads/main` also refuses deleting `main`.

## 4. Precedence `most-specific`

Among the rules that match:

1. The rule with the highest **specificity** decides. Specificity is the
   number of literal (non-`*`) characters in the pattern; an empty pattern
   scores 0.
2. Equal specificity: **deny > allow > escalate**.
3. Two limits keep specificity from being gamed with text the agent
   controls (a path, a command line or a ref can always be made longer so
   that it also matches a longer pattern):
   - a matching **deny always beats a matching escalate**, whatever their
     specificity: escalate may make an allow stricter, never a deny softer;
   - an **allow beats a less specific deny only if it names the target at
     least as precisely as every matching deny**. For URL resources that is
     the host: the allow's **host specificity** (literal characters in its
     authority) must be at least every matching deny's; a long path under a
     wildcard host is not more specific than a deny that names the host.
     For other resources (commands, paths, packages) it is the **literal
     prefix** before the first `*`: `shell:*codex*` cannot outrank
     `shell:sudo*`, but `shell:sudo -n true` can.
4. No match: the document's `default`.

The rule that decided is named in the decision (`matched_rule`) and the
receipt (`rule`) by its `description`, or a generated name.

## 5. Precedence `order` (legacy)

Every matching `deny` is checked first, then every matching `allow`, then
every matching `escalate`, whatever their patterns. Policies written before
`most-specific` existed use it; new policies must not.

## 6. Not in 0.1

Named profiles (`strict`, `balanced`, `observe`) and policy layering (an
organisation's policy that a project's may only narrow) are planned and
will be additive: a document without them means what it means today.

## 7. Tests that fix this contract

`runtime/gateway/internal/policy`: `spec_schema_test.go`,
`TestParseStoreRefusesRulesThatCanNeverMatch`,
`TestParseStore_RefusesUnevaluatedConditions`, `TestMatchResource*`,
`TestMatchResourceAnyPort`, `TestSpecificity`, `TestSplitRefList`,
`FuzzMatchResource`, `FuzzMatchCanonicalResource`, `FuzzSplitRefList`;
`runtime/gateway/internal/evaluator`: `TestMostSpecific*`
(`_EscalateNeverBeatsDeny`, `_URLEscalateNeverBeatsDeny`,
`_BroadHostAllowNeverBeatsNarrowHostDeny`, `_AllowOneWriteDenyTheRest`,
`_SpecificDenyStillWins`, `_TiesAndScope`, `_DefaultDeny`),
`TestShellAllowMustNameTheProgramToBeatADeny`,
`TestDenyHostRuleMatchesAnyPort`, `TestEscalateHostRulesMatchAnyPort`,
`TestGitPush_EachRefDecidedOnItsOwn`, `TestGitPush_ExactRefDenyCoversDeletion`,
`FuzzPrecedence`. The promises these keep are `docs/GUARANTEES.md` §4.
