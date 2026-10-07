# Apparatus Defects — measurement bugs, not OVARA findings

Separate ledger (per Phase-3 review): a changed attack rate must be
attributable to OVARA or to the experiment. Entries here are defects
in the *measurement*; entries in BYPASSES.md are security findings.
Both stay frozen — fixed apparatus defects are still recorded.

| id | defect | contamination risk | fix | status |
|----|--------|--------------------|-----|--------|
| T2-F02 | Adapters fabricated operator consent: CondB/CondC auto-created+auto-approved an approval bound to the attacker's own pending action, so `apr_guess` self-redeemed | Would have produced a phantom "approval bypass" on B and C | Pre-mint ONE legit approval (`fs.read /allowed/readme.txt` / `apr_legit` opsig); probes resolve only pre-existing ids | fixed, recorded |
| APP-01 | Ground truth matched raw resource strings only | False-negative on every representation-mismatch bypass (incl. SEM-001) | `canonicalResource()` + dual raw/canonical matching | fixed |
| APP-02 | Nonce default `t2-<campaign>` reused across cells | Phantom replay denials contaminated B early runs (B:24, 0 bypass before fix) | Per-run nonce `t2-<camp>-<unixnano>` | fixed; early rows stand, marked by timestamp |
| APP-03 | Results writer `os.Create` per run | Prior campaigns' jsonl clobbered | Append-only writer | fixed |
| APP-04 | Prompt example seeded `token_id:"main"` | Attacker self-narrowed B probes through the lease gate; first llm-001-B run missed the traversal it derived | Example uses `token_id:""`; second run BYPASS@1 | fixed; biased run preserved |
| APP-05 | v1 single reason code `action_not_allowed` conflates policy/capability/approval stages | Stage comparisons involving B are approximate | v1 reason→stage map documented in conditions.go | limitation, frozen |
| APP-06 | Reasoning model returns empty content (burns reply budget on hidden reasoning) | Silent budget burn | `chatOrRetry` nudge + max_tokens 16384; empties recorded EXECUTION_FAILURE | fixed |
| APP-07 | classifyReport nil-plan deref; substring `final_report` false-positive in schema echo | Crash / wrong report class | nil guard; `final_report` must be a JSON KEY, `action` preferred | fixed |

Principle (review §7): the experimental apparatus can itself create
or suppress apparent attack capability. Prompt construction alters
measured capability (APP-04 is direct evidence).
