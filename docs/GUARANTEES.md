# What Ovara guarantees

This file is the single source of truth for what Ovara promises. Each
guarantee says what holds, in which mode, under which conditions, and
which tests check it. The README, the threat model and the box plan may
only claim what is written here. If a claim elsewhere is stronger than
this file, this file is right and the other one is a bug.

A guarantee is listed only if a test checks it. Go tests run in CI on
every push (`go-tests.yml`); the scripts under `tests/` run in the
`scenarios.yml` workflow. Each test name below is a Go test function in
the package named before it, unless it is a script path. Tests marked
*(root)* skip unless run as root; in CI the same checks run through
`tests/box/box.sh` in a privileged container. Fuzz targets run their seed
corpus with the unit tests; `fuzz.yml` fuzzes some of them nightly.

Last checked against the code: October 2026 (pre-release 0.9.x line).

## Modes

| Mode | What it is | Where |
|---|---|---|
| **Cooperative** | `ovara run` plus `ovara env`: the agent is *asked* to use the proxy through environment variables | Linux, macOS, Windows |
| **Enforced boundary** | `ovara run --boundary netns\|docker`: the agent runs where the only route out is the proxy | Linux, root to set up |
| **Box tier 1** | `ovara box`: a separate user, a network namespace with the same boundary, a root file system of its own, a copy of the project, and a check on every command | Linux, root |
| **Box tier 2** | `ovara box -tier 2`: the same in a container with no network interface but loopback, no capabilities and a read-only root | Linux, root, Docker |

"All modes" below means the guarantee holds for every request that goes
through the proxy. In cooperative mode, a program that ignores the proxy
is not covered at all (see [Not guaranteed](#not-guaranteed)).

---

## 1. Network egress

### 1.1 Every request through the proxy is decided by policy before it goes out
- **Holds in:** all modes.
- **Conditions:** none. If the gateway cannot be reached, the request is refused (unless `fail_open` is set in `proxy.json`, which `ovara doctor` reports).
- **Tests:** `proxy/internal/proxy`: `TestGatewayDownFailsClosed`, `TestPlainHTTPFailClosed`, `TestPlainHTTPDeny`, `TestConnectMITM`, `TestEscalatedRequestRunsOnlyAfterApproval`, `TestDeniedApprovalNeverReachesUpstream`, `TestUnansweredApprovalTimesOutWithoutRunning`.

### 1.2 There is no way out except through the proxy
- **Holds in:** enforced boundary, box tier 1, box tier 2.
- **Conditions:** the agent is not root inside the boundary. The host side of the boundary is firewalled (iptables or nft); if neither tool exists, setup stops unless `-allow-unhardened-boundary` is given.
- **What it covers:** direct TCP and UDP, other host ports, the cloud metadata address, IPv6, ICMP, QUIC, DNS (off unless `OVARA_BOUNDARY_DNS=1`). The proxy listens on the boundary address and loopback, never on every interface.
- **Tests:** `tests/redteam/boundary/run.sh` (netns, docker, and from inside a tier 2 box), `tests/box/boundary.sh` (`tests/box/run.sh boundary`), `tests/agents/run.sh enforced <agent>` and `box <agent>`; `proxy/cmd/ovara`: `TestProxyListenAddrs`, `TestTier1IsolatedFileSystem` *(root)* (only `lo` in the box).

### 1.3 A host name is not resolved before policy has allowed a request to it
- **Holds in:** all modes.
- **Tests:** `proxy/internal/proxy`: `TestConnectDoesNotResolveNamesBeforePolicy`.

### 1.4 Reads cannot carry much data
- **Holds in:** all modes.
- **What it covers:** a GET or HEAD with a body, a query over 512 bytes, or more than 2 KB of path, query and forwarded headers together is refused, even on a trusted host. Method spelling does not matter (`get` is checked like `GET`). Method-override headers are not forwarded. CONNECT goes to port 443 only, and an absolute-URI `https://` request to another port is refused.
- **Tests:** `proxy/internal/proxy`: `TestReadsThatCarryDataAreRefused`, `TestLowercaseMethodStillGuarded`, `TestReadBudgetCoversPathAndHeaders`, `TestTunnelHeadersAreBounded`, `TestMethodOverrideHeadersAreNotForwarded`, `TestConnectNon443Denied`, `TestPlainProxyHTTPSNon443Refused`, `TestLongResourceIsRefusedAndReceiptBounded`.

### 1.5 Only hosts on the trusted list are read without asking
- **Holds in:** all modes.
- **Conditions:** the default policy from `ovara init` is kept. "Trust this host for reads" from an approval adds a reads-only rule for one host that is removed when `ovara run` stops.
- **Tests:** `tests/scenarios/scenarios.sh`; `proxy/cmd/ovara`: `TestTrustReadHost_AddsReadOnlyRulesOnce`, `TestTrustReadHost_SaysWhereAndWhenAndLastsOneRun`, `TestUI_TrustButtonSaysWhatItDoes`.

### 1.6 The model API is limited to inference, and its bodies are read
- **Holds in:** all modes.
- **Conditions:** the default policy and `model_gate` are kept.
- **What it covers:** only the inference endpoints of the model hosts are allowed without asking. Every model request body is read; one that asks the provider to fetch a URL or connect to a server (MCP connectors, web fetch or search tools, images or documents by URL) pauses for a person; an encoded, unreadable or oversized body is refused.
- **Tests:** `proxy/internal/proxy`: `TestModelGate`.

### 1.7 Allowed traffic to one host is metered
- **Holds in:** all modes.
- **Conditions:** `egress_budget` is not turned off. Defaults: about 600 requests or 8 MB of request bytes per host per minute (more for package registries); past that a person is asked once, and an approval doubles the allowance for the run.
- **Tests:** `proxy/internal/proxy`: `TestEgressBudgetAsksPastTheDefaultAllowance`, `TestEgressBudgetApprovalDoublesAllowance`, `TestEgressBudgetCountsBytes`, `TestPackageRegistriesGetALargerAllowance`.

### 1.8 Git traffic is what it claims to be
- **Holds in:** all modes.
- **What it covers:** an allowed `git-upload-pack` POST must be a real git fetch (path, content type, size and pkt-line body). Any POST to `git-receive-pack` is treated as a push, whatever its spelling or content type; a push whose refs cannot be read is never allowed by a ref rule.
- **Tests:** `proxy/internal/proxy`: `TestUploadPackPostMustBeAGitFetch`, `TestPushDetectionAndUnparsedPushes`, `TestLargePushIsHeldWhole`, `FuzzValidUploadPackRequest`, `FuzzParseRefUpdates`.

---

## 2. Approvals

### 2.1 What is approved is exactly what is sent
- **Holds in:** all modes.
- **What it covers:** the whole body is read before the person is asked (up to 1 MiB, `max_held_body_bytes`; 256 MiB for a git push; 32 MiB for model requests). Its SHA-256 is shown and recorded, and only those bytes are forwarded. A larger body is refused (413), not sent unseen.
- **Tests:** `proxy/internal/proxy`: `TestApprovalCoversTheExactBodySent`, `TestBodyTooLargeToReviewIsRefused`, `TestLargePushIsHeldWhole`, `TestPreviewReachesTheGatewayAndTheUpstreamStillGetsTheBody`.

### 2.2 The person sees evidence, not the agent's description
- **Holds in:** all modes.
- **What it covers:** the preview comes from the proxy's own reading of the request: method, URL, the registrable domain and whether it is trusted, request headers, query, the first 400 bytes of a text body. Bodies that cannot be shown are named ("contents not shown: N bytes of …"). Credential-shaped values are masked; encoded blobs are flagged with their size. Terminal control characters, bidi and invisible characters are escaped. Pending approvals are listed oldest first, and keys typed before a request is shown do not answer it.
- **Tests:** `proxy/internal/proxy`: `TestUnseenBodiesAreNamed`, `TestApproverSeesRequestHeaders`, `TestRequestContext_QueryBodyAndLimits`; `proxy/cmd/ovara`: `TestPrintApproval_ShowsWhereItReallyGoes`, `TestDestinationOf`, `TestUI_PendingNamesTheDestination`, `TestTermSafe`, `TestWatchLoop_IgnoresTypeAhead`, `TestContextLines_BodyAndHeaders`; `runtime/gateway/internal/handlers`: `TestApprovalContext_KeySelectionIsDeterministic`, `TestApprovalContext_CutsOnRuneBoundary`; `runtime/gateway/internal/approval`: `TestListPendingOldestFirst`.

### 2.3 Only a person with the operator role can approve
- **Holds in:** all modes.
- **Conditions:** the agent does not run as Ovara's user (see 6.1).
- **What it covers:** the agent's proxy token cannot reach the approval API. The approval page uses a fresh per-run token that opens only the page, is served on loopback only and cannot be framed.
- **Tests:** `runtime/gateway/internal/auth`: `TestRoleAgent_OperatorEndpointsDenied`; `runtime/gateway/internal/handlers`: `TestRT16_AgentOnOperatorRoute`, `TestRT04_CrossAgentApprovalCreate`; `proxy/cmd/ovara`: `TestUI_PageTokenIsNotTheOperatorToken`, `TestStartUI_LinkCarriesAFreshPageToken`, `TestStartUI_RefusesNonLoopback`, `TestUI_PageIsNotFramable`, `TestOpenUI_TakenPortStopsTheRun`; `tests/redteam/separate-user/run.sh`.

### 2.4 Approvals do not pile up or wait forever
- **Holds in:** all modes.
- **What it covers:** a pending approval expires after 10 minutes (`approval_pending_ttl_secs`) and can then no longer be approved. One agent can have at most 64 waiting; identical requests share one approval. An answer given in the last poll interval still counts.
- **Tests:** `runtime/gateway/internal/approval`: `TestPendingApprovalExpires`, `TestPendingTTLConfigurable`, `TestOpen_PerAgentPendingCap`, `TestOpen_DeduplicatesIdenticalPending`; `runtime/gateway/internal/handlers`: `TestApprovalHandler_ExpiredApproval`, `TestApprovalHandler_FloodControl`; `proxy/internal/proxy`: `TestApprovalInTheLastPollIntervalCounts`, `TestEscalationCapRefusesWhenFull`; `proxy/cmd/ovara`: `TestCapToApprovalTTL`.

---

## 3. Credentials

### 3.1 Ovara never hands the agent a real key
- **Holds in:** all modes.
- **Conditions:** the real keys are in Ovara's environment only. The agent gets placeholders. `ovara env` also unsets other secret-looking variables in the shell it sets up (`-keep-env` keeps them).
- **Tests:** `proxy/cmd/ovara`: `TestAgentEnv_FromInitDeployment`, `TestSecretEnvNames`; `tests/scenarios/scenarios.sh`; `tests/agents/battery.sh`.

### 3.2 A key goes only where its binding says
- **Holds in:** all modes.
- **What it covers:** keys are injected over HTTPS only, never on `fail_open`, and only on requests that match the binding's host, port (443 if none), paths and methods. `ovara box` limits the GitHub key to the project's own repository (`-github-scope repo`). The agent's own credential headers are removed on a bound host, and the real key is set after hop-by-hop headers are stripped. A binding whose secret is shorter than 8 bytes stops startup.
- **Tests:** `proxy/internal/creds`: `TestMatchRequest_PathsAndMethods`, `TestMatchRequest_Port`, `TestScopeToRepo`, `TestLoadReport_RefusesShortSecrets`, `TestLoadReport_RejectsBadPatterns`; `proxy/internal/proxy`: `TestConnectMITMInjectsCreds`, `TestPathScopedBindingInjection`, `TestBindingWithoutPortNotSentToOtherPort`, `TestAgentCredentialHeadersStrippedOnBoundHost`, `TestConnectionTokenCannotStripInjectedHeader`, `TestFailOpenNeverInjectsCredentials`, `TestPlainHTTPAllowNoCredLeakAndReceipts`; `proxy/cmd/ovara`: `TestParseGitHubRemote`.

### 3.3 Sensitive credentialed reads pause
- **Holds in:** all modes.
- **Conditions:** the default policy is kept.
- **What it covers:** GitHub API reads of secrets, Actions and environment variables, Dependabot and Codespaces secrets, the user's keys and emails, org members, gists, authorizations and installations pause for a person. A GET to the Slack API is described and treated as a call. The default Slack binding is the API host only.
- **Tests:** `proxy/cmd/ovara`: `TestDefaultPolicy_SensitiveGitHubReadsEscalate`, `TestSlackAPIGetIsACall`, `TestDefaultSlackBindingIsAPIHost`.

### 3.4 A reflected key does not reach the agent
- **Holds in:** all modes.
- **Conditions:** the request was credentialed. Body scrubbing of signed URL parameters applies to text bodies.
- **What it covers:** injected values and bare tokens are replaced in response headers, header names, bodies and trailers, also in hex, base64 and case-changed spellings and across read boundaries. Signed URL parameters are redacted. Range requests are stripped, and encoded responses on credentialed requests are refused.
- **Tests:** `proxy/internal/proxy`: `TestEncodedReflectionsScrubbed`, `TestDerivedSignedURLsRedacted`, `TestSignedParamReader_Boundary`, `TestVersionLikeHeaderStillScrubbed`, `TestScrubReader_CaseInsensitiveStraddle`, `TestScrubReader_Boundary`, `TestTrailerSecretScrubbed`, `TestSEC0001_RangeStripped`, `TestSEC0001_GzipReflectionScrubbed`, `TestDuplicateContentEncodingRefused`.

### 3.5 The interception CA is narrow and short-lived
- **Holds in:** all modes.
- **What it covers:** the CA can only sign server certificates (path length 0, server authentication only). It lives 30 days and is replaced at start when it has expired, expires within 3 days, or is weaker or longer-lived; CAs from earlier versions are replaced once. Site certificates live at most 24 hours and never past the CA. `ovara doctor` warns before expiry.
- **Tests:** `proxy/internal/ca`: `TestNewCAIsConstrainedAndShortLived`, `TestLoadOrCreateRotatesWeakOrExpiringCA`, `TestLeafCappedAtCAExpiry`.

### 3.6 A brokered binding sends only a short-lived, down-scoped token, or nothing
- **Holds in:** all modes.
- **Conditions:** the binding is a `github_app` or `oauth2` binding (not a static header). The GitHub App's own permissions, or the OAuth server, set the upper bound on what a token can do.
- **What it covers:** the long-lived secret (App private key, client secret, subject token) stays in Ovara's environment and never goes upstream to the bound host. A GitHub App token is minted with an RS256 JWT (issued 60 s back, expiring within 10 minutes) and limited to the binding's repositories and permissions; when the binding lists none and `ovara run -scope-repo owner/repo` is set (as `ovara box` does), to that one repository. It goes out as Bearer on `api.github.com` and as Basic `x-access-token` on `github.com` git smart-HTTP. OAuth tokens come from the client-credentials grant or RFC 8693 token exchange. Tokens are reused until 5 minutes (GitHub) or 60 seconds (OAuth) before they expire; concurrent requests share one mint. When no token can be minted, the request is refused with `credential_unavailable` and not sent; an older token is never used after a failed refresh. The issuer call goes over the proxy's verified-TLS transport, does not pass through policy and is never shown to the agent. Minted tokens are scrubbed from responses like static keys (3.4) and are never logged. A broker setting that is wrong (missing field, unreadable or non-RSA key, plain-HTTP token URL) stops startup; `ovara doctor` checks the same offline, including that the key file is owner-only.
- **Tests:** `proxy/internal/creds`: `TestGitHubAppJWTSignedAndDownScoped`, `TestGitHubAppKeyFormats`, `TestGitHubAppTokenRefreshedBeforeExpiry`, `TestBrokerConcurrentRequestsMintOnce`, `TestBrokerFailureFailsClosed`, `TestBrokeredBindingNotLoadedRefuses`, `TestGitHubAppGitSmartHTTPBasic`, `TestScopeBrokersToRepo`, `TestBrokerConfigErrors`, `TestOAuthClientCredentials`, `TestOAuthTokenExchange`, `TestOAuthRefusesUnusableAnswers`; `proxy/internal/proxy`: `TestBrokeredTokenInjectedAndScrubbed`, `TestBrokerFailureRequestNotForwarded`; `proxy/cmd/ovara`: `TestDoctor_BrokerBindings`, `TestBindingKeysGitHubApp`; `proxy/internal/config`: `TestExampleProxyConfigLoads`.

---

## 4. Policy semantics

### 4.1 A rule that could never match is refused, not ignored
- **Holds in:** all modes.
- **What it covers:** a rule without `action_type` or `environment`, or with conditions the gateway does not evaluate, stops the policy from loading. A bad reload keeps the old policy.
- **Tests:** `runtime/gateway/internal/policy`: `TestParseStoreRefusesRulesThatCanNeverMatch`.

### 4.2 Deny means deny
- **Holds in:** all modes.
- **Conditions:** most-specific precedence (what `ovara init` writes). Older files keep "any deny wins".
- **What it covers:** a matching deny always beats a matching escalate. An allow beats a deny only if it is more specific and names the host at least as precisely. Deny and escalate host rules apply on every port. A push is decided ref by ref and gets the strictest answer; an allow for refs does not cover deleting them unless it says `(delete)`.
- **Tests:** `runtime/gateway/internal/evaluator`: `TestMostSpecific_EscalateNeverBeatsDeny`, `TestMostSpecific_URLEscalateNeverBeatsDeny`, `TestMostSpecific_BroadHostAllowNeverBeatsNarrowHostDeny`, `TestMostSpecific_EscalateStillBeatsWeakerAllow`, `TestDenyHostRuleMatchesAnyPort`, `TestEscalateHostRulesMatchAnyPort`, `TestGitPush_EachRefDecidedOnItsOwn`, `TestGitPush_DeleteRules`; `runtime/gateway/internal/policy`: `TestMatchResourceAnyPort`, `FuzzMatchCanonicalResource`; `tests/scenarios/ci-bot.sh`.

### 4.3 Every decision names the policy that made it
- **Holds in:** all modes.
- **What it covers:** decisions and receipts carry the matched rule and the policy's content hash (`policy_hash`), covered by the gateway's Ed25519 signature.
- **Tests:** `runtime/gateway/internal/policy`: `TestPolicyHash`; `runtime/gateway/internal/evaluator`: `TestDecisionCarriesPolicyHash`, `TestEvaluate_NamesDecidingRuleAndPolicy`; `runtime/gateway/internal/receipt`: `TestPolicyHashIsSigned`; `runtime/gateway/internal/handlers`: `TestPolicyHandler_GetPolicyHash`.

---

## 5. Audit log

### 5.1 Nothing goes upstream without a receipt on disk
- **Holds in:** all modes.
- **Conditions:** `fail_open` is not set.
- **What it covers:** a request that goes upstream gets an attempt receipt, synced to disk before any byte is sent, and an outcome receipt before the response reaches the agent. If the attempt cannot be written, the request is refused. The gateway turns an allow or escalate it cannot record into a deny.
- **Tests:** `proxy/internal/proxy`: `TestNoUpstreamBytesWithoutReceipt`, `TestNoReceiptFailOpenStillForwards`, `TestReceiptIsWrittenBeforeTheResponseReachesTheAgent`, `TestReceiptV2Fields`; `proxy/internal/receipts`: `TestDurableAppendAndTornWrite`, `TestOutcomeNeedsAttempt`; `runtime/gateway/internal/handlers`: `TestAllowWithoutReceiptIsDenied`, `TestPlaceholderSignatureNeverPersisted`.

### 5.2 An edited, cut or forked log fails verification
- **Holds in:** all modes.
- **Conditions:** the signing key and the anchors are not both in the attacker's hands; for an attacker who can write the whole Ovara directory, an off-host anchor is needed (see Not guaranteed).
- **What it covers:** receipts are Ed25519-signed over an unambiguous encoding and hash-chained; lines must be byte-canonical. `ovara log`, `ovara doctor` and `ovara-proxy -verify` check signatures, links, key history and anchors. A log cut short, or cut and continued, fails, and `ovara run` will not append to it.
- **Tests:** `proxy/internal/receipts`: `TestV2CanonicalFormIsUnambiguous`, `TestExtraAndDuplicateKeysRejected`, `TestV1ThenV2Verifies`, `TestTamperedURLFails`, `TestTamperedSignatureFails`, `TestAudit_TamperMatrix`; `proxy/cmd/ovara`: `TestTruncatedLogIsDetected`, `TestTruncateThenContinueIsDetected`, `TestRunRefusesToResumeACutLog`, `TestLogExportRefusesTamperedChain`, `TestVerifyOnly`, `TestIncidentBundleVerifiesOffline`; `tests/redteam/separate-user/run.sh`.

### 5.3 A revoked key stops verifying what it signs afterwards
- **Holds in:** all modes.
- **What it covers:** the proxy keeps a key history; `ovara keys rotate-receipt` and `revoke-receipt` retire a key, and receipts dated outside its window fail. The proxy will not start with a retired key or replace a missing key over an existing log. On the gateway, receipts and v2 journal envelopes signed after a key was revoked, or after a replaced key's grace period, fail.
- **Tests:** `proxy/internal/receipts`: `TestRotateAndRevoke`, `TestMissingKeyWithReceiptsRefused`; `proxy/cmd/ovara`: `TestKeysRotateReceipt`; `runtime/gateway/internal/receipt`: `TestSupersededKey_VerifiesOnlyWhatItSignedInUse`; `runtime/gateway/internal/record`: `TestJournalRespectsKeyRevocation`, `TestJournalBytesAreBound`, `TestJournalV1ThenV2`, `TestStrictFailureIsNotTornTail`.

### 5.4 The gateway fails closed and never re-runs an action blindly
- **Holds in:** all modes.
- **What it covers:** a configured store that cannot be opened stops startup. An approved action whose "executing" claim cannot be written is not run. An action interrupted by a crash is marked "outcome unknown" and is never retried automatically. A journal survives a crash at any byte.
- **Tests:** `runtime/gateway/pkg/server`: `TestRunRefusesToStartWhenConfiguredStoreCannotOpen`; `runtime/gateway/internal/continuation`: `TestRecoveredExecutionIsOutcomeUnknown`, `TestFileBackedStore_ClaimForExecution_RejectsExecuting`; `runtime/gateway/internal/record`: `TestCrashAtEveryByteOffsetLeavesAUsableJournal`.

### 5.5 Anchoring survives a short outage
- **Holds in:** all modes, with `gateway_anchor_mode` set.
- **What it covers:** `ovara doctor` reports "anchored" only when anchoring is really on. In degraded mode a push that fails while the oracle is down is retried until it lands. The oracle's reset token comes from an owner-only file or the environment, never the command line.
- **Tests:** `proxy/cmd/ovara`: `TestDoctorAnchorNeedsMode`; `runtime/gateway/pkg/server`: `TestDegradedAnchorRetriesAfterOutage`, `TestDegradedAnchorLaterPushSupersedes`; `runtime/gateway/cmd/ovara-anchor`: `TestOperatorTokenSources`, `TestResetNeedsToken`.

### 5.6 Ovara's files are owner-only
- **Holds in:** all modes (Linux and macOS for the checks).
- **What it covers:** stores, journals, logs and keys are written 0600 in 0700 directories; `policy.json` is 0600; `ovara init` does not print the operator token. `ovara doctor` fails on loose key and policy permissions.
- **Tests:** `runtime/gateway/internal/logging`: `TestDecisionLogger_OwnerOnly`; `proxy/cmd/ovara`: `TestInitKeepsTokenAndPolicyPrivate`, `TestDoctorPolicyReadableAndIssuerKey`, `TestDoctorSeesFailOpenInProxyJSON`.

---

## 6. Box

### 6.1 The agent cannot touch Ovara
- **Holds in:** enforced boundary (when run as another user, as documented), box tier 1, box tier 2.
- **What it covers:** the agent's user cannot read the keys, edit the policy, forge or delete receipts, approve its own requests, or stop Ovara.
- **Tests:** `tests/redteam/separate-user/run.sh`; `tests/box/box.sh`.

### 6.2 The agent cannot read the host's files or the original project
- **Holds in:** box tier 1 (default `-tier1-fs isolated`), box tier 2.
- **What it covers:** tier 1 runs in a root file system of its own: system directories read-only (with `/etc/shadow`, sudoers and SSH configuration covered), the workspace and a fresh home read-write, nothing from `/home`, `/root`, `/srv`, `/opt`, `/mnt`, `/var` or `/nix`, other users' processes hidden, no_new_privs, and the proxy token on no command line. Tier 2 mounts nothing of the host but the workspace, a fresh home and read-only `-mount` paths; secret locations are refused as mounts in both tiers.
- **Tests:** `proxy/cmd/ovara`: `TestTier1IsolatedFileSystem` *(root)* (and `TestTier1HostFileSystem` *(root)* as the control), `TestCheckMountsTier1`, `TestMountpointNoFollow`, `TestCheckMounts`; `tests/box/box.sh` (tier 1, and `TIER=2` through `tests/box/host.sh box`).

### 6.3 Secrets are left out of the project copy
- **Holds in:** box tier 1, box tier 2.
- **What it covers:** files with secret-looking names, and text files whose content looks like a private key or token, are left out and listed. Credentials in the copy's git remote URLs are removed.
- **Tests:** `proxy/internal/workspace`: `TestCreate_CopiesProjectWithoutSecrets`, `TestScanSecret`, `TestCreate_LeavesOutSecretsByContent`, `TestScrubGitConfig`; `tests/box/box.sh`.

### 6.4 Every command the agent runs is seen and checked
- **Holds in:** box tier 1, box tier 2 (unless `-no-command-gate`).
- **What it covers:** every exec, by any route, is stopped before its first instruction and checked against `shell:` rules on a normalised command line; denied commands are killed, paused ones wait for a person. The agent cannot shed the tracer.
- **Tests:** `proxy/internal/boxgate`: `TestTracer_SeesEveryExecAndKillsDenied`, `TestPolicyLine`; `proxy/cmd/ovara`: `TestCommandGate_PolicyLineAndLaunch`, `TestDefaultPolicy_ShellRulesSeeThroughRespelling`; `tests/box/box.sh`.

### 6.5 Only the reviewed tree comes back
- **Holds in:** box tier 1, box tier 2.
- **What it covers:** commit-back reads the workspace once into a tree in a repository the launcher owns; the agent's `.git` config, hooks and filters never run on the host. The branch is exactly the reviewed tree. Agent config, CI and hook paths are kept out by default, sensitive files are flagged, binary files stay out unless `-allow-binary`, and a cut diff says what it leaves out. The real working tree is never touched.
- **Tests:** `proxy/internal/workspace`: `TestCommitTree_LandsTheReviewedTreeOnly`, `TestSnapshot_IgnoresTheAgentsGitConfig`, `TestReview_SaysWhatACutDiffLeavesOut`, `TestSnapshot_MarksBinaryFiles`, `TestWithout_RenameKeepsBothEnds`, `TestCommitBack_BranchOnlyExcludedPathsRevertedSecretsKept`; `proxy/cmd/ovara`: `TestPlanCommitBack`, `TestCommitBackContext_SaysWhatIsNotShown`, `TestDefaultPolicy_CommitBackPaths`; `runtime/gateway/internal/handlers`: `TestApprovalContext_DiffKeepsItsLength`; `tests/box/box.sh`.

### 6.6 Strict installs: new or altered packages do not arrive unasked
- **Holds in:** box tier 1, box tier 2 with `-profile strict`.
- **Conditions:** the lockfiles are yours; for a repository you are reviewing, use `-untrusted-lockfiles`.
- **What it covers:** a dependency the lockfiles do not pin pauses once by name and version (npm, PyPI, Go, crates, RubyGems, Maven); an unrecognised download from a known registry pauses; a download whose lockfile records a digest is checked as it streams and cut off on a mismatch.
- **Tests:** `proxy/internal/lockfiles`: `TestClassify`, `TestScanPinsDigests`; `proxy/internal/proxy`: `TestDigestReader`, `TestPackageGate_DigestCheckedEndToEnd`, `TestPackageGate_UnrecognisedRegistryDownload`; `proxy/cmd/ovara`: `TestStrictPins_UntrustedLockfiles`; `tests/box/strict.sh`.

### 6.7 Tier 2: the container holds
- **Holds in:** box tier 2.
- **What it covers:** no network interface but loopback; no capabilities for the agent; read-only root; no-new-privileges; Ovara's sockets closed to the agent; the box's PID 1 cannot be killed by the agent; no box container left after a run.
- **Tests:** `tests/box/host.sh box` (CI job `box-tier2`), `tests/box/host.sh redteam`, `tests/agents` in a tier 2 box (CI job `agents-tier2`).

---

## Not guaranteed

These are real limits. Some are design limits, some are not built yet.

- **Cooperative mode can be bypassed.** In cooperative mode the agent is
  only asked to use the proxy. A program that ignores the proxy settings
  reaches the internet directly, and nothing in this file applies to that
  traffic. Cooperative mode stops mistakes, not a hostile agent.
- **macOS and Windows have cooperative mode only.** The enforced boundary
  and `ovara box` are Linux only. A VM-based box for macOS and Windows is
  not built.
- **Same-user agents.** An agent that runs as Ovara's user can read the
  real keys, edit the policy, re-sign the log and approve itself. Ovara
  cannot enforce a separate user for you outside `ovara box`.
- **Root in the boundary.** An agent that is root inside the enforced
  boundary can remove the firewall rules.
- **Data through trusted read hosts.** The read caps and the per-host
  budget make this channel narrow and slow, not closed. An agent with an
  account on a trusted host can still move data through URLs on it. The
  policy limits *where*, not *what*.
- **The approver's judgement.** Ovara shows the exact bytes and their
  hash; it cannot tell the person what 1 MB of upload means, or stop them
  approving the wrong thing.
- **Prompt injection.** Ovara bounds what an injected agent can do and
  records it. It does not stop the agent being talked into trying.
- **Interpreter one-liners and renamed binaries in the box.** The command
  gate sees every exec, but the default rules match command lines. A
  `python -c` that deletes files, a renamed copy of `rm`, or a git alias
  defined in a config file is not caught by the `rm` or `git push` rules.
  The network and file boundaries do not depend on these rules.
- **Arguments rewritten after the check.** The gate reads a command's
  arguments from the stopped process. Another process of the same agent
  could change them before the program reads them. The program itself
  cannot change.
- **Shared kernel.** Tiers 1 and 2 share the host's kernel; a kernel
  exploit leaves the box. Tier 1 has no PID namespace: the agent can
  signal host processes of its own user. A microVM tier is not built.
- **`-tier1-fs host`** turns tier 1's file-system isolation off. With it,
  6.2 does not hold.
- **Signing keys are files.** Whoever steals the receipt or gateway key
  can forge receipts. Revocation stops later-dated forgeries, not
  backdated ones. Hardware-backed keys are not built.
- **Log and local anchors rewritten together.** Without an off-host
  anchor, someone who can write the whole Ovara directory can rewrite the
  log and its anchors consistently.
- **Derived credentials in binary bodies.** Signed URL parameters are
  redacted from text responses only.
- **Minted tokens outlive the run.** A brokered token is not revoked when
  Ovara stops; it expires on its own (one hour for GitHub). Its scope is
  what the binding asked for, never more than the App or the OAuth
  client is granted. The token endpoint must be public: the issuer call
  goes through the same destination guard as agent traffic.
- **GitHub paths spelt differently.** The sensitive-read rules match
  GitHub API paths as written; a percent-encoded or case-changed path
  falls back to the host-wide read rule. In `ovara box` the repository
  scope on the key still applies.
- **Non-HTTP protocols.** SSH, database protocols and raw TCP are not
  inspected; the boundary drops them. HTTP/2, gRPC and WebSockets are not
  supported through the interception.
- **`fail_open`.** With `fail_open` set in `proxy.json`, requests go out
  when the gateway is down or a receipt cannot be written. `ovara doctor`
  reports it.
- **Secrets in git history.** The project copy in `ovara box` keeps the
  repository's history; a secret committed in the past is still in its
  objects.
- **SDK verifiers.** The TypeScript and Python SDK helpers verify v1 proxy
  receipts only, not v2. Use `ovara log -verify-only` for v2.
- **External review.** No independent review of the box has been done
  yet. Until it has, Ovara does not call itself a sandbox without
  qualification.
