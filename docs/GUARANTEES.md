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
- **Holds in:** all modes, under the `strict` policy profile (the default).
- **Conditions:** the default policy from `ovara init` is kept. "Approve and remember" from an approval adds a rule for exactly one thing: reads from one host (for the run, removed when `ovara run` stops, or for the project), one command line in the box, or one MCP tool (both for the run); never a write, never a wildcard; each rule names who, when and the approval. Under the `balanced` and `observe` profiles (`ovara policy profile`) reads from any public host are allowed instead; 1.4, 1.7 and 1.10 bound them, and the trusted list then says which hosts are not counted against the cap.
- **Tests:** `tests/scenarios/scenarios.sh`; `proxy/cmd/ovara`: `TestTrustReadHost_AddsReadOnlyRulesOnce`, `TestTrustReadHost_SaysWhereAndWhenAndLastsOneRun`, `TestUI_RememberOptionsAndScopes`, `TestRememberOptions`, `TestRemember_ScopesAndTheRun`, `TestDefaultPolicyHasNoHostlessAllow`, `TestProfiles_SwitchReplacesOnlyTheProfileRules`.

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

### 1.9 What the upstream receives is exactly what was checked
- **Holds in:** all modes.
- **Conditions:** `model_gate` is on (the default), for the hosts it covers.
- **What it covers:** a model request body the gate reads as JSON is read strictly: UTF-8, one value with only white space around it, no `NaN` or `Infinity`, and no object with two members of the same name (also when one is spelt with `\u` escapes). Before policy is asked, the body is replaced by the canonical encoding of the value read: members sorted by name, no white space, strings escaped one way, numbers byte for byte as written, arrays in order. Those bytes go upstream (Content-Length set), and the approval context's `body_sha256`, `body_bytes` and preview and the receipts' `body_sha256` are of them. So the provider cannot read something the gate did not, whatever its JSON reader does with duplicates, trailing data or invalid UTF-8. A body with duplicate member names or invalid UTF-8 is refused (403, `model_request_ambiguous`), not asked about. A body that is not JSON is asked about (`model_request_not_json`) and, if approved, sent as the person saw it. Reading the canonical form gives the same value as reading the original (a lone `\u` surrogate escape reads as U+FFFD, as it does for the check), and encoding it again gives the same bytes. A 1 MiB request is re-encoded in about 20 ms.
- **Tests:** `proxy/internal/proxy`: `TestModelRequestForwardedCanonical`, `TestModelRequestDuplicateKeysRefused`, `TestModelGate`; `proxy/internal/canonjson`: `TestCanonicalForm`, `TestCanonicalRefuses`, `TestCanonicalProperties`, `FuzzCanonical`, `TestCanonical1MiBIsFast`.

### 1.10 Under an open-read profile, the distinct unlisted hosts an agent reads are capped per run
- **Holds in:** all modes, under the `balanced` and `observe` profiles.
- **Conditions:** `open_reads` is not turned off in `proxy.json` (default: 50 hosts per agent per run).
- **What it covers:** a read allowed by a rule that allows reads from any host (`[open read]` in its description) counts its host toward the agent's cap; past the cap each further host pauses for a person once (action type `egress.open_hosts`), and an approval admits that host for the rest of the run. Hosts a rule names are not counted. The strict policy's guards keep deciding under the profiles: a credentialed read of secrets still pauses, a dump site is still refused, and under `observe` the model API stays reachable while every other write is refused at once, never held. `ovara policy suggest` reads only a chain that verifies.
- **Tests:** `proxy/internal/proxy`: `TestOpenReadsAskPastTheHostCap`, `TestOpenReadsCountOnlyCatchAllReads`; `runtime/gateway/internal/evaluator`: `TestMostSpecific_OpenReadProfilesKeepTheGuards`; `proxy/cmd/ovara`: `TestProfiles_SwitchReplacesOnlyTheProfileRules`, `TestInit_Profile`, `TestPolicySuggest_FromReceipts`.

---

## 2. Approvals

### 2.1 What is approved is exactly what is sent
- **Holds in:** all modes.
- **What it covers:** the whole body is read before the person is asked (up to 1 MiB, `max_held_body_bytes`; 256 MiB for a git push; 32 MiB for model requests). Its SHA-256 is shown and recorded, and only those bytes are forwarded. A larger body is refused (413), not sent unseen. For a body the model or MCP gate reads as JSON, "those bytes" are its canonical form, which replaces the agent's bytes before the person is asked (1.9, 8.5).
- **Tests:** `proxy/internal/proxy`: `TestApprovalCoversTheExactBodySent`, `TestBodyTooLargeToReviewIsRefused`, `TestLargePushIsHeldWhole`, `TestPreviewReachesTheGatewayAndTheUpstreamStillGetsTheBody`, `TestModelRequestForwardedCanonical`, `TestMCPRequestForwardedCanonical`.

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
- **What it covers:** a pending approval expires after 10 minutes (`approval_pending_ttl_secs`) and can then no longer be approved. One agent can have at most 64 waiting; identical requests share one approval. Named agents behind one proxy each have their own 64 (the gateway counts by the agent name the proxy sends with the request, and bounds one caller at four times that across all names; the proxy holds at most 64 requests per agent, 256 in all), so one agent filling its share does not block another's questions. An answer given in the last poll interval still counts.
- **An approval is used once, and a late answer is not wasted.** Before an approved request runs, the proxy claims the approval (`POST /v1/approval/{id}/claim`, single use in the gateway's store); an identical request that finds it already used is refused (`approval_used`) and asked afresh. A request approved after the proxy stopped waiting is not asked again: the identical request (same agent, action, resource, body hash and gateway digest) gets that approval back from `create` while it is unused and within the pending TTL, then claims it. With `escalate_on_timeout: "retry"` (what `ovara init` writes, with a 10-second hold) an unanswered hold is answered 503 with `Retry-After` and the approval id instead of 504, for HTTP requests, the proxy's own questions and MCP tool calls alike; the approval stays open. `"timeout"` keeps the 504. Every refusal names the policy rule that decided (`rule`) when one did.
- **Tests:** `runtime/gateway/internal/approval`: `TestPendingApprovalExpires`, `TestPendingTTLConfigurable`, `TestOpen_PerAgentPendingCap`, `TestOpen_PendingCapIsPerNamedAgent`, `TestOpen_DeduplicatesIdenticalPending`, `TestOpen_ReusesAnApprovedUnusedApprovalOnce`, `TestOpen_ReusesApprovedOnlyForTheIdenticalRequest`, `TestOpen_ApprovedReuseWindowFollowsThePendingTTL`, `TestClaim_OnlyAnApprovedApprovalIsClaimable`; `runtime/gateway/internal/handlers`: `TestApprovalHandler_ExpiredApproval`, `TestApprovalHandler_FloodControl`, `TestClaim_IsSingleUseAndOwnerOnly`; `runtime/gateway/internal/auth`: `TestRoleAgent_AllowedEndpoints`; `proxy/internal/proxy`: `TestApprovalInTheLastPollIntervalCounts`, `TestEscalationCapRefusesWhenFull`, `TestEscalationCapIsPerAgent`, `TestApprovedRequestIsClaimedBeforeItRuns`, `TestAnApprovalAlreadyUsedIsNotReplayed`, `TestRetryAnswerCarriesRetryAfterAndTheApprovalStaysOpen`, `TestTimeoutAnswerIsTheDefault`, `TestAnOlderGatewayWithoutClaimStillRuns`, `TestRefusalsNameTheRule`, `TestMCPToolCallHoldGetsTheRetryAnswer`; `proxy/cmd/ovara`: `TestCapToApprovalTTL`.

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
- **What it covers:** a matching deny always beats a matching escalate. An allow beats a deny only if it is more specific and names the host at least as precisely; for commands and paths, only if its fixed prefix (the text before its first `*`) is at least as long as the deny's, so `shell:*codex*` cannot outrank `shell:sudo*`. Deny and escalate host rules apply on every port. A push is decided ref by ref and gets the strictest answer; an allow for refs does not cover deleting them unless it says `(delete)`, while a deny or escalate for a ref also covers deleting it (a deny for `refs/heads/main` refuses `refs/heads/main(delete)`).
- **Tests:** `runtime/gateway/internal/evaluator`: `TestMostSpecific_EscalateNeverBeatsDeny`, `TestMostSpecific_URLEscalateNeverBeatsDeny`, `TestMostSpecific_BroadHostAllowNeverBeatsNarrowHostDeny`, `TestMostSpecific_EscalateStillBeatsWeakerAllow`, `TestDenyHostRuleMatchesAnyPort`, `TestEscalateHostRulesMatchAnyPort`, `TestGitPush_EachRefDecidedOnItsOwn`, `TestGitPush_DeleteRules`, `TestGitPush_ExactRefDenyCoversDeletion`, `TestShellAllowMustNameTheProgramToBeatADeny`; `runtime/gateway/internal/policy`: `TestMatchResourceAnyPort`, `FuzzMatchCanonicalResource`; `tests/scenarios/ci-bot.sh`.

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
- **What it covers:** stores, journals, logs and keys are written 0600; the deployment and `var/` directories are 0711 (other users cannot list them, and can open only the public CA certificate, which the agent needs); `policy.json` is 0600; `ovara init` does not print the operator token. `ovara doctor` fails on loose key and policy permissions.
- **Tests:** `runtime/gateway/internal/logging`: `TestDecisionLogger_OwnerOnly`; `proxy/cmd/ovara`: `TestInitKeepsTokenAndPolicyPrivate`, `TestDoctorPolicyReadableAndIssuerKey`, `TestDoctorSeesFailOpenInProxyJSON`.

---

## 6. Box

### 6.1 The agent cannot touch Ovara
- **Holds in:** enforced boundary (when run as another user, as documented), box tier 1, box tier 2.
- **What it covers:** the agent's user cannot read the keys, edit the policy, forge or delete receipts, approve its own requests, or stop Ovara.
- **Tests:** `tests/redteam/separate-user/run.sh`; `tests/box/box.sh`.

### 6.2 The agent cannot read the host's files or the original project
- **Holds in:** box tier 1 (default `-tier1-fs isolated`), box tier 2.
- **Conditions:** "other users' processes hidden" needs Linux 5.8 or later (a private `/proc` with `hidepid=invisible`). On an older kernel an isolated tier 1 box refuses to start; with `-allow-visible-procs` it starts and the agent can list the host's processes and their command lines (the rest of 6.2 still holds).
- **What it covers:** tier 1 runs in a root file system of its own: system directories read-only (with `/etc/shadow`, sudoers and SSH configuration covered), the workspace and a fresh home read-write, nothing from `/home`, `/root`, `/srv`, `/opt`, `/mnt`, `/var` or `/nix`, other users' processes hidden, no_new_privs, and the proxy token on no command line. Tier 2 mounts nothing of the host but the workspace, a fresh home and read-only `-mount` paths; secret locations are refused as mounts in both tiers.
- **Tests:** `proxy/cmd/ovara`: `TestTier1IsolatedFileSystem` *(root)* (and `TestTier1HostFileSystem` *(root)* as the control), `TestTier1RefusesAProcThatShowsTheHostsProcesses`, `TestCheckMountsTier1`, `TestMountpointNoFollow`, `TestCheckMounts`; `tests/box/box.sh` (tier 1, and `TIER=2` through `tests/box/host.sh box`).

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

## 7. Agents

### 7.1 A write soon after an untrusted read is asked about
- **Holds in:** all modes.
- **Conditions:** `taint` is not turned off in `proxy.json`, and the
  default policy's `taint.write` rule (escalate) is kept. The mark is
  kept per agent name for 30 minutes (`taint_window_minutes`) and lasts
  one run.
- **What it covers:** after the agent reads untrusted content (a read a
  person approved, a read allowed by a rule added with "trust this host
  for reads", a read matching `untrusted_reads`: by default GitHub and
  GitLab issues, pull and merge requests (bodies, lists, diffs, comments
  and reviews), discussions and commit comments, by API (GitHub's
  numeric repository id paths included) and on the web, matched on the
  decoded path; or a model request whose
  provider-side fetch was let through), every write the policy would allow
  on its own (any method but GET, HEAD and OPTIONS, a git push allowed by
  ref rules included) pauses, with the source and how long ago it was read
  in the approval. A refused write never goes upstream. Receipts record
  `untrusted_read` and `tainted_by:<source>`. Writes the policy already
  pauses or blocks are unchanged; model calls, git fetches and
  `exempt_writes` (npm audit) are not asked about. A receipt names every
  approval its request was asked about: the last in `approval_id`, the
  earlier ones in `reasons` as `approval:<id>`.
- **Tests:** `proxy/internal/proxy`: `TestTaint_UntrustedReadThenAllowedWriteAsks`, `TestTaint_WindowExpires`, `TestTaint_ApprovedReadsTrustedHostsAndModelFetchesTaint`, `TestTaint_LeavesOtherDecisionsAlone`, `TestTaint_AllowedPushAsks`, `TestTaint_Off`, `TestDefaultUntrustedReadPatterns`, `TestReceiptNamesEveryApprovalAskedFor`; `proxy/cmd/ovara`: `TestDefaultPolicy_TaintAndModelBudgetEscalate`, `TestApprovalShowsAgentNameAndTaint`; `runtime/gateway/internal/handlers`: `TestApprovalContext_AgentAndTaintSurviveTheCap`.

### 7.2 Model use is capped per agent
- **Holds in:** all modes.
- **Conditions:** `model_budget` is not turned off. Defaults: 2000
  requests, 50M input and 10M output tokens per agent and model host per
  run.
- **What it covers:** every request to a model host that policy allows is
  counted; tokens are counted from the response's `usage` (a JSON body up
  to 8 MiB, or server-sent events, one line up to 1 MiB). Past the
  allowance a person is asked once (`model.budget`); a refusal stops the
  call, an approval doubles the allowance. A response whose usage cannot
  be read counts as a request only.
- **Tests:** `proxy/internal/proxy`: `TestModelBudget_RequestsAskOnceAndApprovalDoubles`, `TestModelBudget_CountsTokens`, `TestModelBudget_PerAgent`, `TestFindUsage`, `TestUsageReaderBounds`.

### 7.3 Each agent has its own token and name
- **Holds in:** all modes.
- **What it covers:** the proxy accepts any token in `agents` and the
  single `agent_token` (the agent `default`), compares every one in
  constant time, and refuses anything else with 407. Receipts record the
  agent's name in `agent` (`agent_token` keeps its `pt_` hash label), and
  approvals name the agent. Tokens are 32 random bytes, kept in the
  owner-only `proxy.json` and never printed; names are validated and no
  token may be shared. Agents added or removed while Ovara runs take
  effect within a second, also inside tunnels opened before: a removed
  agent's tunnel (or one opened with a token since replaced) gets 403 and
  a receipt (reason `agent_removed`) and is closed. A broken edit keeps
  the current agents. Once any client token is configured, client
  authentication stays on for the run: removing the last agent leaves a
  proxy that refuses every client, never one that accepts anyone.
- **Tests:** `proxy/internal/proxy`: `TestNamedAgentsAreAcceptedAndNamed`, `TestNamedAgentsAloneRequireAuth`, `TestAgentsReloadFromProxyJSON`, `TestRemovingTheLastAgentKeepsAuthOn`, `TestRemovedAgentsOpenTunnelCarriesNoMore`; `proxy/internal/config`: `TestValidateAgents`, `TestLoadAcceptsAgentsAsClientAuth`, `TestWriteAgentsKeepsOtherFields`; `proxy/cmd/ovara`: `TestAgentAddListEnvRemove`, `TestInitCreatesNamedAgents`.

### 7.4 A stopped agent gets nothing more through
- **Holds in:** all modes.
- **What it covers:** `ovara kill -agent NAME` (every agent without
  `-agent`) writes the owner-only stopped list; within a second the
  running proxy refuses every request from that agent, including in
  tunnels opened before, with 403 "this agent was stopped by its
  operator" and a receipt (reason `agent_stopped`); its requests waiting
  for a person stop waiting, its pending approvals are denied, and a
  response still being relayed to it (an event stream, a download) is cut
  within about a quarter of a second, with the connection aborted so a
  cut body cannot pass for a whole one, and a receipt (reason
  `agent_stopped_mid_response`; also for a removed agent). The
  stop is written before the gateway is contacted, so it holds when the
  gateway is down. A stopped list that cannot be read keeps the agents
  stopped. It lasts across restarts until `ovara agent restore`.
- **Tests:** `proxy/internal/proxy`: `TestKilledAgentIsRefusedWithinASecond`, `TestKilledAgentsOpenTunnelCarriesNoMore`, `TestKilledAgentsWaitingRequestStops`, `TestAgentsStreamingResponseIsCutWhenStoppedOrRemoved`, `TestBrokenRevokedFileKeepsAgentsStopped`; `proxy/cmd/ovara`: `TestKillStopsOneAgentAndDeniesItsApprovals`, `TestKillWithoutGatewayStillStops`.

## 8. MCP

These hold for MCP (JSON-RPC 2.0) traffic Ovara can see: requests through
the proxy (Streamable HTTP, and the older HTTP+SSE transport), and stdio
servers started through `ovara mcp wrap`. They need `mcp_gate` on (the
default), and the policy must let the server's URL through first; with
`fail_open` and the gateway down, none of them apply.

### 8.1 Tool definitions nobody approved do not reach the agent
- **Holds in:** all modes, for servers reached through the proxy; for wrapped stdio servers, when `ovara mcp wrap` runs as a user the agent cannot act as.
- **What it covers:** every tool list a server sends (a JSON response, any event of an event stream from a host that is not a model API, a member of a batch, a line from a wrapped server) is compared with the definitions pinned for that server. A definition is its name, title, description, input and output schema and annotations, hashed as canonical JSON. The first list of a server, a new tool and a changed definition are a question for a person (`mcp.tools`, resource `mcp:<host><path> tools <n> new [<m> changed]` or `mcp:stdio:<name> ...`). Until the answer is yes, the list does not reach the agent: the proxy answers 502 with a JSON-RPC error (an event already being relayed is replaced by that error and a deny receipt is written), and the wrapper sends the error in its place. After a refused change, calls to that tool are refused until a definition is approved or the server goes back to the approved one. Pins are kept per server in `var/mcp_pins.json` (owner-only), shared by the proxy and the wrapper.
- **Tests:** `proxy/internal/mcp`: `TestToolHashIsCanonical`, `TestPinStorePersistsAndMerges`, `TestGateDriftDetection`, `TestGateAsksOnceForConcurrentLists`; `proxy/internal/proxy`: `TestMCPFirstToolListAsksOnceThenPinsPass`, `TestMCPChangedDescriptionAsksAgainAndDenialCutsResponse`, `TestMCPLegacySSETransport`, `TestMCPBatches`, `TestMCPPinsPersistAcrossRestarts`; `proxy/cmd/ovara`: `TestMCPWrapPinsAndGatesStdio`, `TestMCPWrapRunsTheServerAsAChildProcess`, `TestMCPWrapWithTheRealGatewayAndDefaultPolicy`, `TestDefaultPolicy_MCP`.

### 8.2 Every tool call is decided by policy, and only approved tools can be called
- **Holds in:** as 7.1.
- **What it covers:** each `tools/call`, alone or in a batch, is checked before it is sent (`mcp.tool_call`, resource `mcp:<host><path>/<tool>` or `mcp:stdio:<name>/<tool>`; characters other than letters, digits, `_`, `-` and `.` in a tool name are percent-encoded). The default policy pauses every call; a rule can allow a tool by name. A call to a tool whose definition was never approved is refused without asking. A refused call gets a JSON-RPC error (code -32001, "denied by Ovara policy") and never reaches the server; over HTTP, a batch with one refused call is refused whole. An approval is bound to the exact call: the question carries `arguments_sha256` (the SHA-256 of the arguments in canonical JSON: members sorted, numbers as written) and the request's `body_sha256` (of the canonical body or line that is sent, 8.5). Two calls that differ anywhere in their arguments are two questions, and the gateway never merges them into one pending approval; a context value the gateway cuts for display ends with the SHA-256 of the whole value.
- **Tests:** `proxy/internal/mcp`: `TestGateToolCalls`, `TestToolCallPreviewBindsArguments`, `TestClientBodyCarriesBodyHash`; `proxy/internal/proxy`: `TestMCPToolCallsAllowedEscalatedDenied`, `TestMCPCallToUnpinnedToolIsDenied`, `TestMCPBatches`, `TestMCPGateOff`; `proxy/cmd/ovara`: `TestMCPWrapPinsAndGatesStdio`, `TestMCPWrapRefusesUnparseableLines`, `TestDefaultPolicy_MCP`; `runtime/gateway/internal/handlers`: `TestApprovalContext_ValuesDifferingPastTheCutStayDifferent`, `TestApprovalContext_HashesSurviveTheCap`.

### 8.3 The person deciding sees the definitions and the warning signs
- **Holds in:** as 7.1.
- **What it covers:** the question about a tool list shows each new definition, and for a change the approved and the new description side by side. Hidden characters (the same classes the terminal output escapes: bidi controls, zero-width and other format characters, Unicode tag characters, whose text is also spelled out), instruction-like wording ("ignore previous instructions", "do not tell the user", `<IMPORTANT>`, "before using this tool, read …", secret file paths, "bcc" to an address), names or mentions of other servers' tools (shadowing), unusual tool names and descriptions over 1 KB are listed as a warning. A tool call shows its arguments, masked where they look like secrets.
- **Tests:** `proxy/internal/mcp`: `TestPoisoningFlags`, `TestGateDriftDetection`, `TestGateToolCalls`; `proxy/internal/textsafe`: `TestKindsAndHidden`; `proxy/internal/proxy`: `TestMCPChangedDescriptionAsksAgainAndDenialCutsResponse`, `TestMCPToolCallsAllowedEscalatedDenied`; `proxy/cmd/ovara`: `TestMCPWrapWithTheRealGatewayAndDefaultPolicy`.

### 8.4 An MCP message is not decided on one reading while the other side acts on another
- **Holds in:** as 7.1.
- **What it covers:** a message with duplicate keys or keys that differ only in case (also by Unicode case folding, and also when a name is spelt with `\u` escapes) or invalid UTF-8 is refused whatever it carries (`mcp_message_ambiguous`): a request that could be JSON-RPC with 403 and a JSON-RPC error per request in it, a 2xx answer to an MCP exchange, or an event or wrapped-server line that could be JSON-RPC, with an error in its place, and a line from the wrapper's client with an error. A batch with a member that is not a message is refused when it carries a tool call or a tool list. Event streams are split the way clients split them (CR, LF and CRLF line ends, a leading byte order mark). A tool list that is malformed is refused, not passed. The agent's `Accept-Encoding` is not forwarded on MCP requests, and a response that still arrives encoded is refused; a request body is read through gzip. A message too large to read whole (over 4 MiB) is refused when it looks like JSON-RPC; an event over 4 MiB ends an MCP event stream, a JSON answer to a tool list over 4 MiB is refused, and a line over 4 MiB from a wrapped server ends the session (one from the client is not passed on).
- **What cannot be read strictly is refused, not passed.** Readers on the other side are more lenient than Ovara (Python's `json.loads` takes `NaN` and `Infinity` and detects UTF-16 and UTF-32). So:
  - A request body that is not valid UTF-8 JSON but that such a reader could take for JSON-RPC is refused with 400 and a JSON-RPC parse error (reason `mcp_unparseable`). That covers byte order marks, the NUL bytes of UTF-16/32, `"jsonrpc"` or `"method"` members (also spelt with `\u` escapes or in another case, in single quotes, or bare before `:`, `=` or `=>`, as Gson and JSON5 readers take them), and `NaN`, `Infinity` or `-Infinity` values. The answer is the same however the body was cut into pieces. A comment before the opening brace is not looked through: such a body is refused only for a server already known to speak MCP (next point).
  - A `tools/call` whose method name is not `tools/call` as written but would be run as one by a dispatcher that ignores case (Unicode case folding), trims white space or control characters, or ends the name at a NUL is refused (`mcp_message_ambiguous`), whether or not the server is known and in `ovara mcp wrap`. Only this method is treated so: it is the one whose spelling is a decision.
  - For a server known to speak MCP, or a request with MCP session headers, any body that is not valid JSON is refused. Servers whose tools are pinned stay known; other servers are forgotten least recently used first.
  - A request body with a Content-Encoding other than gzip is refused when it could be JSON-RPC, known server or not. A body over 4 MiB is refused when anything in it looks like JSON-RPC.
  - `ovara mcp wrap` answers a client line that is not valid JSON with a parse error (-32700) and does not pass it on. A server line that looks like JSON-RPC but cannot be read is refused.
  - For an MCP exchange, a response with a body must name exactly one Content-Type, `application/json` or `text/event-stream` (parameters allowed). Anything else is refused with 502 (`mcp_unexpected_content_type`), even when a client would still read it as JSON or an event stream; error statuses and empty answers pass. A JSON answer, or a message event of an MCP stream, that cannot be read strictly is refused (502, `mcp_unparseable`).
- **Tests:** `proxy/internal/mcp`: `TestDetectMCPBodies`, `TestCheckKeysNested`, `TestSSEEventReader`, `TestToolListMalformed`, `TestServerBodyRefusesUnreadableToolLists`, `TestLooksLikeJSONRPC`, `TestLooksLikeJSONRPCThroughLongWhiteSpace`, `TestSnifferAnswersTheSameForEverySplit`, `TestMisspeltToolCallIsRefusedNotPassedOn`, `TestOtherMethodNamesAreNotMistakenForToolCalls`, `TestServerBodyRefusesUnparseableJSONRPC`, fuzz `FuzzSnifferSplitInvariance` and `FuzzToolCallNameIsAlwaysGated`; `proxy/internal/proxy`: `TestMCPAmbiguousRequestsAreRefused`, `TestMCPEncodedResponseIsRefused`, `TestMCPOversizedMessageIsRefused`, `TestMCPNonMCPTrafficIsUntouched`, `TestMCPToolCallUnparseableByGoIsRefused`, `TestMCPUnparseableRefusedWithoutMCPHeaders`, `TestMCPLenientMemberNamesAreRefusedWithoutMCPHeaders`, `TestMCPMisspeltToolCallIsRefused`, `TestMCPKnownServerRefusesAnyUnparseableBody`, `TestMCPToolListWithOddContentTypeIsRefused`, `TestMCPResponseContentTypesAccepted`, `TestMCPToolListUnparseableByGoIsRefused`, `TestMCPResponseUnparseableIsRefused`, `TestMCPKnownServersSurviveFlooding`, `TestMCPDuplicateKeyMessagesAreRefused`; `proxy/cmd/ovara`: `TestMCPWrapRefusesUnparseableLines`, `TestMCPWrapRefusesMisspeltToolCalls`, `TestMCPWrapForwardsCanonicalLines`.

### 8.5 What the other side receives is exactly what was checked
- **Holds in:** as 8.1.
- **What it covers:** every MCP message the gate reads is read strictly (as 1.9, with member names that differ only in case counted as duplicates and a leading byte order mark dropped) and relayed as the canonical encoding of what was read, never as the bytes that arrived. Over HTTP, a request body (decoded first if it came gzipped) is replaced before policy is asked and sent without Content-Encoding; the URL question's and the tool-call question's `body_sha256` and the receipts' `body_sha256` are of those bytes. A checked JSON answer reaches the client re-encoded, with Content-Length to match. A checked event of an event stream reaches the client rebuilt: its event name, id and retry fields are kept, its data is the canonical encoding on one `data:` line, and comments and unknown fields inside it are dropped; an event without data passes as it came. `ovara mcp wrap` sends each client line to the server, and each server line to the client, as its canonical encoding. So neither side can read a message differently from the gate, whatever its JSON reader does with duplicates, case, escapes or trailing data. Valid JSON that is not MCP is not read as a message and goes as it came.
- **Tests:** `proxy/internal/proxy`: `TestMCPRequestForwardedCanonical`, `TestMCPDuplicateKeyMessagesAreRefused`, `TestMCPJSONResponseReEncoded`, `TestMCPSSEToolListReEncoded`, `TestMCPToolCallsAllowedEscalatedDenied`; `proxy/cmd/ovara`: `TestMCPWrapForwardsCanonicalLines`; `proxy/internal/mcp`: `TestSSEEventReader`; `proxy/internal/canonjson`: `TestCanonicalProperties`, `FuzzCanonical`.

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
  The taint rule (7.1) only sees untrusted content it can recognise:
  content from a trusted host that is not on `untrusted_reads` (a README,
  a commit message, a file in a repository anyone can push to), content
  read before Ovara started, and content that arrives outside the proxy
  do not mark the agent. A write it asks about is still the person's call.
- **Agent names in cooperative mode.** The name in a receipt is the token
  the client presented. Agents that run as the same user can read each
  other's tokens (from the environment `ovara env` sets up, or from
  `proxy.json` if they run as Ovara's user); give agents separate users if
  their names must hold.
- **Model budget accuracy.** Token counts are what the provider's response
  says; a compressed response, a response format the proxy does not know,
  or one larger than its bounds counts as a request only. Counts reset
  when `ovara run` restarts.
- **Interpreter one-liners and renamed binaries in the box.** The command
  gate sees every exec, but the default rules match command lines. A
  `python -c` that deletes files, a renamed copy of `rm`, or a git alias
  defined in a config file is not caught by the `rm` or `git push` rules.
  The network and file boundaries do not depend on these rules.
- **Arguments rewritten after the check.** The gate reads a command's
  arguments from the stopped process. Another process of the same agent
  could change them before the program reads them. The program itself
  cannot change.
- **Restarting without client tokens.** Client authentication cannot be
  relaxed while Ovara runs, but a proxy started with no `agent_token` and
  no agents on a loopback or boundary address runs without it, as it
  always has.
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
  GitHub API paths as written (the numeric-id forms `/repositories/<id>/`
  and `/organizations/<id>/` included); a percent-encoded or case-changed
  path falls back to the host-wide read rule. In `ovara box` the repository
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
- **MCP Ovara cannot see.** A stdio MCP server that is not started through
  `ovara mcp wrap` is invisible to Ovara (inside `ovara box` its process
  and its network traffic are still checked). WebSocket transports are not
  supported. The wrapper protects nothing against an agent that runs as
  the same user: it can edit the pins, read the gateway token or start the
  server directly.
- **What an MCP pin covers.** A pin covers what a server *says* a tool
  does, not what it does: a server can change a tool's behaviour without
  changing its definition. Only `tools/list` and `tools/call` are checked;
  resources, prompts, sampling and elicitation pass as the URL policy
  decides. The warnings about a definition are hints for the person, not
  detection; a definition with none can still be hostile.
- **MCP server identity.** A server is its host and path. After the proxy
  restarts, calls posted to an HTTP+SSE server's endpoint are refused until
  its event stream is opened again (the tie between the two is kept in
  memory).
- **Byte-exact JSON bodies.** Model and MCP bodies Ovara reads as JSON
  arrive upstream in canonical form (1.9, 8.5). An upstream that checks a
  signature the client computed over the original body bytes, or caches
  by those bytes, sees different bytes with the same meaning.
- **SDK verifiers.** The TypeScript and Python SDK helpers verify v1 proxy
  receipts only, not v2. Use `ovara log -verify-only` for v2.
- **External review.** No independent review of the box has been done
  yet. Until it has, Ovara does not call itself a sandbox without
  qualification.
