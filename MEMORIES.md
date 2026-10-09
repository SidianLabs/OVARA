# Ovara — working memory (handoff)

Last updated: 2026-10-09 (cloud session). Read this first, then `README.md`, `docs/threat-model.md`, `docs/use-cases.md`.

Branch: `test/real-agents`, 7 commits ahead of `main`, **not pushed**. The owner said do not push yet.
`hardening/path-to-10` is finished: merged into `main` as PR #27 (`97cafe1`). Do not reuse it.

---

## 0. Where to continue (start here)

### 0.1 State
- Unit suites green (§6). All agent runs below green. Nothing pushed; no PR for this branch.
- The `User scenarios` workflow (`scenarios.yml`) has run 3 times on GitHub (PR #27, dependabot PRs #29 and #32) and **failed every time in under a second**: the entry scripts were committed as mode 100644, so the runner could not execute them. `148e91e` sets the executable bit. The fix only proves itself once this branch is pushed.

### 0.2 Next steps, in order
1. **Ask the owner, then push and open a PR** for `test/real-agents`. Watch the new CI: `scenarios`, `separate-user-attacks`, `boundary-redteam`, `agents` (matrix opencode/anthropic/codex × coop/enforced), `agents-harness`. They have never passed on GitHub. Expect to fix what the runners show.
   - The Codex and Anthropic's agent CLI **coop** jobs on a normal runner should show the 7 bypasses as INFO (21 passed, 8 info, as opencode did on Docker Desktop). That has not been seen yet (see §3.10). If the numbers differ, update `docs/use-cases.md` scenario 1.
2. `tests/scenarios/Dockerfile` chains installs with `;` (the same silent-failure pattern fixed in `tests/agents/Dockerfile`). Make it fail on a failed install.
3. Aider: needs a different driver. It proposes commands and asks before running them. Options: `aider --message "/run <cmd>"` per command, or check whether a flag makes it run suggested commands unattended. Verify before claiming either.
4. Other scenarios: hosted-sandbox pattern, CI-bot pattern (no human, so unanswered approvals give 504), `tests/boundary/docker_test.sh` (never run).
5. Product gaps: scoped approval-page token (`proxy/cmd/ovara/main.go`, `startUI`: the browser link still carries the full operator token); pin GitHub Actions to SHAs (dependabot PR #29 wants checkout v4→v7); Phase 3/4/7 items.
6. Memories skill: `.claude/skills/memories/SKILL.md` and a one-line pointer in README/AGENTS.md. Never done.

### 0.3 Owner's open requests (their words)
- "test on each scenarios … fork opencode … add ovara into it and test if that works properly same for other scenarios can it be broken or bpassed". **Done:** opencode, Anthropic's agent CLI, Codex CLI (coop + enforced) and the custom harness. **Not done:** Aider, hosted-sandbox, CI-bot. No fork was made; the agents are installed from npm. Ask before forking anything.
- VMs/credits for unattended runs: links in §8. The owner's other machine is unreachable until ~2026-10-14. Note: a cloud coding session (this one) **can** run Docker, including `--privileged` netns tests (§5).
- Memories skill + pointer + commit: not done (0.2 step 6).

### 0.4 Blockers waiting on the owner
- **Rewriting `main` history** to drop AI-tool attribution: 49 commits carry assistant co-author lines and `000d70b` a third-party bot's; two merge subjects name that bot's branches. Needs a force-push of public `main` (all later SHAs, tags and PR links change) and GitHub keeps old commits reachable through PR refs. Owner has not decided. File-level traces were removed on `test/real-agents`; README product copy and the `.gitignore` tool-folder entries were kept on purpose.
- OK to push `test/real-agents` and open a PR? (Owner said no for now.)
- OK to commit `MEMORIES.md`?
- Startup credits (links in §8), fork permission, and any `git rm` of tracked dirs: the classifier has blocked these before, so give the owner the exact command.

---

## 1. Project

Ovara is a checkpoint between an AI agent and the internet. A MITM HTTPS proxy asks an embedded gateway to **allow / escalate (pause for a human) / deny** each request, injects real credentials so the agent never holds them, scrubs reflected secrets, and writes signed, hash-chained receipts. One Go binary: `ovara`.

Stack: Go 1.25 (modules `proxy/` and `runtime/gateway/`, plus `tools/*`), TypeScript SDK `sdk/typescript`, Python SDK `sdk/python`. Apache-2.0, `SidianLabs/OVARA`.

Layout:
- `proxy/cmd/ovara/` — the CLI: `init run env watch approvals approve deny log policy doctor demo version`; `main.go` (init/run/boundary), `demo.go`, `policy_defaults.go` (**default policy and trusted-host lists**), `approvals.go`, `trust_host.go`, `ui.go` + `ui/index.html`, `doctor.go`, `env.go`, `log.go`.
- `proxy/scripts/setup-egress-boundary.sh` — the netns/docker boundary (embedded via `boundary.go`).
- `proxy/internal/proxy/` — `proxy.go`, `hardening.go`, `preview.go`, `git.go`, `scrub.go`.
- `proxy/internal/{ca,creds,config,gateway,receipts}`.
- `runtime/gateway/` — `internal/{policy,evaluator,approval,continuation,execution,record,receipt,receipts,trust,gwidentity,idregistry,anchor,handlers,...}`, `pkg/server/server.go`.
- `tests/scenarios/`, `tests/redteam/{boundary,separate-user}/`, `tests/boundary/`, `tests/agents/` (§3.9–3.10), `tests/e2e/` (old, not in CI).
- Experimental, unconnected: `integrations/`, `policy/compiler`, `security/sandbox`, `tools/`.

---

## 2. Infrastructure and environments

- **No servers, no cloud deploys.** Everything runs locally or in CI.
- **Owner's machine**: Windows 11, Docker Desktop (WSL2), repo at `C:\Users\bhawe\OneDrive\Desktop\OVARA`, Git Bash.
- **Cloud coding session** (used 2026-10-09): Linux, repo at `/home/user/OVARA`. Docker is installed but not started; start it with `dockerd --registry-mirror=https://mirror.gcr.io &` (Docker Hub returns 429 from the shared IP). Gotchas in §5.
- Images: `ovara-scenarios` (`tests/scenarios/Dockerfile`), `ovara-agents` (`tests/agents/Dockerfile`: Go 1.25 + node:24 + net tools + `opencode-ai` 1.18.35, `@anthropic-ai/claude-code` 2.1.295, `@openai/codex` 0.162.0 as of this run).
- **GitHub**: `SidianLabs/OVARA` (public). Workflows: `go-tests.yml`, `lint.yml`, `ts-tests.yml`, `docker.yml`, `release.yml`, `scenarios.yml` (jobs `scenarios`, `separate-user-attacks`, `boundary-redteam`, `agents` matrix, `agents-harness`), `fuzz.yml`, `vulncheck.yml`, `dependabot.yml`. Open dependabot PRs include #29 (checkout v7) and #32 (x/sys 0.48.0; note §5 `go` directive rule).
- **Ports in tests**: proxy `9443`, gateway `8080`, approval page `9090`, mock LLM `9100`.
- **Env var NAMES** (values never written anywhere): `GITHUB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SLACK_TOKEN`, `HTTPBIN_TOKEN`, `OVARA_VERIFY`/`OVARA_VERSION`/`OVARA_INSTALL_DIR`/`OVARA_FROM_SOURCE`/`OVARA_BRANCH`/`OVARA_RELEASE_BASE`, `MODE=coop|enforced`, `AGENT` (set by each agent script), `PROXY_TOKEN`/`NS`/`PROXY_IP`/`GATEWAY_PORT`/`CA`. Agent mocks use placeholder keys (`sk-ant-mock`, `MOCK_API_KEY=x`). Test secrets are fake literals (`REALSECRET-…`).
- **Local run**: `cd proxy && go build -o ovara ./cmd/ovara`; `ovara init d && ovara run -dir d`; `eval "$(ovara env -dir d)"`.

---

## 3. What was done

§3.1–3.8 are unchanged from the previous handoff and are summarised here. Details are in `CHANGELOG.md` and `git log`.

### 3.1–3.8 (summary)
- Scope cut (`73a0f6a`, owner ran `git rm`), references fixed (`67a6bfc`).
- Proxy hardening: allowlist default policy, no DNS before policy, `normalizeHost` fixed point, GET/HEAD body/long-query refusal, method-override stripping, scrubbing, timeouts, approval cap, loopback listen, CA never regenerated, receipt before response.
- Gateway fail-closed stores and journals, crash-at-every-byte test, full-UUID IDs, length-prefixed digest.
- Bugs found by running the real binary: shield quarantine, hot reload, unapprovable forced pauses, receipt order, unevaluated policy conditions, gateway client `sync.Once`, doctor keys, npm-audit POST stall (`9049442`).
- Features: approver preview (`a1204f2`), approve and trust host for reads (`c59abee`), netns guidance, release/installers, fuzz tests, SDK wire fixes.
- Harnesses: `tests/scenarios` (36), `tests/redteam/separate-user` (19), `tests/redteam/boundary` (25), `tests/agents`.
- Not verified: `tests/boundary/docker_test.sh`, `-race` on Windows/macOS, release workflow/installers on GitHub; scoped approval token, SHA-pinned Actions, Windows/macOS enforced mode.

### 3.9 tests/agents layout (after this session)
- `battery.sh` — shared: builds committed HEAD, `ovara init`, starts Ovara (coop or `--boundary netns` + user `agent`), writes the 27 commands, then calls the agent script's `prepare_agent` and `launch_agent` (helpers `start_mock <mock.py>` and `run_agent "<cmdline>"`), parses tool outputs from the mock log, runs the checks, lists **every host that went through the proxy**, verifies the receipt chain. Prints `RESULT[<agent> <mode>]: N passed, M failed, K informational`.
- `opencode.sh` + `mock_llm.py` (OpenAI chat-completions).
- `anthropic.sh` + `mock_anthropic.py` (Anthropic Messages SSE; `ANTHROPIC_BASE_URL`, `--permission-mode bypassPermissions`, `IS_SANDBOX=1` for root in coop, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `--model mock` because an unknown model id prints a warning).
- `codex.sh` + `mock_responses.py` (OpenAI Responses API; `~/.codex/config.toml` with a `mock` provider, `wire_api="responses"`; `codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox`, so Codex's own sandbox is off and Ovara is what gets measured). Codex 0.162 offers `exec_command`; a still-running command returns "Process running with session ID N" and the mock polls it through `write_stdin`.
- All mocks keep the contract: `PORT CMDS LOG`, log lines `{"turn"}`, `{"result_of": n, "output"}`, `{"finished"}`, and the turn index comes from the conversation history, so a retry repeats the command instead of skipping it.
- `harness.py` / `harness.sh` — custom agent harness (16 checks).
- `run.sh coop|enforced [opencode|anthropic|codex]` and `run.sh harness`. It fails unless it sees `RESULT[...]: N passed, 0 failed` or `HARNESS_RESULT N passed 0 failed`.

### 3.10 Results 2026-10-09 (cloud session, local Docker)
| Run | Result |
|---|---|
| opencode coop | 25 passed, 0 failed, 4 info |
| opencode enforced | 28 passed, 0 failed, 1 info |
| Anthropic's agent CLI coop | 25 passed, 0 failed, 4 info |
| Anthropic's agent CLI enforced | 28 passed, 0 failed, 1 info |
| Codex coop | 25 passed, 0 failed, 4 info |
| Codex enforced | 28 passed, 0 failed, 1 info |
| harness | HARNESS_RESULT 16 passed 0 failed |
| boundary red team (after the IPv6 fix) | `=== 0 unexpected result(s) ===`, positive control `proxy CONNECT 200` |

- **Coop caveat:** the cloud sandbox intercepts direct TLS with its own CA. The agent's environment only trusts Ovara's CA, so B1–B4 (`curl --noproxy`, unset proxy, Python and Node direct) failed TLS there rather than "getting out". That is why the cloud runs show 25/4 instead of opencode's 21/8 from Docker Desktop. B5–B7 (raw TCP, DNS, git direct) did get out. Re-confirm on a normal CI runner.
- Agents' own traffic through the proxy: opencode → `models.opencode.ai`, `registry.npmjs.org`; Codex → `chatgpt.com` (GET), `ab.chatgpt.com` (POST), both escalated as unknown hosts; Anthropic's agent CLI (nonessential traffic off) → nothing.
- P4 (`https://pastebin.com\@pypi.org/`) gives 200 because curl reads it as userinfo@pypi.org. It is judged by the receipts invariant (clean).

### 3.11 Bugs found this session
- **netns boundary failed on kernels without IPv6** (`20dd08a`): `setup-egress-boundary.sh` wrote `net.ipv6.conf.*.disable_ipv6` unconditionally, so `ovara run --boundary netns` exited 1. It is now skipped only when `/proc/sys/net/ipv6` is absent.
- **CI entry scripts not executable** (`148e91e`): `tests/scenarios/run.sh`, `tests/redteam/separate-user/run.sh` and `tests/redteam/boundary/run-in-docker.sh` were 100644 (committed from Windows). All `scenarios.yml` jobs failed instantly on GitHub.
- **Agent image built without the agent** (`7b2043d`): `tests/agents/Dockerfile` used `;` and `>/dev/null`, so a failed `npm install -g` still produced an image. It now uses `&&` plus `--version` checks.

---

## 4. Decisions (and why)
- Forced blocks are denies, not escalations (the gateway only opens approvals for recorded escalations).
- Approval preview rides in request metadata, copied by the gateway (callers cannot write what the human sees).
- Shield kept but tuned; trust-host is reads-only, one exact https host; hot reload on by default via directory watch; default policy is a read-host allowlist; npm audit POST allowed by exact path.
- Mock models instead of real API keys; agents installed from npm, not forked on GitHub.
- Tests build committed HEAD (clone of `/repo`) but read scripts from the working tree.
- **One shared battery for every agent** (`battery.sh`) so results are comparable; each agent script only configures and launches.
- **Agents' own sandboxes off** (Codex `--dangerously-bypass-approvals-and-sandbox`, Anthropic CLI `bypassPermissions`): the test measures Ovara, not the agent's guardrails.
- Missing IPv6 sysctl is skipped only when the kernel has no IPv6 at all; any other failure still aborts setup.
- Rejected boundary platforms: Cloudflare Sandbox (rootless, no iptables). GitHub Actions and cloud coding sessions both work.

---

## 5. Gotchas and rules
- **Owner rule: never mention Claude in commit messages or branch names.** No Co-Authored-By/Claude-Session trailers, no "claude/..." branches; call the tested product "Anthropic's agent CLI" in commit text.
- **Container tests build committed code.** Commit before running them.
- **Git Bash**: `export MSYS_NO_PATHCONV=1` and `cygpath -w` (see `run.sh`).
- **Never use a bare `wait`** when `ovara run &` is a child. Wait on specific PIDs.
- **Never share one log file between two background runs.**
- **"000" is ambiguous**: always have a positive control; NO-RESULT is a failure.
- opencode: `permission.external_directory: "allow"`; mocks need `NO_PROXY=127.0.0.1,localhost`.
- Anthropic's agent CLI: refuses bypass mode as root unless `IS_SANDBOX=1`; tool results can sit in any user turn, not only the last (the mock scans all of them).
- Codex: tool names change between versions; `mock_responses.py` picks `shell_command` > `shell` > `exec_command`. A Codex function output may be a JSON string `{"output": ...}`.
- Gateway approval create returns **201**. `ovara approve <id> -dir d` (id first).
- **Edit tooling (Windows)**: working tree is CRLF; edit via Python with CRLF round-trip; write files with the Write tool, not nested heredocs.
- **Windows**: rename over an open journal fails (close first).
- **Docker Desktop crash**: stale `%LOCALAPPDATA%\Docker\run\dockerInference`: quit Docker, `wsl --shutdown`, delete it, restart.
- Flaky under load: `TestLoadDecisionLatency`, `TestOrchestrator_SkipNoExecutor_UsesMarkRequeue`.
- `go.mod` `go` directive must stay **1.25.6**; `x/sys` at `v0.44.0` (dependabot #32 bumps it, so check it does not raise the directive).
- Classifier: `git rm` of tracked dirs gets blocked; hand those commands to the owner.
- **Cloud session specifics**: start `dockerd` yourself with `--registry-mirror=https://mirror.gcr.io`. Containers' direct TLS is intercepted by the session's egress proxy, so a local-only image that trusts `/root/.ccr/ca-bundle.crt` is needed. Build it in the scratchpad: copy the Dockerfile, add `COPY ccr.crt /usr/local/share/ca-certificates/` + `update-ca-certificates` + `NODE_EXTRA_CA_CERTS`, tag `ovara-agents-ccr`, then run the same `docker run … bash -c "tr -d '\r' < /repo/tests/agents/X.sh …"` command. **Never commit that CA.** The kernel has no IPv6. The host Go is 1.24, but `GOTOOLCHAIN` fetches 1.25.6 automatically. Python SDK tests need `pip install '.[dev]'` in a venv; delete the `sdk/python/build/` it leaves behind.
- Test expectations that encoded bugs get updated deliberately, and the commit says so.

---

## 6. How to verify

```bash
# unit suites (from repo root)
for m in runtime/gateway proxy tools/cli tools/migration tools/benchmarks; do (cd $m && go vet ./... && go test -count=1 ./...); done
(cd sdk/typescript && npx vitest run && npx tsc --noEmit -p .)   # 35 tests
(cd sdk/python && python -m pytest -q)                            # 80 tests (needs .[dev])

# end-to-end (Docker + internet)
tests/scenarios/run.sh                         # RESULT: 36 passed, 0 failed
tests/redteam/separate-user/run.sh             # RESULT: 19 passed, 0 failed
tests/redteam/boundary/run-in-docker.sh        # === 0 unexpected result(s) ===
tests/agents/run.sh coop opencode              # RESULT[opencode coop]: N passed, 0 failed
tests/agents/run.sh enforced anthropic            # needs --privileged (run.sh adds it)
tests/agents/run.sh enforced codex
tests/agents/run.sh harness                    # HARNESS_RESULT 16 passed 0 failed

make fuzz
cd proxy && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```
"Done" for a change = unit suites green + the relevant harness green with a positive control.

Last full verification 2026-10-09 (cloud): all Go modules vet + test OK; TS 35 + tsc OK; Python 80 OK; agents per §3.10; boundary red team 0 unexpected. Not re-run this session: `tests/scenarios`, `tests/redteam/separate-user`, fuzz, govulncheck, `-race`.

---

## 7. Timeline (newest first)

Branch `test/real-agents`, not pushed (hashes below are from before the message rewrite; see `git log`):
```
6a63ec8 docs: real-agent results for opencode, Anthropic's agent CLI and Codex; changelog
c0c98ed test(agents): Codex CLI behind Ovara; run.sh and CI take the agent
e77f68e test(agents): mock_anthropic reads tool results from every user turn; use a known model id
20dd08a fix(boundary): netns setup works on kernels without IPv6
7b2043d test(agents): shared battery, Anthropic's agent CLI behind Ovara, CI jobs
148e91e test(agents): run.sh wrapper (coop|enforced|harness); make CI entry scripts executable
```
On `main`:
```
97cafe1 Merge pull request #27 from SidianLabs/hardening/path-to-10   (scenarios.yml failed on it: scripts not executable)
dcb8879 test(agents): real opencode behind Ovara (coop + enforced) and a custom-harness scenario; untrack scratch
9049442 feat(policy): allow npm audit's POST; test: real opencode behind Ovara
c0c7878 ci+docs: run the boundary red team in CI; use-cases cites it
7971688 test(redteam): boundary suite authenticates to the proxy and runs in Docker
67d46f6 test+docs: separate-user attack test (19/19), use-cases guide, changelog
c59abee feat: approve and trust a host for reads (CLI, watch prompt, browser page)
a1204f2 feat: the approver sees what is being sent, not just where
0f5dae6 test: committed end-to-end user-scenario harness (tests/scenarios) and CI job; changelog
de581d6 fix(gateway): policy hot reload actually works
720003d fix(gateway): the shield no longer quarantines normal agents
f1b052a fix(proxy): forced blocks are explicit denials, not pretend pauses
3434768 fix(proxy): write the receipt before the response reaches the agent
73a0f6a chore: remove unconnected services, policy adapters, eBPF/AppArmor stubs and research notes   (owner ran)
... (see git log; branch point 984c99d on product/usable-core)
```

---

## 8. Useful tooling and approaches

- **Adding another agent**: write `tests/agents/<name>.sh` with `AGENT=`, `prepare_agent`, `launch_agent` (`start_mock <mock>.py`; `run_agent "<cmd>"`), then `source <(tr -d '\r' < /repo/tests/agents/battery.sh)`. Reuse a mock if the agent speaks chat-completions, Messages or Responses; otherwise copy one and keep the log contract. Add it to the `Dockerfile` install line, to `run.sh`'s agent list and to the CI matrix.
- **Judge bypasses by receipts, not status codes**; always have a positive control.
- **Debugging a container run**: a git-ignored `.scratch-scn/*.sh` printing `ss -ltnp`, `ip netns exec audit-ns curl -v …`, `tail /tmp/run.log`, the last receipts, `/tmp/agent.out`, `/tmp/mock.log`.
- **Free infra** (third-party summaries from 2026-10-09, re-verify): Oracle Always Free, GCP e2-micro, GitHub Actions (public repos), Kamatera trial. Startup programs: https://www.microsoft.com/startups · https://cloud.google.com/startup · https://aws.amazon.com/startups/ · https://www.digitalocean.com/startups · https://startup.ovhcloud.com/en/ · https://www.e2enetworks.com/startup-program · https://www.oracle.com/cloud/free/ · https://cloud.google.com/free · https://www.kamatera.com/free-trial/.
