# External security review: scope and brief

This is the brief for an independent security review of Ovara. Read
[`GUARANTEES.md`](GUARANTEES.md) first: it lists every promise Ovara makes
and the tests behind each one. The review's job is to find any way to break
a promise listed there, or to show that a promise is worded more strongly
than the code supports.

Ovara has been reviewed only by its authors so far. Until this review
reports no open Critical or High finding, the words "sandbox" and
"enforced" are used with the qualifications in `GUARANTEES.md`, never
alone (see `docs/box.md` §16).

## 1. What Ovara is, in one paragraph

A checkpoint between an AI agent and everything it can reach. Every HTTP(S)
request the agent makes goes through a proxy that asks a policy engine (the
gateway) to allow, pause for a person, or deny it. Real credentials are added
by the proxy, so the agent never holds them. Every decision is written to a
signed, hash-chained receipt log. `ovara box` adds a separate user, a network
namespace or container, a root file system of its own, a check on every
program the agent starts, and a reviewed path for bringing changes back.

## 2. Adversary

Assume the agent is **fully hostile**: it is prompt-injected, or the model
itself is pursuing a goal of its own. It can send arbitrary bytes over any
connection it can open, run any program inside its box, and read anything
its OS user can read. It cannot run as Ovara's OS user, and in enforced mode
it has no network route except through Ovara. Its goals, in order:

1. Get data to a place the person did not approve.
2. Perform a write (push, deploy, message, delete) the person did not approve.
3. Obtain a real credential, or use one beyond its intended scope.
4. Make the person approve something other than what they see.
5. Act without leaving a receipt, or make the log say something false.
6. Escape the box (files, processes, network) or change what comes back from it.

Out of scope as adversaries: someone with root on the host, someone who can
edit Ovara's deployment directory, and a malicious model provider or
upstream service (beyond what they send back through the proxy).

## 3. Modes in scope

| Mode | In scope | Notes |
|---|---|---|
| Enforced boundary (`ovara run --boundary netns\|docker`) | **Yes, primary** | Linux |
| `ovara box` tier 1 and tier 2 | **Yes, primary** | Linux, root on host |
| Cooperative (`ovara env` only) | Secondary | Bypass by ignoring the proxy is a documented limit, not a finding |
| macOS / Windows | No | Cooperative only; documented |

## 4. Code that has to be right for the promises to hold

Sizes are non-test Go lines at the time of writing.

| Area | Path | Lines | Why it matters |
|---|---|---|---|
| Request path | `proxy/internal/proxy` | ~5,000 | Every check, in order: method, client identity, body holding, resource string, gateway call, read guards, model gate, MCP gate, taint, budgets, package gate, SSRF, credential injection, receipts, response scrubbing |
| MCP parsing and pinning | `proxy/internal/mcp` | ~1,700 | JSON-RPC and SSE parsing; parser differentials were the main late finding |
| Credentials | `proxy/internal/creds` | ~1,100 | Binding match by host, port, path, method; GitHub App and OAuth2 token minting |
| Receipts | `proxy/internal/receipts` | ~1,150 | v2 signing form, key history, anchors, verification |
| Interception CA | `proxy/internal/ca` | ~270 | Constrained CA, leaf minting |
| Command gate | `proxy/internal/boxgate` | ~450 | ptrace exec stops, command-line normalisation |
| Workspace and commit-back | `proxy/internal/workspace` | ~1,000 | Copy, secret scan, reviewed tree, control repository |
| Strict installs | `proxy/internal/lockfiles` | ~800 | Download naming, pins, digests |
| CLI and box launcher | `proxy/cmd/ovara` | ~7,100 | `box.go`, `box_tier1.go`, `boxinit.go` (namespaces, pivot_root, privilege drop), approvals UI, `mcp wrap` |
| Boundary setup | `proxy/scripts/setup-egress-boundary.sh`, `boundary.go` | | Firewall rules for both sides |
| Policy matching | `runtime/gateway/internal/policy`, `evaluator` | ~2,750 | Canonical resources, precedence, per-ref git decisions |
| Approvals | `runtime/gateway/internal/approval`, `handlers` | | Expiry, caps, de-duplication, who may resolve |
| Gateway auth | `runtime/gateway/internal/auth` | ~250 | Agent vs operator tokens |
| Gateway records | `runtime/gateway/internal/record`, `gwidentity` | | Signed journals, revocation, anchoring |

## 5. Areas we would like the most attention on

These are where the authors' own review found the most problems, so more
are likely:

1. **Parser differentials** between the proxy and the upstream (HTTP framing,
   JSON, JSON-RPC, SSE, git pkt-lines, URLs and hosts). Inspected JSON bodies
   are re-encoded before forwarding so the upstream reads what was checked;
   check whether any inspected format still forwards the agent's bytes.
2. **Ordering in `handleRequest`** and the paths that skip a later check
   (approved escalations, fail-open, CONNECT tunnels, streaming responses).
3. **Approval fidelity**: can what a person sees differ from what is sent?
4. **Tier 1 box**: namespace setup, mounts, `/proc`, privilege drop, the
   pipe that carries the agent's environment, ptrace edge cases.
5. **Commit-back**: anything the agent controls that reaches the host's git
   or the real repository without being shown.
6. **Receipt integrity**: truncation, forks, key rotation and revocation,
   anchors, crash windows between "attempt" and "outcome".
7. **Credential scope**: requests that get a credential they should not
   (host, port, path, method, redirects, minted token scope).

## 6. How to build and test

```bash
cd proxy && go build -o ../ovara ./cmd/ovara      # Go 1.25+
make test                                         # all Go modules, -race
make fuzz FUZZTIME=5m                             # every fuzz target
./ovara bench                                     # attack benchmark (docs/BENCHMARK.md)
sudo -E go test ./proxy/cmd/ovara -run 'Tier1|Box' # tier 1 tests need root
tests/scenarios/run.sh; tests/redteam/separate-user/run.sh; tests/box/run.sh boundary   # need Docker
```

`MEMORIES.md` §5 lists environment gotchas.

## 7. What we ask for in the report

For each finding: the promise in `GUARANTEES.md` it breaks (or "new"), the
mode, severity, a reproduction (a failing Go test is ideal), and a suggested
fix. Please also list what you tried that held up, so we know where the
coverage is.

Report privately: see [`SECURITY.md`](../SECURITY.md). We publish the
report, with fixes and advisories, after the fixes ship.
