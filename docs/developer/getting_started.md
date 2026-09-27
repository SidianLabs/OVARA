# Getting Started

The fastest path — no account, no cloud, everything local:

1. **Build and boot the stack** (from the repo root):

   ```bash
   cd proxy && go build -o ovara ./cmd/ovara && cd ..
   ./proxy/ovara init mystack     # one directory: gateway + proxy config
   ./proxy/ovara run -dir mystack # gateway on :8080, proxy on :9443
   ```

   Or the gateway alone: `./examples/start_gateway.sh` (open auth on
   loopback, demo policy — verified commands are in the README quickstart).

2. **Check an action** — the policy gate every agent call goes through:

   ```bash
   curl -s -X POST http://localhost:8080/v1/runtime/check \
     -H 'Content-Type: application/json' \
     -d '{"action_type":"shell","resource":"shell:ls -la","environment":"local"}' | jq .decision
   ```

   `allow` / `escalate` / `deny` comes from
   `examples/sample_policy_local.json`. Try `environment=dev` and
   `environment=production` to see the other two outcomes.

3. **See the approval loop**: `./examples/demo_approval_flow.sh`
   (escalate → approve → resume, as a human approver).

4. **Inspect receipts**: `./examples/demo_inspection.sh` — every
   decision is Ed25519-signed; the receipt chain is hash-linked in
   `var/receipts.jsonl` (under `mystack/` for `ovara run`).

5. **Point an agent at the proxy**: route its HTTPS traffic through
   `:9443` and the gateway evaluates each action before the proxy
   executes it, with real credentials injected at execution time — the
   agent never sees them. See
   [`../architecture/executor_proxy.md`](../architecture/executor_proxy.md).

Deeper setup (config fields, auth tokens, executors):
[`local_runtime.md`](local_runtime.md) · for real deployments,
[`../deployment.md`](../deployment.md) and [`../operations.md`](../operations.md).
