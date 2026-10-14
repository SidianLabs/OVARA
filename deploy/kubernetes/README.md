# Ovara as a Kubernetes sidecar

*Status: a documented recipe with example manifests. Not run in CI yet; the
pieces it uses (`ovara run -ui off`, `ovara env`, the proxy token, the CA,
`attest_every_minutes`) are each tested on their own.*

One pod, two containers: the agent, and Ovara next to it. They share the
pod's network namespace, so the agent reaches Ovara on `127.0.0.1:9443`
and nothing else: a `NetworkPolicy` lets only the Ovara container's
traffic out. Ovara holds the deployment directory (policy, tokens, CA,
receipts); the agent gets the CA certificate and its own proxy token,
never the directory.

```
┌──────────────────────────── pod ────────────────────────────┐
│  agent container                 ovara container            │
│  HTTPS_PROXY=http://agent:$TOKEN@127.0.0.1:9443             │
│  SSL_CERT_FILE=/ovara-ca/ca.pem  ──►  ovara run -ui off     │──► internet, decided
│  (no route out of its own)            /ovara (owner-only)   │    per policy.json
│                                       var/receipts.jsonl    │
│                                       var/attestations/     │
└─────────────────────────────────────────────────────────────┘
```

## 1. Make the deployment directory once, off-cluster

```sh
ovara init agent-pod -profile strict        # policy.json, proxy.json, config.json, keys
ovara agent add worker -dir agent-pod       # the agent's own token (in proxy.json)
```

Edit `agent-pod/policy.json` for the hosts the agent may reach. Put the
directory into a Secret (it holds the gateway's operator token, the
agents' tokens and the receipt signing key: owner-only in the container,
mounted into the Ovara container only):

```sh
kubectl create secret generic ovara-deployment --from-file=agent-pod/
kubectl create secret generic ovara-agent-token \
  --from-literal=token="$(python3 -c "import json;print(json.load(open('agent-pod/proxy.json'))['agents']['worker'])")"
```

The CA certificate the agent must trust is created the first time
`ovara run` starts; the init container in the manifest runs it once so
`ca.pem` exists before the agent starts, and copies it to a volume the
agent can read.

## 2. Apply the manifest

[`agent-pod.yaml`](agent-pod.yaml) is a `Deployment` with the two
containers, the init container, the volumes, and a `NetworkPolicy` that
blocks the agent container's own egress (the policy applies to the pod;
the Ovara container's traffic leaves because the agent never sends
anything but to loopback, and only Ovara dials out). Receipts and
attestations live on a `PersistentVolumeClaim` (`var/`), so the record
survives the pod.

```sh
kubectl apply -f deploy/kubernetes/agent-pod.yaml
kubectl exec deploy/agent -c ovara -- ovara status -dir /ovara
kubectl exec deploy/agent -c ovara -- ovara approvals -dir /ovara
```

Set `attest_every_minutes` in `proxy.json` (10, say) so an agent that
never stops still has a verifiable record: a signed statement every ten
minutes, each naming the previous one, verified with
`ovara attest verify -dir /ovara`. Approvals reach you through Slack
(`chat.slack` in `proxy.json`, the token in `OVARA_SLACK_TOKEN` from a
Secret) or `kubectl exec ... ovara approve ID`.

## 3. What to check

- The agent container has no network path but loopback: `kubectl exec
  deploy/agent -c agent -- curl -sS https://example.com` must fail,
  `curl -sS --proxy "$HTTPS_PROXY" https://example.com` must be decided by
  policy (a receipt in `ovara log`).
- `/ovara` is mounted only in the Ovara container; the agent sees
  `/ovara-ca/ca.pem` and `OVARA_PROXY_TOKEN`, nothing else of Ovara's.
- `ovara doctor -dir /ovara` is clean.

## What is not here yet

Many pods under one organisation baseline (mount the signed baseline and
set `policy_baseline_file` in `config.json`: it works per pod today; a
control plane that pushes it and collects every pod's receipts is track
G7's next step), receipts shipped off the pod (use `ovara log export` on
a schedule, `docs/operations.md`), and a rootless tier 2 box inside the
pod.
