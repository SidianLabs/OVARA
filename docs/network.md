# Ovara's own network connections

This lists every network connection **Ovara itself** makes, apart from the
agent's traffic that Ovara is there to broker. The agent's requests go to
wherever the agent asked and are recorded in the receipt log; this page is
about Ovara's own side.

The short version: **a default deployment (`ovara init`, `ovara run`,
`ovara box`) makes no outbound internet request of its own.** There is no
telemetry, no analytics, no update check, and no phone-home anywhere in the
code. Every external connection below is turned on only when you configure
the feature that needs it.

## On the machine, always

| Connection | What it is |
|---|---|
| proxy → gateway, over loopback (`gateway_url`, default `127.0.0.1:8080`) | the proxy asks the gateway to decide each action, and claims approvals. Same machine. |
| gateway → the box's local sockets / the Docker daemon (unix socket) | starting and watching a tier 2 box, when the sandbox executor is in use. Local. |
| the enrollment heartbeat | writes the gateway's `last_seen` to a local file on a timer. In the default (local) mode this makes **no** network call. |

## External, only when you turn the feature on

| Connection | Goes to | Enabled by |
|---|---|---|
| GitHub App installation tokens | `api.github.com` | a `github_app` credential binding — Ovara mints the short-lived token it injects |
| OAuth2 client-credentials / token exchange | the token endpoint you set (`token_url`) | an `oauth2` credential binding |
| Slack approvals | `slack.com` | configuring the Slack approver |
| Off-host anchoring of the receipt chain | the anchor service you set | `gateway_anchor_mode` (off by default; `ovara doctor` warns while it is off) |
| Ovara's own outbound requests via a corporate proxy | your CONNECT proxy | `upstream_proxy` in `proxy.json` |
| OpenTelemetry decision spans | your OTLP collector | an exporter endpoint in the gateway config |
| Cloud enrollment, policy sync, federated identity verification | the control plane / server you set | `control_plane_url` / a federated-trust server (not set in local mode) |

Credential minting and the Slack and anchor connections carry only what the
feature needs (a token request, an approval message, a chain head), never
the agent's data. The hosted control plane that earlier versions could enrol
with has been removed from this repository; the enrollment code only dials
out when you point it at a server of your own.

## How to check for yourself

- `ovara doctor -dir <deployment>` lists the credential bindings, the
  anchor mode, and whether an upstream proxy is set.
- `ovara log -dir <deployment>` is every decision Ovara made about the
  agent's traffic; Ovara's own connections above do not appear there because
  they are not the agent's.
- In an enforced deployment, the only route out of the agent's network
  namespace is the proxy, so the agent cannot make a connection that does
  not show up.
