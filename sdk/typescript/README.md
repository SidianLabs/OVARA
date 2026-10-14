# @ovara/sdk

Ovara Runtime Gateway SDK for TypeScript — intercept agent actions, submit them for policy decision, and verify cryptographic receipts.

```ts
import { createClient } from "@ovara/sdk";

const client = createClient({
  baseUrl: "http://localhost:8080",
  token: process.env.OVARA_AGENT_TOKEN!,
});

const decision = await client.checkAction({
  action: "shell.execute",
  resource: "shell:ls",
});

if (decision.decision === "allow") {
  // proceed
}
```

## Install

```bash
npm install @ovara/sdk
```

Requires Node.js >= 18.

## Tool guard

Wrap the functions your framework's tools run, and every call is decided
by the gateway before it runs, held for a person when policy says so, and
reported when it is done. The guard holds the agent token only.

```ts
import { createToolGuard, ToolDenied, ToolHeld } from "@ovara/sdk";

const guard = createToolGuard({ baseUrl: "http://127.0.0.1:8080", apiKey: AGENT_TOKEN, agent: "support-bot", waitSeconds: 60 });
const sendEmail = guard.wrap("send_email", async (to: string, subject: string, body: string) => { ... });
```

A denied call throws `ToolDenied`; a call still waiting on a person after
`waitSeconds` throws `ToolHeld` with the approval id (`waitSeconds: 0` fails
fast; the identical call made later gets the answer back). `guard.last` is
the record of the last call.

## License

Apache-2.0
