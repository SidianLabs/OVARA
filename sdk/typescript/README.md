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

## License

Apache-2.0
