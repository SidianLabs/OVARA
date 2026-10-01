# Ovara LangChain Integration

Advisory check tools that let AI agents consult Ovara runtime trust
policies before acting.

> **Note:** these are advisory checks only — a tool result informs the
> agent but does not enforce policy. Enforcement happens at the Ovara
> egress proxy, which records a signed receipt chain for all egress.

| Tool | Description |
|------|-------------|
| `OvaraCheckTool` | Check if an action is allowed |
| `OvaraStatusTool` | Gateway health status |
| `OvaraReceiptsTool` | List execution receipts |

```typescript
import { OvaraCheckTool, OvaraStatusTool } from "@ovara/integrations-langchain";

// Tools are plain duck-typed objects ({ name, description, schema, _call }),
// not LangChain StructuredTool instances — the @langchain/core dependency
// is intentionally not required. Wrap them in StructuredTool yourself if
// your agent runtime requires it.
const tools = [OvaraCheckTool, OvaraStatusTool];
const result = await OvaraCheckTool._call({ action: "shell", resource: "shell:ls" });
```
