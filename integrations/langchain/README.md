# Ovara LangChain Integration

LangChain tools that let AI agents check actions against Ovara runtime trust policies.

| Tool | Description |
|------|-------------|
| `OvaraCheckTool` | Check if an action is allowed |
| `OvaraStatusTool` | Gateway health status |
| `OvaraReceiptsTool` | List execution receipts |

```typescript
import { OvaraCheckTool, OvaraStatusTool } from "@ovara/integrations-langchain";

const tools = [new OvaraCheckTool(), new OvaraStatusTool()];
```
