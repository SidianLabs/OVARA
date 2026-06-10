import { StructuredTool } from "langchain/tools";
import { z } from "zod";
import { createClient } from "@ovara/sdk";

const OVARA_URL = process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
const OVARA_KEY = process.env.OVARA_API_KEY || "";
const client = createClient({ baseUrl: OVARA_URL, apiKey: OVARA_KEY });

export class OvaraCheckTool extends StructuredTool {
  name = "ovara_check_action";
  description = "Check if an action is allowed by Ovara runtime trust policy before executing it.";
  schema = z.object({
    action: z.string().describe("Action type (shell.execute, git.push, etc.)"),
    resource: z.string().describe("Target resource (command, branch, etc.)"),
    environment: z.enum(["local", "staging", "production"]).default("local"),
  });

  async _call(input: z.infer<typeof this.schema>): Promise<string> {
    const result = await client.check({
      actionType: input.action,
      resource: input.resource,
      environment: input.environment,
    });
    return JSON.stringify(result);
  }
}

export class OvaraStatusTool extends StructuredTool {
  name = "ovara_gateway_status";
  description = "Get the current health and status of the Ovara gateway.";
  schema = z.object({});

  async _call(): Promise<string> {
    const status = await client.status();
    return JSON.stringify(status);
  }
}

export class OvaraReceiptsTool extends StructuredTool {
  name = "ovara_list_receipts";
  description = "List recent execution receipts from the Ovara gateway.";
  schema = z.object({
    limit: z.number().default(20),
    offset: z.number().default(0),
  });

  async _call(input: z.infer<typeof this.schema>): Promise<string> {
    const receipts = await client.listReceipts(input);
    return JSON.stringify(receipts);
  }
}
