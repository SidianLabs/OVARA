import { OvaraClient } from "./client.js";
import type {
  InterceptRequest,
  InterceptDecision,
  InterceptorConfig,
  PageLike,
  BrowserLike,
} from "./types.js";

export class BrowserInterceptor {
  private client: OvaraClient;
  private blockOnDeny: boolean;
  private logDecisions: boolean;

  constructor(config?: InterceptorConfig) {
    const url = config?.baseUrl || process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
    const key = config?.apiKey || process.env.OVARA_API_KEY || "";
    this.client = new OvaraClient({
      baseUrl: url,
      apiKey: key,
      retries: config?.retries ?? 2,
      timeoutMs: config?.timeoutMs ?? 5000,
    });
    this.blockOnDeny = config?.blockOnDeny ?? true;
    this.logDecisions = config?.logDecisions ?? false;
  }

  async evaluate(request: InterceptRequest): Promise<InterceptDecision> {
    const actionType = this.mapTargetToAction(request.target);
    const resource = request.url || request.filePath || "unknown";

    const result = await this.client.check({
      actionType,
      resource,
      environment: request.environment || "local",
    });

    const decision: InterceptDecision = {
      allowed: result.decision === "allow",
      decision: result.decision,
      reason: result.reason,
      receiptId: result.receiptId,
    };

    if (this.logDecisions) {
      console.log(`[Ovara] ${request.target}: ${result.decision} — ${resource}`);
    }

    return decision;
  }

  interceptNavigation(page: PageLike, environment?: string): void {
    page.on("request", async (req: any) => {
      if (req.isNavigationRequest?.() || req.frame?.() === page) {
        const decision = await this.evaluate({
          target: "navigation",
          url: req.url?.() || req.url,
          environment: (environment as any) || "local",
        });

        if (!decision.allowed && this.blockOnDeny) {
          if (typeof req.abort === "function") {
            req.abort("blockedbyclient");
          } else if (typeof req.respond === "function") {
            req.respond({ status: 403, body: "Blocked by Ovara policy" });
          }
        }
      }
    });
  }

  interceptFormSubmissions(page: PageLike, environment?: string): void {
    page.on("request", async (req: any) => {
      const method = (req.method?.() || req.method || "").toUpperCase();
      if (method === "POST" || method === "PUT" || method === "PATCH") {
        const decision = await this.evaluate({
          target: "form_submit",
          url: req.url?.() || req.url,
          method,
          environment: (environment as any) || "local",
        });

        if (!decision.allowed && this.blockOnDeny) {
          if (typeof req.abort === "function") {
            req.abort("blockedbyclient");
          }
        }
      }
    });
  }

  interceptDownloads(browser: BrowserLike, environment?: string): void {
    browser.on("download", async (download: any) => {
      const url = download.url?.() || download.url || "unknown";
      const decision = await this.evaluate({
        target: "file_download",
        url,
        environment: (environment as any) || "local",
      });

      if (!decision.allowed && this.blockOnDeny) {
        if (typeof download.cancel === "function") {
          download.cancel();
        }
      }
    });
  }

  interceptUploads(page: PageLike, environment?: string): void {
    page.on("filechooser", async (fileChooser: any) => {
      const pageUrl = "";
      const decision = await this.evaluate({
        target: "file_upload",
        url: pageUrl,
        environment: (environment as any) || "local",
      });

      if (!decision.allowed && this.blockOnDeny) {
        if (typeof fileChooser.cancel === "function") {
          fileChooser.cancel();
        }
      }
    });
  }

  private mapTargetToAction(target: string): string {
    switch (target) {
      case "navigation":
        return "browser.navigate";
      case "form_submit":
        return "browser.form_submit";
      case "file_download":
        return "browser.download";
      case "file_upload":
        return "browser.upload";
      default:
        return "browser.action";
    }
  }
}

export { OvaraClient, createClient } from "./client.js";
export type {
  InterceptRequest,
  InterceptDecision,
  InterceptorConfig,
  BrowserAPI,
  PageLike,
  BrowserLike,
} from "./types.js";
