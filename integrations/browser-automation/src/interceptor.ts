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

    let result;
    try {
      result = await this.client.check({
        actionType,
        resource,
        environment: request.environment || "local",
      });
    } catch (err: any) {
      // Gateway unreachable/errored: with blockOnDeny we fail closed
      // (deny), otherwise we fail open and log the error.
      const reason = `gateway_error: ${err?.message || err}`;
      if (this.logDecisions || this.blockOnDeny) {
        console.warn(`[Ovara] ${request.target}: ${reason} — ${resource}`);
      }
      return {
        allowed: !this.blockOnDeny,
        decision: "deny",
        reason,
      };
    }

    const decision: InterceptDecision = {
      allowed: result.decision === "allow",
      decision: result.decision,
      reason: result.reason_codes?.join(", "),
      receiptId: result.receipt_stub?.receipt_id,
    };

    if (this.logDecisions) {
      console.log(`[Ovara] ${request.target}: ${result.decision} — ${resource}`);
    }

    return decision;
  }

  // attachRequestInterception enables real (blocking) interception on the
  // page: page.route() for Playwright, setRequestInterception for
  // Puppeteer. Without one of these, "request" events are observational
  // only and cannot block.
  private async attachRequestInterception(
    page: PageLike,
    handle: (req: any, ctx: { abort: () => void; proceed: () => void }) => Promise<void>
  ): Promise<void> {
    if (typeof page.route === "function") {
      // Playwright: route handler must call route.abort() or route.continue().
      await page.route("**/*", async (route: any, request: any) => {
        await handle(request, {
          abort: () => route.abort("blockedbyclient"),
          proceed: () => route.continue(),
        });
      });
      return;
    }
    if (typeof page.setRequestInterception === "function") {
      // Puppeteer: must enable interception before "request" events can block.
      await page.setRequestInterception(true);
      page.on("request", async (req: any) => {
        await handle(req, {
          abort: () => req.abort("blockedbyclient"),
          proceed: () => req.continue(),
        });
      });
      return;
    }
    throw new Error(
      "Page does not support request interception (need page.route or page.setRequestInterception)"
    );
  }

  async interceptNavigation(page: PageLike, environment?: string): Promise<void> {
    await this.attachRequestInterception(page, async (req, ctx) => {
      if (!(req.isNavigationRequest?.() || req.frame?.() === page)) {
        ctx.proceed();
        return;
      }
      const decision = await this.evaluate({
        target: "navigation",
        url: req.url?.() || req.url,
        environment: (environment as any) || "local",
      });

      if (!decision.allowed && this.blockOnDeny) {
        ctx.abort();
        return;
      }
      ctx.proceed();
    });
  }

  async interceptFormSubmissions(page: PageLike, environment?: string): Promise<void> {
    await this.attachRequestInterception(page, async (req, ctx) => {
      const method = (req.method?.() || req.method || "").toUpperCase();
      if (method !== "POST" && method !== "PUT" && method !== "PATCH") {
        ctx.proceed();
        return;
      }
      const decision = await this.evaluate({
        target: "form_submit",
        url: req.url?.() || req.url,
        method,
        environment: (environment as any) || "local",
      });

      if (!decision.allowed && this.blockOnDeny) {
        ctx.abort();
        return;
      }
      ctx.proceed();
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
      // Evaluate against the page the chooser was opened on.
      const pageUrl = typeof page.url === "function" ? page.url() : "unknown";
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
