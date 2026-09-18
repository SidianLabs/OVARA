export type Environment = "local" | "staging" | "production";

export type InterceptionTarget = "navigation" | "form_submit" | "file_download" | "file_upload";

export interface InterceptRequest {
  target: InterceptionTarget;
  url?: string;
  method?: string;
  formData?: Record<string, string>;
  filePath?: string;
  environment?: Environment;
}

export interface InterceptDecision {
  allowed: boolean;
  decision: "allow" | "deny" | "escalate";
  reason?: string;
  receiptId?: string;
}

export type BrowserAPI = "playwright" | "puppeteer";

export interface InterceptorConfig {
  baseUrl?: string;
  apiKey?: string;
  retries?: number;
  timeoutMs?: number;
  browser?: BrowserAPI;
  blockOnDeny?: boolean;
  logDecisions?: boolean;
}

export interface PageLike {
  on(event: string, handler: (...args: unknown[]) => void): void;
  evaluate(fn: (...args: unknown[]) => unknown, ...args: unknown[]): Promise<unknown>;
  /** Playwright-style request routing (required for blocking). */
  route?(url: string | RegExp, handler: (route: unknown, request: unknown) => Promise<void> | void): Promise<void> | void;
  /** Puppeteer-style request interception toggle (required for blocking). */
  setRequestInterception?(enabled: boolean): Promise<void> | void;
  /** Current page URL (Puppeteer/Playwright both expose url()). */
  url?(): string;
}

export interface BrowserLike {
  on(event: string, handler: (...args: unknown[]) => void): void;
}
