// AntiScam AI – Core SDK client
// Covers all communication with the AntiScam AI gateway.

import { createRequire } from "module";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AntiScamConfig {
  /** Your SDK API key from the AntiScam AI dashboard */
  apiKey: string;
  /** Base URL of your AntiScam AI instance (default: https://api.antiscamai.io) */
  endpoint?: string;
  /**
   * Operating mode:
   *  - "block"   → requests scoring ≥65 are blocked automatically  (default)
   *  - "flag"    → requests scoring ≥40 are flagged but allowed
   *  - "monitor" → all requests are allowed; threats are only logged
   */
  mode?: "block" | "flag" | "monitor";
  /** Score at which a request is considered a threat (0-100, default: 65) */
  blockThreshold?: number;
  /** Score at which a request is flagged but allowed (default: 40) */
  flagThreshold?: number;
  /** Max ms to wait for AI response before falling back (default: 3000) */
  timeoutMs?: number;
  /**
   * What to do when the AI service is unreachable:
   *  - "allow"  → fail-open  (default – keeps your service available)
   *  - "block"  → fail-closed (safer but may affect availability)
   */
  onError?: "allow" | "block";
  /** Routes to skip entirely, e.g. ["/health", "/metrics"] */
  excludePaths?: string[];
  /** Only inspect these HTTP methods (default: POST, PUT, PATCH) */
  inspectMethods?: string[];
  /** Optional callback invoked on every threat detection */
  onThreat?: (threat: ThreatEvent) => void | Promise<void>;
}

export interface InspectRequest {
  bodyRaw?: string;
  bodyText?: string;
  extractedUrls?: string[];
  headers?: Record<string, string>;
  sourceIp?: string;
  endpoint?: string;
  method?: string;
  userId?: string;
  mode?: string;
  metadata?: Record<string, string>;
}

export interface ThreatDetail {
  type: "TEXT" | "URL" | "BEHAVIORAL" | "IMAGE";
  category: string;
  score: number;
  confidence: number;
  explanation: string;
}

export interface InspectResponse {
  requestId: string;
  threatScore: number;
  riskLevel: "MINIMAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  decision: "allow" | "flag" | "block";
  shouldBlock: boolean;
  threats: ThreatDetail[];
  processedAt: string;
  modelVersion: string;
}

export interface ThreatEvent {
  requestId: string;
  score: number;
  riskLevel: string;
  decision: string;
  threats: ThreatDetail[];
  endpoint?: string;
  sourceIp?: string;
  userId?: string;
}

// ─── Client ───────────────────────────────────────────────────────────────────

export class AntiScamClient {
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly mode: string;
  private readonly timeoutMs: number;
  private readonly onError: "allow" | "block";

  constructor(config: AntiScamConfig) {
    if (!config.apiKey) throw new Error("[AntiScamAI] apiKey is required");
    this.apiKey = config.apiKey;
    this.endpoint = (config.endpoint ?? "http://localhost:5000").replace(/\/$/, "");
    this.mode = config.mode ?? "block";
    this.timeoutMs = config.timeoutMs ?? 3000;
    this.onError = config.onError ?? "allow";
  }

  async inspect(request: InspectRequest): Promise<InspectResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    const payload: InspectRequest = { ...request, mode: this.mode };

    try {
      const res = await fetch(`${this.endpoint}/sdk/v1/inspect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-AntiScam-Key": this.apiKey,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`AntiScam AI service returned ${res.status}`);
      }

      return (await res.json()) as InspectResponse;
    } catch (err: any) {
      if (err.name === "AbortError") {
        console.warn("[AntiScamAI] Inspection timed out — falling back to:", this.onError);
      } else {
        console.warn("[AntiScamAI] Inspection failed:", err.message, "— falling back to:", this.onError);
      }

      // Fail-open or fail-closed
      return {
        requestId: "error-fallback",
        threatScore: 0,
        riskLevel: "MINIMAL",
        decision: this.onError === "block" ? "block" : "allow",
        shouldBlock: this.onError === "block",
        threats: [],
        processedAt: new Date().toISOString(),
        modelVersion: "unknown",
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Extract all http/https URLs from a string */
export function extractUrls(text: string): string[] {
  const re = /https?:\/\/[^\s"'\]\)>]+/gi;
  return [...new Set(Array.from(text.matchAll(re), (m) => m[0]))];
}

/** Deep-flatten a JSON object to human-readable text */
export function flattenToText(obj: unknown, maxDepth = 5): string {
  const parts: string[] = [];
  const walk = (val: unknown, depth: number) => {
    if (depth > maxDepth) return;
    if (typeof val === "string" && val.length > 2) parts.push(val);
    else if (Array.isArray(val)) val.forEach((v) => walk(v, depth + 1));
    else if (val && typeof val === "object")
      Object.values(val as object).forEach((v) => walk(v, depth + 1));
  };
  walk(obj, 0);
  return parts.join(" ");
}

/** Safe body reader that handles Buffer, string, and parsed objects */
export function readBody(raw: unknown): { text: string; urlsFound: string[] } {
  let text = "";
  if (typeof raw === "string") text = raw;
  else if (Buffer.isBuffer(raw)) text = raw.toString("utf-8");
  else if (raw && typeof raw === "object") text = flattenToText(raw);
  return { text, urlsFound: extractUrls(text) };
}
