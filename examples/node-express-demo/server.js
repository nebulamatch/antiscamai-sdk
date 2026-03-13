/**
 * AntiScam AI SDK — Node.js Validation Demo
 *
 * This is a minimal Express app that demonstrates the SDK middleware.
 * The middleware is inlined here so you don't need to npm-publish the SDK first.
 *
 * To use your real app, replace the inlined middleware with:
 *   import { antiScamExpress } from "@nebulamatch/antiscamai-sdk/express";
 */

import express from "express";

// ─── Inlined SDK middleware (same code as sdk/node/src/middleware/express.ts) ─

const URL_RE = /https?:\/\/[^\s"'\]\)>]+/gi;

function extractUrls(text) {
  return [...new Set(Array.from(text.matchAll(URL_RE), (m) => m[0]))];
}

function flattenToText(obj, depth = 0) {
  if (depth > 5) return "";
  if (typeof obj === "string" && obj.length > 2) return obj;
  if (Array.isArray(obj)) return obj.map((v) => flattenToText(v, depth + 1)).join(" ");
  if (obj && typeof obj === "object")
    return Object.values(obj).map((v) => flattenToText(v, depth + 1)).join(" ");
  return "";
}

function readBody(raw) {
  let text = "";
  if (typeof raw === "string") text = raw;
  else if (Buffer.isBuffer(raw)) text = raw.toString("utf-8");
  else if (raw && typeof raw === "object") text = flattenToText(raw);
  return { text, urlsFound: extractUrls(text) };
}

async function callGateway(payload, { endpoint, apiKey, timeoutMs, onError }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${endpoint}/sdk/v1/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-AntiScam-Key": apiKey },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`Gateway returned ${res.status}`);
    return await res.json();
  } catch (err) {
    const timedOut = err.name === "AbortError";
    console.warn(
      `[AntiScamAI] ${timedOut ? "Timeout" : "Error"}: ${err.message} — fallback: ${onError}`
    );
    const blocked = onError === "block";
    return {
      requestId: "fallback",
      threatScore: 0,
      riskLevel: "MINIMAL",
      decision: blocked ? "block" : "allow",
      shouldBlock: blocked,
      threats: [],
      processedAt: new Date().toISOString(),
      modelVersion: "unknown",
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * antiScamMiddleware(options) → Express middleware
 *
 * options:
 *   apiKey      – your SDK key (required)
 *   endpoint    – AntiScam AI gateway URL (default: http://localhost:5000)
 *   mode        – "block" | "flag" | "monitor"
 *   timeoutMs   – ms before fallback (default: 3000)
 *   onError     – "allow" | "block" when gateway unreachable
 *   excludePaths – paths to skip
 *   onThreat    – callback(result) on detection
 */
function antiScamMiddleware(options = {}) {
  const cfg = {
    apiKey: options.apiKey ?? "dev-key-change-me-in-production",
    endpoint: (options.endpoint ?? "http://localhost:5000").replace(/\/$/, ""),
    mode: options.mode ?? "block",
    timeoutMs: options.timeoutMs ?? 3000,
    onError: options.onError ?? "allow",
    excludePaths: options.excludePaths ?? ["/health", "/metrics"],
    inspectMethods: (options.inspectMethods ?? ["POST", "PUT", "PATCH"]).map((m) =>
      m.toUpperCase()
    ),
    onThreat: options.onThreat,
  };

  return async function (req, res, next) {
    const method = req.method?.toUpperCase() ?? "";

    // Skip excluded paths and non-target HTTP methods
    if (
      cfg.excludePaths.some((p) => req.path.startsWith(p)) ||
      !cfg.inspectMethods.includes(method)
    ) {
      return next();
    }

    const { text, urlsFound } = readBody(req.body);

    const safeHeaders = {};
    for (const h of ["user-agent", "referer", "x-forwarded-for", "origin"]) {
      if (req.headers[h]) safeHeaders[h] = req.headers[h];
    }

    const result = await callGateway(
      {
        bodyText: text.slice(0, 4000),
        extractedUrls: urlsFound.slice(0, 10),
        headers: safeHeaders,
        sourceIp: req.ip,
        endpoint: `${method} ${req.path}`,
        method,
        userId: req.user?.id ?? req.headers["x-user-id"],
        mode: cfg.mode,
        metadata: { path: req.path },
      },
      cfg
    );

    req.antiScam = result;

    if (cfg.onThreat && result.threats?.length > 0) {
      cfg.onThreat(result);
    }

    if (result.shouldBlock) {
      return res.status(403).json({
        error: "Request blocked by AntiScam AI",
        requestId: result.requestId,
        riskLevel: result.riskLevel,
        reason: result.threats?.[0]?.explanation ?? "Suspicious content detected",
      });
    }

    if (result.decision === "flag") {
      res.setHeader("X-AntiScam-Flag", "true");
      res.setHeader("X-AntiScam-Score", String(result.threatScore));
    }

    next();
  };
}

// ─── Express App ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Register AntiScam AI Middleware ──────────────────────────────────────────
// Change `endpoint` to wherever your AntiScam AI backend is running.
app.use(
  antiScamMiddleware({
    apiKey: process.env.ANTISCAM_API_KEY ?? "dev-key-change-me-in-production",
    endpoint: process.env.ANTISCAM_ENDPOINT ?? "http://localhost:5000",
    mode: process.env.ANTISCAM_MODE ?? "block",
    timeoutMs: 5000,
    onError: "allow",  // fail-open so demo works even if gateway is down
    onThreat: (result) => {
      console.log(
        `\n🚨  THREAT DETECTED  score=${result.threatScore}  level=${result.riskLevel}  decision=${result.decision}`
      );
      result.threats?.forEach((t) =>
        console.log(`   → [${t.type}] ${t.category}: ${t.explanation}`)
      );
    },
  })
);

// ── Health endpoint (skipped by middleware) ────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ── Contact form (common scam vector) ─────────────────────────────────────
app.post("/api/contact", (req, res) => {
  const scanResult = req.antiScam;
  res.json({
    message: "Contact form received successfully",
    antiScamResult: {
      score: scanResult?.threatScore ?? 0,
      riskLevel: scanResult?.riskLevel ?? "unknown",
      decision: scanResult?.decision ?? "unknown",
      threats: scanResult?.threats?.length ?? 0,
    },
  });
});

// ── Payment endpoint ───────────────────────────────────────────────────────
app.post("/api/payment", (req, res) => {
  const scanResult = req.antiScam;
  res.json({
    message: "Payment processed",
    antiScamResult: {
      score: scanResult?.threatScore ?? 0,
      riskLevel: scanResult?.riskLevel ?? "unknown",
      decision: scanResult?.decision ?? "unknown",
    },
  });
});

// ── Generic message endpoint ───────────────────────────────────────────────
app.post("/api/message", (req, res) => {
  const scanResult = req.antiScam;
  res.json({
    message: "Message received",
    antiScamResult: {
      score: scanResult?.threatScore ?? 0,
      riskLevel: scanResult?.riskLevel ?? "unknown",
      decision: scanResult?.decision ?? "unknown",
      threats: scanResult?.threats ?? [],
    },
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT ?? 3001;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║    AntiScam AI SDK — Node.js Validation Demo         ║
╠══════════════════════════════════════════════════════╣
║  Demo server     : http://localhost:${PORT}             ║
║  AI Gateway      : ${(process.env.ANTISCAM_ENDPOINT ?? "http://localhost:5000").padEnd(30)} ║
║  Mode            : ${(process.env.ANTISCAM_MODE ?? "block").padEnd(30)} ║
╠══════════════════════════════════════════════════════╣
║  Endpoints:                                          ║
║    GET  /health         → skip (no inspection)       ║
║    POST /api/contact    → INSPECTED                  ║
║    POST /api/payment    → INSPECTED                  ║
║    POST /api/message    → INSPECTED                  ║
╠══════════════════════════════════════════════════════╣
║  Run tests:  node test.js                            ║
╚══════════════════════════════════════════════════════╝
`);
});
