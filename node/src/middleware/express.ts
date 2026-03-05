// AntiScam AI – Express middleware
import type { Request, Response, NextFunction, RequestHandler } from "express";
import { AntiScamClient, AntiScamConfig, readBody, extractUrls } from "../client.js";

export interface ExpressOptions extends AntiScamConfig {}

/**
 * Express / Connect middleware.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { antiScamExpress } from "@antiscamai/sdk/express";
 *
 * const app = express();
 * app.use(express.json());
 * app.use(antiScamExpress({ apiKey: "YOUR_KEY" }));
 * ```
 */
export function antiScamExpress(options: ExpressOptions): RequestHandler {
  const client = new AntiScamClient(options);
  const excludePaths = options.excludePaths ?? ["/health", "/metrics", "/favicon.ico"];
  const inspectMethods = (options.inspectMethods ?? ["POST", "PUT", "PATCH"]).map((m) =>
    m.toUpperCase()
  );

  return async function antiScamMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    // Skip excluded paths or methods we don't inspect
    const method = req.method?.toUpperCase() ?? "";
    if (
      excludePaths.some((p) => req.path.startsWith(p)) ||
      !inspectMethods.includes(method)
    ) {
      return next();
    }

    // Read body (body-parser must have run before this)
    const { text, urlsFound } = readBody(req.body);

    // Extract URLs from query string too
    const queryUrls = Object.values(req.query)
      .flat()
      .filter((v): v is string => typeof v === "string")
      .flatMap(extractUrls);

    // Build safe header map (skip sensitive / large headers)
    const safeHeaders: Record<string, string> = {};
    const headerAllowList = ["user-agent", "referer", "x-forwarded-for", "origin"];
    for (const h of headerAllowList) {
      if (req.headers[h]) safeHeaders[h] = String(req.headers[h]);
    }

    const inspection = await client.inspect({
      bodyText: text.slice(0, 4000), // stay within AI model limits
      extractedUrls: [...urlsFound, ...queryUrls].slice(0, 10),
      headers: safeHeaders,
      sourceIp: req.ip,
      endpoint: `${method} ${req.path}`,
      method,
      userId: (req as any).user?.id ?? (req as any).userId,
      metadata: { path: req.path },
    });

    // Attach result to request for downstream use
    (req as any).antiScam = inspection;

    // Invoke optional callback
    if (options.onThreat && inspection.threats.length > 0) {
      await options.onThreat({
        requestId: inspection.requestId,
        score: inspection.threatScore,
        riskLevel: inspection.riskLevel,
        decision: inspection.decision,
        threats: inspection.threats,
        endpoint: `${method} ${req.path}`,
        sourceIp: req.ip,
        userId: (req as any).user?.id,
      });
    }

    if (inspection.shouldBlock) {
      return res.status(403).json({
        error: "Request blocked by AntiScam AI",
        requestId: inspection.requestId,
        riskLevel: inspection.riskLevel,
        reason: inspection.threats[0]?.explanation ?? "Suspicious content detected",
      });
    }

    if (inspection.decision === "flag") {
      res.setHeader("X-AntiScam-Flag", "true");
      res.setHeader("X-AntiScam-Score", String(inspection.threatScore));
    }

    next();
  };
}
