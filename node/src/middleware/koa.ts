// AntiScam AI – Koa middleware
import type { Context, Next, Middleware } from "koa";
import { AntiScamClient, AntiScamConfig, readBody, extractUrls } from "../client.js";

export interface KoaOptions extends AntiScamConfig {}

/**
 * Koa middleware for AntiScam AI request inspection.
 *
 * @example
 * ```ts
 * import Koa from "koa";
 * import bodyParser from "koa-bodyparser";
 * import { antiScamKoa } from "@antiscamai/sdk/koa";
 *
 * const app = new Koa();
 * app.use(bodyParser());
 * app.use(antiScamKoa({ apiKey: "YOUR_KEY" }));
 * ```
 */
export function antiScamKoa(options: KoaOptions): Middleware {
  const client = new AntiScamClient(options);
  const excludePaths = options.excludePaths ?? ["/health", "/metrics"];
  const inspectMethods = (options.inspectMethods ?? ["POST", "PUT", "PATCH"]).map(
    (m) => m.toUpperCase()
  );

  return async function antiScamMiddleware(ctx: Context, next: Next) {
    const method = ctx.method.toUpperCase();
    if (
      excludePaths.some((p) => ctx.path.startsWith(p)) ||
      !inspectMethods.includes(method)
    ) {
      return next();
    }

    const { text, urlsFound } = readBody((ctx.request as any).body);

    const safeHeaders: Record<string, string> = {};
    const allowList = ["user-agent", "referer", "x-forwarded-for", "origin"];
    for (const h of allowList) {
      const val = ctx.get(h);
      if (val) safeHeaders[h] = val;
    }

    const inspection = await client.inspect({
      bodyText: text.slice(0, 4000),
      extractedUrls: urlsFound.slice(0, 10),
      headers: safeHeaders,
      sourceIp: ctx.ip,
      endpoint: `${method} ${ctx.path}`,
      method,
      userId: (ctx.state as any).user?.id,
    });

    ctx.state.antiScam = inspection;

    if (options.onThreat && inspection.threats.length > 0) {
      await options.onThreat({
        requestId: inspection.requestId,
        score: inspection.threatScore,
        riskLevel: inspection.riskLevel,
        decision: inspection.decision,
        threats: inspection.threats,
        endpoint: ctx.path,
        sourceIp: ctx.ip,
      });
    }

    if (inspection.shouldBlock) {
      ctx.status = 403;
      ctx.body = {
        error: "Request blocked by AntiScam AI",
        requestId: inspection.requestId,
        riskLevel: inspection.riskLevel,
        reason: inspection.threats[0]?.explanation ?? "Suspicious content detected",
      };
      return; // do not call next()
    }

    if (inspection.decision === "flag") {
      ctx.set("X-AntiScam-Flag", "true");
      ctx.set("X-AntiScam-Score", String(inspection.threatScore));
    }

    return next();
  };
}
