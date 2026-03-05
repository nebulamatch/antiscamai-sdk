// AntiScam AI – Fastify plugin
import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from "fastify";
import fp from "fastify-plugin";
import { AntiScamClient, AntiScamConfig, readBody, extractUrls } from "../client.js";

declare module "fastify" {
  interface FastifyRequest {
    antiScam?: import("../client.js").InspectResponse;
  }
}

export interface FastifyOptions extends AntiScamConfig {}

/**
 * Fastify plugin for AntiScam AI request inspection.
 *
 * @example
 * ```ts
 * import Fastify from "fastify";
 * import antiScamFastify from "@antiscamai/sdk/fastify";
 *
 * const app = Fastify();
 * await app.register(antiScamFastify, { apiKey: "YOUR_KEY" });
 * ```
 */
const antiScamFastifyPlugin: FastifyPluginAsync<FastifyOptions> = async (
  fastify,
  options
) => {
  const client = new AntiScamClient(options);
  const excludePaths = options.excludePaths ?? ["/health", "/metrics"];
  const inspectMethods = (options.inspectMethods ?? ["POST", "PUT", "PATCH"]).map(
    (m) => m.toUpperCase()
  );

  fastify.addHook(
    "preHandler",
    async (request: FastifyRequest, reply: FastifyReply) => {
      const method = request.method.toUpperCase();
      if (
        excludePaths.some((p) => request.url.startsWith(p)) ||
        !inspectMethods.includes(method)
      ) {
        return;
      }

      const { text, urlsFound } = readBody(request.body);

      const safeHeaders: Record<string, string> = {};
      const allowList = ["user-agent", "referer", "x-forwarded-for", "origin"];
      for (const h of allowList) {
        if (request.headers[h]) safeHeaders[h] = String(request.headers[h]);
      }

      const inspection = await client.inspect({
        bodyText: text.slice(0, 4000),
        extractedUrls: urlsFound.slice(0, 10),
        headers: safeHeaders,
        sourceIp: request.ip,
        endpoint: `${method} ${request.routerPath ?? request.url}`,
        method,
        userId: (request as any).user?.id,
      });

      request.antiScam = inspection;

      if (options.onThreat && inspection.threats.length > 0) {
        await options.onThreat({
          requestId: inspection.requestId,
          score: inspection.threatScore,
          riskLevel: inspection.riskLevel,
          decision: inspection.decision,
          threats: inspection.threats,
          endpoint: request.url,
          sourceIp: request.ip,
        });
      }

      if (inspection.shouldBlock) {
        return reply.code(403).send({
          error: "Request blocked by AntiScam AI",
          requestId: inspection.requestId,
          riskLevel: inspection.riskLevel,
          reason: inspection.threats[0]?.explanation ?? "Suspicious content detected",
        });
      }

      if (inspection.decision === "flag") {
        reply.header("X-AntiScam-Flag", "true");
        reply.header("X-AntiScam-Score", String(inspection.threatScore));
      }
    }
  );
};

export default fp(antiScamFastifyPlugin, {
  name: "@antiscamai/sdk-fastify",
  fastify: ">=4.0.0",
});
