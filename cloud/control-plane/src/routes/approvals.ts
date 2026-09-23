import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { gateways } from "../db/schema";
import { authenticate, requireScope } from "../middleware/auth";
import { writeAudit } from "../audit";
import { eq } from "drizzle-orm";

// Approvals live on the gateways, not the control plane. These routes
// fan out over the org's enrolled gateways using the same push credential
// the policy distributor uses (OVARA_GATEWAY_API_KEY) and merge the
// results so an operator sees every pending approval in one place.
const GATEWAY_API_KEY = process.env.OVARA_GATEWAY_API_KEY ?? "";
const GATEWAY_TIMEOUT_MS = 5000;

function validateEndpoint(endpoint: string, allowInsecure: boolean): void {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error(`Invalid gateway endpoint_url: ${endpoint}`);
  }
  if (url.protocol !== "https:" && !allowInsecure) {
    throw new Error(
      `Gateway endpoint_url must use https (got ${url.protocol}); set allow_insecure to override`
    );
  }
}

async function callGateway(
  endpoint: string,
  path: string,
  init?: RequestInit
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GATEWAY_TIMEOUT_MS);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (GATEWAY_API_KEY) headers["Authorization"] = `Bearer ${GATEWAY_API_KEY}`;
  try {
    return await fetch(`${endpoint.replace(/\/$/, "")}${path}`, {
      ...init,
      headers: { ...headers, ...(init?.headers as Record<string, string>) },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

export function approvalRoutes(app: FastifyInstance) {
  // Aggregated approval list across every org gateway with an endpoint_url.
  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const orgGateways = await db.query.gateways.findMany({
      where: eq(gateways.organizationId, auth.organizationId),
    });

    const results = await Promise.all(
      orgGateways
        .filter((gw) => gw.endpointUrl)
        .map(async (gw) => {
          try {
            validateEndpoint(gw.endpointUrl!, gw.allowInsecure);
            const res = await callGateway(gw.endpointUrl!, "/v1/approvals");
            if (!res.ok) {
              return {
                gatewayId: gw.id,
                gatewayName: gw.name,
                approvals: [],
                error: `gateway returned ${res.status}`,
              };
            }
            const body = (await res.json()) as { approvals?: unknown[]; count?: number };
            return {
              gatewayId: gw.id,
              gatewayName: gw.name,
              approvals: body.approvals ?? [],
              error: null,
            };
          } catch (err) {
            return {
              gatewayId: gw.id,
              gatewayName: gw.name,
              approvals: [],
              error: err instanceof Error ? err.message : "unreachable",
            };
          }
        })
    );

    return reply.send({
      gateways: results,
      total: results.reduce((n, r) => n + r.approvals.length, 0),
    });
  });

  // Proxy approve/deny to the owning gateway. Resolution is a security
  // authority action — admin scope only.
  for (const action of ["approve", "deny"] as const) {
    app.post(`/:gatewayId/:approvalId/${action}`, {
      preHandler: [authenticate, requireScope("admin")],
    }, async (request: FastifyRequest, reply: FastifyReply) => {
      const auth = await authenticate(request);
      const { gatewayId, approvalId } = request.params as {
        gatewayId: string;
        approvalId: string;
      };
      const body = (request.body ?? {}) as { resolved_by?: string; reason?: string };

      const gw = await db.query.gateways.findFirst({
        where: eq(gateways.id, gatewayId),
      });
      if (!gw || gw.organizationId !== auth.organizationId) {
        return reply.status(404).send({ error: "gateway not found" });
      }
      if (!gw.endpointUrl) {
        return reply.status(422).send({ error: "gateway has no endpoint_url configured" });
      }
      try {
        validateEndpoint(gw.endpointUrl, gw.allowInsecure);
      } catch (err) {
        return reply.status(422).send({ error: (err as Error).message });
      }

      let res: Response;
      try {
        res = await callGateway(
          gw.endpointUrl,
          `/v1/approval/${encodeURIComponent(approvalId)}/${action}`,
          {
            method: "POST",
            body: JSON.stringify({
              resolved_by: body.resolved_by ?? `apikey:${auth.keyId}`,
              reason: body.reason,
            }),
          }
        );
      } catch (err) {
        return reply.status(502).send({
          error: `gateway unreachable: ${(err as Error).message}`,
        });
      }

      const text = await res.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
      if (res.ok) {
        await writeAudit(auth, request, `approval.${action}`, "approval", approvalId, {
          gatewayId,
        });
      }
      return reply.status(res.status).send(parsed);
    });
  }
}
