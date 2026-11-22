#!/usr/bin/env node
import { sanitizeOperatorEnvValue } from "./config/policy.mjs";
                                                       
import { ColdpinHttpMcpServer } from "./mcp/http-server.mjs";
import { loadOperatorConfigFromEnv } from "./mcp/server.mjs";

function checkMinimumNodeVersion()       {
  const major = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  if (!Number.isFinite(major) || major < 24) {
    process.stderr.write(`Coldpin HTTP MCP requires Node.js >= 24.0.0; detected v${process.versions.node}\n`);
    process.exit(1);
  }
}

function splitCsvEnv(raw                    )           {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => sanitizeOperatorEnvValue(s))
    .filter((s)              => Boolean(s));
}

function isTruthy(raw                    )          {
  if (!raw) return false;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

async function main()                {
  checkMinimumNodeVersion();
  const env = process.env;
  const bindHost = sanitizeOperatorEnvValue(env["COLDPIN_HTTP_HOST"]) ?? "127.0.0.1";
  const port = Number.parseInt(sanitizeOperatorEnvValue(env["COLDPIN_HTTP_PORT"]) ?? "8787", 10);
  const resourceUrl = sanitizeOperatorEnvValue(env["COLDPIN_HTTP_RESOURCE_URL"]);
  const authMode = sanitizeOperatorEnvValue(env["COLDPIN_HTTP_AUTH_MODE"])                            ;
  if (!resourceUrl || !authMode) {
    process.stderr.write(
      "ERROR: Coldpin HTTP MCP adapter fails closed without COLDPIN_HTTP_RESOURCE_URL and COLDPIN_HTTP_AUTH_MODE (oauth | api_key | both).\n",
    );
    process.exit(1);
  }

  const oauthIssuer = sanitizeOperatorEnvValue(env["COLDPIN_OAUTH_ISSUER"]);
  const authServers = splitCsvEnv(env["COLDPIN_OAUTH_AUTH_SERVERS"]);
  if (authServers.length === 0 && oauthIssuer) authServers.push(oauthIssuer);

  const server = new ColdpinHttpMcpServer({
    bindHost,
    port: Number.isFinite(port) && port >= 0 && port <= 65535 ? port : 8787,
    allowLoopbackInsecure: isTruthy(env["COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE"]),
    allowedHosts: splitCsvEnv(env["COLDPIN_HTTP_ALLOWED_HOSTS"]),
    allowedOrigins: splitCsvEnv(env["COLDPIN_HTTP_ALLOWED_ORIGINS"]),
    rateLimitPerMinute: Number.parseInt(sanitizeOperatorEnvValue(env["COLDPIN_HTTP_RATE_LIMIT_PER_MIN"]) ?? "60", 10) || 60,
    operatorConfig: loadOperatorConfigFromEnv(env),
    auth: {
      mode: authMode,
      resourceUrl,
      authorizationServers: authServers,
      oauthIssuer,
      oauthRequiredScope: sanitizeOperatorEnvValue(env["COLDPIN_OAUTH_REQUIRED_SCOPE"]) ?? "coldpin:read",
      jwksPath: sanitizeOperatorEnvValue(env["COLDPIN_OAUTH_JWKS_PATH"]),
      jwksUrl: sanitizeOperatorEnvValue(env["COLDPIN_OAUTH_JWKS_URL"]),
      apiKeySha256List: splitCsvEnv(env["COLDPIN_MCP_API_KEY_SHA256"]),
      allowLoopbackJwksHttp: isTruthy(env["COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE"]),
    },
  });

  const info = await server.listen();
  process.stderr.write(
    `${JSON.stringify({ event: "coldpin_http_mcp_started", bind: `${info.host}:${info.port}`, resource: resourceUrl, auth_mode: authMode })}\n`,
  );

  const shutdown = ()       => {
    void server.close().finally(() => process.exit(0));
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

main().catch((err) => {
  process.stderr.write(`Coldpin HTTP MCP startup failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});


//# sourceURL=mcp-http.ts
