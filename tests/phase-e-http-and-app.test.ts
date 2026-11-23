import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fetchJwksJson } from "../src/intel/registry-osv.ts";
import {
  EVIDENCE_CARD_UI_META,
  EVIDENCE_CARD_UI_MIME,
  EVIDENCE_CARD_UI_URI,
  renderEvidenceCardAppHtml,
} from "../src/mcp/evidence-card-app.ts";
import {
  HttpBearerAuthenticator,
  verifyApiKeyConstantTime,
  type JwksDocument,
  type JwksKeyEntry,
} from "../src/mcp/http-auth.ts";
import { ColdpinHttpMcpServer } from "../src/mcp/http-server.ts";
import { ColdpinMcpServer, loadOperatorConfigFromEnv } from "../src/mcp/server.ts";
import { computeMcpSchemaPin, MCP_RESOURCES, MCP_TOOLS } from "../src/mcp/tool-catalog.ts";

function b64url(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function signTestJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: KeyObject | string,
  alg: "RS256" | "ES256" | "HS256" | "none",
): string {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const signingInput = Buffer.from(`${h}.${p}`, "ascii");
  if (alg === "none") {
    return `${h}.${p}.`;
  }
  if (alg === "HS256") {
    const mac = createHmac("sha256", typeof privateKey === "string" ? privateKey : "secret").update(signingInput).digest();
    return `${h}.${p}.${b64url(mac)}`;
  }
  const sig = cryptoSign(
    "sha256",
    signingInput,
    alg === "ES256" ? { key: privateKey as KeyObject, dsaEncoding: "ieee-p1363" } : (privateKey as KeyObject),
  );
  return `${h}.${p}.${b64url(sig)}`;
}

function rawHttpRequest(opts: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
}): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; text: string }> {
  return new Promise((resolveReq, rejectReq) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port: opts.port,
        method: opts.method,
        path: opts.path,
        headers: opts.headers ?? {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (d: Buffer) => chunks.push(d));
        res.on("end", () => {
          resolveReq({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", rejectReq);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

describe("Phase E (v1.6+): Zero-Dep MCP App, Self-Hosted Streamable HTTP MCP Adapter & Scheduled Sidecar Template", () => {
  it("E2: exposes ui://coldpin/evidence-card.html with default-deny CSP, strict DOM-only rendering, UI capability echo, and <=1,800 tools/list tokens", async () => {
    // 1. Catalog metadata and token budget check
    const uiRes = MCP_RESOURCES.find((r) => r.uri === EVIDENCE_CARD_UI_URI);
    assert.ok(uiRes, "Missing ui://coldpin/evidence-card.html resource in MCP_RESOURCES");
    assert.equal(uiRes.mimeType, EVIDENCE_CARD_UI_MIME);
    assert.deepEqual(uiRes._meta, EVIDENCE_CARD_UI_META);

    const linkedTools = MCP_TOOLS.filter(
      (t) => ((t._meta as { ui?: { resourceUri?: string } } | undefined)?.ui?.resourceUri) === EVIDENCE_CARD_UI_URI,
    ).map((t) => t.name);
    assert.deepEqual(linkedTools.sort(), [
      "audit_manifest_batch",
      "inspect_package_artifact",
      "resolve_safe_anchor",
      "verify_confusion",
    ]);

    const pin = computeMcpSchemaPin();
    assert.ok(pin.estimated_tokens <= 1800, `tools/list token budget exceeded: ${pin.estimated_tokens} > 1800`);

    // 2. HTML self-containment & zero-injection security invariants
    const html = renderEvidenceCardAppHtml();
    assert.ok(html.startsWith("<!DOCTYPE html>"));
    assert.ok(html.includes("default-src 'none'"));
    assert.ok(html.includes("ui/initialize"));
    assert.ok(html.includes("ui/notifications/tool-result"));
    assert.ok(html.includes("ui/notifications/host-context-changed"));
    assert.ok(html.includes("get_artifact_report"));
    assert.ok(html.includes("--color-background-primary"));
    assert.ok(html.includes("Copy Command"));
    assert.equal(/\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function)\b/.test(html), false);
    assert.equal(/<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)\s*=\s*["']https?:\/\//i.test(html), false);

    // 3. MCP initialize negotiates io.modelcontextprotocol/ui & resources/read serves HTML + _meta
    const srv = new ColdpinMcpServer({
      operatorConfig: loadOperatorConfigFromEnv({ COLDPIN_CACHE_DIR: ":memory:", COLDPIN_OFFLINE: "1" }),
      hijackProcessStdio: false,
      hostCapabilities: {
        node_version: process.version,
        git_available: true,
        git_partial_clone_supported: true,
        rea_cli_available: false,
        sqlite_available: true,
      },
    });
    try {
      const initReply = await srv.dispatchJsonRpc({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {
            extensions: {
              "io.modelcontextprotocol/ui": { mimeTypes: [EVIDENCE_CARD_UI_MIME] },
            },
          },
          clientInfo: { name: "antigravity-app", version: "2.34.0" },
        },
      });
      const caps = (initReply?.result as { capabilities: { extensions?: Record<string, unknown> } }).capabilities;
      assert.deepEqual(caps.extensions, {
        "io.modelcontextprotocol/ui": { mimeTypes: [EVIDENCE_CARD_UI_MIME] },
      });

      const listRes = await srv.dispatchJsonRpc({ jsonrpc: "2.0", id: 2, method: "resources/list" });
      const resList = (listRes?.result as { resources: Array<{ uri: string }> }).resources;
      assert.equal(resList.length, 2);
      assert.ok(resList.some((r) => r.uri === EVIDENCE_CARD_UI_URI));

      const readRes = await srv.dispatchJsonRpc({
        jsonrpc: "2.0",
        id: 3,
        method: "resources/read",
        params: { uri: EVIDENCE_CARD_UI_URI },
      });
      const content = ((readRes?.result as { contents: Array<{ uri: string; mimeType: string; text: string; _meta: unknown }> }).contents[0])!;
      assert.equal(content.uri, EVIDENCE_CARD_UI_URI);
      assert.equal(content.mimeType, EVIDENCE_CARD_UI_MIME);
      assert.deepEqual(content._meta, EVIDENCE_CARD_UI_META);
      assert.ok(content.text.includes("Coldpin Evidence Card"));
    } finally {
      await srv.shutdown();
    }
  });

  it("E1: enforces fail-closed OAuth 2.1 (RS256/ES256, RFC 9728, RFC 8707 aud, scope, live JWKS), constant-time API keys, Host/Origin guards, 1 MiB cap, rate limit, and session isolation", async () => {
    const rsaPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const ecPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const rsaJwk = { ...(rsaPair.publicKey.export({ format: "jwk" }) as JwksKeyEntry), kid: "rsa-1", use: "sig", alg: "RS256" };
    const ecJwk = { ...(ecPair.publicKey.export({ format: "jwk" }) as JwksKeyEntry), kid: "ec-1", use: "sig", alg: "ES256" };
    const jwksDoc: JwksDocument = { keys: [rsaJwk, ecJwk] };

    // Live loopback JWKS server to verify fetchJwksJson integration
    const jwksSrv = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(jwksDoc));
    });
    await new Promise<void>((r) => jwksSrv.listen(0, "127.0.0.1", () => r()));
    const jwksPort = (jwksSrv.address() as AddressInfo).port;
    const jwksUrl = `http://127.0.0.1:${jwksPort}/jwks.json`;

    // Direct fetchJwksJson SSRF & loopback checks
    const jwksLiveRes = await fetchJwksJson(jwksUrl, { allowLoopbackHttp: true });
    assert.equal(jwksLiveRes.ok, true);
    assert.equal(jwksLiveRes.jwks?.keys.length, 2);
    const jwksBlockedLoopback = await fetchJwksJson(jwksUrl, { allowLoopbackHttp: false });
    assert.equal(jwksBlockedLoopback.ok, false);
    const jwksBlockedImds = await fetchJwksJson("http://169.254.169.254/latest/meta-data", { allowLoopbackHttp: true });
    assert.equal(jwksBlockedImds.ok, false);

    const apiKeyA = "cpk_live_0123456789abcdef0123456789abcdef";
    const apiKeyB = "cpk_live_fedcba9876543210fedcba9876543210";
    const apiKeyASha = createHash("sha256").update(apiKeyA, "utf8").digest("hex");
    const apiKeyBSha = createHash("sha256").update(apiKeyB, "utf8").digest("hex");

    // 1. Fail-closed constructor checks
    assert.throws(
      () =>
        new ColdpinHttpMcpServer({
          bindHost: "127.0.0.1",
          port: 0,
          allowLoopbackInsecure: false,
          auth: {
            mode: "api_key",
            resourceUrl: "http://127.0.0.1/mcp",
            authorizationServers: [],
            apiKeySha256List: [apiKeyASha],
          },
        }),
      /must use https:\/\//i,
    );
    assert.throws(
      () =>
        new HttpBearerAuthenticator({
          mode: "oauth",
          resourceUrl: "https://coldpin.acme.internal/mcp",
          authorizationServers: ["https://idp.acme.internal"],
          apiKeySha256List: [],
        }),
      /COLDPIN_OAUTH_ISSUER/i,
    );
    assert.throws(
      () =>
        new HttpBearerAuthenticator({
          mode: "api_key",
          resourceUrl: "https://coldpin.acme.internal/mcp",
          authorizationServers: [],
          apiKeySha256List: ["not-a-valid-sha256"],
        }),
      /SHA-256/i,
    );

    // 2. Reject short (<32 char) and placeholder API keys
    assert.equal(verifyApiKeyConstantTime("cpk_live_short", [apiKeyASha]).ok, false);
    assert.equal(verifyApiKeyConstantTime("${COLDPIN_MCP_API_KEY}", [apiKeyASha]).ok, false);
    assert.equal(verifyApiKeyConstantTime(apiKeyA, [apiKeyASha]).ok, true);

    // 3. Boot ephemeral Streamable HTTP MCP server in `both` mode (OAuth + API key)
    const resourceUrl = "https://coldpin.acme.internal/mcp";
    const issuer = "https://idp.acme.internal";
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-http-"));
    writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "http-ws", version: "1.0.0", dependencies: {} }));

    const httpMcp = new ColdpinHttpMcpServer({
      bindHost: "127.0.0.1",
      port: 0,
      allowedOrigins: ["https://console.acme.internal"],
      rateLimitPerMinute: 25,
      operatorConfig: loadOperatorConfigFromEnv({
        COLDPIN_ALLOWED_ROOTS: tmpDir,
        COLDPIN_CACHE_DIR: ":memory:",
        COLDPIN_OFFLINE: "1",
      }),
      hostCapabilities: {
        node_version: process.version,
        git_available: true,
        git_partial_clone_supported: true,
        rea_cli_available: false,
        sqlite_available: true,
      },
      auth: {
        mode: "both",
        resourceUrl,
        authorizationServers: [issuer],
        oauthIssuer: issuer,
        oauthRequiredScope: "coldpin:read",
        jwksUrl,
        allowLoopbackJwksHttp: true,
        apiKeySha256List: [apiKeyASha, apiKeyBSha],
      },
    });

    try {
      const bound = await httpMcp.listen();
      const port = bound.port;
      const nowSec = Math.floor(Date.now() / 1000);

      // 3a. RFC 9728 Protected Resource Metadata discovery (root AND path-inserted, public without auth)
      for (const metaPath of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
        const metaRes = await rawHttpRequest({ port, method: "GET", path: metaPath });
        assert.equal(metaRes.status, 200);
        const metaDoc = JSON.parse(metaRes.text) as { resource: string; authorization_servers: string[]; scopes_supported: string[] };
        assert.equal(metaDoc.resource, resourceUrl);
        assert.deepEqual(metaDoc.authorization_servers, [issuer]);
        assert.deepEqual(metaDoc.scopes_supported, ["coldpin:read"]);
      }

      // 3b. Anti-DNS-rebinding Host header guard -> 403
      const badHost = await rawHttpRequest({
        port,
        method: "GET",
        path: "/healthz",
        headers: { Host: "evil.attacker.example" },
      });
      assert.equal(badHost.status, 403);

      // 3c. Unlisted Origin guard -> 403
      const badOrigin = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: {
          Origin: "https://evil.example",
          Authorization: `Bearer ${apiKeyA}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      });
      assert.equal(badOrigin.status, 403);

      // 3d. Missing Bearer -> 401 + RFC 9728 WWW-Authenticate header
      const unauth = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      assert.equal(unauth.status, 401);
      const wwwAuth = String(unauth.headers["www-authenticate"] ?? "");
      assert.ok(wwwAuth.includes('resource_metadata="https://coldpin.acme.internal/.well-known/oauth-protected-resource/mcp"'));

      // 3e. JWT cryptographic attack matrix (RS256 & ES256 valid vs alg:none, HS256, tampered sig, expired, future nbf, wrong iss, wrong RFC 8707 aud, missing scope)
      const validRsaJwt = signTestJwt(
        { alg: "RS256", typ: "JWT", kid: "rsa-1" },
        { iss: issuer, sub: "alice", aud: resourceUrl, scope: "coldpin:read", exp: nowSec + 300, nbf: nowSec - 10 },
        rsaPair.privateKey,
        "RS256",
      );
      const validEcJwt = signTestJwt(
        { alg: "ES256", typ: "JWT", kid: "ec-1" },
        { iss: issuer, sub: "bob", aud: [resourceUrl, "https://other.internal"], scp: ["coldpin:read"], exp: nowSec + 300 },
        ecPair.privateKey,
        "ES256",
      );
      const algNoneJwt = signTestJwt(
        { alg: "none", typ: "JWT" },
        { iss: issuer, sub: "mallory", aud: resourceUrl, scope: "coldpin:read", exp: nowSec + 300 },
        "",
        "none",
      );
      const hs256Jwt = signTestJwt(
        { alg: "HS256", typ: "JWT", kid: "rsa-1" },
        { iss: issuer, sub: "mallory", aud: resourceUrl, scope: "coldpin:read", exp: nowSec + 300 },
        "hmac-secret",
        "HS256",
      );
      const tamperedJwt = `${validRsaJwt.slice(0, -4)}${validRsaJwt.endsWith("AAAA") ? "BBBB" : "AAAA"}`;
      const expiredJwt = signTestJwt(
        { alg: "RS256", kid: "rsa-1" },
        { iss: issuer, sub: "alice", aud: resourceUrl, scope: "coldpin:read", exp: nowSec - 120 },
        rsaPair.privateKey,
        "RS256",
      );
      const futureNbfJwt = signTestJwt(
        { alg: "RS256", kid: "rsa-1" },
        { iss: issuer, sub: "alice", aud: resourceUrl, scope: "coldpin:read", exp: nowSec + 600, nbf: nowSec + 300 },
        rsaPair.privateKey,
        "RS256",
      );
      const wrongIssJwt = signTestJwt(
        { alg: "RS256", kid: "rsa-1" },
        { iss: "https://rogue-idp.example", sub: "alice", aud: resourceUrl, scope: "coldpin:read", exp: nowSec + 300 },
        rsaPair.privateKey,
        "RS256",
      );
      const wrongAudJwt = signTestJwt(
        { alg: "RS256", kid: "rsa-1" },
        { iss: issuer, sub: "alice", aud: "https://different-api.acme.internal/mcp", scope: "coldpin:read", exp: nowSec + 300 },
        rsaPair.privateKey,
        "RS256",
      );
      const missingScopeJwt = signTestJwt(
        { alg: "RS256", kid: "rsa-1" },
        { iss: issuer, sub: "alice", aud: resourceUrl, scope: "profile", exp: nowSec + 300 },
        rsaPair.privateKey,
        "RS256",
      );

      for (const [label, tok, expectedStatus] of [
        ["alg:none", algNoneJwt, 401],
        ["HS256", hs256Jwt, 401],
        ["tampered", tamperedJwt, 401],
        ["expired", expiredJwt, 401],
        ["future nbf", futureNbfJwt, 401],
        ["wrong iss", wrongIssJwt, 401],
        ["wrong aud", wrongAudJwt, 401],
        ["missing scope", missingScopeJwt, 403],
      ] as const) {
        const resp = await rawHttpRequest({
          port,
          method: "POST",
          path: "/mcp",
          headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } }),
        });
        assert.equal(resp.status, expectedStatus, `Expected ${expectedStatus} for ${label}, got ${resp.status}: ${resp.text}`);
        if (expectedStatus === 403) {
          assert.ok(String(resp.headers["www-authenticate"] ?? "").includes('error="insufficient_scope"'));
        }
      }

      // 3f. Valid RS256 OAuth session flow: initialize -> Mcp-Session-Id -> tools/list -> resources/read -> cross-principal hijack 403 -> DELETE 204
      const initResp = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: {
          Authorization: `Bearer ${validRsaJwt}`,
          Origin: "https://console.acme.internal",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: { extensions: { "io.modelcontextprotocol/ui": { mimeTypes: [EVIDENCE_CARD_UI_MIME] } } },
            clientInfo: { name: "antigravity-remote" },
          },
        }),
      });
      assert.equal(initResp.status, 200);
      const sessionId = String(initResp.headers["mcp-session-id"] ?? "");
      assert.match(sessionId, /^[a-f0-9]{48}$/);

      // Notification -> 202 Accepted
      const notifResp = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: {
          Authorization: `Bearer ${validRsaJwt}`,
          "Mcp-Session-Id": sessionId,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
      assert.equal(notifResp.status, 202);

      // Same principal -> tools/list succeeds (7 tools)
      const listResp = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: {
          Authorization: `Bearer ${validRsaJwt}`,
          "Mcp-Session-Id": sessionId,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      });
      assert.equal(listResp.status, 200);
      const listJson = JSON.parse(listResp.text) as { result: { tools: unknown[] } };
      assert.equal(listJson.result.tools.length, 7);

      // Different principal (ES256 Bob) attempting to hijack Alice's Mcp-Session-Id -> 403!
      const hijackResp = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: {
          Authorization: `Bearer ${validEcJwt}`,
          "Mcp-Session-Id": sessionId,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list" }),
      });
      assert.equal(hijackResp.status, 403);

      // ES256 Bob starts own session cleanly -> 200
      const bobInit = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: { Authorization: `Bearer ${validEcJwt}`, "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } }),
      });
      assert.equal(bobInit.status, 200);

      // API Key A starts own session & executes verify_confusion cleanly
      const keyInit = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: { Authorization: `Bearer ${apiKeyA}`, "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } }),
      });
      assert.equal(keyInit.status, 200);
      const keySid = String(keyInit.headers["mcp-session-id"] ?? "");

      const confCall = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: { Authorization: `Bearer ${apiKeyA}`, "Mcp-Session-Id": keySid, "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "verify_confusion", arguments: {} } }),
      });
      assert.equal(confCall.status, 200);
      const confParsed = JSON.parse(confCall.text) as { result: { isError: boolean; structuredContent: { passed: boolean } } };
      assert.equal(confParsed.result.isError, false);
      assert.equal(confParsed.result.structuredContent.passed, true);

      // Oversized > 1 MiB body -> 413 Payload Too Large
      const hugePayload = Buffer.alloc(1_048_576 + 1024, 0x61);
      const tooBigResp = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: { Authorization: `Bearer ${apiKeyB}`, "Content-Type": "application/json" },
        body: hugePayload,
      });
      assert.equal(tooBigResp.status, 413);

      // DELETE session -> 204, subsequent reuse -> 404
      const delResp = await rawHttpRequest({
        port,
        method: "DELETE",
        path: "/mcp",
        headers: { Authorization: `Bearer ${validRsaJwt}`, "Mcp-Session-Id": sessionId },
      });
      assert.equal(delResp.status, 204);
      const afterDel = await rawHttpRequest({
        port,
        method: "POST",
        path: "/mcp",
        headers: { Authorization: `Bearer ${validRsaJwt}`, "Mcp-Session-Id": sessionId, "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping" }),
      });
      assert.equal(afterDel.status, 404);
    } finally {
      await httpMcp.close();
      jwksSrv.close();
      rmSync(tmpDir, { recursive: true, force: true });
    }

    // 4. Dedicated tight rate-limit test (2 req/min -> 3rd returns 429 + Retry-After)
    const rlSrv = new ColdpinHttpMcpServer({
      bindHost: "127.0.0.1",
      port: 0,
      rateLimitPerMinute: 2,
      operatorConfig: loadOperatorConfigFromEnv({ COLDPIN_CACHE_DIR: ":memory:", COLDPIN_OFFLINE: "1" }),
      auth: {
        mode: "api_key",
        resourceUrl,
        authorizationServers: [],
        apiKeySha256List: [apiKeyASha],
      },
    });
    try {
      const { port } = await rlSrv.listen();
      const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });
      const r1 = await rawHttpRequest({ port, method: "POST", path: "/mcp", headers: { Authorization: `Bearer ${apiKeyA}`, "Content-Type": "application/json" }, body });
      const r2 = await rawHttpRequest({ port, method: "POST", path: "/mcp", headers: { Authorization: `Bearer ${apiKeyA}`, "Content-Type": "application/json" }, body });
      const r3 = await rawHttpRequest({ port, method: "POST", path: "/mcp", headers: { Authorization: `Bearer ${apiKeyA}`, "Content-Type": "application/json" }, body });
      assert.equal(r1.status, 200);
      assert.equal(r2.status, 200);
      assert.equal(r3.status, 429);
      assert.ok(Number(r3.headers["retry-after"]) >= 1);
    } finally {
      await rlSrv.close();
    }

    // 5. Compiled lib/mcp-http.mjs fails closed with exit code 1 when auth env is missing
    const cliCheck = spawnSync(process.execPath, ["--no-warnings", resolve("lib/mcp-http.mjs")], {
      env: { PATH: process.env["PATH"] ?? "" },
      encoding: "utf8",
      timeout: 5000,
      windowsHide: true,
    });
    assert.equal(cliCheck.status, 1);
    assert.match(cliCheck.stderr, /fails closed/i);
  });

  it("E3: validates disabled-by-default scheduled sidecar template, remote HTTP config template, and zero active sidecars/ at plugin root", () => {
    // Plugin root MUST NOT ship an active sidecars/ directory (opt-in only!)
    assert.equal(existsSync(resolve("sidecars")), false);

    // Sidecar template structure & strictly read-only Coldpin MCP grants
    const sidecarPath = resolve("examples/sidecar.weekly-audit.example.json");
    assert.ok(existsSync(sidecarPath));
    const sc = JSON.parse(readFileSync(sidecarPath, "utf8")) as {
      display_name: string;
      builtin: string;
      restart_policy: string;
      args: string[];
      arguments: Array<{ key: string; workspace_arg?: Record<string, unknown> }>;
      agent_permissions: { workspace_uris: string[]; access_grants: string[] };
    };
    assert.equal(sc.builtin, "schedule");
    assert.equal(sc.restart_policy, "always");
    assert.ok(sc.args.includes("agentapi") && sc.args.includes("new-conversation"));
    assert.ok(sc.arguments.some((a) => a.key === "workspace_dir" && a.workspace_arg !== undefined));
    assert.ok(sc.agent_permissions.access_grants.length >= 2);
    for (const grant of sc.agent_permissions.access_grants) {
      assert.ok(grant.startsWith("mcp(coldpin_coldpin/"), `Unexpected non-Coldpin grant: ${grant}`);
      assert.equal(/command\(|write_file|edit_file|run_command/.test(grant), false);
    }

    // Remote HTTP example config covers OAuth CIMD, API Key (with sensitive variable), and Cloud Run ADC
    const httpCfg = JSON.parse(readFileSync(resolve("examples/mcp_config.http-remote.example.json"), "utf8")) as {
      mcpServers: Record<string, { serverUrl?: string; authProviderType?: string; headers?: Record<string, string>; variables?: Array<{ name: string; sensitive?: boolean; required?: boolean }> }>;
    };
    assert.equal(httpCfg.mcpServers["coldpin-oauth-cimd"]?.serverUrl, "https://coldpin.acme.internal/mcp");
    assert.equal(httpCfg.mcpServers["coldpin-cloud-run-adc"]?.authProviderType, "google_credentials");
    assert.equal(httpCfg.mcpServers["coldpin-api-key"]?.headers?.["Authorization"], "Bearer ${COLDPIN_MCP_API_KEY}");
    assert.equal(httpCfg.mcpServers["coldpin-api-key"]?.variables?.[0]?.sensitive, true);
    assert.equal(httpCfg.mcpServers["coldpin-api-key"]?.variables?.[0]?.required, false);

    // Default root mcp_config.json stays strictly local stdio-only (zero serverUrl)
    const rootMcp = JSON.parse(readFileSync(resolve("mcp_config.json"), "utf8")) as {
      mcpServers: Record<string, Record<string, unknown>>;
    };
    for (const srv of Object.values(rootMcp.mcpServers)) {
      assert.equal("serverUrl" in srv, false);
      assert.equal("url" in srv, false);
      assert.equal(srv["command"], "node");
    }
  });
});
