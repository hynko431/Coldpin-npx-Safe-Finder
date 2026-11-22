import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { OperatorRuntimeConfig } from "../core/workflows.ts";
import { ENGINE_VERSION, type HostCapabilities } from "../types.ts";
import {
  buildProtectedResourceMetadata,
  buildProtectedResourceMetadataPath,
  buildWwwAuthenticateHeader,
  HttpBearerAuthenticator,
  PrincipalRateLimiter,
  type HttpAuthConfig,
} from "./http-auth.ts";
import { ColdpinMcpServer, loadOperatorConfigFromEnv } from "./server.ts";
import { JSONRPC_ERRORS } from "./types.ts";

const MAX_HTTP_BODY_BYTES = 1_048_576; // 1 MiB cap matching stdio framing limit
const MAX_ACTIVE_SESSIONS = 64;
const SESSION_IDLE_TTL_MS = 30 * 60 * 1000;

export interface ColdpinHttpMcpServerOptions {
  readonly bindHost?: string;
  readonly port?: number;
  readonly mcpPath?: string;
  readonly auth: HttpAuthConfig;
  readonly allowedHosts?: readonly string[];
  readonly allowedOrigins?: readonly string[];
  readonly rateLimitPerMinute?: number;
  readonly allowLoopbackInsecure?: boolean;
  readonly operatorConfig?: OperatorRuntimeConfig;
  readonly hostCapabilities?: HostCapabilities;
}

interface HttpMcpSession {
  readonly id: string;
  readonly principalHash: string;
  readonly server: ColdpinMcpServer;
  lastAccessMs: number;
}

function isLoopbackBindHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === "127.0.0.1" || h === "::1" || h === "localhost";
}

function writeJsonResponse(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Length": String(Buffer.byteLength(payload, "utf8")),
    ...extraHeaders,
  });
  res.end(payload);
}

function readCappedRequestBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; status: 413 | 400; message: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const finish = (res: { ok: true; text: string } | { ok: false; status: 413 | 400; message: string }): void => {
      if (settled) return;
      settled = true;
      resolve(res);
    };

    req.on("data", (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      total += buf.length;
      if (total > maxBytes) {
        req.pause();
        finish({ ok: false, status: 413, message: `Request body exceeds ${maxBytes} byte cap.` });
        return;
      }
      chunks.push(buf);
    });
    req.on("end", () => {
      finish({ ok: true, text: Buffer.concat(chunks, total).toString("utf8") });
    });
    req.on("error", () => {
      finish({ ok: false, status: 400, message: "Malformed HTTP request stream." });
    });
  });
}

/**
 * Opt-in Self-Hosted Enterprise Streamable HTTP MCP Adapter (`v1.6+` Phase E):
 * - Separate from default local `stdio` server (`lib/mcp.mjs` remains strictly socket-free).
 * - Enforces fail-closed OAuth 2.1 (PKCE/CIMD/RFC 9728/RFC 8707) and/or SHA-256 constant-time API key auth.
 * - Enforces anti-DNS-rebinding `Host` + `Origin` allowlists, 1 MiB body cap, per-principal rate limits,
 *   and cryptographic `Mcp-Session-Id` bound to the authenticated principal.
 */
export class ColdpinHttpMcpServer {
  private readonly bindHost: string;
  private readonly requestedPort: number;
  private readonly mcpPath: string;
  private readonly resourceUrl: string;
  private readonly resourceOrigin: string;
  private readonly metadataPath: string;
  private readonly metadataUrl: string;
  private readonly requiredScope?: string;
  private readonly allowedHostSet: Set<string>;
  private readonly allowedOriginSet: Set<string>;
  private readonly authenticator: HttpBearerAuthenticator;
  private readonly rateLimiter: PrincipalRateLimiter;
  private readonly operatorConfig: OperatorRuntimeConfig;
  private readonly hostCapabilities?: HostCapabilities;
  private readonly protectedResourceMetadata: Record<string, unknown>;
  private readonly sessions = new Map<string, HttpMcpSession>();
  private server: Server | null = null;

  constructor(opts: ColdpinHttpMcpServerOptions) {
    this.bindHost = opts.bindHost ?? "127.0.0.1";
    this.requestedPort = opts.port ?? 8787;

    let parsedResource: URL;
    try {
      parsedResource = new URL(opts.auth.resourceUrl);
    } catch {
      throw new Error(`Invalid COLDPIN_HTTP_RESOURCE_URL: '${opts.auth.resourceUrl}'.`);
    }
    const derivedPath = parsedResource.pathname.replace(/\/+$/, "");
    this.mcpPath = (opts.mcpPath ?? (derivedPath && derivedPath !== "/" ? derivedPath : "/mcp")).replace(/\/+$/, "") || "/mcp";
    if (parsedResource.protocol !== "https:") {
      const loopbackOk = Boolean(opts.allowLoopbackInsecure) && isLoopbackBindHost(this.bindHost) && isLoopbackBindHost(parsedResource.hostname);
      if (!loopbackOk) {
        throw new Error(
          "COLDPIN_HTTP_RESOURCE_URL must use https:// (plaintext http:// is permitted only on loopback with COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE=1).",
        );
      }
    }

    this.resourceUrl = opts.auth.resourceUrl;
    this.resourceOrigin = parsedResource.origin;
    this.metadataPath = buildProtectedResourceMetadataPath(this.resourceUrl);
    this.metadataUrl = `${this.resourceOrigin}${this.metadataPath}`;
    this.requiredScope = opts.auth.oauthRequiredScope ?? "coldpin:read";
    this.authenticator = new HttpBearerAuthenticator(opts.auth);
    this.rateLimiter = new PrincipalRateLimiter(opts.rateLimitPerMinute ?? 60, 60_000);
    this.operatorConfig = opts.operatorConfig ?? loadOperatorConfigFromEnv();
    this.hostCapabilities = opts.hostCapabilities;
    this.protectedResourceMetadata = buildProtectedResourceMetadata({
      resourceUrl: this.resourceUrl,
      authorizationServers: opts.auth.authorizationServers,
      requiredScope: this.requiredScope,
    });

    this.allowedHostSet = new Set<string>([parsedResource.host.toLowerCase(), parsedResource.hostname.toLowerCase()]);
    for (const h of opts.allowedHosts ?? []) {
      const trimmed = h.trim().toLowerCase();
      if (trimmed) this.allowedHostSet.add(trimmed);
    }
    if (isLoopbackBindHost(this.bindHost)) {
      this.allowedHostSet.add("127.0.0.1");
      this.allowedHostSet.add("localhost");
      this.allowedHostSet.add("[::1]");
    }

    this.allowedOriginSet = new Set<string>();
    for (const o of opts.allowedOrigins ?? []) {
      const trimmed = o.trim().toLowerCase().replace(/\/+$/, "");
      if (trimmed) this.allowedOriginSet.add(trimmed);
    }
  }

  async listen(): Promise<{ host: string; port: number; url: string }> {
    if (this.server) {
      const addr = this.server.address() as AddressInfo;
      return { host: this.bindHost, port: addr.port, url: `http://${this.bindHost}:${addr.port}${this.mcpPath}` };
    }
    const srv = createServer((req, res) => {
      void this.handleHttpRequest(req, res).catch(() => {
        if (!res.headersSent) {
          writeJsonResponse(res, 500, { error: "internal_server_error" });
        }
      });
    });
    srv.requestTimeout = 30_000;
    srv.headersTimeout = 10_000;
    this.server = srv;

    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(this.requestedPort, this.bindHost, () => {
        srv.off("error", reject);
        resolve();
      });
    });

    const addr = srv.address() as AddressInfo;
    if (isLoopbackBindHost(this.bindHost)) {
      this.allowedHostSet.add(`127.0.0.1:${addr.port}`);
      this.allowedHostSet.add(`localhost:${addr.port}`);
      this.allowedHostSet.add(`[::1]:${addr.port}`);
    }
    return { host: this.bindHost, port: addr.port, url: `http://${this.bindHost}:${addr.port}${this.mcpPath}` };
  }

  async close(): Promise<void> {
    const closingSessions = Array.from(this.sessions.values());
    this.sessions.clear();
    await Promise.all(closingSessions.map((s) => s.server.shutdown()));
    if (!this.server) return;
    const srv = this.server;
    this.server = null;
    await new Promise<void>((resolve) => {
      srv.close(() => resolve());
    });
  }

  private isAllowedHostHeader(hostHeader: string | undefined): boolean {
    if (!hostHeader) return false;
    const lower = hostHeader.trim().toLowerCase();
    if (this.allowedHostSet.has(lower)) return true;
    const hostWithoutPort = lower.startsWith("[")
      ? lower.slice(0, lower.indexOf("]") + 1)
      : lower.split(":")[0] ?? "";
    return this.allowedHostSet.has(hostWithoutPort);
  }

  private isAllowedOriginHeader(originHeader: string | undefined): boolean {
    if (!originHeader) return true; // Non-browser MCP clients omit Origin
    const norm = originHeader.trim().toLowerCase().replace(/\/+$/, "");
    return this.allowedOriginSet.has(norm);
  }

  private evictExpiredSessions(nowMs = Date.now()): void {
    for (const [sid, session] of this.sessions) {
      if (nowMs - session.lastAccessMs > SESSION_IDLE_TTL_MS) {
        this.sessions.delete(sid);
        void session.server.shutdown();
      }
    }
    while (this.sessions.size >= MAX_ACTIVE_SESSIONS) {
      let oldestId: string | null = null;
      let oldestMs = Infinity;
      for (const [sid, s] of this.sessions) {
        if (s.lastAccessMs < oldestMs) {
          oldestMs = s.lastAccessMs;
          oldestId = sid;
        }
      }
      if (!oldestId) break;
      const evicted = this.sessions.get(oldestId);
      this.sessions.delete(oldestId);
      if (evicted) void evicted.server.shutdown();
    }
  }

  private getOrCreateSession(
    requestedSessionId: string | undefined,
    principalHash: string,
    isInitialize: boolean,
  ): { ok: true; session: HttpMcpSession } | { ok: false; status: 400 | 403 | 404; message: string } {
    const nowMs = Date.now();
    this.evictExpiredSessions(nowMs);

    if (requestedSessionId) {
      const existing = this.sessions.get(requestedSessionId);
      if (!existing) {
        return { ok: false, status: 404, message: "Unknown or expired Mcp-Session-Id." };
      }
      if (existing.principalHash !== principalHash) {
        return { ok: false, status: 403, message: "Mcp-Session-Id does not belong to authenticated principal." };
      }
      existing.lastAccessMs = nowMs;
      return { ok: true, session: existing };
    }

    if (!isInitialize) {
      return { ok: false, status: 400, message: "Missing Mcp-Session-Id header; send 'initialize' first." };
    }

    const sessionId = randomBytes(24).toString("hex");
    const mcpServer = new ColdpinMcpServer({
      operatorConfig: this.operatorConfig,
      hijackProcessStdio: false,
      hostCapabilities: this.hostCapabilities,
    });
    const session: HttpMcpSession = {
      id: sessionId,
      principalHash,
      server: mcpServer,
      lastAccessMs: nowMs,
    };
    this.sessions.set(sessionId, session);
    return { ok: true, session };
  }

  private async handleHttpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = (req.method ?? "GET").toUpperCase();
    const rawUrl = req.url ?? "/";
    let pathname: string;
    try {
      pathname = new URL(rawUrl, "http://localhost").pathname.replace(/\/+$/, "") || "/";
    } catch {
      writeJsonResponse(res, 400, { error: "invalid_request_uri" });
      return;
    }

    // Anti-DNS-rebinding Host validation on ALL endpoints
    if (!this.isAllowedHostHeader(req.headers.host)) {
      writeJsonResponse(res, 403, { error: "forbidden_host", message: "Host header rejected by anti-DNS-rebinding policy." });
      return;
    }

    // RFC 9728 Protected Resource Metadata (public discovery endpoint; root AND path-inserted forms)
    if (
      method === "GET" &&
      (pathname === "/.well-known/oauth-protected-resource" || pathname === this.metadataPath)
    ) {
      writeJsonResponse(res, 200, this.protectedResourceMetadata);
      return;
    }

    if (method === "GET" && pathname === "/healthz") {
      writeJsonResponse(res, 200, { status: "ok", engine_version: ENGINE_VERSION });
      return;
    }

    if (pathname !== this.mcpPath) {
      writeJsonResponse(res, 404, { error: "not_found" });
      return;
    }

    // Cross-origin browser request guard
    const originHeader = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    if (!this.isAllowedOriginHeader(originHeader)) {
      writeJsonResponse(res, 403, { error: "forbidden_origin", message: "Origin header rejected by allowlist." });
      return;
    }

    // Fail-closed Bearer authentication (OAuth 2.1 JWT / Scoped MCP API Key)
    const authHeader = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
    const authResult = await this.authenticator.verifyAuthorizationHeader(authHeader);
    if (!authResult.ok || !authResult.principalHash) {
      const wwwAuth = buildWwwAuthenticateHeader(
        this.metadataUrl,
        authResult.errorCode,
        authResult.errorDescription,
        this.requiredScope,
      );
      writeJsonResponse(
        res,
        authResult.status,
        { error: authResult.errorCode ?? "invalid_token", error_description: authResult.errorDescription ?? "Unauthorized." },
        { "WWW-Authenticate": wwwAuth },
      );
      return;
    }

    // Per-principal rate limit
    const rate = this.rateLimiter.check(authResult.principalHash);
    if (!rate.allowed) {
      writeJsonResponse(
        res,
        429,
        { error: "rate_limited", message: "Too many MCP requests for principal; retry later." },
        { "Retry-After": String(rate.retryAfterSec) },
      );
      return;
    }

    const sessionIdHeader =
      typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"].trim() : undefined;

    if (method === "DELETE") {
      if (!sessionIdHeader) {
        writeJsonResponse(res, 400, { error: "missing_session_id" });
        return;
      }
      const existing = this.sessions.get(sessionIdHeader);
      if (!existing) {
        writeJsonResponse(res, 404, { error: "session_not_found" });
        return;
      }
      if (existing.principalHash !== authResult.principalHash) {
        writeJsonResponse(res, 403, { error: "session_principal_mismatch" });
        return;
      }
      this.sessions.delete(sessionIdHeader);
      await existing.server.shutdown();
      res.writeHead(204, { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      res.end();
      return;
    }

    if (method !== "POST") {
      writeJsonResponse(res, 405, { error: "method_not_allowed" }, { Allow: "POST, DELETE" });
      return;
    }

    const contentType = typeof req.headers["content-type"] === "string" ? req.headers["content-type"].toLowerCase() : "";
    if (!contentType.includes("application/json")) {
      writeJsonResponse(res, 415, { error: "unsupported_media_type", message: "Content-Type must be application/json." });
      return;
    }

    const bodyRes = await readCappedRequestBody(req, MAX_HTTP_BODY_BYTES);
    if (!bodyRes.ok) {
      writeJsonResponse(
        res,
        bodyRes.status,
        { error: "payload_error", message: bodyRes.message },
        bodyRes.status === 413 ? { Connection: "close" } : {},
      );
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyRes.text);
    } catch {
      writeJsonResponse(res, 400, {
        jsonrpc: "2.0",
        id: null,
        error: { code: JSONRPC_ERRORS.PARSE_ERROR, message: "Malformed JSON-RPC payload." },
      });
      return;
    }

    const isInitialize =
      Boolean(parsed) &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      (parsed as Record<string, unknown>)["method"] === "initialize";

    const sessionRes = this.getOrCreateSession(sessionIdHeader, authResult.principalHash, isInitialize);
    if (!sessionRes.ok) {
      writeJsonResponse(res, sessionRes.status, { error: "session_error", message: sessionRes.message });
      return;
    }

    const rpcReply = await sessionRes.session.server.dispatchJsonRpc(parsed);
    if (rpcReply === null) {
      res.writeHead(202, {
        "Mcp-Session-Id": sessionRes.session.id,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      res.end();
      return;
    }

    writeJsonResponse(res, 200, rpcReply, { "Mcp-Session-Id": sessionRes.session.id });
  }
}
