import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify,                                 } from "node:crypto";
import { readFileSync } from "node:fs";
import { sanitizeOperatorEnvValue } from "../config/policy.mjs";
import { fetchJwksJson } from "../intel/registry-osv.mjs";

                                                        

                                                  
               
               
               
              
 

                               
                       
 

                                 
                              
                               
                                                   
                                
                                       
                             
                            
                                     
                                               
                                 
                                           
 

                                         
                       
                                   
                                                              
                                     
                                                
                                  
                            
 

const ALLOWED_JWT_ALGS = new Set(["RS256", "ES256"]);
const MIN_API_KEY_LENGTH = 32;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const JWKS_MIN_REFRESH_INTERVAL_MS = 10_000;

function sha256Hex(input        )         {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function decodeBase64UrlToBuffer(segment        )         {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new Error("Invalid base64url segment");
  }
  const padded = segment + "=".repeat((4 - (segment.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function parseJsonObject(buf        )                          {
  const parsed          = JSON.parse(buf.toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Expected JSON object");
  }
  return parsed                           ;
}

export function buildProtectedResourceMetadata(config   
                      
                                          
                         
 )                          {
  return {
    resource: config.resourceUrl,
    authorization_servers: [...config.authorizationServers],
    scopes_supported: config.requiredScope ? [config.requiredScope] : ["coldpin:read"],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://coldpin-docs.pages.dev/",
  };
}

export function buildProtectedResourceMetadataPath(resourceUrl        )         {
  const u = new URL(resourceUrl);
  const cleanPath = u.pathname.replace(/\/+$/, "");
  if (!cleanPath || cleanPath === "/") {
    return "/.well-known/oauth-protected-resource";
  }
  return `/.well-known/oauth-protected-resource${cleanPath}`;
}

export function buildWwwAuthenticateHeader(
  metadataUrl        ,
  errorCode                                         ,
  errorDescription         ,
  requiredScope         ,
)         {
  const esc = (s        )         => s.replace(/["\\\r\n]/g, "");
  const parts = [`Bearer realm="coldpin"`, `resource_metadata="${esc(metadataUrl)}"`];
  if (errorCode) parts.push(`error="${esc(errorCode)}"`);
  if (errorDescription) parts.push(`error_description="${esc(errorDescription)}"`);
  if (errorCode === "insufficient_scope" && requiredScope) {
    parts.push(`scope="${esc(requiredScope)}"`);
  }
  return parts.join(", ");
}

export function verifyApiKeyConstantTime(
  presentedToken        ,
  allowedSha256HexList                   ,
)                                          {
  const sanitized = sanitizeOperatorEnvValue(presentedToken);
  if (!sanitized || sanitized.length < MIN_API_KEY_LENGTH || allowedSha256HexList.length === 0) {
    return { ok: false };
  }
  const presentedDigest = createHash("sha256").update(sanitized, "utf8").digest();
  let matched = false;
  for (const hex of allowedSha256HexList) {
    if (!SHA256_HEX_RE.test(hex)) continue;
    const expectedDigest = Buffer.from(hex.toLowerCase(), "hex");
    if (expectedDigest.length === presentedDigest.length && timingSafeEqual(presentedDigest, expectedDigest)) {
      matched = true;
    }
  }
  if (!matched) return { ok: false };
  return { ok: true, principalHash: `apikey_${presentedDigest.toString("hex").slice(0, 16)}` };
}

function hasRequiredScope(claims                         , requiredScope        )          {
  const scopeStr = claims["scope"];
  if (typeof scopeStr === "string") {
    const tokens = scopeStr.split(/\s+/).filter(Boolean);
    if (tokens.includes(requiredScope)) return true;
  }
  const scp = claims["scp"];
  if (Array.isArray(scp) && scp.some((s) => s === requiredScope)) {
    return true;
  }
  return false;
}

function audienceMatches(audClaim         , expectedResourceUrl        )          {
  const normalize = (s        )         => s.replace(/\/+$/, "");
  const expected = normalize(expectedResourceUrl);
  if (typeof audClaim === "string") {
    return normalize(audClaim) === expected;
  }
  if (Array.isArray(audClaim)) {
    return audClaim.some((item) => typeof item === "string" && normalize(item) === expected);
  }
  return false;
}

function jwkMatchesAlgorithm(jwk              , alg                   )          {
  if (jwk.use && jwk.use !== "sig") return false;
  if (jwk.alg && jwk.alg !== alg) return false;
  if (alg === "RS256") return jwk.kty === "RSA";
  if (alg === "ES256") return jwk.kty === "EC" && (!jwk.crv || jwk.crv === "P-256");
  return false;
}

export class HttpBearerAuthenticator {
                   config                ;
          cachedJwks                      = null;
          cachedAtMs = 0;
          lastRefreshAttemptMs = 0;

  constructor(config                ) {
    if (config.mode !== "oauth" && config.mode !== "api_key" && config.mode !== "both") {
      throw new Error(`Invalid COLDPIN_HTTP_AUTH_MODE: '${String(config.mode)}'.`);
    }
    if (config.mode === "api_key" || config.mode === "both") {
      const validHashes = config.apiKeySha256List.filter((h) => SHA256_HEX_RE.test(h));
      if (validHashes.length === 0) {
        throw new Error("HTTP auth mode requires at least one valid 64-hex SHA-256 hash in COLDPIN_MCP_API_KEY_SHA256.");
      }
    }
    if (config.mode === "oauth" || config.mode === "both") {
      if (!config.oauthIssuer) {
        throw new Error("OAuth HTTP auth mode requires COLDPIN_OAUTH_ISSUER.");
      }
      if (!config.staticJwks && !config.jwksPath && !config.jwksUrl) {
        throw new Error("OAuth HTTP auth mode requires COLDPIN_OAUTH_JWKS_PATH or COLDPIN_OAUTH_JWKS_URL.");
      }
      if (config.authorizationServers.length === 0) {
        throw new Error("OAuth HTTP auth mode requires at least one authorization server URL.");
      }
    }
    this.config = config;
    if (config.staticJwks) {
      this.cachedJwks = config.staticJwks;
      this.cachedAtMs = Date.now();
    }
  }

          async loadJwks(forceRefresh = false)                               {
    if (this.config.staticJwks) return this.config.staticJwks;
    const now = Date.now();
    if (!forceRefresh && this.cachedJwks && now - this.cachedAtMs < JWKS_CACHE_TTL_MS) {
      return this.cachedJwks;
    }
    if (this.config.jwksPath) {
      const raw = readFileSync(this.config.jwksPath, "utf8");
      const parsed = JSON.parse(raw)                ;
      if (!parsed || !Array.isArray(parsed.keys)) {
        throw new Error("Invalid JWKS document at COLDPIN_OAUTH_JWKS_PATH.");
      }
      this.cachedJwks = parsed;
      this.cachedAtMs = now;
      return parsed;
    }
    if (this.config.jwksUrl) {
      if (forceRefresh && now - this.lastRefreshAttemptMs < JWKS_MIN_REFRESH_INTERVAL_MS && this.cachedJwks) {
        return this.cachedJwks;
      }
      this.lastRefreshAttemptMs = now;
      const res = await fetchJwksJson(this.config.jwksUrl, {
        allowLoopbackHttp: this.config.allowLoopbackJwksHttp,
      });
      if (!res.ok || !res.jwks) {
        return this.cachedJwks;
      }
      this.cachedJwks = res.jwks                           ;
      this.cachedAtMs = now;
      return this.cachedJwks;
    }
    return null;
  }

  async verifyAuthorizationHeader(authHeader                    )                                  {
    if (!authHeader || typeof authHeader !== "string") {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "Missing Authorization Bearer header." };
    }
    const match = /^Bearer\s+([^\s]+)$/i.exec(authHeader.trim());
    if (!match?.[1]) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "Malformed Authorization Bearer header." };
    }
    const token = match[1];

    // Check API key mode first if token is not a 3-segment JWT (or if api_key-only mode)
    const isJwtShape = token.split(".").length === 3;
    if (this.config.mode === "api_key" || (this.config.mode === "both" && !isJwtShape)) {
      const keyRes = verifyApiKeyConstantTime(token, this.config.apiKeySha256List);
      if (keyRes.ok) {
        return { ok: true, status: 200, authMethod: "api_key", principalHash: keyRes.principalHash };
      }
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "Invalid MCP API key." };
    }

    if (this.config.mode === "oauth" || this.config.mode === "both") {
      const jwtRes = await this.verifyOAuthJwt(token);
      if (jwtRes.ok) return jwtRes;
      if (this.config.mode === "both" && jwtRes.status === 401) {
        const fallbackKey = verifyApiKeyConstantTime(token, this.config.apiKeySha256List);
        if (fallbackKey.ok) {
          return { ok: true, status: 200, authMethod: "api_key", principalHash: fallbackKey.principalHash };
        }
      }
      return jwtRes;
    }

    return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "Authentication failed." };
  }

          async verifyOAuthJwt(token        )                                  {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "JWT must have 3 segments." };
    }
    let header                         ;
    let payload                         ;
    let sigBuf        ;
    try {
      header = parseJsonObject(decodeBase64UrlToBuffer(parts[0] ));
      payload = parseJsonObject(decodeBase64UrlToBuffer(parts[1] ));
      sigBuf = decodeBase64UrlToBuffer(parts[2] );
    } catch {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "Malformed JWT encoding." };
    }

    const alg = typeof header["alg"] === "string" ? header["alg"] : "";
    if (!ALLOWED_JWT_ALGS.has(alg)) {
      return {
        ok: false,
        status: 401,
        errorCode: "invalid_token",
        errorDescription: `Unsupported or disallowed JWT algorithm '${alg}'.`,
      };
    }
    const kid = typeof header["kid"] === "string" ? header["kid"] : undefined;

    let jwks = await this.loadJwks(false);
    let candidates = (jwks?.keys ?? []).filter((k) => jwkMatchesAlgorithm(k, alg                     ) && (!kid || k.kid === kid));
    if (candidates.length === 0 && kid) {
      jwks = await this.loadJwks(true);
      candidates = (jwks?.keys ?? []).filter((k) => jwkMatchesAlgorithm(k, alg                     ) && k.kid === kid);
    }
    if (candidates.length === 0) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "No matching signing key in pinned JWKS." };
    }

    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
    let sigValid = false;
    for (const jwk of candidates) {
      try {
        const keyObj            = createPublicKey({ key: jwk              , format: "jwk" });
        const ok = cryptoVerify(
          "sha256",
          signingInput,
          alg === "ES256" ? { key: keyObj, dsaEncoding: "ieee-p1363" } : keyObj,
          sigBuf,
        );
        if (ok) {
          sigValid = true;
          break;
        }
      } catch {
        // Continue checking remaining matching candidates
      }
    }
    if (!sigValid) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "JWT signature verification failed." };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const skew = Math.min(Math.max(this.config.clockSkewSec ?? 30, 0), 120);
    const exp = payload["exp"];
    if (typeof exp !== "number" || !Number.isFinite(exp) || nowSec - skew >= exp) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "JWT missing valid exp or expired." };
    }
    const nbf = payload["nbf"];
    if (nbf !== undefined && (typeof nbf !== "number" || !Number.isFinite(nbf) || nowSec + skew < nbf)) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "JWT not yet valid (nbf)." };
    }

    const iss = typeof payload["iss"] === "string" ? payload["iss"].replace(/\/+$/, "") : "";
    const expectedIss = (this.config.oauthIssuer ?? "").replace(/\/+$/, "");
    if (!iss || iss !== expectedIss) {
      return { ok: false, status: 401, errorCode: "invalid_token", errorDescription: "JWT issuer (iss) mismatch." };
    }

    // RFC 8707 Resource Indicator audience validation
    if (!audienceMatches(payload["aud"], this.config.resourceUrl)) {
      return {
        ok: false,
        status: 401,
        errorCode: "invalid_token",
        errorDescription: "JWT audience (aud) does not match protected MCP resource URI (RFC 8707).",
      };
    }

    const requiredScope = this.config.oauthRequiredScope ?? "coldpin:read";
    if (requiredScope && !hasRequiredScope(payload, requiredScope)) {
      return {
        ok: false,
        status: 403,
        errorCode: "insufficient_scope",
        errorDescription: `Missing required scope '${requiredScope}'.`,
      };
    }

    const sub = typeof payload["sub"] === "string" && payload["sub"].trim() ? payload["sub"].trim() : "unknown";
    return {
      ok: true,
      status: 200,
      authMethod: "oauth_jwt",
      subject: sub,
      principalHash: `oauth_${sha256Hex(`${iss}|${sub}`).slice(0, 16)}`,
    };
  }
}

export class PrincipalRateLimiter {
                   maxRequests        ;
                   windowMs        ;
                   buckets = new Map                                              ();

  constructor(maxRequests = 60, windowMs = 60_000) {
    this.maxRequests = Math.max(1, maxRequests);
    this.windowMs = Math.max(1000, windowMs);
  }

  check(principalKey        , nowMs = Date.now())                                              {
    if (this.buckets.size > 4096) {
      for (const [k, v] of this.buckets) {
        if (v.resetAtMs <= nowMs) this.buckets.delete(k);
      }
      if (this.buckets.size > 4096) {
        const oldest = this.buckets.keys().next().value;
        if (oldest !== undefined) this.buckets.delete(oldest);
      }
    }
    const existing = this.buckets.get(principalKey);
    if (!existing || existing.resetAtMs <= nowMs) {
      this.buckets.set(principalKey, { count: 1, resetAtMs: nowMs + this.windowMs });
      return { allowed: true, retryAfterSec: 0 };
    }
    if (existing.count >= this.maxRequests) {
      return {
        allowed: false,
        retryAfterSec: Math.max(1, Math.ceil((existing.resetAtMs - nowMs) / 1000)),
      };
    }
    existing.count++;
    return { allowed: true, retryAfterSec: 0 };
  }
}


//# sourceURL=mcp/http-auth.ts
