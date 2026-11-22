import { createHash, createPublicKey, verify as cryptoVerify, X509Certificate } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { existsSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { SingleFlight,                      } from "../cache/sqlite-store.mjs";
import {
  isPublicNpmRegistryUrl,
  loadNpmrc,
  routeDiscoveryQuery,
                   
} from "../config/policy.mjs";
import { openReadCappedFile, redactHomePath } from "../core/path-confinement.mjs";
import {
  ENGINE_VERSION,
                      
                        
                       
                          
                         
                   
                       
                    
                        
                
} from "../types.mjs";
import { sanitizeUntrustedText } from "../analysis/static-triage.mjs";
import { evaluateSlopsquatAndCooldown } from "../discovery/slopsquat-guard.mjs";

const USER_AGENT = `coldpin/${ENGINE_VERSION}`;
const osvDetailFlight = new SingleFlight                                     ();
const versionMetaFlight = new SingleFlight  
              
                                 
                               
                 
  ();
const tarballFlight = new SingleFlight                                                  ();
const MAX_PACKUMENT_JSON_BYTES = 25 * 1024 * 1024;
const MAX_SMALL_JSON_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

function hashAuthScope(token         )         {
  return createHash("sha256").update(token ?? "anon").digest("hex").slice(0, 16);
}

const BLOCKED_METADATA_HOSTS = new Set([
  "169.254.169.254",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.goog",
  "fd00:ec2::254",
]);
const MAX_REDIRECT_HOPS = 5;

function decodeMappedIpv4(host        )                {
  if (!host.startsWith("::ffff:")) return null;
  const mapped = host.slice("::ffff:".length);
  if (mapped.includes(".")) return mapped;
  const parts = mapped.split(":");
  if (parts.length !== 2) return null;
  const hi = Number.parseInt(parts[0] , 16);
  const lo = Number.parseInt(parts[1] , 16);
  if (!Number.isFinite(hi) || !Number.isFinite(lo)) return null;
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

function parseIpv4Octets(ip        )                                          {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => (/^\d+$/.test(p) ? Number(p) : -1));
  if (nums.some((n) => n < 0 || n > 255)) return null;
  return [nums[0] , nums[1] , nums[2] , nums[3] ];
}

export function isPrivateOrReservedIpv4(ip        )          {
  const oct = parseIpv4Octets(ip);
  if (!oct) return false;
  const [a, b] = oct;
  if (a === 0) return true; // 0.0.0.0/8 unspecified
  if (a === 10) return true; // 10.0.0.0/8 RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / IMDS
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
  return false;
}

function isMetadataOrLinkLocalHost(rawHost        )          {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_METADATA_HOSTS.has(host) || host.startsWith("169.254.")) return true;
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true;
  const mappedV4 = decodeMappedIpv4(host);
  if (mappedV4) {
    return BLOCKED_METADATA_HOSTS.has(mappedV4) || mappedV4.startsWith("169.254.");
  }
  return false;
}

function isLoopbackHost(rawHost        )          {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.startsWith("127.") ||
    host.startsWith("0.") ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "::" ||
    host === "0:0:0:0:0:0:0:1" ||
    host === "0:0:0:0:0:0:0:0"
  ) {
    return true;
  }
  const mappedV4 = decodeMappedIpv4(host);
  return Boolean(mappedV4 && (mappedV4.startsWith("127.") || mappedV4.startsWith("0.")));
}

export function isPrivateOrReservedIp(rawHost        )          {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (isMetadataOrLinkLocalHost(host) || isLoopbackHost(host)) return true;
  if (isPrivateOrReservedIpv4(host)) return true;
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // IPv6 ULA fc00::/7
  const mappedV4 = decodeMappedIpv4(host);
  if (mappedV4 && isPrivateOrReservedIpv4(mappedV4)) return true;
  return false;
}

function isPublicOsvUrl(rawUrl        )          {
  try {
    return new URL(rawUrl).hostname.toLowerCase() === "api.osv.dev";
  } catch {
    return true;
  }
}

export function validateOutboundUrl(
  rawUrl        ,
  allowPlainHttpForExplicitOrigin         ,
  allowedPrivateOrigin         ,
)                                                {
  let parsed     ;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, error: `Malformed URL: ${rawUrl}` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: "Rejected outbound URL containing embedded credentials/userinfo." };
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (isMetadataOrLinkLocalHost(host)) {
    return { ok: false, error: `Blocked link-local/cloud metadata host '${host}' (SSRF defense).` };
  }
  const matchesExplicitHttp = Boolean(allowPlainHttpForExplicitOrigin && parsed.origin === allowPlainHttpForExplicitOrigin);
  const matchesExplicitPrivate =
    matchesExplicitHttp || Boolean(allowedPrivateOrigin && parsed.origin === allowedPrivateOrigin);

  if (isLoopbackHost(host) && !matchesExplicitPrivate) {
    return { ok: false, error: `Blocked loopback/unspecified host '${host}' (SSRF defense).` };
  }
  if (isIP(host) !== 0 && isPrivateOrReservedIp(host) && !matchesExplicitPrivate) {
    return { ok: false, error: `Blocked private/reserved IP host '${host}' (SSRF defense).` };
  }
  if (parsed.protocol === "https:") {
    return { ok: true, parsed };
  }
  if (parsed.protocol === "http:" && matchesExplicitHttp) {
    return { ok: true, parsed };
  }
  return {
    ok: false,
    error: `Rejected non-HTTPS outbound URL '${parsed.protocol}//${parsed.host}'.`,
  };
}

async function verifyDnsNotSsrf(
  host        ,
  allowPrivateTarget         ,
)                                           {
  if (isIP(host) !== 0) return { ok: true };
  try {
    const records = await dnsLookup(host, { all: true });
    for (const rec of records) {
      if (isMetadataOrLinkLocalHost(rec.address)) {
        return { ok: false, error: `DNS resolved '${host}' to blocked metadata/link-local address '${rec.address}'.` };
      }
      if (!allowPrivateTarget && isPrivateOrReservedIp(rec.address)) {
        return { ok: false, error: `DNS resolved '${host}' to blocked private/reserved address '${rec.address}'.` };
      }
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `DNS lookup failed for '${host}': ${err instanceof Error ? err.message : String(err)}` };
  }
}

export async function readResponseBytesCapped(
  res          ,
  maxBytes        ,
  label        ,
)                                                                       {
  const contentLen = Number.parseInt(res.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(contentLen) && contentLen > maxBytes) {
    return { ok: false, error: `${label} content-length (${contentLen}) exceeded limit (${maxBytes} bytes)` };
  }
  if (!res.body) return { ok: false, error: `Empty ${label} response body` };
  const chunks           = [];
  let total = 0;
  const reader = res.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { ok: false, error: `${label} response exceeded limit (${maxBytes} bytes)` };
      }
      chunks.push(Buffer.from(value));
    }
  }
  return { ok: true, buffer: Buffer.concat(chunks, total) };
}

export async function fetchWithSafeRedirects(params   
              
                          
                
                                  
                     
                             
                                
                                
                      
 )                                                                {
  const method = params.method ?? "GET";
  let currentUrl = params.url;
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    const check = validateOutboundUrl(currentUrl, params.allowPlainHttpOrigin, params.allowedPrivateOrigin);
    if (!check.ok || !check.parsed) {
      return { ok: false, error: check.error };
    }
    const host = check.parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    const allowPrivateTarget =
      Boolean(params.allowPlainHttpOrigin && check.parsed.origin === params.allowPlainHttpOrigin) ||
      Boolean(params.allowedPrivateOrigin && check.parsed.origin === params.allowedPrivateOrigin);
    const dnsCheck = await verifyDnsNotSsrf(host, allowPrivateTarget);
    if (!dnsCheck.ok) {
      return { ok: false, error: dnsCheck.error };
    }

    const reqHeaders                         = { connection: "close" };
    // Strip sensitive credential headers case-insensitively before setting origin-scoped HTTPS-only auth (CWE-200)
    for (const [k, v] of Object.entries(params.headers)) {
      const kl = k.toLowerCase();
      if (kl === "authorization" || kl === "proxy-authorization" || kl === "cookie") continue;
      reqHeaders[k] = v;
    }
    // Security [MCP-09]: strictly require HTTPS + exact origin match before attaching Bearer token
    if (
      params.authToken &&
      params.allowedAuthOrigin &&
      check.parsed.protocol === "https:" &&
      check.parsed.origin === params.allowedAuthOrigin
    ) {
      reqHeaders["authorization"] = `Bearer ${params.authToken}`;
    }

    const res = await fetch(currentUrl, {
      method,
      headers: reqHeaders,
      ...(method === "POST" && params.body !== undefined ? { body: params.body } : {}),
      redirect: "manual",
      signal: params.signal,
    });

    if (res.status >= 300 && res.status < 400) {
      if (method === "POST") {
        return { ok: false, error: `Refused HTTP ${res.status} redirect on POST request.` };
      }
      const location = res.headers.get("location");
      if (!location) return { ok: false, error: `Redirect HTTP ${res.status} without Location header` };
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return { ok: false, error: "Invalid redirect Location URL" };
      }
      continue;
    }

    return { ok: true, response: res };
  }
  return { ok: false, error: `Exceeded max redirect hops (${MAX_REDIRECT_HOPS})` };
}

                                          
               
                  
                      
                     
                    
                          
                                
                               
                                      
                          
                        
                      
                  
                  
                      
                     
                                  
                                       
                                                
                      
 

                                   
               
                         
                      
                        
                    
                          
                        
                       
                      
                                 
                                        
                            
                                         
                                                  
     
                                       
 

                                             
                           
                          
                               
                          
                      
                       
                         
                                 
                              
                     
 

function encodePkgName(name        )         {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

function extractLicense(raw         )         {
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  if (raw && typeof raw === "object" && "type" in raw && typeof (raw                      ).type === "string") {
    return (raw                    ).type;
  }
  return "UNKNOWN";
}

function extractCreator(raw         )         {
  if (typeof raw === "string" && raw.trim()) return sanitizeUntrustedText(raw, 80);
  if (raw && typeof raw === "object" && "name" in raw && typeof (raw                      ).name === "string") {
    return sanitizeUntrustedText((raw                    ).name, 80);
  }
  return "unknown";
}

function extractRepo(raw         )                                       {
  if (typeof raw === "string") return { url: raw };
  if (raw && typeof raw === "object") {
    const obj = raw                                          ;
    return {
      url: typeof obj.url === "string" ? obj.url : undefined,
      directory: typeof obj.directory === "string" ? obj.directory : undefined,
    };
  }
  return {};
}

function extractBinNames(pkgName        , rawBin         )           {
  if (typeof rawBin === "string") {
    const bare = pkgName.includes("/") ? pkgName.slice(pkgName.indexOf("/") + 1) : pkgName;
    return [bare];
  }
  if (rawBin && typeof rawBin === "object" && !Array.isArray(rawBin)) {
    return Object.keys(rawBin                           );
  }
  return [];
}

function extractProvenanceUrl(versionObj                         )                     {
  const dist = versionObj["dist"];
  if (!dist || typeof dist !== "object") return undefined;
  const attestations = (dist                           )["attestations"];
  if (!attestations || typeof attestations !== "object") return undefined;
  const url = (attestations                           )["url"];
  return typeof url === "string" && url.trim().length > 0 ? url.trim() : undefined;
}

function sriOrHexToSha512Hex(raw        )                {
  const trimmed = raw.trim();
  if (trimmed.startsWith("sha512-")) {
    const buf = Buffer.from(trimmed.slice("sha512-".length), "base64");
    return buf.length === 64 ? buf.toString("hex").toLowerCase() : null;
  }
  if (/^[0-9a-f]{128}$/i.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return null;
}

function parseNpmPurl(subjectName        )                                            {
  if (!subjectName.startsWith("pkg:npm/")) return null;
  let rest = subjectName.slice("pkg:npm/".length);
  const qIdx = rest.indexOf("?");
  if (qIdx !== -1) rest = rest.slice(0, qIdx);
  const hIdx = rest.indexOf("#");
  if (hIdx !== -1) rest = rest.slice(0, hIdx);
  if (!rest) return null;

  const atIdx = rest.lastIndexOf("@");
  const rawName = atIdx > 0 ? rest.slice(0, atIdx) : rest;
  const rawVersion = atIdx > 0 ? rest.slice(atIdx + 1) : undefined;
  let decodedName        ;
  try {
    decodedName = decodeURIComponent(rawName);
  } catch {
    decodedName = rawName.replace(/^%40/i, "@").replace(/%2f/gi, "/");
  }
  if (!decodedName) return null;
  let decodedVersion                    ;
  if (rawVersion && rawVersion.length > 0) {
    try {
      decodedVersion = decodeURIComponent(rawVersion);
    } catch {
      decodedVersion = rawVersion;
    }
  }
  return { name: decodedName, ...(decodedVersion ? { version: decodedVersion } : {}) };
}

function dssePae(payloadType        , payloadBytes        )         {
  const ptBuf = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${ptBuf.length} `, "utf8"),
    ptBuf,
    Buffer.from(` ${payloadBytes.length} `, "utf8"),
    payloadBytes,
  ]);
}

/**
 * Locally inspects an npm Sigstore/SLSA attestation document against the downloaded tarball SHA-512.
 * Epistemic boundary:
 * - Verifies in-toto Statement subject SHA-512 + npm PURL package/version identity binding and verifies
 *   the DSSE signature against the bundled leaf X.509 certificate (or explicit publicKeyPem).
 * - NEVER sets `provenance_attested: true` without Sigstore Fulcio CA chain + Rekor TUF root
 *   verification; returns `dsse_leaf_verified_unanchored` with an explicit trust-root unknown instead.
 * - Flags tampered subject digests, mismatched package/version PURLs, or invalid DSSE signatures as CRITICAL.
 */
export function verifyNpmAttestationPayload(
  doc         ,
  expectedTarballSha512        ,
  expectedPackageName         ,
  provenanceUrl         ,
  expectedPackageVersion         ,
)                             {
  const observations                = [];
  const unknowns           = [];
  const expectedHex = sriOrHexToSha512Hex(expectedTarballSha512);
  if (!expectedHex) {
    unknowns.push("PROVENANCE_CRYPTO_UNVERIFIED: could not normalize expected tarball SHA-512 for attestation comparison.");
    return { status: "metadata_url_only", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  let slsaBundle                                 = null;
  let declaredPredicateType                    ;

  if (doc && typeof doc === "object") {
    const obj = doc                           ;
    if (Array.isArray(obj["attestations"])) {
      for (const item of obj["attestations"]) {
        if (!item || typeof item !== "object") continue;
        const rec = item                           ;
        const pt = typeof rec["predicateType"] === "string" ? rec["predicateType"] : "";
        if (pt.startsWith("https://slsa.dev/provenance/") && rec["bundle"] && typeof rec["bundle"] === "object") {
          slsaBundle = rec["bundle"]                           ;
          declaredPredicateType = pt;
          break;
        }
      }
    } else if (obj["dsseEnvelope"] && typeof obj["dsseEnvelope"] === "object") {
      slsaBundle = obj;
    }
  }

  if (!slsaBundle) {
    unknowns.push(
      "PROVENANCE_CRYPTO_UNVERIFIED: registry attestation endpoint returned no SLSA provenance bundle; Sigstore/SLSA provenance is NOT verified.",
    );
    return { status: "metadata_url_only", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const envelope = slsaBundle["dsseEnvelope"];
  if (!envelope || typeof envelope !== "object") {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "npm SLSA attestation bundle is missing a valid dsseEnvelope.",
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const envObj = envelope                           ;
  const payloadType = typeof envObj["payloadType"] === "string" ? envObj["payloadType"] : "";
  const payloadB64 = typeof envObj["payload"] === "string" ? envObj["payload"] : "";
  const signatures = Array.isArray(envObj["signatures"]) ? (envObj["signatures"]                                  ) : [];
  const sigEntries = signatures
    .map((s) => (s && typeof s === "object" && typeof s["sig"] === "string" ? String(s["sig"]).trim() : ""))
    .filter((s) => s.length > 0);

  if (payloadType !== "application/vnd.in-toto+json" || !payloadB64 || sigEntries.length === 0) {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: `Invalid or incomplete DSSE envelope (payloadType='${sanitizeUntrustedText(payloadType, 64)}').`,
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const payloadBytes = Buffer.from(payloadB64, "base64");
  let statement                         ;
  try {
    const parsed          = JSON.parse(payloadBytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Statement is not a JSON object");
    }
    statement = parsed                           ;
  } catch {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "Failed to parse base64-encoded in-toto Statement JSON inside DSSE envelope.",
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const stmtType = typeof statement["_type"] === "string" ? statement["_type"] : "";
  const stmtPredicateType = typeof statement["predicateType"] === "string" ? statement["predicateType"] : declaredPredicateType;
  if (
    (stmtType !== "https://in-toto.io/Statement/v1" && stmtType !== "https://in-toto.io/Statement/v0.1") ||
    !stmtPredicateType?.startsWith("https://slsa.dev/provenance/")
  ) {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: `Unexpected in-toto statement _type ('${sanitizeUntrustedText(stmtType, 48)}') or predicateType ('${sanitizeUntrustedText(stmtPredicateType ?? "", 64)}').`,
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const subjects = Array.isArray(statement["subject"]) ? (statement["subject"]                                  ) : [];
  const matchedSubject = subjects.find((s) => {
    const dig = s?.["digest"];
    if (!dig || typeof dig !== "object") return false;
    const sha512 = (dig                           )["sha512"];
    return typeof sha512 === "string" && sha512.toLowerCase() === expectedHex;
  });

  if (!matchedSubject) {
    observations.push({
      code: "PROVENANCE_DIGEST_MISMATCH",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "SLSA attestation subject SHA-512 does not match the verified tarball digest.",
    });
    return {
      status: "verification_failed",
      provenance_url: provenanceUrl,
      provenance_attested: false,
      predicate_type: stmtPredicateType,
      observations,
      unknowns,
    };
  }

  if (expectedPackageName) {
    const rawSubName = typeof matchedSubject["name"] === "string" ? matchedSubject["name"].trim() : "";
    const parsedPurl = rawSubName ? parseNpmPurl(rawSubName) : null;
    if (!parsedPurl) {
      observations.push({
        code: "PROVENANCE_DIGEST_MISMATCH",
        severity: "CRITICAL",
        path: "<attestation>",
        attack_id: "T1195.002",
        detail: `SLSA attestation subject name '${sanitizeUntrustedText(rawSubName || "<missing>", 80)}' is not a valid npm PURL for inspected package '${sanitizeUntrustedText(expectedPackageName, 80)}'.`,
      });
      return {
        status: "verification_failed",
        provenance_url: provenanceUrl,
        provenance_attested: false,
        predicate_type: stmtPredicateType,
        observations,
        unknowns,
      };
    }
    if (parsedPurl.name.toLowerCase() !== expectedPackageName.toLowerCase()) {
      observations.push({
        code: "PROVENANCE_DIGEST_MISMATCH",
        severity: "CRITICAL",
        path: "<attestation>",
        attack_id: "T1195.002",
        detail: `SLSA attestation subject package '${sanitizeUntrustedText(parsedPurl.name, 80)}' does not match inspected package '${sanitizeUntrustedText(expectedPackageName, 80)}'.`,
      });
      return {
        status: "verification_failed",
        provenance_url: provenanceUrl,
        provenance_attested: false,
        predicate_type: stmtPredicateType,
        observations,
        unknowns,
      };
    }
    if (expectedPackageVersion && parsedPurl.version && parsedPurl.version !== expectedPackageVersion) {
      observations.push({
        code: "PROVENANCE_DIGEST_MISMATCH",
        severity: "CRITICAL",
        path: "<attestation>",
        attack_id: "T1195.002",
        detail: `SLSA attestation subject version '${sanitizeUntrustedText(parsedPurl.version, 48)}' does not match inspected version '${sanitizeUntrustedText(expectedPackageVersion, 48)}'.`,
      });
      return {
        status: "verification_failed",
        provenance_url: provenanceUrl,
        provenance_attested: false,
        predicate_type: stmtPredicateType,
        observations,
        unknowns,
      };
    }
  }

  // Extract optional SLSA v1 / v0.2 metadata for transparency
  const pred = (statement["predicate"] && typeof statement["predicate"] === "object"
    ? (statement["predicate"]                           )
    : {})                           ;
  const runDetails = pred["runDetails"]                                       ;
  const builderObj = (runDetails?.["builder"] ?? pred["builder"])                                       ;
  const builderId = typeof builderObj?.["id"] === "string" ? sanitizeUntrustedText(builderObj["id"], 120) : undefined;
  const buildDef = pred["buildDefinition"]                                       ;
  const extParams = buildDef?.["externalParameters"]                                       ;
  const workflow = extParams?.["workflow"]                                       ;
  const invocation = pred["invocation"]                                       ;
  const configSource = invocation?.["configSource"]                                       ;
  const sourceRepoRaw =
    typeof workflow?.["repository"] === "string"
      ? workflow["repository"]
      : typeof configSource?.["uri"] === "string"
        ? configSource["uri"]
        : undefined;
  const sourceRepo = sourceRepoRaw ? sanitizeUntrustedText(sourceRepoRaw, 140) : undefined;
  const resolvedDeps = Array.isArray(buildDef?.["resolvedDependencies"])
    ? (buildDef["resolvedDependencies"]                                  )
    : [];
  const firstDepDigest = resolvedDeps[0]?.["digest"]                                       ;
  const cfgDigest = configSource?.["digest"]                                       ;
  const sourceCommit =
    typeof firstDepDigest?.["gitCommit"] === "string"
      ? sanitizeUntrustedText(firstDepDigest["gitCommit"], 48)
      : typeof firstDepDigest?.["sha1"] === "string"
        ? sanitizeUntrustedText(firstDepDigest["sha1"], 48)
        : typeof cfgDigest?.["sha1"] === "string"
          ? sanitizeUntrustedText(cfgDigest["sha1"], 48)
          : undefined;

  // Verify DSSE signature against bundled leaf X.509 certificate or public key
  const vm = (slsaBundle["verificationMaterial"] && typeof slsaBundle["verificationMaterial"] === "object"
    ? (slsaBundle["verificationMaterial"]                           )
    : {})                           ;
  const hasRekorTlog = Array.isArray(vm["tlogEntries"]) && vm["tlogEntries"].length > 0;

  let leafCertRawB64                    ;
  const certObj = vm["certificate"]                                       ;
  if (typeof certObj?.["rawBytes"] === "string") {
    leafCertRawB64 = certObj["rawBytes"];
  } else {
    const chainObj = vm["x509CertificateChain"]                                       ;
    const certs = Array.isArray(chainObj?.["certificates"]) ? (chainObj["certificates"]                                  ) : [];
    if (typeof certs[0]?.["rawBytes"] === "string") {
      leafCertRawB64 = certs[0]["rawBytes"];
    }
  }
  const pubKeyPem = typeof vm["publicKeyPem"] === "string" ? vm["publicKeyPem"] : undefined;

  if (!leafCertRawB64 && !pubKeyPem) {
    unknowns.push(
      "PROVENANCE_CRYPTO_UNVERIFIED: SLSA subject SHA-512 matched tarball, but verificationMaterial omitted a certificate/public key; DSSE signature and Sigstore trust root were NOT verified.",
    );
    return {
      status: "metadata_url_only",
      provenance_url: provenanceUrl,
      provenance_attested: false,
      predicate_type: stmtPredicateType,
      builder_id: builderId,
      source_repo: sourceRepo,
      source_commit: sourceCommit,
      has_rekor_tlog_entry: hasRekorTlog,
      observations,
      unknowns,
    };
  }

  let sigValid = false;
  try {
    const pubKey = leafCertRawB64
      ? new X509Certificate(Buffer.from(leafCertRawB64, "base64")).publicKey
      : createPublicKey(pubKeyPem );
    const keyType = pubKey.asymmetricKeyType;
    const curve = pubKey.asymmetricKeyDetails?.namedCurve;
    const hashAlg =
      keyType === "ed25519" || keyType === "ed448"
        ? null
        : curve === "secp384r1"
          ? "sha384"
          : curve === "secp521r1"
            ? "sha512"
            : "sha256";
    const pae = dssePae(payloadType, payloadBytes);
    for (const sigB64 of sigEntries) {
      if (cryptoVerify(hashAlg, pae, pubKey, Buffer.from(sigB64, "base64"))) {
        sigValid = true;
        break;
      }
    }
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "SLSA DSSE envelope signature failed cryptographic verification against the bundled certificate/key.",
    });
    return {
      status: "verification_failed",
      provenance_url: provenanceUrl,
      provenance_attested: false,
      predicate_type: stmtPredicateType,
      builder_id: builderId,
      source_repo: sourceRepo,
      source_commit: sourceCommit,
      has_rekor_tlog_entry: hasRekorTlog,
      observations,
      unknowns,
    };
  }

  unknowns.push(
    "PROVENANCE_TRUST_ROOT_UNVERIFIED: SLSA DSSE signature verified against bundled leaf certificate and subject SHA-512 matched tarball, but Sigstore Fulcio CA chain and Rekor transparency-log proofs were NOT verified locally (no embedded Sigstore TUF trusted_root). Run 'npm audit signatures' or cosign for full cryptographic verification.",
  );
  return {
    status: "dsse_leaf_verified_unanchored",
    provenance_url: provenanceUrl,
    provenance_attested: false,
    predicate_type: stmtPredicateType,
    builder_id: builderId,
    source_repo: sourceRepo,
    source_commit: sourceCommit,
    has_rekor_tlog_entry: hasRekorTlog,
    observations,
    unknowns,
  };
}

export async function inspectNpmAttestationBundle(params   
                         
                                
                               
                                  
                               
                     
                             
                     
 )                                      {
  // Enforce private-scope non-leakage: never fetch public npmjs.org or off-registry attestation URLs for private scopes
  if (params.route === "private") {
    let attOrigin                    ;
    try {
      attOrigin = new URL(params.attestationUrl).origin;
    } catch {
      attOrigin = undefined;
    }
    if (
      isPublicNpmRegistryUrl(params.attestationUrl) ||
      (params.allowedAuthOrigin && attOrigin !== params.allowedAuthOrigin)
    ) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          "PRIVATE_SCOPE_PROVENANCE_FETCH_SUPPRESSED: skipped off-origin/public dist.attestations.url fetch to prevent internal package metadata leakage.",
        ],
      };
    }
  }
  const MAX_ATTESTATION_BYTES = 2 * 1024 * 1024;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs ?? 10000);
  try {
    let allowHttpOrigin                    ;
    if (params.allowedAuthOrigin && params.allowedAuthOrigin.startsWith("http://")) {
      allowHttpOrigin = params.allowedAuthOrigin;
    }
    const fetched = await fetchWithSafeRedirects({
      url: params.attestationUrl,
      headers: { "user-agent": USER_AGENT, accept: "application/json" },
      authToken: params.authToken,
      allowedAuthOrigin: params.allowedAuthOrigin,
      allowPlainHttpOrigin: allowHttpOrigin,
      allowedPrivateOrigin: params.allowedAuthOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          `PROVENANCE_ATTESTATION_FETCH_FAILED: registry metadata advertised dist.attestations.url, but fetching the attestation bundle failed (${fetched.error ?? "network error"}); Sigstore/SLSA provenance is NOT verified.`,
        ],
      };
    }
    const res = fetched.response;
    if (!res.ok) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          `PROVENANCE_ATTESTATION_FETCH_FAILED: registry metadata advertised dist.attestations.url, but endpoint returned HTTP ${res.status}; Sigstore/SLSA provenance is NOT verified.`,
        ],
      };
    }
    const readRes = await readResponseBytesCapped(res, MAX_ATTESTATION_BYTES, "Attestation");
    if (!readRes.ok) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          `PROVENANCE_ATTESTATION_FETCH_FAILED: ${readRes.error}; Sigstore/SLSA provenance is NOT verified.`,
        ],
      };
    }
    let parsed         ;
    try {
      parsed = JSON.parse(readRes.buffer.toString("utf8"));
    } catch {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          "PROVENANCE_ATTESTATION_FETCH_FAILED: attestation endpoint returned malformed JSON; Sigstore/SLSA provenance is NOT verified.",
        ],
      };
    }
    return verifyNpmAttestationPayload(
      parsed,
      params.expectedTarballSha512,
      params.expectedPackageName,
      params.attestationUrl,
      params.expectedPackageVersion,
    );
  } catch (err) {
    return {
      status: "metadata_url_only",
      provenance_url: params.attestationUrl,
      provenance_attested: false,
      observations: [],
      unknowns: [
        `PROVENANCE_ATTESTATION_FETCH_FAILED: ${err instanceof Error ? err.message : String(err)}; Sigstore/SLSA provenance is NOT verified.`,
      ],
    };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJsonWithTimeout   (
  url        ,
  headers                        ,
  timeoutMs = 12000,
  auth                                             ,
  opts    
                      
                                  
                                  
   ,
)                                                                     {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Security [MCP-09]: never auto-set allowPlainHttpOrigin from untrusted `url`;
    // only honor explicit server/policy-configured origins passed by caller.
    const fetched = await fetchWithSafeRedirects({
      url,
      headers,
      authToken: auth?.token,
      allowedAuthOrigin: auth?.allowedOrigin,
      allowPlainHttpOrigin: opts?.allowPlainHttpOrigin,
      allowedPrivateOrigin: opts?.allowedPrivateOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response) {
      return { ok: false, status: 0, error: fetched.error ?? "fetch failed" };
    }
    const res = fetched.response;
    if (!res.ok) return { ok: false, status: res.status, error: `HTTP ${res.status}` };
    const maxBytes = opts?.maxBytes ?? MAX_SMALL_JSON_BYTES;
    const readRes = await readResponseBytesCapped(res, maxBytes, "JSON");
    if (!readRes.ok) {
      return { ok: false, status: res.status, error: readRes.error };
    }
    const data = JSON.parse(readRes.buffer.toString("utf8"))     ;
    return { ok: true, status: res.status, data };
  } catch (err) {
    return { ok: false, status: 0, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchTarballBuffer(
  tarballUrl        ,
  maxBytes        ,
  authToken         ,
  timeoutMs = 20000,
  allowedAuthOrigin         ,
  callerSignal              ,
)                                                            {
  const flightKey = `${tarballUrl}|${maxBytes}|${hashAuthScope(authToken)}`;
  try {
    const shared = await tarballFlight.run(
      flightKey,
      async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const allowHttpOrigin =
            allowedAuthOrigin && allowedAuthOrigin.startsWith("http://") ? allowedAuthOrigin : undefined;
          const fetched = await fetchWithSafeRedirects({
            url: tarballUrl,
            headers: { "user-agent": USER_AGENT },
            authToken,
            allowedAuthOrigin,
            allowPlainHttpOrigin: allowHttpOrigin,
            allowedPrivateOrigin: allowedAuthOrigin,
            signal: controller.signal,
          });
          if (!fetched.ok || !fetched.response) {
            return { ok: false, error: fetched.error ?? "Failed downloading tarball" };
          }
          const res = fetched.response;
          if (!res.ok) return { ok: false, error: `HTTP ${res.status} downloading tarball` };
          const readRes = await readResponseBytesCapped(res, maxBytes, "Tarball");
          if (!readRes.ok) return { ok: false, error: readRes.error };
          return { ok: true, buffer: readRes.buffer };
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        } finally {
          clearTimeout(timer);
        }
      },
      callerSignal,
    );
    // Return an isolated Buffer copy to each waiter so mutations cannot leak across concurrent requests
    if (shared.ok && shared.buffer) {
      return { ok: true, buffer: Buffer.from(shared.buffer) };
    }
    return shared;
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function fetchVersionMetadata(params   
                       
                   
                       
                      
                       
 )                                                                                                         {
  const flightKey = `${params.registry_url}|${params.package_name}|${params.version ?? "latest"}|${hashAuthScope(params.auth_token)}`;
  try {
    return await versionMetaFlight.run(
      flightKey,
      async () => {
        const headers                         = {
          "user-agent": USER_AGENT,
          accept: "application/json",
        };
        let parsedReg     ;
        try {
          parsedReg = new URL(params.registry_url);
        } catch {
          return { ok: false, error: `Invalid registry URL: ${params.registry_url}` };
        }
        const registryOrigin = parsedReg.origin;
        const allowHttpOrigin = parsedReg.protocol === "http:" ? registryOrigin : undefined;
        const auth = params.auth_token ? { token: params.auth_token, allowedOrigin: registryOrigin } : undefined;
        const netOpts = {
          maxBytes: MAX_PACKUMENT_JSON_BYTES,
          allowPlainHttpOrigin: allowHttpOrigin,
          allowedPrivateOrigin: registryOrigin,
        };

        const baseUrl = `${params.registry_url}/${encodePkgName(params.package_name)}`;
        // Fetch packument first so time[ver] (cooldown), time.created (slopsquat age), dist-tags, and release history
        // are ALWAYS preserved even when an explicit @version is inspected!
        const res = await fetchJsonWithTimeout                         (baseUrl, headers, 12000, auth, netOpts);

        if (res.ok && res.data) {
          const doc = res.data;
          const distTags = (doc["dist-tags"] ?? {})                          ;
          const versions = (doc["versions"] ?? {})                                           ;
          const timeMap = (doc["time"] ?? {})                          ;
          const latestVer = distTags["latest"];
          const requestedVer =
            params.version && params.version !== "latest"
              ? (versions[params.version] ? params.version : distTags[params.version])
              : latestVer;

          const buildMeta = (ver        , vObj                         )                          => {
            const dist = (vObj["dist"] ?? {})                           ;
            const repo = extractRepo(vObj["repository"] ?? doc["repository"]);
            const provUrl = extractProvenanceUrl(vObj);
            return {
              name: String(vObj["name"] ?? params.package_name),
              version: ver,
              tarball_url: String(dist["tarball"] ?? ""),
              integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
              git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
              repository_url: repo.url,
              repository_directory: repo.directory,
              // Packument dist.attestations.url alone is unverified metadata, never cryptographic Sigstore attestation
              provenance_attested: false,
              provenance_status: provUrl ? "metadata_url_only" : "none",
              provenance_url: provUrl,
              published_at: timeMap[ver],
              created_at: timeMap["created"],
              license: extractLicense(vObj["license"] ?? doc["license"]),
              creator: extractCreator(vObj["author"] ?? vObj["_npmUser"]),
              description: sanitizeUntrustedText(String(vObj["description"] ?? doc["description"] ?? ""), 220),
              keywords: Array.isArray(vObj["keywords"] ?? doc["keywords"])
                ? ((vObj["keywords"] ?? doc["keywords"])             )
                    .filter((k)              => typeof k === "string")
                    .slice(0, 10)
                : [],
              scripts:
                vObj["scripts"] && typeof vObj["scripts"] === "object"
                  ? (vObj["scripts"]                          )
                  : {},
              dependencies:
                vObj["dependencies"] && typeof vObj["dependencies"] === "object"
                  ? (vObj["dependencies"]                          )
                  : {},
              optional_dependencies:
                vObj["optionalDependencies"] && typeof vObj["optionalDependencies"] === "object"
                  ? (vObj["optionalDependencies"]                          )
                  : {},
              bin_names: extractBinNames(params.package_name, vObj["bin"]),
            };
          };

          if (requestedVer && versions[requestedVer]) {
            const targetMeta = buildMeta(requestedVer, versions[requestedVer] );
            const latestMeta = latestVer && versions[latestVer] ? buildMeta(latestVer, versions[latestVer] ) : targetMeta;
            const versionsDesc = Object.entries(versions)
              .map(([ver, vObj]) => {
                const dist = (vObj["dist"] ?? {})                           ;
                const provUrl = extractProvenanceUrl(vObj);
                return {
                  version: ver,
                  published_at: timeMap[ver],
                  tarball_url: String(dist["tarball"] ?? ""),
                  integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
                  git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
                  provenance_attested: false,
                  provenance_status: provUrl ? ("metadata_url_only"         ) : ("none"         ),
                  provenance_url: provUrl,
                  dependencies:
                    vObj["dependencies"] && typeof vObj["dependencies"] === "object"
                      ? (vObj["dependencies"]                          )
                      : {},
                  optional_dependencies:
                    vObj["optionalDependencies"] && typeof vObj["optionalDependencies"] === "object"
                      ? (vObj["optionalDependencies"]                          )
                      : {},
                };
              })
              .sort((a, b) => Date.parse(b.published_at ?? "0") - Date.parse(a.published_at ?? "0"))
              .slice(0, 30);

            return {
              ok: true,
              meta: targetMeta,
              packument: {
                name: latestMeta.name,
                latest_version: latestVer ?? requestedVer,
                created_at: timeMap["created"],
                versions_desc: versionsDesc,
                latest_meta: latestMeta,
              },
            };
          }
        }

        // Fallback to single-version endpoint if packument omitted the explicit version or returned error
        if (params.version && params.version !== "latest") {
          const singleUrl = `${baseUrl}/${encodeURIComponent(params.version)}`;
          const single = await fetchJsonWithTimeout                         (singleUrl, headers, 12000, auth, netOpts);
          if (!single.ok || !single.data) {
            return { ok: false, error: single.error ?? res.error ?? "Failed to fetch version metadata" };
          }
          const vObj = single.data;
          const dist = (vObj["dist"] ?? {})                           ;
          const repo = extractRepo(vObj["repository"]);
          const provUrl = extractProvenanceUrl(vObj);
          const meta                          = {
            name: String(vObj["name"] ?? params.package_name),
            version: String(vObj["version"] ?? params.version),
            tarball_url: String(dist["tarball"] ?? ""),
            integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
            git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
            repository_url: repo.url,
            repository_directory: repo.directory,
            provenance_attested: false,
            provenance_status: provUrl ? "metadata_url_only" : "none",
            provenance_url: provUrl,
            license: extractLicense(vObj["license"]),
            creator: extractCreator(vObj["author"] ?? vObj["_npmUser"]),
            description: sanitizeUntrustedText(String(vObj["description"] ?? ""), 220),
            keywords: Array.isArray(vObj["keywords"])
              ? vObj["keywords"].filter((k)              => typeof k === "string").slice(0, 10)
              : [],
            scripts:
              vObj["scripts"] && typeof vObj["scripts"] === "object"
                ? (vObj["scripts"]                          )
                : {},
            dependencies:
              vObj["dependencies"] && typeof vObj["dependencies"] === "object"
                ? (vObj["dependencies"]                          )
                : {},
            optional_dependencies:
              vObj["optionalDependencies"] && typeof vObj["optionalDependencies"] === "object"
                ? (vObj["optionalDependencies"]                          )
                : {},
            bin_names: extractBinNames(params.package_name, vObj["bin"]),
          };
          return { ok: true, meta };
        }

        return { ok: false, error: res.error ?? `No 'latest' version found for ${params.package_name}` };
      },
      params.signal,
    );
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function mapOsvSeverity(vuln                         )           {
  const id = String(vuln["id"] ?? "");
  if (id.startsWith("MAL-")) return "CRITICAL";
  const dbSpec = vuln["database_specific"]                                       ;
  const sevStr = String(dbSpec?.["severity"] ?? "").toUpperCase();
  if (sevStr === "CRITICAL") return "CRITICAL";
  if (sevStr === "HIGH") return "HIGH";
  if (sevStr === "MODERATE" || sevStr === "MEDIUM") return "MEDIUM";
  if (sevStr === "LOW") return "LOW";
  return "HIGH";
}

export async function queryOsvAdvisories(params   
                                                      
                       
                          
                              
 )                                                                {
  const unknowns           = [];
  if (params.policy.offline_mode) {
    unknowns.push("OFFLINE_INTEL_SKIPPED: OSV/OpenSSF MAL-* lookup skipped in offline mode.");
    return { advisories: [], unknowns };
  }
  const osvBaseUrl = (params.policy.osv_api_url || "https://api.osv.dev").replace(/\/+$/, "");
  if (params.route === "private" && isPublicOsvUrl(osvBaseUrl)) {
    unknowns.push("PRIVATE_SCOPE_OSV_SUPPRESSED: skipped public api.osv.dev query to prevent internal package name leakage.");
    return { advisories: [], unknowns };
  }
  if (params.packages.length === 0) return { advisories: [], unknowns };

  let osvConfiguredOrigin        ;
  let osvExplicitHttpOrigin                    ;
  try {
    const parsedOsv = new URL(osvBaseUrl);
    osvConfiguredOrigin = parsedOsv.origin;
    if (parsedOsv.protocol === "http:") osvExplicitHttpOrigin = parsedOsv.origin;
  } catch {
    unknowns.push(`OSV_API_ERROR: invalid osv_api_url '${osvBaseUrl}'`);
    return { advisories: [], unknowns };
  }
  const batchUrl = `${osvBaseUrl}/v1/querybatch`;
  const batchCheck = validateOutboundUrl(batchUrl, osvExplicitHttpOrigin, osvConfiguredOrigin);
  if (!batchCheck.ok) {
    unknowns.push(`OSV_API_ERROR: ${batchCheck.error ?? "rejected OSV URL"}`);
    return { advisories: [], unknowns };
  }

  // Security [MCP-13]: namespace BOTH batch and detail OSV cache/SingleFlight keys by sha256(osvBaseUrl)
  const osvNs = createHash("sha256").update(osvBaseUrl).digest("hex").slice(0, 16);
  const advisories                   = [];
  const toQuery                                                         = [];

  for (const p of params.packages) {
    const key = `osv:${osvNs}:npm:${p.name}@${p.version ?? "*"}`;
    const cached = params.cache?.getThreatIntel                  (key);
    if (cached && !cached.stale) {
      advisories.push(...cached.data);
    } else {
      toQuery.push({ ...p, key });
    }
  }

  if (toQuery.length === 0) return { advisories, unknowns };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const fetched = await fetchWithSafeRedirects({
      url: batchUrl,
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({
        queries: toQuery.map((q) => ({
          package: { ecosystem: "npm", name: q.name },
          ...(q.version ? { version: q.version } : {}),
        })),
      }),
      allowPlainHttpOrigin: osvExplicitHttpOrigin,
      allowedPrivateOrigin: osvConfiguredOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response) {
      unknowns.push(`OSV_API_UNAVAILABLE: ${fetched.error ?? "fetch failed"}`);
      return { advisories, unknowns };
    }
    const res = fetched.response;
    if (!res.ok) {
      unknowns.push(`OSV_API_UNAVAILABLE: HTTP ${res.status}`);
      return { advisories, unknowns };
    }
    const readRes = await readResponseBytesCapped(res, MAX_SMALL_JSON_BYTES, "OSV batch");
    if (!readRes.ok) {
      unknowns.push(`OSV_API_ERROR: ${readRes.error}`);
      return { advisories, unknowns };
    }
    const body = JSON.parse(readRes.buffer.toString("utf8"))     
                                                          
     ;
    const results = body.results ?? [];

    for (let i = 0; i < toQuery.length; i++) {
      const q = toQuery[i] ;
      const vulns = results[i]?.vulns ?? [];
      const pkgAdvisories                   = [];

      // Fetch detail for up to 10 vulns per package to bound API fan-out
      for (const v of vulns.slice(0, 10)) {
        const vid = v.id;
        if (!vid) continue;
        const detailKey = `osv-vuln:${osvNs}:${vid}`;
        const cachedDetail = params.cache?.getThreatIntel                         (detailKey);
        let detailObj = cachedDetail && !cachedDetail.stale ? cachedDetail.data : undefined;
        if (!detailObj) {
          detailObj = await osvDetailFlight.run(detailKey, async () => {
            const detRes = await fetchJsonWithTimeout                         (
              `${osvBaseUrl}/v1/vulns/${encodeURIComponent(vid)}`,
              { "user-agent": USER_AGENT },
              8000,
              undefined,
              {
                maxBytes: MAX_SMALL_JSON_BYTES,
                allowPlainHttpOrigin: osvExplicitHttpOrigin,
                allowedPrivateOrigin: osvConfiguredOrigin,
              },
            );
            if (detRes.ok && detRes.data) {
              params.cache?.putThreatIntel({
                intel_key: detailKey,
                source: "osv",
                payload: detRes.data,
                ttl_seconds: params.policy.intel_ttl_seconds,
              });
              return detRes.data;
            }
            return undefined;
          });
        }
        const isMal = vid.startsWith("MAL-");
        const dbSpec = detailObj?.["database_specific"]                                       ;
        const kev = Boolean(dbSpec?.["cisa_kev"] || String(detailObj?.["summary"] ?? "").toLowerCase().includes("known exploited"));
        pkgAdvisories.push({
          id: vid,
          is_malicious: isMal,
          severity: detailObj ? mapOsvSeverity(detailObj) : isMal ? "CRITICAL" : "HIGH",
          kev,
          summary: sanitizeUntrustedText(String(detailObj?.["summary"] ?? (isMal ? "OpenSSF Malicious Package advisory" : "OSV advisory")), 160),
          package_name: q.name,
          affected_version: q.version,
        });
      }

      params.cache?.putThreatIntel({
        intel_key: q.key,
        source: "osv",
        payload: pkgAdvisories,
        ttl_seconds: params.policy.intel_ttl_seconds,
      });
      advisories.push(...pkgAdvisories);
    }
  } catch (err) {
    unknowns.push(`OSV_API_ERROR: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timer);
  }

  return { advisories, unknowns };
}

export async function discoverPackages(params   
                
               
                   
                    
                 
                       
                     
                          
 )                             {
  const unknowns           = [];
  const candidates                       = [];
  const blocked_candidates                                                  = [];

  const routeTarget = params.org ? (params.org.startsWith("@") ? params.org : `@${params.org}`) : params.query;
  const routing = routeDiscoveryQuery(params.query, params.org, params.policy, params.npmrc, {
    creator: params.creator,
    category: params.category,
  });
  if (
    routing.route === "blocked_typo" ||
    routing.route === "blocked_unconfigured" ||
    routing.route === "blocked_secret"
  ) {
    return {
      schema_version: "1",
      query: params.query,
      filters: { org: params.org, creator: params.creator, category: params.category },
      registry_route: "private",
      candidates: [],
      blocked_candidates: [{ package_name: routing.matched_scope_or_prefix ?? routeTarget, reason: routing.reason }],
      unknowns: [routing.reason],
    };
  }

  if (params.policy.offline_mode) {
    unknowns.push("OFFLINE_MODE: live registry discovery disabled.");
    return {
      schema_version: "1",
      query: params.query,
      filters: { org: params.org, creator: params.creator, category: params.category },
      registry_route: routing.route,
      candidates: [],
      blocked_candidates: [],
      unknowns,
    };
  }

  const terms           = [];
  if (params.query.trim()) terms.push(params.query.trim());
  if (params.org) terms.push(`scope:${params.org.replace(/^@/, "")}`);
  if (params.creator) terms.push(`maintainer:${params.creator}`);
  if (params.category) terms.push(`keywords:${params.category}`);

  const searchText = terms.join(" ").trim();
  const rawLimit = typeof params.limit === "number" && Number.isFinite(params.limit) ? Math.floor(params.limit) : 10;
  const size = Math.min(Math.max(rawLimit, 1), 25);
  const searchUrl = `${routing.registry_url}/-/v1/search?text=${encodeURIComponent(searchText)}&size=${size}`;
  const headers                         = { "user-agent": USER_AGENT };
  let searchOrigin                    ;
  let searchAllowHttpOrigin                    ;
  try {
    const parsedSearch = new URL(routing.registry_url);
    searchOrigin = parsedSearch.origin;
    if (parsedSearch.protocol === "http:") searchAllowHttpOrigin = parsedSearch.origin;
  } catch {
    searchOrigin = undefined;
  }

  const res = await fetchJsonWithTimeout                                                            (
    searchUrl,
    headers,
    12000,
    routing.auth_token && searchOrigin ? { token: routing.auth_token, allowedOrigin: searchOrigin } : undefined,
    {
      maxBytes: MAX_SMALL_JSON_BYTES,
      allowPlainHttpOrigin: searchAllowHttpOrigin,
      allowedPrivateOrigin: searchOrigin,
    },
  );
  if (!res.ok || !res.data) {
    unknowns.push(`DISCOVERY_SEARCH_FAILED: ${res.error ?? "upstream registry error"}`);
    return {
      schema_version: "1",
      query: params.query,
      filters: { org: params.org, creator: params.creator, category: params.category },
      registry_route: routing.route,
      candidates: [],
      blocked_candidates: [],
      unknowns,
    };
  }

  for (const item of res.data.objects ?? []) {
    const pkg = item.package;
    if (!pkg || typeof pkg["name"] !== "string") continue;
    const pkgName = pkg["name"];
    const version = String(pkg["version"] ?? "0.0.0");
    const scope = pkgName.startsWith("@") ? pkgName.slice(0, pkgName.indexOf("/")) : "unscoped";
    const scopeLower = scope.toLowerCase();
    const license = extractLicense(pkg["license"]);

    if (params.policy.denied_orgs.includes(scopeLower)) {
      blocked_candidates.push({ package_name: pkgName, reason: `Org/scope '${scope}' is on policy denied_orgs list.` });
      continue;
    }
    if (params.policy.allowed_orgs.length > 0 && !params.policy.allowed_orgs.includes(scopeLower)) {
      blocked_candidates.push({ package_name: pkgName, reason: `Org/scope '${scope}' is not on policy allowed_orgs list.` });
      continue;
    }
    if (params.policy.blocked_licenses.some((b) => b.toLowerCase() === license.toLowerCase())) {
      blocked_candidates.push({ package_name: pkgName, reason: `License '${license}' is blocked by enterprise policy.` });
      continue;
    }

    const squatWarnings = evaluateSlopsquatAndCooldown({
      package_name: pkgName,
      version_published_at_iso: typeof pkg["date"] === "string" ? pkg["date"] : undefined,
      has_lifecycle_scripts: false,
      policy: params.policy,
    });

    const hasCritSquat = squatWarnings.some((o) => o.severity === "CRITICAL");
    const hasWarnSquat = squatWarnings.length > 0;

    candidates.push({
      package_name: pkgName,
      version,
      org_or_scope: scope,
      creator: extractCreator(pkg["publisher"] ?? pkg["author"]),
      summary: sanitizeUntrustedText(String(pkg["description"] ?? ""), 180),
      license,
      keywords: Array.isArray(pkg["keywords"])
        ? pkg["keywords"].filter((k)              => typeof k === "string").slice(0, 8)
        : [],
      published_at: typeof pkg["date"] === "string" ? pkg["date"] : undefined,
      squat_warnings: squatWarnings,
      verdict_preview: hasCritSquat
        ? "MALICIOUS_INDICATORS_FOUND"
        : hasWarnSquat
          ? "QUARANTINE_SUSPICIOUS"
          : "UNVERIFIABLE_UNKNOWN",
    });
  }

  // Batch-check returned candidates against OSV/OpenSSF MAL-* (public route or configured internal OSV mirror)
  if (candidates.length > 0) {
    const osvRes = await queryOsvAdvisories({
      packages: candidates.map((c) => ({ name: c.package_name, version: c.version })),
      policy: params.policy,
      cache: params.cache,
      route: routing.route,
    });
    if (osvRes.unknowns.length > 0) unknowns.push(...osvRes.unknowns);
    for (const adv of osvRes.advisories) {
      const cand = candidates.find((c) => c.package_name === adv.package_name);
      if (!cand) continue;
      if (adv.is_malicious) {
        cand.verdict_preview = "MALICIOUS_INDICATORS_FOUND";
        cand.squat_warnings.push({
          code: "OSV_MALICIOUS_PACKAGE_ADVISORY",
          severity: "CRITICAL",
          path: "<threat-intel>",
          attack_id: "T1195.002",
          detail: `${adv.id}: ${adv.summary}`,
        });
      } else if (
        cand.verdict_preview !== "MALICIOUS_INDICATORS_FOUND" &&
        ((params.policy.block_on_kev && adv.kev) ||
          (params.policy.block_on_critical_cve && adv.severity === "CRITICAL") ||
          (params.policy.block_on_high_cve && adv.severity === "HIGH"))
      ) {
        cand.verdict_preview = "QUARANTINE_SUSPICIOUS";
      }
    }
  }

  return {
    schema_version: "1",
    query: params.query,
    filters: { org: params.org, creator: params.creator, category: params.category },
    registry_route: routing.route,
    candidates,
    blocked_candidates,
    unknowns,
  };
}

/**
 * Dependency Confusion Audit (`T1195.001`):
 * Inspects local package.json + .npmrc + policy for unpinned private scopes
 * or unscoped internal prefixes vulnerable to public registry shadowing.
 */
export async function auditDependencyConfusion(params   
              
                        
                       
                                    
                            
 )                           {
  const manifestPath = resolve(params.manifestPath ?? resolve(params.cwd, "package.json"));
  const npmrc = loadNpmrc(dirname(manifestPath));
  const displayManifestPath = params.redactHomePaths ? redactHomePath(manifestPath) : manifestPath;
  const displayNpmrcPaths = params.redactHomePaths
    ? npmrc.paths_loaded.map((p) => redactHomePath(p))
    : npmrc.paths_loaded;
  const findings                     = [];
  const unknowns           = [];

  if (!existsSync(manifestPath)) {
    return {
      schema_version: "1",
      manifest_path: displayManifestPath,
      npmrc_paths: displayNpmrcPaths,
      findings: [],
      passed: false,
      unknowns: [`Manifest not found at ${displayManifestPath}`],
    };
  }

  let pkg                                                                 ;
  try {
    const rawBuf = await openReadCappedFile(manifestPath, MAX_MANIFEST_BYTES);
    pkg = JSON.parse(rawBuf.toString("utf8"))                       
                                                
     ;
  } catch (err) {
    return {
      schema_version: "1",
      manifest_path: displayManifestPath,
      npmrc_paths: displayNpmrcPaths,
      findings: [],
      passed: false,
      unknowns: [`MANIFEST_PARSE_ERROR: failed to parse ${displayManifestPath}: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  const allDeps                         = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
    ...(pkg.peerDependencies ?? {}),
  };

  for (const [depName, range] of Object.entries(allDeps)) {
    const lower = depName.toLowerCase();
    const isScoped = lower.startsWith("@");
    const scope = isScoped ? lower.slice(0, lower.indexOf("/")) : undefined;

    if (scope && params.policy.private_scopes.includes(scope)) {
      const pinnedUrl = npmrc.scoped_registries[scope] ?? params.policy.private_registries[scope];
      if (!pinnedUrl || isPublicNpmRegistryUrl(pinnedUrl)) {
        findings.push({
          package_name: depName,
          declared_range: range,
          issue: "UNPINNED_PRIVATE_SCOPE",
          severity: "CRITICAL",
          detail: `Private scope '${scope}' is declared in policy but not pinned to a private registry in .npmrc.`,
          remediation: `Add '${scope}:registry=https://<your-private-registry>/' to project .npmrc.`,
        });
      }
      continue;
    }

    const matchedPrefix = params.policy.private_prefixes.find((pref) => lower.startsWith(pref));
    if (!isScoped && matchedPrefix) {
      findings.push({
        package_name: depName,
        declared_range: range,
        issue: "UNSCOPED_PRIVATE_PREFIX",
        severity: "HIGH",
        detail: `Unscoped internal package '${depName}' (prefix '${matchedPrefix}') is vulnerable to public npm substitution (T1195.001).`,
        remediation: `Migrate '${depName}' into an organization scope pinned in .npmrc or reserve a placeholder package.`,
      });

      if (params.checkPublicClaimability && !params.policy.offline_mode) {
        const probe = await fetchJsonWithTimeout                         (
          `https://registry.npmjs.org/${encodePkgName(depName)}`,
          { "user-agent": USER_AGENT, accept: "application/vnd.npm.install-v1+json" },
          6000,
          undefined,
          { maxBytes: MAX_SMALL_JSON_BYTES },
        );
        if (probe.status === 404) {
          findings.push({
            package_name: depName,
            declared_range: range,
            issue: "CLAIMABLE_ON_PUBLIC_NPM",
            severity: "CRITICAL",
            detail: `Unscoped internal name '${depName}' returned HTTP 404 on public npmjs.org and is immediately claimable by an attacker.`,
            remediation: `Pin registry strictly to a non-merging private proxy and reserve or scope '${depName}'.`,
          });
        } else if (probe.ok) {
          findings.push({
            package_name: depName,
            declared_range: range,
            issue: "PUBLIC_SHADOW_EXISTS",
            severity: "CRITICAL",
            detail: `Unscoped internal name '${depName}' already exists on public npmjs.org; verify ownership immediately.`,
            remediation: `Verify publisher ownership on npmjs.org and isolate internal resolution via .npmrc.`,
          });
        }
      }
    }
  }

  return {
    schema_version: "1",
    manifest_path: displayManifestPath,
    npmrc_paths: displayNpmrcPaths,
    findings,
    passed: findings.length === 0 && unknowns.length === 0,
    unknowns,
  };
}

/**
 * Consolidated SSRF-guarded HTTPS JWKS fetcher for the opt-in Streamable HTTP MCP adapter (`v1.6+`).
 * Reuses `fetchWithSafeRedirects` + `readResponseTextWithCap` so all outbound `fetch()` stays in `registry-osv.ts`.
 */
export async function fetchJwksJson(
  jwksUrl        ,
  opts                                                      = {},
)                                                                                            {
  let parsed     ;
  try {
    parsed = new URL(jwksUrl);
  } catch {
    return { ok: false, error: "Invalid JWKS URL." };
  }
  const allowPlainHttpOrigin =
    opts.allowLoopbackHttp && parsed.protocol === "http:" && isLoopbackHost(parsed.hostname) ? parsed.origin : undefined;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 6000);
  try {
    const fetched = await fetchWithSafeRedirects({
      url: jwksUrl,
      headers: { "user-agent": USER_AGENT, accept: "application/json" },
      allowPlainHttpOrigin,
      allowedPrivateOrigin: allowPlainHttpOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response || !fetched.response.ok) {
      return { ok: false, error: fetched.error ?? `HTTP ${fetched.response?.status ?? 0}` };
    }
    const capped = await readResponseBytesCapped(fetched.response, 256 * 1024, "JWKS");
    if (!capped.ok) {
      return { ok: false, error: capped.error };
    }
    const parsedJson = JSON.parse(capped.buffer.toString("utf8"))                      ;
    if (!parsedJson || !Array.isArray(parsedJson.keys)) {
      return { ok: false, error: "JWKS payload missing 'keys' array." };
    }
    return { ok: true, jwks: { keys: parsedJson.keys                                   } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}


//# sourceURL=intel/registry-osv.ts
