import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { pathToFileURL } from "node:url";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const BADGE_FN_PATH = join(REPO_ROOT, "functions", "badge", "[[path]].js");
const BADGE_FN_URL = pathToFileURL(BADGE_FN_PATH).href;

interface NpmCardMetrics {
  packageName: string;
  version: string;
  license: string;
  depsCount: number;
  provenanceVerified: boolean;
  weekly: number | null;
  monthly: number | null;
  sparklineValues: number[];
  endDate: string | null;
  downloadsAvailable: boolean;
  registryAvailable: boolean;
  degraded: boolean;
}

interface PagesContext {
  request: Request;
  waitUntil?: (promise: Promise<unknown>) => void;
}

interface BadgeModule {
  PKG: string;
  FALLBACK_VERSION: string;
  FALLBACK_LICENSE: string;
  escapeXml: (value: unknown) => string;
  formatCompactCount: (value: unknown) => string;
  computeNpmCardMetrics: (downloadsJson: unknown, registryJson: unknown) => NpmCardMetrics;
  renderNpmCardSvg: (metrics: Partial<NpmCardMetrics>, theme?: string) => string;
  renderNpmDownloadsBadgeSvg: (metrics: Partial<NpmCardMetrics>, theme?: string) => string;
  onRequest: (context: PagesContext) => Promise<Response>;
  onRequestGet: (context: PagesContext) => Promise<Response>;
  onRequestHead: (context: PagesContext) => Promise<Response>;
}

interface MockCacheStore {
  match: (req: Request) => Promise<Response | undefined>;
  put: (req: Request, res: Response) => Promise<void>;
  entries: Map<string, Response>;
  putKeys: Array<{ url: string; method: string; bodyLen: number }>;
}

function createStrictMockCache(): MockCacheStore {
  const entries = new Map<string, Response>();
  const putKeys: Array<{ url: string; method: string; bodyLen: number }> = [];
  return {
    entries,
    putKeys,
    async match(req: Request): Promise<Response | undefined> {
      const hit = entries.get(`${req.method}:${req.url}`);
      return hit ? hit.clone() : undefined;
    },
    async put(req: Request, res: Response): Promise<void> {
      if (req.method !== "GET") {
        throw new TypeError(`Cannot cache ${req.method} request in caches.default`);
      }
      const bodyText = await res.clone().text();
      if (!bodyText) {
        throw new TypeError("Cannot cache empty response body for SVG badge");
      }
      putKeys.push({ url: req.url, method: req.method, bodyLen: bodyText.length });
      entries.set(`${req.method}:${req.url}`, res.clone());
    },
  };
}

function buildNov2026DownloadsPayload(): {
  start: string;
  end: string;
  package: string;
  downloads: Array<{ day: string; downloads: number }>;
} {
  const downloads: Array<{ day: string; downloads: number }> = [];
  for (let i = 1; i <= 27; i += 1) {
    downloads.push({ day: `2026-10-${String(i).padStart(2, "0")}`, downloads: 0 });
  }
  downloads.push({ day: "2026-11-21", downloads: 537 });
  downloads.push({ day: "2026-11-22", downloads: 84 });
  downloads.push({ day: "2026-11-23", downloads: 210 });
  return {
    start: "2026-10-25",
    end: "2026-11-23",
    package: "coldpin",
    downloads,
  };
}

function buildLiveRegistryPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: "coldpin",
    version: "1.6.0",
    license: "Apache-2.0",
    dependencies: {},
    dist: {
      attestations: {
        provenance: {
          predicateType: "https://slsa.dev/provenance/v1",
        },
      },
    },
    ...overrides,
  };
}

function assertSvgSecurityInvariants(svg: string, label: string): void {
  assert.ok(svg.startsWith("<svg "), `${label}: must start with <svg`);
  assert.ok(svg.endsWith("</svg>"), `${label}: must end with </svg>`);
  assert.match(svg, /role="img"/, `${label}: missing role="img"`);
  assert.match(svg, /aria-label="[^"]+"/, `${label}: missing aria-label`);
  assert.match(svg, /<title>[^<]+<\/title>/, `${label}: missing <title>`);
  assert.match(svg, /<desc>[^<]+<\/desc>/, `${label}: missing <desc>`);
  assert.doesNotMatch(svg, /\bNaN\b/, `${label}: NaN coordinate emitted`);

  // Structural XML tag & attribute audit (proves zero real active elements/attributes even on poisoned text)
  const forbiddenTags = new Set(["script", "style", "foreignobject", "iframe", "object", "embed", "animate", "set"]);
  const tagStack: string[] = [];
  const tagRe = /<(\/?)([A-Za-z][A-Za-z0-9:_-]*)([^>]*)>/g;
  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = tagRe.exec(svg)) !== null) {
    const isClose = tagMatch[1] === "/";
    const tagName = tagMatch[2]!;
    const rawAttrs = tagMatch[3]!;
    const lowerTag = tagName.toLowerCase();
    assert.ok(!forbiddenTags.has(lowerTag), `${label}: forbidden active SVG element <${tagName}>`);

    if (isClose) {
      const popped = tagStack.pop();
      assert.equal(popped, tagName, `${label}: mismatched closing tag </${tagName}> (expected </${popped}>)`);
      continue;
    }

    const selfClosing = rawAttrs.trimEnd().endsWith("/");
    if (!selfClosing) {
      tagStack.push(tagName);
    }

    const attrSource = selfClosing ? rawAttrs.trimEnd().slice(0, -1) : rawAttrs;
    const attrRe = /([A-Za-z_:][A-Za-z0-9:._-]*)\s*=\s*"([^"]*)"/g;
    let attrMatch: RegExpExecArray | null;
    while ((attrMatch = attrRe.exec(attrSource)) !== null) {
      const attrName = attrMatch[1]!.toLowerCase();
      const attrVal = attrMatch[2]!;
      assert.ok(!attrName.startsWith("on"), `${label}: forbidden SVG event attribute '${attrName}' on <${tagName}>`);
      assert.ok(
        attrName !== "href" && attrName !== "xlink:href" && attrName !== "src" && attrName !== "style",
        `${label}: forbidden SVG attribute '${attrName}' on <${tagName}>`,
      );
      if (attrName === "xmlns") {
        assert.equal(attrVal, "http://www.w3.org/2000/svg", `${label}: unexpected xmlns`);
      } else {
        assert.doesNotMatch(attrVal, /\burl\s*\(/i, `${label}: forbidden url() in ${attrName}`);
        assert.doesNotMatch(attrVal, /https?:\/\/|javascript:|data:/i, `${label}: forbidden URI in ${attrName}`);
      }
    }
    assert.equal(
      attrSource.replace(attrRe, "").trim(),
      "",
      `${label}: unexpected unparsed attribute syntax in <${tagName}>: ${attrSource}`,
    );
  }
  assert.equal(tagStack.length, 0, `${label}: unclosed SVG tags: ${tagStack.join(", ")}`);

  const withoutXmlns = svg.replace('xmlns="http://www.w3.org/2000/svg"', "");
  assert.doesNotMatch(withoutXmlns, /https?:\/\/|javascript:|data:/i, `${label}: forbidden external or active URI`);
}

function assertSvgSecurityHeaders(res: Response, label: string): void {
  assert.equal(res.headers.get("content-type"), "image/svg+xml; charset=utf-8", `${label}: content-type`);
  assert.equal(res.headers.get("content-security-policy"), "default-src 'none'; sandbox", `${label}: CSP`);
  assert.equal(res.headers.get("cross-origin-resource-policy"), "cross-origin", `${label}: CORP`);
  assert.equal(res.headers.get("access-control-allow-origin"), "*", `${label}: ACAO`);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff", `${label}: nosniff`);
  assert.equal(res.headers.get("x-frame-options"), "DENY", `${label}: XFO`);
  assert.equal(res.headers.get("referrer-policy"), "no-referrer", `${label}: referrer-policy`);
  assert.equal(res.headers.get("vary"), "Accept-Encoding", `${label}: vary`);
}

describe("First-Party Cloudflare Pages Badge Function (functions/badge/[[path]].js)", () => {
  it("passes node --check syntax gate, LF-only UTF-8 hygiene, and exports all required handlers & helpers", async () => {
    const check = spawnSync(process.execPath, ["--check", BADGE_FN_PATH], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 10000,
      windowsHide: true,
    });
    assert.equal(check.status, 0, `node --check failed:\n${check.stderr}`);

    const raw = readFileSync(BADGE_FN_PATH);
    assert.ok(!raw.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])), "must not contain UTF-8 BOM");
    assert.ok(!raw.includes(Buffer.from("\r\n")), "must use LF line endings only");

    const mod = (await import(BADGE_FN_URL)) as BadgeModule;
    assert.equal(mod.PKG, "coldpin");
    for (const fnName of [
      "escapeXml",
      "formatCompactCount",
      "computeNpmCardMetrics",
      "renderNpmCardSvg",
      "renderNpmDownloadsBadgeSvg",
      "onRequest",
      "onRequestGet",
      "onRequestHead",
    ] as const) {
      assert.equal(typeof mod[fnName], "function", `missing export: ${fnName}`);
    }
  });

  it("computes exact weekly, 30-day monthly, sparkline, and provenance metrics (537 + 84 + 210 = 831) and handles boundary cases", async () => {
    const mod = (await import(BADGE_FN_URL)) as BadgeModule;

    // Exact Coldpin Nov 2026 live attribution data
    const metrics = mod.computeNpmCardMetrics(buildNov2026DownloadsPayload(), buildLiveRegistryPayload());
    assert.equal(metrics.packageName, "coldpin");
    assert.equal(metrics.version, "1.6.0");
    assert.equal(metrics.license, "Apache-2.0");
    assert.equal(metrics.depsCount, 0);
    assert.equal(metrics.provenanceVerified, true);
    assert.equal(metrics.weekly, 831);
    assert.equal(metrics.monthly, 831);
    assert.equal(metrics.endDate, "2026-11-23");
    assert.equal(metrics.sparklineValues.length, 30);
    assert.deepEqual(metrics.sparklineValues.slice(-3), [537, 84, 210]);
    assert.equal(metrics.downloadsAvailable, true);
    assert.equal(metrics.registryAvailable, true);
    assert.equal(metrics.degraded, false);

    // Diverging weekly vs monthly (> 7 active days) and > 31-day cap
    const longSeries = Array.from({ length: 40 }, (_, i) => ({
      day: `2026-11-${String((i % 28) + 1).padStart(2, "0")}`,
      downloads: i >= 33 ? 50 : 10, // last 7 days = 7 * 50 = 350; last 31 days = 24 * 10 + 7 * 50 = 590
    }));
    const capped = mod.computeNpmCardMetrics(
      { end: "2026-11-30", downloads: longSeries },
      buildLiveRegistryPayload({
        version: "1.6.1",
        license: { type: "MIT" },
        dependencies: { a: "^1.0.0", b: "^2.0.0" },
        dist: { attestations: { provenance: { predicateType: "https://example.invalid/v0" } } },
      }),
    );
    assert.equal(capped.sparklineValues.length, 31);
    assert.equal(capped.weekly, 350);
    assert.equal(capped.monthly, 590);
    assert.equal(capped.license, "MIT");
    assert.equal(capped.depsCount, 2);
    assert.equal(capped.provenanceVerified, false);

    // Compact number formatting boundaries
    assert.equal(mod.formatCompactCount(0), "0");
    assert.equal(mod.formatCompactCount(831), "831");
    assert.equal(mod.formatCompactCount(999), "999");
    assert.equal(mod.formatCompactCount(1000), "1k");
    assert.equal(mod.formatCompactCount(1240), "1.2k");
    assert.equal(mod.formatCompactCount(99999), "100k");
    assert.equal(mod.formatCompactCount(999950), "1M");
    assert.equal(mod.formatCompactCount(1500000), "1.5M");
    assert.equal(mod.formatCompactCount(-1), "—");
    assert.equal(mod.formatCompactCount(Number.NaN), "—");
    assert.equal(mod.formatCompactCount(null), "—");

    // Empty / invalid upstream degrades cleanly
    const degraded = mod.computeNpmCardMetrics({ downloads: [] }, null);
    assert.equal(degraded.weekly, null);
    assert.equal(degraded.monthly, null);
    assert.deepEqual(degraded.sparklineValues, []);
    assert.equal(degraded.downloadsAvailable, false);
    assert.equal(degraded.registryAvailable, false);
    assert.equal(degraded.provenanceVerified, false);
    assert.equal(degraded.degraded, true);
  });

  it("XML-escapes injection payloads and renders pure presentation-attribute SVGs with zero <script>, <style>, on*, or external URLs", async () => {
    const mod = (await import(BADGE_FN_URL)) as BadgeModule;

    assert.equal(
      mod.escapeXml(`<script>"'&\u202e\x07`),
      "&lt;script&gt;&quot;&#39;&amp;",
    );

    const poisonedMetrics: Partial<NpmCardMetrics> = {
      packageName: `coldpin"><script>alert(1)</script>`,
      version: `1.6.0" onload="x()`,
      license: `Apache&<img/src=x>`,
      depsCount: 1,
      provenanceVerified: true,
      weekly: 831,
      monthly: 831,
      sparklineValues: [0, 537, 84, 210],
      endDate: "2026-11-23",
      downloadsAvailable: true,
      registryAvailable: true,
      degraded: false,
    };

    for (const theme of ["dark", "light", "invalid-theme"] as const) {
      const cardSvg = mod.renderNpmCardSvg(poisonedMetrics, theme);
      assertSvgSecurityInvariants(cardSvg, `card-${theme}`);
      assert.match(cardSvg, /width="380" height="200" viewBox="0 0 380 200"/);
      assert.match(cardSvg, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
      assert.match(cardSvg, /<polyline points="[^"]+"/);
      assert.match(cardSvg, /1 dep/);
      assert.match(cardSvg, /updated 2026-11-23/);

      const expectedStroke = theme === "light" ? "#0F766E" : "#5EEAD4";
      assert.ok(cardSvg.includes(`stroke="${expectedStroke}"`), `card-${theme}: expected teal sparkline stroke ${expectedStroke}`);

      const pillSvg = mod.renderNpmDownloadsBadgeSvg(poisonedMetrics, theme);
      assertSvgSecurityInvariants(pillSvg, `pill-${theme}`);
      assert.match(pillSvg, /height="20"/);
      assert.match(pillSvg, /831\/week/);
    }

    // Edge sparkline shapes: single-day, all-zeros, and empty degraded
    for (const edgeVals of [[537], [0, 0, 0, 0], []] as const) {
      const edgeSvg = mod.renderNpmCardSvg(
        {
          ...mod.computeNpmCardMetrics(buildNov2026DownloadsPayload(), buildLiveRegistryPayload()),
          sparklineValues: [...edgeVals],
          weekly: edgeVals.length === 0 ? null : edgeVals.reduce((a, b) => a + b, 0),
          monthly: edgeVals.length === 0 ? null : edgeVals.reduce((a, b) => a + b, 0),
          degraded: edgeVals.length === 0,
        },
        "dark",
      );
      assertSvgSecurityInvariants(edgeSvg, `edge-len-${edgeVals.length}`);
    }
  });

  it("enforces strict GET/HEAD method handling (405 + Allow) and strict 2-route allowlist (404) with zero upstream fetches", async () => {
    const mod = (await import(BADGE_FN_URL)) as BadgeModule;
    const origFetch = globalThis.fetch;
    let fetchCalls = 0;

    globalThis.fetch = (async () => {
      fetchCalls += 1;
      throw new Error("fetch must not be called on 405 or 404");
    }) as typeof fetch;

    try {
      for (const method of ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]) {
        const res = await mod.onRequest({
          request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg", { method }),
        });
        assert.equal(res.status, 405, `${method} must return 405`);
        assert.equal(res.headers.get("allow"), "GET, HEAD");
        assert.equal(res.headers.get("cache-control"), "no-store");
        assert.equal(res.headers.get("x-content-type-options"), "nosniff");
        assert.equal(res.headers.get("cross-origin-resource-policy"), "cross-origin");
      }

      for (const badPath of [
        "/badge/",
        "/badge/unknown.svg",
        "/badge/npm-card.svg/",
        "/badge/npm-card.svg/extra",
        "/badge/npm-downloads.svg/x",
        "/other/npm-card.svg",
      ]) {
        const getRes = await mod.onRequest({
          request: new Request(`https://coldpin-docs.pages.dev${badPath}`, { method: "GET" }),
        });
        assert.equal(getRes.status, 404, `GET ${badPath} must return 404`);
        assert.equal(getRes.headers.get("cache-control"), "no-store");

        const headRes = await mod.onRequest({
          request: new Request(`https://coldpin-docs.pages.dev${badPath}`, { method: "HEAD" }),
        });
        assert.equal(headRes.status, 404, `HEAD ${badPath} must return 404`);
        assert.equal(await headRes.text(), "", `HEAD ${badPath} must return empty body`);
      }

      assert.equal(fetchCalls, 0);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("hardcodes coldpin upstream URLs (zero SSRF), validates ?theme, and emits exact security headers on both SVG routes", async () => {
    const mod = (await import(BADGE_FN_URL)) as BadgeModule;
    const origFetch = globalThis.fetch;
    const origCaches = (globalThis as Record<string, unknown>)["caches"];
    const seenRequests: Array<{ url: string; ua: string | null; hasSignal: boolean }> = [];

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const headers = new Headers(init?.headers);
      seenRequests.push({
        url,
        ua: headers.get("user-agent"),
        hasSignal: Boolean(init?.signal),
      });
      if (url === "https://api.npmjs.org/downloads/range/last-month/coldpin") {
        return new Response(JSON.stringify(buildNov2026DownloadsPayload()), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url === "https://registry.npmjs.org/coldpin/latest") {
        return new Response(JSON.stringify(buildLiveRegistryPayload()), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      throw new Error(`Unexpected upstream URL: ${url}`);
    }) as typeof fetch;
    (globalThis as Record<string, unknown>)["caches"] = undefined;

    try {
      // Card route with light theme + untrusted query parameters that must be ignored
      const lightRes = await mod.onRequestGet({
        request: new Request(
          "https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=light&pkg=evil&host=169.254.169.254",
        ),
      });
      assert.equal(lightRes.status, 200);
      assertSvgSecurityHeaders(lightRes, "card-light");
      assert.equal(
        lightRes.headers.get("cache-control"),
        "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400",
      );
      assert.equal(lightRes.headers.get("x-coldpin-badge-state"), "live");
      assert.equal(lightRes.headers.get("x-coldpin-badge-cache"), "MISS");

      const lightSvg = await lightRes.text();
      assertSvgSecurityInvariants(lightSvg, "live-card-light");
      assert.ok(lightSvg.includes('fill="#FFFFFF"'), "light card should use white background");
      assert.ok(lightSvg.includes('stroke="#0F766E"'), "light card should use #0F766E sparkline stroke");
      assert.ok(lightSvg.includes("831/wk"), "card should show 831/wk");
      assert.ok(lightSvg.includes("831/mo"), "card should show 831/mo");
      assert.ok(lightSvg.includes("v1.6.0"), "card should show v1.6.0");
      assert.ok(lightSvg.includes("SLSA Provenance"), "card should show SLSA Provenance");
      assert.ok(lightSvg.includes("0 deps"), "card should show 0 deps");
      assert.ok(lightSvg.includes("Apache-2.0"), "card should show Apache-2.0");
      assert.ok(lightSvg.includes("updated 2026-11-23"), "card should show cutoff date");

      assert.equal(seenRequests.length, 2, "card route must execute strictly 2 parallel upstream fetches");
      assert.deepEqual(
        seenRequests.map((r) => r.url).sort(),
        [
          "https://api.npmjs.org/downloads/range/last-month/coldpin",
          "https://registry.npmjs.org/coldpin/latest",
        ],
      );
      for (const reqInfo of seenRequests) {
        assert.equal(reqInfo.ua, "coldpin-badge/1.6.0 (+https://coldpin-docs.pages.dev)");
        assert.equal(reqInfo.hasSignal, true);
      }

      // Invalid ?theme falls back safely to dark
      seenRequests.length = 0;
      const darkFallbackRes = await mod.onRequestGet({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=neon"),
      });
      const darkSvg = await darkFallbackRes.text();
      assertSvgSecurityInvariants(darkSvg, "live-card-dark-fallback");
      assert.ok(darkSvg.includes('fill="#0D1420"'), "invalid theme must default to dark");
      assert.ok(darkSvg.includes('stroke="#5EEAD4"'), "dark card must use #5EEAD4 sparkline stroke");

      // Compact 20px downloads pill route (strictly 1 fetch to api.npmjs.org)
      seenRequests.length = 0;
      const pillRes = await mod.onRequestGet({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-downloads.svg"),
      });
      assert.equal(pillRes.status, 200);
      assertSvgSecurityHeaders(pillRes, "downloads-pill");
      assert.equal(pillRes.headers.get("x-coldpin-badge-state"), "live");
      const pillSvg = await pillRes.text();
      assertSvgSecurityInvariants(pillSvg, "live-pill");
      assert.ok(pillSvg.includes("831/week"));
      assert.equal(seenRequests.length, 1);
      assert.equal(seenRequests[0]?.url, "https://api.npmjs.org/downloads/range/last-month/coldpin");
    } finally {
      globalThis.fetch = origFetch;
      (globalThis as Record<string, unknown>)["caches"] = origCaches;
    }
  });

  it("performs HEAD-safe caches.default persistence using canonical GET cache keys and serves HIT without re-fetching", async () => {
    const mod = (await import(BADGE_FN_URL)) as BadgeModule;
    const origFetch = globalThis.fetch;
    const origCaches = (globalThis as Record<string, unknown>)["caches"];
    const mockCache = createStrictMockCache();
    let fetchCalls = 0;

    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
      fetchCalls += 1;
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.npmjs.org")) {
        return new Response(JSON.stringify(buildNov2026DownloadsPayload()), { status: 200 });
      }
      return new Response(JSON.stringify(buildLiveRegistryPayload()), { status: 200 });
    }) as typeof fetch;
    (globalThis as Record<string, unknown>)["caches"] = { default: mockCache };

    try {
      const pending: Array<Promise<unknown>> = [];
      const waitUntil = (p: Promise<unknown>) => {
        pending.push(p);
      };

      // Cold HEAD request must never crash caches.default.put() and must return empty body
      const coldHead = await mod.onRequest({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=dark&cachebust=1", {
          method: "HEAD",
        }),
        waitUntil,
      });
      await Promise.all(pending);

      assert.equal(coldHead.status, 200);
      assertSvgSecurityHeaders(coldHead, "cold-head");
      assert.equal(coldHead.headers.get("x-coldpin-badge-cache"), "MISS");
      assert.equal(coldHead.headers.get("x-coldpin-badge-state"), "live");
      assert.ok(Number(coldHead.headers.get("content-length")) > 500, "HEAD must carry byte Content-Length");
      assert.equal(await coldHead.text(), "", "HEAD response body must be empty");
      assert.equal(fetchCalls, 2);
      assert.equal(mockCache.putKeys.length, 1);
      assert.equal(mockCache.putKeys[0]?.method, "GET", "cache key must be canonical GET");
      assert.equal(
        mockCache.putKeys[0]?.url,
        "https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=dark",
        "cache key must strip arbitrary query parameters",
      );
      assert.ok((mockCache.putKeys[0]?.bodyLen ?? 0) > 500, "cached entry must contain full SVG");

      // Subsequent GET with different noise query param hits cache without upstream fetch
      const warmGet = await mod.onRequest({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=dark&other=xyz", {
          method: "GET",
        }),
        waitUntil,
      });
      assert.equal(warmGet.status, 200);
      assertSvgSecurityHeaders(warmGet, "warm-get");
      assert.equal(warmGet.headers.get("x-coldpin-badge-cache"), "HIT");
      assert.equal(warmGet.headers.get("x-coldpin-badge-state"), "live");
      const warmSvg = await warmGet.text();
      assertSvgSecurityInvariants(warmSvg, "warm-get-svg");
      assert.ok(warmSvg.includes("831/wk"));
      assert.equal(fetchCalls, 2, "cache HIT must not re-fetch upstream");

      // Subsequent HEAD hits cache with empty body and zero upstream fetches
      const warmHead = await mod.onRequestHead({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg", { method: "HEAD" }),
        waitUntil,
      });
      assert.equal(warmHead.status, 200);
      assert.equal(warmHead.headers.get("x-coldpin-badge-cache"), "HIT");
      assert.equal(await warmHead.text(), "");
      assert.equal(fetchCalls, 2);
    } finally {
      globalThis.fetch = origFetch;
      (globalThis as Record<string, unknown>)["caches"] = origCaches;
    }
  });

  it("returns graceful HTTP 200 image/svg+xml degraded fallback (max-age=300) on upstream 429, 503, and timeout", async () => {
    const mod = (await import(BADGE_FN_URL)) as BadgeModule;
    const origFetch = globalThis.fetch;
    const origCaches = (globalThis as Record<string, unknown>)["caches"];
    (globalThis as Record<string, unknown>)["caches"] = undefined;

    try {
      // Case 1: api.npmjs.org returns 429, registry succeeds
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("api.npmjs.org")) {
          return new Response("Rate Limited", { status: 429 });
        }
        return new Response(JSON.stringify(buildLiveRegistryPayload()), { status: 200 });
      }) as typeof fetch;

      const rateLimited = await mod.onRequestGet({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg"),
      });
      assert.equal(rateLimited.status, 200);
      assertSvgSecurityHeaders(rateLimited, "degraded-429");
      assert.equal(rateLimited.headers.get("cache-control"), "public, max-age=300, s-maxage=300");
      assert.equal(rateLimited.headers.get("x-coldpin-badge-state"), "degraded");
      const rateLimitedSvg = await rateLimited.text();
      assertSvgSecurityInvariants(rateLimitedSvg, "degraded-429-svg");
      assert.ok(rateLimitedSvg.includes("Live stats unavailable"));
      assert.ok(rateLimitedSvg.includes("SLSA Provenance"), "registry data should still render when only downloads failed");

      // Case 2: both upstreams time out
      globalThis.fetch = (async (): Promise<Response> => {
        throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
      }) as typeof fetch;

      const timedOut = await mod.onRequestGet({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=light"),
      });
      assert.equal(timedOut.status, 200);
      assertSvgSecurityHeaders(timedOut, "degraded-timeout");
      assert.equal(timedOut.headers.get("cache-control"), "public, max-age=300, s-maxage=300");
      assert.equal(timedOut.headers.get("x-coldpin-badge-state"), "degraded");
      const timedOutSvg = await timedOut.text();
      assertSvgSecurityInvariants(timedOutSvg, "degraded-timeout-svg");
      assert.ok(timedOutSvg.includes("Registry fallback"));
      assert.ok(timedOutSvg.includes("Live stats unavailable"));
      assert.ok(!timedOutSvg.includes("SLSA Provenance"), "must not claim verified provenance when registry failed");

      // Case 3: compact downloads pill degraded on 503
      globalThis.fetch = (async (): Promise<Response> => new Response("Service Unavailable", { status: 503 })) as typeof fetch;

      const degradedPill = await mod.onRequestGet({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-downloads.svg"),
      });
      assert.equal(degradedPill.status, 200);
      assertSvgSecurityHeaders(degradedPill, "degraded-pill");
      assert.equal(degradedPill.headers.get("cache-control"), "public, max-age=300, s-maxage=300");
      assert.equal(degradedPill.headers.get("x-coldpin-badge-state"), "degraded");
      const pillSvg = await degradedPill.text();
      assertSvgSecurityInvariants(pillSvg, "degraded-pill-svg");
      assert.ok(pillSvg.includes("unavailable"));

      // Case 4: registry returns 429 while api.npmjs.org succeeds -> live counts preserved, registry fallback honest
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("api.npmjs.org")) {
          return new Response(JSON.stringify(buildNov2026DownloadsPayload()), { status: 200 });
        }
        return new Response("Too Many Requests", { status: 429 });
      }) as typeof fetch;

      const regDown = await mod.onRequestGet({
        request: new Request("https://coldpin-docs.pages.dev/badge/npm-card.svg"),
      });
      assert.equal(regDown.status, 200);
      assertSvgSecurityHeaders(regDown, "degraded-registry-429");
      assert.equal(regDown.headers.get("cache-control"), "public, max-age=300, s-maxage=300");
      assert.equal(regDown.headers.get("x-coldpin-badge-state"), "degraded");
      const regDownSvg = await regDown.text();
      assertSvgSecurityInvariants(regDownSvg, "degraded-registry-429-svg");
      assert.ok(regDownSvg.includes("831/wk"), "live downloads must still render when only registry fails");
      assert.ok(regDownSvg.includes("Registry fallback"), "must indicate fallback registry state");
      assert.ok(!regDownSvg.includes("SLSA Provenance"), "must not claim verified provenance when registry fails");
    } finally {
      globalThis.fetch = origFetch;
      (globalThis as Record<string, unknown>)["caches"] = origCaches;
    }
  });
});
