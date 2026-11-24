/**
 * Coldpin First-Party Official npmjs.com Package Card & Downloads Pill
 * Cloudflare Pages Function: `/badge/npm-card.svg` and `/badge/npm-downloads.svg`
 *
 * Security & Architecture Invariants:
 * - Zero npm runtime dependencies; pure standard Web Fetch / Cache APIs.
 * - Hardcoded package (`coldpin`) -> zero SSRF or open-proxy surface.
 * - Strictly GET / HEAD (`405` otherwise); strictly two allowlisted routes (`404` otherwise).
 * - `?theme=` strictly allowlisted to `light` | `dark` (default `dark`).
 * - HEAD-safe canonical GET cache key in `caches.default` via `context.waitUntil()`.
 * - Graceful HTTP 200 `image/svg+xml` degraded fallback on upstream 429/5xx/timeout.
 * - Pure SVG presentation attributes only: zero <style>, zero <script>, zero on*, zero external URLs.
 */

export const PKG = "coldpin";
export const FALLBACK_VERSION = "1.6.0";
export const FALLBACK_LICENSE = "Apache-2.0";

const CANONICAL_ORIGIN = "https://coldpin-docs.pages.dev";
const DOWNLOADS_URL = `https://api.npmjs.org/downloads/range/last-month/${PKG}`;
const REGISTRY_URL = `https://registry.npmjs.org/${PKG}/latest`;
const USER_AGENT = `coldpin-badge/${FALLBACK_VERSION} (+${CANONICAL_ORIGIN})`;
const UPSTREAM_TIMEOUT_MS = 4000;
const LIVE_CACHE_CONTROL = "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400";
const DEGRADED_CACHE_CONTROL = "public, max-age=300, s-maxage=300";
const SLSA_V1_PREDICATE = "https://slsa.dev/provenance/v1";

const ROUTE_CARD = "/badge/npm-card.svg";
const ROUTE_DOWNLOADS = "/badge/npm-downloads.svg";
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const UNSAFE_CHAR_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad]/g;
const FONT_SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
const FONT_MONO = "ui-monospace, 'Cascadia Mono', 'SFMono-Regular', Menlo, Consolas, monospace";

const BASE_SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": "default-src 'none'; sandbox",
  "Cross-Origin-Resource-Policy": "cross-origin",
  "Access-Control-Allow-Origin": "*",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
});

const THEMES = Object.freeze({
  dark: Object.freeze({
    cardBg: "#0D1420",
    cardBorder: "#1E293B",
    panelBg: "#131C2B",
    panelBorder: "#243247",
    divider: "#1E293B",
    inkPrimary: "#F8FAFC",
    inkSecondary: "#CBD5E1",
    inkMuted: "#94A3B8",
    accent: "#5EEAD4",
    accentSoftBg: "#0A2E2B",
    accentSoftBorder: "#134E4A",
    accentAreaOpacity: "0.16",
    pillBg: "#162032",
    pillBorder: "#263449",
    pillText: "#CBD5E1",
    versionBg: "#132A2E",
    versionBorder: "#1D4D4F",
    versionText: "#5EEAD4",
    warnBg: "#2B210B",
    warnBorder: "#6B4E16",
    warnText: "#FCD34D",
    gridLine: "#29384D",
    npmBg: "#CB3837",
    npmText: "#FFFFFF",
    badgeLeftBg: "#1E293B",
    badgeRightBg: "#0F766E",
    badgeDegradedBg: "#475569",
  }),
  light: Object.freeze({
    cardBg: "#FFFFFF",
    cardBorder: "#CBD5E1",
    panelBg: "#F8FAFC",
    panelBorder: "#E2E8F0",
    divider: "#E2E8F0",
    inkPrimary: "#0D1420",
    inkSecondary: "#334155",
    inkMuted: "#475569",
    accent: "#0F766E",
    accentSoftBg: "#E6F7F5",
    accentSoftBorder: "#99F6E4",
    accentAreaOpacity: "0.12",
    pillBg: "#F1F5F9",
    pillBorder: "#CBD5E1",
    pillText: "#334155",
    versionBg: "#E6F7F5",
    versionBorder: "#99F6E4",
    versionText: "#0F766E",
    warnBg: "#FFFBEB",
    warnBorder: "#FDE68A",
    warnText: "#92400E",
    gridLine: "#CBD5E1",
    npmBg: "#CB3837",
    npmText: "#FFFFFF",
    badgeLeftBg: "#334155",
    badgeRightBg: "#0F766E",
    badgeDegradedBg: "#64748B",
  }),
});

/**
 * Escapes arbitrary strings for safe XML/SVG text and attribute interpolation.
 * Also strips ASCII control characters and hidden/bidi Unicode.
 */
export function escapeXml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(UNSAFE_CHAR_RE, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Formats non-negative download counts into compact human-readable badges.
 * Examples: 0 -> "0", 831 -> "831", 1200 -> "1.2k", 999950 -> "1M", 1500000 -> "1.5M".
 */
export function formatCompactCount(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return "—";
  }
  const n = Math.floor(value);
  if (n < 1_000) return String(n);
  if (n < 1_000_000) {
    if (n >= 100_000) {
      const rounded = Math.round(n / 1_000);
      return rounded >= 1_000 ? "1M" : `${rounded}k`;
    }
    const scaled = Math.round((n / 1_000) * 10) / 10;
    if (scaled >= 1_000) return "1M";
    return `${Number.isInteger(scaled) ? scaled.toFixed(0) : scaled.toFixed(1)}k`;
  }
  if (n < 1_000_000_000) {
    if (n >= 100_000_000) {
      const rounded = Math.round(n / 1_000_000);
      return rounded >= 1_000 ? "1B" : `${rounded}M`;
    }
    const scaled = Math.round((n / 1_000_000) * 10) / 10;
    if (scaled >= 1_000) return "1B";
    return `${Number.isInteger(scaled) ? scaled.toFixed(0) : scaled.toFixed(1)}M`;
  }
  const scaled = Math.round((n / 1_000_000_000) * 10) / 10;
  return `${Number.isInteger(scaled) ? scaled.toFixed(0) : scaled.toFixed(1)}B`;
}

function normalizeTheme(theme) {
  return theme === "light" ? "light" : "dark";
}

function clampLabel(raw, maxLen) {
  const clean = String(raw ?? "").replace(UNSAFE_CHAR_RE, "").trim();
  if (clean.length <= maxLen) return clean;
  return `${clean.slice(0, Math.max(1, maxLen - 1))}…`;
}

/**
 * Pure metric calculation from `api.npmjs.org/downloads/range/last-month/coldpin`
 * and `registry.npmjs.org/coldpin/latest`.
 */
export function computeNpmCardMetrics(downloadsJson, registryJson) {
  const rawEntries =
    downloadsJson && typeof downloadsJson === "object" && Array.isArray(downloadsJson.downloads)
      ? downloadsJson.downloads
      : [];

  const validDaily = [];
  for (const entry of rawEntries) {
    if (
      entry &&
      typeof entry === "object" &&
      typeof entry.downloads === "number" &&
      Number.isFinite(entry.downloads) &&
      entry.downloads >= 0
    ) {
      validDaily.push({
        day: typeof entry.day === "string" && ISO_DATE_RE.test(entry.day) ? entry.day : null,
        downloads: Math.floor(entry.downloads),
      });
    }
  }

  const boundedDaily = validDaily.slice(-31);
  const downloadsAvailable = boundedDaily.length > 0;
  const weekly = downloadsAvailable
    ? boundedDaily.slice(-7).reduce((sum, item) => sum + item.downloads, 0)
    : null;
  const monthly = downloadsAvailable
    ? boundedDaily.reduce((sum, item) => sum + item.downloads, 0)
    : null;
  const sparklineValues = boundedDaily.map((item) => item.downloads);

  let endDate = null;
  if (downloadsJson && typeof downloadsJson === "object" && typeof downloadsJson.end === "string" && ISO_DATE_RE.test(downloadsJson.end)) {
    endDate = downloadsJson.end;
  } else {
    for (let i = boundedDaily.length - 1; i >= 0; i -= 1) {
      if (boundedDaily[i].day) {
        endDate = boundedDaily[i].day;
        break;
      }
    }
  }

  const hasRegistry = Boolean(registryJson && typeof registryJson === "object" && !Array.isArray(registryJson));
  const rawVersion = hasRegistry && typeof registryJson.version === "string" ? registryJson.version.replace(UNSAFE_CHAR_RE, "").trim() : "";
  const registryAvailable = rawVersion.length > 0;
  const version = registryAvailable ? clampLabel(rawVersion, 24) : FALLBACK_VERSION;

  let license = FALLBACK_LICENSE;
  if (hasRegistry) {
    if (typeof registryJson.license === "string" && registryJson.license.trim()) {
      license = clampLabel(registryJson.license, 18);
    } else if (
      registryJson.license &&
      typeof registryJson.license === "object" &&
      typeof registryJson.license.type === "string" &&
      registryJson.license.type.trim()
    ) {
      license = clampLabel(registryJson.license.type, 18);
    }
  }

  const depsCount =
    hasRegistry &&
    registryJson.dependencies &&
    typeof registryJson.dependencies === "object" &&
    !Array.isArray(registryJson.dependencies)
      ? Object.keys(registryJson.dependencies).length
      : 0;

  const provenanceVerified = Boolean(
    registryAvailable &&
      registryJson?.dist?.attestations?.provenance?.predicateType === SLSA_V1_PREDICATE,
  );

  return {
    packageName: PKG,
    version,
    license,
    depsCount,
    provenanceVerified,
    weekly,
    monthly,
    sparklineValues,
    endDate,
    downloadsAvailable,
    registryAvailable,
    degraded: !downloadsAvailable || !registryAvailable,
  };
}

function buildSparklineElements(values, palette) {
  const xMin = 240;
  const xMax = 350;
  const yTop = 109;
  const yBottom = 143;

  const baseline = `<line x1="${xMin}" y1="${yBottom}" x2="${xMax}" y2="${yBottom}" stroke="${palette.gridLine}" stroke-width="1" stroke-dasharray="2 2"/>`;

  if (!Array.isArray(values) || values.length === 0) {
    return [
      baseline,
      `<line x1="${xMin}" y1="126" x2="${xMax}" y2="126" stroke="${palette.gridLine}" stroke-width="1.25" stroke-dasharray="3 3"/>`,
      `<text x="295" y="122" text-anchor="middle" fill="${palette.inkMuted}" font-family="${FONT_SANS}" font-size="10">n/a</text>`,
    ].join("");
  }

  const clean = values.map((v) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0));

  if (clean.length === 1) {
    const y = clean[0] > 0 ? 126 : yBottom;
    const pts = `${xMin.toFixed(1)},${y.toFixed(1)} ${xMax.toFixed(1)},${y.toFixed(1)}`;
    return [
      baseline,
      `<polyline points="${pts}" fill="none" stroke="${palette.accent}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`,
      `<circle cx="${xMax.toFixed(1)}" cy="${y.toFixed(1)}" r="2.75" fill="${palette.accent}"/>`,
    ].join("");
  }

  const maxVal = Math.max(...clean);
  const spanX = xMax - xMin;
  const spanY = yBottom - yTop;
  const denom = clean.length - 1;

  const coords = clean.map((v, idx) => {
    const x = xMin + (idx / denom) * spanX;
    const y = maxVal > 0 ? yBottom - (v / maxVal) * spanY : yBottom;
    return [x.toFixed(1), y.toFixed(1)];
  });

  const polylinePts = coords.map(([x, y]) => `${x},${y}`).join(" ");
  const areaPts = `${xMin.toFixed(1)},${yBottom.toFixed(1)} ${polylinePts} ${xMax.toFixed(1)},${yBottom.toFixed(1)}`;
  const [lastX, lastY] = coords[coords.length - 1];

  return [
    baseline,
    `<polygon points="${areaPts}" fill="${palette.accent}" fill-opacity="${palette.accentAreaOpacity}"/>`,
    `<polyline points="${polylinePts}" fill="none" stroke="${palette.accent}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`,
    `<circle cx="${lastX}" cy="${lastY}" r="2.75" fill="${palette.accent}"/>`,
  ].join("");
}

/**
 * Renders the 380x200 Official npmjs.com Package Card SVG.
 * Pure SVG presentation attributes only (zero <style>, <script>, on*, or external URLs).
 */
export function renderNpmCardSvg(metrics, theme = "dark") {
  const mode = normalizeTheme(theme);
  const t = THEMES[mode];

  const pkgText = escapeXml(metrics?.packageName || PKG);
  const rawVer = clampLabel(metrics?.version || FALLBACK_VERSION, 16);
  const verLabel = `v${rawVer}`;
  const verText = escapeXml(verLabel);
  const licenseRaw = clampLabel(metrics?.license || FALLBACK_LICENSE, 16);
  const licenseText = escapeXml(licenseRaw);

  const depsNum =
    typeof metrics?.depsCount === "number" && Number.isFinite(metrics.depsCount) && metrics.depsCount >= 0
      ? Math.floor(metrics.depsCount)
      : 0;
  const depsLabel = `${depsNum} ${depsNum === 1 ? "dep" : "deps"}`;
  const depsText = escapeXml(depsLabel);

  const provenanceVerified = Boolean(metrics?.provenanceVerified);
  const registryAvailable = metrics?.registryAvailable !== false;
  const hasDownloads = typeof metrics?.weekly === "number" && Number.isFinite(metrics.weekly);

  const weeklyStr = hasDownloads ? formatCompactCount(metrics.weekly) : null;
  const monthlyStr =
    typeof metrics?.monthly === "number" && Number.isFinite(metrics.monthly)
      ? formatCompactCount(metrics.monthly)
      : weeklyStr;

  const endDate =
    typeof metrics?.endDate === "string" && ISO_DATE_RE.test(metrics.endDate) ? metrics.endDate : null;

  // Dynamic pill widths kept comfortably within x = 18..362
  const verPillX = 124;
  const verPillW = Math.max(48, Math.min(110, Math.round(verLabel.length * 6.8 + 16)));

  const provX = 18;
  let provW;
  let provFill;
  let provStroke;
  let provInk;
  let provMarkup;

  if (provenanceVerified) {
    provW = 118;
    provFill = t.accentSoftBg;
    provStroke = t.accentSoftBorder;
    provInk = t.accent;
    provMarkup =
      `<rect x="${provX}" y="66" width="${provW}" height="22" rx="11" fill="${provFill}" stroke="${provStroke}" stroke-width="1"/>` +
      `<path d="M27.5 77.2 L30.3 80 L35.5 74.5" fill="none" stroke="${provInk}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>` +
      `<text x="41" y="80.5" fill="${provInk}" font-family="${FONT_SANS}" font-size="10.5" font-weight="600">SLSA Provenance</text>`;
  } else if (!registryAvailable) {
    provW = 110;
    provFill = t.warnBg;
    provStroke = t.warnBorder;
    provInk = t.warnText;
    provMarkup =
      `<rect x="${provX}" y="66" width="${provW}" height="22" rx="11" fill="${provFill}" stroke="${provStroke}" stroke-width="1"/>` +
      `<text x="${provX + provW / 2}" y="80.5" text-anchor="middle" fill="${provInk}" font-family="${FONT_SANS}" font-size="10.5" font-weight="600">Registry fallback</text>`;
  } else {
    provW = 112;
    provFill = t.pillBg;
    provStroke = t.pillBorder;
    provInk = t.pillText;
    provMarkup =
      `<rect x="${provX}" y="66" width="${provW}" height="22" rx="11" fill="${provFill}" stroke="${provStroke}" stroke-width="1"/>` +
      `<text x="${provX + provW / 2}" y="80.5" text-anchor="middle" fill="${provInk}" font-family="${FONT_SANS}" font-size="10.5" font-weight="600">No SLSA attest.</text>`;
  }

  const depsX = provX + provW + 8;
  const depsW = Math.max(52, Math.min(82, Math.round(depsLabel.length * 6.5 + 18)));
  const licX = depsX + depsW + 8;
  const maxLicW = Math.max(54, 362 - licX);
  const licW = Math.max(54, Math.min(maxLicW, Math.round(licenseRaw.length * 6.4 + 18)));

  const statsMarkup = hasDownloads
    ? `<text x="30" y="122" fill="${t.inkPrimary}" font-family="${FONT_SANS}" font-size="15.5" font-weight="700">` +
      `<tspan fill="${t.accent}">&#x2193;</tspan> ${escapeXml(weeklyStr)}/wk` +
      `<tspan fill="${t.inkMuted}" font-size="12.5" font-weight="500"> &#xB7; ${escapeXml(monthlyStr)}/mo</tspan>` +
      `</text>` +
      `<text x="30" y="141" fill="${t.inkMuted}" font-family="${FONT_SANS}" font-size="10.5">30-day downloads &#xB7; api.npmjs.org</text>`
    : `<text x="30" y="122" fill="${t.warnText}" font-family="${FONT_SANS}" font-size="13.5" font-weight="600">Live stats unavailable</text>` +
      `<text x="30" y="141" fill="${t.inkMuted}" font-family="${FONT_SANS}" font-size="10.5">npmjs.com fallback &#xB7; retry pending</text>`;

  const sparklineMarkup = buildSparklineElements(
    hasDownloads ? metrics?.sparklineValues : [],
    t,
  );

  const footerRight = endDate
    ? `updated ${escapeXml(endDate)}`
    : metrics?.degraded
      ? "cached fallback"
      : "live registry";

  const summaryDownloads = hasDownloads
    ? `${weeklyStr} weekly and ${monthlyStr} 30-day downloads`
    : "live download stats temporarily unavailable";
  const provDesc = provenanceVerified ? "verified SLSA v1 provenance" : "unverified provenance";
  const ariaLabel = escapeXml(
    `${metrics?.packageName || PKG} ${verLabel} on official npmjs.com registry: ${summaryDownloads}, ${depsLabel}, ${licenseRaw} license, ${provDesc}`,
  );
  const titleText = escapeXml(`${metrics?.packageName || PKG} ${verLabel} — Official npmjs.com Package Card`);
  const descText = escapeXml(
    `Official npmjs.com package statistics for ${metrics?.packageName || PKG} (${verLabel}): ${summaryDownloads}, ${depsLabel}, ${licenseRaw}, ${provDesc}${endDate ? `, data through ${endDate}` : ""}.`,
  );

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="380" height="200" viewBox="0 0 380 200" role="img" aria-label="${ariaLabel}">`,
    `<title>${titleText}</title>`,
    `<desc>${descText}</desc>`,
    `<rect x="0.75" y="0.75" width="378.5" height="198.5" rx="12" fill="${t.cardBg}" stroke="${t.cardBorder}" stroke-width="1.5"/>`,
    `<g transform="translate(18 18) scale(0.5)">`,
    `<rect width="64" height="64" rx="14" fill="#0F766E"/>`,
    `<path d="M32 10 L50 18 V32 C50 43.5 42.2 52.4 32 56 C21.8 52.4 14 43.5 14 32 V18 Z" fill="none" stroke="#FFFFFF" stroke-width="3.5" stroke-linejoin="round"/>`,
    `<path d="M24 32.5 L29.5 38 L41 26" fill="none" stroke="#5EEAD4" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>`,
    `</g>`,
    `<text x="60" y="34" fill="${t.inkPrimary}" font-family="${FONT_SANS}" font-size="16" font-weight="700">${pkgText}</text>`,
    `<rect x="${verPillX}" y="19" width="${verPillW}" height="19" rx="9.5" fill="${t.versionBg}" stroke="${t.versionBorder}" stroke-width="1"/>`,
    `<text x="${verPillX + verPillW / 2}" y="32" text-anchor="middle" fill="${t.versionText}" font-family="${FONT_MONO}" font-size="10.5" font-weight="600">${verText}</text>`,
    `<text x="60" y="50" fill="${t.inkMuted}" font-family="${FONT_SANS}" font-size="11">official npmjs.com registry</text>`,
    `<rect x="314" y="19" width="48" height="21" rx="5" fill="${t.npmBg}"/>`,
    `<text x="338" y="33.5" text-anchor="middle" fill="${t.npmText}" font-family="${FONT_SANS}" font-size="11.5" font-weight="700" letter-spacing="0.2">npm</text>`,
    provMarkup,
    `<rect x="${depsX}" y="66" width="${depsW}" height="22" rx="11" fill="${t.pillBg}" stroke="${t.pillBorder}" stroke-width="1"/>`,
    `<text x="${depsX + depsW / 2}" y="80.5" text-anchor="middle" fill="${t.pillText}" font-family="${FONT_SANS}" font-size="10.5" font-weight="500">${depsText}</text>`,
    `<rect x="${licX}" y="66" width="${licW}" height="22" rx="11" fill="${t.pillBg}" stroke="${t.pillBorder}" stroke-width="1"/>`,
    `<text x="${licX + licW / 2}" y="80.5" text-anchor="middle" fill="${t.pillText}" font-family="${FONT_SANS}" font-size="10.5" font-weight="500">${licenseText}</text>`,
    `<rect x="18" y="98" width="344" height="56" rx="8" fill="${t.panelBg}" stroke="${t.panelBorder}" stroke-width="1"/>`,
    statsMarkup,
    sparklineMarkup,
    `<line x1="18" y1="166" x2="362" y2="166" stroke="${t.divider}" stroke-width="1"/>`,
    `<text x="18" y="184" fill="${t.inkMuted}" font-family="${FONT_SANS}" font-size="10.5">Node &gt;= 24 &#xB7; CLI + MCP &#xB7; npmjs.com</text>`,
    `<text x="362" y="184" text-anchor="end" fill="${t.inkMuted}" font-family="${FONT_SANS}" font-size="10.5">${footerRight}</text>`,
    `</svg>`,
  ].join("");
}

/**
 * Renders the compact 20px first-party weekly npmjs downloads pill SVG.
 * Pure SVG presentation attributes only (zero <style>, <script>, on*, or external URLs).
 */
export function renderNpmDownloadsBadgeSvg(metrics, theme = "dark") {
  const mode = normalizeTheme(theme);
  const t = THEMES[mode];

  const hasDownloads = typeof metrics?.weekly === "number" && Number.isFinite(metrics.weekly);
  const labelText = "npmjs downloads";
  const valueText = hasDownloads ? `${formatCompactCount(metrics.weekly)}/week` : "unavailable";
  const rightFill = hasDownloads ? t.badgeRightBg : t.badgeDegradedBg;

  const leftW = 108;
  const rightW = Math.max(66, Math.round(valueText.length * 6.5 + 16));
  const totalW = leftW + rightW;

  const ariaLabel = escapeXml(`${labelText}: ${valueText}`);
  const titleText = escapeXml(`${metrics?.packageName || PKG} ${labelText}: ${valueText}`);
  const descText = escapeXml(
    `Weekly downloads for ${metrics?.packageName || PKG} from official npmjs.com registry: ${valueText}.`,
  );

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="20" viewBox="0 0 ${totalW} 20" role="img" aria-label="${ariaLabel}">`,
    `<title>${titleText}</title>`,
    `<desc>${descText}</desc>`,
    `<rect width="${totalW}" height="20" rx="3" fill="${t.badgeLeftBg}"/>`,
    `<rect x="${leftW}" width="${rightW}" height="20" rx="3" fill="${rightFill}"/>`,
    `<rect x="${leftW}" width="4" height="20" fill="${rightFill}"/>`,
    `<text x="${(leftW / 2).toFixed(1)}" y="14" text-anchor="middle" fill="#FFFFFF" font-family="${FONT_SANS}" font-size="11" font-weight="500">${escapeXml(labelText)}</text>`,
    `<text x="${(leftW + rightW / 2).toFixed(1)}" y="14" text-anchor="middle" fill="#FFFFFF" font-family="${FONT_SANS}" font-size="11" font-weight="700">${escapeXml(valueText)}</text>`,
    `</svg>`,
  ].join("");
}

async function fetchUpstreamJson(url) {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    },
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Upstream HTTP ${response.status}`);
  }
  return await response.json();
}

function buildTextErrorResponse(status, message, extraHeaders = {}, isHead = false) {
  const headers = new Headers({
    ...BASE_SECURITY_HEADERS,
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  return new Response(isHead ? null : message, { status, headers });
}

async function handleReadRequest(context, isHead) {
  let parsedUrl;
  try {
    parsedUrl = new URL(context.request.url);
  } catch {
    return buildTextErrorResponse(404, "Not Found", {}, isHead);
  }

  const pathname = parsedUrl.pathname;
  if (pathname !== ROUTE_CARD && pathname !== ROUTE_DOWNLOADS) {
    return buildTextErrorResponse(404, "Not Found", {}, isHead);
  }

  const theme = normalizeTheme(parsedUrl.searchParams.get("theme"));
  const canonicalUrl = `${CANONICAL_ORIGIN}${pathname}?theme=${theme}`;
  const cacheKey = new Request(canonicalUrl, { method: "GET" });
  const cache = globalThis.caches?.default ?? null;

  if (cache) {
    try {
      const cached = await cache.match(cacheKey);
      if (cached) {
        const hitHeaders = new Headers(cached.headers);
        hitHeaders.set("X-Coldpin-Badge-Cache", "HIT");
        if (isHead) {
          return new Response(null, { status: cached.status, headers: hitHeaders });
        }
        return new Response(cached.body, { status: cached.status, headers: hitHeaders });
      }
    } catch {
      // Cache read failure must never block badge rendering
    }
  }

  const isCard = pathname === ROUTE_CARD;
  let downloadsJson = null;
  let registryJson = null;

  if (isCard) {
    const [downloadsRes, registryRes] = await Promise.allSettled([
      fetchUpstreamJson(DOWNLOADS_URL),
      fetchUpstreamJson(REGISTRY_URL),
    ]);
    downloadsJson = downloadsRes.status === "fulfilled" ? downloadsRes.value : null;
    registryJson = registryRes.status === "fulfilled" ? registryRes.value : null;
  } else {
    const [downloadsRes] = await Promise.allSettled([fetchUpstreamJson(DOWNLOADS_URL)]);
    downloadsJson = downloadsRes.status === "fulfilled" ? downloadsRes.value : null;
  }

  const metrics = computeNpmCardMetrics(downloadsJson, registryJson);
  const isDegraded = isCard ? metrics.degraded : !metrics.downloadsAvailable;
  const svg = isCard
    ? renderNpmCardSvg(metrics, theme)
    : renderNpmDownloadsBadgeSvg(metrics, theme);

  const byteLength = String(new TextEncoder().encode(svg).byteLength);
  const baseHeaders = {
    ...BASE_SECURITY_HEADERS,
    "Content-Type": "image/svg+xml; charset=utf-8",
    "Content-Length": byteLength,
    "Vary": "Accept-Encoding",
    "Cache-Control": isDegraded ? DEGRADED_CACHE_CONTROL : LIVE_CACHE_CONTROL,
    "X-Coldpin-Badge-State": isDegraded ? "degraded" : "live",
  };

  if (cache) {
    const cacheHeaders = new Headers({
      ...baseHeaders,
      "X-Coldpin-Badge-Cache": "HIT",
    });
    const responseToCache = new Response(svg, { status: 200, headers: cacheHeaders });
    const putPromise = Promise.resolve()
      .then(() => cache.put(cacheKey, responseToCache))
      .catch(() => {});
    if (typeof context?.waitUntil === "function") {
      context.waitUntil(putPromise);
    } else {
      await putPromise;
    }
  }

  const clientHeaders = new Headers({
    ...baseHeaders,
    "X-Coldpin-Badge-Cache": "MISS",
  });

  if (isHead) {
    return new Response(null, { status: 200, headers: clientHeaders });
  }
  return new Response(svg, { status: 200, headers: clientHeaders });
}

export async function onRequestGet(context) {
  return handleReadRequest(context, false);
}

export async function onRequestHead(context) {
  return handleReadRequest(context, true);
}

export async function onRequest(context) {
  const method = String(context?.request?.method || "").toUpperCase();
  if (method === "GET") return onRequestGet(context);
  if (method === "HEAD") return onRequestHead(context);
  return buildTextErrorResponse(405, "Method Not Allowed", { Allow: "GET, HEAD" });
}
