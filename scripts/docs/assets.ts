import { META_CSP } from "./renderer.ts";
import type { RepoMetrics } from "./types.ts";

export function renderHeadersFile(): string {
  const edgeCsp = `${META_CSP} frame-ancestors 'none'; upgrade-insecure-requests`;
  return `# Cloudflare Pages HTTP security & caching headers for Coldpin Docs (site/)
# Applies automatically when deploying \`site\` as the static output directory.
# Kept strictly synchronized with every HTML page's <meta http-equiv="Content-Security-Policy">.

/*
  Content-Security-Policy: ${edgeCsp}
  Strict-Transport-Security: max-age=31536000
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  X-Permitted-Cross-Domain-Policies: none

# Sandboxed SEP-1865 MCP App live preview frame (still zero 'unsafe-inline', default-src 'none')
# Cover all three Cloudflare Pages path forms so Pretty URLs never inherit /* frame-ancestors 'none'.
/evidence-card-app
  ! Content-Security-Policy
  ! X-Frame-Options
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; upgrade-insecure-requests
  X-Frame-Options: SAMEORIGIN
  Cache-Control: public, max-age=0, must-revalidate

/evidence-card-app/
  ! Content-Security-Policy
  ! X-Frame-Options
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; upgrade-insecure-requests
  X-Frame-Options: SAMEORIGIN
  Cache-Control: public, max-age=0, must-revalidate

/evidence-card-app/index.html
  ! Content-Security-Policy
  ! X-Frame-Options
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; upgrade-insecure-requests
  X-Frame-Options: SAMEORIGIN
  Cache-Control: public, max-age=0, must-revalidate

/docs/*.md
  Content-Type: text/markdown; charset=utf-8
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/llms.txt
  Content-Type: text/plain; charset=utf-8
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/robots.txt
  Content-Type: text/plain; charset=utf-8
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/search-index.json
  Content-Type: application/json; charset=utf-8
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/sitemap.xml
  Content-Type: application/xml; charset=utf-8
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/styles.css
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/app.js
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/theme-init.js
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/hook-eval.js
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/evidence-card-app.css
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/evidence-card-app.js
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400

/icon.svg
  Cache-Control: public, max-age=86400, stale-while-revalidate=604800
`;
}

export function renderThemeInitJs(m: RepoMetrics): string {
  return `/* Coldpin Docs Anti-FOUC 3-Way Theme Bootstrap & Legacy #hash Redirect Shim
 * Blocking external script under strict zero-'unsafe-inline' CSP.
 */
(function () {
  "use strict";
  var root = document.documentElement;
  var mode = "auto";
  try {
    var saved = window.localStorage.getItem("coldpin-docs-theme-mode");
    if (saved === "auto" || saved === "light" || saved === "dark") {
      mode = saved;
    } else {
      var legacy = window.localStorage.getItem("coldpin-docs-theme");
      if (legacy === "light" || legacy === "dark") mode = legacy;
    }
    if (window.localStorage.getItem("coldpin-docs-announce-v${m.version}") === "dismissed") {
      root.setAttribute("data-announce-dismissed", "true");
    }
  } catch (_) {}

  var prefersDark = false;
  try {
    prefersDark = Boolean(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  } catch (_) {}
  var resolved = mode === "auto" ? (prefersDark ? "dark" : "light") : mode;
  root.setAttribute("data-theme-mode", mode);
  root.setAttribute("data-theme", resolved);

  if (root.getAttribute("data-page-slug") === "overview" && window.location && window.location.hash) {
    var h = window.location.hash.toLowerCase();
    var map = {
      "#quickstart": "./docs/quickstart/",
      "#simulator": "./docs/policy-lab/",
      "#policy-lab": "./docs/policy-lab/",
      "#antigravity-plugin": "./docs/antigravity-plugin/",
      "#agents-and-hooks": "./docs/agents-and-rules/",
      "#hooks": "./docs/hooks/",
      "#slash-commands": "./docs/slash-commands/",
      "#mcp-and-cli": "./docs/mcp-tools/",
      "#cli": "./docs/cli-reference/",
      "#enterprise-http": "./docs/enterprise-http/",
      "#harnesses": "./docs/harnesses/",
      "#configuration": "./docs/configuration/",
      "#privacy": "./docs/privacy/",
      "#security": "./docs/security/",
      "#verification": "./docs/verification/",
      "#changelog": "./docs/changelog/",
      "#faq": "./docs/faq/"
    };
    if (Object.prototype.hasOwnProperty.call(map, h)) {
      window.location.replace(map[h]);
    }
  }
})();
`;
}

export function renderStylesCss(): string {
  return `/* Coldpin Documentation Portal v2 — Three-Layer Design Token Architecture
 * Primitive -> Semantic -> Component | Slate + Teal | WCAG 2.2 AA/AAA
 * Zero resting card shadows/glass | Dual-theme syntax tokens | 320px zero-overflow
 */

/* ==========================================================================
   1. PRIMITIVE TOKENS
   ========================================================================== */
:root {
  --raw-white: #ffffff;
  --raw-slate-25: #fafbfd;
  --raw-slate-50: #f3f6fa;
  --raw-slate-100: #e8eef5;
  --raw-slate-200: #cbd5e1;
  --raw-slate-300: #94a3b8;
  --raw-slate-500: #475569;
  --raw-slate-600: #334155;
  --raw-slate-700: #1e293b;
  --raw-slate-800: #161f2e;
  --raw-slate-900: #0d1420;
  --raw-slate-950: #080c14;

  --raw-teal-50: #e6f7f5;
  --raw-teal-100: #c7efe9;
  --raw-teal-300: #5eead4;
  --raw-teal-400: #2dd4bf;
  --raw-teal-600: #0f766e;
  --raw-teal-700: #115e59;
  --raw-teal-800: #134e4a;
  --raw-teal-950: #072826;

  --raw-green-50: #ecfdf5;
  --raw-green-700: #15803d;
  --raw-green-300: #86efac;
  --raw-green-950: #062b22;

  --raw-amber-50: #fffbeb;
  --raw-amber-800: #92400e;
  --raw-amber-300: #fcd34d;
  --raw-amber-950: #2d1f07;

  --raw-red-50: #fef2f2;
  --raw-red-700: #b91c1c;
  --raw-red-300: #fca5a5;
  --raw-red-950: #2f0e10;

  --raw-font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --raw-code-face: ui-monospace, "Cascadia Mono", "SFMono-Regular", Menlo, Consolas, monospace;

  --raw-ease-out: cubic-bezier(0.23, 1, 0.32, 1);
  --raw-dur-fast: 140ms;
  --raw-dur-base: 190ms;

  --raw-space-1: 0.25rem;
  --raw-space-2: 0.5rem;
  --raw-space-3: 0.75rem;
  --raw-space-4: 1rem;
  --raw-space-5: 1.25rem;
  --raw-space-6: 1.5rem;
  --raw-space-8: 2rem;
  --raw-space-10: 2.5rem;
  --raw-space-12: 3rem;

  /* ========================================================================
     2. SEMANTIC TOKENS (Light Mode Default)
     ======================================================================== */
  --surface-canvas: var(--raw-slate-25);
  --surface-header: rgba(255, 255, 255, 0.92);
  --surface-sidebar: var(--raw-slate-50);
  --surface-panel: var(--raw-slate-50);
  --surface-panel-strong: var(--raw-slate-100);
  --surface-elevated: var(--raw-white);
  --surface-code: #f1f5f9;
  --surface-code-bar: #e2e8f0;
  --surface-code-border: #cbd5e1;
  --surface-accent-soft: var(--raw-teal-50);

  --ink-primary: var(--raw-slate-900);
  --ink-secondary: var(--raw-slate-600);
  --ink-muted: var(--raw-slate-500);
  --ink-on-accent: var(--raw-white);
  --ink-accent: var(--raw-teal-700);
  --ink-accent-soft: var(--raw-teal-800);
  --ink-code: #0f172a;
  --ink-code-muted: #334155;

  /* Dual-theme syntax tokens (Light: WCAG AA >= 4.5:1 on #f1f5f9) */
  --tok-key: #0f766e;
  --tok-cmd: #0369a1;
  --tok-flag: #6d28d9;
  --tok-str: #166534;
  --tok-num: #9a3412;
  --tok-kw: #0f766e;
  --tok-cmt: #475569;

  --accent-primary: var(--raw-teal-600);
  --accent-primary-hover: var(--raw-teal-700);
  --focus-ring: var(--raw-teal-600);
  --table-rule: var(--raw-slate-200);
  --control-border: var(--raw-slate-200);
  --selection-bg: var(--raw-teal-100);
  --selection-ink: var(--raw-slate-950);

  --status-allow-bg: var(--raw-green-50);
  --status-allow-ink: var(--raw-green-700);
  --status-ask-bg: var(--raw-amber-50);
  --status-ask-ink: var(--raw-amber-800);
  --status-deny-bg: var(--raw-red-50);
  --status-deny-ink: var(--raw-red-700);

  --callout-note-bg: #f0fdfa;
  --callout-note-border: #0f766e;
  --callout-tip-bg: #ecfdf5;
  --callout-tip-border: #15803d;
  --callout-caution-bg: #fffbeb;
  --callout-caution-border: #b45309;
  --callout-danger-bg: #fef2f2;
  --callout-danger-border: #b91c1c;

  --overlay-shadow: 0 20px 48px rgba(8, 12, 20, 0.16), 0 4px 12px rgba(8, 12, 20, 0.08);
  --backdrop-scrim: rgba(8, 12, 20, 0.45);

  /* ========================================================================
     3. COMPONENT TOKENS (2-row sticky header = 92px <= 100px)
     ======================================================================== */
  --header-row1: 52px;
  --header-row2: 40px;
  --header-height: 92px;
  --sidebar-width: 264px;
  --toc-width: 224px;
  --prose-max: 70ch;
  --radius-control: 6px;
  --radius-panel: 8px;
}

[data-theme="dark"] {
  --surface-canvas: var(--raw-slate-950);
  --surface-header: rgba(13, 20, 32, 0.92);
  --surface-sidebar: var(--raw-slate-900);
  --surface-panel: var(--raw-slate-900);
  --surface-panel-strong: var(--raw-slate-800);
  --surface-elevated: var(--raw-slate-800);
  --surface-code: #05080f;
  --surface-code-bar: #0f172a;
  --surface-code-border: #1e293b;
  --surface-accent-soft: var(--raw-teal-950);

  --ink-primary: #f1f5f9;
  --ink-secondary: #cbd5e1;
  --ink-muted: #94a3b8;
  --ink-on-accent: var(--raw-slate-950);
  --ink-accent: var(--raw-teal-300);
  --ink-accent-soft: var(--raw-teal-300);
  --ink-code: #e6edf6;
  --ink-code-muted: #94a3b8;

  /* Dual-theme syntax tokens (Dark: WCAG AA+ on #05080f) */
  --tok-key: #5eead4;
  --tok-cmd: #7dd3fc;
  --tok-flag: #c4b5fd;
  --tok-str: #86efac;
  --tok-num: #fcd34d;
  --tok-kw: #5eead4;
  --tok-cmt: #94a3b8;

  --accent-primary: var(--raw-teal-400);
  --accent-primary-hover: var(--raw-teal-300);
  --focus-ring: var(--raw-teal-300);
  --table-rule: #253247;
  --control-border: #253247;
  --selection-bg: var(--raw-teal-800);
  --selection-ink: #ffffff;

  --status-allow-bg: var(--raw-green-950);
  --status-allow-ink: var(--raw-green-300);
  --status-ask-bg: var(--raw-amber-950);
  --status-ask-ink: var(--raw-amber-300);
  --status-deny-bg: var(--raw-red-950);
  --status-deny-ink: var(--raw-red-300);

  --callout-note-bg: #072826;
  --callout-note-border: #2dd4bf;
  --callout-tip-bg: #062b22;
  --callout-tip-border: #4ade80;
  --callout-caution-bg: #2d1f07;
  --callout-caution-border: #fbbf24;
  --callout-danger-bg: #2f0e10;
  --callout-danger-border: #f87171;

  --overlay-shadow: 0 24px 60px rgba(0, 0, 0, 0.55), 0 6px 18px rgba(0, 0, 0, 0.35);
  --backdrop-scrim: rgba(2, 6, 14, 0.72);
}

/* ==========================================================================
   BASE & ACCESSIBILITY
   ========================================================================== */
*,
*::before,
*::after {
  box-sizing: border-box;
}

html {
  font-size: 16px;
  scroll-behavior: smooth;
  scroll-padding-top: calc(var(--header-height) + var(--raw-space-6));
  color-scheme: light dark;
}

body {
  margin: 0;
  font-family: var(--raw-font-sans);
  font-size: 1rem;
  line-height: 1.6;
  font-variant-numeric: tabular-nums;
  background-color: var(--surface-canvas);
  color: var(--ink-primary);
  caret-color: var(--accent-primary);
  -webkit-font-smoothing: antialiased;
  overflow-x: clip;
}

::selection {
  background-color: var(--selection-bg);
  color: var(--selection-ink);
}

::highlight(coldpin-search-match) {
  background-color: var(--selection-bg);
  color: var(--selection-ink);
}

:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
  border-radius: 4px;
}

a {
  color: var(--ink-accent);
  text-decoration: underline;
  text-decoration-thickness: 1px;
  text-underline-offset: 0.2em;
  transition: color var(--raw-dur-fast) var(--raw-ease-out);
}

@media (hover: hover) and (pointer: fine) {
  a:hover {
    color: var(--accent-primary-hover);
  }
}

button,
input,
select {
  font: inherit;
  color: inherit;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.skip-link {
  position: fixed;
  top: -120px;
  left: var(--raw-space-4);
  z-index: 200;
  padding: 0.65rem 1rem;
  background-color: var(--accent-primary);
  color: var(--ink-on-accent);
  font-weight: 600;
  text-decoration: none;
  border-radius: var(--radius-control);
  opacity: 0;
  pointer-events: none;
}

.skip-link:focus {
  top: var(--raw-space-3);
  opacity: 1;
  pointer-events: auto;
}

/* ==========================================================================
   DISMISSIBLE ANNOUNCEMENT PILL
   ========================================================================== */
[data-announce-dismissed="true"] .announcement-bar {
  display: none;
}

.announcement-bar {
  background-color: var(--surface-accent-soft);
  color: var(--ink-accent-soft);
  border-bottom: 1px solid var(--table-rule);
  font-size: 0.84rem;
}

.announcement-inner {
  max-width: 1440px;
  margin: 0 auto;
  padding: 0.38rem var(--raw-space-5);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.6rem;
  min-width: 0;
}

.announcement-pill {
  flex-shrink: 0;
  padding: 0.08rem 0.45rem;
  border-radius: 999px;
  background-color: var(--accent-primary);
  color: var(--ink-on-accent);
  font-size: 0.72rem;
  font-weight: 700;
}

.announcement-text {
  min-width: 0;
  overflow-wrap: anywhere;
}

.announcement-dismiss {
  flex-shrink: 0;
  margin-left: auto;
  width: 26px;
  height: 26px;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--ink-accent-soft);
  font-size: 1.05rem;
  line-height: 1;
  cursor: pointer;
}

/* ==========================================================================
   COMPACT 2-ROW STICKY TRANSLUCENT BLURRED HEADER (92px <= 100px)
   ========================================================================== */
.site-header {
  position: sticky;
  top: 0;
  z-index: 60;
  background-color: var(--surface-header);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--table-rule);
}

.header-row-1 {
  max-width: 1440px;
  height: var(--header-row1);
  margin: 0 auto;
  padding: 0 var(--raw-space-5);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-3);
}

.header-left {
  display: flex;
  align-items: center;
  gap: var(--raw-space-2);
  min-width: 0;
}

.brand-link {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  color: var(--ink-primary);
  text-decoration: none;
  font-weight: 750;
  font-size: 1rem;
  letter-spacing: -0.015em;
  white-space: nowrap;
}

.brand-version {
  font-size: 0.74rem;
  font-weight: 600;
  color: var(--ink-accent-soft);
  background-color: var(--surface-accent-soft);
  padding: 0.1rem 0.42rem;
  border-radius: 4px;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  min-width: 0;
}

.search-trigger {
  display: inline-flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-4);
  min-height: 34px;
  min-width: 196px;
  padding: 0 0.65rem;
  background-color: var(--surface-panel);
  color: var(--ink-muted);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
  font-size: 0.85rem;
  white-space: nowrap;
  cursor: pointer;
  transition: background-color var(--raw-dur-fast) var(--raw-ease-out),
              color var(--raw-dur-fast) var(--raw-ease-out),
              transform var(--raw-dur-fast) var(--raw-ease-out);
}

.search-kbd-group {
  display: inline-flex;
  gap: 0.2rem;
}

/* 3D Tactile Keyboard Keycaps */
.kbd {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.08rem 0.38rem;
  font-family: var(--raw-code-face);
  font-size: 0.72rem;
  font-weight: 600;
  line-height: 1.25;
  color: var(--ink-secondary);
  background-color: var(--surface-elevated);
  border: 1px solid var(--control-border);
  border-bottom-width: 2px;
  border-radius: 5px;
  white-space: nowrap;
}

/* 3-Way Auto | Light | Dark Theme Segmented Control */
.theme-segmented {
  display: inline-flex;
  align-items: center;
  padding: 2px;
  background-color: var(--surface-panel);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
}

.theme-opt {
  min-height: 28px;
  padding: 0 0.5rem;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--ink-muted);
  font-size: 0.76rem;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
  transition: background-color var(--raw-dur-fast) var(--raw-ease-out),
              color var(--raw-dur-fast) var(--raw-ease-out);
}

.theme-opt[aria-pressed="true"] {
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
}

.header-ext {
  display: inline-flex;
  align-items: center;
  min-height: 34px;
  padding: 0 0.55rem;
  color: var(--ink-secondary);
  text-decoration: none;
  font-size: 0.85rem;
  font-weight: 500;
  border-radius: var(--radius-control);
  white-space: nowrap;
}

.icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.35rem;
  min-width: 34px;
  min-height: 34px;
  padding: 0 0.6rem;
  background-color: var(--surface-panel);
  color: var(--ink-primary);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
  font-size: 0.82rem;
  font-weight: 600;
  cursor: pointer;
}

.mobile-menu-btn {
  display: none;
}

/* Row 2: 5-Pillar Horizontal Tabs */
.header-row-2 {
  border-top: 1px solid var(--table-rule);
}

.pillar-tabs-inner {
  max-width: 1440px;
  height: var(--header-row2);
  margin: 0 auto;
  padding: 0 var(--raw-space-5);
  display: flex;
  align-items: stretch;
  gap: 0.25rem;
  overflow-x: auto;
  scrollbar-width: none;
}

.pillar-tabs-inner::-webkit-scrollbar {
  display: none;
}

.pillar-tab {
  position: relative;
  display: inline-flex;
  align-items: center;
  padding: 0 0.75rem;
  color: var(--ink-secondary);
  text-decoration: none;
  font-size: 0.85rem;
  font-weight: 600;
  white-space: nowrap;
  flex-shrink: 0;
}

.pillar-tab[aria-current="page"] {
  color: var(--ink-accent);
}

.pillar-tab[aria-current="page"]::after {
  content: "";
  position: absolute;
  left: 0.5rem;
  right: 0.5rem;
  bottom: 0;
  height: 2px;
  background-color: var(--accent-primary);
}

.search-trigger:active,
.icon-btn:active,
.btn:active,
.tab-btn:active,
.preset-btn:active,
.copy-btn:active,
.md-menu-btn:active,
.surface-card:active {
  transform: scale(0.97);
}

@media (hover: hover) and (pointer: fine) {
  .search-trigger:hover,
  .icon-btn:hover,
  .header-ext:hover,
  .pillar-tab:hover,
  .md-menu-btn:hover {
    background-color: var(--surface-panel-strong);
    color: var(--ink-primary);
  }
  .theme-opt:hover {
    color: var(--ink-primary);
  }
}

/* ==========================================================================
   THREE-COLUMN DOCUMENTATION SHELL
   ========================================================================== */
.docs-shell {
  max-width: 1440px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: var(--sidebar-width) minmax(0, 1fr) var(--toc-width);
  align-items: start;
}

.sidebar {
  position: sticky;
  top: var(--header-height);
  height: calc(100vh - var(--header-height));
  overflow-y: auto;
  padding: var(--raw-space-5) var(--raw-space-3) var(--raw-space-10);
  background-color: var(--surface-sidebar);
  border-right: 1px solid var(--table-rule);
}

.nav-group {
  margin-bottom: var(--raw-space-3);
}

.nav-group-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.42rem var(--raw-space-3);
  border-radius: var(--radius-control);
  font-size: 0.8rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--ink-muted);
  cursor: pointer;
  list-style: none;
}

.nav-group-title::-webkit-details-marker {
  display: none;
}

.nav-group-title::after {
  content: "▸";
  font-size: 0.78rem;
  transition: transform var(--raw-dur-fast) var(--raw-ease-out);
}

.nav-group[open] .nav-group-title::after {
  transform: rotate(90deg);
}

.nav-list {
  list-style: none;
  margin: 0.2rem 0 0;
  padding: 0;
}

.nav-link {
  display: block;
  padding: 0.42rem var(--raw-space-3);
  margin-bottom: 2px;
  border-radius: var(--radius-control);
  border-left: 2px solid transparent;
  color: var(--ink-secondary);
  text-decoration: none;
  font-size: 0.89rem;
  font-weight: 500;
  line-height: 1.36;
}

.nav-link[aria-current="page"] {
  background-color: var(--surface-accent-soft);
  border-left-color: var(--accent-primary);
  color: var(--ink-accent-soft);
  font-weight: 650;
}

@media (hover: hover) and (pointer: fine) {
  .nav-link:hover {
    background-color: var(--surface-panel-strong);
    color: var(--ink-primary);
  }
  .nav-link[aria-current="page"]:hover {
    background-color: var(--surface-accent-soft);
    color: var(--ink-accent-soft);
  }
}

.docs-main {
  min-width: 0;
  padding: var(--raw-space-6) var(--raw-space-10) var(--raw-space-12);
}

.docs-article {
  max-width: 800px;
  margin: 0 auto;
  min-width: 0;
}

/* ==========================================================================
   ARTICLE TOPBAR: BREADCRUMBS + NATIVE POPOVER MARKDOWN MENU
   ========================================================================== */
.article-topbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-3);
  margin-bottom: var(--raw-space-4);
}

.breadcrumbs ol {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem;
  list-style: none;
  margin: 0;
  padding: 0;
  font-size: 0.82rem;
  color: var(--ink-muted);
}

.breadcrumbs li:not(:last-child)::after {
  content: "/";
  margin-left: 0.35rem;
  color: var(--ink-muted);
}

.breadcrumbs a {
  color: var(--ink-muted);
  text-decoration: none;
}

.breadcrumbs a:hover {
  color: var(--ink-accent);
  text-decoration: underline;
}

.md-menu-wrap {
  position: relative;
}

.md-menu-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  min-height: 32px;
  padding: 0 0.65rem;
  background-color: var(--surface-panel);
  color: var(--ink-secondary);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
  font-size: 0.8rem;
  font-weight: 600;
  cursor: pointer;
}

.md-popover {
  margin: 0;
  padding: 0.3rem;
  min-width: 186px;
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-panel);
  box-shadow: var(--overlay-shadow);
}

@supports (anchor-name: --md-anchor) {
  .md-menu-btn {
    anchor-name: --md-menu-anchor;
  }
  .md-popover {
    position: fixed;
    position-anchor: --md-menu-anchor;
    top: calc(anchor(bottom) + 6px);
    bottom: auto;
    right: anchor(right);
    left: auto;
    max-width: calc(100vw - 1rem);
    position-try-fallbacks: flip-inline;
  }
}

.md-popover.is-fallback-open {
  display: block;
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  z-index: 80;
}

.md-popover-item {
  display: block;
  width: 100%;
  text-align: left;
  padding: 0.45rem 0.65rem;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--ink-primary);
  text-decoration: none;
  font-size: 0.84rem;
  font-weight: 500;
  cursor: pointer;
}

@media (hover: hover) and (pointer: fine) {
  .md-popover-item:hover {
    background-color: var(--surface-panel);
    color: var(--ink-accent);
  }
}

/* ==========================================================================
   RIGHT-RAIL DESKTOP TOC & MOBILE COLLAPSIBLE TOC
   ========================================================================== */
.toc-aside {
  position: sticky;
  top: var(--header-height);
  height: calc(100vh - var(--header-height));
  overflow-y: auto;
  padding: var(--raw-space-6) var(--raw-space-5) var(--raw-space-10) var(--raw-space-3);
}

.toc-title {
  margin: 0 0 var(--raw-space-2);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--ink-muted);
}

.toc-list {
  list-style: none;
  margin: 0 0 var(--raw-space-5);
  padding: 0;
  border-left: 1px solid var(--table-rule);
}

.toc-link {
  display: block;
  padding: 0.28rem 0.6rem;
  margin-left: -1px;
  border-left: 2px solid transparent;
  color: var(--ink-muted);
  text-decoration: none;
  font-size: 0.82rem;
  line-height: 1.38;
}

.toc-link.is-active {
  color: var(--ink-accent);
  border-left-color: var(--accent-primary);
  background-color: var(--surface-accent-soft);
  font-weight: 600;
}

.toc-meta {
  padding: var(--raw-space-4);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  font-size: 0.8rem;
  color: var(--ink-secondary);
}

.toc-meta-title {
  margin: 0 0 var(--raw-space-2);
  font-weight: 700;
  color: var(--ink-primary);
}

.toc-meta ul {
  list-style: none;
  margin: 0;
  padding: 0;
}

.toc-meta li {
  margin-bottom: 0.35rem;
}

.mobile-toc {
  display: none;
  margin: var(--raw-space-4) 0;
  padding: 0.35rem var(--raw-space-4);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
}

.mobile-toc summary {
  padding: 0.4rem 0;
  font-size: 0.86rem;
  font-weight: 700;
  color: var(--ink-primary);
  cursor: pointer;
}

/* ==========================================================================
   HERO, SURFACE CHIPS & TYPOGRAPHY
   ========================================================================== */
.hero-block {
  padding-bottom: var(--raw-space-5);
  border-bottom: 1px solid var(--table-rule);
}

.doc-h1 {
  margin: 0;
  font-size: 2rem;
  font-weight: 780;
  line-height: 1.15;
  letter-spacing: -0.025em;
  color: var(--ink-primary);
  text-wrap: balance;
  overflow-wrap: anywhere;
}

.doc-lead {
  margin: var(--raw-space-3) 0 var(--raw-space-4);
  max-width: var(--prose-max);
  font-size: 1.02rem;
  line-height: 1.58;
  color: var(--ink-secondary);
}

.surface-chips-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.4rem;
  margin-bottom: var(--raw-space-4);
}

.surface-chips-label {
  font-size: 0.72rem;
  font-weight: 750;
  letter-spacing: 0.05em;
  color: var(--ink-muted);
}

.surface-chip {
  display: inline-flex;
  align-items: center;
  padding: 0.14rem 0.52rem;
  border-radius: 999px;
  background-color: var(--surface-panel);
  border: 1px solid var(--control-border);
  color: var(--ink-secondary);
  font-size: 0.74rem;
  font-weight: 600;
}

.hero-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--raw-space-3);
  margin: var(--raw-space-4) 0;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  min-height: 40px;
  padding: 0.5rem 1rem;
  border-radius: var(--radius-control);
  border: 1px solid transparent;
  font-size: 0.9rem;
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
  transition: background-color var(--raw-dur-fast) var(--raw-ease-out),
              color var(--raw-dur-fast) var(--raw-ease-out),
              transform var(--raw-dur-fast) var(--raw-ease-out);
}

.btn-sm {
  min-height: 34px;
  padding: 0.35rem 0.78rem;
  font-size: 0.82rem;
}

.btn-primary {
  background-color: var(--accent-primary);
  color: var(--ink-on-accent);
}

.btn-secondary {
  background-color: var(--surface-panel-strong);
  border-color: var(--control-border);
  color: var(--ink-primary);
}

@media (hover: hover) and (pointer: fine) {
  .btn-primary:hover {
    background-color: var(--accent-primary-hover);
    color: var(--ink-on-accent);
  }
  .btn-secondary:hover {
    background-color: var(--table-rule);
    color: var(--ink-primary);
  }
}

.spec-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--raw-space-4);
  margin: var(--raw-space-4) 0 0;
  padding: var(--raw-space-4) var(--raw-space-5);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
}

.spec-item dt {
  margin: 0 0 0.2rem;
  font-size: 0.76rem;
  color: var(--ink-muted);
  font-weight: 600;
}

.spec-item dd {
  margin: 0;
  font-size: 0.92rem;
  font-weight: 700;
  color: var(--ink-primary);
  overflow-wrap: anywhere;
}

.doc-section {
  padding-top: var(--raw-space-8);
  min-width: 0;
}

.heading-row {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  margin-bottom: var(--raw-space-3);
}

.doc-h2 {
  margin: 0;
  font-size: 1.48rem;
  font-weight: 740;
  line-height: 1.24;
  letter-spacing: -0.02em;
  color: var(--ink-primary);
  text-wrap: balance;
  overflow-wrap: anywhere;
}

.doc-h3 {
  margin: 0;
  font-size: 1.12rem;
  font-weight: 700;
  line-height: 1.3;
  color: var(--ink-primary);
  overflow-wrap: anywhere;
}

.heading-anchor-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--ink-muted);
  font-weight: 700;
  cursor: pointer;
  flex-shrink: 0;
  transition: opacity var(--raw-dur-fast) var(--raw-ease-out),
              color var(--raw-dur-fast) var(--raw-ease-out),
              background-color var(--raw-dur-fast) var(--raw-ease-out);
}

@media (hover: hover) and (pointer: fine) {
  .heading-anchor-btn {
    opacity: 0;
  }
  .heading-row:hover .heading-anchor-btn,
  .heading-anchor-btn:focus-visible {
    opacity: 1;
  }
  .heading-anchor-btn:hover {
    color: var(--ink-accent);
    background-color: var(--surface-accent-soft);
  }
}

.prose,
.prose-muted {
  max-width: var(--prose-max);
  margin: 0 0 var(--raw-space-4);
  overflow-wrap: anywhere;
}

.prose {
  color: var(--ink-primary);
}

.prose-muted {
  color: var(--ink-secondary);
}

.doc-list {
  max-width: var(--prose-max);
  margin: 0 0 var(--raw-space-4);
  padding-left: 1.35rem;
}

.doc-list li {
  margin-bottom: var(--raw-space-2);
  overflow-wrap: anywhere;
}

code {
  font-family: var(--raw-code-face);
  font-size: 0.86em;
  background-color: var(--surface-panel-strong);
  color: var(--ink-primary);
  padding: 0.1rem 0.34rem;
  border-radius: 4px;
  overflow-wrap: anywhere;
  word-break: break-word;
}

/* ==========================================================================
   4-HARNESS MASTER SELECTOR & RESOURCE CARDS (ZERO RESTING SHADOWS)
   ========================================================================== */
.surface-selector {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--raw-space-3);
  margin: var(--raw-space-4) 0;
}

.surface-card {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  text-align: left;
  padding: var(--raw-space-4);
  background-color: var(--surface-panel);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-panel);
  cursor: pointer;
  transition: border-color var(--raw-dur-fast) var(--raw-ease-out),
              background-color var(--raw-dur-fast) var(--raw-ease-out),
              transform var(--raw-dur-fast) var(--raw-ease-out);
}

.surface-card[aria-pressed="true"] {
  background-color: var(--surface-accent-soft);
  border-color: var(--accent-primary);
}

.surface-card-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.surface-card-title {
  font-weight: 700;
  font-size: 0.94rem;
  color: var(--ink-primary);
}

.surface-card-badge {
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.08rem 0.45rem;
  border-radius: 999px;
  background-color: var(--surface-elevated);
  border: 1px solid var(--control-border);
  color: var(--ink-accent);
  white-space: nowrap;
}

.surface-card-desc {
  font-size: 0.84rem;
  line-height: 1.45;
  color: var(--ink-secondary);
}

.resource-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--raw-space-3);
  margin: var(--raw-space-4) 0;
}

.resource-card {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  padding: var(--raw-space-4);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  text-decoration: none;
  color: inherit;
}

.resource-pillar {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--ink-accent);
}

.resource-title {
  font-weight: 700;
  font-size: 0.96rem;
  color: var(--ink-primary);
}

.resource-desc {
  font-size: 0.85rem;
  line-height: 1.45;
  color: var(--ink-secondary);
}

@media (hover: hover) and (pointer: fine) {
  .resource-card:hover,
  .surface-card:hover {
    border-color: var(--accent-primary);
  }
}

/* ==========================================================================
   SEMANTIC 4PX LEFT-ACCENT CALLOUTS & NUMBERED .sl-steps
   ========================================================================== */
.callout {
  padding: 0.85rem var(--raw-space-5);
  border-radius: var(--radius-panel);
  border: 1px solid var(--table-rule);
  border-left-width: 4px;
  margin: var(--raw-space-4) 0;
  max-width: var(--prose-max);
  font-size: 0.92rem;
}

.callout-note {
  background-color: var(--callout-note-bg);
  border-left-color: var(--callout-note-border);
}

.callout-tip {
  background-color: var(--callout-tip-bg);
  border-left-color: var(--callout-tip-border);
}

.callout-caution {
  background-color: var(--callout-caution-bg);
  border-left-color: var(--callout-caution-border);
}

.callout-danger {
  background-color: var(--callout-danger-bg);
  border-left-color: var(--callout-danger-border);
}

.callout-title {
  margin: 0 0 0.25rem;
  font-weight: 700;
  font-size: 0.92rem;
  color: var(--ink-primary);
}

.callout-body {
  margin: 0;
  color: var(--ink-secondary);
  overflow-wrap: anywhere;
}

.sl-steps {
  list-style: none;
  counter-reset: sl-step;
  margin: var(--raw-space-4) 0;
  padding: 0;
}

.sl-step {
  position: relative;
  counter-increment: sl-step;
  padding-left: 2.5rem;
  padding-bottom: var(--raw-space-5);
  min-width: 0;
}

.sl-step::before {
  content: counter(sl-step);
  position: absolute;
  left: 0;
  top: 0.05rem;
  width: 1.75rem;
  height: 1.75rem;
  border-radius: 999px;
  background-color: var(--surface-accent-soft);
  border: 1px solid var(--accent-primary);
  color: var(--ink-accent);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.82rem;
  font-weight: 750;
}

.sl-step:not(:last-child)::after {
  content: "";
  position: absolute;
  left: 0.85rem;
  top: 2.05rem;
  bottom: 0.35rem;
  width: 1px;
  background-color: var(--table-rule);
}

.sl-step-title {
  margin: 0 0 0.35rem;
  font-size: 1rem;
  font-weight: 700;
  color: var(--ink-primary);
}

/* ==========================================================================
   DUAL-THEME CODE BLOCKS & TABS
   ========================================================================== */
.tab-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
  padding: 0.3rem;
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  margin-bottom: var(--raw-space-4);
}

.tab-btn {
  min-height: 34px;
  padding: 0.35rem 0.8rem;
  border: 0;
  border-radius: var(--radius-control);
  background: transparent;
  color: var(--ink-secondary);
  font-size: 0.86rem;
  font-weight: 600;
  cursor: pointer;
}

.tab-btn[aria-selected="true"] {
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
}

.tab-panel[hidden] {
  display: none;
}

.code-block {
  margin: var(--raw-space-3) 0 var(--raw-space-5);
  border: 1px solid var(--surface-code-border);
  border-radius: var(--radius-panel);
  overflow: hidden;
  background-color: var(--surface-code);
}

.code-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-3);
  padding: 0.45rem 0.85rem;
  background-color: var(--surface-code-bar);
  border-bottom: 1px solid var(--surface-code-border);
  color: var(--ink-code-muted);
  font-size: 0.78rem;
  font-weight: 600;
}

.code-label {
  min-width: 0;
  overflow-wrap: anywhere;
}

.copy-btn {
  min-height: 28px;
  padding: 0.2rem 0.62rem;
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
  border: 1px solid var(--control-border);
  border-radius: 4px;
  font-size: 0.76rem;
  font-weight: 600;
  cursor: pointer;
  flex-shrink: 0;
}

.code-block pre {
  margin: 0;
  padding: var(--raw-space-4);
  overflow-x: auto;
  font-family: var(--raw-code-face);
  font-size: 0.84rem;
  line-height: 1.56;
  color: var(--ink-code);
}

.code-block pre code {
  background: transparent;
  color: inherit;
  padding: 0;
  font-size: inherit;
  overflow-wrap: normal;
  word-break: normal;
}

.tok-key { color: var(--tok-key); font-weight: 600; }
.tok-cmd { color: var(--tok-cmd); font-weight: 600; }
.tok-flag { color: var(--tok-flag); }
.tok-str { color: var(--tok-str); }
.tok-num { color: var(--tok-num); }
.tok-kw { color: var(--tok-kw); font-weight: 600; }
.tok-cmt { color: var(--tok-cmt); font-style: italic; }

/* ==========================================================================
   COMPONENT LEDGER & SAFE PROMPT COMPOSER CARDS
   ========================================================================== */
.component-ledger {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--raw-space-3);
  margin: var(--raw-space-4) 0;
}

.ledger-row {
  display: grid;
  grid-template-columns: 196px minmax(0, 1fr);
  gap: var(--raw-space-5);
  padding: var(--raw-space-4) var(--raw-space-5);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
}

.ledger-term {
  font-weight: 700;
  color: var(--ink-primary);
  font-size: 0.95rem;
}

.ledger-count {
  display: block;
  margin-top: 0.2rem;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--ink-accent);
}

.ledger-body p {
  margin: 0 0 0.4rem;
  color: var(--ink-secondary);
  font-size: 0.92rem;
}

.ledger-body p:last-child {
  margin-bottom: 0;
}

.prompt-card {
  margin: var(--raw-space-4) 0;
  padding: var(--raw-space-5);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  min-width: 0;
}

.prompt-card-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-2);
  margin-bottom: var(--raw-space-3);
}

.prompt-card-titles {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
}

.prompt-slash-badge {
  font-family: var(--raw-code-face);
  font-size: 0.82rem;
  font-weight: 700;
  padding: 0.16rem 0.55rem;
  border-radius: 4px;
  background-color: var(--surface-accent-soft);
  color: var(--ink-accent);
}

.prompt-card-title {
  margin: 0;
  font-size: 1rem;
  font-weight: 700;
  color: var(--ink-primary);
}

.prompt-card-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}

.prompt-code {
  margin: 0 0 var(--raw-space-4);
  padding: var(--raw-space-3) var(--raw-space-4);
  background-color: var(--surface-code);
  border: 1px solid var(--surface-code-border);
  border-radius: var(--radius-control);
  color: var(--ink-code);
  font-family: var(--raw-code-face);
  font-size: 0.83rem;
  line-height: 1.5;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.prompt-code code {
  background: transparent;
  padding: 0;
  color: inherit;
}

.prompt-card-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--raw-space-2);
}

.prompt-fallback {
  margin: var(--raw-space-3) 0 0;
  padding: 0.65rem 0.85rem;
  border-radius: var(--radius-control);
  background-color: var(--callout-caution-bg);
  border-left: 3px solid var(--callout-caution-border);
  font-size: 0.84rem;
  color: var(--ink-secondary);
}

/* ==========================================================================
   INTERACTIVE POLICY LAB & SANDBOXED SEP-1865 MCP APP FRAME
   ========================================================================== */
.sim-shell {
  margin: var(--raw-space-4) 0;
  padding: var(--raw-space-5);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  min-width: 0;
}

.sim-controls {
  display: grid;
  grid-template-columns: 204px minmax(0, 1fr);
  gap: var(--raw-space-3);
  margin-bottom: var(--raw-space-3);
}

.sim-field label {
  display: block;
  margin-bottom: 0.28rem;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--ink-secondary);
}

.sim-select,
.sim-input {
  width: 100%;
  min-height: 38px;
  padding: 0.4rem 0.65rem;
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
  font-family: var(--raw-code-face);
  font-size: 0.84rem;
}

.sim-presets {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-bottom: var(--raw-space-4);
}

.preset-btn {
  min-height: 32px;
  padding: 0.25rem 0.62rem;
  background-color: var(--surface-elevated);
  color: var(--ink-secondary);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
  font-size: 0.8rem;
  font-weight: 550;
  cursor: pointer;
}

.preset-btn[aria-pressed="true"] {
  background-color: var(--surface-accent-soft);
  border-color: var(--accent-primary);
  color: var(--ink-accent-soft);
  font-weight: 650;
}

.sim-result,
.verdict-card {
  padding: var(--raw-space-4);
  background-color: var(--surface-elevated);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-control);
  min-width: 0;
}

.sim-result-head,
.verdict-card-title {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-2);
  margin-bottom: var(--raw-space-3);
}

.verdict-heading {
  margin: 0;
  font-size: 1rem;
  font-weight: 700;
  color: var(--ink-primary);
  overflow-wrap: anywhere;
}

.decision-pill {
  display: inline-flex;
  align-items: center;
  padding: 0.2rem 0.58rem;
  border-radius: 4px;
  font-family: var(--raw-code-face);
  font-size: 0.78rem;
  font-weight: 700;
  overflow-wrap: anywhere;
}

.decision-allow { background-color: var(--status-allow-bg); color: var(--status-allow-ink); }
.decision-ask { background-color: var(--status-ask-bg); color: var(--status-ask-ink); }
.decision-deny { background-color: var(--status-deny-bg); color: var(--status-deny-ink); }

.sim-meta {
  font-size: 0.8rem;
  color: var(--ink-muted);
}

.sim-reason {
  margin: 0 0 var(--raw-space-3);
  font-size: 0.9rem;
  color: var(--ink-primary);
  overflow-wrap: anywhere;
}

.sim-io-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--raw-space-3);
}

.sim-io-grid > div {
  min-width: 0;
}

.sim-io-label {
  margin: 0 0 0.3rem;
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--ink-muted);
}

.sim-json {
  margin: 0;
  padding: 0.7rem 0.8rem;
  background-color: var(--surface-code);
  border: 1px solid var(--surface-code-border);
  color: var(--ink-code);
  border-radius: var(--radius-control);
  overflow-x: auto;
  font-family: var(--raw-code-face);
  font-size: 0.8rem;
  line-height: 1.48;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.verdict-kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--raw-space-3);
  margin: 0 0 var(--raw-space-3);
}

.verdict-kv dt {
  font-size: 0.76rem;
  font-weight: 600;
  color: var(--ink-muted);
}

.verdict-kv dd {
  margin: 0.15rem 0 0;
  font-size: 0.87rem;
  color: var(--ink-primary);
  overflow-wrap: anywhere;
}

.mcp-app-preview-wrap {
  margin-top: var(--raw-space-4);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  overflow: hidden;
  background-color: var(--surface-elevated);
}

.mcp-app-preview-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-2);
  padding: 0.55rem 0.85rem;
  background-color: var(--surface-panel-strong);
  border-bottom: 1px solid var(--table-rule);
}

.mcp-app-eyebrow {
  font-size: 0.76rem;
  font-weight: 700;
  color: var(--ink-primary);
  margin-right: 0.5rem;
}

.mcp-app-uri {
  font-size: 0.76rem;
}

.mcp-app-status {
  font-size: 0.74rem;
  color: var(--ink-muted);
}

.mcp-app-frame {
  display: block;
  width: 100%;
  height: 410px;
  border: 0;
  background-color: var(--surface-canvas);
}

/* ==========================================================================
   DATA TABLES & MOBILE CARDS | TABLE SWITCHER
   ========================================================================== */
.table-container {
  margin: var(--raw-space-4) 0 var(--raw-space-6);
  min-width: 0;
}

.table-view-bar {
  display: none;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.table-view-label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--ink-muted);
}

.table-view-btns {
  display: inline-flex;
  padding: 2px;
  background-color: var(--surface-panel);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-control);
}

.table-view-btn {
  min-height: 28px;
  padding: 0 0.6rem;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--ink-muted);
  font-size: 0.78rem;
  font-weight: 600;
  cursor: pointer;
}

.table-view-btn[aria-pressed="true"] {
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
}

.table-scroll {
  overflow-x: auto;
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  background-color: var(--surface-elevated);
}

table {
  width: 100%;
  min-width: 600px;
  border-collapse: collapse;
  font-size: 0.88rem;
}

th,
td {
  text-align: left;
  padding: 0.68rem 0.85rem;
  border-bottom: 1px solid var(--table-rule);
  vertical-align: top;
}

td.nowrap,
th.nowrap {
  white-space: nowrap;
}

td.nowrap code {
  white-space: nowrap;
  overflow-wrap: normal;
  word-break: normal;
}

thead th {
  background-color: var(--surface-panel);
  color: var(--ink-primary);
  font-weight: 700;
  font-size: 0.82rem;
}

tbody tr:last-child td {
  border-bottom: 0;
}

/* ==========================================================================
   NATIVE FAQ & CHANGELOG ACCORDIONS (320px ZERO-OVERFLOW GUARD)
   ========================================================================== */
.details-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: var(--raw-space-3);
}

.faq-list,
.release-list {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--raw-space-3);
  margin: var(--raw-space-4) 0;
  min-width: 0;
}

.faq-item,
.release-item {
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  padding: 0.25rem var(--raw-space-4);
  min-width: 0;
  max-width: 100%;
}

.faq-item summary,
.release-item summary {
  padding: var(--raw-space-3) 0;
  font-weight: 680;
  font-size: 0.96rem;
  color: var(--ink-primary);
  cursor: pointer;
  list-style: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--raw-space-3);
  min-width: 0;
  overflow-wrap: anywhere;
}

.summary-text {
  min-width: 0;
  overflow-wrap: anywhere;
}

.summary-badge {
  display: inline-block;
  margin-left: 0.4rem;
  padding: 0.08rem 0.45rem;
  border-radius: 999px;
  background-color: var(--surface-accent-soft);
  color: var(--ink-accent);
  font-size: 0.72rem;
  font-weight: 700;
  vertical-align: middle;
}

.faq-item summary::-webkit-details-marker,
.release-item summary::-webkit-details-marker {
  display: none;
}

.faq-item summary::after,
.release-item summary::after {
  content: "+";
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--ink-muted);
  flex-shrink: 0;
}

.faq-item[open] summary::after,
.release-item[open] summary::after {
  content: "−";
}

.faq-answer {
  padding: 0 0 var(--raw-space-4);
  color: var(--ink-secondary);
  font-size: 0.92rem;
  min-width: 0;
  overflow-wrap: anywhere;
}

/* ==========================================================================
   PAGINATION & FOOTER
   ========================================================================== */
.doc-pagination {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--raw-space-3);
  margin-top: var(--raw-space-10);
  padding-top: var(--raw-space-6);
  border-top: 1px solid var(--table-rule);
}

.pagination-link {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  padding: var(--raw-space-4);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
  text-decoration: none;
  background-color: var(--surface-panel);
}

.pagination-next {
  text-align: right;
}

.pagination-dir {
  font-size: 0.74rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--ink-muted);
}

.pagination-title {
  font-size: 0.94rem;
  font-weight: 700;
  color: var(--ink-accent);
}

@media (hover: hover) and (pointer: fine) {
  .pagination-link:hover {
    border-color: var(--accent-primary);
  }
}

.site-footer {
  margin-top: var(--raw-space-10);
  padding: var(--raw-space-6) 0 var(--raw-space-4);
  color: var(--ink-muted);
  font-size: 0.84rem;
}

.footer-panel {
  padding: var(--raw-space-5);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
}

.footer-top {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: var(--raw-space-3);
  align-items: center;
  margin-bottom: var(--raw-space-3);
}

.footer-links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--raw-space-3);
}

.footer-disclaimer {
  margin: 0;
  font-size: 0.8rem;
  color: var(--ink-muted);
}

/* 404 Page */
.not-found-main {
  max-width: 780px;
  margin: 0 auto;
  padding: var(--raw-space-10) var(--raw-space-5);
}

.not-found-card {
  padding: var(--raw-space-6);
  background-color: var(--surface-panel);
  border: 1px solid var(--table-rule);
  border-radius: var(--radius-panel);
}

.not-found-code {
  margin: 0 0 0.5rem;
  font-family: var(--raw-code-face);
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--ink-accent);
}

/* ==========================================================================
   WAI-ARIA COMMAND PALETTE SEARCH DIALOG (<dialog>)
   ========================================================================== */
.search-dialog {
  width: min(640px, calc(100vw - 1.5rem));
  padding: 0;
  border: 1px solid var(--control-border);
  border-radius: var(--radius-panel);
  background-color: var(--surface-elevated);
  color: var(--ink-primary);
  box-shadow: var(--overlay-shadow);
}

.search-dialog::backdrop {
  background-color: var(--backdrop-scrim);
}

.search-dialog-head {
  display: flex;
  align-items: center;
  gap: var(--raw-space-2);
  padding: var(--raw-space-3) var(--raw-space-4);
  background-color: var(--surface-panel);
  border-bottom: 1px solid var(--table-rule);
}

.search-dialog-input {
  flex: 1;
  min-width: 0;
  min-height: 38px;
  border: 0;
  background: transparent;
  color: var(--ink-primary);
  font-size: 0.96rem;
}

.search-dialog-input:focus {
  outline: none;
}

.search-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  padding: 0.55rem var(--raw-space-4);
  border-bottom: 1px solid var(--table-rule);
  background-color: var(--surface-panel);
}

.search-chip {
  min-height: 28px;
  padding: 0.15rem 0.58rem;
  border: 1px solid var(--control-border);
  border-radius: 999px;
  background-color: var(--surface-elevated);
  color: var(--ink-secondary);
  font-size: 0.76rem;
  font-weight: 600;
  cursor: pointer;
}

.search-chip[aria-pressed="true"] {
  background-color: var(--surface-accent-soft);
  border-color: var(--accent-primary);
  color: var(--ink-accent-soft);
}

.search-results {
  list-style: none;
  margin: 0;
  padding: var(--raw-space-2);
  max-height: 380px;
  overflow-y: auto;
}

.search-result-option {
  margin-bottom: 2px;
}

.search-result-link {
  display: block;
  padding: 0.6rem 0.75rem;
  border-radius: var(--radius-control);
  border-left: 2px solid transparent;
  text-decoration: none;
  color: var(--ink-primary);
}

.search-result-option[aria-selected="true"] .search-result-link,
.search-result-link:hover {
  background-color: var(--surface-accent-soft);
  border-left-color: var(--accent-primary);
}

.search-result-top {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.5rem;
}

.search-result-title {
  font-weight: 650;
  font-size: 0.9rem;
}

.search-result-meta {
  font-size: 0.74rem;
  color: var(--ink-accent);
  white-space: nowrap;
}

.search-result-snippet {
  display: block;
  margin-top: 0.18rem;
  font-size: 0.8rem;
  color: var(--ink-muted);
  overflow-wrap: anywhere;
}

.search-empty {
  padding: var(--raw-space-6);
  text-align: center;
  color: var(--ink-muted);
  font-size: 0.9rem;
}

.search-dialog-foot {
  display: flex;
  flex-wrap: wrap;
  gap: 0.9rem;
  padding: 0.5rem var(--raw-space-4);
  border-top: 1px solid var(--table-rule);
  background-color: var(--surface-panel);
  font-size: 0.75rem;
  color: var(--ink-muted);
}

.sidebar-backdrop {
  position: fixed;
  inset: var(--header-height) 0 0 0;
  z-index: 65;
  background-color: var(--backdrop-scrim);
}

/* ==========================================================================
   RESPONSIVE BREAKPOINTS (1220px, 960px, 720px, 560px, 320px)
   ========================================================================== */
@media (max-width: 1220px) {
  .docs-shell {
    grid-template-columns: var(--sidebar-width) minmax(0, 1fr);
  }
  .toc-aside {
    display: none;
  }
  .mobile-toc {
    display: block;
  }
}

@media (max-width: 960px) {
  .docs-shell {
    grid-template-columns: minmax(0, 1fr);
  }
  .mobile-menu-btn {
    display: inline-flex;
  }
  .header-ext {
    display: none;
  }
  .search-trigger {
    min-width: auto;
    gap: 0.4rem;
  }
  .search-kbd-group {
    display: none;
  }
  .sidebar {
    position: fixed;
    inset: var(--header-height) auto 0 0;
    z-index: 70;
    width: min(300px, 86vw);
    height: calc(100vh - var(--header-height));
    visibility: hidden;
    transform: translateX(-105%);
    transition: transform var(--raw-dur-base) var(--raw-ease-out),
                visibility var(--raw-dur-base) var(--raw-ease-out);
  }
  .sidebar.is-open {
    visibility: visible;
    box-shadow: var(--overlay-shadow);
    transform: translateX(0);
  }
  .docs-main {
    padding: var(--raw-space-5) var(--raw-space-5) var(--raw-space-10);
  }
  .spec-strip,
  .surface-selector,
  .resource-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .ledger-row,
  .sim-controls,
  .sim-io-grid,
  .verdict-kv {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (max-width: 720px) {
  .table-container[data-table-switcher="true"] .table-view-bar {
    display: flex;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] .table-scroll {
    overflow-x: visible;
    border: 0;
    background: transparent;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] table {
    min-width: 0;
    display: block;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] thead {
    display: none;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] tbody {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 0.65rem;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] tr {
    display: block;
    padding: 0.75rem 0.85rem;
    background-color: var(--surface-panel);
    border: 1px solid var(--table-rule);
    border-radius: var(--radius-panel);
  }
  .table-container[data-table-switcher="true"][data-view="cards"] td {
    display: block;
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--table-rule);
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] td.nowrap code {
    white-space: normal;
    overflow-wrap: anywhere;
    word-break: break-word;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] td:last-child {
    border-bottom: 0;
  }
  .table-container[data-table-switcher="true"][data-view="cards"] td::before {
    content: attr(data-label);
    display: block;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--ink-muted);
    margin-bottom: 0.14rem;
  }
}

@media (max-width: 560px) {
  .doc-h1 {
    font-size: 1.48rem;
  }
  .header-row-1 {
    padding: 0 0.6rem;
    gap: 0.4rem;
  }
  .header-left {
    gap: 0.35rem;
  }
  .header-actions {
    gap: 0.35rem;
  }
  .pillar-tabs-inner {
    padding: 0 var(--raw-space-3);
  }
  .docs-main {
    padding: var(--raw-space-4) var(--raw-space-3) var(--raw-space-8);
  }
  .brand-link {
    font-size: 0.92rem;
    gap: 0.35rem;
  }
  .brand-link img {
    width: 20px;
    height: 20px;
  }
  .brand-name-ext,
  .brand-version,
  .search-label-ext {
    display: none;
  }
  .search-trigger {
    padding: 0 0.5rem;
    font-size: 0.8rem;
  }
  .theme-opt {
    padding: 0 0.38rem;
    font-size: 0.72rem;
  }
  .md-popover.is-fallback-open {
    left: 0;
    right: auto;
  }
  .spec-strip,
  .surface-selector,
  .resource-grid,
  .doc-pagination {
    grid-template-columns: minmax(0, 1fr);
  }
  .pagination-next {
    text-align: left;
  }
  .sim-shell,
  .prompt-card {
    padding: var(--raw-space-3);
  }
}

@media (max-width: 380px) {
  .header-row-1 {
    padding: 0 0.45rem;
    gap: 0.25rem;
  }
  .header-left {
    gap: 0.25rem;
  }
  .header-actions {
    gap: 0.25rem;
  }
  .brand-link {
    font-size: 0.84rem;
    gap: 0.28rem;
  }
  .brand-link img {
    width: 18px;
    height: 18px;
  }
  .search-trigger {
    min-height: 32px;
    padding: 0 0.42rem;
    font-size: 0.75rem;
  }
  .icon-btn {
    min-width: 30px;
    min-height: 32px;
    padding: 0 0.38rem;
    font-size: 0.75rem;
  }
  .theme-opt {
    min-height: 26px;
    padding: 0 0.28rem;
    font-size: 0.69rem;
  }
}

/* ==========================================================================
   PRINT, FORCED COLORS & REDUCED MOTION
   ========================================================================== */
@media print {
  :root,
  [data-theme="dark"] {
    --surface-canvas: #ffffff;
    --surface-panel: #ffffff;
    --surface-elevated: #ffffff;
    --surface-code: #f8fafc;
    --ink-primary: #000000;
    --ink-secondary: #1e293b;
    --ink-muted: #334155;
    --ink-code: #000000;
    --table-rule: #94a3b8;
  }
  .announcement-bar,
  .site-header,
  .sidebar,
  .toc-aside,
  .mobile-toc,
  .md-menu-wrap,
  .heading-anchor-btn,
  .copy-btn,
  .table-view-bar,
  .doc-pagination,
  .search-dialog,
  .sidebar-backdrop {
    display: none !important;
  }
  .docs-shell {
    display: block;
  }
  .docs-main {
    padding: 0;
  }
  .docs-article {
    max-width: none;
  }
  h1, h2, h3 {
    break-after: avoid;
  }
  .code-block,
  .callout,
  .sl-step,
  .table-scroll,
  .verdict-card {
    break-inside: avoid;
  }
}

@media (forced-colors: active) {
  .btn,
  .icon-btn,
  .search-trigger,
  .tab-btn,
  .preset-btn,
  .surface-card,
  .callout,
  .kbd,
  .decision-pill,
  .md-menu-btn,
  .md-popover,
  .search-dialog {
    border: 1px solid CanvasText;
  }
  :focus-visible {
    outline: 2px solid Highlight;
  }
}

@media (prefers-reduced-motion: reduce) {
  html {
    scroll-behavior: auto;
  }
  *,
  *::before,
  *::after {
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
  }
}
`;
}

export function renderAppJs(m: RepoMetrics, validSlugs: readonly string[]): string {
  const slugsJson = JSON.stringify(validSlugs);
  const checksumsJson = JSON.stringify(m.sha256Sums);
  return `/* Coldpin Documentation Portal v2 Runtime
 * Pure ES2020 | Zero innerHTML | Strict CSP ('self') | WCAG 2.2 AA
 * Features: 3-way Theme + BroadcastChannel sync, 4-Harness Master Selector,
 * Native Popover Markdown menu, Mobile Cards|Table switcher, WAI-ARIA Ctrl+K RRF Search,
 * CSS.highlights zero-XSS highlighting, Exact hook-eval.js Policy Lab, Live SEP-1865 MCP App,
 * Safe read-only Antigravity Prompt Composer, and Read-only WebMCP (document.modelContext).
 */
(function () {
  "use strict";

  var DOC_VERSION = ${JSON.stringify(m.version)};
  var VALID_SLUGS = ${slugsJson};
  var RELEASE_CHECKSUMS = ${checksumsJson};
  var RELEASE_URL = ${JSON.stringify(m.releaseUrl)};
  var MAX_INPUT_LEN = 4096;
  var WEBMCP_MAX_CHARS = 1500;

  var root = document.documentElement;
  var docsRoot = root.getAttribute("data-docs-root") || ".";
  var announcer = document.getElementById("live-announcer");
  var senderId = (typeof crypto !== "undefined" && crypto.randomUUID)
    ? crypto.randomUUID()
    : ("tab-" + String(Date.now()) + "-" + String(Math.random()).slice(2, 10));

  var bc = null;
  try {
    if (typeof BroadcastChannel === "function") {
      bc = new BroadcastChannel("coldpin-docs-sync");
    }
  } catch (_) {}

  function announce(msg) {
    if (!announcer) return;
    announcer.textContent = "";
    window.setTimeout(function () {
      announcer.textContent = msg;
    }, 30);
  }

  function resolveRelHref(logicalHref) {
    if (!logicalHref) return docsRoot + "/";
    if (/^https?:\\/\\//.test(logicalHref) || logicalHref.charAt(0) === "#") return logicalHref;
    if (logicalHref === "/") return docsRoot === "." ? "./" : docsRoot + "/";
    return docsRoot + "/" + logicalHref.replace(/^\\/+/, "");
  }

  /* ========================================================================
     1. 3-WAY THEME SELECTOR (Auto | Light | Dark) + BROADCASTCHANNEL SYNC
     ======================================================================== */
  var themeButtons = Array.prototype.slice.call(document.querySelectorAll("[data-theme-set]"));

  function systemPrefersDark() {
    return Boolean(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  }

  function resolveTheme(mode) {
    var m = mode || root.getAttribute("data-theme-mode") || "auto";
    if (m === "light" || m === "dark") return m;
    return systemPrefersDark() ? "dark" : "light";
  }

  function notifyMcpAppTheme(resolvedTheme) {
    var frame = document.getElementById("mcp-app-frame");
    if (frame && frame.contentWindow) {
      try {
        frame.contentWindow.postMessage({
          jsonrpc: "2.0",
          method: "ui/notifications/host-context-changed",
          params: { theme: resolvedTheme }
        }, "*");
      } catch (_) {}
    }
  }

  function applyThemeMode(mode, shouldPersist, shouldBroadcast) {
    var valid = (mode === "auto" || mode === "light" || mode === "dark") ? mode : "auto";
    var resolved = resolveTheme(valid);
    root.setAttribute("data-theme-mode", valid);
    root.setAttribute("data-theme", resolved);
    themeButtons.forEach(function (btn) {
      btn.setAttribute("aria-pressed", btn.getAttribute("data-theme-set") === valid ? "true" : "false");
    });
    if (shouldPersist) {
      try {
        window.localStorage.setItem("coldpin-docs-theme-mode", valid);
      } catch (_) {}
    }
    if (shouldBroadcast && bc) {
      try {
        bc.postMessage({ sender: senderId, type: "theme", mode: valid });
      } catch (_) {}
    }
    notifyMcpAppTheme(resolved);
  }

  applyThemeMode(root.getAttribute("data-theme-mode") || "auto", false, false);

  themeButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var mode = btn.getAttribute("data-theme-set") || "auto";
      applyThemeMode(mode, true, true);
      announce("Theme set to " + mode);
    });
  });

  if (window.matchMedia) {
    var mediaQ = window.matchMedia("(prefers-color-scheme: dark)");
    var onSystemChange = function () {
      if ((root.getAttribute("data-theme-mode") || "auto") === "auto") {
        applyThemeMode("auto", false, false);
      }
    };
    if (typeof mediaQ.addEventListener === "function") {
      mediaQ.addEventListener("change", onSystemChange);
    }
  }

  /* ========================================================================
     2. DISMISSIBLE ANNOUNCEMENT BAR
     ======================================================================== */
  var announceBar = document.getElementById("announcement-bar");
  var announceDismiss = document.getElementById("announcement-dismiss");
  if (announceBar && announceDismiss) {
    announceDismiss.addEventListener("click", function () {
      root.setAttribute("data-announce-dismissed", "true");
      announceBar.hidden = true;
      try {
        window.localStorage.setItem("coldpin-docs-announce-v" + DOC_VERSION, "dismissed");
      } catch (_) {}
      announce("Release announcement dismissed");
    });
  }

  /* ========================================================================
     3. MOBILE SIDEBAR DRAWER + SESSIONSTORAGE STATE PERSISTENCE
     ======================================================================== */
  var sidebar = document.getElementById("docs-sidebar");
  var menuBtn = document.getElementById("mobile-menu-btn");
  var sidebarBackdrop = document.getElementById("sidebar-backdrop");

  function setMenuOpen(open) {
    if (!sidebar || !menuBtn) return;
    sidebar.classList.toggle("is-open", open);
    menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    menuBtn.textContent = open ? "Close" : "Menu";
    if (sidebarBackdrop) sidebarBackdrop.hidden = !open;
  }

  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", function () {
      setMenuOpen(!sidebar.classList.contains("is-open"));
    });
    if (sidebarBackdrop) {
      sidebarBackdrop.addEventListener("click", function () {
        setMenuOpen(false);
        menuBtn.focus();
      });
    }
    sidebar.addEventListener("click", function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest("a.nav-link")) {
        setMenuOpen(false);
      }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && sidebar.classList.contains("is-open")) {
        setMenuOpen(false);
        menuBtn.focus();
      }
    });

    // Persist sidebar scroll & collapsible group state in sessionStorage
    try {
      var savedScroll = Number(window.sessionStorage.getItem("coldpin-sidebar-scroll") || "0");
      if (savedScroll > 0) sidebar.scrollTop = savedScroll;
      sidebar.addEventListener("scroll", function () {
        try {
          window.sessionStorage.setItem("coldpin-sidebar-scroll", String(sidebar.scrollTop));
        } catch (_) {}
      }, { passive: true });

      var groups = sidebar.querySelectorAll("details[data-nav-group]");
      var activePillar = root.getAttribute("data-pillar") || "";
      for (var g = 0; g < groups.length; g++) {
        (function (det) {
          var gid = det.getAttribute("data-nav-group") || "";
          var st = window.sessionStorage.getItem("coldpin-nav-" + gid);
          if (st === "open") det.open = true;
          else if (st === "closed" && gid !== activePillar) det.open = false;
          det.addEventListener("toggle", function () {
            try {
              window.sessionStorage.setItem("coldpin-nav-" + gid, det.open ? "open" : "closed");
            } catch (_) {}
          });
        })(groups[g]);
      }
    } catch (_) {}
  }

  /* ========================================================================
     4. SYNCED 4-HARNESS MASTER SELECTOR (?surface=, localStorage, Dynamic TOC)
     ======================================================================== */
  var VALID_SURFACES = { antigravity: true, "npm-cli": true, "mcp-hosts": true, "enterprise-http": true };
  var surfaceCards = Array.prototype.slice.call(document.querySelectorAll("[data-surface-select]"));
  var surfacePanes = Array.prototype.slice.call(document.querySelectorAll("[data-surface-pane]"));
  var tocSurfaceItems = Array.prototype.slice.call(document.querySelectorAll("[data-toc-surface]"));

  function applySurface(surfaceId, updateUrl, shouldPersist, shouldBroadcast) {
    var chosen = VALID_SURFACES[surfaceId] ? surfaceId : "antigravity";
    surfaceCards.forEach(function (card) {
      card.setAttribute("aria-pressed", card.getAttribute("data-surface-select") === chosen ? "true" : "false");
    });
    surfacePanes.forEach(function (pane) {
      pane.hidden = pane.getAttribute("data-surface-pane") !== chosen;
    });
    tocSurfaceItems.forEach(function (li) {
      li.hidden = li.getAttribute("data-toc-surface") !== chosen;
    });
    if (shouldPersist) {
      try {
        window.localStorage.setItem("coldpin-docs-surface", chosen);
      } catch (_) {}
    }
    if (updateUrl && window.history && typeof window.history.replaceState === "function") {
      try {
        var u = new URL(window.location.href);
        u.searchParams.set("surface", chosen);
        window.history.replaceState(null, "", u.pathname + u.search + u.hash);
      } catch (_) {}
    }
    if (shouldBroadcast && bc) {
      try {
        bc.postMessage({ sender: senderId, type: "surface", surface: chosen });
      } catch (_) {}
    }
  }

  if (surfaceCards.length > 0) {
    var initSurface = "antigravity";
    try {
      var sp = new URLSearchParams(window.location.search).get("surface");
      if (sp && VALID_SURFACES[sp]) {
        initSurface = sp;
      } else {
        var savedSurf = window.localStorage.getItem("coldpin-docs-surface");
        if (savedSurf && VALID_SURFACES[savedSurf]) initSurface = savedSurf;
      }
    } catch (_) {}
    applySurface(initSurface, false, false, false);

    surfaceCards.forEach(function (card) {
      card.addEventListener("click", function () {
        var s = card.getAttribute("data-surface-select") || "antigravity";
        applySurface(s, true, true, true);
        announce("Selected harness: " + s);
      });
    });
  }

  if (bc) {
    bc.addEventListener("message", function (ev) {
      var d = ev.data;
      if (!d || typeof d !== "object" || d.sender === senderId) return;
      if (d.type === "theme") applyThemeMode(d.mode, false, false);
      if (d.type === "surface" && surfaceCards.length > 0) applySurface(d.surface, false, false, false);
    });
  }

  /* ========================================================================
     5. NATIVE POPOVER MARKDOWN MENU + COPY MARKDOWN
     ======================================================================== */
  var mdBtn = document.getElementById("md-menu-btn");
  var mdPopover = document.getElementById("md-menu-popover");
  var hasNativePopover = Boolean(mdPopover && typeof mdPopover.showPopover === "function");

  if (mdBtn && mdPopover) {
    if (hasNativePopover) {
      mdPopover.addEventListener("toggle", function (ev) {
        var isOpen = ev.newState === "open";
        mdBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      });
    } else {
      mdBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var open = !mdPopover.classList.contains("is-fallback-open");
        mdPopover.classList.toggle("is-fallback-open", open);
        mdBtn.setAttribute("aria-expanded", open ? "true" : "false");
      });
      document.addEventListener("click", function (ev) {
        if (!mdPopover.contains(ev.target) && ev.target !== mdBtn) {
          mdPopover.classList.remove("is-fallback-open");
          mdBtn.setAttribute("aria-expanded", "false");
        }
      });
    }
  }

  function closeMdPopover() {
    if (!mdPopover) return;
    if (hasNativePopover) {
      try { mdPopover.hidePopover(); } catch (_) {}
    } else {
      mdPopover.classList.remove("is-fallback-open");
      if (mdBtn) mdBtn.setAttribute("aria-expanded", "false");
    }
  }

  var copyMdBtns = document.querySelectorAll("[data-copy-md]");
  for (var mIdx = 0; mIdx < copyMdBtns.length; mIdx++) {
    copyMdBtns[mIdx].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var mdUrl = btn.getAttribute("data-copy-md");
      if (!mdUrl || typeof fetch !== "function") return;
      btn.textContent = "Copying...";
      fetch(mdUrl, { credentials: "same-origin" })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.text();
        })
        .then(function (mdText) {
          if (!navigator.clipboard || !navigator.clipboard.writeText) {
            throw new Error("Clipboard unavailable");
          }
          return navigator.clipboard.writeText(mdText);
        })
        .then(function () {
          btn.textContent = "Copied Markdown";
          announce("Copied raw Markdown to clipboard");
          window.setTimeout(function () {
            btn.textContent = "Copy Markdown";
            closeMdPopover();
          }, 900);
        })
        .catch(function () {
          btn.textContent = "Copy failed";
          announce("Unable to copy Markdown; use View Markdown link");
          window.setTimeout(function () {
            btn.textContent = "Copy Markdown";
          }, 1500);
        });
    });
  }

  /* ========================================================================
     6. WAI-ARIA TAB GROUPS, COPY BUTTONS, HEADING ANCHORS, DETAILS TOOLBAR
     ======================================================================== */
  var tablists = document.querySelectorAll('[role="tablist"]');
  function activateTab(tablist, targetTab, shouldFocus) {
    var tabs = tablist.querySelectorAll('[role="tab"]');
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i];
      var selected = tab === targetTab;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.setAttribute("tabindex", selected ? "0" : "-1");
      var panelId = tab.getAttribute("aria-controls");
      var panel = panelId ? document.getElementById(panelId) : null;
      if (panel) panel.hidden = !selected;
    }
    if (shouldFocus) targetTab.focus();
  }

  for (var t = 0; t < tablists.length; t++) {
    (function (tablist) {
      var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
      tabs.forEach(function (tab, idx) {
        tab.addEventListener("click", function () {
          activateTab(tablist, tab, false);
        });
        tab.addEventListener("keydown", function (ev) {
          var nextIdx = -1;
          if (ev.key === "ArrowRight") nextIdx = (idx + 1) % tabs.length;
          else if (ev.key === "ArrowLeft") nextIdx = (idx - 1 + tabs.length) % tabs.length;
          else if (ev.key === "Home") nextIdx = 0;
          else if (ev.key === "End") nextIdx = tabs.length - 1;
          if (nextIdx !== -1) {
            ev.preventDefault();
            activateTab(tablist, tabs[nextIdx], true);
          }
        });
      });
    })(tablists[t]);
  }

  var copyButtons = document.querySelectorAll(".copy-btn[data-copy]");
  for (var c = 0; c < copyButtons.length; c++) {
    copyButtons[c].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var origLabel = btn.textContent || "Copy";
      var targetId = btn.getAttribute("data-copy");
      var el = targetId ? document.getElementById(targetId) : null;
      if (!el) return;
      var text = el.textContent || "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = "Copied";
          announce("Copied snippet to clipboard");
          window.setTimeout(function () { btn.textContent = origLabel; }, 1600);
        }, function () {
          announce("Copy failed: select the text manually");
        });
      } else {
        announce("Clipboard API unavailable: select the text manually");
      }
    });
  }

  var anchorBtns = document.querySelectorAll(".heading-anchor-btn[data-copy-anchor]");
  for (var a = 0; a < anchorBtns.length; a++) {
    anchorBtns[a].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var id = btn.getAttribute("data-copy-anchor");
      if (!id) return;
      var url = window.location.href.split("#")[0] + "#" + id;
      if (window.history && typeof window.history.replaceState === "function") {
        window.history.replaceState(null, "", "#" + id);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function () {
          btn.textContent = "✓";
          announce("Copied section link #" + id);
          window.setTimeout(function () { btn.textContent = "#"; }, 1400);
        }, function () {});
      }
    });
  }

  var detailsToolbars = document.querySelectorAll(".details-toolbar[data-details-target]");
  for (var dt = 0; dt < detailsToolbars.length; dt++) {
    (function (bar) {
      var targetId = bar.getAttribute("data-details-target");
      var container = targetId ? document.getElementById(targetId) : null;
      if (!container) return;
      var btns = bar.querySelectorAll("[data-details-action]");
      for (var b = 0; b < btns.length; b++) {
        btns[b].addEventListener("click", function (ev) {
          var action = ev.currentTarget.getAttribute("data-details-action");
          var items = container.querySelectorAll("details");
          var open = action === "expand";
          for (var k = 0; k < items.length; k++) items[k].open = open;
          announce(open ? "Expanded all releases" : "Collapsed all releases");
        });
      }
    })(detailsToolbars[dt]);
  }

  /* ========================================================================
     7. MOBILE CARDS | TABLE VIEW SWITCHER
     ======================================================================== */
  var tableSwitchers = document.querySelectorAll('[data-table-switcher="true"]');
  for (var ts = 0; ts < tableSwitchers.length; ts++) {
    (function (wrap) {
      var btns = Array.prototype.slice.call(wrap.querySelectorAll("[data-table-view]"));
      btns.forEach(function (btn) {
        btn.addEventListener("click", function () {
          var view = btn.getAttribute("data-table-view") === "table" ? "table" : "cards";
          wrap.setAttribute("data-view", view);
          btns.forEach(function (b) {
            b.setAttribute("aria-pressed", b.getAttribute("data-table-view") === view ? "true" : "false");
          });
          announce("Switched mobile table view to " + view);
        });
      });
    })(tableSwitchers[ts]);
  }

  /* ========================================================================
     8. SAFE READ-ONLY ANTIGRAVITY PROMPT DEEP-LINK LAUNCHER (ZERO npx LINKS)
     ======================================================================== */
  var agyBtns = document.querySelectorAll(".agy-deeplink-btn[data-agy-prompt]");
  for (var dIdx = 0; dIdx < agyBtns.length; dIdx++) {
    agyBtns[dIdx].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var prompt = btn.getAttribute("data-agy-prompt") || "";
      var fbId = btn.getAttribute("data-fallback-id");
      var fbEl = fbId ? document.getElementById(fbId) : null;
      // Defense-in-depth: never emit npx execution deep links
      if (!prompt || /\\bnpx\\b/i.test(prompt)) return;

      var handled = false;
      function markHandled() {
        handled = true;
        window.removeEventListener("blur", markHandled);
        document.removeEventListener("visibilitychange", onVis);
      }
      function onVis() {
        if (document.hidden) markHandled();
      }
      window.addEventListener("blur", markHandled);
      document.addEventListener("visibilitychange", onVis);

      var deepUrl = "antigravity://open?prompt=" + encodeURIComponent(prompt);
      window.location.href = deepUrl;

      window.setTimeout(function () {
        window.removeEventListener("blur", markHandled);
        document.removeEventListener("visibilitychange", onVis);
        if (!handled && fbEl) {
          fbEl.hidden = false;
          announce("Antigravity desktop app did not respond; copy the prompt manually.");
        }
      }, 1500);
    });
  }

  /* ========================================================================
     9. INTERACTIVE POLICY LAB: EXACT src/hook-core.ts ENGINE (100% PARITY)
     ======================================================================== */
  var toolSelect = document.getElementById("sim-tool");
  var payloadInput = document.getElementById("sim-payload");
  var decisionBadge = document.getElementById("sim-decision-badge");
  var metaEl = document.getElementById("sim-meta");
  var reasonEl = document.getElementById("sim-reason");
  var stdinEl = document.getElementById("sim-stdin-json");
  var jsonEl = document.getElementById("sim-json");

  function hookGroupForTool(toolName) {
    if (toolName === "define_subagent") return "coldpin-delegation-guard";
    if (
      toolName === "write_to_file" ||
      toolName === "replace_file_content" ||
      toolName === "multi_replace_file_content" ||
      toolName === "write_file" ||
      toolName === "edit_file" ||
      toolName === "sed_file"
    ) {
      return "coldpin-config-guard";
    }
    if (toolName === "raw_json") return "fail-closed-parser";
    return "coldpin-npx-guard";
  }

  function buildHookPayloadObject(toolName, rawValue) {
    var val = String(rawValue || "").slice(0, MAX_INPUT_LEN);
    if (toolName === "raw_json") {
      var trimmed = val.trim();
      if (!trimmed) return { parseError: "Empty hook stdin payload; explicit human confirmation required.", rawText: "" };
      try {
        return { payload: JSON.parse(trimmed), rawText: trimmed };
      } catch (_) {
        return { parseError: "Malformed JSON on hook stdin; explicit human confirmation required.", rawText: trimmed };
      }
    }
    if (toolName === "run_command") {
      return { payload: { toolCall: { name: "run_command", args: { CommandLine: val } } } };
    }
    if (toolName === "manage_task") {
      return { payload: { toolCall: { name: "manage_task", args: { Action: "send_input", Input: val } } } };
    }
    if (toolName === "define_subagent") {
      var trimmedSub = val.trim();
      var argsObj = {};
      try {
        var parsed = JSON.parse(trimmedSub || "{}");
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) argsObj = parsed;
      } catch (_) {
        if (trimmedSub.charAt(0) === "{" || trimmedSub.charAt(0) === "[") {
          return { parseError: "Malformed JSON in define_subagent payload; explicit human confirmation required.", rawText: trimmedSub };
        }
        if (/\\b(EnableWriteTools|enable_write_tools)\\s*:\\s*true\\b/i.test(val)) {
          argsObj = { EnableWriteTools: true };
        } else {
          argsObj = { EnableWriteTools: false };
        }
      }
      return { payload: { toolCall: { name: "define_subagent", args: argsObj } } };
    }
    return { payload: { toolCall: { name: toolName, args: { TargetFile: val } } } };
  }

  function evaluateRealHook(toolName, rawValue) {
    var built = buildHookPayloadObject(toolName, rawValue);
    if (built.parseError) {
      return {
        hookGroup: hookGroupForTool(toolName),
        stdinDisplay: built.rawText || "(empty stdin)",
        result: { decision: "force_ask", reason: built.parseError }
      };
    }
    var core = window.ColdpinHookCore;
    var res = (core && typeof core.evaluatePreToolUsePayload === "function")
      ? core.evaluatePreToolUsePayload(built.payload)
      : { decision: "force_ask", reason: "Hook engine failed to load; failing closed." };
    return {
      hookGroup: hookGroupForTool(toolName),
      stdinDisplay: JSON.stringify(built.payload, null, 2),
      result: res
    };
  }

  function renderHookSimulation() {
    if (!toolSelect || !payloadInput || !decisionBadge || !metaEl || !reasonEl || !jsonEl) return;
    var out = evaluateRealHook(toolSelect.value, payloadInput.value);
    var dec = out.result.decision;
    decisionBadge.className = "decision-pill";
    if (dec === "allow") {
      decisionBadge.classList.add("decision-allow");
      decisionBadge.textContent = "ALLOW";
    } else if (dec === "force_ask") {
      decisionBadge.classList.add("decision-ask");
      decisionBadge.textContent = "FORCE_ASK";
    } else {
      decisionBadge.classList.add("decision-deny");
      decisionBadge.textContent = "DENY";
    }
    metaEl.textContent = out.hookGroup + " · real src/hook-core.ts engine · exit 0";
    reasonEl.textContent = out.result.reason || "Allowed cleanly under default Antigravity host policy (zero auto-approval).";
    if (stdinEl) stdinEl.textContent = out.stdinDisplay;
    jsonEl.textContent = JSON.stringify(out.result, null, 2);
  }

  if (toolSelect && payloadInput) {
    var simPresetBtns = Array.prototype.slice.call(document.querySelectorAll(".preset-btn[data-sim-tool]"));
    function syncSimPresetPressed() {
      simPresetBtns.forEach(function (b) {
        var match = b.getAttribute("data-sim-tool") === toolSelect.value && b.getAttribute("data-sim-payload") === payloadInput.value;
        b.setAttribute("aria-pressed", match ? "true" : "false");
      });
    }
    toolSelect.addEventListener("change", function () { syncSimPresetPressed(); renderHookSimulation(); });
    payloadInput.addEventListener("input", function () { syncSimPresetPressed(); renderHookSimulation(); });
    simPresetBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        toolSelect.value = btn.getAttribute("data-sim-tool") || "run_command";
        payloadInput.value = btn.getAttribute("data-sim-payload") || "";
        syncSimPresetPressed();
        renderHookSimulation();
        announce("Simulated " + btn.textContent);
      });
    });
    renderHookSimulation();
  }

  /* ========================================================================
     10. 4-STATE VERDICT EXPLORER + LIVE SEP-1865 MCP APP SANDBOX BRIDGE
     ======================================================================== */
  var VERDICTS = {
    clean: {
      title: "semver@7.7.1",
      badgeClass: "decision-allow",
      badgeText: "VERIFIED_CLEAN_WITHIN_SCOPE (exit 0)",
      sha512: "sha512-verified (in-memory stream, 14 files, 0 lifecycle hooks)",
      parity: "Tier 1 + Tier 2 verified (Git tag matches tarball files)",
      findings: "0 malicious indicators, 0 OSV/MAL-* advisories, 0 hidden Unicode or taint chains",
      unknowns: "Runtime behavior of floating transitive dependencies is outside static tarball scope.",
      command: "npx --yes --ignore-scripts --package=semver@7.7.1 -- semver --help",
      mcpPayload: {
        report_id: "rep_clean_semver771",
        package_name: "semver",
        version: "7.7.1",
        verdict: "VERIFIED_CLEAN_WITHIN_SCOPE",
        parity_tier: "TIER_1_AND_2_VERIFIED",
        provenance_status: "PROVENANCE_UNANCHORED_DSSE",
        integrity_sha512: "sha512-4L2fQ9a8V7rB9mN3pK1xZ0wT6yH2cD5eJ8uS1vA4bC7dE9fG==",
        pinned_execution: {
          command: "npx --yes --ignore-scripts --package=semver@7.7.1 -- semver --help",
          caveat: "Stock npx has no --integrity flag and resolves floating transitive ranges at runtime."
        },
        counts: { observations: 1, unknowns: 1, iocs: 0 },
        top_observations: [
          { code: "IN_MEMORY_QUARANTINE_OK", severity: "INFO", detail: "14 archive entries verified; 0 lifecycle hooks, 0 taint chains, 0 OSV advisories." }
        ],
        unknowns: [
          "Runtime behavior of floating transitive dependencies is outside static tarball scope."
        ],
        iocs: []
      }
    },
    suspicious: {
      title: "fast-json-helper@2.4.1",
      badgeClass: "decision-ask",
      badgeText: "QUARANTINE_SUSPICIOUS (exit 2)",
      sha512: "sha512-verified (42 files; postinstall script present)",
      parity: "Tarball drift detected: dist/loader.js absent from Git tag v2.4.1",
      findings: "High-entropy escape density (6.12 bits/char) and dynamic Function() invocation",
      unknowns: "Obfuscated bundle requires Tier-2 REA inspection before human decision.",
      command: "# Command suppressed. Run: coldpin resolve-anchor fast-json-helper --git-dir ./repo",
      mcpPayload: {
        report_id: "rep_susp_fastjson",
        package_name: "fast-json-helper",
        version: "2.4.1",
        verdict: "QUARANTINE_SUSPICIOUS",
        parity_tier: "TARBALL_SOURCE_DRIFT",
        provenance_status: "PROVENANCE_ABSENT",
        integrity_sha512: "sha512-9X7mP2kL4qR8vN1wC5tB6yF3hJ0dS8uA2cE4gK6mN9pQ1rT==",
        counts: { observations: 3, unknowns: 2, iocs: 0 },
        top_observations: [
          { code: "TARBALL_SOURCE_DRIFT", severity: "HIGH", path: "dist/loader.js", detail: "Compiled file absent from Git tag v2.4.1." },
          { code: "HIGH_ENTROPY_OBFUSCATION", severity: "MEDIUM", path: "dist/loader.js", line: 1, detail: "Dense hex/unicode escape obfuscation (6.12 bits/char)." }
        ],
        unknowns: [
          "Obfuscated dist/loader.js requires Tier-2 REA decompilation before approval."
        ],
        iocs: [],
        pagedMore: {
          observations: [
            { code: "LIFECYCLE_HOOK_PRESENT", severity: "MEDIUM", path: "package.json", detail: "postinstall script executes node dist/loader.js." }
          ],
          unknowns: [
            "No SLSA provenance attestation found on npm registry response."
          ]
        }
      }
    },
    malicious: {
      title: "react-cli-utils@1.9.4",
      badgeClass: "decision-deny",
      badgeText: "MALICIOUS_INDICATORS_FOUND (exit 3)",
      sha512: "sha512-verified (OSV advisory MAL-2026-00419 matched)",
      parity: "Tarball-only injection in preinstall.js; source repo HEAD uncompromised",
      findings: "TAINT_CRED_TO_NETWORK_OR_EXEC: process.env -> https.request(hxxps://collect[.]evil[.]example/ingest)",
      unknowns: "Check local package-lock.json and rotate exposed CI/developer tokens immediately.",
      command: "# Execution blocked. Run /coldpin-incident or coldpin resolve-anchor react-cli-utils",
      mcpPayload: {
        report_id: "rep_mal_reactcli",
        package_name: "react-cli-utils",
        version: "1.9.4",
        verdict: "MALICIOUS_INDICATORS_FOUND",
        parity_tier: "TARBALL_ONLY_INJECTION",
        provenance_status: "PROVENANCE_DIGEST_MISMATCH",
        local_workspace_compromised: true,
        integrity_sha512: "sha512-0A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE==",
        counts: { observations: 2, unknowns: 1, iocs: 2 },
        top_observations: [
          { code: "TAINT_CRED_TO_NETWORK_OR_EXEC", severity: "CRITICAL", path: "scripts/preinstall.js", line: 14, detail: "process.env serialized into https.request body." },
          { code: "OSV_MALICIOUS_ADVISORY", severity: "CRITICAL", detail: "Matched OpenSSF MAL-2026-00419." }
        ],
        unknowns: [
          "Verify whether prior CI runs installed 1.9.4 and rotate npm/GitHub/cloud tokens."
        ],
        iocs: [
          { kind: "url", tlp: "TLP:CLEAR", value: "hxxps://collect[.]evil[.]example/ingest" }
        ],
        pagedMore: {
          iocs: [
            { kind: "domain", tlp: "TLP:CLEAR", value: "collect[.]evil[.]example" }
          ]
        }
      }
    },
    unknown: {
      title: "native-crypto-cli@0.8.0",
      badgeClass: "decision-ask",
      badgeText: "UNVERIFIABLE_UNKNOWN (exit 2)",
      sha512: "sha512-verified (offline mode or compiled native binary)",
      parity: "Contains prebuilt ELF/PE .node binary (bin/addon.node)",
      findings: "0 JS taint findings, but native binary payload is opaque to JS/TS static analysis",
      unknowns: "Fail-closed: escalate binary to pre-registered REA server before execution.",
      command: "# Command suppressed under fail-closed policy (uninspected native artifact)",
      mcpPayload: {
        report_id: "rep_unk_native",
        package_name: "native-crypto-cli",
        version: "0.8.0",
        verdict: "UNVERIFIABLE_UNKNOWN",
        parity_tier: "UNINSPECTED_BINARY_ARTIFACT",
        provenance_status: "PROVENANCE_ABSENT",
        counts: { observations: 1, unknowns: 1, iocs: 0 },
        top_observations: [
          { code: "UNINSPECTED_NATIVE_BINARY", severity: "HIGH", path: "bin/addon.node", detail: "Compiled ELF/PE native addon is opaque to JS/TS static taint analysis." }
        ],
        unknowns: [
          "Escalate bin/addon.node to pre-registered REA server (never bootstrap rea-agents via npx)."
        ],
        iocs: []
      }
    },
    batch: {
      title: "package.json (audit_manifest_batch)",
      badgeClass: "decision-deny",
      badgeText: "MALICIOUS_OR_BLOCKED (exit 3)",
      sha512: "50 / 50 direct dependencies screened locally ($0/mo)",
      parity: "Private @acme/* scopes isolated from public registry & OSV",
      findings: "1 MALICIOUS_OR_BLOCKED (es1int homoglyph), 1 FLAGGED_SUSPICIOUS, 48 CLEAN_SCREENED",
      unknowns: "Batch triage screens metadata, squats, policy & OSV; run inspect_package_artifact on flagged deps.",
      command: "# Run: coldpin inspect es1int@1.0.2 --offline",
      mcpPayload: {
        report_id: "rep_batch_demo",
        manifest_path: "./package.json",
        total_declared: 50,
        evaluated_count: 50,
        summary_counts: { clean_screened: 48, flagged_suspicious: 1, malicious_or_blocked: 1 },
        counts: { observations: 2, unknowns: 1, iocs: 0 },
        top_flagged: [
          { package_name: "es1int", status: "MALICIOUS_OR_BLOCKED", reason: "Homoglyph typosquat of popular package 'eslint'." },
          { package_name: "@acme-internal/ui", status: "FLAGGED_SUSPICIOUS", reason: "Private scope unconfigured in .npmrc (T1195.001 confusion risk)." }
        ],
        unknowns: [
          "Private-scope packages were withheld from public api.osv.dev per non-leakage policy."
        ],
        iocs: []
      }
    },
    anchor: {
      title: "@org/cli (resolve_safe_anchor)",
      badgeClass: "decision-allow",
      badgeText: "ROLLBACK_TO_SAFE_ANCHOR (exit 0)",
      sha512: "Patient-zero commit 8f4c12a9b0e1 isolated via --first-parent SQLite cache",
      parity: "Verified npm tarball @org/cli@2.3.0 matches pre-compromise commit 3b9e41d0f2a7",
      findings: "0 residual CVEs / 0 CISA KEV advisories on 2.3.0",
      unknowns: "Verify local lockfiles do not pin 2.3.1+ and rotate exposed tokens if compromised version ran.",
      command: "npx --yes --ignore-scripts --package=@org/cli@2.3.0 -- cli --version",
      mcpPayload: {
        report_id: "rep_anchor_orgcli",
        package_name: "@org/cli",
        recommended_action: "ROLLBACK_TO_SAFE_ANCHOR",
        patient_zero_commit: "8f4c12a9b0e14492d10a",
        safe_anchor_version: "2.3.0",
        commit_sha: "3b9e41d0f2a78813c90e",
        pinned_execution: {
          command: "npx --yes --ignore-scripts --package=@org/cli@2.3.0 -- cli --version",
          caveat: "Rollback target verified clean in static scope with 0 KEV/CVE advisories."
        },
        counts: { observations: 1, unknowns: 1, iocs: 0 },
        top_observations: [
          { code: "SAFE_ANCHOR_VERIFIED", severity: "INFO", detail: "Commit 3b9e41d0f2a7 precedes patient-zero 8f4c12a9b0e1 and matches published npm tarball 2.3.0." }
        ],
        unknowns: [
          "Confirm local package-lock.json and CI caches purge version 2.3.1."
        ],
        iocs: []
      }
    }
  };

  var activeVerdictKey = "clean";
  var mcpAppReady = false;
  var mcpAppFrame = document.getElementById("mcp-app-frame");
  var vTitle = document.getElementById("vc-title");
  var vBadge = document.getElementById("vc-badge");
  var vSha = document.getElementById("vc-sha");
  var vParity = document.getElementById("vc-parity");
  var vFindings = document.getElementById("vc-findings");
  var vUnknowns = document.getElementById("vc-unknowns");
  var vCmd = document.getElementById("vc-cmd");
  var verdictBtns = Array.prototype.slice.call(document.querySelectorAll(".preset-btn[data-verdict]"));

  function pushVerdictToMcpApp(key) {
    if (!mcpAppFrame || !mcpAppFrame.contentWindow) return;
    var entry = VERDICTS[key] || VERDICTS.clean;
    try {
      mcpAppFrame.contentWindow.postMessage({
        jsonrpc: "2.0",
        method: "ui/notifications/tool-result",
        params: { structuredContent: entry.mcpPayload }
      }, "*");
    } catch (_) {}
  }

  function renderVerdictCard(key) {
    activeVerdictKey = VERDICTS[key] ? key : "clean";
    var data = VERDICTS[activeVerdictKey];
    verdictBtns.forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-verdict") === activeVerdictKey ? "true" : "false");
    });
    if (vTitle) {
      vTitle.textContent = data.title;
      vBadge.className = "decision-pill " + data.badgeClass;
      vBadge.textContent = data.badgeText;
      vSha.textContent = data.sha512;
      vParity.textContent = data.parity;
      vFindings.textContent = data.findings;
      vUnknowns.textContent = data.unknowns;
      vCmd.textContent = data.command;
    }
    if (mcpAppReady) pushVerdictToMcpApp(activeVerdictKey);
  }

  if (verdictBtns.length > 0) {
    verdictBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var key = btn.getAttribute("data-verdict") || "clean";
        renderVerdictCard(key);
        announce("Loaded " + key + " evidence card sample");
      });
    });
    renderVerdictCard("clean");
  }

  if (mcpAppFrame) {
    window.addEventListener("message", function (ev) {
      if (ev.source !== mcpAppFrame.contentWindow) return;
      var msg = ev.data;
      if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") return;

      if (msg.method === "ui/initialize" && msg.id !== undefined) {
        mcpAppFrame.contentWindow.postMessage({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            protocolVersion: "2026-01-26",
            hostInfo: { name: "Coldpin Docs Policy Lab", version: DOC_VERSION },
            hostContext: { theme: resolveTheme() }
          }
        }, "*");
        return;
      }

      if (msg.method === "ui/notifications/initialized") {
        mcpAppReady = true;
        pushVerdictToMcpApp(activeVerdictKey);
        return;
      }

      if (msg.method === "ui/notifications/size-changed" && msg.params && typeof msg.params.height === "number") {
        var clamped = Math.max(260, Math.min(680, Math.ceil(msg.params.height) + 16));
        mcpAppFrame.style.height = String(clamped) + "px";
        return;
      }

      if (msg.method === "tools/call" && msg.id !== undefined && msg.params && msg.params.name === "get_artifact_report") {
        var callArgs = msg.params.arguments || {};
        var sec = callArgs.section || "observations";
        var cur = VERDICTS[activeVerdictKey] || VERDICTS.clean;
        var extra = (cur.mcpPayload.pagedMore && cur.mcpPayload.pagedMore[sec]) || [];
        var base = sec === "observations"
          ? (cur.mcpPayload.top_observations || cur.mcpPayload.top_flagged || [])
          : sec === "unknowns"
            ? (cur.mcpPayload.unknowns || [])
            : (cur.mcpPayload.iocs || []);
        mcpAppFrame.contentWindow.postMessage({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            structuredContent: {
              report_id: cur.mcpPayload.report_id,
              section: sec,
              items: base.concat(extra),
              next_offset: null
            }
          }
        }, "*");
      }
    });

    function isMcpAppDocumentLoaded() {
      try {
        var doc = mcpAppFrame.contentDocument;
        return Boolean(
          doc &&
          doc.readyState === "complete" &&
          doc.location &&
          doc.location.href &&
          doc.location.href !== "about:blank"
        );
      } catch (_) {
        return true;
      }
    }

    function ensureMcpAppBootstrapped() {
      if (!isMcpAppDocumentLoaded()) return;
      window.setTimeout(function () {
        if (!mcpAppReady && isMcpAppDocumentLoaded()) {
          mcpAppReady = true;
          notifyMcpAppTheme(resolveTheme());
          pushVerdictToMcpApp(activeVerdictKey);
        }
      }, 250);
    }
    mcpAppFrame.addEventListener("load", ensureMcpAppBootstrapped);
    if (isMcpAppDocumentLoaded()) {
      ensureMcpAppBootstrapped();
    }
  }

  /* ========================================================================
     11. WAI-ARIA COMMAND PALETTE SEARCH (Ctrl+K / '/', Zero-ReDoS RRF)
     ======================================================================== */
  var searchDialog = document.getElementById("search-dialog");
  var searchTrigger = document.getElementById("search-trigger");
  var searchInput = document.getElementById("search-input");
  var searchClose = document.getElementById("search-close");
  var searchList = document.getElementById("search-results");
  var searchStatus = document.getElementById("search-status");
  var searchChipBtns = Array.prototype.slice.call(document.querySelectorAll(".search-chip[data-search-pillar]"));

  var searchData = null;
  var searchLoadPromise = null;
  var activePillarFilter = "all";
  var activeResultIdx = -1;
  var currentRenderedItems = [];
  var lastTriggerFocus = null;

  function loadSearchIndex() {
    if (searchData) return Promise.resolve(searchData);
    if (searchLoadPromise) return searchLoadPromise;
    var url = docsRoot + "/search-index.json";
    searchLoadPromise = fetch(url, { credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (json) {
        searchData = json;
        return json;
      })
      .catch(function () {
        searchData = { version: DOC_VERSION, synonyms: {}, discovery: [], entries: [] };
        return searchData;
      });
    return searchLoadPromise;
  }

  function scoreRrfSearch(indexObj, rawQuery, pillarFilter) {
    var q = String(rawQuery || "").slice(0, 128).trim().toLowerCase();
    var entries = (indexObj && Array.isArray(indexObj.entries)) ? indexObj.entries : [];
    var synonyms = (indexObj && indexObj.synonyms) || {};

    var filtered = entries.filter(function (item) {
      return !pillarFilter || pillarFilter === "all" || item.pillar === pillarFilter;
    });
    if (!q) return [];

    var rawTokens = q.split(/\\s+/).filter(Boolean).slice(0, 8);
    var expandedSet = {};
    rawTokens.forEach(function (tok) {
      if (Array.isArray(synonyms[tok])) {
        synonyms[tok].forEach(function (syn) { expandedSet[String(syn).toLowerCase()] = true; });
      }
    });
    var synTokens = Object.keys(expandedSet);

    var titleRanks = [];
    var bodyRanks = [];
    var synRanks = [];

    filtered.forEach(function (item) {
      var tLow = item.title.toLowerCase();
      var pLow = item.pageTitle.toLowerCase();
      var kLow = item.keywords;
      var sLow = item.snippet.toLowerCase();

      var titleScore = 0;
      if (tLow === q) titleScore += 100;
      else if (tLow.indexOf(q) === 0) titleScore += 65;
      else if (tLow.indexOf(q) !== -1) titleScore += 45;
      rawTokens.forEach(function (tok) {
        if (tLow.indexOf(tok) !== -1) titleScore += 18;
        if (pLow.indexOf(tok) !== -1) titleScore += 8;
      });
      if (titleScore > 0) titleRanks.push({ item: item, score: titleScore });

      var bodyScore = 0;
      rawTokens.forEach(function (tok) {
        if (kLow.indexOf(tok) !== -1) bodyScore += 14;
        if (sLow.indexOf(tok) !== -1) bodyScore += 10;
      });
      if (bodyScore > 0) bodyRanks.push({ item: item, score: bodyScore });

      if (synTokens.length > 0) {
        var synScore = 0;
        synTokens.forEach(function (syn) {
          if (tLow.indexOf(syn) !== -1) synScore += 10;
          if (kLow.indexOf(syn) !== -1 || sLow.indexOf(syn) !== -1) synScore += 6;
        });
        if (synScore > 0) synRanks.push({ item: item, score: synScore });
      }
    });

    function sortDesc(a, b) { return b.score - a.score; }
    titleRanks.sort(sortDesc);
    bodyRanks.sort(sortDesc);
    synRanks.sort(sortDesc);

    var rrfK = 30;
    var combined = {};
    var byId = {};

    function foldList(list, weight) {
      for (var i = 0; i < list.length; i++) {
        var id = list[i].item.id;
        byId[id] = list[i].item;
        combined[id] = (combined[id] || 0) + (weight / (rrfK + i + 1));
      }
    }
    foldList(titleRanks, 1.5);
    foldList(bodyRanks, 1.0);
    foldList(synRanks, 0.7);

    return Object.keys(combined)
      .map(function (id) { return { item: byId[id], rrf: combined[id] }; })
      .sort(function (a, b) { return b.rrf - a.rrf; })
      .slice(0, 14)
      .map(function (x) { return x.item; });
  }

  function clearChildren(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function setSelectedResult(idx) {
    if (!searchList || !searchInput) return;
    var opts = searchList.querySelectorAll('[role="option"]');
    if (opts.length === 0) {
      activeResultIdx = -1;
      searchInput.removeAttribute("aria-activedescendant");
      return;
    }
    var bounded = Math.max(0, Math.min(opts.length - 1, idx));
    activeResultIdx = bounded;
    for (var i = 0; i < opts.length; i++) {
      var sel = i === bounded;
      opts[i].setAttribute("aria-selected", sel ? "true" : "false");
      if (sel) {
        searchInput.setAttribute("aria-activedescendant", opts[i].id);
        if (typeof opts[i].scrollIntoView === "function") {
          opts[i].scrollIntoView({ block: "nearest" });
        }
      }
    }
  }

  function buildSearchHref(logicalHref, queryText) {
    var rel = resolveRelHref(logicalHref);
    var q = String(queryText || "").trim();
    if (!q) return rel;
    var parts = rel.split("#");
    var sep = parts[0].indexOf("?") >= 0 ? "&" : "?";
    return parts[0] + sep + "hl=" + encodeURIComponent(q.slice(0, 64)) + (parts[1] ? "#" + parts[1] : "");
  }

  function renderSearchPalette(query) {
    if (!searchList) return;
    clearChildren(searchList);
    currentRenderedItems = [];
    var q = String(query || "").slice(0, 128).trim();

    if (!q && searchData && Array.isArray(searchData.discovery)) {
      var disc = searchData.discovery.filter(function (d) {
        return activePillarFilter === "all" || d.pillarId === activePillarFilter;
      });
      var toShow = disc.length > 0 ? disc : searchData.discovery;
      toShow.forEach(function (card, idx) {
        var li = document.createElement("li");
        li.className = "search-result-option";
        li.id = "search-opt-" + String(idx);
        li.setAttribute("role", "option");
        li.setAttribute("aria-selected", idx === 0 ? "true" : "false");

        var a = document.createElement("a");
        a.className = "search-result-link";
        a.href = resolveRelHref(card.href);

        var top = document.createElement("span");
        top.className = "search-result-top";
        var tSpan = document.createElement("span");
        tSpan.className = "search-result-title";
        tSpan.textContent = card.title;
        var mSpan = document.createElement("span");
        mSpan.className = "search-result-meta";
        mSpan.textContent = card.pillar;
        top.appendChild(tSpan);
        top.appendChild(mSpan);

        var snip = document.createElement("span");
        snip.className = "search-result-snippet";
        snip.textContent = card.note;

        a.appendChild(top);
        a.appendChild(snip);
        a.addEventListener("click", function () {
          if (searchDialog && searchDialog.open) searchDialog.close();
        });
        li.appendChild(a);
        searchList.appendChild(li);
        currentRenderedItems.push(a);
      });
      if (searchStatus) searchStatus.textContent = "Showing " + String(currentRenderedItems.length) + " discovery guides.";
      setSelectedResult(0);
      return;
    }

    var matches = scoreRrfSearch(searchData, q, activePillarFilter);
    if (matches.length === 0) {
      var empty = document.createElement("li");
      empty.className = "search-empty";
      empty.textContent = "No Coldpin documentation matched '" + q + "'. Try 'hooks', 'oauth', 'sbom', 'offline', or 'sha256sums'.";
      searchList.appendChild(empty);
      if (searchStatus) searchStatus.textContent = "No documentation matched.";
      setSelectedResult(-1);
      return;
    }

    matches.forEach(function (item, idx) {
      var li = document.createElement("li");
      li.className = "search-result-option";
      li.id = "search-opt-" + String(idx);
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", idx === 0 ? "true" : "false");

      var a = document.createElement("a");
      a.className = "search-result-link";
      a.href = buildSearchHref(item.href, q);

      var top = document.createElement("span");
      top.className = "search-result-top";
      var tSpan = document.createElement("span");
      tSpan.className = "search-result-title";
      tSpan.textContent = item.title;
      var mSpan = document.createElement("span");
      mSpan.className = "search-result-meta";
      mSpan.textContent = item.pillarLabel + " · " + item.pageTitle;
      top.appendChild(tSpan);
      top.appendChild(mSpan);

      var snip = document.createElement("span");
      snip.className = "search-result-snippet";
      snip.textContent = item.snippet;

      a.appendChild(top);
      a.appendChild(snip);
      a.addEventListener("click", function () {
        if (searchDialog && searchDialog.open) searchDialog.close();
      });
      li.appendChild(a);
      searchList.appendChild(li);
      currentRenderedItems.push(a);
    });
    if (searchStatus) searchStatus.textContent = String(matches.length) + " results available.";
    setSelectedResult(0);
  }

  function openSearch() {
    if (!searchDialog || typeof searchDialog.showModal !== "function") return;
    if (searchDialog.open) {
      searchDialog.close();
      return;
    }
    lastTriggerFocus = document.activeElement;
    searchDialog.showModal();
    if (searchInput) {
      searchInput.focus();
      searchInput.select();
    }
    loadSearchIndex().then(function () {
      renderSearchPalette(searchInput ? searchInput.value : "");
    });
  }

  if (searchTrigger) searchTrigger.addEventListener("click", openSearch);
  if (searchClose && searchDialog) {
    searchClose.addEventListener("click", function () { searchDialog.close(); });
  }
  if (searchDialog) {
    searchDialog.addEventListener("click", function (ev) {
      if (ev.target === searchDialog) searchDialog.close();
    });
    searchDialog.addEventListener("close", function () {
      if (lastTriggerFocus && typeof lastTriggerFocus.focus === "function") {
        lastTriggerFocus.focus();
      }
      lastTriggerFocus = null;
    });
  }
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      renderSearchPalette(searchInput.value);
    });
    searchInput.addEventListener("keydown", function (ev) {
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        setSelectedResult(activeResultIdx + 1);
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault();
        setSelectedResult(activeResultIdx - 1);
      } else if (ev.key === "Home") {
        ev.preventDefault();
        setSelectedResult(0);
      } else if (ev.key === "End") {
        ev.preventDefault();
        setSelectedResult(currentRenderedItems.length - 1);
      } else if (ev.key === "Enter" && activeResultIdx >= 0 && currentRenderedItems[activeResultIdx]) {
        ev.preventDefault();
        currentRenderedItems[activeResultIdx].click();
      }
    });
  }

  searchChipBtns.forEach(function (chip) {
    chip.addEventListener("click", function () {
      activePillarFilter = chip.getAttribute("data-search-pillar") || "all";
      searchChipBtns.forEach(function (b) {
        b.setAttribute("aria-pressed", b.getAttribute("data-search-pillar") === activePillarFilter ? "true" : "false");
      });
      renderSearchPalette(searchInput ? searchInput.value : "");
    });
  });

  document.addEventListener("keydown", function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault();
      openSearch();
    } else if (ev.key === "/" && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      var tag = document.activeElement ? document.activeElement.tagName : "";
      if (tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") {
        ev.preventDefault();
        openSearch();
      }
    }
  });

  /* ========================================================================
     12. ZERO-XSS CSS.highlights IN-PAGE MATCH HIGHLIGHTING (?hl=...)
     ======================================================================== */
  (function applySearchHighlight() {
    if (typeof CSS === "undefined" || !CSS.highlights || typeof window.Highlight !== "function") return;
    var rawTerm = "";
    try {
      rawTerm = (new URLSearchParams(window.location.search).get("hl") || "").slice(0, 64).trim().toLowerCase();
    } catch (_) { return; }
    if (rawTerm.length < 2) return;
    var article = document.querySelector(".docs-article");
    if (!article) return;

    var seenTok = {};
    var terms = [];
    rawTerm.split(/\\s+/).forEach(function (tok) {
      if (tok.length >= 2 && !seenTok[tok] && terms.length < 6) {
        seenTok[tok] = true;
        terms.push(tok);
      }
    });
    if (terms.length === 0) return;

    var ranges = [];
    var walker = document.createTreeWalker(article, NodeFilter.SHOW_TEXT);
    var node;
    while ((node = walker.nextNode()) && ranges.length < 40) {
      var parentEl = node.parentElement;
      if (parentEl && typeof parentEl.closest === "function" && parentEl.closest("[hidden]")) continue;
      var text = node.nodeValue || "";
      var lower = text.toLowerCase();
      for (var tIdx = 0; tIdx < terms.length && ranges.length < 40; tIdx++) {
        var term = terms[tIdx];
        var pos = 0;
        while (pos < lower.length && ranges.length < 40) {
          var idx = lower.indexOf(term, pos);
          if (idx === -1) break;
          var r = document.createRange();
          r.setStart(node, idx);
          r.setEnd(node, idx + term.length);
          ranges.push(r);
          pos = idx + term.length;
        }
      }
    }
    if (ranges.length > 0) {
      var hl = new window.Highlight();
      for (var i = 0; i < ranges.length; i++) hl.add(ranges[i]);
      CSS.highlights.set("coldpin-search-match", hl);
    }
  })();

  /* ========================================================================
     13. DESKTOP + MOBILE TOC SCROLL-SPY & TARGETED <details> AUTO-OPEN
     ======================================================================== */
  function openTargetDetails(hashStr) {
    if (!hashStr || hashStr.length < 2) return;
    var targetId = hashStr.charAt(0) === "#" ? hashStr.slice(1) : hashStr;
    var targetEl = document.getElementById(targetId);
    if (!targetEl) return;
    if (targetEl.tagName === "DETAILS") {
      targetEl.open = true;
    } else if (typeof targetEl.closest === "function") {
      var parentDet = targetEl.closest("details");
      if (parentDet) parentDet.open = true;
    }
  }
  if (window.location && window.location.hash) {
    openTargetDetails(window.location.hash);
  }
  window.addEventListener("hashchange", function () {
    if (window.location && window.location.hash) openTargetDetails(window.location.hash);
  });

  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc-link[href^='#']"));
  var observedTargets = [];
  tocLinks.forEach(function (link) {
    var href = link.getAttribute("href");
    var el = href ? document.getElementById(href.slice(1)) : null;
    if (el && observedTargets.indexOf(el) === -1) observedTargets.push(el);
    link.addEventListener("click", function () {
      if (href) openTargetDetails(href);
    });
  });

  function setActiveToc(id) {
    tocLinks.forEach(function (link) {
      link.classList.toggle("is-active", link.getAttribute("href") === "#" + id);
    });
  }

  if ("IntersectionObserver" in window && observedTargets.length > 0) {
    var spy = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting && !entries[i].target.hidden) {
          setActiveToc(entries[i].target.id);
          break;
        }
      }
    }, { rootMargin: "-15% 0px -70% 0px", threshold: 0 });
    for (var s = 0; s < observedTargets.length; s++) spy.observe(observedTargets[s]);
  }

  /* ========================================================================
     14. READ-ONLY WEBMCP (document.modelContext, <= 1,500-CHAR VALID JSON)
     ======================================================================== */
  function capWebMcpText(obj) {
    var text = typeof obj === "string" ? obj : JSON.stringify(obj);
    if (text.length <= WEBMCP_MAX_CHARS) return text;
    return JSON.stringify({ truncated: true, max_chars: WEBMCP_MAX_CHARS, preview: text.slice(0, WEBMCP_MAX_CHARS - 96) });
  }

  function packSearchResultsJson(queryText, rawMatches) {
    var snippetCaps = [100, 64, 0];
    for (var sc = 0; sc < snippetCaps.length; sc++) {
      var cap = snippetCaps[sc];
      for (var take = Math.min(6, rawMatches.length); take >= 0; take--) {
        var list = rawMatches.slice(0, take).map(function (r) {
          var rec = { title: r.title, pillar: r.pillarLabel, href: r.href, md: "/docs/" + r.slug + ".md" };
          if (cap > 0) rec.snippet = r.snippet.slice(0, cap);
          return rec;
        });
        var payload = {
          version: DOC_VERSION,
          query: queryText,
          count: list.length,
          truncated: take < rawMatches.length,
          results: list
        };
        var encoded = JSON.stringify(payload);
        if (encoded.length <= WEBMCP_MAX_CHARS) return encoded;
      }
    }
    return JSON.stringify({ version: DOC_VERSION, query: queryText.slice(0, 40), count: 0, truncated: true, results: [] });
  }

  function packMarkdownSliceJson(slug, md, offset) {
    var remaining = md.length - offset;
    if (remaining <= 0) {
      return JSON.stringify({ slug: slug, offset: offset, total_chars: md.length, next_offset: null, markdown: "" });
    }
    var low = 0;
    var high = Math.min(remaining, WEBMCP_MAX_CHARS);
    var best = "";
    while (low <= high) {
      var mid = Math.floor((low + high) / 2);
      var chunk = md.slice(offset, offset + mid);
      var nextOff = offset + chunk.length < md.length ? offset + chunk.length : null;
      var encoded = JSON.stringify({ slug: slug, offset: offset, total_chars: md.length, next_offset: nextOff, markdown: chunk });
      if (encoded.length <= WEBMCP_MAX_CHARS) {
        best = encoded;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return best || JSON.stringify({ slug: slug, offset: offset, total_chars: md.length, next_offset: null, markdown: "" });
  }

  var simulateHookTool = {
    name: "simulate_coldpin_hook",
    description: "Read-only PreToolUse hook simulation using Coldpin's exact ES2020 src/hook-core.ts evaluator (zero execution, <=1500 chars).",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    inputSchema: {
      type: "object",
      required: ["tool_name", "payload"],
      properties: {
        tool_name: { type: "string", enum: ["run_command", "write_to_file", "replace_file_content", "edit_file", "define_subagent", "manage_task"] },
        payload: { type: "string", maxLength: 1024 }
      }
    },
    execute: function (args) {
      var toolName = String((args && args.tool_name) || "run_command");
      var payload = String((args && args.payload) || "").slice(0, 1024);
      var res = evaluateRealHook(toolName, payload);
      return Promise.resolve({
        content: [{ type: "text", text: capWebMcpText({ tool_name: toolName, hook_group: res.hookGroup, exit_code: 0, output: res.result }) }]
      });
    }
  };

  var webMcpTools = [
    {
      name: "search_coldpin_docs",
      description: "Read-only search across Coldpin v" + DOC_VERSION + " documentation pages and sections (synonym-aware RRF, <=1500 chars).",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        type: "object",
        required: ["query"],
        properties: {
          query: { type: "string", maxLength: 128 },
          pillar: { type: "string", enum: ["all", "get-started", "plugin-guardrails", "mcp-cli", "enterprise-security", "verification-releases"] }
        }
      },
      execute: function (args) {
        var q = String((args && args.query) || "").slice(0, 128);
        var p = String((args && args.pillar) || "all");
        return loadSearchIndex().then(function (idx) {
          var matches = scoreRrfSearch(idx, q, p);
          return { content: [{ type: "text", text: packSearchResultsJson(q, matches) }] };
        });
      }
    },
    {
      name: "get_coldpin_doc_markdown",
      description: "Fetch a read-only raw Markdown slice (<=1500 chars) for an allowlisted Coldpin documentation slug.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        type: "object",
        required: ["slug"],
        properties: {
          slug: { type: "string", enum: VALID_SLUGS },
          offset: { type: "integer", minimum: 0, default: 0 }
        }
      },
      execute: function (args) {
        var slug = String((args && args.slug) || "").trim().toLowerCase();
        if (VALID_SLUGS.indexOf(slug) === -1) {
          return Promise.resolve({ content: [{ type: "text", text: capWebMcpText({ error: "invalid_slug", allowed: VALID_SLUGS }) }] });
        }
        var offset = Math.max(0, Number((args && args.offset) || 0) || 0);
        return fetch(docsRoot + "/docs/" + slug + ".md", { credentials: "same-origin" })
          .then(function (r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.text();
          })
          .then(function (md) {
            return {
              content: [{ type: "text", text: packMarkdownSliceJson(slug, md, offset) }]
            };
          });
      }
    }
  ];

  if (window.ColdpinHookCore && typeof window.ColdpinHookCore.evaluatePreToolUsePayload === "function") {
    webMcpTools.push(simulateHookTool);
  }

  webMcpTools.push({
    name: "get_coldpin_release_checksums",
    description: "Return verified Coldpin v" + DOC_VERSION + " SHA256SUMS.txt digests and SLSA provenance links (read-only, <=1500 chars).",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    inputSchema: { type: "object", properties: {} },
    execute: function () {
      return Promise.resolve({
        content: [{ type: "text", text: capWebMcpText({ version: DOC_VERSION, release_url: RELEASE_URL, sha256sums: RELEASE_CHECKSUMS }) }]
      });
    }
  });

  window.ColdpinWebMcpTools = Object.freeze(webMcpTools);

  function registerOnContext(ctx) {
    if (!ctx || typeof ctx.registerTool !== "function") return;
    webMcpTools.forEach(function (tool) {
      try { ctx.registerTool(tool); } catch (_) {}
    });
  }
  try {
    if (document.modelContext) registerOnContext(document.modelContext);
    else if (typeof navigator !== "undefined" && navigator.modelContext) registerOnContext(navigator.modelContext);
  } catch (_) {}
})();
`;
}
