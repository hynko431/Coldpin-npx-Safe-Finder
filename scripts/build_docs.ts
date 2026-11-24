#!/usr/bin/env node
/**
 * Zero-Dependency Node 24 Static Documentation Generator for Coldpin (`site/`).
 *
 * Deterministically builds Coldpin's 5-pillar / 17-page (Overview + 16 subpages) static
 * documentation portal under `site/` with:
 * - Zero npm dependencies, zero external CDNs, LF-only UTF-8 output.
 * - Direct compilation of `src/hook-core.ts` -> `site/hook-eval.js` (100% parity with `lib/hook.mjs`).
 * - Direct extraction of `src/mcp/evidence-card-app.ts` -> `site/evidence-card-app/index.html` + `site/evidence-card-app.{css,js}`
 *   so the Policy Lab runs Coldpin's real SEP-1865 MCP App under zero-'unsafe-inline' CSP.
 * - Raw Markdown twins (`/docs/<slug>.md`), `404.html`, `robots.txt`, `sitemap.xml`, `llms.txt`,
 *   `search-index.json`, `theme-init.js`, `styles.css`, `app.js`, and synced `site/_headers`.
 * - `--check` mode verifying 1:1 SHA-256 parity with zero drift or orphaned files.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { renderEvidenceCardAppHtml } from "../src/mcp/evidence-card-app.ts";
import { renderAppJs, renderHeadersFile, renderStylesCss, renderThemeInitJs } from "./docs/assets.ts";
import { buildDocPages, loadRepoMetrics } from "./docs/content.ts";
import {
  buildSearchIndex,
  render404Html,
  renderLlmsTxt,
  renderPageHtml,
  renderPageMarkdown,
  renderRobotsTxt,
  renderSitemapXml,
} from "./docs/renderer.ts";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const SITE_DIR = join(REPO_ROOT, "site");

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

function normalizeLf(text: string): string {
  const lf = text.replace(/\r\n/g, "\n");
  return lf.endsWith("\n") ? lf : `${lf}\n`;
}

function walkSiteFiles(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const full = join(dir, entry.name);
    const lst = lstatSync(full);
    if (lst.isSymbolicLink()) {
      throw new Error(`Refusing symlink in site/ tree: ${full}`);
    }
    if (entry.isDirectory()) {
      walkSiteFiles(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function removeEmptyDirs(dir: string): void {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      const sub = join(dir, entry.name);
      removeEmptyDirs(sub);
      if (readdirSync(sub).length === 0) {
        rmSync(sub, { recursive: true, force: true });
      }
    }
  }
}

export function compileHookCoreToBrowserJs(hookCoreTs: string): string {
  const normalized = hookCoreTs.replace(/\r\n/g, "\n");
  const stripped = stripTypeScriptTypes(normalized, { mode: "strip", sourceUrl: "hook-core.ts" })
    .replace(/\r\n/g, "\n")
    .replace(/^export\s+(const|function)\s+/gm, "$1 ");

  const wrapped = [
    "/* Coldpin PreToolUse Browser Evaluator — compiled verbatim from src/hook-core.ts.",
    " * Pure ES2020 | 100% parity with lib/hook.mjs | Do not edit manually; run `npm run build:docs`.",
    " */",
    "(function (globalScope) {",
    '  "use strict";',
    stripped.trimEnd(),
    "  globalScope.ColdpinHookCore = Object.freeze({",
    "    MAX_COMMAND_CHARS: MAX_COMMAND_CHARS,",
    "    MAX_WRAPPER_DEPTH: MAX_WRAPPER_DEPTH,",
    "    FILE_EDIT_TOOLS: FILE_EDIT_TOOLS,",
    "    SENSITIVE_BASENAMES: SENSITIVE_BASENAMES,",
    "    SENSITIVE_SUFFIXES: SENSITIVE_SUFFIXES,",
    "    evaluateCommandText: evaluateCommandText,",
    "    evaluateFileEditPath: evaluateFileEditPath,",
    "    evaluatePreToolUsePayload: evaluatePreToolUsePayload",
    "  });",
    '})(typeof globalThis !== "undefined" ? globalThis : window);',
    "",
  ].join("\n");
  return normalizeLf(wrapped);
}

export function splitEvidenceCardApp(): { html: string; css: string; js: string } {
  const raw = renderEvidenceCardAppHtml().replace(/\r\n/g, "\n");
  const styleMatch = /<style>\n([\s\S]*?)\n<\/style>/.exec(raw);
  const scriptMatch = /<script>\n([\s\S]*?)\n<\/script>/.exec(raw);
  if (!styleMatch?.[1] || !scriptMatch?.[1]) {
    throw new Error("Failed extracting <style> and <script> blocks from src/mcp/evidence-card-app.ts");
  }
  const css = normalizeLf(`/* Extracted verbatim from src/mcp/evidence-card-app.ts */\n${styleMatch[1]}`);
  const js = normalizeLf(`/* Extracted verbatim from src/mcp/evidence-card-app.ts */\n${scriptMatch[1]}`);
  const html = normalizeLf(
    raw
      .replace(
        /<meta http-equiv="Content-Security-Policy" content="[^"]+">/,
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; style-src \'self\'; img-src data:; base-uri \'none\'; form-action \'none\';">',
      )
      .replace(styleMatch[0], '<link rel="stylesheet" href="../evidence-card-app.css">')
      .replace(scriptMatch[0], '<script src="../evidence-card-app.js" defer></script>'),
  );
  return { html, css, js };
}

export function computeExpectedSiteFiles(repoRoot = REPO_ROOT): Map<string, Buffer> {
  const metrics = loadRepoMetrics(repoRoot);
  const pages = buildDocPages(metrics);
  const validSlugs = pages.map((p) => p.slug);
  const siteDir = join(repoRoot, "site");
  const out = new Map<string, Buffer>();

  const setText = (relPath: string, text: string) => {
    out.set(join(siteDir, relPath), Buffer.from(normalizeLf(text), "utf8"));
  };

  // Canonical icon byte-parity + .nojekyll
  out.set(join(siteDir, "icon.svg"), readFileSync(join(repoRoot, "assets", "icon.svg")));
  out.set(join(siteDir, ".nojekyll"), Buffer.from("\n", "utf8"));

  // Core assets & headers
  setText("_headers", renderHeadersFile());
  setText("theme-init.js", renderThemeInitJs(metrics));
  setText("styles.css", renderStylesCss());
  setText("app.js", renderAppJs(metrics, validSlugs));

  // Compiled exact hook core & extracted SEP-1865 MCP App
  const hookCoreSrc = readFileSync(join(repoRoot, "src", "hook-core.ts"), "utf8");
  setText("hook-eval.js", compileHookCoreToBrowserJs(hookCoreSrc));

  const mcpApp = splitEvidenceCardApp();
  setText(join("evidence-card-app", "index.html"), mcpApp.html);
  setText("evidence-card-app.css", mcpApp.css);
  setText("evidence-card-app.js", mcpApp.js);

  // All 17 doc HTML pages + 17 /docs/<slug>.md raw Markdown twins
  for (const page of pages) {
    const htmlRel = page.isRoot ? "index.html" : join("docs", page.slug, "index.html");
    setText(htmlRel, renderPageHtml(page, pages, metrics));
    setText(join("docs", `${page.slug}.md`), renderPageMarkdown(page, metrics));
  }

  // 404, crawlers, AI index, and search index
  setText("404.html", render404Html(pages, metrics));
  setText("robots.txt", renderRobotsTxt());
  setText("sitemap.xml", renderSitemapXml(pages, metrics));
  setText("llms.txt", renderLlmsTxt(pages, metrics));
  setText("search-index.json", buildSearchIndex(pages, metrics));

  return out;
}

function main(): void {
  const t0 = performance.now();
  const args = new Set(process.argv.slice(2));
  const checkOnly = args.has("--check");

  const expected = computeExpectedSiteFiles(REPO_ROOT);

  if (checkOnly) {
    const actualFiles = new Set(walkSiteFiles(SITE_DIR));
    const errors: string[] = [];
    for (const [fullPath, expBuf] of expected) {
      if (!actualFiles.has(fullPath)) {
        errors.push(`MISSING: ${relative(REPO_ROOT, fullPath).replace(/\\/g, "/")}`);
        continue;
      }
      actualFiles.delete(fullPath);
      const actBuf = readFileSync(fullPath);
      if (sha256Hex(actBuf) !== sha256Hex(expBuf)) {
        errors.push(`DRIFT: ${relative(REPO_ROOT, fullPath).replace(/\\/g, "/")}`);
      }
    }
    for (const orphan of actualFiles) {
      errors.push(`ORPHAN: ${relative(REPO_ROOT, orphan).replace(/\\/g, "/")}`);
    }
    if (errors.length > 0) {
      process.stderr.write(`DOCS_PARITY_FAILED:\n${errors.join("\n")}\n`);
      process.exit(1);
    }
    const elapsed = (performance.now() - t0).toFixed(1);
    process.stdout.write(`DOCS_PARITY_OK (${expected.size} files verified in ${elapsed} ms)\n`);
    return;
  }

  mkdirSync(SITE_DIR, { recursive: true });
  const existing = new Set(walkSiteFiles(SITE_DIR));
  let written = 0;

  for (const [fullPath, buf] of expected) {
    existing.delete(fullPath);
    mkdirSync(dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, buf);
    if (fullPath.endsWith(".js")) {
      execFileSync(process.execPath, ["--check", fullPath], { stdio: "pipe" });
    }
    written++;
  }

  for (const orphan of existing) {
    rmSync(orphan, { force: true });
  }
  removeEmptyDirs(SITE_DIR);

  const elapsed = (performance.now() - t0).toFixed(1);
  process.stdout.write(`BUILD_DOCS_OK: emitted and syntax-checked ${written} files under site/ in ${elapsed} ms\n`);
}

const isMain =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  main();
}
