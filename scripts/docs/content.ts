import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  MCP_PROMPTS,
  MCP_RESOURCES,
  MCP_RESOURCE_TEMPLATES,
  MCP_TOOLS,
} from "../../src/mcp/tool-catalog.ts";
import type { DocPage, InlineSegment, PillarMeta, RepoMetrics } from "./types.ts";

export const SITE_CANONICAL_ORIGIN = "https://coldpin-docs.pages.dev";
export const GH_PAGES_MIRROR_URL = "https://hynko431.github.io/Coldpin-npx-Safe-Finder/";

export const PILLARS: readonly PillarMeta[] = [
  { id: "get-started", label: "Get Started", shortLabel: "Get Started", entrySlug: "overview" },
  { id: "plugin-guardrails", label: "Plugin & Guardrails", shortLabel: "Plugin", entrySlug: "antigravity-plugin" },
  { id: "mcp-cli", label: "MCP & CLI", shortLabel: "MCP & CLI", entrySlug: "mcp-tools" },
  { id: "enterprise-security", label: "Enterprise & Security", shortLabel: "Enterprise", entrySlug: "configuration" },
  { id: "verification-releases", label: "Verification & Releases", shortLabel: "Verification", entrySlug: "verification" },
];

export const V160_SHA256SUMS = [
  "7983b4d4f02cf556de1de458e986d0d6394030f360722bc6e645feeee0ef2822  coldpin-antigravity.zip",
  "3b520c6688d56f88dcd213470f9d10d9e1345fd73d16909c6055989d65f9e50a  coldpin-claude.zip",
  "723fc06ed8a8989c738d7f8e216b5f12e018efd2a0ae82a6f6b901dd988223df  coldpin-openai.zip",
  "929682d1dd7ef2b40b82e8e8cce3ac25344631399987ab9493cbd0a98a73caf9  skillspector-self-audit.sarif",
].join("\n");

function countFilesRecursive(dir: string, suffix: string): number {
  let count = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) count += countFilesRecursive(full, suffix);
    else if (entry.isFile() && entry.name.endsWith(suffix)) count++;
  }
  return count;
}

function parseChangelog(md: string): RepoMetrics["changelogReleases"] {
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const releases: Array<{
    version: string;
    date: string;
    groups: Array<{ heading: string; items: string[] }>;
  }> = [];
  let curRelease: (typeof releases)[number] | null = null;
  let curGroup: { heading: string; items: string[] } | null = null;

  for (const line of lines) {
    const relMatch = /^## \[([^\]]+)\]\s*-\s*(\d{4}-\d{2}-\d{2})/.exec(line);
    if (relMatch) {
      curRelease = { version: relMatch[1]!, date: relMatch[2]!, groups: [] };
      releases.push(curRelease);
      curGroup = null;
      continue;
    }
    const grpMatch = /^###\s+(.+)$/.exec(line);
    if (grpMatch && curRelease) {
      curGroup = { heading: grpMatch[1]!.trim(), items: [] };
      curRelease.groups.push(curGroup);
      continue;
    }
    const topBullet = /^-\s+(.+)$/.exec(line);
    if (topBullet && curGroup) {
      curGroup.items.push(topBullet[1]!.trim());
      continue;
    }
    const subBullet = /^\s+-\s+(.+)$/.exec(line);
    if (subBullet && curGroup) {
      curGroup.items.push(subBullet[1]!.trim());
    }
  }
  return releases;
}

function parseInlineMarkdown(raw: string, allowStrong = true): InlineSegment[] {
  const segs: InlineSegment[] = [];
  let buf = "";
  let i = 0;

  const flushBuf = () => {
    if (buf) {
      segs.push(buf);
      buf = "";
    }
  };

  while (i < raw.length) {
    // Inline code span: `...`
    if (raw[i] === "`") {
      const end = raw.indexOf("`", i + 1);
      if (end > i + 1) {
        flushBuf();
        segs.push({ code: raw.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }

    // Bold span: **...** (skipping over nested `...` code spans like `lib/**/*.mjs`)
    if (allowStrong && raw[i] === "*" && raw[i + 1] === "*") {
      let j = i + 2;
      let closeIdx = -1;
      while (j < raw.length - 1) {
        if (raw[j] === "`") {
          const cEnd = raw.indexOf("`", j + 1);
          if (cEnd > j) {
            j = cEnd + 1;
            continue;
          }
        }
        if (raw[j] === "*" && raw[j + 1] === "*") {
          closeIdx = j;
          break;
        }
        j++;
      }
      if (closeIdx > i + 2) {
        flushBuf();
        const inner = raw.slice(i + 2, closeIdx);
        const innerSegs = parseInlineMarkdown(inner, false);
        segs.push({
          strong: innerSegs.length === 1 && typeof innerSegs[0] === "string" ? innerSegs[0] : innerSegs,
        });
        i = closeIdx + 2;
        continue;
      }
    }

    // Markdown link: [label](href)
    if (raw[i] === "[") {
      const closeBracket = raw.indexOf("]", i + 1);
      if (closeBracket > i + 1 && raw[closeBracket + 1] === "(") {
        const closeParen = raw.indexOf(")", closeBracket + 2);
        if (closeParen > closeBracket + 2) {
          const label = raw.slice(i + 1, closeBracket);
          const href = raw.slice(closeBracket + 2, closeParen);
          flushBuf();
          segs.push({ link: label, href, external: /^https?:\/\//.test(href) });
          i = closeParen + 1;
          continue;
        }
      }
    }

    buf += raw[i]!;
    i++;
  }

  flushBuf();
  return segs;
}

function countSigResources(sigPath: string): number {
  try {
    const bundle = JSON.parse(readFileSync(sigPath, "utf8")) as { dsseEnvelope?: { payload?: string } };
    if (!bundle.dsseEnvelope?.payload) return 0;
    const stmt = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8")) as {
      predicate?: { resources?: unknown[] };
    };
    return Array.isArray(stmt.predicate?.resources) ? stmt.predicate.resources.length : 0;
  } catch {
    return 0;
  }
}

export function loadRepoMetrics(repoRoot: string): RepoMetrics {
  const pluginJson = JSON.parse(readFileSync(join(repoRoot, "plugin.json"), "utf8")) as {
    version: string;
    description: string;
    license: string;
    repository: string;
  };
  const schemaPin = JSON.parse(readFileSync(join(repoRoot, "catalog", "mcp-schema-pin.json"), "utf8")) as {
    tools_count: number;
    resources_count: number;
    resource_templates_count: number;
    prompts_count: number;
    estimated_tokens: number;
    tools_list_chars: number;
    catalog_sha256: string;
  };
  const agentsMdBytes = readFileSync(join(repoRoot, "rules", "AGENTS.md")).length;
  const compiledEsmCount = countFilesRecursive(join(repoRoot, "src"), ".ts");
  const skillAttestedFiles = countSigResources(join(repoRoot, "skills", "coldpin", "skill.oms.sig"));
  const pluginAttestedFiles = countSigResources(join(repoRoot, "catalog", "plugin.oms.sig"));

  const benchText = readFileSync(join(repoRoot, "skills", "coldpin", "BENCHMARK.md"), "utf8");
  const mutMatch = /(\d+)\/(\d+)\s+mutation proofs/i.exec(benchText);
  const mutationCount = mutMatch ? Number.parseInt(mutMatch[1]!, 10) : 38;
  const fixMatch = /Corpus:\s*(\d+)\s+deterministic fixtures/i.exec(benchText);
  const corpusFixtures = fixMatch ? Number.parseInt(fixMatch[1]!, 10) : 49;

  const auditText = readFileSync(join(repoRoot, "docs", "verification", "skill-inspector-self-audit.md"), "utf8");
  const riskMatch = /\*\*Risk:\*\*\s*(\d+)\/100/.exec(auditText);
  const verdictMatch = /\*\*Verdict:\*\*\s*`([A-Z]+)`/.exec(auditText);
  const blockMatch = /\*\*(\d+)\s+blocking findings\*\*/.exec(auditText);

  const changelogText = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");
  const changelogReleases = parseChangelog(changelogText);
  const lastBuildDate = changelogReleases[0]?.date ?? "2026-11-23";

  const readTrim = (rel: string): string => readFileSync(join(repoRoot, rel), "utf8").replace(/\r\n/g, "\n").trim();

  return {
    version: pluginJson.version,
    description: pluginJson.description,
    license: pluginJson.license,
    repoUrl: pluginJson.repository,
    npmUrl: "https://npmjs.com/package/coldpin",
    releaseUrl: `${pluginJson.repository}/releases/tag/v${pluginJson.version}`,
    mcpToolsCount: schemaPin.tools_count,
    mcpResourcesCount: schemaPin.resources_count,
    mcpTemplatesCount: schemaPin.resource_templates_count,
    mcpPromptsCount: schemaPin.prompts_count,
    mcpEstimatedTokens: schemaPin.estimated_tokens,
    mcpToolsListChars: schemaPin.tools_list_chars,
    mcpCatalogSha256: schemaPin.catalog_sha256,
    agentsMdBytes,
    compiledEsmCount,
    skillAttestedFiles: skillAttestedFiles || 18,
    pluginAttestedFiles: pluginAttestedFiles || 45,
    coreTestCount: 42,
    mutationCount,
    corpusFixtures,
    selfAuditRisk: riskMatch ? Number.parseInt(riskMatch[1]!, 10) : 16,
    selfAuditBlocking: blockMatch ? Number.parseInt(blockMatch[1]!, 10) : 0,
    selfAuditVerdict: verdictMatch?.[1] ?? "APPROVE",
    lastBuildDate,
    sha256Sums: V160_SHA256SUMS,
    hooksJsonText: readTrim("hooks.json"),
    mcpConfigText: readTrim("mcp_config.json"),
    privateRegistryConfigText: readTrim("examples/mcp_config.private-registry.example.json"),
    httpRemoteConfigText: readTrim("examples/mcp_config.http-remote.example.json"),
    weeklySidecarConfigText: readTrim("examples/sidecar.weekly-audit.example.json"),
    changelogReleases,
  };
}

export function buildDocPages(m: RepoMetrics): readonly DocPage[] {
  const v = m.version;
  const mcpToolRows = MCP_TOOLS.map((tool) => {
    const props = (tool.inputSchema["properties"] ?? {}) as Record<string, { type?: string }>;
    const required = new Set(Array.isArray(tool.inputSchema["required"]) ? (tool.inputSchema["required"] as string[]) : []);
    const paramList = Object.keys(props)
      .map((k) => (required.has(k) ? `${k}*` : k))
      .join(", ");
    const hasUi = Boolean(tool._meta?.ui?.resourceUri);
    return [
      [{ code: tool.name }],
      [tool.description],
      [{ code: paramList || "(none)" }],
      [hasUi ? "Read-only · MCP App Card" : "Read-only"],
    ];
  });

  const changelogItems = m.changelogReleases.map((rel, idx) => ({
    id: `v${rel.version.replace(/\./g, "-")}`,
    summary: `v${rel.version} — ${rel.date}`,
    badge: idx === 0 ? "Latest" : undefined,
    open: idx === 0,
    blocks: rel.groups.flatMap((grp) => [
      { kind: "p" as const, text: [{ strong: grp.heading }] },
      { kind: "ul" as const, items: grp.items.map((item) => parseInlineMarkdown(item)) },
    ]),
  }));

  return [
    // =========================================================================
    // PILLAR 1: GET STARTED (4 pages: Overview /, Quickstart, Harnesses, Policy Lab)
    // =========================================================================
    {
      slug: "overview",
      isRoot: true,
      pillar: "get-started",
      title: "Coldpin Documentation",
      shortTitle: "Overview",
      heroTitle: "Inspect npx packages cold. Pin clean releases.",
      description:
        "Zero-dependency Node.js 24 CLI, local stdio & opt-in HTTP MCP server, and native Antigravity plugin for zero-execution npm tarball triage and clean-anchor recovery.",
      lead: [
        "Coldpin (",
        { code: `coldpin v${v}` },
        ") is a zero-dependency Node.js 24 CLI, local ",
        { code: "stdio" },
        " MCP server (",
        { code: "io.github.hynko431/coldpin" },
        "), and native Antigravity plugin that vets npm tarballs in memory, verifies 3-tier tarball-to-source parity, and recovers pre-compromise release anchors without executing untrusted install scripts.",
      ],
      surfaces: ["Antigravity >= v1.5.13", "MCP Apps >= v2.34.0", "Node.js >= 24", "Claude Code", "Codex CLI"],
      keywords: [
        "coldpin",
        "overview",
        "npx",
        "npm",
        "security",
        "zero execution",
        "antigravity",
        "mcp",
        "tarball",
        "taint",
        "safe anchor",
      ],
      heroCtas: [
        { label: "Quickstart Install", href: "/docs/quickstart/", primary: true },
        { label: "Open Policy Lab", href: "/docs/policy-lab/" },
        { label: `Release v${v}`, href: m.releaseUrl, external: true },
      ],
      heroSpecStrip: [
        { label: "Runtime & Cost", value: "Node >= 24, 0 deps, $0/mo" },
        { label: "Antigravity Strict", value: "0 findings (5 primitives)" },
        { label: "Benchmark Corpus", value: `100.0% recall, 0.0% FPR (${m.corpusFixtures})` },
        { label: "Self-Audit & Proofs", value: `${m.selfAuditVerdict} ${m.selfAuditRisk}/100, ${m.mutationCount}/${m.mutationCount}` },
      ],
      sections: [
        {
          id: "choose-surface",
          title: "Choose your harness",
          blocks: [
            {
              kind: "p",
              text: [
                "Select how you run Coldpin. Your choice syncs across this page, updates the ",
                { strong: "On this page" },
                " navigation, and persists across tabs via ",
                { code: "?surface=" },
                " and ",
                { code: "localStorage" },
                ".",
              ],
            },
            { kind: "surface-selector" },
          ],
        },
        {
          id: "surface-antigravity",
          title: "Antigravity Plugin Setup (5 Native Primitives)",
          surface: "antigravity",
          blocks: [
            {
              kind: "p",
              text: [
                "Install directly via ",
                { code: "agy plugin install" },
                ". Public installs activate on first click with zero mandatory variables, registering ",
                { strong: "3 skills" },
                " (including ",
                { code: "/coldpin-audit" },
                " and ",
                { code: "/coldpin-incident" },
                "), ",
                { strong: "7 read-only aspect agents" },
                ", ",
                { strong: "3 rules" },
                ", ",
                { strong: "3 fail-safe PreToolUse hook groups" },
                ", and ",
                { strong: "1 local stdio MCP server" },
                " (",
                { code: `${m.mcpEstimatedTokens.toLocaleString("en-US")} eager tokens` },
                ").",
              ],
            },
            {
              kind: "code",
              id: "ov-code-agy",
              label: "Antigravity CLI (macOS, Linux, Windows)",
              lang: "sh",
              code: `agy plugin install ${m.repoUrl}\nagy plugin list\nagy --agent coldpin-auditor`,
            },
            {
              kind: "callout",
              tone: "tip",
              title: "Inline MCP App Evidence Cards (Antigravity >= v2.34.0)",
              body: [
                "Tools ",
                { code: "inspect_package_artifact" },
                ", ",
                { code: "resolve_safe_anchor" },
                ", ",
                { code: "verify_confusion" },
                ", and ",
                { code: "audit_manifest_batch" },
                " automatically link ",
                { code: "ui://coldpin/evidence-card.html" },
                " (SEP-1865, default-deny CSP, copy-only commands). Preview it live in the ",
                { link: "Interactive Policy Lab", href: "/docs/policy-lab/" },
                ".",
              ],
            },
          ],
        },
        {
          id: "surface-npm-cli",
          title: "Standalone CLI & Local stdio MCP (npm)",
          surface: "npm-cli",
          blocks: [
            {
              kind: "p",
              text: [
                "Run Coldpin directly on Node.js ",
                { code: ">= 24.0.0" },
                " with zero runtime dependencies. Every CLI verb returns deterministic exit codes (",
                { code: "0" },
                " clean, ",
                { code: "2" },
                " suspicious/unknown, ",
                { code: "3" },
                " malicious, ",
                { code: "1" },
                " error) and supports ",
                { code: "--json" },
                ", ",
                { code: "--sarif" },
                ", and ",
                { code: "--sbom" },
                ".",
              ],
            },
            {
              kind: "code",
              id: "ov-code-npm",
              label: "Pinned npm execution (never unpinned, scripts disabled)",
              lang: "sh",
              code: `npx --ignore-scripts coldpin@${v} inspect semver@7.7.1\nnpx --ignore-scripts coldpin@${v} audit-batch ./package.json --limit 50\nnpx --ignore-scripts coldpin@${v} mcp`,
            },
          ],
        },
        {
          id: "surface-mcp-hosts",
          title: "Claude Code, Codex CLI & Official MCP Registry",
          surface: "mcp-hosts",
          blocks: [
            {
              kind: "p",
              text: [
                "Coldpin ships one canonical skill source (",
                { code: "skills/coldpin/" },
                ") and one compiled ESM runtime (",
                { code: "lib/" },
                ") across Claude Code, Codex CLI, Cursor, and the Official MCP Registry (",
                { code: "io.github.hynko431/coldpin" },
                ").",
              ],
            },
            {
              kind: "code",
              id: "ov-code-mcp",
              label: "Verify checksums & extract host-targeted bundle",
              lang: "sh",
              code: `sha256sum -c SHA256SUMS.txt\npython -m zipfile -e coldpin-claude.zip ./coldpin-claude\npython -m zipfile -e coldpin-openai.zip ./coldpin-openai`,
            },
          ],
        },
        {
          id: "surface-enterprise-http",
          title: "Self-Hosted HTTP MCP & Air-Gapped Enterprise",
          surface: "enterprise-http",
          blocks: [
            {
              kind: "p",
              text: [
                "For centralized VPCs, Cloud Run gateways, or air-gapped CI runners, run the opt-in Streamable HTTP adapter (",
                { code: "coldpin-mcp-http" },
                ") with fail-closed OAuth 2.1 CIMD / SHA-256 API keys, or enforce strict offline tarball inspection via ",
                { code: "COLDPIN_OFFLINE=1" },
                ".",
              ],
            },
            {
              kind: "code",
              id: "ov-code-airgap",
              label: "Air-gapped offline tarball inspection (zero outbound traffic)",
              lang: "sh",
              code: `COLDPIN_OFFLINE=1 node --no-warnings lib/cli.mjs inspect \\\n  --tarball ./vendor/pkg.tgz \\\n  --git-dir ./vendor/repo \\\n  --offline --sarif --audit-log ./audit.jsonl`,
            },
          ],
        },
        {
          id: "architecture-layers",
          title: "Defense-in-Depth Architecture",
          blocks: [
            {
              kind: "p",
              text: [
                "Coldpin separates untrusted package content from deterministic static analysis and human execution authority across four strict trust boundaries:",
              ],
            },
            {
              kind: "table",
              id: "overview-layers-table",
              switchable: true,
              headers: ["Layer", "Trust Boundary", "Responsibility"],
              nowrapCols: [0],
              rows: [
                [
                  [{ strong: "Deterministic CLI & MCP (" }, { code: "lib/" }, { strong: ")" }],
                  ["Zero execution; in-memory tar unpacking; stdio-only default (0 listening sockets); operator-only control plane"],
                  ["Computes 4-state verdict, SHA-512 verification, lexical taint, 3-tier parity, defanged IOCs, SARIF 2.1.0, CycloneDX 1.5 SBOM, and LRU paging."],
                ],
                [
                  [{ strong: "Native Guardrails (" }, { code: "rules/" }, ", ", { code: "agents/" }, ", ", { code: "hooks.json" }, { strong: ")" }],
                  ["Read-only aspect subagents (", { code: 'commandExecutionPolicy: "off"' }, "); pure ES2020 PreToolUse hook exiting ", { code: "0" }],
                  ["Routes 6 security aspects across isolated subagents, blocks evasive package runners, and forces confirmation on pinned runs, config edits, and writable subagents."],
                ],
                [
                  [{ strong: "Agent Skills (" }, { code: "skills/" }, { strong: ")" }],
                  ["Untrusted package READMEs & metadata isolated as data; fail-closed on unknowns"],
                  ["Orchestrates all 7 MCP tools / 6 CLI verbs with 5 aspect playbooks plus ", { code: "/coldpin-audit" }, " and ", { code: "/coldpin-incident" }, " slash commands."],
                ],
                [
                  [{ strong: "Human Operator" }],
                  ["Explicit approval gate before any host execution"],
                  ["Reviews observations, inferences, unknowns, and stock-npx transitive caveats before approving any pinned command."],
                ],
              ],
            },
          ],
        },
        {
          id: "explore-docs",
          title: "Explore the Documentation",
          blocks: [
            {
              kind: "resource-cards",
              cards: [
                {
                  pillar: "Get Started",
                  title: "Interactive Policy Lab",
                  description: "Run Coldpin's real ES2020 PreToolUse hook engine in your browser and inspect the live SEP-1865 MCP App card.",
                  href: "/docs/policy-lab/",
                },
                {
                  pillar: "Plugin & Guardrails",
                  title: "5-Component Antigravity Plugin",
                  description: "7 read-only aspect agents, 3 Markdown rules, 3 PreToolUse hook groups, and /coldpin-audit & /coldpin-incident.",
                  href: "/docs/antigravity-plugin/",
                },
                {
                  pillar: "MCP & CLI",
                  title: "Self-Hosted HTTP MCP & Sidecar (v1.6)",
                  description: "Deploy coldpin-mcp-http with OAuth 2.1 CIMD, RFC 9728/8707, inline MCP Apps, and opt-in weekly audits.",
                  href: "/docs/enterprise-http/",
                },
                {
                  pillar: "Verification & Releases",
                  title: "Benchmarks, Checksums & Provenance",
                  description: "Live synced schema pin (1,628 tokens), 38/38 mutation proofs, SS-03..SS-18 audit, and v1.6.0 SHA256SUMS.",
                  href: "/docs/verification/",
                },
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 2: /docs/quickstart/
    // =========================================================================
    {
      slug: "quickstart",
      pillar: "get-started",
      title: "Quickstart Install",
      shortTitle: "Quickstart",
      description:
        "Install Coldpin in under 30 seconds across Antigravity, npm/CLI, SLSA-verified release bundles, or air-gapped environments.",
      lead: [
        "Coldpin runs 100% locally with zero mandatory credentials, zero npm runtime dependencies, and ",
        { strong: "$0/mo" },
        " steady-state cost. Pick an install method and run your first cold tarball inspection.",
      ],
      surfaces: ["Antigravity >= v1.5.13", "Node.js >= 24", "Git >= 2.25", "Offline / Air-Gapped"],
      keywords: [
        "quickstart",
        "install",
        "setup",
        "prerequisites",
        "antigravity",
        "npm",
        "offline",
        "air-gapped",
        "getting started",
        "workflow",
      ],
      sections: [
        {
          id: "prerequisites",
          title: "Prerequisites",
          blocks: [
            {
              kind: "ul",
              items: [
                [{ strong: "Node.js " }, { code: ">= 24.0.0" }, " — uses native TypeScript type-stripping, ", { code: "node:sqlite" }, ", ", { code: "node:zlib" }, ", ", { code: "node:crypto" }, ", and ", { code: "fetch" }, " with zero ", { code: "npm install" }, " required."],
                [{ strong: "Git " }, { code: ">= 2.25" }, " — required for ", { code: "resolve-anchor" }, " commit history walks and local tarball-vs-Git parity checks."],
                [{ strong: "Antigravity " }, { code: ">= v1.5.13" }, " — required for native ", { code: "PreToolUse" }, " hooks; ", { code: ">= v2.34.0" }, " enables inline SEP-1865 MCP App evidence cards."],
                [{ strong: "Optional Tier-2 Forensics (REA): " }, "A pre-registered ", { code: "rea-agents" }, " MCP server or pre-installed ", { code: "rea" }, " binary on ", { code: "PATH" }, " for compiled ", { code: ".node" }, "/WASM/ELF/PE/Mach-O binaries. Never run ", { code: "npx -y rea-agents" }, "."],
              ],
            },
          ],
        },
        {
          id: "install-methods",
          title: "Install Methods",
          blocks: [
            {
              kind: "tabs",
              id: "qs-install-tabs",
              ariaLabel: "Installation method",
              tabs: [
                {
                  id: "tab-agy",
                  label: "Antigravity Plugin",
                  blocks: [
                    {
                      kind: "code",
                      id: "qs-code-agy",
                      label: "Antigravity CLI (macOS, Linux, Windows)",
                      lang: "sh",
                      code: `agy plugin install ${m.repoUrl}\nagy plugin list\nagy --agent coldpin-auditor`,
                    },
                    {
                      kind: "p",
                      muted: true,
                      text: [
                        "Enables immediately with zero required variables: 3 skills, 7 read-only aspect agents, 3 Markdown rules, 3 ",
                        { code: "PreToolUse" },
                        " hook groups, and 1 local ",
                        { code: "stdio" },
                        " MCP server.",
                      ],
                    },
                  ],
                },
                {
                  id: "tab-npm",
                  label: "npm / Standalone CLI",
                  blocks: [
                    {
                      kind: "code",
                      id: "qs-code-npm",
                      label: "Pinned npm invocation (zero install scripts)",
                      lang: "sh",
                      code: `npx --ignore-scripts coldpin@${v} mcp\nnpx --ignore-scripts coldpin@${v} inspect semver@7.7.1\nnpx --ignore-scripts coldpin@${v} audit-batch ./package.json --limit 50`,
                    },
                    {
                      kind: "p",
                      muted: true,
                      text: [
                        "Published as ",
                        { link: `coldpin@${v}`, href: m.npmUrl, external: true },
                        " on npm and indexed in the ",
                        { link: "Official MCP Registry", href: "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.hynko431/coldpin", external: true },
                        " as ",
                        { code: "io.github.hynko431/coldpin" },
                        ".",
                      ],
                    },
                  ],
                },
                {
                  id: "tab-bundle",
                  label: "SLSA Release Bundle",
                  blocks: [
                    {
                      kind: "code",
                      id: "qs-code-release",
                      label: "Verify SHA-256 & strict Antigravity validation before install",
                      lang: "sh",
                      code: `sha256sum -c SHA256SUMS.txt\npython -m zipfile -e coldpin-antigravity.zip ./coldpin-antigravity\nagy plugin validate --strict ./coldpin-antigravity\nagy plugin install ./coldpin-antigravity`,
                    },
                  ],
                },
                {
                  id: "tab-offline",
                  label: "Offline / Air-Gapped",
                  blocks: [
                    {
                      kind: "code",
                      id: "qs-code-offline",
                      label: "Zero outbound network — fails closed when live OSV is absent",
                      lang: "sh",
                      code: `COLDPIN_OFFLINE=1 node --no-warnings lib/cli.mjs inspect \\\n  --tarball ./vendor/pkg.tgz \\\n  --git-dir ./vendor/repo \\\n  --offline --sarif --audit-log ./audit.jsonl`,
                    },
                  ],
                },
              ],
            },
          ],
        },
        {
          id: "core-workflow",
          title: "Core 5-Step Audit Workflow",
          blocks: [
            {
              kind: "steps",
              items: [
                {
                  title: "Configure private-scope isolation (optional for public repos, required for enterprises)",
                  body: [
                    "Declare internal ",
                    { code: "private_scopes" },
                    " and ",
                    { code: "private_prefixes" },
                    " in ",
                    { code: ".coldpin.policy.json" },
                    " or ",
                    { code: "COLDPIN_PRIVATE_SCOPES" },
                    " so internal names never leak to public ",
                    { code: "registry.npmjs.org" },
                    " or ",
                    { code: "api.osv.dev" },
                    ". See ",
                    { link: "Configuration & Private Scopes", href: "/docs/configuration/" },
                    ".",
                  ],
                },
                {
                  title: "Discover candidates with 7-primitive slopsquat defense",
                  body: [
                    "Filter out denied orgs, young cooldown releases, and typosquats before downloading any archive.",
                  ],
                  code: {
                    id: "qs-step-discover",
                    label: "Discover CLI packages",
                    lang: "sh",
                    code: `node --no-warnings lib/cli.mjs discover "json formatter" --category cli --limit 10`,
                  },
                },
                {
                  title: "Inspect a package or offline tarball cold in memory",
                  body: [
                    "Verifies SHA-512 integrity, unpacks strictly in memory, runs linear-time JS/TS lexical taint and hidden-Unicode triage, checks OSV/",
                    { code: "MAL-*" },
                    ", and verifies 3-tier tarball-to-Git parity.",
                  ],
                  code: {
                    id: "qs-step-inspect",
                    label: "Inspect online or offline tarball",
                    lang: "sh",
                    code: `node --no-warnings lib/cli.mjs inspect semver@7.7.1\nnode --no-warnings lib/cli.mjs inspect --tarball ./pkg.tgz --git-dir ./repo --offline --sarif`,
                  },
                },
                {
                  title: "Batch-screen package.json & audit dependency confusion",
                  body: [
                    "Screen up to 50 direct dependencies locally and check ",
                    { code: ".npmrc" },
                    " for ",
                    { code: "T1195.001" },
                    " dependency confusion risks.",
                  ],
                  code: {
                    id: "qs-step-batch",
                    label: "Batch manifest & confusion audit",
                    lang: "sh",
                    code: `node --no-warnings lib/cli.mjs audit-batch ./package.json --limit 50\nnode --no-warnings lib/cli.mjs verify-confusion ./package.json`,
                  },
                },
                {
                  title: "Recover a clean pre-compromise anchor & verify audit trail",
                  body: [
                    "When ",
                    { code: "inspect" },
                    " returns exit code ",
                    { code: "3" },
                    " (",
                    { code: "MALICIOUS_INDICATORS_FOUND" },
                    "), pinpoint the patient-zero commit and verify hash-chained ",
                    { code: "audit.jsonl" },
                    " logs.",
                  ],
                  code: {
                    id: "qs-step-recover",
                    label: "Commit bisect & audit log verification",
                    lang: "sh",
                    code: `node --no-warnings lib/cli.mjs resolve-anchor @org/tool --git-dir ./repo --window 200\nnode --no-warnings lib/cli.mjs audit-verify ./audit.jsonl`,
                  },
                },
              ],
            },
            {
              kind: "callout",
              tone: "note",
              title: "Keyboard Shortcuts in This Portal",
              body: [
                "Press ",
                { kbd: "Ctrl" },
                " + ",
                { kbd: "K" },
                " (or ",
                { kbd: "/" },
                ") anywhere to open instant documentation search, use ",
                { kbd: "↑" },
                " / ",
                { kbd: "↓" },
                " and ",
                { kbd: "Enter" },
                " to jump directly to any section, and ",
                { kbd: "Esc" },
                " to close.",
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 3: /docs/harnesses/
    // =========================================================================
    {
      slug: "harnesses",
      pillar: "get-started",
      title: "Harnesses & Cross-Platform Distribution",
      shortTitle: "Harnesses & Install",
      description:
        "One canonical skill source and one zero-dependency ESM runtime targeting Antigravity, Claude Code, Codex CLI, Official MCP Registry, and CI.",
      lead: [
        "Coldpin maintains ",
        { strong: "one canonical skill source" },
        " under ",
        { code: "skills/coldpin/" },
        " and ",
        { strong: "one compiled zero-dependency ESM runtime" },
        " under ",
        { code: "lib/" },
        " (built deterministically from ",
        { code: "src/" },
        " via ",
        { code: "npm run build" },
        "). No agent harness receives forked prose.",
      ],
      surfaces: ["Antigravity", "Claude Code", "Codex CLI", "Cursor / MCP", "Standalone CLI"],
      keywords: [
        "harnesses",
        "distribution",
        "antigravity",
        "claude code",
        "codex",
        "cursor",
        "mcp registry",
        "pack_plugin",
        "zip",
        "0755",
      ],
      sections: [
        {
          id: "install-matrix",
          title: "Cross-Platform Install Matrix",
          blocks: [
            {
              kind: "table",
              id: "harnesses-matrix-table",
              switchable: true,
              headers: ["Harness / Channel", "Manifest / Identifier", "Entrypoint & Install", "Verification Status"],
              nowrapCols: [0],
              rows: [
                [
                  [{ strong: "Antigravity (App, CLI, IDEs)" }],
                  [{ code: "plugin.json" }, ", ", { code: "mcp_config.json" }, ", ", { code: "hooks.json" }],
                  [{ code: "agy plugin install https://github.com/hynko431/Coldpin-npx-Safe-Finder" }],
                  ["Live ", { code: "agy plugin validate --strict" }, " (", { code: "findings: []" }, ") verified locally"],
                ],
                [
                  [{ strong: "Claude Code" }],
                  [{ code: ".claude-plugin/plugin.json" }, " (inline ", { code: "mcpServers" }, ")"],
                  [{ code: "python scripts/pack_plugin.py --target claude --verify" }, " → ", { code: "coldpin-claude.zip" }],
                  ["Manifest schema & reproducible archive verified; live Claude host trace not run locally"],
                ],
                [
                  [{ strong: "Codex CLI / ChatGPT" }],
                  [{ code: ".codex-plugin/plugin.json" }, ", ", { code: ".agents/plugins/marketplace.json" }],
                  [{ code: "python scripts/pack_plugin.py --target openai --verify" }, " → ", { code: "coldpin-openai.zip" }],
                  ["Manifest schema & reproducible archive verified; live Codex host trace not run locally"],
                ],
                [
                  [{ strong: "Official MCP Registry / npm / Cursor" }],
                  [{ code: "server.json" }, " (", { code: "io.github.hynko431/coldpin" }, "), ", { code: "package.json" }],
                  [{ code: `npx --ignore-scripts coldpin@${v} mcp` }],
                  ["Schema parity, ", { code: "node_modules" }, " smoke test & JSON-RPC stdio suite verified"],
                ],
                [
                  [{ strong: "Standalone Node 24 CLI / CI" }],
                  [{ code: "package.json" }, " (", { code: "coldpin" }, ", ", { code: "coldpin-mcp" }, ", ", { code: "coldpin-mcp-http" }, ")"],
                  [{ code: "node --no-warnings lib/cli.mjs --help" }],
                  ["End-to-end tests + 49-fixture corpus verified on Ubuntu & Windows (Node 24 & 26)"],
                ],
              ],
            },
          ],
        },
        {
          id: "manual-and-workspace-sync",
          title: "Manual Install & Workspace Sync",
          blocks: [
            {
              kind: "p",
              text: [
                "For workspace-scoped discovery inside a cloned repository, sync ",
                { code: ".agents/skills/coldpin/" },
                " automatically using the deterministic packager:",
              ],
            },
            {
              kind: "code",
              id: "harness-sync-code",
              label: "Build all verified bundles & sync workspace mirror",
              lang: "sh",
              code: `python scripts/pack_plugin.py --target all --verify --sync-workspace`,
            },
            {
              kind: "p",
              text: [
                "For manual Antigravity installation without the CLI, extract ",
                { code: "coldpin-antigravity.zip" },
                " into ",
                { code: "~/.gemini/config/plugins/coldpin/" },
                " (removing any prior version first so stale files do not linger), reload the window, and verify ",
                { code: "coldpin" },
                " appears in ",
                { code: "agy plugin list" },
                ".",
              ],
            },
          ],
        },
        {
          id: "manifest-drift-and-packaging",
          title: "13-Manifest Parity & Deterministic Zip Packaging",
          blocks: [
            {
              kind: "ul",
              items: [
                [{ strong: "Single source of truth: " }, "Root ", { code: "plugin.json" }, " conforms strictly to ", { code: "https://antigravity.google/schemas/v1/plugin.json" }, " (", { code: "additionalProperties: false" }, ", zero inline ", { code: "mcpServers" }, " or ", { code: "hooks" }, ")."],
                [{ strong: "13-manifest version parity: " }, { code: "scripts/lint_skill.py" }, " fails if version or metadata drifts across ", { code: "plugin.json" }, ", ", { code: "package.json" }, ", ", { code: "server.json" }, ", ", { code: ".claude-plugin/{plugin,marketplace}.json" }, ", ", { code: ".codex-plugin/plugin.json" }, ", ", { code: "src/types.ts" }, ", ", { code: "catalog/triage-rules.json" }, ", ", { code: "catalog/mcp-schema-pin.json" }, ", ", { code: "skills/coldpin/{SKILL,skill-card}.md" }, ", and ", { code: "skills/coldpin-{audit,incident}/SKILL.md" }, "."],
                [{ strong: "Reproducible POSIX zips: " }, { code: "scripts/pack_plugin.py" }, " sorts entries, fixes timestamps (", { code: "2026-01-01 00:00:00 UTC" }, "), sets explicit ", { code: "create_system=3" }, " with ", { code: "0100755" }, " on ", { code: "lib/{cli,mcp,mcp-http,hook}.mjs" }, " and ", { code: "0100644" }, " otherwise, isolates Antigravity-only primitives strictly to ", { code: 'HOST_GLOBS["antigravity"]' }, ", and verifies byte-for-byte SHA-256 identity across two builds."],
              ],
            },
            {
              kind: "callout",
              tone: "caution",
              title: "Cloud-Only Chat Sessions",
              body: [
                "Cloud-only chat sessions without a local Node.js >= 24 runtime cannot execute ",
                { code: "lib/mcp.mjs" },
                " or ",
                { code: "lib/cli.mjs" },
                " locally and must fail closed (",
                { code: "UNVERIFIABLE_UNKNOWN" },
                ") unless connected to a self-hosted ",
                { link: "coldpin-mcp-http gateway", href: "/docs/enterprise-http/" },
                ".",
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 4: /docs/policy-lab/
    // =========================================================================
    {
      slug: "policy-lab",
      pillar: "get-started",
      title: "Interactive Policy Lab",
      shortTitle: "Interactive Policy Lab",
      description:
        "Test Coldpin's exact ES2020 PreToolUse hook engine (100% parity with lib/hook.mjs) and inspect Coldpin's live SEP-1865 MCP App Evidence Card in your browser.",
      lead: [
        "Everything below runs 100% locally in your browser with zero outbound network requests. The Hook Simulator executes ",
        { code: "site/hook-eval.js" },
        " compiled directly from Coldpin's real ",
        { code: "src/hook-core.ts" },
        " engine (100% parity with ",
        { code: "lib/hook.mjs" },
        "), and the Verdict Explorer feeds live SEP-1865 JSON-RPC messages into Coldpin's real ",
        { code: "ui://coldpin/evidence-card.html" },
        " MCP App.",
      ],
      surfaces: ["Browser Sandbox (0 Network)", "Exact lib/hook.mjs Engine", "Live SEP-1865 MCP App"],
      keywords: [
        "policy lab",
        "simulator",
        "hook",
        "pretooluse",
        "deny",
        "force_ask",
        "allow",
        "verdict",
        "evidence card",
        "mcp app",
        "sep-1865",
        "ui://coldpin/evidence-card.html",
      ],
      sections: [
        {
          id: "hook-simulator",
          title: "PreToolUse Hook Simulator (Exact lib/hook.mjs Engine)",
          blocks: [
            {
              kind: "p",
              text: [
                "Choose an intercepted tool and type any command, file path, subagent delegation payload, or raw JSON stdin. Coldpin's pure ES2020 hook engine always exits ",
                { code: "0" },
                " and returns strictly ",
                { code: "allow" },
                ", ",
                { code: "force_ask" },
                ", or ",
                { code: "deny" },
                " — never auto-approval.",
              ],
            },
            { kind: "policy-lab-hook" },
          ],
        },
        {
          id: "verdict-explorer",
          title: "4-State Verdict Explorer & Live SEP-1865 MCP App",
          blocks: [
            {
              kind: "p",
              text: [
                "Switch between Coldpin's 4 deterministic ",
                { code: "TrustVerdict" },
                " states (plus ",
                { code: "audit_manifest_batch" },
                " and ",
                { code: "resolve_safe_anchor" },
                " responses) to inspect both the accessible text card and the live sandboxed ",
                { code: "ui://coldpin/evidence-card.html" },
                " MCP App frame (synchronized live with your Light/Dark theme and ",
                { code: "get_artifact_report" },
                " paging).",
              ],
            },
            { kind: "policy-lab-verdict" },
          ],
        },
      ],
    },

    // =========================================================================
    // PILLAR 2: PLUGIN & GUARDRAILS (4 pages)
    // =========================================================================
    {
      slug: "antigravity-plugin",
      pillar: "plugin-guardrails",
      title: "Antigravity 5-Component Architecture",
      shortTitle: "5-Component Architecture",
      description:
        "How Coldpin maps cleanly onto all 5 Antigravity plugin primitives (skills, agents, rules, hooks, MCP) with zero strict validation findings.",
      lead: [
        "Coldpin conforms strictly to the official Antigravity plugin manifest schema (",
        { code: "https://antigravity.google/schemas/v1/plugin.json" },
        "). Scanner rule data lives cleanly in ",
        { code: "catalog/" },
        " so ",
        { code: "rules/" },
        " holds strictly pure agent Markdown rules.",
      ],
      surfaces: ["Antigravity >= v1.5.13", "MCP Apps >= v2.34.0"],
      keywords: [
        "antigravity",
        "plugin.json",
        "mcp_config.json",
        "vertical slice",
        "strict",
        "agy plugin validate",
        "catalog",
        "primitives",
      ],
      sections: [
        {
          id: "component-ledger",
          title: "Five Native Plugin Primitives",
          blocks: [
            {
              kind: "ledger",
              rows: [
                {
                  term: "Skills",
                  count: "3 bundled",
                  paragraphs: [
                    [{ code: "skills/coldpin/" }, " is the canonical cross-harness skill with 5 modular playbooks under ", { code: "references/aspect-*.md" }, "."],
                    ["Two Antigravity slash skills (", { link: "/coldpin-audit and /coldpin-incident", href: "/docs/slash-commands/" }, ") orchestrate read-only workspace audits and supply-chain compromise recovery."],
                  ],
                },
                {
                  term: "Read-Only Agents",
                  count: "7 bundled",
                  paragraphs: [
                    ["Primary orchestrator ", { code: "coldpin-auditor" }, " (", { code: "mainAgent: true" }, ") delegates across 6 isolated background aspect specialists."],
                    ["All 7 enforce ", { code: 'commandExecutionPolicy: "off"' }, " and canonical read-only tool allowlists; all 6 background workers set ", { code: "inheritCustomizations: false" }, " to block workspace rule poisoning."],
                  ],
                },
                {
                  term: "Markdown Rules",
                  count: "3 bundled",
                  paragraphs: [
                    [{ code: "rules/AGENTS.md" }, " stays under 1,800 bytes (", { code: `${m.agentsMdBytes.toLocaleString("en-US")} bytes` }, " measured) with a compact 6-aspect delegation routing table."],
                    [{ code: "rules/coldpin-manifest-guard.md" }, " activates via ", { code: "trigger: glob" }, " on manifests/lockfiles; ", { code: "rules/coldpin-incident-checklist.md" }, " activates via ", { code: "trigger: model_decision" }, "."],
                  ],
                },
                {
                  term: "Lifecycle Hooks",
                  count: "3 enabled groups",
                  paragraphs: [
                    ["Root ", { code: "hooks.json" }, " runs pure ES2020 ", { code: "./lib/hook.mjs" }, " across ", { code: "coldpin-npx-guard" }, ", ", { code: "coldpin-config-guard" }, ", and ", { code: "coldpin-delegation-guard" }, "."],
                    ["Always exits ", { code: "0" }, " with strictly ", { code: "allow" }, ", ", { code: "deny" }, ", or ", { code: "force_ask" }, ". Never emits auto-approval."],
                  ],
                },
                {
                  term: "Local MCP Server",
                  count: "1 stdio server",
                  paragraphs: [
                    ["Root ", { code: "mcp_config.json" }, " launches ", { code: "node --no-warnings ${PLUGIN_ROOT}/lib/mcp.mjs" }, " with ", { code: "timeoutSeconds: 300" }, ", ", { code: "${PLUGIN_DATA}" }, " cache isolation, and all ", { code: String(m.mcpToolsCount) }, " read-only tools marked ", { code: "eager: true" }, " (", { code: `${m.mcpEstimatedTokens.toLocaleString("en-US")} tokens` }, ")."],
                    ["Zero mandatory ", { code: "variables" }, " keeps public installs active immediately; enterprises can layer ", { link: "private-registry variables", href: "/docs/configuration/" }, " or ", { link: "self-hosted HTTP MCP", href: "/docs/enterprise-http/" }, "."],
                  ],
                },
              ],
            },
          ],
        },
        {
          id: "strict-validation",
          title: "Strict Antigravity CLI Validation",
          blocks: [
            {
              kind: "code",
              id: "ap-validate-json",
              label: "Measured Output: agy plugin validate . --strict --json",
              lang: "json",
              code: `{\n  "manifest": "plugin.json",\n  "name": "coldpin",\n  "components": {\n    "agents": 7,\n    "hooks": 3,\n    "mcpServers": 1,\n    "rules": 3,\n    "sidecars": 0,\n    "skills": 3\n  },\n  "findings": []\n}`,
            },
            {
              kind: "callout",
              tone: "note",
              title: "Why sidecars is 0 by default",
              body: [
                "Per SkillSpector rule ",
                { code: "SS-17-SIDECAR-LEAST-PRIV" },
                ", installing Coldpin never spawns background daemons automatically. The scheduled weekly audit sidecar ships disabled-by-default under ",
                { code: "examples/sidecar.weekly-audit.example.json" },
                " for explicit operator opt-in.",
              ],
            },
          ],
        },
        {
          id: "root-mcp-config",
          title: "Root mcp_config.json (Zero Mandatory Variables)",
          blocks: [
            {
              kind: "code",
              id: "ap-mcp-config",
              label: "mcp_config.json",
              lang: "json",
              code: m.mcpConfigText,
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 6: /docs/agents-and-rules/
    // =========================================================================
    {
      slug: "agents-and-rules",
      pillar: "plugin-guardrails",
      title: "7 Read-Only Aspect Agents & 3 Rules",
      shortTitle: "Agents & Rules",
      description:
        "Least-privilege read-only subagent delegation across 6 security aspects and 3 pure Markdown rules enforcing supply-chain invariants.",
      lead: [
        "Every Coldpin security aspect runs inside an isolated read-only subagent with private body rules, ",
        { code: 'commandExecutionPolicy: "off"' },
        ", and a scoped Coldpin MCP tool allowlist enforced by ",
        { code: "SS-14-AGENT-LEAST-PRIV" },
        " and ",
        { code: "SS-15-RULES-HYGIENE" },
        ".",
      ],
      surfaces: ["Antigravity App", "Antigravity CLI", "Antigravity IDEs"],
      keywords: [
        "agents",
        "subagents",
        "rules",
        "coldpin-auditor",
        "coldpin-discoverer",
        "coldpin-inspector",
        "coldpin-manifest-auditor",
        "coldpin-confusion-auditor",
        "coldpin-forensics",
        "coldpin-compliance",
        "inheritCustomizations",
        "AGENTS.md",
      ],
      sections: [
        {
          id: "aspect-agents",
          title: "7 Read-Only Aspect Agents",
          blocks: [
            {
              kind: "table",
              id: "agents-table",
              switchable: true,
              headers: ["Agent", "Role & Mode", "Scoped Coldpin MCP Tools", "Isolation Controls"],
              nowrapCols: [0],
              rows: [
                [
                  [{ code: "coldpin-auditor" }],
                  ["Primary orchestrator (", { code: "mainAgent: true" }, ")"],
                  ["Delegates via ", { code: "invoke_subagent" }, " + all 7 read-only Coldpin MCP tools"],
                  [{ code: 'commandExecutionPolicy: "off"' }, "; canonical read-only tools"],
                ],
                [
                  [{ code: "coldpin-discoverer" }],
                  ["Capability search & 7-primitive squat screening"],
                  [{ code: "discover_packages" }],
                  [{ code: "inheritCustomizations: false" }, "; ", { code: 'commandExecutionPolicy: "off"' }],
                ],
                [
                  [{ code: "coldpin-inspector" }],
                  ["In-memory tarball triage, lexical taint & 3-tier parity"],
                  [{ code: "inspect_package_artifact" }, ", ", { code: "get_artifact_report" }],
                  [{ code: "inheritCustomizations: false" }, "; ", { code: 'commandExecutionPolicy: "off"' }],
                ],
                [
                  [{ code: "coldpin-manifest-auditor" }],
                  ["Batch screening of ", { code: "package.json" }, " (up to 50 direct deps)"],
                  [{ code: "audit_manifest_batch" }, ", ", { code: "get_artifact_report" }],
                  [{ code: "inheritCustomizations: false" }, "; ", { code: 'commandExecutionPolicy: "off"' }],
                ],
                [
                  [{ code: "coldpin-confusion-auditor" }],
                  ["Private-scope & ", { code: ".npmrc" }, " confusion audit (", { code: "T1195.001" }, ")"],
                  [{ code: "verify_confusion" }],
                  [{ code: "inheritCustomizations: false" }, "; ", { code: 'commandExecutionPolicy: "off"' }],
                ],
                [
                  [{ code: "coldpin-forensics" }],
                  ["Patient-zero Git bisect, rollback anchors & REA Tier-2 planning"],
                  [{ code: "resolve_safe_anchor" }, ", ", { code: "inspect_package_artifact" }],
                  [{ code: "inheritCustomizations: false" }, "; ", { code: 'commandExecutionPolicy: "off"' }],
                ],
                [
                  [{ code: "coldpin-compliance" }],
                  ["Policy posture, hash-chained ", { code: "audit.jsonl" }, " & SARIF/SBOM evidence"],
                  [{ code: "audit_verify" }, ", ", { code: "get_artifact_report" }],
                  [{ code: "inheritCustomizations: false" }, "; ", { code: 'commandExecutionPolicy: "off"' }],
                ],
              ],
            },
            {
              kind: "callout",
              tone: "tip",
              title: "Why background subagents set inheritCustomizations: false ([PLG-15])",
              body: [
                "When auditing an untrusted cloned repository, malicious ",
                { code: ".agents/rules/" },
                " or workspace hooks inside that repository must never hijack Coldpin's specialist workers. Setting ",
                { code: "inheritCustomizations: false" },
                " isolates all 6 leaf workers from untrusted workspace overrides.",
              ],
            },
          ],
        },
        {
          id: "markdown-rules",
          title: "3 Pure Markdown Rules",
          blocks: [
            {
              kind: "table",
              id: "rules-table",
              switchable: true,
              headers: ["Rule File", "Trigger Mode", "Budget / Scope", "Enforced Guardrails"],
              nowrapCols: [0, 1],
              rows: [
                [
                  [{ code: "rules/AGENTS.md" }],
                  ["Always loaded"],
                  [{ code: `${m.agentsMdBytes.toLocaleString("en-US")} bytes` }, " (strict ", { code: "<= 1,800 B" }, " cap)"],
                  ["4 supply-chain invariants (Vet First, Untrusted Data, Private Scopes, Human Gate) + 6-aspect delegation routing table."],
                ],
                [
                  [{ code: "rules/coldpin-manifest-guard.md" }],
                  [{ code: "trigger: glob" }],
                  ["Comma-separated globs for ", { code: "package.json" }, ", lockfiles, ", { code: ".npmrc" }, ", ", { code: "mcp_config.json" }],
                  ["Requires batch screening, confusion checks, exact ", { code: "X.Y.Z" }, " pins + ", { code: "--ignore-scripts" }, ", and zero secret tokens in MCP CLI args."],
                ],
                [
                  [{ code: "rules/coldpin-incident-checklist.md" }],
                  [{ code: "trigger: model_decision" }],
                  ["Activates on ", { code: "MALICIOUS_INDICATORS_FOUND" }, " or lockfile exposure"],
                  ["Halts execution, delegates bisect to ", { code: "coldpin-forensics" }, ", preserves hashes, rotates credentials, and surfaces CERT-In / NIS2 / CRA / GDPR clocks."],
                ],
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 7: /docs/hooks/
    // =========================================================================
    {
      slug: "hooks",
      pillar: "plugin-guardrails",
      title: "Fail-Safe PreToolUse Hooks",
      shortTitle: "PreToolUse Hooks",
      description:
        "Pure ES2020 PreToolUse hook architecture enforcing zero unvetted package runners, config tamper gates, and writable subagent confirmation.",
      lead: [
        "Coldpin ships 3 default-enabled ",
        { code: "PreToolUse" },
        " hook groups in root ",
        { code: "hooks.json" },
        " backed by pure ES2020 ",
        { code: "src/hook-core.ts" },
        " + ",
        { code: "src/hook.ts" },
        " → ",
        { code: "./lib/hook.mjs" },
        ". The exact same engine powers the browser ",
        { link: "Interactive Policy Lab", href: "/docs/policy-lab/" },
        ".",
      ],
      surfaces: ["Antigravity >= v1.5.13", "Node 18/20/22/24/26 (ES2020)"],
      keywords: [
        "hooks",
        "hooks.json",
        "PreToolUse",
        "hook.mjs",
        "hook-core.ts",
        "coldpin-npx-guard",
        "coldpin-config-guard",
        "coldpin-delegation-guard",
        "force_ask",
        "deny",
        "allow",
        "SS-08",
      ],
      sections: [
        {
          id: "hook-contract",
          title: "Binary-Verified Antigravity Hook Contract",
          blocks: [
            {
              kind: "ul",
              items: [
                [{ strong: "Explicit allow pass-through: " }, "Benign commands emit ", { code: '{"decision":"allow"}' }, " (exit ", { code: "0" }, ") — emitting ", { code: "{}" }, " is rewritten to ", { code: "deny" }, " by Antigravity's ", { code: "applyPreToolHooks" }, ", whereas ", { code: "allow" }, " delegates cleanly to default policy without auto-approval."],
                [{ strong: "Zero auto-approval tokens: " }, { code: "SS-08-HOOK-LEAST-PRIV" }, " forbids ", { code: "auto_approve" }, ", ", { code: "permissionOverrides" }, ", ", { code: "overwrite" }, ", ", { code: "allowTool" }, ", and any network/subprocess API in both ", { code: "src/hook.ts" }, " and ", { code: "src/hook-core.ts" }, "."],
                [{ strong: "Exit 0 in 100% of paths: " }, "Top-level ", { code: "uncaughtException" }, ", ", { code: "unhandledRejection" }, ", empty stdin, and malformed JSON all emit ", { code: '{"decision":"force_ask",...}' }, " and exit ", { code: "0" }, " to neutralize host fail-open on non-zero exit."],
                [{ strong: "Bounded stdin + fast-path edits: " }, "Commands over ", { code: "256 KiB" }, " fail closed with ", { code: "deny" }, "; legitimate file edits over ", { code: "256 KiB" }, " (up to ", { code: "8 MiB" }, ") scan the first ", { code: "16 KiB" }, " JSON header linearly so large source-code writes never trigger false prompts."],
              ],
            },
          ],
        },
        {
          id: "hooks-json",
          title: "Root hooks.json Configuration",
          blocks: [
            {
              kind: "code",
              id: "hooks-json-code",
              label: "hooks.json (3 enabled PreToolUse groups)",
              lang: "json",
              code: m.hooksJsonText,
            },
          ],
        },
        {
          id: "evasion-coverage",
          title: "Multi-Shell Evasion & Config Tamper Matrix",
          blocks: [
            {
              kind: "table",
              id: "hooks-matrix-table",
              switchable: true,
              headers: ["Vector / Category", "Example Input", "Hook Decision", "Hook Group"],
              nowrapCols: [2, 3],
              rows: [
                [
                  ["Quoted / escaped / backtick / path-qualified ", { code: "npx" }],
                  [{ code: 'n""px evil-pkg' }, ", ", { code: "n`px evil" }, ", ", { code: "C:\\nodejs\\npx.cmd evil" }],
                  [{ code: "deny" }],
                  [{ code: "coldpin-npx-guard" }],
                ],
                [
                  ["Shell wrappers & subshells"],
                  [{ code: 'sh -c "npx evil"' }, ", ", { code: "cmd /c npx evil" }, ", ", { code: "echo $(npx evil)" }],
                  [{ code: "deny" }],
                  [{ code: "coldpin-npx-guard" }],
                ],
                [
                  ["Alternative runners & remote initializers"],
                  [{ code: "pnpm dlx" }, ", ", { code: "yarn dlx" }, ", ", { code: "bunx" }, ", ", { code: "corepack" }, ", ", { code: "npm init create-x" }],
                  [{ code: "deny" }],
                  [{ code: "coldpin-npx-guard" }],
                ],
                [
                  ["Download-and-execute pipes & interactive stdin"],
                  [{ code: "curl https://... | sh" }, ", ", { code: "irm ... | iex" }, ", ", { code: "manage_task(send_input)" }],
                  [{ code: "deny" }],
                  [{ code: "coldpin-npx-guard" }],
                ],
                [
                  ["Exact-pinned Coldpin ", { code: "--ignore-scripts" }, " standalone"],
                  [{ code: `npx --ignore-scripts coldpin@${v} mcp` }, ", ", { code: "npx --yes --ignore-scripts --package=semver@7.7.1 -- semver" }],
                  [{ code: "force_ask" }],
                  [{ code: "coldpin-npx-guard" }],
                ],
                [
                  ["Sensitive config edits (all 6 file-edit tools + shell)"],
                  [{ code: ".npmrc" }, ", ", { code: ".coldpin.policy.json" }, ", ", { code: "hooks.json" }, ", ", { code: "mcp_config.json" }, ", ", { code: "lib/hook.mjs" }, ", ", { code: "agy plugin disable" }],
                  [{ code: "force_ask" }],
                  [{ code: "coldpin-config-guard" }],
                ],
                [
                  ["Writable dynamic subagent requests"],
                  [{ code: "define_subagent({ EnableWriteTools: true })" }],
                  [{ code: "force_ask" }],
                  [{ code: "coldpin-delegation-guard" }],
                ],
              ],
            },
            {
              kind: "callout",
              tone: "caution",
              title: "Layer-1 Guardrail Boundaries",
              body: [
                "Because Antigravity fails open if ",
                { code: "node" },
                " is missing on ",
                { code: "PATH" },
                " or a hook times out, and because argument inspection cannot observe compiled binaries or pre-existing shell aliases, always pair Coldpin hooks with OS sandboxing and the companion ",
                { code: "catalog/sigma/" },
                " EDR rules.",
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 8: /docs/slash-commands/
    // =========================================================================
    {
      slug: "slash-commands",
      pillar: "plugin-guardrails",
      title: "Slash Commands (/coldpin-audit & /coldpin-incident)",
      shortTitle: "Slash Commands",
      description:
        "Guided Antigravity slash workflows for read-only workspace audits and supply-chain compromise recovery, with safe read-only prompt launchers.",
      lead: [
        "Coldpin bundles two dedicated Antigravity slash skills under ",
        { code: "skills/coldpin-audit/" },
        " and ",
        { code: "skills/coldpin-incident/" },
        ". Both are strictly read-only — they never execute shell commands, edit files, or recommend unvetted ",
        { code: "npx" },
        " runs.",
      ],
      surfaces: ["Antigravity App", "Antigravity CLI", "Antigravity IDEs"],
      keywords: [
        "slash commands",
        "coldpin-audit",
        "coldpin-incident",
        "try in antigravity",
        "prompt",
        "workflow",
        "incident response",
        "audit",
      ],
      sections: [
        {
          id: "coldpin-audit",
          title: "/coldpin-audit — Read-Only Workspace Audit",
          blocks: [
            {
              kind: "prompt-composer",
              id: "prompt-coldpin-audit",
              slashCommand: "/coldpin-audit",
              title: "Launch Read-Only Workspace Supply-Chain Audit",
              description:
                "Screens workspace package.json (<= 50 direct deps), audits .npmrc for T1195.001 dependency confusion, verifies local audit.jsonl chains, and cold-inspects flagged packages.",
              prompt:
                "/coldpin-audit Run a strictly read-only Coldpin supply-chain audit of this workspace: check coldpin://policy/active, batch-screen package.json via audit_manifest_batch, audit .npmrc via verify_confusion, verify any local audit.jsonl via audit_verify, and cold-inspect any flagged dependencies without running shell commands or modifying files.",
              badges: ["Read-Only", "Zero Shell Execution", "6 Aspect Subagents"],
            },
            {
              kind: "steps",
              items: [
                {
                  title: "Read active policy posture",
                  body: ["Queries ", { code: "coldpin://policy/active" }, " to confirm ", { code: "policy_sha256" }, ", ", { code: "private_scopes" }, ", ", { code: "denied_orgs" }, ", and ", { code: "offline_mode" }, "."],
                },
                {
                  title: "Run parallel read-only aspect audits",
                  body: ["Delegates to ", { code: "coldpin-manifest-auditor" }, " (", { code: "audit_manifest_batch" }, "), ", { code: "coldpin-confusion-auditor" }, " (", { code: "verify_confusion" }, "), and ", { code: "coldpin-compliance" }, " (", { code: "audit_verify" }, ")."],
                },
                {
                  title: "Escalate flagged dependencies cold",
                  body: ["Passes every ", { code: "MALICIOUS_OR_BLOCKED" }, " or ", { code: "FLAGGED_SUSPICIOUS" }, " dependency to ", { code: "coldpin-inspector" }, " (", { code: "inspect_package_artifact" }, " in summary mode with LRU paging)."],
                },
                {
                  title: "Hand off to /coldpin-incident on compromise",
                  body: ["If any package returns ", { code: "MALICIOUS_INDICATORS_FOUND" }, " or ", { code: "local_workspace_compromised" }, ", transitions immediately to containment and patient-zero bisect."],
                },
              ],
            },
          ],
        },
        {
          id: "coldpin-incident",
          title: "/coldpin-incident — Supply-Chain Compromise Response",
          blocks: [
            {
              kind: "prompt-composer",
              id: "prompt-coldpin-incident",
              slashCommand: "/coldpin-incident",
              title: "Launch Read-Only Supply-Chain Incident Containment",
              description:
                "Halts unvetted execution, runs --first-parent Git commit bisect via resolve_safe_anchor, verifies audit.jsonl evidence, surfaces regulatory clocks, and prepares safe REA Tier-2 handoff.",
              prompt:
                "/coldpin-incident Run a strictly read-only Coldpin incident response brief: confirm zero package execution, keep all IOCs defanged, inspect the flagged package cold via inspect_package_artifact, locate patient-zero and a verified rollback anchor or vetted alternative via resolve_safe_anchor, verify audit.jsonl via audit_verify, and summarize containment and regulatory notification clocks without running shell commands.",
              badges: ["Read-Only", "Defanged IOCs Only", "Zero Self-Bootstrap"],
            },
            {
              kind: "callout",
              tone: "danger",
              title: "Never Run Unvetted Commands During Incident Response",
              body: [
                "Deep-link prompts on this portal are strictly read-only and never emit shell or ",
                { code: "npx" },
                " execution links. Never recommend ",
                { code: "@latest" },
                " or bootstrap ",
                { code: "rea-agents" },
                " via ",
                { code: "npx" },
                " during compromise triage.",
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PILLAR 3: MCP & CLI (3 pages)
    // =========================================================================
    {
      slug: "mcp-tools",
      pillar: "mcp-cli",
      title: "7 MCP Tools, Resources & Prompts",
      shortTitle: "7 MCP Tools",
      description:
        "Complete live-synced reference for Coldpin's 7 read-only MCP tools, 2 resources, 1 resource template, 2 prompts, and SHA-256 rug-pull schema pin.",
      lead: [
        "Coldpin exposes a static, plain-English MCP catalog (",
        { code: "MCP 2025-11-25" },
        ", ",
        { code: "2025-06-18" },
        ", ",
        { code: "2025-03-26" },
        ") pinned cryptographically in ",
        { code: "catalog/mcp-schema-pin.json" },
        " at ",
        { code: `${m.mcpEstimatedTokens.toLocaleString("en-US")} <= 1,800` },
        " estimated tokens (",
        { code: `${m.mcpToolsListChars.toLocaleString("en-US")} chars` },
        "). Control-plane parameters (",
        { code: "policy_path" },
        ", writable ",
        { code: "audit_log_path" },
        ", ",
        { code: "override_ticket_id" },
        ") are permanently omitted from tool schemas.",
      ],
      surfaces: ["Local stdio (lib/mcp.mjs)", "Self-Hosted HTTP (lib/mcp-http.mjs)", "Official MCP Registry"],
      keywords: [
        "mcp",
        "tools",
        "discover_packages",
        "inspect_package_artifact",
        "resolve_safe_anchor",
        "verify_confusion",
        "audit_manifest_batch",
        "audit_verify",
        "get_artifact_report",
        "resources",
        "prompts",
        "schema pin",
        "1628",
      ],
      sections: [
        {
          id: "mcp-tool-reference",
          title: "7 Read-Only MCP Tools",
          blocks: [
            {
              kind: "table",
              id: "mcp-tools-table",
              switchable: true,
              headers: ["Tool Name", "Description", "Parameters (* = required)", "Posture"],
              nowrapCols: [0, 3],
              rows: mcpToolRows,
            },
          ],
        },
        {
          id: "mcp-resources-prompts",
          title: "Resources, Templates & Prompts",
          blocks: [
            {
              kind: "table",
              id: "mcp-res-table",
              switchable: true,
              headers: ["Type", "URI / Name", "MIME / Arguments", "Purpose"],
              nowrapCols: [0, 1],
              rows: [
                ...MCP_RESOURCES.map((r) => [
                  ["Resource"],
                  [{ code: r.uri }],
                  [{ code: r.mimeType }],
                  [r.description],
                ]),
                ...MCP_RESOURCE_TEMPLATES.map((rt) => [
                  ["Template"],
                  [{ code: rt.uriTemplate }],
                  [{ code: rt.mimeType }],
                  [rt.description],
                ]),
                ...MCP_PROMPTS.map((pr) => [
                  ["Prompt"],
                  [{ code: pr.name }],
                  [{ code: pr.arguments.map((a) => (a.required ? `${a.name}*` : a.name)).join(", ") }],
                  [pr.description],
                ]),
              ],
            },
          ],
        },
        {
          id: "mcp-runtime-bounds",
          title: "Transport, Concurrency & Schema Pin Guarantees",
          blocks: [
            {
              kind: "ul",
              items: [
                [{ strong: "Framing & stdio safety: " }, "Byte-buffered LF/CRLF framing with ", { code: "1 MiB" }, " cap, ", { code: "stdout" }, " hijack guard, and ", { code: "drain" }, " backpressure."],
                [{ strong: "3-tier workspace root confinement: " }, "Resolves allowed local roots from operator ", { code: "COLDPIN_ALLOWED_ROOTS" }, " and MCP ", { code: "roots/list" }, " (blocking symlink escapes, path traversal, and NTFS ADS)."],
                [{ strong: "Bounded concurrency & session LRU: " }, "Semaphore caps ", { code: "maxConcurrent=4" }, " / ", { code: "maxQueue=16" }, " with ", { code: "notifications/cancelled" }, " support; ephemeral LRU holds max ", { code: "25" }, " reports / ", { code: "30 min" }, " TTL / ", { code: "15 MiB" }, " cap (never persisted to SQLite)."],
                [{ strong: "Rug-pull schema pin (SS-11): " }, "Live ", { code: "tools/list" }, " + ", { code: "resources/list" }, " + ", { code: "prompts/list" }, " canonical SHA-256 ", { code: `${m.mcpCatalogSha256.slice(0, 16)}...` }, " is verified automatically on every build and self-audit."],
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 10: /docs/cli-reference/
    // =========================================================================
    {
      slug: "cli-reference",
      pillar: "mcp-cli",
      title: "CLI Reference & Exit Codes",
      shortTitle: "6 CLI Verbs & Exit Codes",
      description:
        "Complete command, flag, output format, and exit-code reference for Coldpin's zero-dependency Node.js 24 CLI.",
      lead: [
        "Both the standalone CLI (",
        { code: "lib/cli.mjs" },
        " / ",
        { code: "coldpin" },
        ") and the MCP servers execute the exact same pure async workflows under ",
        { code: "src/core/workflows.ts" },
        ".",
      ],
      surfaces: ["Standalone CLI", "GitHub Actions / CI", "Node.js >= 24"],
      keywords: [
        "cli",
        "discover",
        "inspect",
        "resolve-anchor",
        "verify-confusion",
        "audit-batch",
        "audit-verify",
        "exit codes",
        "sarif",
        "sbom",
        "flags",
      ],
      sections: [
        {
          id: "cli-verbs",
          title: "6 Canonical CLI Verbs (+ mcp Dispatch)",
          blocks: [
            {
              kind: "table",
              id: "cli-verbs-table",
              switchable: true,
              headers: ["CLI Verb", "MCP Equivalent", "Exit Codes", "Description"],
              nowrapCols: [0, 1, 2],
              rows: [
                [
                  [{ code: "discover [query]" }],
                  [{ code: "discover_packages" }],
                  [{ code: "0 / 2 / 1" }],
                  ["Search npm by capability, category, org, or creator with org allow/deny policy, release cooldown, and 7-primitive typosquat/slopsquat filters."],
                ],
                [
                  [{ code: "inspect <pkg[@ver]>" }],
                  [{ code: "inspect_package_artifact" }],
                  [{ code: "0 / 2 / 3 / 1" }],
                  ["Zero-execution tarball inspection, SHA-512 check, lexical JS/TS taint, hidden-Unicode scan, OSV/MAL-*, and 3-tier tarball-to-Git parity."],
                ],
                [
                  [{ code: "resolve-anchor <pkg>" }],
                  [{ code: "resolve_safe_anchor" }],
                  [{ code: "0 / 2 / 3 / 1" }],
                  ["Walk ", { code: "--first-parent" }, " Git history with blob-cached SQLite scans to locate patient-zero and verify a clean npm tarball rollback or alternative."],
                ],
                [
                  [{ code: "verify-confusion [path]" }],
                  [{ code: "verify_confusion" }],
                  [{ code: "0 / 3 / 1" }],
                  ["Audit ", { code: "package.json" }, " and ", { code: ".npmrc" }, " for unpinned private scopes and claimable internal names (", { code: "T1195.001" }, ")."],
                ],
                [
                  [{ code: "audit-batch [path]" }],
                  [{ code: "audit_manifest_batch" }],
                  [{ code: "0 / 2 / 3 / 1" }],
                  ["Batch-screen up to 50 direct dependencies from ", { code: "package.json" }, " with private-scope OSV non-leakage."],
                ],
                [
                  [{ code: "audit-verify <jsonl>" }],
                  [{ code: "audit_verify" }],
                  [{ code: "0 / 3 / 1" }],
                  ["Verify sequence continuity, extra-field tamper protection, and SHA-256 hash chain of local ", { code: "audit.jsonl" }, " files."],
                ],
                [
                  [{ code: "mcp" }],
                  ["Server entrypoint"],
                  [{ code: "0 / 1" }],
                  ["Start local zero-dependency JSON-RPC 2.0 ", { code: "stdio" }, " MCP server (", { code: "lib/mcp.mjs" }, ")."],
                ],
              ],
            },
          ],
        },
        {
          id: "exit-codes",
          title: "Deterministic Exit Codes",
          blocks: [
            {
              kind: "table",
              id: "cli-exit-table",
              switchable: true,
              headers: ["Exit Code", "Meaning", "Typical Verdicts / CI Action"],
              nowrapCols: [0],
              rows: [
                [[{ code: "0" }], ["Clean within scope / Pass"], [{ code: "VERIFIED_CLEAN_WITHIN_SCOPE" }, ", ", { code: "USE_PINNED_LATEST" }, ", valid ", { code: "audit.jsonl" }, ", ", { code: "--version" }, " / ", { code: "-V" }]],
                [[{ code: "2" }], ["Suspicious, quarantined, or unverifiable"], [{ code: "QUARANTINE_SUSPICIOUS" }, ", ", { code: "UNVERIFIABLE_UNKNOWN" }, ", ", { code: "FORENSIC_COMMIT_ONLY" }, " — fail closed in CI until reviewed"]],
                [[{ code: "3" }], ["Malicious indicators or policy block"], [{ code: "MALICIOUS_INDICATORS_FOUND" }, ", dependency confusion found, tampered ", { code: "audit.jsonl" }, " — halt build immediately"]],
                [[{ code: "1" }], ["Invalid usage or operational error"], ["Unknown flag, missing required value, Node < 24, or unreadable local target"]],
              ],
            },
          ],
        },
        {
          id: "cli-flags",
          title: "Common Flags & Output Formats",
          blocks: [
            {
              kind: "table",
              id: "cli-flags-table",
              switchable: true,
              headers: ["Flag", "Applies To", "Behavior"],
              nowrapCols: [0, 1],
              rows: [
                [[{ code: "--json" }], ["All verbs"], ["Emit canonical JSON report to ", { code: "stdout" }]],
                [[{ code: "--sarif" }], [{ code: "inspect" }], ["Emit OASIS SARIF 2.1.0 JSON for GitHub Code Scanning"]],
                [[{ code: "--sbom" }], [{ code: "inspect" }], ["Emit OWASP CycloneDX 1.5 SBOM + VEX JSON (with ", { code: "coldpin:provenance-status" }, ")"]],
                [[{ code: "--tarball <file.tgz>" }], [{ code: "inspect" }], ["Inspect a local ", { code: ".tgz" }, " archive directly in memory"]],
                [[{ code: "--git-dir <dir>" }, " / ", { code: "--repo-url <url>" }], [{ code: "inspect" }, ", ", { code: "resolve-anchor" }], ["Local Git checkout or HTTPS remote (redirects & Git hooks disabled)"]],
                [[{ code: "--offline" }], ["All network verbs"], ["Forbid all outbound HTTP requests and remote ", { code: "git clone" }, " (fails closed)"]],
                [[{ code: "--limit <1..50>" }, " / ", { code: "--include-dev" }], [{ code: "discover" }, ", ", { code: "audit-batch" }], ["Bound result count (max 50 direct deps for ", { code: "audit-batch" }, ") or include ", { code: "devDependencies" }]],
                [[{ code: "--policy <file>" }, " / ", { code: "--audit-log <file>" }], ["All verbs"], ["Explicit ", { code: ".coldpin.policy.json" }, " path or append-only hash-chained ", { code: "audit.jsonl" }]],
                [[{ code: "--override-ticket <id>" }], [{ code: "inspect" }], ["Record approval ticket ID in ", { code: "audit.jsonl" }, " (never alters deterministic verdict)"]],
                [[{ code: "--verbose" }, " / ", { code: "--version" }, " (", { code: "-V" }, ")"], ["All verbs"], ["Structured JSON operational logs on ", { code: "stderr" }, " or print ", { code: `coldpin v${v}` }]],
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 11: /docs/enterprise-http/ (FULL v1.6.0 PHASE E COVERAGE)
    // =========================================================================
    {
      slug: "enterprise-http",
      pillar: "mcp-cli",
      title: "Self-Hosted HTTP MCP, MCP App & Weekly Sidecar (v1.6+)",
      shortTitle: "Enterprise HTTP & Sidecar",
      description:
        "Complete Phase E (v1.6.0) guide: opt-in coldpin-mcp-http Streamable HTTP adapter with OAuth 2.1 CIMD/JWKS, SEP-1865 inline MCP App, and disabled-by-default weekly audit sidecar.",
      lead: [
        "Introduced in ",
        { code: `v${v}` },
        " (Phase E), all three enterprise extensions are strictly opt-in and preserve Coldpin's ",
        { strong: "$0/mo" },
        " maintainer cost and default local ",
        { code: "stdio" },
        "-only zero-socket posture (",
        { code: "mcp_config.json" },
        " → ",
        { code: "lib/mcp.mjs" },
        ").",
      ],
      surfaces: ["Self-Hosted VPC / Cloud Run", "Antigravity >= v2.34.0 (MCP App)", "MCP 2025-11-25"],
      keywords: [
        "enterprise http",
        "phase e",
        "coldpin-mcp-http",
        "mcp-http.mjs",
        "COLDPIN_HTTP_RESOURCE_URL",
        "COLDPIN_HTTP_AUTH_MODE",
        "COLDPIN_OAUTH_ISSUER",
        "COLDPIN_MCP_API_KEY_SHA256",
        "oauth 2.1",
        "cimd",
        "jwks",
        "rfc 9728",
        "rfc 8707",
        "cloud run",
        "evidence-card.html",
        "sidecar",
        "weekly audit",
      ],
      sections: [
        {
          id: "http-adapter-overview",
          title: "Opt-In Streamable HTTP MCP Adapter (coldpin-mcp-http)",
          blocks: [
            {
              kind: "p",
              text: [
                "Binary ",
                { code: "coldpin-mcp-http" },
                " (",
                { code: "lib/mcp-http.mjs" },
                ", POSIX ",
                { code: "0100755" },
                ") exposes Coldpin's exact 7 read-only MCP tools over Streamable HTTP (",
                { code: "MCP 2025-11-25" },
                ") on your own VPC or Cloud Run infrastructure. It is isolated from ",
                { code: "lib/mcp.mjs" },
                " and enforced by SkillSpector rule ",
                { code: "SS-16-HTTP-ADAPTER-HARDENING" },
                ".",
              ],
            },
            {
              kind: "callout",
              tone: "caution",
              title: "Fail-Closed Startup Requirements",
              body: [
                { code: "coldpin-mcp-http" },
                " refuses to start unless BOTH ",
                { code: "COLDPIN_HTTP_RESOURCE_URL" },
                " (must be ",
                { code: "https://" },
                ") and ",
                { code: "COLDPIN_HTTP_AUTH_MODE" },
                " (",
                { code: "oauth" },
                ", ",
                { code: "api_key" },
                ", or ",
                { code: "both" },
                ") are explicitly configured. Plaintext ",
                { code: "http://" },
                " is rejected unless loopback-bound with ",
                { code: "COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE=1" },
                ".",
              ],
            },
            {
              kind: "ul",
              items: [
                [{ strong: "OAuth 2.1 + PKCE (S256) + CIMD: " }, "Serves RFC 9728 Protected Resource Metadata on both ", { code: "/.well-known/oauth-protected-resource" }, " and path-inserted forms, supports Antigravity CIMD (", { code: "https://antigravity.google/oauth/client-metadata.json" }, "), verifies ", { code: "RS256" }, " / ", { code: "ES256" }, " JWTs via pure Node 24 ", { code: "node:crypto" }, " against pinned JWKS (strictly rejecting ", { code: "alg: none" }, " and ", { code: "HS*" }, "), and enforces RFC 8707 ", { code: "aud" }, " + required scope (", { code: "403 insufficient_scope" }, ")."],
                [{ strong: "Constant-Time SHA-256 API Keys: " }, "Accepts ", { code: ">= 32" }, "-char ", { code: "cpk_live_*" }, " bearer keys compared against ", { code: "COLDPIN_MCP_API_KEY_SHA256" }, " via ", { code: "crypto.timingSafeEqual" }, " (rejecting unexpanded ", { code: "${VAR}" }, " placeholders)."],
                [{ strong: "Transport Hardening: " }, "Anti-DNS-rebinding ", { code: "Host" }, " + browser ", { code: "Origin" }, " allowlists (", { code: "403" }, "), ", { code: "1 MiB" }, " request body cap (", { code: "413" }, "), per-principal rate limiting (", { code: "429" }, " + ", { code: "Retry-After" }, "), and principal-bound cryptographic ", { code: "Mcp-Session-Id" }, " (", { code: "403" }, " on cross-principal reuse, ", { code: "DELETE /mcp" }, " returns ", { code: "204" }, ")."],
              ],
            },
          ],
        },
        {
          id: "http-env-vars",
          title: "HTTP & OAuth 2.1 Environment Variables",
          blocks: [
            {
              kind: "table",
              id: "http-env-table",
              switchable: true,
              headers: ["Environment Variable", "Default / Required", "Purpose & Hardening Behavior"],
              nowrapCols: [0, 1],
              rows: [
                [[{ code: "COLDPIN_HTTP_RESOURCE_URL" }], ["Required"], ["Canonical ", { code: "https://" }, " MCP endpoint URI (e.g. ", { code: "https://coldpin.acme.internal/mcp" }, ") used for RFC 9728 metadata and RFC 8707 ", { code: "aud" }, " validation."]],
                [[{ code: "COLDPIN_HTTP_AUTH_MODE" }], ["Required"], ["Authentication policy: ", { code: "oauth" }, ", ", { code: "api_key" }, ", or ", { code: "both" }, "."]],
                [[{ code: "COLDPIN_HTTP_HOST" }], [{ code: "127.0.0.1" }], ["Bind address (keep ", { code: "127.0.0.1" }, " behind a TLS reverse proxy / Cloud Run ingress)."]],
                [[{ code: "COLDPIN_HTTP_PORT" }], [{ code: "8787" }], ["TCP listen port (", { code: "0..65535" }, ")."]],
                [[{ code: "COLDPIN_HTTP_ALLOWED_HOSTS" }], ["Resource host"], ["Comma-separated additional ", { code: "Host" }, " headers permitted by anti-DNS-rebinding policy."]],
                [[{ code: "COLDPIN_HTTP_ALLOWED_ORIGINS" }], ["None (non-browser)"], ["Comma-separated browser ", { code: "Origin" }, " allowlist (requests without ", { code: "Origin" }, " pass; unknown browser origins get ", { code: "403" }, ")."]],
                [[{ code: "COLDPIN_HTTP_RATE_LIMIT_PER_MIN" }], [{ code: "60" }], ["Per-principal sliding-window request limit per minute (returns ", { code: "429" }, " + ", { code: "Retry-After" }, ")."]],
                [[{ code: "COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE" }], [{ code: "0" }, " (false)"], ["Set to ", { code: "1" }, " strictly for local loopback testing over ", { code: "http://127.0.0.1" }, "."]],
                [[{ code: "COLDPIN_OAUTH_ISSUER" }], ["Required (oauth/both)"], ["Expected JWT ", { code: "iss" }, " claim (exact match after trailing-slash normalization)."]],
                [[{ code: "COLDPIN_OAUTH_AUTH_SERVERS" }], ["Falls back to issuer"], ["Comma-separated RFC 9728 ", { code: "authorization_servers" }, " URIs advertised to MCP clients."]],
                [[{ code: "COLDPIN_OAUTH_REQUIRED_SCOPE" }], [{ code: "coldpin:read" }], ["Required JWT ", { code: "scope" }, " or ", { code: "scp" }, " entry; missing scope returns ", { code: "403 insufficient_scope" }, "."]],
                [[{ code: "COLDPIN_OAUTH_JWKS_URL" }], ["OAuth (XOR path)"], ["HTTPS JWKS endpoint fetched via SSRF-guarded ", { code: "fetchJwksJson()" }, " (5-min TTL, 10s min refresh)."]],
                [[{ code: "COLDPIN_OAUTH_JWKS_PATH" }], ["OAuth (XOR URL)"], ["Local filesystem JWKS JSON file for offline or air-gapped OAuth key pinning."]],
                [[{ code: "COLDPIN_MCP_API_KEY_SHA256" }], ["Required (api_key/both)"], ["Comma-separated 64-hex SHA-256 digests of ", { code: ">= 32" }, "-char ", { code: "cpk_live_*" }, " read-only keys (raw keys never stored on server)."]],
              ],
            },
          ],
        },
        {
          id: "http-remote-config",
          title: "Antigravity Remote HTTP & Cloud Run Config Templates",
          blocks: [
            {
              kind: "p",
              text: [
                "Coldpin ships three ready-to-adapt client entries in ",
                { code: "examples/mcp_config.http-remote.example.json" },
                " covering OAuth 2.1 CIMD, scoped API key ",
                { code: "variables" },
                ", and Google Cloud Run ",
                { code: "google_credentials" },
                " ADC:",
              ],
            },
            {
              kind: "code",
              id: "eh-remote-json",
              label: "examples/mcp_config.http-remote.example.json",
              lang: "json",
              code: m.httpRemoteConfigText,
            },
          ],
        },
        {
          id: "inline-mcp-app",
          title: "Zero-Dependency Inline MCP App (ui://coldpin/evidence-card.html)",
          blocks: [
            {
              kind: "p",
              text: [
                "Resource ",
                { code: "ui://coldpin/evidence-card.html" },
                " (",
                { code: "text/html;profile=mcp-app" },
                ", ",
                { code: "SEP-1865" },
                " / ",
                { code: "io.modelcontextprotocol/ui" },
                ") renders interactive read-only ",
                { code: "Title + Info + Evidence" },
                " cards inline in Antigravity (",
                { code: ">= v2.34.0" },
                ") while hosts without MCP App support continue receiving compact JSON/Markdown summaries automatically.",
              ],
            },
            {
              kind: "ul",
              items: [
                [{ strong: "Linked tools (4): " }, { code: "inspect_package_artifact" }, ", ", { code: "resolve_safe_anchor" }, ", ", { code: "verify_confusion" }, ", and ", { code: "audit_manifest_batch" }, " declare ", { code: "_meta.ui.resourceUri" }, " while holding ", { code: "tools/list" }, " at ", { code: `${m.mcpEstimatedTokens.toLocaleString("en-US")} <= 1,800` }, " tokens."],
                [{ strong: "Security invariants (SS-18): " }, "Default-deny CSP (", { code: "csp: {}" }, ", ", { code: "default-src 'none'" }, "), zero external URLs, strict ", { code: "createElement" }, "/", { code: "textContent" }, " DOM rendering (zero ", { code: "innerHTML" }, "), copy-only command button (never executes), Antigravity ", { code: "--color-*" }, " theme tokens, and read-only ", { code: "get_artifact_report" }, " paging."],
              ],
            },
            {
              kind: "callout",
              tone: "tip",
              title: "Try the Real MCP App Card Live",
              body: [
                "Interact with Coldpin's real compiled ",
                { code: "ui://coldpin/evidence-card.html" },
                " card across all 4 verdicts and test live ",
                { code: "get_artifact_report" },
                " paging in the ",
                { link: "Interactive Policy Lab", href: "/docs/policy-lab/#verdict-explorer" },
                ".",
              ],
            },
          ],
        },
        {
          id: "weekly-sidecar",
          title: "Disabled-by-Default Scheduled Weekly Audit Sidecar",
          blocks: [
            {
              kind: "p",
              text: [
                "Organizations wanting recurring weekly supply-chain audits can opt into ",
                { code: "examples/sidecar.weekly-audit.example.json" },
                ". Per ",
                { code: "SS-17-SIDECAR-LEAST-PRIV" },
                ", no active ",
                { code: "sidecars/" },
                " directory ships at the plugin root, and ",
                { code: "agent_permissions.access_grants" },
                " permits strictly three read-only Coldpin MCP tools (zero shell or file-write grants):",
              ],
            },
            {
              kind: "code",
              id: "eh-sidecar-json",
              label: "examples/sidecar.weekly-audit.example.json",
              lang: "json",
              code: m.weeklySidecarConfigText,
            },
            {
              kind: "code",
              id: "eh-sidecar-enable",
              label: "Explicit opt-in installation path",
              lang: "sh",
              code: `mkdir -p ~/.gemini/config/sidecars/coldpin-weekly-audit\ncp examples/sidecar.weekly-audit.example.json ~/.gemini/config/sidecars/coldpin-weekly-audit/sidecar.json`,
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PILLAR 4: ENTERPRISE & SECURITY (3 pages)
    // =========================================================================
    {
      slug: "configuration",
      pillar: "enterprise-security",
      title: "Configuration & Private-Scope Isolation",
      shortTitle: "Configuration & Policy",
      description:
        "Configure Coldpin's operator environment variables, .coldpin.policy.json, private npm registries, and Antigravity variables without leaking internal scopes.",
      lead: [
        "Coldpin enforces an operator-only control plane: security policy, private scopes, registry credentials, and allowed local roots are configured strictly through startup environment variables or pinned operator policy files — never mutable by untrusted tool calls.",
      ],
      surfaces: ["Local CLI", "Local stdio MCP", "Self-Hosted HTTP MCP", "Antigravity Variables"],
      keywords: [
        "configuration",
        "COLDPIN_POLICY_PATH",
        "COLDPIN_ALLOWED_ROOTS",
        "COLDPIN_AUDIT_LOG",
        "COLDPIN_CACHE_DIR",
        "COLDPIN_OFFLINE",
        "COLDPIN_PRIVATE_SCOPES",
        "COLDPIN_PRIVATE_REGISTRY_URL",
        "COLDPIN_REGISTRY_TOKEN",
        "private registry",
        "npmrc",
        "policy",
      ],
      sections: [
        {
          id: "operator-env-vars",
          title: "Core Operator Environment Variables",
          blocks: [
            {
              kind: "callout",
              tone: "note",
              title: "Private-Scope Non-Leakage & 1-Edit Typo Hard-Block",
              body: [
                "Any scope listed in ",
                { code: "COLDPIN_PRIVATE_SCOPES" },
                ", ",
                { code: ".coldpin.policy.json" },
                ", or ",
                { code: "$HOME/.npmrc" },
                " NEVER contacts public ",
                { code: "registry.npmjs.org" },
                " or ",
                { code: "api.osv.dev" },
                ". Scopes within 1 Levenshtein edit or adjacent transposition (e.g., ",
                { code: "@amce" },
                " vs ",
                { code: "@acme" },
                ") are hard-blocked (",
                { code: "blocked_typo" },
                ") before any network call.",
              ],
            },
            {
              kind: "table",
              id: "cfg-env-table",
              switchable: true,
              headers: ["Environment Variable", "Required", "Behavior & Guardrails"],
              nowrapCols: [0, 1],
              rows: [
                [[{ code: "COLDPIN_POLICY_PATH" }], ["No"], ["Operator-pinned immutable ", { code: ".coldpin.policy.json" }, " (overrides workspace policy and env scope defaults)."]],
                [[{ code: "COLDPIN_ALLOWED_ROOTS" }], ["No"], ["OS-delimited local workspace root allowlist for root-confined tarball, lockfile, and Git reads when an MCP host omits ", { code: "roots/list" }, "."]],
                [[{ code: "COLDPIN_AUDIT_LOG" }], ["No"], ["Path to optional append-only hash-chained ", { code: "audit.jsonl" }, " storing pseudonymous SHA-256 ", { code: "actor_id_hash" }, "."]],
                [[{ code: "COLDPIN_CACHE_DIR" }], ["No"], ["Split-Plane SQLite cache directory (defaults to ", { code: "${PLUGIN_DATA}" }, " in Antigravity or OS cache dir; ", { code: "0700" }, "/", { code: "0600" }, " POSIX modes)."]],
                [[{ code: "COLDPIN_OFFLINE" }], ["No"], ["Set to ", { code: "1" }, " to forbid all outbound HTTP traffic and remote ", { code: "git clone" }, " (fails closed)."]],
                [[{ code: "COLDPIN_PRIVATE_SCOPES" }], ["No"], ["Comma-separated internal ", { code: "@scope" }, " list routed exclusively to ", { code: "COLDPIN_PRIVATE_REGISTRY_URL" }, "."]],
                [[{ code: "COLDPIN_PRIVATE_REGISTRY_URL" }], ["No"], ["HTTPS-only private registry origin validated against SSRF loopback, link-local, IMDS, CGNAT, and RFC 1918 ranges."]],
                [[{ code: "COLDPIN_REGISTRY_TOKEN" }], ["No (Secret)"], ["Read-only bearer token sent strictly over HTTPS to the exact matching private host. Unexpanded ", { code: "${VAR}" }, " placeholders are rejected (", { code: "[PLG-09]" }, ") and tokens are never logged."]],
                [[{ code: "COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE" }], ["No"], ["Set to ", { code: "1" }, " to permit ", { code: "verify_confusion(check_public: true)" }, " in MCP mode (disabled by default to prevent scope leakage)."]],
                [[{ code: "COLDPIN_HOOK_VERBOSE" }], ["No"], ["Set to ", { code: "1" }, " to log diagnostic ", { code: "PreToolUse" }, " hook decisions to ", { code: "stderr" }, " without altering ", { code: "stdout" }, " JSON."]],
              ],
            },
          ],
        },
        {
          id: "private-registry-overlay",
          title: "Enterprise Private Registry Overlay (Antigravity Variables)",
          blocks: [
            {
              kind: "p",
              text: [
                "Default ",
                { code: "mcp_config.json" },
                " declares zero mandatory ",
                { code: "variables" },
                " so public installs work immediately. Enterprise teams routing internal scopes to Artifactory, Verdaccio, or GitHub Packages can apply ",
                { code: "examples/mcp_config.private-registry.example.json" },
                " (all variables stay in ",
                { code: "env" },
                " — never CLI ",
                { code: "args" },
                ", verified by ",
                { code: "SS-12" },
                "):",
              ],
            },
            {
              kind: "code",
              id: "cfg-priv-json",
              label: "examples/mcp_config.private-registry.example.json",
              lang: "json",
              code: m.privateRegistryConfigText,
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 13: /docs/privacy/
    // =========================================================================
    {
      slug: "privacy",
      pillar: "enterprise-security",
      title: "Privacy & Data Handling",
      shortTitle: "Privacy & Data Handling",
      description:
        "Zero telemetry, local-only persistence boundaries, private-scope non-leakage, token hygiene, and host agent processing boundaries.",
      lead: [
        "Coldpin operates no hosted backend service, telemetry endpoint, analytics collector, cookies, or external database. No account or license key is required, and this documentation portal itself collects zero analytics and sets zero cookies.",
      ],
      surfaces: ["Local CLI & stdio MCP", "Offline Mode", "Self-Hosted HTTP MCP"],
      keywords: [
        "privacy",
        "telemetry",
        "data handling",
        "sqlite",
        "lru",
        "audit.jsonl",
        "actor_id_hash",
        "egress",
        "private scope",
        "dpdp",
        "gdpr",
      ],
      sections: [
        {
          id: "local-storage",
          title: "Local Inputs & Persistence Boundaries",
          blocks: [
            {
              kind: "ul",
              items: [
                [{ strong: "Split-Plane SQLite Cache: " }, "Stored locally at ", { code: "%LOCALAPPDATA%\\coldpin\\cache.sqlite" }, " (Windows), ", { code: "~/.cache/coldpin/cache.sqlite" }, " (POSIX), or ", { code: "${PLUGIN_DATA}/cache.sqlite" }, " (Antigravity) with owner-only ", { code: "0700" }, "/", { code: "0600" }, " permissions and direct ", { code: ":memory:" }, " fallback (never shared ", { code: "/tmp" }, "). Caches structural static facts and base-URL-namespaced TTL-bounded OSV payloads."],
                [{ strong: "Ephemeral Session LRU: " }, "MCP server report paging keeps at most ", { code: "25" }, " reports (", { code: "30-minute" }, " TTL, ", { code: "15 MiB" }, " cap) strictly in process memory — never persisted to SQLite."],
                [{ strong: "Optional Local Audit Trail: " }, "Written only when ", { code: "--audit-log" }, " or ", { code: "COLDPIN_AUDIT_LOG" }, " is explicitly set; records a pseudonymous SHA-256 ", { code: "actor_id_hash" }, " rather than raw usernames or email addresses."],
                [{ strong: "Retention Control: " }, "Coldpin enforces no remote retention; local cache and JSONL logs stay under operator control until purged or archived to enterprise WORM storage."],
              ],
            },
          ],
        },
        {
          id: "outbound-egress",
          title: "Outbound Network Egress & Secrets Handling",
          blocks: [
            {
              kind: "table",
              id: "privacy-egress-table",
              switchable: true,
              headers: ["Mode / Target", "Endpoints Contacted", "Privacy & Token Controls"],
              nowrapCols: [0],
              rows: [
                [
                  ["Offline (", { code: "--offline" }, " / ", { code: "COLDPIN_OFFLINE=1" }, ")"],
                  ["None (0 outbound requests; remote ", { code: "git clone" }, " blocked)"],
                  ["Fails closed as ", { code: "UNVERIFIABLE_UNKNOWN" }, " / ", { code: "OFFLINE_MODE_GIT_CLONE_BLOCKED" }],
                ],
                [
                  ["Public Package Inspection"],
                  [{ code: "registry.npmjs.org" }, ", ", { code: "api.osv.dev" }, ", declared HTTPS Git remote (on ", { code: "resolve-anchor" }, ")"],
                  ["Pre-flight DNS IP guard blocks loopback, IMDS, RFC 1918, CGNAT, ULA; streaming byte caps before ", { code: "JSON.parse" }, "; Git HTTP redirects disabled"],
                ],
                [
                  ["Private Scope / Prefix Inspection"],
                  ["Configured HTTPS private registry ONLY (zero public npm or OSV queries)"],
                  ["Token parsed only from ", { code: "$HOME/.npmrc" }, " or operator ", { code: "COLDPIN_REGISTRY_TOKEN" }, " (never untrusted workspace ", { code: ".npmrc" }, "), exact-host HTTPS only, stripped on cross-origin redirect (", { code: "CWE-200" }, ")"],
                ],
              ],
            },
          ],
        },
        {
          id: "host-agent-boundary",
          title: "Host Agent Processing",
          blocks: [
            {
              kind: "p",
              text: [
                "When invoked inside an AI host (Antigravity, Claude Code, Codex, Cursor), prompts and tool responses are governed by that host's privacy policy. Coldpin's default MCP server is local ",
                { code: "stdio" },
                "-only, its inline MCP App enforces default-deny CSP (",
                { code: "csp: {}" },
                ") with zero network calls, and self-hosted ",
                { code: "lib/mcp-http.mjs" },
                " runs entirely on the customer's own VPC/Cloud Run under their own IdP — Coldpin's maintainer never receives tokens, prompts, or scan telemetry.",
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 14: /docs/security/
    // =========================================================================
    {
      slug: "security",
      pillar: "enterprise-security",
      title: "Security Policy & Compliance Reference",
      shortTitle: "Security & Compliance",
      description:
        "Supported versions, confidential vulnerability reporting, hard security boundaries, EDR Sigma rules, and regulatory incident clocks.",
      lead: [
        "Coldpin treats every scanned npm tarball, ",
        { code: "README.md" },
        ", manifest field, and Git commit message as hostile untrusted input. Verdicts are computed deterministically in TypeScript code outside LLM context.",
      ],
      surfaces: ["v1.6.x Active Maintenance", "SARIF 2.1.0", "CycloneDX 1.5", "Sigma EDR"],
      keywords: [
        "security",
        "vulnerability",
        "supported versions",
        "cert-in",
        "dpdp",
        "cra",
        "nis2",
        "gdpr",
        "soc 2",
        "nist ssdf",
        "sigma",
        "boundaries",
      ],
      sections: [
        {
          id: "supported-versions",
          title: "Supported Versions & Vulnerability Disclosure",
          blocks: [
            {
              kind: "table",
              id: "sec-versions-table",
              switchable: true,
              headers: ["Version Line", "Status"],
              nowrapCols: [0],
              rows: [
                [[{ code: "1.6.x" }], ["Active maintenance (Antigravity >= v1.5.13 hooks; >= v2.34.0 MCP Apps; Node >= 24)"]],
                [[{ code: "1.0.x – 1.5.x" }], ["Security fixes delivered via upgrade to ", { code: "1.6.x" }]],
              ],
            },
            {
              kind: "callout",
              tone: "danger",
              title: "Confidential Security Reporting",
              body: [
                "Do not open a public GitHub issue with weaponized exploit chains or live malicious URLs. Submit confidential reports via ",
                { link: "GitHub Private Vulnerability Reporting", href: `${m.repoUrl}/security/advisories/new`, external: true },
                " with a minimal synthetic fixture tarball, redacted CLI command, expected vs. observed verdict, Node version, and commit SHA. Triage target: 2 business days [Typical].",
              ],
            },
          ],
        },
        {
          id: "hard-boundaries",
          title: "Hard Security Boundaries",
          blocks: [
            {
              kind: "ul",
              items: [
                [{ strong: "Zero-Execution Inspection: " }, "Never runs ", { code: "npm install" }, ", ", { code: "npm pack" }, ", lifecycle hooks, or untrusted binaries during inspection."],
                [{ strong: "No Self-Bootstrap: " }, "Never executes ", { code: "npx -y rea-agents" }, " or silently installs third-party analyzers."],
                [{ strong: "Non-LLM Verdict Authority: " }, "The 4-state ", { code: "TrustVerdict" }, " is deterministic TypeScript; indirect prompt injection (", { code: "AML.T0051" }, ") and Trojan-Source bidi Unicode are quarantined and never override verdicts."],
                [{ strong: "Archive & Network Defenses: " }, "Rejects Zip-Slip traversal, symlinks/hardlinks, duplicate tar entries, EOF polyglot smuggling, corrupt tar checksums, NTFS ADS, zip bombs, and IPv4/IPv6-mapped SSRF."],
                [{ strong: "Companion EDR Detections: " }, "Pair static inspection and Layer-1 hooks with the bundled Linux/Windows Sigma rules under ", { code: "catalog/sigma/" }, "."],
              ],
            },
          ],
        },
        {
          id: "compliance-clocks",
          title: "Compliance & Regulatory Incident Clocks",
          blocks: [
            {
              kind: "p",
              text: [
                "When malicious indicators or lockfile exposure are confirmed, ",
                { code: "rules/coldpin-incident-checklist.md" },
                " and ",
                { code: "/coldpin-incident" },
                " surface standard regulatory clocks for legal and incident-response review (verified in ",
                { code: "docs/fact-ledger.md" },
                "):",
              ],
            },
            {
              kind: "table",
              id: "sec-compliance-table",
              switchable: true,
              headers: ["Framework / Regulation", "Reporting Window / Artifact", "Coldpin Evidence Support"],
              nowrapCols: [0],
              rows: [
                [["India CERT-In Directions (2022-04-28)"], ["6-hour cyber-incident reporting; 180-day ICT log retention"], ["Hash-chained ", { code: "audit.jsonl" }, " + defanged IOCs + lockfile hashes"]],
                [["India DPDP Act 2023 & Rules 2025"], ["Data minimization & breach notification duties"], ["Zero telemetry, zero PII collection, pseudonymous ", { code: "actor_id_hash" }]],
                [["EU Cyber Resilience Act (Reg. 2024/2847)"], ["24h early warning / 72h notification; SBOM obligations"], ["CycloneDX 1.5 SBOM + VEX (", { code: "--sbom" }, ") & SLSA provenance status"]],
                [["EU NIS2 & GDPR Art. 33"], ["24h early warning (NIS2) / 72h breach notification"], ["Deterministic SARIF 2.1.0 (", { code: "--sarif" }, ") + ", { code: "audit-verify" }, " integrity proofs"]],
                [["NIST SSDF & SOC 2"], ["Pre-execution supply-chain control & tamper-evident trails"], ["14-gate CI pipeline, dual DSSE attestations, and operator policy SHA-256"]],
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PILLAR 5: VERIFICATION & RELEASES (3 pages)
    // =========================================================================
    {
      slug: "verification",
      pillar: "verification-releases",
      title: "Verification, Benchmarks & Provenance",
      shortTitle: "Verification & Benchmarks",
      description:
        "Live-synced Coldpin verification gates: 49-fixture corpus (100% recall, 0% FPR), 38/38 mutation proofs, SkillSpector SS-03..SS-18, MCP schema pin, and v1.6.0 SHA256SUMS.",
      lead: [
        "Every Coldpin release passes a cross-platform 14-gate pipeline across ",
        { code: "ubuntu-latest" },
        " and ",
        { code: "windows-latest" },
        " on Node ",
        { code: "24" },
        " LTS and Node ",
        { code: "26" },
        " Active LTS, followed by keyless npm OIDC Trusted Publishing and GitHub SLSA Build Provenance attestations.",
      ],
      surfaces: ["Node 24 & 26 CI Matrix", "Ubuntu & Windows", "SLSA Build Provenance", "Dual DSSE"],
      keywords: [
        "verification",
        "benchmarks",
        "sha256sums",
        "checksums",
        "slsa",
        "provenance",
        "dsse",
        "skillspector",
        "mutations",
        "1628",
        "SS-03",
        "SS-18",
        "42/42",
        "48/48",
      ],
      sections: [
        {
          id: "live-metrics",
          title: "Live Synced Verification Metrics (v" + v + ")",
          blocks: [
            {
              kind: "spec-strip",
              ariaLabel: `Live synced Coldpin v${v} verification metrics`,
              items: [
                { label: "MCP Schema Pin", value: `${m.mcpEstimatedTokens.toLocaleString("en-US")} / 1,800 tokens (${m.mcpToolsCount} tools)` },
                { label: "Core Engine Tests", value: `${m.coreTestCount}/${m.coreTestCount} + docs portal suite` },
                { label: "Mutation Proofs", value: `${m.mutationCount}/${m.mutationCount} regressions caught` },
                { label: "SkillSpector Self-Audit", value: `${m.selfAuditVerdict} ${m.selfAuditRisk}/100 (${m.selfAuditBlocking} blocking)` },
              ],
            },
            {
              kind: "table",
              id: "verif-gates-table",
              switchable: true,
              headers: ["Verification Gate", "Command", "Measured Result"],
              nowrapCols: [0, 1],
              rows: [
                [["Compiled ESM Parity (", { code: "SS-13" }, ")"], [{ code: "npm run build" }], [`${m.compiledEsmCount} compiled LF lib/**/*.mjs files syntax-checked & 1:1 SHA-256 verified`]],
                [["Deterministic Test Suites"], [{ code: "npm test" }], [`${m.coreTestCount}/${m.coreTestCount} core/MCP/plugin/Phase-E tests + automated docs-site parity suite`]],
                [["49-Fixture Security Corpus"], [{ code: "npm run bench:check" }], [`100.0% recall (28/28 adversarial), 0.0% FPR (0/21 benign), ${m.mutationCount}/${m.mutationCount} mutation proofs`]],
                [["SkillSpector Self-Audit"], [{ code: "npm run audit:self" }], [`SS-03–SS-18: ${m.selfAuditVerdict} (risk ${m.selfAuditRisk}/100, ${m.selfAuditBlocking} blocking, 0 SARIF alerts)`]],
                [["MCP Schema Rug-Pull Pin (", { code: "SS-11" }, ")"], [{ code: "catalog/mcp-schema-pin.json" }], [`${m.mcpToolsCount} tools, ${m.mcpResourcesCount} resources, ${m.mcpPromptsCount} prompts, ${m.mcpEstimatedTokens.toLocaleString("en-US")} tokens (${m.mcpCatalogSha256.slice(0, 12)}...)`]],
                [["Dual in-toto DSSE Attestations"], [{ code: "npm run sign:verify" }], [`skills/coldpin/skill.oms.sig (${m.skillAttestedFiles} files) & catalog/plugin.oms.sig (${m.pluginAttestedFiles} files)`]],
                [["Antigravity Strict Validation"], [{ code: "agy plugin validate --strict" }], ["agents: 7, hooks: 3, mcpServers: 1, rules: 3, skills: 3, sidecars: 0, findings: []"]],
                [["Static Docs Parity & Hygiene"], [{ code: "npm run build:docs -- --check" }, " & ", { code: "npm run verify:hygiene" }], ["Zero broken links/anchors, dual-CSP sync, 100% hook-eval.js parity, LF-only UTF-8"]],
              ],
            },
          ],
        },
        {
          id: "release-checksums",
          title: `Release v${v} Verified SHA256SUMS.txt`,
          blocks: [
            {
              kind: "code",
              id: "verif-sha256",
              label: `Release v${v} SHA256SUMS.txt`,
              lang: "text",
              code: m.sha256Sums,
            },
            {
              kind: "p",
              text: [
                "Verify GitHub SLSA Build Provenance attestations online at ",
                { link: "GitHub Attestations", href: `${m.repoUrl}/attestations`, external: true },
                ", or inspect the full source reports: ",
                { link: "BENCHMARK.md", href: `${m.repoUrl}/blob/main/skills/coldpin/BENCHMARK.md`, external: true },
                ", ",
                { link: "SkillSpector Self-Audit", href: `${m.repoUrl}/blob/main/docs/verification/skill-inspector-self-audit.md`, external: true },
                ", and ",
                { link: "TESTING.md", href: `${m.repoUrl}/blob/main/TESTING.md`, external: true },
                ".",
              ],
            },
          ],
        },
        {
          id: "verification-boundaries",
          title: "Explicit Verification Boundaries (Honest Non-Claims)",
          blocks: [
            {
              kind: "callout",
              tone: "caution",
              title: "Tier 3 Live Multi-Agent Sandbox Uplift: NOT RUN (N/A)",
              body: [
                "Offline CI executes deterministic Tier 1 (lint, hygiene, SkillSpector) and Tier 2 (49-fixture corpus, cache benchmarks, ",
                { code: `${m.mutationCount}/${m.mutationCount}` },
                " mutation proofs) gates. Tier 3 live multi-agent LLM token uplift across hosted sandboxes is honestly recorded as ",
                { code: "NOT RUN (N/A)" },
                " rather than fabricated, and local ",
                { code: "*.oms.sig" },
                " dev keys are explicitly labeled ",
                { code: "local-dev-self-signed" },
                ".",
              ],
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 16: /docs/changelog/
    // =========================================================================
    {
      slug: "changelog",
      pillar: "verification-releases",
      title: "Changelog",
      shortTitle: "Changelog",
      description:
        "Complete release history of Coldpin from v1.0.0 through v1.6.0, synced directly from CHANGELOG.md.",
      lead: [
        "All notable changes to ",
        { code: "coldpin" },
        " following Keep a Changelog and Semantic Versioning. Jump to any release from the version index or toggle all entries below.",
      ],
      surfaces: [`Latest: v${v}`, "Semantic Versioning", "Apache-2.0"],
      keywords: [
        "changelog",
        "releases",
        "history",
        "v1.6.0",
        "v1.5.2",
        "v1.5.1",
        "v1.5.0",
        "v1.4.0",
        "v1.3.0",
        "v1.2.1",
        "v1.2.0",
        "v1.1.0",
        "v1.0.0",
      ],
      sections: [
        {
          id: "releases",
          title: `Release History (v1.0.0 – v${v})`,
          blocks: [
            {
              kind: "details",
              id: "changelog-list",
              variant: "release",
              expandAllId: "changelog-toggle-controls",
              items: changelogItems,
            },
          ],
        },
      ],
    },

    // =========================================================================
    // PAGE 17: /docs/faq/
    // =========================================================================
    {
      slug: "faq",
      pillar: "verification-releases",
      title: "FAQ & Epistemic Limits",
      shortTitle: "FAQ & Epistemic Limits",
      description:
        "Honest answers about what static tarball triage can and cannot prove, stock npx transitive caveats, REA escalation, and alternatives.",
      lead: [
        "Security tooling should never overstate what static analysis can prove. These answers define Coldpin's exact epistemic boundaries and how it complements runtime isolation and private registries.",
      ],
      surfaces: ["Epistemic Rigor", "All Harnesses"],
      keywords: [
        "faq",
        "epistemic limits",
        "VERIFIED_CLEAN_WITHIN_SCOPE",
        "sha512",
        "transitive",
        "FORENSIC_COMMIT_ONLY",
        "rea-agents",
        "tier 3",
        "alternatives",
        "support",
      ],
      sections: [
        {
          id: "common-questions",
          title: "Frequently Asked Questions",
          blocks: [
            {
              kind: "details",
              id: "faq-accordion",
              variant: "faq",
              items: [
                {
                  id: "faq-clean-scope",
                  summary: "Does VERIFIED_CLEAN_WITHIN_SCOPE prove a package has zero malware?",
                  open: true,
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        { strong: "No." },
                        " Static analysis cannot prove absence of malware on dynamically fetched remote payloads, time-bombed triggers, or uninspected compiled binaries. ",
                        { code: "VERIFIED_CLEAN_WITHIN_SCOPE" },
                        " means only that no malicious, suspicious, policy-violating, or uninspected-binary indicators were observed within the stated static inspection boundary.",
                      ],
                    },
                  ],
                },
                {
                  id: "faq-npx-caveat",
                  summary: "Why does the recommended npx command carry a SHA-512 and transitive caveat?",
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        "Stock ",
                        { code: "npx" },
                        " (",
                        { code: "npm exec" },
                        ") has no ",
                        { code: "--integrity <sha512>" },
                        " CLI flag and ignores lockfiles inside published npm packages, resolving floating ",
                        { code: "^x.y.z" },
                        " transitive dependencies live at runtime. Coldpin states that boundary honestly rather than implying a bare ",
                        { code: "npx" },
                        " command enforces full transitive locks. Combine ",
                        { code: "--ignore-scripts" },
                        " and exact pins with a private caching proxy or shrinkwrapped install for regulated builds.",
                      ],
                    },
                  ],
                },
                {
                  id: "faq-forensic-commit",
                  summary: "Why does resolve-anchor emit FORENSIC_COMMIT_ONLY when no npm tarball matches?",
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        "Running ",
                        { code: "npx github:org/repo#<clean_sha>" },
                        " executes ",
                        { code: "prepare" },
                        " and ",
                        { code: "postinstall" },
                        " build scripts locally and pulls floating transitive dependencies. When a clean Git commit has no matching published npm release tarball, Coldpin suppresses runnable commands and recommends either building inside an isolated sandbox or switching to a vetted alternative (",
                        { code: "SWITCH_TO_ALTERNATIVE" },
                        ").",
                      ],
                    },
                  ],
                },
                {
                  id: "faq-rea",
                  summary: "Do I need REA (rea-agents) installed to use Coldpin?",
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        { strong: "No." },
                        " Discovery, in-memory archive quarantine, JS/TS lexical taint analysis, hidden-Unicode detection, 3-tier tarball parity, and Git commit bisection all run on pure Node.js 24 with zero external packages. When an artifact contains obfuscated bundles or compiled ",
                        { code: ".node" },
                        "/WASM/ELF/PE/Mach-O binaries, Coldpin fails closed and points to a pre-registered REA server — never auto-bootstrapping ",
                        { code: "npx -y rea-agents" }, // never bootstrap rea-agents via npx
                        ".",
                      ],
                    },
                  ],
                },
                {
                  id: "faq-tier3",
                  summary: "Why does BENCHMARK.md mark Tier 3 Live Multi-Agent Evaluation as NOT RUN?",
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        "Epistemic honesty. Tier 3 requires live LLM API calls in isolated sandbox containers across Antigravity, Claude Code, and Codex. Instead of fabricating uplift numbers, ",
                        { code: "BENCHMARK.md" },
                        " reports real measured Tier 1–2 metrics (",
                        { code: `${m.corpusFixtures}` },
                        "-fixture corpus recall/FPR, latency, cache speedup, ",
                        { code: `${m.mutationCount}` },
                        " mutation proofs, and positive/decoy trigger selection) and leaves Tier 3 honestly ",
                        { code: "N/A" },
                        ".",
                      ],
                    },
                  ],
                },
                {
                  id: "faq-http-cost",
                  summary: "Does v1.6.0 HTTP MCP or the Weekly Sidecar open ports or run daemons by default?",
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        { strong: "No." },
                        " Default ",
                        { code: "mcp_config.json" },
                        " runs strictly local ",
                        { code: "stdio" },
                        " (",
                        { code: "lib/mcp.mjs" },
                        ", zero listening sockets), and no active ",
                        { code: "sidecars/" },
                        " directory ships at the plugin root. Both ",
                        { code: "coldpin-mcp-http" },
                        " and ",
                        { code: "examples/sidecar.weekly-audit.example.json" },
                        " are strictly opt-in.",
                      ],
                    },
                  ],
                },
                {
                  id: "faq-alternatives",
                  summary: "Are there alternatives, and where do I get support?",
                  blocks: [
                    {
                      kind: "p",
                      text: [
                        "Yes: Socket.dev, Snyk, GuardDog, OSV-Scanner, and private registries (Verdaccio, Artifactory) solve overlapping parts of npm supply-chain security. Coldpin focuses specifically on the zero-dependency local agentic pre-",
                        { code: "npx" },
                        " workflow. Report bugs or detection gaps publicly on ",
                        { link: "GitHub Issues", href: `${m.repoUrl}/issues`, external: true },
                        "; report security vulnerabilities confidentially via ",
                        { link: "Security Policy", href: "/docs/security/" },
                        ".",
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ];
}
