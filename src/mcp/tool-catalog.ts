import { createHash } from "node:crypto";
import { ENGINE_VERSION } from "../types.ts";
import {
  EVIDENCE_CARD_UI_META,
  EVIDENCE_CARD_UI_MIME,
  EVIDENCE_CARD_UI_URI,
  INLINE_EVIDENCE_CARD_TOOL_META,
} from "./evidence-card-app.ts";
import type {
  McpPromptDefinition,
  McpResourceDefinition,
  McpResourceTemplateDefinition,
  McpToolDefinition,
} from "./types.ts";

/**
 * Static, plain-English MCP tool catalog (`ADR-003`, `[MCP-07]`):
 * - Zero dynamic description generation, zero hidden directives, zero execution tools.
 * - Control-plane parameters (`policy_path`, writable `audit_log_path`, `override_ticket_id`)
 *   are permanently omitted from all tool schemas.
 * - Total serialized `tools/list` footprint is kept strictly <= 1,800 estimated tokens (~7,200 chars).
 */
export const MCP_TOOLS: readonly McpToolDefinition[] = [
  {
    name: "discover_packages",
    description:
      "Search npm packages by query, org, creator, or category with slopsquat, cooldown, policy, and OSV preview verdicts.",
    annotations: {
      title: "Discover npm Packages",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["query"],
      properties: {
        query: { type: "string", minLength: 1, maxLength: 128, description: "Search query text." },
        org: { type: "string", maxLength: 64, description: "Optional npm scope or org filter." },
        creator: { type: "string", maxLength: 64, description: "Optional maintainer handle filter." },
        category: { type: "string", maxLength: 64, description: "Optional keyword or capability filter." },
        limit: { type: "integer", minimum: 1, maximum: 25, default: 10, description: "Max results (1-25)." },
        detail: { type: "string", enum: ["summary", "full"], default: "summary", description: "Output detail level." },
      },
    },
  },
  {
    name: "inspect_package_artifact",
    description:
      "Inspect an npm package or local .tgz cold in memory for taint, lifecycle hooks, Git parity, provenance, and OSV/KEV.",
    annotations: {
      title: "Inspect Package Artifact",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        package_spec: { type: "string", minLength: 1, maxLength: 256, description: "npm spec <pkg>[@<ver>]; XOR tarball_path." },
        tarball_path: { type: "string", minLength: 1, maxLength: 1024, description: "Root-confined local .tgz path; XOR package_spec." },
        git_dir: { type: "string", minLength: 1, maxLength: 1024, description: "Optional root-confined local Git dir for parity." },
        subdir: { type: "string", maxLength: 256, description: "Optional monorepo subdirectory inside Git repo." },
        offline: { type: "boolean", default: false, description: "Tighten-only flag to disable outbound network." },
        detail: { type: "string", enum: ["summary", "card", "full"], default: "summary", description: "Output detail level." },
        format: { type: "string", enum: ["json", "card", "sarif", "sbom"], default: "json", description: "Output format." },
      },
    },
    _meta: INLINE_EVIDENCE_CARD_TOOL_META,
  },
  {
    name: "resolve_safe_anchor",
    description:
      "Walk Git history to locate patient-zero compromise commit and recommend a clean pre-compromise release or alternative.",
    annotations: {
      title: "Resolve Safe Git Anchor",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["package_name"],
      properties: {
        package_name: { type: "string", minLength: 1, maxLength: 214, description: "Target npm package name." },
        git_dir: { type: "string", minLength: 1, maxLength: 1024, description: "Root-confined local Git directory." },
        repo_url: { type: "string", minLength: 1, maxLength: 256, description: "HTTPS remote Git URL (no query/userinfo)." },
        subdir: { type: "string", maxLength: 256, description: "Optional monorepo subdirectory." },
        window: { type: "integer", minimum: 1, maximum: 200, description: "Max commits to inspect (clamped to policy)." },
        detail: { type: "string", enum: ["summary", "full"], default: "summary", description: "Output detail level." },
      },
    },
    _meta: INLINE_EVIDENCE_CARD_TOOL_META,
  },
  {
    name: "verify_confusion",
    description:
      "Audit a root-confined package.json and .npmrc for unpinned private scopes or dependency confusion risks (T1195.001).",
    annotations: {
      title: "Verify Dependency Confusion",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        manifest_path: { type: "string", minLength: 1, maxLength: 1024, description: "Optional root-confined package.json path." },
        check_public: { type: "boolean", default: false, description: "Requires operator COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE=1." },
      },
    },
    _meta: INLINE_EVIDENCE_CARD_TOOL_META,
  },
  {
    name: "audit_verify",
    description:
      "Read-only verification of a root-confined hash-chained Coldpin audit.jsonl log for sequence gaps or tampering.",
    annotations: {
      title: "Verify Audit Log Integrity",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["audit_log_path"],
      properties: {
        audit_log_path: { type: "string", minLength: 1, maxLength: 1024, description: "Root-confined audit.jsonl path (read-only)." },
      },
    },
  },
  {
    name: "audit_manifest_batch",
    description:
      "Batch-screen up to 50 direct dependencies from a root-confined package.json for squats, policy, private scopes, and OSV/KEV.",
    annotations: {
      title: "Batch Audit Manifest Dependencies",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        manifest_path: { type: "string", minLength: 1, maxLength: 1024, description: "Optional root-confined package.json path." },
        include_dev: { type: "boolean", default: false, description: "Include devDependencies." },
        max_deps: { type: "integer", minimum: 1, maximum: 50, default: 50, description: "Max direct dependencies (1-50)." },
        offline: { type: "boolean", default: false, description: "Tighten-only offline flag." },
        detail: { type: "string", enum: ["summary", "full"], default: "summary", description: "Output detail level." },
      },
    },
    _meta: INLINE_EVIDENCE_CARD_TOOL_META,
  },
  {
    name: "get_artifact_report",
    description:
      "Page through a session-scoped Coldpin report section (observations, iocs, unknowns, commits, card, sarif, sbom) by report_id.",
    annotations: {
      title: "Get Paginated Artifact Report",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["report_id", "section"],
      properties: {
        report_id: { type: "string", minLength: 4, maxLength: 64, description: "Session report_id from a prior Coldpin tool call." },
        section: {
          type: "string",
          enum: ["observations", "iocs", "unknowns", "commits", "card", "sarif", "sbom"],
          description: "Report section to slice.",
        },
        offset: { type: "integer", minimum: 0, maximum: 10_000_000, default: 0, description: "Item index or UTF-8 byte offset." },
        limit: { type: "integer", minimum: 1, maximum: 50, default: 20, description: "Max items for list sections (1-50)." },
      },
    },
  },
];

export const MCP_RESOURCES: readonly McpResourceDefinition[] = [
  {
    uri: "coldpin://policy/active",
    name: "Active Coldpin Policy",
    description: "Sanitized active operator policy, SHA-256 hash, authorized root count, and host capabilities (zero secrets).",
    mimeType: "application/json",
  },
  {
    uri: EVIDENCE_CARD_UI_URI,
    name: "Coldpin Evidence Card MCP App",
    description: "Zero-dependency interactive read-only Title + Info + Evidence card (default-deny CSP, copy-only commands).",
    mimeType: EVIDENCE_CARD_UI_MIME,
    _meta: EVIDENCE_CARD_UI_META,
  },
];

export const MCP_RESOURCE_TEMPLATES: readonly McpResourceTemplateDefinition[] = [
  {
    uriTemplate: "coldpin://reports/{report_id}",
    name: "Coldpin Session Report Summary",
    description: "Read-only summary of a session-scoped Coldpin report stored in ephemeral memory.",
    mimeType: "application/json",
  },
];

export const MCP_PROMPTS: readonly McpPromptDefinition[] = [
  {
    name: "vet_before_npx",
    description: "Vet an npm package cold with Coldpin before approving any pinned npx command.",
    arguments: [
      { name: "package_spec", description: "Target package specification (<pkg> or <pkg>@<ver>).", required: true },
      { name: "git_dir", description: "Optional local Git repository directory for parity verification.", required: false },
    ],
  },
  {
    name: "investigate_compromised_org",
    description: "Identify patient-zero compromise commit and safe rollback anchor or vetted alternative for an npm package.",
    arguments: [
      { name: "package_name", description: "Target npm package name.", required: true },
      { name: "repo_url", description: "Optional HTTPS repository URL.", required: false },
    ],
  },
];

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export interface McpSchemaPin {
  schema_version: "1";
  engine_version: string;
  tools_count: number;
  resources_count: number;
  resource_templates_count: number;
  prompts_count: number;
  tools_list_chars: number;
  estimated_tokens: number;
  tools_sha256: string;
  resources_sha256: string;
  prompts_sha256: string;
  catalog_sha256: string;
}

export function computeMcpSchemaPin(): McpSchemaPin {
  const toolsJson = canonicalJson(MCP_TOOLS);
  const resourcesJson = canonicalJson({ resources: MCP_RESOURCES, resourceTemplates: MCP_RESOURCE_TEMPLATES });
  const promptsJson = canonicalJson(MCP_PROMPTS);
  const catalogJson = canonicalJson({
    tools: MCP_TOOLS,
    resources: MCP_RESOURCES,
    resourceTemplates: MCP_RESOURCE_TEMPLATES,
    prompts: MCP_PROMPTS,
  });
  const toolsListChars = JSON.stringify({ tools: MCP_TOOLS }).length;
  return {
    schema_version: "1",
    engine_version: ENGINE_VERSION,
    tools_count: MCP_TOOLS.length,
    resources_count: MCP_RESOURCES.length,
    resource_templates_count: MCP_RESOURCE_TEMPLATES.length,
    prompts_count: MCP_PROMPTS.length,
    tools_list_chars: toolsListChars,
    estimated_tokens: Math.ceil(toolsListChars / 4),
    tools_sha256: createHash("sha256").update(toolsJson).digest("hex"),
    resources_sha256: createHash("sha256").update(resourcesJson).digest("hex"),
    prompts_sha256: createHash("sha256").update(promptsJson).digest("hex"),
    catalog_sha256: createHash("sha256").update(catalogJson).digest("hex"),
  };
}
