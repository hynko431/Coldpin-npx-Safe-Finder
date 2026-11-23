import { randomUUID } from "node:crypto";
import { delimiter } from "node:path";
import type { Readable, Writable } from "node:stream";
import { cleanupActiveGitTempDirs } from "../analysis/parity-and-bisect.ts";
import { defaultCacheDbPath, SplitPlaneCache } from "../cache/sqlite-store.ts";
import {
  hasSecretLikeDiscoveryToken,
  loadMcpPolicy,
  loadNpmrc,
  probeHostCapabilitiesAsync,
  sanitizeOperatorEnvValue,
} from "../config/policy.ts";
import {
  canonicalizeAuthorizedRoots,
  intersectAuthorizedRoots,
  parseFileUriToPath,
} from "../core/path-confinement.ts";
import {
  runAuditManifestBatch,
  runAuditVerify,
  runDiscover,
  runInspect,
  runResolveAnchor,
  runVerifyConfusion,
  type OperatorRuntimeConfig,
  type WorkflowContext,
} from "../core/workflows.ts";
import {
  ENGINE_VERSION,
  type DiscoveryCardList,
  type HostCapabilities,
  type ManifestBatchReport,
  type PackageInspectionReport,
  type SafeAnchorDecision,
} from "../types.ts";
import {
  formatCycloneDxSbom,
  formatInspectionMarkdownCard,
  formatSarif210,
} from "../verdict/engine-and-formatters.ts";
import {
  EVIDENCE_CARD_UI_META,
  EVIDENCE_CARD_UI_MIME,
  EVIDENCE_CARD_UI_URI,
  renderEvidenceCardAppHtml,
} from "./evidence-card-app.ts";
import { BoundedReportStore, REPORT_TEXT_CHUNK_MAX_BYTES, sliceUtf8Safe } from "./report-store.ts";
import { StdioJsonRpcTransport } from "./stdio-transport.ts";
import { MCP_PROMPTS, MCP_RESOURCES, MCP_RESOURCE_TEMPLATES, MCP_TOOLS } from "./tool-catalog.ts";
import {
  JSONRPC_ERRORS,
  SUPPORTED_PROTOCOL_VERSIONS,
  type JsonRpcId,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpLifecycleState,
  type McpToolCallResult,
  type SupportedProtocolVersion,
} from "./types.ts";

interface JsonRpcReplySink {
  sendResult(id: JsonRpcId, result: unknown): Promise<void>;
  sendError(id: JsonRpcId, code: number, message: string, data?: unknown): Promise<void>;
}

const SUMMARY_MAX_BYTES = 6144;
const BATCH_SUMMARY_MAX_BYTES = 2000;
const FULL_PAYLOAD_HARD_CAP_BYTES = 48 * 1024;
const DEFAULT_MAX_CONCURRENT = 4;
const DEFAULT_MAX_QUEUE = 16;

function isTruthyEnv(val: string | undefined): boolean {
  if (!val) return false;
  const v = val.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

export function loadOperatorConfigFromEnv(env: NodeJS.ProcessEnv = process.env): OperatorRuntimeConfig {
  const rawRoots = env["COLDPIN_ALLOWED_ROOTS"] ?? "";
  const allowedRoots = rawRoots
    .split(delimiter)
    .map((s) => sanitizeOperatorEnvValue(s))
    .filter((s): s is string => Boolean(s));
  return {
    policyPath: sanitizeOperatorEnvValue(env["COLDPIN_POLICY_PATH"]),
    trustWorkspacePolicy: isTruthyEnv(env["COLDPIN_TRUST_WORKSPACE_POLICY"]),
    auditLogPath: sanitizeOperatorEnvValue(env["COLDPIN_AUDIT_LOG"]),
    cacheDir: sanitizeOperatorEnvValue(env["COLDPIN_CACHE_DIR"]),
    allowedRoots,
    forceOffline: isTruthyEnv(env["COLDPIN_OFFLINE"]),
    verbose: isTruthyEnv(env["COLDPIN_VERBOSE"]),
    allowPublicConfusionProbe: isTruthyEnv(env["COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE"]),
  };
}

class BoundedSemaphore {
  private active = 0;
  private readonly queue: Array<{
    resolve: () => void;
    reject: (err: Error) => void;
    signal?: AbortSignal;
    onAbort?: () => void;
  }> = [];
  private readonly maxConcurrent: number;
  private readonly maxQueue: number;

  constructor(maxConcurrent = DEFAULT_MAX_CONCURRENT, maxQueue = DEFAULT_MAX_QUEUE) {
    this.maxConcurrent = maxConcurrent;
    this.maxQueue = maxQueue;
  }

  get activeSlots(): number {
    return this.active;
  }

  acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) {
      return Promise.reject(new Error("Operation aborted"));
    }
    if (this.active < this.maxConcurrent) {
      this.active++;
      return Promise.resolve(() => this.release());
    }
    if (this.queue.length >= this.maxQueue) {
      return Promise.reject(new Error("SERVER_BUSY"));
    }
    return new Promise<() => void>((resolveAcquire, rejectAcquire) => {
      const item: {
        resolve: () => void;
        reject: (err: Error) => void;
        signal?: AbortSignal;
        onAbort?: () => void;
      } = {
        resolve: () => resolveAcquire(() => this.release()),
        reject: rejectAcquire,
        signal,
      };
      if (signal) {
        const onAbort = () => {
          const idx = this.queue.indexOf(item);
          if (idx >= 0) {
            this.queue.splice(idx, 1);
            rejectAcquire(new Error("Operation aborted"));
          }
        };
        item.onAbort = onAbort;
        signal.addEventListener("abort", onAbort, { once: true });
      }
      this.queue.push(item);
    });
  }

  private release(): void {
    this.active = Math.max(0, this.active - 1);
    while (this.queue.length > 0 && this.active < this.maxConcurrent) {
      const next = this.queue.shift()!;
      if (next.signal && next.onAbort) {
        next.signal.removeEventListener("abort", next.onAbort);
      }
      if (next.signal?.aborted) continue;
      this.active++;
      next.resolve();
      return;
    }
  }
}

class ParamValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParamValidationError";
  }
}

function assertAllowedKeys(obj: Record<string, unknown>, allowed: readonly string[], toolName: string): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(obj)) {
    if (!allowedSet.has(key)) {
      throw new ParamValidationError(`Unexpected parameter '${key}' for tool '${toolName}'.`);
    }
  }
}

function readOptionalString(
  obj: Record<string, unknown>,
  key: string,
  maxLen: number,
  minLen = 0,
): string | undefined {
  const val = obj[key];
  if (val === undefined) return undefined;
  if (typeof val !== "string") throw new ParamValidationError(`Parameter '${key}' must be a string.`);
  if (val.length < minLen || val.length > maxLen) {
    throw new ParamValidationError(`Parameter '${key}' length must be between ${minLen} and ${maxLen}.`);
  }
  return val;
}

function readRequiredString(obj: Record<string, unknown>, key: string, minLen: number, maxLen: number): string {
  const val = readOptionalString(obj, key, maxLen, minLen);
  if (val === undefined) throw new ParamValidationError(`Missing required string parameter '${key}'.`);
  return val;
}

function readOptionalInt(
  obj: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
): number | undefined {
  const val = obj[key];
  if (val === undefined) return undefined;
  if (typeof val !== "number" || !Number.isInteger(val) || val < min || val > max) {
    throw new ParamValidationError(`Parameter '${key}' must be an integer between ${min} and ${max}.`);
  }
  return val;
}

function readOptionalBool(obj: Record<string, unknown>, key: string): boolean | undefined {
  const val = obj[key];
  if (val === undefined) return undefined;
  if (typeof val !== "boolean") throw new ParamValidationError(`Parameter '${key}' must be a boolean.`);
  return val;
}

function readOptionalEnum<T extends string>(
  obj: Record<string, unknown>,
  key: string,
  allowed: readonly T[],
  fallback: T,
): T {
  const val = obj[key];
  if (val === undefined) return fallback;
  if (typeof val !== "string" || !allowed.includes(val as T)) {
    throw new ParamValidationError(`Parameter '${key}' must be one of: ${allowed.join(", ")}.`);
  }
  return val as T;
}

function truncateText(s: string, maxChars: number): string {
  return s.length <= maxChars ? s : `${s.slice(0, Math.max(0, maxChars - 1))}…`;
}

function fitJsonSummaryWithinBudget(
  buildPayload: (obsLimit: number, unkLimit: number, detailChars: number) => Record<string, unknown>,
  maxBytes = SUMMARY_MAX_BYTES,
): { obj: Record<string, unknown>; text: string } {
  const attempts: Array<[number, number, number]> = [
    [10, 8, 140],
    [6, 5, 110],
    [3, 3, 90],
    [1, 2, 72],
    [0, 1, 60],
  ];
  for (const [oLim, uLim, dChars] of attempts) {
    const obj = buildPayload(oLim, uLim, dChars);
    const text = JSON.stringify(obj);
    if (Buffer.byteLength(text, "utf8") <= maxBytes) {
      return { obj, text };
    }
  }
  const minimal = buildPayload(0, 0, 40);
  return { obj: minimal, text: JSON.stringify(minimal) };
}

function buildInspectSummary(report: PackageInspectionReport, reportId: string): {
  obj: Record<string, unknown>;
  text: string;
} {
  const allObs = report.evidence.flatMap((e) => e.observations);
  const allUnknowns = report.evidence.flatMap((e) => e.unknowns);
  return fitJsonSummaryWithinBudget((obsLim, unkLim, detailChars) => ({
    schema_version: "1",
    report_id: reportId,
    package_name: report.title.package_name,
    version: report.title.version,
    verdict: report.verdict,
    recommended_action: report.recommended_action,
    parity_tier: report.info.parity_tier,
    pinned_execution: {
      command: report.pinned_execution.command,
      exact_version: report.pinned_execution.exact_version,
      tarball_sha512: report.pinned_execution.tarball_sha512,
      caveat: truncateText(report.pinned_execution.caveat, 160),
    },
    top_observations: allObs.slice(0, obsLim).map((o) => ({
      code: o.code,
      severity: o.severity,
      path: truncateText(o.path, 80),
      ...(o.line !== undefined ? { line: o.line } : {}),
      detail: truncateText(o.detail, detailChars),
    })),
    unknowns: allUnknowns.slice(0, unkLim).map((u) => truncateText(u, detailChars)),
    ...(report.local_workspace_compromised
      ? {
          local_workspace_compromised: {
            lockfile_kind: report.local_workspace_compromised.lockfile_kind,
            matched_version: report.local_workspace_compromised.matched_version,
            containment_steps_count: report.local_workspace_compromised.containment_steps.length,
          },
        }
      : {}),
    ...(report.rea_escalation_plan
      ? {
          rea_escalation_plan: {
            required: report.rea_escalation_plan.required,
            rea_available_on_host: report.rea_escalation_plan.rea_available_on_host,
            steps_count: report.rea_escalation_plan.steps.length,
          },
        }
      : {}),
    counts: {
      observations: allObs.length,
      iocs: report.iocs.length,
      unknowns: allUnknowns.length,
      evidence: report.evidence.length,
    },
  }));
}

function buildDiscoverSummary(report: DiscoveryCardList, reportId: string): {
  obj: Record<string, unknown>;
  text: string;
} {
  return fitJsonSummaryWithinBudget((candLim, blkLim, detailChars) => ({
    schema_version: "1",
    report_id: reportId,
    query: truncateText(report.query, 96),
    registry_route: report.registry_route,
    candidates: report.candidates.slice(0, Math.max(candLim, 1)).map((c) => ({
      package_name: c.package_name,
      version: c.version,
      license: c.license,
      verdict_preview: c.verdict_preview,
      squat_warning_count: c.squat_warnings.length,
      summary: truncateText(c.summary, detailChars),
    })),
    blocked_candidates: report.blocked_candidates.slice(0, Math.max(blkLim, 1)).map((b) => ({
      package_name: truncateText(b.package_name, 80),
      reason: truncateText(b.reason, detailChars),
    })),
    unknowns: report.unknowns.slice(0, 4).map((u) => truncateText(u, detailChars)),
    counts: {
      candidates: report.candidates.length,
      blocked: report.blocked_candidates.length,
      unknowns: report.unknowns.length,
    },
  }));
}

function buildAnchorSummary(decision: SafeAnchorDecision, reportId: string): {
  obj: Record<string, unknown>;
  text: string;
} {
  return fitJsonSummaryWithinBudget((altLim, unkLim, detailChars) => ({
    schema_version: "1",
    report_id: reportId,
    package_name: decision.package_name,
    recommended_action: decision.recommended_action,
    compromised_latest: {
      ...(decision.compromised_latest.version ? { version: decision.compromised_latest.version } : {}),
      ...(decision.compromised_latest.patient_zero_sha
        ? { patient_zero_sha: decision.compromised_latest.patient_zero_sha }
        : {}),
      reason: truncateText(decision.compromised_latest.reason, 180),
    },
    ...(decision.safe_anchor
      ? {
          safe_anchor: {
            commit_sha: decision.safe_anchor.commit_sha,
            version: decision.safe_anchor.version,
            pinned_command: decision.safe_anchor.pinned_execution.command,
            residual_advisories_count: decision.safe_anchor.residual_advisories.length,
          },
        }
      : {}),
    alternatives: decision.alternatives.slice(0, Math.max(altLim, 1)).map((a) => ({
      package_name: a.package_name,
      version: a.version,
      verdict: a.verdict,
      reason: truncateText(a.reason, detailChars),
    })),
    unknowns: decision.unknowns.slice(0, unkLim).map((u) => truncateText(u, detailChars)),
    counts: {
      inspected_commits: decision.inspected_commits.length,
      alternatives: decision.alternatives.length,
      evidence: decision.evidence.length,
      unknowns: decision.unknowns.length,
    },
  }));
}

function buildBatchSummary(report: ManifestBatchReport, reportId: string): {
  obj: Record<string, unknown>;
  text: string;
} {
  return fitJsonSummaryWithinBudget(
    (flagLim, unkLim, detailChars) => ({
      schema_version: "1",
      report_id: reportId,
      manifest_path: truncateText(report.manifest_path, 120),
      total_declared: report.total_declared,
      evaluated_count: report.evaluated_count,
      truncated_at_cap: report.truncated_at_cap,
      offline_mode: report.offline_mode,
      summary_counts: report.summary_counts,
      top_flagged: report.flagged.slice(0, flagLim).map((f) => ({
        package_name: truncateText(f.package_name, 72),
        status: f.status,
        route: f.route,
        reason: truncateText(f.reasons[0] ?? "", Math.min(detailChars, 90)),
        ...(f.advisory_ids.length > 0 ? { advisory_ids: f.advisory_ids.slice(0, 3) } : {}),
      })),
      unknowns: report.unknowns.slice(0, Math.min(unkLim, 4)).map((u) => truncateText(u, Math.min(detailChars, 100))),
      counts: {
        flagged: report.flagged.length,
        unknowns: report.unknowns.length,
      },
    }),
    BATCH_SUMMARY_MAX_BYTES,
  );
}

function buildResourceConstraintResult(reportId: string, section: string, totalBytes: number): McpToolCallResult {
  const payload = {
    schema_version: "1",
    resource_constraint: true,
    report_id: reportId,
    section,
    total_bytes: totalBytes,
    max_inline_bytes: FULL_PAYLOAD_HARD_CAP_BYTES,
    next_call: {
      tool: "get_artifact_report",
      arguments: { report_id: reportId, section, offset: 0 },
    },
    message: `Payload (${totalBytes} bytes) exceeds 48 KiB inline cap; page via get_artifact_report.`,
  };
  return {
    content: [{ type: "text", text: JSON.stringify(payload) }],
    structuredContent: payload,
    isError: false,
  };
}

export interface ColdpinMcpServerOptions {
  operatorConfig?: OperatorRuntimeConfig;
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  hijackProcessStdio?: boolean;
  maxConcurrent?: number;
  maxQueue?: number;
  reportStore?: BoundedReportStore;
  hostCapabilities?: HostCapabilities;
}

export class ColdpinMcpServer {
  private readonly operatorConfig: OperatorRuntimeConfig;
  private readonly transport: StdioJsonRpcTransport;
  private readonly cache: SplitPlaneCache;
  private readonly reportStore: BoundedReportStore;
  private readonly semaphore: BoundedSemaphore;

  private state: McpLifecycleState = "UNINITIALIZED";
  private negotiatedProtocol: SupportedProtocolVersion = SUPPORTED_PROTOCOL_VERSIONS[0];
  private clientSupportsRoots = false;
  private clientName: string | undefined;
  private clientRoots: string[] = [];
  private effectiveRoots: string[];
  private hostCapabilitiesPromise: Promise<HostCapabilities> | null = null;
  private readonly inFlightControllers = new Map<string, AbortController>();
  private shutdownComplete = false;

  constructor(opts: ColdpinMcpServerOptions = {}) {
    this.operatorConfig = opts.operatorConfig ?? loadOperatorConfigFromEnv();
    this.effectiveRoots = canonicalizeAuthorizedRoots(this.operatorConfig.allowedRoots);
    this.cache = new SplitPlaneCache(
      this.operatorConfig.cacheDir ? defaultCacheDbPath(this.operatorConfig.cacheDir) : defaultCacheDbPath(),
    );
    this.reportStore = opts.reportStore ?? new BoundedReportStore();
    this.semaphore = new BoundedSemaphore(opts.maxConcurrent, opts.maxQueue);

    if (opts.hostCapabilities) {
      this.hostCapabilitiesPromise = Promise.resolve(opts.hostCapabilities);
    }

    this.transport = new StdioJsonRpcTransport({
      input: opts.input,
      output: opts.output,
      errorOutput: opts.errorOutput,
      hijackProcessStdio: opts.hijackProcessStdio ?? false,
      onMessage: (raw) => this.handleIncomingMessage(raw),
      onParseError: (msg) => {
        if (this.operatorConfig.verbose) {
          this.transport.writeStderrLog({ stage: "parse_error", message: msg });
        }
      },
      onClose: () => {
        void this.shutdown();
      },
    });
  }

  start(): void {
    // Warm host capability probe asynchronously at startup (never blocks event loop)
    if (!this.hostCapabilitiesPromise) {
      this.hostCapabilitiesPromise = probeHostCapabilitiesAsync();
    }
    this.transport.start();
  }

  async shutdown(): Promise<void> {
    if (this.shutdownComplete) return;
    this.shutdownComplete = true;
    this.state = "SHUTTING_DOWN";
    for (const ctrl of this.inFlightControllers.values()) {
      ctrl.abort();
    }
    this.inFlightControllers.clear();
    cleanupActiveGitTempDirs();
    try {
      await this.transport.flush();
    } catch {
      // Ignore flush error during shutdown
    }
    try {
      this.cache.close();
    } catch {
      // Ignore already-closed cache
    }
  }

  private recomputeEffectiveRoots(): void {
    const opRoots = canonicalizeAuthorizedRoots(this.operatorConfig.allowedRoots);
    if (opRoots.length > 0) {
      this.effectiveRoots =
        this.clientRoots.length > 0 ? intersectAuthorizedRoots(this.clientRoots, opRoots) : opRoots;
    } else if (this.clientRoots.length > 0) {
      this.effectiveRoots = canonicalizeAuthorizedRoots(this.clientRoots);
    } else {
      this.effectiveRoots = [];
    }
  }

  private async syncClientRoots(): Promise<void> {
    if (!this.clientSupportsRoots || this.state === "SHUTTING_DOWN") return;
    try {
      const res = (await this.transport.sendClientRequest("roots/list", {}, 3000)) as {
        roots?: Array<{ uri?: string }>;
      } | null;
      const parsedPaths: string[] = [];
      for (const r of res?.roots ?? []) {
        if (typeof r?.uri === "string") {
          const fsPath = parseFileUriToPath(r.uri);
          if (fsPath) parsedPaths.push(fsPath);
        }
      }
      this.clientRoots = parsedPaths;
      this.recomputeEffectiveRoots();
    } catch (err) {
      if (this.operatorConfig.verbose) {
        this.transport.writeStderrLog({
          stage: "roots_sync_fallback",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  private async buildWorkflowContext(requestId: string, signal?: AbortSignal): Promise<WorkflowContext> {
    const hostCaps = await (this.hostCapabilitiesPromise ?? probeHostCapabilitiesAsync());
    const primaryRoot = this.effectiveRoots[0];
    const { policy, policy_sha256 } = loadMcpPolicy({
      explicitPolicyPath: this.operatorConfig.policyPath,
      workspaceRoot: primaryRoot,
      trustWorkspacePolicy: this.operatorConfig.trustWorkspacePolicy,
      forceOffline: this.operatorConfig.forceOffline,
    });
    const npmrc = loadNpmrc(primaryRoot ?? process.cwd(), {
      includeWorkspaceRegistries: this.operatorConfig.trustWorkspacePolicy,
    });
    return {
      cwd: primaryRoot,
      workspaceRoots: this.effectiveRoots,
      enforceRootConfinement: true,
      policy,
      policy_sha256,
      npmrc,
      host_capabilities: hostCaps,
      cache: this.cache,
      auditLogPath: this.operatorConfig.auditLogPath,
      invokerSurface: "mcp",
      mcpClientName: this.clientName,
      requestId,
      signal,
      onTelemetry: this.operatorConfig.verbose
        ? (ev) => this.transport.writeStderrLog({ ...ev, active_slots: this.semaphore.activeSlots })
        : undefined,
    };
  }

  async dispatchJsonRpc(raw: unknown): Promise<JsonRpcResponse | null> {
    if (!this.hostCapabilitiesPromise) {
      this.hostCapabilitiesPromise = probeHostCapabilitiesAsync();
    }
    let reply: JsonRpcResponse | null = null;
    const captureSink: JsonRpcReplySink = {
      sendResult: async (id: JsonRpcId, result: unknown) => {
        reply = { jsonrpc: "2.0", id, result };
      },
      sendError: async (id: JsonRpcId, code: number, message: string, data?: unknown) => {
        reply = {
          jsonrpc: "2.0",
          id,
          error: data !== undefined ? { code, message, data } : { code, message },
        };
      },
    };
    await this.handleIncomingMessage(raw, captureSink);
    return reply;
  }

  private async handleIncomingMessage(raw: unknown, sink: JsonRpcReplySink = this.transport): Promise<void> {
    // Reject JSON-RPC batch arrays on MCP 2025-06-18 / 2025-11-25 (and pre-init)
    if (Array.isArray(raw)) {
      await sink.sendError(
        null,
        JSONRPC_ERRORS.INVALID_REQUEST,
        `JSON-RPC batch requests are not supported under MCP ${this.negotiatedProtocol}.`,
      );
      return;
    }

    if (raw === null || typeof raw !== "object") {
      await sink.sendError(null, JSONRPC_ERRORS.INVALID_REQUEST, "Invalid JSON-RPC request object.");
      return;
    }

    const msg = raw as Partial<JsonRpcRequest>;
    const hasId = Object.prototype.hasOwnProperty.call(msg, "id");
    const id: JsonRpcId = hasId ? (msg.id as JsonRpcId) : null;

    if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string" || msg.method.length === 0) {
      if (hasId) {
        await sink.sendError(id, JSONRPC_ERRORS.INVALID_REQUEST, "Invalid JSON-RPC 2.0 envelope.");
      }
      return;
    }

    const method = msg.method;
    const params = msg.params && typeof msg.params === "object" && !Array.isArray(msg.params) ? msg.params : {};

    // Notifications (no id)
    if (!hasId) {
      await this.handleNotification(method, params, sink === this.transport);
      return;
    }

    // Requests (have id)
    if (method === "ping") {
      await sink.sendResult(id, {});
      return;
    }

    if (method === "initialize") {
      await this.handleInitialize(id, params, sink);
      return;
    }

    if (this.state === "UNINITIALIZED") {
      await sink.sendError(
        id,
        JSONRPC_ERRORS.NOT_INITIALIZED,
        "Server not initialized; send 'initialize' first.",
      );
      return;
    }

    // Legacy client compatibility: transition INITIALIZING -> ACTIVE without blocking on roots/list
    if (this.state === "INITIALIZING") {
      this.state = "ACTIVE";
    }

    if (this.state === "SHUTTING_DOWN") {
      await sink.sendError(id, JSONRPC_ERRORS.SERVER_BUSY, "Server is shutting down.");
      return;
    }

    if (method === "tools/list") {
      await sink.sendResult(id, { tools: MCP_TOOLS });
      return;
    }

    if (method === "resources/list") {
      await sink.sendResult(id, { resources: MCP_RESOURCES });
      return;
    }

    if (method === "resources/templates/list") {
      await sink.sendResult(id, { resourceTemplates: MCP_RESOURCE_TEMPLATES });
      return;
    }

    if (method === "resources/read") {
      await this.handleResourceRead(id, params, sink);
      return;
    }

    if (method === "prompts/list") {
      await sink.sendResult(id, { prompts: MCP_PROMPTS });
      return;
    }

    if (method === "prompts/get") {
      await this.handlePromptGet(id, params, sink);
      return;
    }

    if (method === "tools/call") {
      await this.handleToolCall(id, params, sink);
      return;
    }

    await sink.sendError(id, JSONRPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${method}`);
  }

  private async handleNotification(method: string, params: Record<string, unknown>, supportsBidirectionalRoots = true): Promise<void> {
    if (method === "notifications/initialized") {
      if (this.state === "INITIALIZING") {
        if (supportsBidirectionalRoots) {
          this.state = "ROOTS_SYNCING";
          await this.syncClientRoots();
          if (this.state === "ROOTS_SYNCING") this.state = "ACTIVE";
        } else {
          this.state = "ACTIVE";
        }
      }
      return;
    }
    if (method === "notifications/roots/list_changed") {
      if (this.state === "ACTIVE" && supportsBidirectionalRoots) {
        await this.syncClientRoots();
      }
      return;
    }
    if (method === "notifications/cancelled") {
      const targetId = params["requestId"];
      if (targetId !== undefined && targetId !== null) {
        const ctrl = this.inFlightControllers.get(String(targetId));
        if (ctrl) ctrl.abort();
      }
    }
  }

  private async handleInitialize(id: JsonRpcId, params: Record<string, unknown>, sink: JsonRpcReplySink = this.transport): Promise<void> {
    const requested = typeof params["protocolVersion"] === "string" ? params["protocolVersion"] : "";
    const matched = SUPPORTED_PROTOCOL_VERSIONS.find((v) => v === requested);
    this.negotiatedProtocol = matched ?? SUPPORTED_PROTOCOL_VERSIONS[0];

    const clientCaps =
      params["capabilities"] && typeof params["capabilities"] === "object"
        ? (params["capabilities"] as Record<string, unknown>)
        : {};
    this.clientSupportsRoots = Boolean(clientCaps["roots"]);
    const clientExtensions =
      clientCaps["extensions"] && typeof clientCaps["extensions"] === "object"
        ? (clientCaps["extensions"] as Record<string, unknown>)
        : {};
    const clientSupportsUi = Boolean(clientExtensions["io.modelcontextprotocol/ui"]);

    const clientInfo =
      params["clientInfo"] && typeof params["clientInfo"] === "object"
        ? (params["clientInfo"] as Record<string, unknown>)
        : {};
    if (typeof clientInfo["name"] === "string" && clientInfo["name"].trim().length > 0) {
      this.clientName = clientInfo["name"].trim().slice(0, 64);
    }

    this.state = "INITIALIZING";
    await sink.sendResult(id, {
      protocolVersion: this.negotiatedProtocol,
      capabilities: {
        tools: { listChanged: false },
        resources: { subscribe: false, listChanged: false },
        prompts: { listChanged: false },
        ...(clientSupportsUi
          ? {
              extensions: {
                "io.modelcontextprotocol/ui": {
                  mimeTypes: [EVIDENCE_CARD_UI_MIME],
                },
              },
            }
          : {}),
      },
      serverInfo: {
        name: "coldpin",
        version: ENGINE_VERSION,
      },
    });
  }

  private async handleResourceRead(id: JsonRpcId, params: Record<string, unknown>, sink: JsonRpcReplySink = this.transport): Promise<void> {
    const uri = typeof params["uri"] === "string" ? params["uri"] : "";
    if (!uri) {
      await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, "Missing required resource 'uri'.");
      return;
    }

    if (uri === EVIDENCE_CARD_UI_URI) {
      await sink.sendResult(id, {
        contents: [
          {
            uri,
            mimeType: EVIDENCE_CARD_UI_MIME,
            text: renderEvidenceCardAppHtml(),
            _meta: EVIDENCE_CARD_UI_META,
          },
        ],
      });
      return;
    }

    if (uri === "coldpin://policy/active") {
      const ctx = await this.buildWorkflowContext(`res_${randomUUID().slice(0, 12)}`);
      const sanitized = {
        schema_version: "1",
        engine_version: ENGINE_VERSION,
        policy_sha256: ctx.policy_sha256,
        allowed_roots_count: this.effectiveRoots.length,
        trust_workspace_policy: this.operatorConfig.trustWorkspacePolicy,
        allow_public_confusion_probe: this.operatorConfig.allowPublicConfusionProbe,
        audit_logging_enabled: Boolean(this.operatorConfig.auditLogPath),
        host_capabilities: ctx.host_capabilities,
        policy: {
          private_scopes: ctx.policy.private_scopes,
          private_prefixes: ctx.policy.private_prefixes,
          private_registry_scopes: Object.keys(ctx.policy.private_registries),
          default_registry: ctx.policy.default_registry,
          osv_api_url: ctx.policy.osv_api_url,
          allow_public_fallback: ctx.policy.allow_public_fallback,
          allowed_orgs: ctx.policy.allowed_orgs,
          denied_orgs: ctx.policy.denied_orgs,
          blocked_licenses: ctx.policy.blocked_licenses,
          cooldown_hours: ctx.policy.cooldown_hours,
          max_compressed_bytes: ctx.policy.max_compressed_bytes,
          max_uncompressed_bytes: ctx.policy.max_uncompressed_bytes,
          max_files: ctx.policy.max_files,
          max_single_file_bytes: ctx.policy.max_single_file_bytes,
          block_on_kev: ctx.policy.block_on_kev,
          block_on_critical_cve: ctx.policy.block_on_critical_cve,
          block_on_high_cve: ctx.policy.block_on_high_cve,
          require_provenance: ctx.policy.require_provenance,
          require_source_link: ctx.policy.require_source_link,
          bisect_max_commits: ctx.policy.bisect_max_commits,
          bisect_max_days: ctx.policy.bisect_max_days,
          offline_mode: ctx.policy.offline_mode,
        },
      };
      await sink.sendResult(id, {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(sanitized, null, 2),
          },
        ],
      });
      return;
    }

    const rptMatch = /^coldpin:\/\/reports\/(rpt_[a-f0-9-]{4,48})$/.exec(uri);
    if (rptMatch?.[1]) {
      const reportId = rptMatch[1];
      const stored = this.reportStore.get(reportId);
      if (!stored) {
        await sink.sendError(
          id,
          JSONRPC_ERRORS.INVALID_PARAMS,
          `Session report '${reportId}' not found or expired.`,
        );
        return;
      }
      const summary =
        stored.kind === "inspect"
          ? buildInspectSummary(stored.report, reportId).text
          : stored.kind === "discover"
            ? buildDiscoverSummary(stored.report, reportId).text
            : stored.kind === "batch"
              ? buildBatchSummary(stored.report, reportId).text
              : buildAnchorSummary(stored.decision, reportId).text;
      await sink.sendResult(id, {
        contents: [{ uri, mimeType: "application/json", text: summary }],
      });
      return;
    }

    await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, `Unknown resource URI: ${uri}`);
  }

  private async handlePromptGet(id: JsonRpcId, params: Record<string, unknown>, sink: JsonRpcReplySink = this.transport): Promise<void> {
    const name = typeof params["name"] === "string" ? params["name"] : "";
    const args =
      params["arguments"] && typeof params["arguments"] === "object" && !Array.isArray(params["arguments"])
        ? (params["arguments"] as Record<string, unknown>)
        : {};

    if (name === "vet_before_npx") {
      const pkgSpec = typeof args["package_spec"] === "string" ? args["package_spec"].trim() : "";
      if (!pkgSpec || pkgSpec.length > 256) {
        await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, "Prompt 'vet_before_npx' requires 'package_spec'.");
        return;
      }
      const gitDir = typeof args["git_dir"] === "string" ? args["git_dir"].trim() : "";
      const text = gitDir
        ? `Run Coldpin tool 'inspect_package_artifact' with package_spec="${pkgSpec}" and git_dir="${gitDir}" (detail="summary"). Present the deterministic verdict, parity tier, unknowns, and only propose the pinned npx command if verdict is VERIFIED_CLEAN_WITHIN_SCOPE and the human explicitly approves execution.`
        : `Run Coldpin tool 'inspect_package_artifact' with package_spec="${pkgSpec}" (detail="summary"). Present the deterministic verdict, parity tier, unknowns, and only propose the pinned npx command if verdict is VERIFIED_CLEAN_WITHIN_SCOPE and the human explicitly approves execution.`;
      await sink.sendResult(id, {
        description: "Vet an npm package cold before running npx.",
        messages: [{ role: "user", content: { type: "text", text } }],
      });
      return;
    }

    if (name === "investigate_compromised_org") {
      const pkgName = typeof args["package_name"] === "string" ? args["package_name"].trim() : "";
      if (!pkgName || pkgName.length > 214) {
        await sink.sendError(
          id,
          JSONRPC_ERRORS.INVALID_PARAMS,
          "Prompt 'investigate_compromised_org' requires 'package_name'.",
        );
        return;
      }
      const repoUrl = typeof args["repo_url"] === "string" ? args["repo_url"].trim() : "";
      const text = repoUrl
        ? `Run Coldpin tool 'resolve_safe_anchor' with package_name="${pkgName}" and repo_url="${repoUrl}" (detail="summary"). Report patient-zero commit SHA, safe pre-compromise version or vetted alternatives, and any residual advisories or unknowns.`
        : `Run Coldpin tool 'resolve_safe_anchor' with package_name="${pkgName}" (detail="summary"). Report patient-zero commit SHA, safe pre-compromise version or vetted alternatives, and any residual advisories or unknowns.`;
      await sink.sendResult(id, {
        description: "Locate patient-zero commit and safe rollback anchor or vetted alternative.",
        messages: [{ role: "user", content: { type: "text", text } }],
      });
      return;
    }

    await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, `Unknown prompt: ${name}`);
  }

  private async handleToolCall(id: JsonRpcId, params: Record<string, unknown>, sink: JsonRpcReplySink = this.transport): Promise<void> {
    const toolName = typeof params["name"] === "string" ? params["name"] : "";
    const rawArgs = params["arguments"] ?? {};
    if (!toolName || rawArgs === null || typeof rawArgs !== "object" || Array.isArray(rawArgs)) {
      await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, "Invalid tools/call parameters.");
      return;
    }
    const args = rawArgs as Record<string, unknown>;
    const knownTool = MCP_TOOLS.some((t) => t.name === toolName);
    if (!knownTool) {
      await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, `Unknown tool: ${toolName}`);
      return;
    }

    // Validate parameters synchronously BEFORE acquiring semaphore slot so bad schemas never consume slots
    try {
      this.validateToolArguments(toolName, args);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Invalid tool arguments";
      await sink.sendError(id, JSONRPC_ERRORS.INVALID_PARAMS, msg);
      return;
    }

    const startMs = Date.now();
    const rpcKey = String(id);
    const controller = new AbortController();
    this.inFlightControllers.set(rpcKey, controller);

    let release: (() => void) | null = null;
    try {
      release = await this.semaphore.acquire(controller.signal);
    } catch (err) {
      this.inFlightControllers.delete(rpcKey);
      const errMsg = err instanceof Error ? err.message : String(err);
      if (errMsg === "SERVER_BUSY") {
        await sink.sendError(
          id,
          JSONRPC_ERRORS.SERVER_BUSY,
          "Coldpin MCP server concurrency queue saturated; retry shortly.",
        );
      } else {
        await sink.sendResult(id, {
          content: [{ type: "text", text: "Request cancelled before execution." }],
          isError: true,
        });
      }
      return;
    }

    const requestId = `mcp_${randomUUID().slice(0, 12)}`;
    try {
      const result = await this.executeTool(toolName, args, requestId, controller.signal);
      if (this.operatorConfig.verbose) {
        this.transport.writeStderrLog({
          request_id: requestId,
          rpc_id: id,
          tool: toolName,
          duration_ms: Date.now() - startMs,
          active_slots: this.semaphore.activeSlots,
          is_error: result.isError,
        });
      }
      await sink.sendResult(id, result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (this.operatorConfig.verbose) {
        this.transport.writeStderrLog({
          request_id: requestId,
          rpc_id: id,
          tool: toolName,
          duration_ms: Date.now() - startMs,
          active_slots: this.semaphore.activeSlots,
          error_code: "TOOL_EXEC_ERROR",
        });
      }
      await sink.sendResult(id, {
        content: [{ type: "text", text: `Operational error executing '${toolName}': ${msg}` }],
        isError: true,
      });
    } finally {
      this.inFlightControllers.delete(rpcKey);
      if (release) release();
    }
  }

  private validateToolArguments(toolName: string, args: Record<string, unknown>): void {
    if (toolName === "discover_packages") {
      assertAllowedKeys(args, ["query", "org", "creator", "category", "limit", "detail"], toolName);
      const query = readRequiredString(args, "query", 1, 128);
      const org = readOptionalString(args, "org", 64);
      const creator = readOptionalString(args, "creator", 64);
      const category = readOptionalString(args, "category", 64);
      readOptionalInt(args, "limit", 1, 25);
      readOptionalEnum(args, "detail", ["summary", "full"] as const, "summary");
      // Security [MCP-04]: reject credential/secret-like strings across all 4 discovery arguments with -32602
      for (const [k, v] of [
        ["query", query],
        ["org", org],
        ["creator", creator],
        ["category", category],
      ] as const) {
        if (v && hasSecretLikeDiscoveryToken(v)) {
          throw new ParamValidationError(`Parameter '${k}' contains credential-shaped or secret-like material.`);
        }
      }
      return;
    }

    if (toolName === "inspect_package_artifact") {
      assertAllowedKeys(
        args,
        ["package_spec", "tarball_path", "git_dir", "subdir", "offline", "detail", "format"],
        toolName,
      );
      const pkgSpec = readOptionalString(args, "package_spec", 256, 1);
      const tarballPath = readOptionalString(args, "tarball_path", 1024, 1);
      if (Boolean(pkgSpec) === Boolean(tarballPath)) {
        throw new ParamValidationError("Specify exactly one of 'package_spec' or 'tarball_path' (XOR).");
      }
      readOptionalString(args, "git_dir", 1024, 1);
      readOptionalString(args, "subdir", 256);
      readOptionalBool(args, "offline");
      readOptionalEnum(args, "detail", ["summary", "card", "full"] as const, "summary");
      readOptionalEnum(args, "format", ["json", "card", "sarif", "sbom"] as const, "json");
      return;
    }

    if (toolName === "resolve_safe_anchor") {
      assertAllowedKeys(args, ["package_name", "git_dir", "repo_url", "subdir", "window", "detail"], toolName);
      readRequiredString(args, "package_name", 1, 214);
      readOptionalString(args, "git_dir", 1024, 1);
      readOptionalString(args, "repo_url", 256, 1);
      readOptionalString(args, "subdir", 256);
      readOptionalInt(args, "window", 1, 200);
      readOptionalEnum(args, "detail", ["summary", "full"] as const, "summary");
      return;
    }

    if (toolName === "verify_confusion") {
      assertAllowedKeys(args, ["manifest_path", "check_public"], toolName);
      readOptionalString(args, "manifest_path", 1024, 1);
      readOptionalBool(args, "check_public");
      return;
    }

    if (toolName === "audit_verify") {
      assertAllowedKeys(args, ["audit_log_path"], toolName);
      readRequiredString(args, "audit_log_path", 1, 1024);
      return;
    }

    if (toolName === "audit_manifest_batch") {
      assertAllowedKeys(args, ["manifest_path", "include_dev", "max_deps", "offline", "detail"], toolName);
      readOptionalString(args, "manifest_path", 1024, 1);
      readOptionalBool(args, "include_dev");
      readOptionalInt(args, "max_deps", 1, 50);
      readOptionalBool(args, "offline");
      readOptionalEnum(args, "detail", ["summary", "full"] as const, "summary");
      return;
    }

    if (toolName === "get_artifact_report") {
      assertAllowedKeys(args, ["report_id", "section", "offset", "limit"], toolName);
      readRequiredString(args, "report_id", 4, 64);
      readOptionalEnum(
        args,
        "section",
        ["observations", "iocs", "unknowns", "commits", "card", "sarif", "sbom"] as const,
        "observations",
      );
      if (args["section"] === undefined) {
        throw new ParamValidationError("Missing required parameter 'section'.");
      }
      readOptionalInt(args, "offset", 0, 10_000_000);
      readOptionalInt(args, "limit", 1, 50);
    }
  }

  private async executeTool(
    toolName: string,
    args: Record<string, unknown>,
    requestId: string,
    signal: AbortSignal,
  ): Promise<McpToolCallResult> {
    if (toolName === "get_artifact_report") {
      return this.executeGetArtifactReport(args);
    }

    const ctx = await this.buildWorkflowContext(requestId, signal);

    if (toolName === "discover_packages") {
      const detail = readOptionalEnum(args, "detail", ["summary", "full"] as const, "summary");
      const res = await runDiscover(ctx, {
        query: args["query"] as string,
        org: args["org"] as string | undefined,
        creator: args["creator"] as string | undefined,
        category: args["category"] as string | undefined,
        limit: (args["limit"] as number | undefined) ?? 10,
      });
      const reportId = this.reportStore.put({ kind: "discover", report: res.report });
      if (detail === "summary") {
        const { obj, text } = buildDiscoverSummary(res.report, reportId);
        return { content: [{ type: "text", text }], structuredContent: obj, isError: false };
      }
      const fullObj = { ...res.report, report_id: reportId };
      const fullText = JSON.stringify(fullObj);
      if (Buffer.byteLength(fullText, "utf8") > FULL_PAYLOAD_HARD_CAP_BYTES) {
        return buildResourceConstraintResult(reportId, "unknowns", Buffer.byteLength(fullText, "utf8"));
      }
      return { content: [{ type: "text", text: fullText }], structuredContent: fullObj, isError: false };
    }

    if (toolName === "inspect_package_artifact") {
      const detail = readOptionalEnum(args, "detail", ["summary", "card", "full"] as const, "summary");
      const format = readOptionalEnum(args, "format", ["json", "card", "sarif", "sbom"] as const, "json");
      const res = await runInspect(ctx, {
        packageSpec: args["package_spec"] as string | undefined,
        tarballPath: args["tarball_path"] as string | undefined,
        localGitDir: args["git_dir"] as string | undefined,
        subdir: args["subdir"] as string | undefined,
        offline: args["offline"] as boolean | undefined,
      });
      if (!res.ok) {
        if (!res.isOperationalError) {
          const blockedPayload = {
            schema_version: "1",
            verdict: "MALICIOUS_INDICATORS_FOUND",
            recommended_action: "BLOCK_NO_SAFE_PATH",
            reason: res.error,
          };
          return {
            content: [{ type: "text", text: JSON.stringify(blockedPayload) }],
            structuredContent: blockedPayload,
            isError: false,
          };
        }
        return { content: [{ type: "text", text: res.error }], isError: true };
      }

      const reportId = this.reportStore.put({
        kind: "inspect",
        report: res.report,
        dependencies: res.dependencies,
      });

      if (format === "card" || detail === "card") {
        const card = formatInspectionMarkdownCard(res.report);
        const bytes = Buffer.byteLength(card, "utf8");
        if (bytes > FULL_PAYLOAD_HARD_CAP_BYTES) {
          return buildResourceConstraintResult(reportId, "card", bytes);
        }
        return {
          content: [{ type: "text", text: card }],
          structuredContent: {
            report_id: reportId,
            verdict: res.report.verdict,
            recommended_action: res.report.recommended_action,
            format: "card",
          },
          isError: false,
        };
      }

      if (format === "sarif") {
        const sarifText = JSON.stringify(formatSarif210(res.report));
        const bytes = Buffer.byteLength(sarifText, "utf8");
        if (bytes > FULL_PAYLOAD_HARD_CAP_BYTES) {
          return buildResourceConstraintResult(reportId, "sarif", bytes);
        }
        return {
          content: [{ type: "text", text: sarifText }],
          structuredContent: { report_id: reportId, format: "sarif", bytes },
          isError: false,
        };
      }

      if (format === "sbom") {
        const sbomText = JSON.stringify(formatCycloneDxSbom(res.report, res.dependencies));
        const bytes = Buffer.byteLength(sbomText, "utf8");
        if (bytes > FULL_PAYLOAD_HARD_CAP_BYTES) {
          return buildResourceConstraintResult(reportId, "sbom", bytes);
        }
        return {
          content: [{ type: "text", text: sbomText }],
          structuredContent: { report_id: reportId, format: "sbom", bytes },
          isError: false,
        };
      }

      if (detail === "full") {
        const fullObj = { ...res.report, report_id: reportId };
        const fullText = JSON.stringify(fullObj);
        const bytes = Buffer.byteLength(fullText, "utf8");
        if (bytes > FULL_PAYLOAD_HARD_CAP_BYTES) {
          return buildResourceConstraintResult(reportId, "observations", bytes);
        }
        return { content: [{ type: "text", text: fullText }], structuredContent: fullObj, isError: false };
      }

      const { obj, text } = buildInspectSummary(res.report, reportId);
      return { content: [{ type: "text", text }], structuredContent: obj, isError: false };
    }

    if (toolName === "resolve_safe_anchor") {
      const detail = readOptionalEnum(args, "detail", ["summary", "full"] as const, "summary");
      const res = await runResolveAnchor(ctx, {
        packageName: args["package_name"] as string,
        localGitDir: args["git_dir"] as string | undefined,
        repoUrl: args["repo_url"] as string | undefined,
        subdir: args["subdir"] as string | undefined,
        window: args["window"] as number | undefined,
      });
      if (!res.ok) {
        if (!res.isOperationalError) {
          const blockedPayload = {
            schema_version: "1",
            recommended_action: "BLOCK_NO_SAFE_PATH",
            reason: res.error,
          };
          return {
            content: [{ type: "text", text: JSON.stringify(blockedPayload) }],
            structuredContent: blockedPayload,
            isError: false,
          };
        }
        return { content: [{ type: "text", text: res.error }], isError: true };
      }

      const reportId = this.reportStore.put({ kind: "anchor", decision: res.decision });
      if (detail === "full") {
        const fullObj = { ...res.decision, report_id: reportId };
        const fullText = JSON.stringify(fullObj);
        const bytes = Buffer.byteLength(fullText, "utf8");
        if (bytes > FULL_PAYLOAD_HARD_CAP_BYTES) {
          return buildResourceConstraintResult(reportId, "commits", bytes);
        }
        return { content: [{ type: "text", text: fullText }], structuredContent: fullObj, isError: false };
      }

      const { obj, text } = buildAnchorSummary(res.decision, reportId);
      return { content: [{ type: "text", text }], structuredContent: obj, isError: false };
    }

    if (toolName === "verify_confusion") {
      const res = await runVerifyConfusion(ctx, {
        manifestPath: args["manifest_path"] as string | undefined,
        checkPublic: args["check_public"] as boolean | undefined,
        allowPublicProbe: this.operatorConfig.allowPublicConfusionProbe,
      });
      if (!res.ok) {
        return { content: [{ type: "text", text: res.error }], isError: true };
      }
      const payload = res.report as unknown as Record<string, unknown>;
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
        structuredContent: payload,
        isError: false,
      };
    }

    if (toolName === "audit_verify") {
      const res = await runAuditVerify(ctx, {
        auditLogPath: args["audit_log_path"] as string,
      });
      if (!res.ok) {
        return { content: [{ type: "text", text: res.error }], isError: true };
      }
      // Valid OR tampered audit chains are deterministic security verdicts (isError: false)
      const payload = res.result as unknown as Record<string, unknown>;
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
        structuredContent: payload,
        isError: false,
      };
    }

    if (toolName === "audit_manifest_batch") {
      const detail = readOptionalEnum(args, "detail", ["summary", "full"] as const, "summary");
      const res = await runAuditManifestBatch(ctx, {
        manifestPath: args["manifest_path"] as string | undefined,
        includeDev: args["include_dev"] as boolean | undefined,
        maxDeps: args["max_deps"] as number | undefined,
        offline: args["offline"] as boolean | undefined,
      });
      if (!res.ok) {
        return { content: [{ type: "text", text: res.error }], isError: true };
      }
      const reportId = this.reportStore.put({ kind: "batch", report: res.report });
      if (detail === "full") {
        const fullObj = { ...res.report, report_id: reportId };
        const fullText = JSON.stringify(fullObj);
        const bytes = Buffer.byteLength(fullText, "utf8");
        if (bytes > FULL_PAYLOAD_HARD_CAP_BYTES) {
          return buildResourceConstraintResult(reportId, "observations", bytes);
        }
        return { content: [{ type: "text", text: fullText }], structuredContent: fullObj, isError: false };
      }
      const { obj, text } = buildBatchSummary(res.report, reportId);
      return { content: [{ type: "text", text }], structuredContent: obj, isError: false };
    }

    return { content: [{ type: "text", text: `Unhandled tool: ${toolName}` }], isError: true };
  }

  private executeGetArtifactReport(args: Record<string, unknown>): McpToolCallResult {
    const reportId = args["report_id"] as string;
    const section = args["section"] as "observations" | "iocs" | "unknowns" | "commits" | "card" | "sarif" | "sbom";
    const offset = (args["offset"] as number | undefined) ?? 0;
    const limit = (args["limit"] as number | undefined) ?? 20;

    const stored = this.reportStore.get(reportId);
    if (!stored) {
      return {
        content: [{ type: "text", text: `Report '${reportId}' not found or expired in session store.` }],
        isError: true,
      };
    }

    if (section === "card" || section === "sarif" || section === "sbom") {
      if (stored.kind !== "inspect") {
        return {
          content: [{ type: "text", text: `Section '${section}' is only available for inspection reports.` }],
          isError: true,
        };
      }
      const fullText =
        section === "card"
          ? formatInspectionMarkdownCard(stored.report)
          : section === "sarif"
            ? JSON.stringify(formatSarif210(stored.report))
            : JSON.stringify(formatCycloneDxSbom(stored.report, stored.dependencies));
      const sliced = sliceUtf8Safe(fullText, offset, REPORT_TEXT_CHUNK_MAX_BYTES);
      const payload = { report_id: reportId, section, ...sliced };
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
        structuredContent: payload,
        isError: false,
      };
    }

    let items: unknown[] = [];
    if (section === "observations") {
      if (stored.kind === "inspect") items = stored.report.evidence.flatMap((e) => e.observations);
      else if (stored.kind === "discover") items = stored.report.candidates;
      else if (stored.kind === "batch") items = stored.report.flagged;
      else items = stored.decision.evidence;
    } else if (section === "iocs") {
      items = stored.kind === "inspect" ? stored.report.iocs : [];
    } else if (section === "unknowns") {
      if (stored.kind === "inspect") items = stored.report.evidence.flatMap((e) => e.unknowns);
      else if (stored.kind === "discover") items = stored.report.unknowns;
      else if (stored.kind === "batch") items = stored.report.unknowns;
      else items = stored.decision.unknowns;
    } else if (section === "commits") {
      items = stored.kind === "anchor" ? stored.decision.inspected_commits : [];
    }

    const slice = items.slice(offset, offset + limit);
    const nextOffset = offset + slice.length < items.length ? offset + slice.length : null;
    const payload = {
      report_id: reportId,
      section,
      offset,
      limit,
      total: items.length,
      next_offset: nextOffset,
      items: slice,
    };
    return {
      content: [{ type: "text", text: JSON.stringify(payload) }],
      structuredContent: payload,
      isError: false,
    };
  }
}

export async function startMcpServerFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const server = new ColdpinMcpServer({
    operatorConfig: loadOperatorConfigFromEnv(env),
    hijackProcessStdio: true,
  });

  const onSignal = (): void => {
    void server.shutdown().finally(() => {
      process.exit(0);
    });
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  return new Promise<number>((resolveExit) => {
    process.stdin.once("close", () => {
      void server.shutdown().finally(() => {
        process.off("SIGINT", onSignal);
        process.off("SIGTERM", onSignal);
        resolveExit(0);
      });
    });
    server.start();
  });
}
