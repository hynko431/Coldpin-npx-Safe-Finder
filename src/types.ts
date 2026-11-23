export const ENGINE_VERSION = "1.6.0";
export const CACHE_SCHEMA_VERSION = "3";

export type TrustVerdict =
  | "VERIFIED_CLEAN_WITHIN_SCOPE"
  | "QUARANTINE_SUSPICIOUS"
  | "MALICIOUS_INDICATORS_FOUND"
  | "UNVERIFIABLE_UNKNOWN";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type RecommendedAction =
  | "USE_PINNED_LATEST"
  | "ROLLBACK_TO_SAFE_ANCHOR"
  | "FORENSIC_COMMIT_ONLY"
  | "SWITCH_TO_ALTERNATIVE"
  | "BLOCK_NO_SAFE_PATH";

export type ProvenanceStatus =
  | "none"
  | "metadata_url_only"
  | "dsse_leaf_verified_unanchored"
  | "sigstore_verified"
  | "verification_failed";

export type ParityTier =
  | "PROVENANCE_ATTESTED"
  | "PROVENANCE_UNANCHORED_DSSE"
  | "PROVENANCE_METADATA_UNVERIFIED"
  | "MANIFEST_PARITY_VERIFIED"
  | "COMPILED_DIST_UNATTESTED"
  | "TARBALL_SOURCE_DRIFT"
  | "SOURCE_UNLINKED";

export type ExitCode = 0 | 1 | 2 | 3;

export interface PolicyConfig {
  private_scopes: string[];
  private_prefixes: string[];
  private_registries: Record<string, string>;
  default_registry: string;
  osv_api_url: string;
  allow_public_fallback: boolean;
  allowed_orgs: string[];
  denied_orgs: string[];
  blocked_licenses: string[];
  cooldown_hours: number;
  max_compressed_bytes: number;
  max_uncompressed_bytes: number;
  max_files: number;
  max_single_file_bytes: number;
  block_on_kev: boolean;
  block_on_critical_cve: boolean;
  block_on_high_cve: boolean;
  require_provenance: boolean;
  require_source_link: boolean;
  bisect_max_commits: number;
  bisect_max_days: number;
  intel_ttl_seconds: number;
  offline_mode: boolean;
}

export interface Observation {
  code: string;
  severity: Severity;
  path: string;
  line?: number;
  digest_sha256?: string;
  attack_id?: string;
  atlas_id?: string;
  detail: string;
}

export interface DefangedIoc {
  kind: "url" | "domain" | "ip" | "sha256" | "sha512";
  value: string;
  tlp: "TLP:CLEAR" | "TLP:AMBER";
  confidence: "high" | "medium" | "low";
  source_path: string;
}

export interface EvidenceRecord {
  evidence_id: string;
  source:
    | "tier0_intel"
    | "tier1_unpack"
    | "tier1_static"
    | "tier1_parity"
    | "tier2_rea"
    | "tier3_bisect";
  artifact_sha512?: string;
  commit_sha?: string;
  observations: Observation[];
  inferences: string[];
  unknowns: string[];
  coverage: {
    files_inspected: number;
    files_skipped: number;
    rea_invoked: boolean;
    transitive_checked: boolean;
  };
}

export interface TarEntry {
  path: string;
  size: number;
  sha256: string;
  content: Buffer;
}

export interface UnpackResult {
  ok: boolean;
  tarball_sha512: string;
  compressed_bytes: number;
  uncompressed_bytes: number;
  entries: TarEntry[];
  observations: Observation[];
  unknowns: string[];
  halted_by_cap: boolean;
}

export interface PackageManifest {
  name?: string;
  version?: string;
  description?: string;
  license?: string | { type?: string };
  author?: string | { name?: string };
  bin?: string | Record<string, string>;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  keywords?: string[];
  repository?: string | { type?: string; url?: string; directory?: string };
  gitHead?: string;
}

export interface TriageResult {
  ruleset_sha256: string;
  manifest: PackageManifest | null;
  observations: Observation[];
  inferences: string[];
  unknowns: string[];
  iocs: DefangedIoc[];
  has_obfuscation: boolean;
  has_native_or_wasm: boolean;
  rea_recommended: boolean;
  files_inspected: number;
  files_skipped: number;
}

export interface AdvisoryRecord {
  id: string;
  is_malicious: boolean;
  severity: Severity;
  kev: boolean;
  epss?: number;
  summary: string;
  package_name: string;
  affected_version?: string;
}

export interface ParityResult {
  tier: ParityTier;
  git_head?: string;
  repository_url?: string;
  provenance_attested: boolean;
  provenance_status?: ProvenanceStatus;
  provenance_url?: string;
  observations: Observation[];
  unknowns: string[];
}

export interface PinnedExecutionInfo {
  command: string | null;
  exact_version?: string;
  tarball_sha512?: string;
  bin_name?: string;
  caveat: string;
}

export interface ReaEscalationStep {
  path: string;
  signal: string;
  recommended_tool: string;
  rationale: string;
}

export interface ReaEscalationPlan {
  required: boolean;
  rea_available_on_host: boolean;
  bootstrap_prohibition: string;
  steps: ReaEscalationStep[];
}

export interface PackageInspectionReport {
  schema_version: string;
  generated_at_utc: string;
  title: {
    package_name: string;
    version: string;
    org_or_scope: string;
    creator: string;
    category_tags: string[];
    commit_sha?: string;
  };
  info: {
    summary: string;
    license: string;
    published_at?: string;
    weekly_downloads?: number;
    has_bin: boolean;
    bin_names: string[];
    lifecycle_scripts: string[];
    direct_dependency_count: number;
    parity_tier: ParityTier;
    provenance_attested: boolean;
    provenance_status: ProvenanceStatus;
    provenance_url?: string;
  };
  verdict: TrustVerdict;
  recommended_action: RecommendedAction;
  pinned_execution: PinnedExecutionInfo;
  advisories: AdvisoryRecord[];
  evidence: EvidenceRecord[];
  iocs: DefangedIoc[];
  rea_escalation_plan?: ReaEscalationPlan;
  local_workspace_compromised?: {
    lockfile_path: string;
    lockfile_kind?: "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock";
    matched_version: string;
    containment_steps: string[];
  };
  host_capabilities: HostCapabilities;
}

export interface DiscoveryCandidate {
  package_name: string;
  version: string;
  org_or_scope: string;
  creator: string;
  summary: string;
  license: string;
  keywords: string[];
  published_at?: string;
  weekly_downloads?: number;
  squat_warnings: Observation[];
  policy_blocked_reason?: string;
  verdict_preview: TrustVerdict;
}

export interface DiscoveryCardList {
  schema_version: string;
  query: string;
  filters: {
    org?: string;
    creator?: string;
    category?: string;
  };
  registry_route: "private" | "public";
  candidates: DiscoveryCandidate[];
  blocked_candidates: Array<{ package_name: string; reason: string }>;
  unknowns: string[];
}

export interface CommitAuditSummary {
  commit_sha: string;
  committed_at_utc: string;
  subject: string;
  verdict: TrustVerdict;
  changed_blobs: number;
  cache_hits: number;
  observations_count: number;
}

export interface SafeAnchorDecision {
  schema_version: string;
  package_name: string;
  compromised_latest: {
    version?: string;
    commit_sha?: string;
    patient_zero_sha?: string;
    reason: string;
  };
  recommended_action: RecommendedAction;
  safe_anchor?: {
    version?: string;
    commit_sha?: string;
    tarball_sha512?: string;
    provenance_attested: boolean;
    provenance_status?: ProvenanceStatus;
    pinned_execution: PinnedExecutionInfo;
    residual_advisories: AdvisoryRecord[];
  };
  alternatives: Array<{
    package_name: string;
    version: string;
    org_or_scope: string;
    verdict: TrustVerdict;
    pinned_command: string | null;
    reason: string;
  }>;
  inspected_commits: CommitAuditSummary[];
  evidence: EvidenceRecord[];
  unknowns: string[];
}

export interface ConfusionFinding {
  package_name: string;
  declared_range: string;
  issue: "UNPINNED_PRIVATE_SCOPE" | "UNSCOPED_PRIVATE_PREFIX" | "CLAIMABLE_ON_PUBLIC_NPM" | "PUBLIC_SHADOW_EXISTS";
  severity: Severity;
  detail: string;
  remediation: string;
}

export interface ConfusionReport {
  schema_version: string;
  manifest_path: string;
  npmrc_paths: string[];
  findings: ConfusionFinding[];
  passed: boolean;
  unknowns: string[];
}

export interface BatchDependencyFinding {
  package_name: string;
  declared_range: string;
  route: "private" | "public" | "blocked_typo" | "blocked_unconfigured" | "blocked_secret";
  status: "CLEAN_SCREENED" | "FLAGGED_SUSPICIOUS" | "MALICIOUS_OR_BLOCKED" | "UNVERIFIABLE_OFFLINE";
  reasons: string[];
  advisory_ids: string[];
}

export interface ManifestBatchReport {
  schema_version: string;
  manifest_path: string;
  total_declared: number;
  evaluated_count: number;
  truncated_at_cap: boolean;
  offline_mode: boolean;
  summary_counts: {
    clean_screened: number;
    flagged_suspicious: number;
    malicious_or_blocked: number;
    unverifiable_offline: number;
  };
  flagged: BatchDependencyFinding[];
  unknowns: string[];
}

export interface AuditEvent {
  seq: number;
  ts_utc: string;
  request_id?: string;
  invoker_surface?: "cli" | "mcp";
  mcp_client_name?: string;
  tool_name?: string;
  actor_id_hash: string;
  action: "discover" | "inspect" | "resolve-anchor" | "verify-confusion" | "audit-manifest-batch";
  target: string;
  version?: string;
  commit_sha?: string;
  tarball_sha512?: string;
  verdict: string;
  policy_sha256: string;
  evidence_ids: string[];
  override_ticket_id?: string;
  prev_hash: string;
  entry_hash: string;
}

export interface HostCapabilities {
  node_version: string;
  git_available: boolean;
  git_partial_clone_supported: boolean;
  rea_cli_available: boolean;
  rea_cli_command?: string;
  sqlite_available: boolean;
}
