export type PillarId =
  | "get-started"
  | "plugin-guardrails"
  | "mcp-cli"
  | "enterprise-security"
  | "verification-releases";

export type SurfaceId = "antigravity" | "npm-cli" | "mcp-hosts" | "enterprise-http";

export interface PillarMeta {
  readonly id: PillarId;
  readonly label: string;
  readonly shortLabel: string;
  readonly entrySlug: string;
}

export type InlineSegment =
  | string
  | { readonly code: string }
  | { readonly strong: string | readonly InlineSegment[] }
  | { readonly kbd: string }
  | { readonly link: string; readonly href: string; readonly external?: boolean };

export type DocBlock =
  | { readonly kind: "p"; readonly text: readonly InlineSegment[]; readonly muted?: boolean }
  | { readonly kind: "ul"; readonly items: readonly (readonly InlineSegment[])[] }
  | {
      readonly kind: "callout";
      readonly tone: "note" | "tip" | "caution" | "danger";
      readonly title: string;
      readonly body: readonly InlineSegment[];
    }
  | {
      readonly kind: "code";
      readonly id: string;
      readonly label: string;
      readonly lang: "sh" | "json" | "yaml" | "text";
      readonly code: string;
    }
  | {
      readonly kind: "steps";
      readonly items: ReadonlyArray<{
        readonly title: string;
        readonly body: readonly InlineSegment[];
        readonly code?: {
          readonly id: string;
          readonly label: string;
          readonly lang: "sh" | "json" | "yaml" | "text";
          readonly code: string;
        };
      }>;
    }
  | {
      readonly kind: "table";
      readonly id: string;
      readonly caption?: string;
      readonly switchable?: boolean;
      readonly headers: readonly string[];
      readonly nowrapCols?: readonly number[];
      readonly rows: readonly (readonly (readonly InlineSegment[])[])[];
    }
  | {
      readonly kind: "ledger";
      readonly rows: ReadonlyArray<{
        readonly term: string;
        readonly count: string;
        readonly paragraphs: readonly (readonly InlineSegment[])[];
      }>;
    }
  | {
      readonly kind: "tabs";
      readonly id: string;
      readonly ariaLabel: string;
      readonly tabs: ReadonlyArray<{
        readonly id: string;
        readonly label: string;
        readonly blocks: readonly DocBlock[];
      }>;
    }
  | {
      readonly kind: "details";
      readonly id?: string;
      readonly variant: "faq" | "release";
      readonly expandAllId?: string;
      readonly items: ReadonlyArray<{
        readonly id?: string;
        readonly summary: string;
        readonly badge?: string;
        readonly open?: boolean;
        readonly blocks: readonly DocBlock[];
      }>;
    }
  | {
      readonly kind: "prompt-composer";
      readonly id: string;
      readonly slashCommand: string;
      readonly title: string;
      readonly description: string;
      readonly prompt: string;
      readonly badges: readonly string[];
    }
  | {
      readonly kind: "resource-cards";
      readonly cards: ReadonlyArray<{
        readonly pillar: string;
        readonly title: string;
        readonly description: string;
        readonly href: string;
      }>;
    }
  | { readonly kind: "surface-selector" }
  | { readonly kind: "policy-lab-hook" }
  | { readonly kind: "policy-lab-verdict" }
  | {
      readonly kind: "spec-strip";
      readonly ariaLabel: string;
      readonly items: ReadonlyArray<{ readonly label: string; readonly value: string }>;
    };

export interface DocSection {
  readonly id: string;
  readonly title: string;
  readonly level?: 2 | 3;
  readonly surface?: SurfaceId;
  readonly blocks: readonly DocBlock[];
}

export interface DocPage {
  readonly slug: string;
  readonly isRoot?: boolean;
  readonly pillar: PillarId;
  readonly title: string;
  readonly shortTitle: string;
  readonly heroTitle?: string;
  readonly description: string;
  readonly lead: readonly InlineSegment[];
  readonly surfaces: readonly string[];
  readonly keywords: readonly string[];
  readonly heroCtas?: ReadonlyArray<{
    readonly label: string;
    readonly href: string;
    readonly primary?: boolean;
    readonly external?: boolean;
  }>;
  readonly heroSpecStrip?: ReadonlyArray<{ readonly label: string; readonly value: string }>;
  readonly sections: readonly DocSection[];
}

export interface RepoMetrics {
  readonly version: string;
  readonly description: string;
  readonly license: string;
  readonly repoUrl: string;
  readonly npmUrl: string;
  readonly releaseUrl: string;
  readonly mcpToolsCount: number;
  readonly mcpResourcesCount: number;
  readonly mcpTemplatesCount: number;
  readonly mcpPromptsCount: number;
  readonly mcpEstimatedTokens: number;
  readonly mcpToolsListChars: number;
  readonly mcpCatalogSha256: string;
  readonly agentsMdBytes: number;
  readonly compiledEsmCount: number;
  readonly skillAttestedFiles: number;
  readonly pluginAttestedFiles: number;
  readonly coreTestCount: number;
  readonly mutationCount: number;
  readonly corpusFixtures: number;
  readonly selfAuditRisk: number;
  readonly selfAuditBlocking: number;
  readonly selfAuditVerdict: string;
  readonly lastBuildDate: string;
  readonly sha256Sums: string;
  readonly hooksJsonText: string;
  readonly mcpConfigText: string;
  readonly privateRegistryConfigText: string;
  readonly httpRemoteConfigText: string;
  readonly weeklySidecarConfigText: string;
  readonly changelogReleases: ReadonlyArray<{
    readonly version: string;
    readonly date: string;
    readonly groups: ReadonlyArray<{
      readonly heading: string;
      readonly items: readonly string[];
    }>;
  }>;
}

export interface SearchIndexRecord {
  readonly id: string;
  readonly slug: string;
  readonly href: string;
  readonly title: string;
  readonly pageTitle: string;
  readonly pillar: PillarId;
  readonly pillarLabel: string;
  readonly snippet: string;
  readonly keywords: string;
  readonly surfaces: readonly string[];
}
