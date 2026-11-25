# <a href="https://coldpin-docs.pages.dev/"><img src="assets/icon.svg" width="36" height="36" alt="Coldpin documentation portal" align="absmiddle"></a> Coldpin

Inspect `npx` packages cold in memory. Pin clean releases with verifiable evidence.

[Quickstart](#quickstart) · [Install](#install) · [CLI and MCP Reference](#cli-and-mcp-reference) · [Architecture](#architecture) · [Security and Limits](#security-and-limits) · [Documentation](https://coldpin-docs.pages.dev/) · [Policy Lab](https://coldpin-docs.pages.dev/docs/policy-lab/) · [llms.txt](https://coldpin-docs.pages.dev/llms.txt)

<p>
  <a href="https://npmjs.com/package/coldpin"><img height="20" src="https://img.shields.io/npm/v/coldpin?logo=npm&logoColor=white&color=0f766e&label=npm" alt="npm version" /></a>
  <a href="https://npmjs.com/package/coldpin"><img height="20" src="https://img.shields.io/npm/dw/coldpin?logo=npm&logoColor=white&color=0f766e&label=npmjs%20downloads" alt="npmjs weekly downloads" /></a>
  <a href="LICENSE"><img height="20" src="https://img.shields.io/npm/l/coldpin?color=0f766e&label=license" alt="Apache-2.0 license" /></a>
  <a href="https://github.com/hynko431/Coldpin-npx-Safe-Finder/actions/workflows/ci.yml"><img height="20" src="https://img.shields.io/github/actions/workflow/status/hynko431/Coldpin-npx-Safe-Finder/ci.yml?branch=main&label=CI" alt="CI status" /></a>
  <a href="https://mcprush.com/to/coldpin-mcp?ref=badge">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://mcprush.com/badge/coldpin-mcp/score.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://mcprush.com/badge/coldpin-mcp/score.svg?theme=light" />
      <img height="20" src="https://mcprush.com/badge/coldpin-mcp/score.svg?theme=light" alt="Coldpin MCP trust score on MCPRush" />
    </picture>
  </a>
  <a href="https://m8ven.ai/mcp/hynko431-coldpin-npx-safe-finder-yksxpp?s=readme"><img height="20" src="https://m8ven.ai/badge/mcp/hynko431-coldpin-npx-safe-finder-yksxpp?v=646b36986a4cb8051eb18e5681fbf13f&variant=verified" alt="M8ven Score" /></a>
</p>

<p>
  <a href="https://npmjs.com/package/coldpin">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://coldpin-docs.pages.dev/badge/npm-card.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=light" />
      <img width="380" height="200" src="https://coldpin-docs.pages.dev/badge/npm-card.svg?theme=light" alt="Coldpin official npmjs.com package card" />
    </picture>
  </a>
  <a href="https://mcprush.com/to/coldpin-mcp?ref=badge">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://mcprush.com/badge/coldpin-mcp/card.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://mcprush.com/badge/coldpin-mcp/card.svg?theme=light" />
      <img width="380" height="200" src="https://mcprush.com/badge/coldpin-mcp/card.svg?theme=light" alt="Coldpin MCP server listing on MCPRush" />
    </picture>
  </a>
</p>

*Both download counts originate from the official [npmjs.com](https://npmjs.com/package/coldpin) registry (`api.npmjs.org`, measuring tarball GETs); MCPRush polls npm on a ~24h lag and serves zero hosted proxy traffic.*

## Why Coldpin

**Coldpin** (`coldpin`) is a zero-dependency Node.js 24 CLI, local-first JSON-RPC 2.0 `stdio` MCP server (`lib/mcp.mjs`), and multi-harness AI agent plugin for vetting npm and `npx` packages before anything runs on your host.

| Supply-Chain Threat | Coldpin Control |
| --- | --- |
| Floating `npx -y` & install hooks (`preinstall`/`postinstall`) | Downloads tarballs over HTTPS, verifies SHA-512 integrity, unpacks strictly in memory with zero execution, and emits exact-pinned `--ignore-scripts` commands. |
| Credential theft, obfuscation & typosquats (`T1195.002`) | Linear-time JS/TS lexical taint analysis, hidden-Unicode checks, 7 typosquat/slopsquat mutation primitives, and route-isolated OSV/OpenSSF `MAL-*` + CISA KEV checks. |
| Tarball-only compromises & source drift | 3-tier tarball-to-Git parity plus `--first-parent` patient-zero commit bisection (`resolve-anchor`) recovering a verified pre-compromise release or clean alternative. |
| Dependency confusion & private-scope leaks (`T1195.001`) | Workspace `package.json` + `.npmrc` audits (`verify-confusion`) with strict non-leakage routing and fuzzy private-scope typo blocking (`blocked_typo`). |
| Indirect prompt injection in package metadata (`AML.T0051`) | Treats `README.md`, descriptions, and comments strictly as untrusted data; fails closed on uninspected native/WASM artifacts (`UNVERIFIABLE_UNKNOWN`). |

## Quickstart

Run a zero-execution cold inspection directly from your terminal (Node.js `>= 24.0.0`, zero runtime dependencies):

```sh
npx --ignore-scripts coldpin@1.6.1 inspect semver@7.7.1
```

*(From a local clone with zero `npm install`, run `node --no-warnings lib/cli.mjs inspect semver@7.7.1`.)*

Sample `Title + Info + Evidence` output:

```markdown
# Title: `semver@7.7.1`
- Verdict: `VERIFIED_CLEAN_WITHIN_SCOPE` | Recommended Action: `USE_PINNED_LATEST`
- Commit SHA: `30c438bb46c74f319aa8783f96d233ebf5f4a90d`

## Info
- License: `ISC` | Direct Dependencies: 0 | Binaries: `semver` | Lifecycle Hooks: none
- Tarball Parity Tier: `PROVENANCE_UNANCHORED_DSSE` | Verified SHA-512: `sha512-hlq8tAfn...`

## Safe Execution Command
npx --yes --ignore-scripts --package=semver@7.7.1 -- semver
> Caveat: Stock npx pins top-level version and disables install scripts, but cannot
> enforce SHA-512 integrity or transitive lockfiles at runtime.

## Evidence Summary
- Evidence IDs: `ev_t0_hlq8tAfn0m/6`, `ev_t1_unpack_hlq8tAfn0m/6`, `ev_t1_static_3ffa52570aa1`, `ev_t1_parity_30c438bb46c7`
- Observations: No malicious or suspicious static indicators observed within inspected scope.
```

### Verdict and Exit-Code Contract

| Verdict | Exit Code | Meaning |
| --- | :---: | --- |
| `VERIFIED_CLEAN_WITHIN_SCOPE` | `0` | No malicious, suspicious, policy-violating, or uninspected-binary indicators observed within inspected static scope. |
| `QUARANTINE_SUSPICIOUS` | `2` | Suspicious static indicators, obfuscation, archive anomalies, or policy warnings require review before execution. |
| `UNVERIFIABLE_UNKNOWN` | `2` | Fail-closed result: offline threat intel unavailable, uninspected native/WASM binary present, or strict provenance unverified. |
| `MALICIOUS_INDICATORS_FOUND` | `3` | High-confidence malicious taint, `MAL-*` advisory, archive attack, or workspace compromise indicators detected; runnable command suppressed. |
| Runtime / Input Error | `1` | Invalid CLI usage, missing target, or unrecoverable local I/O error. |

## Install

Choose your coding agent, MCP client, or standalone CLI. Coldpin maintains one canonical source tree with reproducible host bundles (`coldpin-{antigravity,claude,openai}.zip` + `SHA256SUMS.txt` on [GitHub Releases](https://github.com/hynko431/Coldpin-npx-Safe-Finder/releases)).

| Target | Entrypoint / Manifest | Install Path | Details |
| --- | --- | --- | --- |
| **Standalone CLI & Local MCP** | `lib/cli.mjs`, `lib/mcp.mjs` (`Node >= 24`) | `npx --ignore-scripts coldpin@1.6.1 mcp` or `git clone` | [Getting Started](docs/getting_started.md) |
| **Antigravity (`>= v1.5.13`)** | `plugin.json`, `mcp_config.json`, `hooks.json`, `rules/`, `agents/`, `skills/` | `agy plugin install ./coldpin-antigravity` | [Harnesses](docs/harnesses.md#antigravity-app-and-antigravity-for-ides) |
| **Claude Code** | `.claude-plugin/plugin.json`, `skills/coldpin/` | `python scripts/pack_plugin.py --target claude --verify` | [Harnesses](docs/harnesses.md) |
| **Codex CLI / ChatGPT Desktop** | `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json` | `python scripts/pack_plugin.py --target openai --verify` | [Harnesses](docs/harnesses.md) |
| **Official MCP Registry / Cursor** | `server.json` (`io.github.hynko431/coldpin`) | `npx --ignore-scripts coldpin@1.6.1 mcp` | [Harnesses](docs/harnesses.md) |
| **OCI Container (GHCR)** | `Dockerfile` (`ghcr.io/hynko431/coldpin`) | `docker run --rm ghcr.io/hynko431/coldpin:latest inspect semver@7.7.1` | [Testing](TESTING.md) |

<details>
<summary>Standalone CLI &amp; Local MCP Server (from source or npm)</summary>

```sh
git clone https://github.com/hynko431/Coldpin-npx-Safe-Finder.git
cd Coldpin-npx-Safe-Finder
node --no-warnings lib/cli.mjs --help
node --no-warnings lib/mcp.mjs        # Start local stdio MCP server (or: coldpin mcp)
```

Or run via npm without global install: `npx --ignore-scripts coldpin@1.6.1 mcp`.

</details>

<details>
<summary>Antigravity Plugin Bundle (CLI, Workspace, App &amp; IDEs)</summary>

Ships all 5 native primitives (`rules/`: 3 Markdown rules, `agents/`: 7 strictly read-only aspect agents, `skills/`: 3 skills including `/coldpin-audit` and `/coldpin-incident`, `hooks.json`: 3 default-enabled fail-safe `PreToolUse` groups, and `mcp_config.json`: local zero-variable `stdio` with 7 eager tools and `${PLUGIN_DATA}` cache isolation):

```sh
python scripts/pack_plugin.py --target antigravity --verify
python -m zipfile -e dist/coldpin-antigravity.zip ./coldpin-antigravity
agy plugin install ./coldpin-antigravity
agy --agent coldpin-auditor
```

For workspace-scoped discovery inside this repository, run `python scripts/pack_plugin.py --verify --sync-workspace`. For manual installation into `~/.gemini/config/plugins/coldpin/`, see [Harnesses](docs/harnesses.md#antigravity-app-and-antigravity-for-ides).

</details>

<details>
<summary>Claude Code, Codex CLI &amp; Official MCP Registry</summary>

Build host-specific reproducible archives from this single source tree (no forked skill prose):

```sh
python scripts/pack_plugin.py --target all --verify
```

See [Harnesses](docs/harnesses.md) for `mcp_config.json`, `server.json`, `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`, and marketplace catalog setup.

</details>

## CLI and MCP Reference

Invoke any workflow directly from the terminal or through Coldpin's 7 local `stdio` MCP tools:

| CLI Verb | MCP Tool | Exit Codes | Purpose |
| --- | --- | :---: | --- |
| `discover` | `discover_packages` | `0 / 2 / 1` | Search npm tools by query, org, creator, or category with typosquat, cooldown, and org-policy screening. |
| `inspect` | `inspect_package_artifact` | `0 / 2 / 3 / 1` | Vet a package or offline `.tgz` in memory without execution and emit Card, JSON, SARIF 2.1.0, or CycloneDX 1.5 SBOM. |
| `resolve-anchor` | `resolve_safe_anchor` | `0 / 2 / 3 / 1` | Pinpoint the patient-zero commit, check cached full-tree blobs + CVE/KEV gates, and emit `ROLLBACK_TO_SAFE_ANCHOR`, `FORENSIC_COMMIT_ONLY`, or `SWITCH_TO_ALTERNATIVE`. |
| `verify-confusion` | `verify_confusion` | `0 / 3 / 1` | Audit `package.json` and `.npmrc` for unpinned private scopes and claimable internal names (`T1195.001`). |
| `audit-batch` | `audit_manifest_batch` | `0 / 2 / 3 / 1` | Batch-screen up to 50 direct dependencies in `package.json` (squat, policy, route-isolated OSV/`MAL-*`/KEV) with `<= 500`-token MCP summaries. |
| `audit-verify` | `audit_verify` | `0 / 3 / 1` | Verify local hash-chained `audit.jsonl` sequence and digest integrity. |
| `mcp` | `get_artifact_report` | `0 / 1` | Serve the local `stdio` MCP server and page session-scoped inspection reports without SQLite verdict caching. |

Common command recipes:

```sh
# 1. Discover npx tools safely
node --no-warnings lib/cli.mjs discover "json formatter" --category cli --limit 10

# 2. Inspect a package or offline tarball (+ SARIF 2.1.0 / CycloneDX 1.5 SBOM)
node --no-warnings lib/cli.mjs inspect semver@7.7.1
node --no-warnings lib/cli.mjs inspect --tarball ./pkg.tgz --git-dir ./repo --offline --sarif

# 3. Recover a clean pre-compromise commit/release anchor
node --no-warnings lib/cli.mjs resolve-anchor @org/tool --git-dir ./repo --window 200

# 4. Batch-screen package.json, audit dependency confusion & verify audit trail
node --no-warnings lib/cli.mjs audit-batch ./package.json --limit 50
node --no-warnings lib/cli.mjs verify-confusion ./package.json
node --no-warnings lib/cli.mjs audit-verify ./audit.jsonl
```

## Architecture

| Layer | Trust Boundary | Responsibility |
| --- | --- | --- |
| **Deterministic CLI & Local MCP (`lib/`)** | Zero execution; in-memory archive parsing; `stdio`-only (`0` listening sockets); operator-only control plane | Computes 4-state verdict, SHA-512 verification, lexical taint, 3-tier parity, defanged IOCs, SARIF 2.1.0, CycloneDX 1.5 SBOM, and summary-first MCP paging. |
| **Native Guardrails (`rules/`, `agents/`, `hooks.json`)** | Read-only aspect subagents (`commandExecutionPolicy: "off"`); fail-safe ES2020 `PreToolUse` hook (exit `0`, zero auto-approval) | Routes 6 security aspects across isolated subagents, blocks unvetted/evasive `npx` runners, and forces confirmation on pinned runs, config edits, and writable `define_subagent` calls. |
| **Agent Skills (`skills/`)** | Untrusted package prose isolated as data; fails closed on unknowns | Orchestrates the 7 MCP tools / 6 CLI verbs with 5 modular aspect playbooks plus Antigravity `/coldpin-audit` and `/coldpin-incident` workflows. |
| **You (Human Gate)** | Explicit human approval before any host execution | Reviews observations, inferences, unknowns, and transitive caveats before running any pinned command. |

### Optional Enterprise Extensions (`v1.6+`)

All enterprise extensions are strictly opt-in and preserve **$0/mo** maintainer cost and default local `stdio` zero-socket posture:

- **Private Registry Overlay:** Copy [examples/mcp_config.private-registry.example.json](examples/mcp_config.private-registry.example.json) as an opt-in Antigravity `variables` overlay for scoped private registries.
- **Self-Hosted Streamable HTTP MCP Adapter (`lib/mcp-http.mjs` / `coldpin-mcp-http`):** Opt-in remote MCP (`2025-11-25`) for VPCs or Cloud Run with OAuth 2.1 CIMD / `RS256`+`ES256` JWKS / RFC 9728 / RFC 8707 `aud`, constant-time SHA-256 `cpk_live_*` API keys, anti-DNS-rebinding `Host`/`Origin` guards, and per-principal rate limits ([examples/mcp_config.http-remote.example.json](examples/mcp_config.http-remote.example.json)).
- **Inline MCP App Evidence Cards (`ui://coldpin/evidence-card.html`):** Zero-dependency SEP-1865 (`io.modelcontextprotocol/ui`, Antigravity `>= v2.34.0`) inline evidence card with default-deny CSP (`csp: {}`), zero `innerHTML`, and copy-only command controls.
- **Disabled-by-Default Weekly Audit Sidecar:** Read-only scheduled scan template ([examples/sidecar.weekly-audit.example.json](examples/sidecar.weekly-audit.example.json)) restricted to `audit_manifest_batch`, `verify_confusion`, and `get_artifact_report`. See [Harnesses](docs/harnesses.md#optional-enterprise-extensions-v16-phase-e).

## Security and Limits

Measured deterministic Tier 1–2 results from [BENCHMARK.md](skills/coldpin/BENCHMARK.md) and [SkillSpector Self-Audit](docs/verification/skill-inspector-self-audit.md):

| Dimension | Measured Tier 1–2 Result | Tier 3 Live Multi-Agent Uplift |
| --- | --- | --- |
| Adversarial Recall (`49`-fixture corpus) | `100.0%` (`28/28` adversarial & fail-closed fixtures caught) | `N/A` (not run offline) |
| False-Positive Rate | `0.0%` (`0/21` benign CLIs misclassified; target `< 5%`) | `N/A` (not run offline) |
| Mutation Proofs & Trigger Proxy | `38/38` regressions caught red · `10/10` selection (`5` pos + `5` decoys) | `N/A` (not run offline) |
| Tier-1 Latency & Self-Audit | Benign p50 `4.01 ms`, p95 `12.43 ms` · `SS-03`–`SS-18` `APPROVE` (`16/100`, `0` blocking) | `N/A` (not run offline) |

Explicit operational boundaries:

- **Static scope is not proof of zero malware:** `VERIFIED_CLEAN_WITHIN_SCOPE` means no malicious, suspicious, or policy-violating indicators were observed within inspected static scope; it cannot guarantee absence of remote dynamic payloads or time-bombed triggers.
- **Stock `npx` runtime caveat:** `npx --ignore-scripts` pins the top-level version and disables install scripts, but stock `npx` cannot enforce SHA-512 integrity or lock floating transitive dependencies at runtime; use a private caching proxy or shrinkwrapped install for regulated builds.
- **Fail-closed on native/obfuscated artifacts:** Compiled `.node`/WASM/ELF/PE/Mach-O binaries and heavily obfuscated bundles return `UNVERIFIABLE_UNKNOWN` or `QUARANTINE_SUSPICIOUS` and point to pre-installed Tier-2 inspection (`rea` / `rea-agents`) or sandboxed review without ever auto-downloading analyzers via `npx`.

## Documentation

- [Documentation Portal (Cloudflare Pages)](https://coldpin-docs.pages.dev/): 5-pillar / 17-page zero-dependency docs site with raw `.md` twins, [`/llms.txt`](https://coldpin-docs.pages.dev/llms.txt), the [Interactive Policy Lab](https://coldpin-docs.pages.dev/docs/policy-lab/) (compiled from `src/hook-core.ts` alongside the live SEP-1865 MCP App preview), and a [GitHub Pages mirror](https://hynko431.github.io/Coldpin-npx-Safe-Finder/). Regenerate via `npm run build:docs`.
- [Getting started](docs/getting_started.md): end-to-end workflows, policy setup, MCP env vars, and offline usage.
- [Harnesses](docs/harnesses.md): Antigravity, Claude Code, Codex CLI, Official MCP Registry (`server.json`), and Phase E optional enterprise extensions.
- [Privacy & data handling](docs/privacy.md): exact network egress, private-scope non-leakage, and credential boundaries.
- [FAQ](docs/faq.md): trade-offs, false-positive controls, stock `npx` limits, and REA optionality.
- [Design specification](docs/designs/coldpin.md) & [Design sitemap](docs/designs/SITEMAP.md): locked architecture and design records.
- [Testing & verification](TESTING.md): 15-gate verification pipeline, cross-platform CI matrix, SkillSpector self-audit (`SS-03`–`SS-18`), and reproducible builds.
- [Benchmarks](skills/coldpin/BENCHMARK.md) & [Skill Card](skills/coldpin/skill-card.md): real executed Tier 1–2 measurements and honest Tier 3 status.
- [Fact Ledger](docs/fact-ledger.md), [Maintenance Cadence](MAINTENANCE.md), & [Changelog](CHANGELOG.md).

## Contributing, Security and Accessibility

- Read [SECURITY.md](SECURITY.md) for security boundaries and responsible vulnerability disclosure.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for zero-dependency rules, Detection-as-Code requirements, and pre-PR gates.
- See [ACCESSIBILITY.md](ACCESSIBILITY.md) for CLI/card accessibility practices and known harness limits.

## License

[Apache 2.0](LICENSE). *Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
