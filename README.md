# <a href="https://coldpin-docs.pages.dev/"><img src="assets/icon.svg" width="36" height="36" alt="Coldpin documentation portal" align="absmiddle"></a> Coldpin

Inspect `npx` packages cold in memory. Pin clean releases with verifiable evidence.

[Install](#install) · [Quickstart](#try-your-first-audit) · [Documentation](https://coldpin-docs.pages.dev/) · [Getting Started](docs/getting_started.md) · [Benchmarks](skills/coldpin/BENCHMARK.md)

<a href="https://mcprush.com/to/coldpin-mcp?ref=badge">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://mcprush.com/badge/coldpin-mcp/score.svg" />
    <source media="(prefers-color-scheme: light)" srcset="https://mcprush.com/badge/coldpin-mcp/score.svg?theme=light" />
    <img height="20" src="https://mcprush.com/badge/coldpin-mcp/score.svg?theme=light" alt="Coldpin MCP on mcprush" />
  </picture>
</a>

Discover `npx` CLI packages by capability, category, creator, or organization without executing untrusted install scripts. **Coldpin** (`coldpin`) is a zero-dependency Node.js 24 CLI, local-first JSON-RPC 2.0 `stdio` MCP server (`lib/mcp.mjs`), and multi-harness AI agent plugin.

**Deterministic CLI & Local MCP Server** fetch tarballs over HTTPS, verify SHA-512 integrity, unpack strictly in memory, run linear-time JS/TS lexical taint and hidden-Unicode triage, check OSV/OpenSSF `MAL-*` advisories, and validate 3-tier tarball-to-Git parity. **Safe-Anchor Resolver** walks release history and cached Git commits (`--first-parent`) to isolate the patient-zero commit and recover a verified pre-compromise release or vetted alternative. **You** review the `Title + Info + Evidence` card and decide whether to run any command.

<a href="https://mcprush.com/to/coldpin-mcp?ref=badge">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://mcprush.com/badge/coldpin-mcp/card.svg" />
    <source media="(prefers-color-scheme: light)" srcset="https://mcprush.com/badge/coldpin-mcp/card.svg?theme=light" />
    <img width="380" height="200" src="https://mcprush.com/badge/coldpin-mcp/card.svg?theme=light" alt="Coldpin MCP server" />
  </picture>
</a>

## Install

Choose your coding agent, MCP client, or run the CLI standalone.

### Standalone CLI & Local MCP Server (Node.js `>= 24.0.0`, zero runtime dependencies)

```sh
git clone https://github.com/hynko431/Coldpin-npx-Safe-Finder.git
cd Coldpin-npx-Safe-Finder
node --no-warnings lib/cli.mjs --help
node --no-warnings lib/mcp.mjs        # Start local stdio MCP server (or: coldpin mcp)
```

Or install via npm (`npx --ignore-scripts coldpin@1.5.2 mcp`) or download a checksum-verified host bundle (`coldpin-{antigravity,claude,openai}.zip` + `SHA256SUMS.txt`) from [GitHub Releases](https://github.com/hynko431/Coldpin-npx-Safe-Finder/releases).

### Antigravity (CLI / Workspace / App / IDEs — requires `agy >= v1.5.13`)

Build (or download from [GitHub Releases](https://github.com/hynko431/Coldpin-npx-Safe-Finder/releases)) the clean allowlisted Antigravity plugin bundle — shipping all 5 native primitives (`rules/`: 3 Markdown rules, `agents/`: 7 strictly read-only aspect agents, `skills/`: 3 skills including `/coldpin-audit` and `/coldpin-incident`, `hooks.json`: 3 default-enabled fail-safe `PreToolUse` groups, and `mcp_config.json`: local zero-variable `stdio` with 7 eager tools and `${PLUGIN_DATA}` cache isolation):

```sh
python scripts/pack_plugin.py --target antigravity --verify
python -m zipfile -e dist/coldpin-antigravity.zip ./coldpin-antigravity
agy plugin install ./coldpin-antigravity
agy --agent coldpin-auditor
```

For enterprise private registries, copy [mcp_config.private-registry.example.json](examples/mcp_config.private-registry.example.json) as an opt-in Antigravity `variables` overlay. For workspace-scoped discovery inside this repository, run `python scripts/pack_plugin.py --verify --sync-workspace` (syncs `.agents/skills/coldpin/`). For manual global installation into `~/.gemini/config/plugins/coldpin/`, see [Harnesses](docs/harnesses.md#antigravity-app-and-antigravity-for-ides).

### Claude Code, Codex CLI & Official MCP Registry

Build host-specific reproducible archives from this single source tree (no forked skill text):

```sh
python scripts/pack_plugin.py --target all --verify
```

See [Harnesses](docs/harnesses.md) for `mcp_config.json`, `server.json` (`io.github.hynko431/coldpin`), `.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`, and marketplace catalog setup.

## Try your first audit

Run any step below directly from your terminal or ask your coding agent to invoke Coldpin's 7 MCP tools (`discover_packages`, `inspect_package_artifact`, `resolve_safe_anchor`, `verify_confusion`, `audit_manifest_batch`, `audit_verify`, `get_artifact_report`).

<img src="skills/coldpin/assets/icon.svg" width="20" height="20" align="top" alt=""> **1. Discover `npx` tools safely**

```sh
node --no-warnings lib/cli.mjs discover "json formatter" --category cli --limit 10
```

Screens candidates against org allow/deny policy, 7 typosquatting/slopsquatting mutation primitives, and release age cooldowns while routing private scopes exclusively to private registries.

<img src="skills/coldpin/assets/icon.svg" width="20" height="20" align="top" alt=""> **2. Inspect a package or offline tarball**

```sh
node --no-warnings lib/cli.mjs inspect semver@7.7.1
node --no-warnings lib/cli.mjs inspect --tarball ./pkg.tgz --git-dir ./repo --offline --sarif
```

Emits a deterministic `Title + Info + Evidence` card (or `--json`, `--sarif`, `--sbom`) with exit code `0` (clean within scope), `2` (suspicious or unknown), or `3` (malicious indicators found).

<img src="skills/coldpin/assets/icon.svg" width="20" height="20" align="top" alt=""> **3. Recover a clean commit/release anchor**

```sh
node --no-warnings lib/cli.mjs resolve-anchor @org/tool --git-dir ./repo --window 200
```

Pinpoints the patient-zero commit, checks cached full-tree blobs across history, verifies CVE/KEV gates, and emits `ROLLBACK_TO_SAFE_ANCHOR` only when a verified npm tarball exists (otherwise `FORENSIC_COMMIT_ONLY` or `SWITCH_TO_ALTERNATIVE`).

<img src="skills/coldpin/assets/icon.svg" width="20" height="20" align="top" alt=""> **4. Batch-screen `package.json`, audit dependency confusion & verify local audit trail**

```sh
node --no-warnings lib/cli.mjs audit-batch ./package.json --limit 50
node --no-warnings lib/cli.mjs verify-confusion ./package.json
node --no-warnings lib/cli.mjs audit-verify ./audit.jsonl
```

## How it works

<table>
  <thead><tr><th align="left">Layer</th><th align="left">Trust Boundary</th><th align="left">Responsibility</th></tr></thead>
  <tbody>
    <tr valign="top"><td><strong>Deterministic CLI &amp; Local MCP (<code>lib/</code>)</strong></td><td>Zero execution; in-memory archive parsing; stdio-only (0 listening sockets); operator-only control plane</td><td>Computes 4-state verdict, SHA-512 verification, AST taint, parity, defanged IOCs, SARIF 2.1.0, CycloneDX 1.5 SBOM, and summary-first MCP paging.</td></tr>
    <tr valign="top"><td><strong>Native Guardrails (<code>rules/</code>, <code>agents/</code>, <code>hooks.json</code>)</strong></td><td>Read-only aspect subagents (<code>commandExecutionPolicy: "off"</code>); fail-safe ES2020 <code>PreToolUse</code> hook (exit <code>0</code>, zero auto-approval)</td><td>Routes 6 security aspects across isolated subagents, blocks unvetted/evasive <code>npx</code> commands, and forces confirmation on pinned runs, config edits, and writable <code>define_subagent</code> requests.</td></tr>
    <tr valign="top"><td><strong>Agent Skills (<code>skills/</code>)</strong></td><td>Untrusted package prose isolated as data; fails closed on unknowns</td><td>Orchestrates the 7 MCP tools / 6 CLI verbs with 5 modular aspect playbooks plus Antigravity <code>/coldpin-audit</code> and <code>/coldpin-incident</code> workflows.</td></tr>
    <tr valign="top"><td><strong>You</strong></td><td>Human approval gate before any host execution</td><td>Review observations, inferences, unknowns, and transitive caveats before running any pinned command.</td></tr>
  </tbody>
</table>

Static triage does not replace runtime isolation or human judgment. See [FAQ](docs/faq.md) and [Benchmarks](skills/coldpin/BENCHMARK.md) for measured detection coverage and explicit unknowns.

## Choose a workflow

<table>
  <thead><tr><th align="left">CLI Verb / MCP Tool</th><th align="left">Exit Codes</th><th align="left">Use it to…</th></tr></thead>
  <tbody>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>discover</code> / <code>discover_packages</code></td><td><code>0 / 2 / 1</code></td><td>Search npm tools by query, org, creator, or category with typosquat and policy filters.</td></tr>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>inspect</code> / <code>inspect_package_artifact</code></td><td><code>0 / 2 / 3 / 1</code></td><td>Vet a package or local <code>.tgz</code> without execution and emit Card, JSON, SARIF 2.1.0, or CycloneDX SBOM.</td></tr>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>resolve-anchor</code> / <code>resolve_safe_anchor</code></td><td><code>0 / 2 / 3 / 1</code></td><td>Find patient-zero commit and recover a verified pre-compromise release or clean alternative.</td></tr>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>verify-confusion</code> / <code>verify_confusion</code></td><td><code>0 / 3 / 1</code></td><td>Audit <code>package.json</code> and <code>.npmrc</code> for unpinned private scopes and claimable internal names (<code>T1195.001</code>).</td></tr>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>audit-batch</code> / <code>audit_manifest_batch</code></td><td><code>0 / 2 / 3 / 1</code></td><td>Batch-screen up to 50 direct dependencies in <code>package.json</code> (squat, policy, route-isolated OSV/<code>MAL-*</code>/KEV) with <code>&lt;= 500</code>-token MCP summaries.</td></tr>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>audit-verify</code> / <code>audit_verify</code></td><td><code>0 / 3 / 1</code></td><td>Verify local hash-chained <code>audit.jsonl</code> sequence and digest integrity.</td></tr>
    <tr valign="top"><td width="210"><img src="skills/coldpin/assets/icon.svg" width="18" height="18" alt="" align="top">&nbsp;<code>mcp</code> / <code>get_artifact_report</code></td><td><code>0 / 1</code></td><td>Serve the local <code>stdio</code> MCP server and page session-scoped inspection reports without SQLite verdict caching.</td></tr>
  </tbody>
</table>

## Learn more

- [Getting started](docs/getting_started.md): end-to-end workflows, policy setup, MCP env vars, and offline usage.
- [Harnesses](docs/harnesses.md): Antigravity, Claude Code, Codex CLI, Official MCP Registry (`server.json`), and verified support status.
- [Privacy & data handling](docs/privacy.md): exact network egress, private-scope non-leakage, and credential boundaries.
- [FAQ](docs/faq.md): trade-offs, false-positive controls, stock `npx` limits, and REA optionality.
- [Design specification](docs/designs/coldpin.md) & [Design sitemap](docs/designs/SITEMAP.md): locked architecture and design records.
- [Testing & verification](TESTING.md): deterministic unit/E2E/MCP/hook tests, 14 automated verification gates, cross-platform CI matrix, SkillSpector self-audit (`SS-03`–`SS-15`), and reproducible build gates.
- [Benchmarks](skills/coldpin/BENCHMARK.md) & [Skill Card](skills/coldpin/skill-card.md): real executed Tier 1–2 measurements (`49`-fixture corpus, mutation proofs) and honest Tier 3 status.
- [Fact Ledger](docs/fact-ledger.md), [Maintenance Cadence](MAINTENANCE.md), & [Changelog](CHANGELOG.md).

## Contribute & Security

- Read [SECURITY.md](SECURITY.md) for security boundaries and responsible vulnerability disclosure.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for zero-dependency rules, Detection-as-Code requirements, and pre-PR gates.
- See [ACCESSIBILITY.md](ACCESSIBILITY.md) for CLI/card accessibility practices and known harness limits.

## License

[Apache 2.0](LICENSE). *Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
