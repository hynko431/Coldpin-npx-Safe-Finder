# Inspect npx packages cold. Pin clean releases.

> **Coldpin v1.6.0** · Section: Get Started · Available on: Antigravity >= v1.5.13, MCP Apps >= v2.34.0, Node.js >= 24, Claude Code, Codex CLI
> Canonical HTML: https://coldpin-docs.pages.dev/

Coldpin (`coldpin v1.6.0`) is a zero-dependency Node.js 24 CLI, local `stdio` MCP server (`io.github.hynko431/coldpin`), and native Antigravity plugin that vets npm tarballs in memory, verifies 3-tier tarball-to-source parity, and recovers pre-compromise release anchors without executing untrusted install scripts.

- **Runtime & Cost:** Node >= 24, 0 deps, $0/mo
- **Antigravity Strict:** 0 findings (5 primitives)
- **Benchmark Corpus:** 100.0% recall, 0.0% FPR (49)
- **Self-Audit & Proofs:** APPROVE 16/100, 38/38

## Choose your harness

Select how you run Coldpin. Your choice syncs across this page, updates the **On this page** navigation, and persists across tabs via `?surface=` and `localStorage`.

- **Antigravity Plugin** (`?surface=antigravity`)
- **npm & Standalone CLI** (`?surface=npm-cli`)
- **Claude / Codex / MCP** (`?surface=mcp-hosts`)
- **Enterprise HTTP & Air-Gap** (`?surface=enterprise-http`)

## Antigravity Plugin Setup (5 Native Primitives)

Install directly via `agy plugin install`. Public installs activate on first click with zero mandatory variables, registering **3 skills** (including `/coldpin-audit` and `/coldpin-incident`), **7 read-only aspect agents**, **3 rules**, **3 fail-safe PreToolUse hook groups**, and **1 local stdio MCP server** (`1,628 eager tokens`).

```sh
agy plugin install https://github.com/hynko431/Coldpin-npx-Safe-Finder
agy plugin list
agy --agent coldpin-auditor
```

> **TIP — Inline MCP App Evidence Cards (Antigravity >= v2.34.0):** Tools `inspect_package_artifact`, `resolve_safe_anchor`, `verify_confusion`, and `audit_manifest_batch` automatically link `ui://coldpin/evidence-card.html` (SEP-1865, default-deny CSP, copy-only commands). Preview it live in the [Interactive Policy Lab](https://coldpin-docs.pages.dev/docs/policy-lab/).

## Standalone CLI & Local stdio MCP (npm)

Run Coldpin directly on Node.js `>= 24.0.0` with zero runtime dependencies. Every CLI verb returns deterministic exit codes (`0` clean, `2` suspicious/unknown, `3` malicious, `1` error) and supports `--json`, `--sarif`, and `--sbom`.

```sh
npx --ignore-scripts coldpin@1.6.0 inspect semver@7.7.1
npx --ignore-scripts coldpin@1.6.0 audit-batch ./package.json --limit 50
npx --ignore-scripts coldpin@1.6.0 mcp
```

## Claude Code, Codex CLI & Official MCP Registry

Coldpin ships one canonical skill source (`skills/coldpin/`) and one compiled ESM runtime (`lib/`) across Claude Code, Codex CLI, Cursor, and the Official MCP Registry (`io.github.hynko431/coldpin`).

```sh
sha256sum -c SHA256SUMS.txt
python -m zipfile -e coldpin-claude.zip ./coldpin-claude
python -m zipfile -e coldpin-openai.zip ./coldpin-openai
```

## Self-Hosted HTTP MCP & Air-Gapped Enterprise

For centralized VPCs, Cloud Run gateways, or air-gapped CI runners, run the opt-in Streamable HTTP adapter (`coldpin-mcp-http`) with fail-closed OAuth 2.1 CIMD / SHA-256 API keys, or enforce strict offline tarball inspection via `COLDPIN_OFFLINE=1`.

```sh
COLDPIN_OFFLINE=1 node --no-warnings lib/cli.mjs inspect \
  --tarball ./vendor/pkg.tgz \
  --git-dir ./vendor/repo \
  --offline --sarif --audit-log ./audit.jsonl
```

## Defense-in-Depth Architecture

Coldpin separates untrusted package content from deterministic static analysis and human execution authority across four strict trust boundaries:

| Layer | Trust Boundary | Responsibility |
| --- | --- | --- |
| **Deterministic CLI & MCP (**`lib/`**)** | Zero execution; in-memory tar unpacking; stdio-only default (0 listening sockets); operator-only control plane | Computes 4-state verdict, SHA-512 verification, lexical taint, 3-tier parity, defanged IOCs, SARIF 2.1.0, CycloneDX 1.5 SBOM, and LRU paging. |
| **Native Guardrails (**`rules/`, `agents/`, `hooks.json`**)** | Read-only aspect subagents (`commandExecutionPolicy: "off"`); pure ES2020 PreToolUse hook exiting `0` | Routes 6 security aspects across isolated subagents, blocks evasive package runners, and forces confirmation on pinned runs, config edits, and writable subagents. |
| **Agent Skills (**`skills/`**)** | Untrusted package READMEs & metadata isolated as data; fail-closed on unknowns | Orchestrates all 7 MCP tools / 6 CLI verbs with 5 aspect playbooks plus `/coldpin-audit` and `/coldpin-incident` slash commands. |
| **Human Operator** | Explicit approval gate before any host execution | Reviews observations, inferences, unknowns, and stock-npx transitive caveats before approving any pinned command. |

## Explore the Documentation

- **Interactive Policy Lab** (Get Started): Run Coldpin's real ES2020 PreToolUse hook engine in your browser and inspect the live SEP-1865 MCP App card. — https://coldpin-docs.pages.dev/docs/policy-lab/
- **5-Component Antigravity Plugin** (Plugin & Guardrails): 7 read-only aspect agents, 3 Markdown rules, 3 PreToolUse hook groups, and /coldpin-audit & /coldpin-incident. — https://coldpin-docs.pages.dev/docs/antigravity-plugin/
- **Self-Hosted HTTP MCP & Sidecar (v1.6)** (MCP & CLI): Deploy coldpin-mcp-http with OAuth 2.1 CIMD, RFC 9728/8707, inline MCP Apps, and opt-in weekly audits. — https://coldpin-docs.pages.dev/docs/enterprise-http/
- **Benchmarks, Checksums & Provenance** (Verification & Releases): Live synced schema pin (1,628 tokens), 38/38 mutation proofs, SS-03..SS-18 audit, and v1.6.0 SHA256SUMS. — https://coldpin-docs.pages.dev/docs/verification/

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
