# Harnesses & Cross-Platform Distribution

> **Coldpin v1.6.0** · Section: Get Started · Available on: Antigravity, Claude Code, Codex CLI, Cursor / MCP, Standalone CLI
> Canonical HTML: https://coldpin-docs.pages.dev/docs/harnesses/

Coldpin maintains **one canonical skill source** under `skills/coldpin/` and **one compiled zero-dependency ESM runtime** under `lib/` (built deterministically from `src/` via `npm run build`). No agent harness receives forked prose.

## Cross-Platform Install Matrix

| Harness / Channel | Manifest / Identifier | Entrypoint & Install | Verification Status |
| --- | --- | --- | --- |
| **Antigravity (App, CLI, IDEs)** | `plugin.json`, `mcp_config.json`, `hooks.json` | `agy plugin install https://github.com/hynko431/Coldpin-npx-Safe-Finder` | Live `agy plugin validate --strict` (`findings: []`) verified locally |
| **Claude Code** | `.claude-plugin/plugin.json` (inline `mcpServers`) | `python scripts/pack_plugin.py --target claude --verify` → `coldpin-claude.zip` | Manifest schema & reproducible archive verified; live Claude host trace not run locally |
| **Codex CLI / ChatGPT** | `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json` | `python scripts/pack_plugin.py --target openai --verify` → `coldpin-openai.zip` | Manifest schema & reproducible archive verified; live Codex host trace not run locally |
| **Official MCP Registry / npm / Cursor** | `server.json` (`io.github.hynko431/coldpin`), `package.json` | `npx --ignore-scripts coldpin@1.6.0 mcp` | Schema parity, `node_modules` smoke test & JSON-RPC stdio suite verified |
| **Standalone Node 24 CLI / CI** | `package.json` (`coldpin`, `coldpin-mcp`, `coldpin-mcp-http`) | `node --no-warnings lib/cli.mjs --help` | End-to-end tests + 49-fixture corpus verified on Ubuntu & Windows (Node 24 & 26) |

## Manual Install & Workspace Sync

For workspace-scoped discovery inside a cloned repository, sync `.agents/skills/coldpin/` automatically using the deterministic packager:

```sh
python scripts/pack_plugin.py --target all --verify --sync-workspace
```

For manual Antigravity installation without the CLI, extract `coldpin-antigravity.zip` into `~/.gemini/config/plugins/coldpin/` (removing any prior version first so stale files do not linger), reload the window, and verify `coldpin` appears in `agy plugin list`.

## 13-Manifest Parity & Deterministic Zip Packaging

- **Single source of truth: **Root `plugin.json` conforms strictly to `https://antigravity.google/schemas/v1/plugin.json` (`additionalProperties: false`, zero inline `mcpServers` or `hooks`).
- **13-manifest version parity: **`scripts/lint_skill.py` fails if version or metadata drifts across `plugin.json`, `package.json`, `server.json`, `.claude-plugin/{plugin,marketplace}.json`, `.codex-plugin/plugin.json`, `src/types.ts`, `catalog/triage-rules.json`, `catalog/mcp-schema-pin.json`, `skills/coldpin/{SKILL,skill-card}.md`, and `skills/coldpin-{audit,incident}/SKILL.md`.
- **Reproducible POSIX zips: **`scripts/pack_plugin.py` sorts entries, fixes timestamps (`2026-01-01 00:00:00 UTC`), sets explicit `create_system=3` with `0100755` on `lib/{cli,mcp,mcp-http,hook}.mjs` and `0100644` otherwise, isolates Antigravity-only primitives strictly to `HOST_GLOBS["antigravity"]`, and verifies byte-for-byte SHA-256 identity across two builds.

> **CAUTION — Cloud-Only Chat Sessions:** Cloud-only chat sessions without a local Node.js >= 24 runtime cannot execute `lib/mcp.mjs` or `lib/cli.mjs` locally and must fail closed (`UNVERIFIABLE_UNKNOWN`) unless connected to a self-hosted [coldpin-mcp-http gateway](https://coldpin-docs.pages.dev/docs/enterprise-http/).

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
