<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to `coldpin`

Thank you for contributing to `coldpin` (Coldpin). This project follows strict supply-chain hygiene and zero-dependency standards.

## Engineering Rules

1. **Zero External Runtime Dependencies:** `src/` must run natively on Node.js `>= 24.0.0` (`node:sqlite`, `node:zlib`, `node:crypto`, `node:module`, `fetch`) using `erasableSyntaxOnly` TypeScript. Governance scripts under `scripts/` must use Python `>= 3.11` stdlib or Node 24 stdlib only. Keep `package.json` `"files"` restricted to vetted runtime and documentation paths.
2. **One Canonical Skill Source:** Edit skill prose only under `skills/coldpin/`. Never hand-edit `.agents/skills/coldpin/`; regenerate it via `npm run pack:plugin`.
3. **Version Parity, Compiled `lib/` Parity & Static `site/` Parity:** Keep version numbers synchronized across all 13 files: `src/types.ts` (`ENGINE_VERSION`), `package.json`, `plugin.json`, `server.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.codex-plugin/plugin.json`, `catalog/triage-rules.json`, `catalog/mcp-schema-pin.json`, `skills/coldpin/SKILL.md`, `skills/coldpin/skill-card.md`, `skills/coldpin-audit/SKILL.md`, and `skills/coldpin-incident/SKILL.md` (enforced by `scripts/lint_skill.py`). Re-run `npm run build` whenever `src/` changes so committed `lib/**/*.mjs` matches `src/**/*.ts` 1:1. Never hand-edit generated files under `site/`; update `scripts/docs/`, `src/hook-core.ts`, or `src/mcp/evidence-card-app.ts` and re-run `npm run build:docs` (verified by `npm run build:docs:check`).
4. **Rule Lifecycle Hygiene:** Every new static detection rule must:
   - Be registered in `catalog/triage-rules.json` with severity, owner, and MITRE ATT&CK/ATLAS mapping.
   - Include both a positive adversarial fixture AND a negative benign fixture in `tests/benchmark-corpus.ts`.
   - Pass mutation verification proving the assertion turns red when the attack is introduced.
5. **No Fabricated Evidence:** Never fabricate Tier 3 multi-agent benchmark scores or overclaim static coverage.
6. **Fact Ledger Discipline:** Any new regulatory date, compliance threshold, or external URL host added to docs or references must carry a dated entry in `docs/fact-ledger.md`.

## Mandatory Pre-PR Verification

Refresh measured and signed artifacts in exact order whenever `src/`, `catalog/`, `rules/`, `skills/`, or corpus files change, then run the full verification pipeline:

```sh
npm run build
npm run build:docs
npm run bench
npm run audit:self
npm run sign:skill
npm run verify:all
```

Every gate (build + `node --check`, docs portal parity across all `49` files under `site/`, unit/E2E/hardening/MCP/Phase-E/docs-site tests, skill & MCP lint, hygiene & dual-CSP audit, staleness, static eval, SkillSpector self-audit `SS-03`–`SS-18`, benchmark verification, cryptographic DSSE signature verification, and reproducible multi-host packaging) must exit `0` with zero CRLF or untracked-file drift. Complete the checklist in `.github/PULL_REQUEST_TEMPLATE.md` when opening a pull request.

## CI & Release Workflows

- **Cross-Platform CI (`.github/workflows/ci.yml`):** Runs `npm run verify:all` on both `ubuntu-latest` and `windows-latest` (`fail-fast: false`) on pushes to `main`, pull requests, manual dispatch, and a weekly Monday staleness schedule, using commit-SHA-pinned actions and uploading `dist/skillspector-self-audit.sarif` on Ubuntu.
- **Tag-Driven Releases (`.github/workflows/release.yml`):** Triggered by pushing a `v*` tag (matching `package.json` version) or via manual dispatch. Runs `npm run verify:all`, builds reproducible `dist/coldpin-{antigravity,claude,openai}.zip` bundles, writes `dist/SHA256SUMS.txt`, and publishes a GitHub Release via built-in `gh release create`.
