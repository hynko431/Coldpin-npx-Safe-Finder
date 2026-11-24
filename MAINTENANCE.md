---
last_reviewed: 2026-11-24
review_by: 2027-02-24
status: current
owner_lens: maintenance-cadence
sources: Enterprise Commons MAINTENANCE.md; Google EGM runtime_packaging.md; NVIDIA Auto-Ontology BENCHMARK.md
---

# Maintenance Cadence (`coldpin`)

| Cadence | Task | Command / Owner |
| --- | --- | --- |
| **Every edit** | Compiled ESM runtime build & syntax gate (`25` files under `lib/`) | `npm run build` |
| **Every edit** | Static documentation portal parity check (`49` files under `site/`, including `hook-eval.js`, `/evidence-card-app/`, raw `.md` twins, and `site/_headers`) | `npm run build:docs:check` (regenerate via `npm run build:docs`) |
| **Every edit** | Unit, quarantine, taint, provenance, prompt-injection, Git E2E, MCP, Phase E, hook, docs-site, badge-function & Tier-3 harness tests (`59/59`) | `npm test` |
| **Every edit** | Structural skill lint, link check & 13-manifest/vertical-slice parity | `npm run lint:skill` |
| **Every edit** | Hygiene, BOM, Unicode, secret scan, `#anchor` check, `site/` dual-CSP check & URL allow-list check | `npm run verify:hygiene` |
| **Every edit** | Static coverage + positive/decoy trigger selection proxy | `npm run eval:static` |
| **Every edit** | SkillSpector-class static self-audit (`SS-03`–`SS-18`) + LF-normalized SARIF emission | `npm run audit:self` |
| **Every release** | Real 49-fixture corpus benchmark, 38 mutation checks & `BENCHMARK.md` refresh | `npm run bench` |
| **Every release** | Dual cryptographic in-toto DSSE (`skill.oms.sig` + `plugin.oms.sig`) sign & verify | `npm run sign:skill` / `npm run sign:verify` |
| **Every release** | Reproducible multi-host bundles (`antigravity`, `claude`, `openai`) & tag-driven GitHub Release (`SHA256SUMS.txt`) | `npm run pack:plugin` / `.github/workflows/release.yml` |
| **Weekly (scheduled CI)** | Cross-platform `verify:all` (`ubuntu-latest` + `windows-latest`), live-network CLI/MCP smoke test (`npm run test:live`), staleness check (`30d` window), & Dependabot `github-actions` updates | `.github/workflows/ci.yml` (`npm run check:stale`, `npm run test:live`) / `.github/dependabot.yml` |
| **Quarterly** | Review volatile Fact Ledger rows (`docs/fact-ledger.md`) against primary pages; run live Tier-3 multi-agent sandbox evals (`npm run eval:tier3 run agy`) | Skill Maintainer / AppSec |
| **On upstream change** | New ATT&CK, ATLAS, EU CRA, India DPDP, or CERT-In updates | Update `docs/fact-ledger.md` row first, then `references/` |

## Rules

- No volatile regulatory date or external threshold enters `skills/` without a corresponding row in `docs/fact-ledger.md`.
- Every file under `skills/coldpin/references/` carries `last_reviewed`, `review_by` (3 months for regulation-heavy files, 6 months max), and `status`.
- Keep `skills/coldpin/SKILL.md` strictly `<= 220` lines and `<= 24,000` bytes.
- Never hand-edit `.agents/skills/coldpin/`; always regenerate via `scripts/pack_plugin.py --sync-workspace`.
- Never hand-edit generated files under `site/`; update `scripts/docs/`, `src/hook-core.ts`, `src/mcp/evidence-card-app.ts`, or canonical source metadata and regenerate via `npm run build:docs`.
- Regenerate `lib/**/*.mjs`, `site/**`, `BENCHMARK.md`, `docs/verification/skill-inspector-self-audit.md`, and `skill.oms.sig` / `plugin.oms.sig` (in order: `build` → `build:docs` → `bench` → `audit:self` → `sign:skill` → `pack:plugin`) whenever any file in `skills/coldpin/`, `catalog/`, `rules/`, `scripts/docs/`, or `src/` changes, and bump `CHANGELOG.md` (semver) on releases.

Next quarterly review: `2027-02-24`.
