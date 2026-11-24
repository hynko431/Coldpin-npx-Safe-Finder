## Summary

Describe what changed and why. Link any related issue.

## Engineering & Security Checklist

- [ ] **Zero External Dependencies:** `src/` uses Node.js `>= 24.0.0` stdlib only (`erasableSyntaxOnly` TypeScript); `scripts/` uses Python `>= 3.11` stdlib or Node 24 stdlib only; `package.json` keeps zero runtime dependencies.
- [ ] **Detection-as-Code (if changing detection rules):** Registered in `catalog/triage-rules.json` (severity, owner, MITRE ATT&CK/ATLAS ID), backed by both a positive adversarial fixture and a negative benign fixture in `tests/benchmark-corpus.ts`, plus a mutation check in `scripts/run_benchmarks.ts`.
- [ ] **Fact Ledger & Link Hygiene:** Any new regulatory date, standard revision, or external URL host is recorded in `docs/fact-ledger.md`, and all relative Markdown links and `#heading-anchors` resolve cleanly.
- [ ] **Single Canonical Skill Source:** Skill edits were made only under `skills/coldpin/` (never hand-edited under `.agents/skills/coldpin/`), and `.agents/skills/coldpin/` was regenerated via `npm run pack:plugin`.
- [ ] **Compiled Runtime, Docs Portal & MCP Schema Pin:** Re-ran `npm run build` so committed `lib/**/*.mjs` matches `src/**/*.ts` 1:1, re-ran `npm run build:docs` (never hand-editing generated `site/` files) so `npm run build:docs:check` passes with zero drift, and updated `catalog/mcp-schema-pin.json` deliberately if MCP tool/resource/prompt schemas changed.
- [ ] **Signed & Measured Artifacts Refreshed:** Re-ran `npm run bench`, `npm run audit:self`, `npm run sign:skill`, and `npm run pack:plugin` (in that exact order) whenever `src/`, `catalog/`, `rules/`, `skills/`, or corpus files changed.
- [ ] **Epistemic Honesty:** No fabricated Tier 3 metrics, no overclaimed static coverage, and no unverified trust-root provenance claims.
- [ ] **Full Verification Passed:** Ran `npm run verify:all` locally with exit code `0` across all verification gates and zero CRLF or untracked-file drift.
