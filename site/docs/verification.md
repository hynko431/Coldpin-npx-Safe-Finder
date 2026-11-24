# Verification, Benchmarks & Provenance

> **Coldpin v1.6.0** · Section: Verification & Releases · Available on: Node 24 & 26 CI Matrix, Ubuntu & Windows, SLSA Build Provenance, Dual DSSE
> Canonical HTML: https://coldpin-docs.pages.dev/docs/verification/

Every Coldpin release passes a cross-platform 14-gate pipeline across `ubuntu-latest` and `windows-latest` on Node `24` LTS and Node `26` Active LTS, followed by keyless npm OIDC Trusted Publishing and GitHub SLSA Build Provenance attestations.

## Live Synced Verification Metrics (v1.6.0)

- **MCP Schema Pin:** 1,643 / 1,800 tokens (7 tools)
- **Automated Tests:** 42/42 core + docs & badge suites (56/56)
- **Mutation Proofs:** 38/38 regressions caught
- **SkillSpector Self-Audit:** APPROVE 16/100 (0 blocking)

| Verification Gate | Command | Measured Result |
| --- | --- | --- |
| Compiled ESM Parity (`SS-13`) | `npm run build` | 25 compiled LF lib/**/*.mjs files syntax-checked & 1:1 SHA-256 verified |
| Deterministic Test Suites | `npm test` | 56/56 tests across 9 suites (42/42 core/MCP/plugin/Phase-E + docs portal + badge function suites) |
| 49-Fixture Security Corpus | `npm run bench:check` | 100.0% recall (28/28 adversarial), 0.0% FPR (0/21 benign), 38/38 mutation proofs |
| SkillSpector Self-Audit | `npm run audit:self` | SS-03–SS-18: APPROVE (risk 16/100, 0 blocking, 0 SARIF alerts) |
| MCP Schema Rug-Pull Pin (`SS-11`) | `catalog/mcp-schema-pin.json` | 7 tools, 2 resources, 2 prompts, 1,643 tokens (47c052d4f7e0...) |
| Dual in-toto DSSE Attestations | `npm run sign:verify` | skills/coldpin/skill.oms.sig (18 files) & catalog/plugin.oms.sig (45 files) |
| Antigravity Strict Validation | `agy plugin validate --strict` | agents: 7, hooks: 3, mcpServers: 1, rules: 3, skills: 3, sidecars: 0, findings: [] |
| Static Docs Parity & Hygiene | `npm run build:docs -- --check` & `npm run verify:hygiene` | Zero broken links/anchors, dual-CSP sync, 100% hook-eval.js parity, LF-only UTF-8 |

## Release v1.6.0 Verified SHA256SUMS.txt

```
7983b4d4f02cf556de1de458e986d0d6394030f360722bc6e645feeee0ef2822  coldpin-antigravity.zip
3b520c6688d56f88dcd213470f9d10d9e1345fd73d16909c6055989d65f9e50a  coldpin-claude.zip
723fc06ed8a8989c738d7f8e216b5f12e018efd2a0ae82a6f6b901dd988223df  coldpin-openai.zip
929682d1dd7ef2b40b82e8e8cce3ac25344631399987ab9493cbd0a98a73caf9  skillspector-self-audit.sarif
```

Verify GitHub SLSA Build Provenance attestations online at [GitHub Attestations](https://github.com/hynko431/Coldpin-npx-Safe-Finder/attestations), or inspect the full source reports: [BENCHMARK.md](https://github.com/hynko431/Coldpin-npx-Safe-Finder/blob/main/skills/coldpin/BENCHMARK.md), [SkillSpector Self-Audit](https://github.com/hynko431/Coldpin-npx-Safe-Finder/blob/main/docs/verification/skill-inspector-self-audit.md), and [TESTING.md](https://github.com/hynko431/Coldpin-npx-Safe-Finder/blob/main/TESTING.md).

## Explicit Verification Boundaries (Honest Non-Claims)

> **CAUTION — Tier 3 Live Multi-Agent Sandbox Uplift: NOT RUN (N/A):** Offline CI executes deterministic Tier 1 (lint, hygiene, SkillSpector) and Tier 2 (49-fixture corpus, cache benchmarks, `38/38` mutation proofs) gates. Tier 3 live multi-agent LLM token uplift across hosted sandboxes is honestly recorded as `NOT RUN (N/A)` rather than fabricated, and local `*.oms.sig` dev keys are explicitly labeled `local-dev-self-signed`.

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
