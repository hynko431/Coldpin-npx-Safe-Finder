<!--
SPDX-FileCopyrightText: Copyright (c) 2026 hynko431
SPDX-License-Identifier: Apache-2.0
-->

## Description: <br>
Discover `npx` CLI tools and npm libraries by capability, category, creator, or organization; run zero-execution in-memory tarball unpacking, JS/TS lexical credential-exfiltration taint triage, 3-tier tarball-to-source parity verification, dependency confusion auditing, and pre-compromise safe-anchor recovery. <br>

This skill is ready for local developer and CI use on Node.js `>= 24.0.0`. <br>

## Owner
hynko431 <br>

### License/Terms of Use: <br>
Apache-2.0 <br>

## Use Case: <br>
Software engineers, AppSec teams, and AI coding agents use this skill before executing `npx` commands to screen packages for typosquatting/slopsquatting, hostile install scripts, credential exfiltration, indirect prompt injection, and tarball-only supply-chain compromises, and to recover verified pre-compromise releases or clean alternatives. <br>

### Deployment Geography for Use: <br>
Global (default enterprise compliance routing covers India DPDP/CERT-In, EU CRA/NIS2/GDPR, and US NIST SSDF/SOC 2/ISO 27001). <br>

## Requirements / Dependencies: <br>
**Requires API Key or External Credential:** [No for public/offline use; Optional for private registries] <br>
**Credential Type(s):** [Private registry `.npmrc` `${ENV_VAR}` token] <br>

Do not include secrets in prompts, logs, cache files, SARIF, SBOMs, or audit outputs; use least-privilege scoped tokens and rotate credentials immediately if a workspace compromise is detected. <br>

## Known Risks and Mitigations: <br>
Risk: Static inspection cannot prove absence of dynamically fetched runtime malware, and stock `npx` cannot enforce `--integrity <sha512>` or lock floating transitive dependencies at execution time. <br>
Mitigation: Deterministic 4-state verdict reports explicit observations, inferences, and unknowns; fails closed on uninspected binaries/obfuscation/caps; suppresses runnable commands on unsafe packages; preserves stock-`npx` transitive caveats; and requires explicit human approval before host execution. <br>

## Reference(s): <br>
- [Threat taxonomy and detection catalog](references/threat-taxonomy.md) <br>
- [REA Tier-2 forensic escalation playbook](references/rea-integration-playbook.md) <br>
- [Enterprise policy schema and compliance clocks](references/enterprise-policy-schema.md) <br>
- [Evidence card, SARIF, and SBOM specifications](references/evidence-card-spec.md) <br>
- [Machine-readable runtime contract](assets/runtime-contract.yaml) <br>
- [Executed Tier 1–2 benchmark report](BENCHMARK.md) <br>

## Skill Output: <br>
**Output Type(s):** [Deterministic CLI Analysis, Evidence Cards, SARIF 2.1.0, CycloneDX 1.5 SBOM, Local Audit JSONL] <br>
**Output Format:** [Markdown (`Title + Info + Evidence`), Canonical JSON, SARIF 2.1.0 JSON, CycloneDX 1.5 JSON] <br>
**Output Parameters:** [Exit codes `0`, `1`, `2`, `3`; 4-state `TrustVerdict`] <br>
**Other Properties Related to Output:** [Zero untrusted script execution; defanged IOCs (`hxxp://`, `[.]`); private scopes never query public npmjs.org or api.osv.dev] <br>

## Evaluation Tasks & Results: <br>
See [BENCHMARK.md](BENCHMARK.md) for the executed 49-fixture adversarial/benign corpus, 38 perturbation/mutation checks, cold vs. warm Split-Plane SQLite cache measurements, and positive/decoy trigger selection proxy. <br>

| Dimension | Tier 1–2 Measured (Local Deterministic) | Tier 3 Live Multi-Agent Sandbox |
|---|---:|---:|
| Security (Adversarial Recall) | 100.0% (28/28 fixtures) | N/A (not run offline) |
| Security (False-Positive Rate) | 0.0% (0/21 benign CLIs) | N/A (not run offline) |
| Correctness (Mutation Proofs) | 100.0% (38/38 regressions caught) | N/A (not run offline) |
| Discoverability (Trigger + Decoys) | 100.0% (5/5 positive, 5/5 decoys avoided) | N/A (not run offline) |
| Skill Self-Audit (SkillSpector-class) | APPROVE (0 blocking findings) | N/A (not run offline) |

## Skill Version(s): <br>
1.6.2 (source: `SKILL.md` frontmatter) <br>

## Ethical Considerations & Security Reporting: <br>
This skill is strictly for defensive software supply-chain security and authorized inspection. Never detonate suspected malware outside an isolated lab. Engineering guidance, not legal, medical or financial advice; confirm compliance decisions with qualified counsel. <br>
