# Security Policy & Compliance Reference

> **Coldpin v1.6.0** · Section: Enterprise & Security · Available on: v1.6.x Active Maintenance, SARIF 2.1.0, CycloneDX 1.5, Sigma EDR
> Canonical HTML: https://coldpin-docs.pages.dev/docs/security/

Coldpin treats every scanned npm tarball, `README.md`, manifest field, and Git commit message as hostile untrusted input. Verdicts are computed deterministically in TypeScript code outside LLM context.

## Supported Versions & Vulnerability Disclosure

| Version Line | Status |
| --- | --- |
| `1.6.x` | Active maintenance (Antigravity >= v1.5.13 hooks; >= v2.34.0 MCP Apps; Node >= 24) |
| `1.0.x – 1.5.x` | Security fixes delivered via upgrade to `1.6.x` |

> **DANGER — Confidential Security Reporting:** Do not open a public GitHub issue with weaponized exploit chains or live malicious URLs. Submit confidential reports via [GitHub Private Vulnerability Reporting](https://github.com/hynko431/Coldpin-npx-Safe-Finder/security/advisories/new) with a minimal synthetic fixture tarball, redacted CLI command, expected vs. observed verdict, Node version, and commit SHA. Triage target: 2 business days [Typical].

## Hard Security Boundaries

- **Zero-Execution Inspection: **Never runs `npm install`, `npm pack`, lifecycle hooks, or untrusted binaries during inspection.
- **No Self-Bootstrap: **Never executes `npx -y rea-agents` or silently installs third-party analyzers.
- **Non-LLM Verdict Authority: **The 4-state `TrustVerdict` is deterministic TypeScript; indirect prompt injection (`AML.T0051`) and Trojan-Source bidi Unicode are quarantined and never override verdicts.
- **Archive & Network Defenses: **Rejects Zip-Slip traversal, symlinks/hardlinks, duplicate tar entries, EOF polyglot smuggling, corrupt tar checksums, NTFS ADS, zip bombs, and IPv4/IPv6-mapped SSRF.
- **Companion EDR Detections: **Pair static inspection and Layer-1 hooks with the bundled Linux/Windows Sigma rules under `catalog/sigma/`.

## Compliance & Regulatory Incident Clocks

When malicious indicators or lockfile exposure are confirmed, `rules/coldpin-incident-checklist.md` and `/coldpin-incident` surface standard regulatory clocks for legal and incident-response review (verified in `docs/fact-ledger.md`):

| Framework / Regulation | Reporting Window / Artifact | Coldpin Evidence Support |
| --- | --- | --- |
| India CERT-In Directions (2022-04-28) | 6-hour cyber-incident reporting; 180-day ICT log retention | Hash-chained `audit.jsonl` + defanged IOCs + lockfile hashes |
| India DPDP Act 2023 & Rules 2025 | Data minimization & breach notification duties | Zero telemetry, zero PII collection, pseudonymous `actor_id_hash` |
| EU Cyber Resilience Act (Reg. 2024/2847) | 24h early warning / 72h notification; SBOM obligations | CycloneDX 1.5 SBOM + VEX (`--sbom`) & SLSA provenance status |
| EU NIS2 & GDPR Art. 33 | 24h early warning (NIS2) / 72h breach notification | Deterministic SARIF 2.1.0 (`--sarif`) + `audit-verify` integrity proofs |
| NIST SSDF & SOC 2 | Pre-execution supply-chain control & tamper-evident trails | 14-gate CI pipeline, dual DSSE attestations, and operator policy SHA-256 |

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
