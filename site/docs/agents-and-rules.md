# 7 Read-Only Aspect Agents & 3 Rules

> **Coldpin v1.6.1** · Section: Plugin & Guardrails · Available on: Antigravity App, Antigravity CLI, Antigravity IDEs
> Canonical HTML: https://coldpin-docs.pages.dev/docs/agents-and-rules/

Every Coldpin security aspect runs inside an isolated read-only subagent with private body rules, `commandExecutionPolicy: "off"`, and a scoped Coldpin MCP tool allowlist enforced by `SS-14-AGENT-LEAST-PRIV` and `SS-15-RULES-HYGIENE`.

## 7 Read-Only Aspect Agents

| Agent | Role & Mode | Scoped Coldpin MCP Tools | Isolation Controls |
| --- | --- | --- | --- |
| `coldpin-auditor` | Primary orchestrator (`mainAgent: true`) | Delegates via `invoke_subagent` + all 7 read-only Coldpin MCP tools | `commandExecutionPolicy: "off"`; canonical read-only tools |
| `coldpin-discoverer` | Capability search & 7-primitive squat screening | `discover_packages` | `inheritCustomizations: false`; `commandExecutionPolicy: "off"` |
| `coldpin-inspector` | In-memory tarball triage, lexical taint & 3-tier parity | `inspect_package_artifact`, `get_artifact_report` | `inheritCustomizations: false`; `commandExecutionPolicy: "off"` |
| `coldpin-manifest-auditor` | Batch screening of `package.json` (up to 50 direct deps) | `audit_manifest_batch`, `get_artifact_report` | `inheritCustomizations: false`; `commandExecutionPolicy: "off"` |
| `coldpin-confusion-auditor` | Private-scope & `.npmrc` confusion audit (`T1195.001`) | `verify_confusion` | `inheritCustomizations: false`; `commandExecutionPolicy: "off"` |
| `coldpin-forensics` | Patient-zero Git bisect, rollback anchors & REA Tier-2 planning | `resolve_safe_anchor`, `inspect_package_artifact` | `inheritCustomizations: false`; `commandExecutionPolicy: "off"` |
| `coldpin-compliance` | Policy posture, hash-chained `audit.jsonl` & SARIF/SBOM evidence | `audit_verify`, `get_artifact_report` | `inheritCustomizations: false`; `commandExecutionPolicy: "off"` |

> **TIP — Why background subagents set inheritCustomizations: false ([PLG-15]):** When auditing an untrusted cloned repository, malicious `.agents/rules/` or workspace hooks inside that repository must never hijack Coldpin's specialist workers. Setting `inheritCustomizations: false` isolates all 6 leaf workers from untrusted workspace overrides.

## 3 Pure Markdown Rules

| Rule File | Trigger Mode | Budget / Scope | Enforced Guardrails |
| --- | --- | --- | --- |
| `rules/AGENTS.md` | Always loaded | `1,599 bytes` (strict `<= 1,800 B` cap) | 4 supply-chain invariants (Vet First, Untrusted Data, Private Scopes, Human Gate) + 6-aspect delegation routing table. |
| `rules/coldpin-manifest-guard.md` | `trigger: glob` | Comma-separated globs for `package.json`, lockfiles, `.npmrc`, `mcp_config.json` | Requires batch screening, confusion checks, exact `X.Y.Z` pins + `--ignore-scripts`, and zero secret tokens in MCP CLI args. |
| `rules/coldpin-incident-checklist.md` | `trigger: model_decision` | Activates on `MALICIOUS_INDICATORS_FOUND` or lockfile exposure | Halts execution, delegates bisect to `coldpin-forensics`, preserves hashes, rotates credentials, and surfaces CERT-In / NIS2 / CRA / GDPR clocks. |

---

*Coldpin v1.6.1 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
