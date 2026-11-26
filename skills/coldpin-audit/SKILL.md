---
name: coldpin-audit
description: >-
  Run an end-to-end read-only workspace supply-chain audit using Coldpin's
  aspect subagents: batch-screen package.json dependencies, audit .npmrc for
  dependency confusion (T1195.001), verify policy posture and hash-chained
  audit.jsonl logs, and cold-inspect any flagged packages without execution.
license: Apache-2.0
metadata:
  version: "1.6.2"
  author: "hynko431"
  tags:
    - npx
    - npm
    - supply-chain-audit
    - dependency-confusion
    - compliance
---

# Coldpin Workspace Supply-Chain Audit (`/coldpin-audit`)

Orchestrates a deterministic, strictly read-only audit of the current workspace's npm supply-chain posture without executing any package manager install or lifecycle script.

## Execution Workflow

1. **Read Policy Posture:** Query `coldpin://policy/active` to confirm active `policy_sha256`, `private_scopes`, `private_prefixes`, `denied_orgs`, and `offline_mode`.
2. **Run Parallel Read-Only Aspect Audits:**
   - **Manifest & Lockfile Batch (`coldpin-manifest-auditor`):** Call `audit_manifest_batch` on workspace `package.json` (`<= 50` direct dependencies), check `truncated_at_cap`, and page flagged items via `get_artifact_report`.
   - **Dependency Confusion (`coldpin-confusion-auditor`):** Call `verify_confusion` on workspace `package.json` and `.npmrc` to flag unpinned private scopes, unscoped internal prefixes (`T1195.001`), and 1-edit private-scope lookalikes.
   - **Governance & Audit Trail (`coldpin-compliance`):** If a root-confined `audit.jsonl` exists, call `audit_verify` to confirm SHA-256 sequence integrity and capture policy/SBOM/SARIF readiness.
3. **Escalate Flagged Dependencies Cold (`coldpin-inspector`):** For every `MALICIOUS_OR_BLOCKED` or `FLAGGED_SUSPICIOUS` dependency returned above, run `inspect_package_artifact` cold in memory (`detail: "summary"`, paging with `get_artifact_report` if needed).
4. **Trigger Incident Recovery If Compromised:** If any dependency returns `MALICIOUS_INDICATORS_FOUND` or `local_workspace_compromised`, immediately hand off to `/coldpin-incident` (`coldpin-forensics`).

## Hard Invariants
- Strictly read-only: zero shell execution, zero file writes, zero `npm install` or unvetted `npx`.
- Never send private scopes or denied orgs to public `registry.npmjs.org` or `api.osv.dev`.
- Present unified `Title + Info + Evidence` summary with Observations, Inferences, Unknowns, defanged IOCs, and prioritized remediations.

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
