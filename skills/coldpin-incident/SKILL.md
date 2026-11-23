---
name: coldpin-incident
description: >-
  Run a read-only npm supply-chain compromise response workflow with Coldpin:
  halt unvetted execution, bisect Git history to locate patient-zero and a clean
  rollback anchor or vetted alternative, guide lockfile containment and token
  rotation, and prepare REA Tier-2 escalation without self-bootstrapping.
license: Apache-2.0
metadata:
  version: "1.6.0"
  author: "hynko431"
  tags:
    - incident-response
    - supply-chain-security
    - forensics
    - safe-anchor
    - rea
---

# Coldpin Supply-Chain Incident Response (`/coldpin-incident`)

Guides rapid, strictly read-only containment, root-cause bisect, clean-anchor recovery, and compliance evidence capture when Coldpin flags `MALICIOUS_INDICATORS_FOUND`, `local_workspace_compromised`, tarball-to-source drift, or tampered SLSA provenance.

## Execution Workflow

1. **Immediate Containment Gate:** Confirm zero execution of the affected package or lockfile. Keep every extracted URL, domain, IP, and webhook strictly defanged (`hxxp://`, `[.]`).
2. **Cold Artifact & Parity Evidence (`coldpin-inspector`):** If not already captured, run `inspect_package_artifact` (`detail: "summary"`, paging `observations`/`iocs`/`unknowns` via `get_artifact_report`) to preserve the deterministic verdict, SHA-512 digest, and `rea_escalation_plan`.
3. **Patient-Zero Bisect & Safe Anchor (`coldpin-forensics`):** Run `resolve_safe_anchor` against the package's local Git directory or HTTPS `repo_url` (`--first-parent`, `window <= 200`) to pinpoint the compromise commit and emit `ROLLBACK_TO_SAFE_ANCHOR`, `FORENSIC_COMMIT_ONLY`, `SWITCH_TO_ALTERNATIVE`, or `BLOCK_NO_SAFE_PATH`.
4. **Audit Trail & Regulatory Clocks (`coldpin-compliance`):** Verify local `audit.jsonl` integrity via `audit_verify`, export SARIF/SBOM evidence via `get_artifact_report`, and surface applicable notification windows (India CERT-In `6 h`, EU NIS2/CRA `24 h` / `72 h`, GDPR Art. 33 `72 h`) for legal/IR counsel.
5. **REA Tier-2 Escalation (Only When Pre-Installed):** If obfuscated JS, native `.node`, WASM, or drifted binaries require decompilation, invoke pre-registered `rea` / `rea-agents` only—never run `rea-agents` via `npx`.

## Hard Invariants
- Never recommend `@latest` or unvetted package execution during incident response.
- Never overwrite Coldpin verdicts or fabricate clean rollback versions when no verified tarball passes CVE/KEV gates.
- Advise immediate credential rotation and host IR review of shell startup profiles, scheduled tasks, OS launch entries, and `catalog/sigma/` EDR rules.

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
