# Slash Commands (/coldpin-audit & /coldpin-incident)

> **Coldpin v1.6.2** · Section: Plugin & Guardrails · Available on: Antigravity App, Antigravity CLI, Antigravity IDEs
> Canonical HTML: https://coldpin-docs.pages.dev/docs/slash-commands/

Coldpin bundles two dedicated Antigravity slash skills under `skills/coldpin-audit/` and `skills/coldpin-incident/`. Both are strictly read-only — they never execute shell commands, edit files, or recommend unvetted `npx` runs.

## /coldpin-audit — Read-Only Workspace Audit

### /coldpin-audit — Launch Read-Only Workspace Supply-Chain Audit

Screens workspace package.json (<= 50 direct deps), audits .npmrc for T1195.001 dependency confusion, verifies local audit.jsonl chains, and cold-inspects flagged packages.

```text
/coldpin-audit Run a strictly read-only Coldpin supply-chain audit of this workspace: check coldpin://policy/active, batch-screen package.json via audit_manifest_batch, audit .npmrc via verify_confusion, verify any local audit.jsonl via audit_verify, and cold-inspect any flagged dependencies without running shell commands or modifying files.
```

1. **Read active policy posture**
   Queries `coldpin://policy/active` to confirm `policy_sha256`, `private_scopes`, `denied_orgs`, and `offline_mode`.

2. **Run parallel read-only aspect audits**
   Delegates to `coldpin-manifest-auditor` (`audit_manifest_batch`), `coldpin-confusion-auditor` (`verify_confusion`), and `coldpin-compliance` (`audit_verify`).

3. **Escalate flagged dependencies cold**
   Passes every `MALICIOUS_OR_BLOCKED` or `FLAGGED_SUSPICIOUS` dependency to `coldpin-inspector` (`inspect_package_artifact` in summary mode with LRU paging).

4. **Hand off to /coldpin-incident on compromise**
   If any package returns `MALICIOUS_INDICATORS_FOUND` or `local_workspace_compromised`, transitions immediately to containment and patient-zero bisect.

## /coldpin-incident — Supply-Chain Compromise Response

### /coldpin-incident — Launch Read-Only Supply-Chain Incident Containment

Halts unvetted execution, runs --first-parent Git commit bisect via resolve_safe_anchor, verifies audit.jsonl evidence, surfaces regulatory clocks, and prepares safe REA Tier-2 handoff.

```text
/coldpin-incident Run a strictly read-only Coldpin incident response brief: confirm zero package execution, keep all IOCs defanged, inspect the flagged package cold via inspect_package_artifact, locate patient-zero and a verified rollback anchor or vetted alternative via resolve_safe_anchor, verify audit.jsonl via audit_verify, and summarize containment and regulatory notification clocks without running shell commands.
```

> **DANGER — Never Run Unvetted Commands During Incident Response:** Deep-link prompts on this portal are strictly read-only and never emit shell or `npx` execution links. Never recommend `@latest` or bootstrap `rea-agents` via `npx` during compromise triage.

---

*Coldpin v1.6.2 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
