# Antigravity 5-Component Architecture

> **Coldpin v1.6.0** · Section: Plugin & Guardrails · Available on: Antigravity >= v1.5.13, MCP Apps >= v2.34.0
> Canonical HTML: https://coldpin-docs.pages.dev/docs/antigravity-plugin/

Coldpin conforms strictly to the official Antigravity plugin manifest schema (`https://antigravity.google/schemas/v1/plugin.json`). Scanner rule data lives cleanly in `catalog/` so `rules/` holds strictly pure agent Markdown rules.

## Five Native Plugin Primitives

### Skills (3 bundled)

`skills/coldpin/` is the canonical cross-harness skill with 5 modular playbooks under `references/aspect-*.md`.

Two Antigravity slash skills ([/coldpin-audit and /coldpin-incident](https://coldpin-docs.pages.dev/docs/slash-commands/)) orchestrate read-only workspace audits and supply-chain compromise recovery.

### Read-Only Agents (7 bundled)

Primary orchestrator `coldpin-auditor` (`mainAgent: true`) delegates across 6 isolated background aspect specialists.

All 7 enforce `commandExecutionPolicy: "off"` and canonical read-only tool allowlists; all 6 background workers set `inheritCustomizations: false` to block workspace rule poisoning.

### Markdown Rules (3 bundled)

`rules/AGENTS.md` stays under 1,800 bytes (`1,599 bytes` measured) with a compact 6-aspect delegation routing table.

`rules/coldpin-manifest-guard.md` activates via `trigger: glob` on manifests/lockfiles; `rules/coldpin-incident-checklist.md` activates via `trigger: model_decision`.

### Lifecycle Hooks (3 enabled groups)

Root `hooks.json` runs pure ES2020 `./lib/hook.mjs` across `coldpin-npx-guard`, `coldpin-config-guard`, and `coldpin-delegation-guard`.

Always exits `0` with strictly `allow`, `deny`, or `force_ask`. Never emits auto-approval.

### Local MCP Server (1 stdio server)

Root `mcp_config.json` launches `node --no-warnings ${PLUGIN_ROOT}/lib/mcp.mjs` with `timeoutSeconds: 300`, `${PLUGIN_DATA}` cache isolation, and all `7` read-only tools marked `eager: true` (`1,643 tokens`).

Zero mandatory `variables` keeps public installs active immediately; enterprises can layer [private-registry variables](https://coldpin-docs.pages.dev/docs/configuration/) or [self-hosted HTTP MCP](https://coldpin-docs.pages.dev/docs/enterprise-http/).

## Strict Antigravity CLI Validation

```json
{
  "manifest": "plugin.json",
  "name": "coldpin",
  "components": {
    "agents": 7,
    "hooks": 3,
    "mcpServers": 1,
    "rules": 3,
    "sidecars": 0,
    "skills": 3
  },
  "findings": []
}
```

> **NOTE — Why sidecars is 0 by default:** Per SkillSpector rule `SS-17-SIDECAR-LEAST-PRIV`, installing Coldpin never spawns background daemons automatically. The scheduled weekly audit sidecar ships disabled-by-default under `examples/sidecar.weekly-audit.example.json` for explicit operator opt-in.

## Root mcp_config.json (Zero Mandatory Variables)

```json
{
  "mcpServers": {
    "coldpin": {
      "command": "node",
      "args": ["--no-warnings", "${PLUGIN_ROOT}/lib/mcp.mjs"],
      "env": {
        "COLDPIN_CACHE_DIR": "${PLUGIN_DATA}"
      },
      "timeoutSeconds": 300,
      "tools": {
        "discover_packages": { "eager": true },
        "inspect_package_artifact": { "eager": true },
        "resolve_safe_anchor": { "eager": true },
        "verify_confusion": { "eager": true },
        "audit_manifest_batch": { "eager": true },
        "audit_verify": { "eager": true },
        "get_artifact_report": { "eager": true }
      }
    }
  }
}
```

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
