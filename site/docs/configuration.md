# Configuration & Private-Scope Isolation

> **Coldpin v1.6.1** · Section: Enterprise & Security · Available on: Local CLI, Local stdio MCP, Self-Hosted HTTP MCP, Antigravity Variables
> Canonical HTML: https://coldpin-docs.pages.dev/docs/configuration/

Coldpin enforces an operator-only control plane: security policy, private scopes, registry credentials, and allowed local roots are configured strictly through startup environment variables or pinned operator policy files — never mutable by untrusted tool calls.

## Core Operator Environment Variables

> **NOTE — Private-Scope Non-Leakage & 1-Edit Typo Hard-Block:** Any scope listed in `COLDPIN_PRIVATE_SCOPES`, `.coldpin.policy.json`, or `$HOME/.npmrc` NEVER contacts public `registry.npmjs.org` or `api.osv.dev`. Scopes within 1 Levenshtein edit or adjacent transposition (e.g., `@amce` vs `@acme`) are hard-blocked (`blocked_typo`) before any network call.

| Environment Variable | Required | Behavior & Guardrails |
| --- | --- | --- |
| `COLDPIN_POLICY_PATH` | No | Operator-pinned immutable `.coldpin.policy.json` (overrides workspace policy and env scope defaults). |
| `COLDPIN_ALLOWED_ROOTS` | No | OS-delimited local workspace root allowlist for root-confined tarball, lockfile, and Git reads when an MCP host omits `roots/list`. |
| `COLDPIN_AUDIT_LOG` | No | Path to optional append-only hash-chained `audit.jsonl` storing pseudonymous SHA-256 `actor_id_hash`. |
| `COLDPIN_CACHE_DIR` | No | Split-Plane SQLite cache directory (defaults to `${PLUGIN_DATA}` in Antigravity or OS cache dir; `0700`/`0600` POSIX modes). |
| `COLDPIN_OFFLINE` | No | Set to `1` to forbid all outbound HTTP traffic and remote `git clone` (fails closed). |
| `COLDPIN_PRIVATE_SCOPES` | No | Comma-separated internal `@scope` list routed exclusively to `COLDPIN_PRIVATE_REGISTRY_URL`. |
| `COLDPIN_PRIVATE_REGISTRY_URL` | No | HTTPS-only private registry origin validated against SSRF loopback, link-local, IMDS, CGNAT, and RFC 1918 ranges. |
| `COLDPIN_REGISTRY_TOKEN` | No (Secret) | Read-only bearer token sent strictly over HTTPS to the exact matching private host. Unexpanded `${VAR}` placeholders are rejected (`[PLG-09]`) and tokens are never logged. |
| `COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE` | No | Set to `1` to permit `verify_confusion(check_public: true)` in MCP mode (disabled by default to prevent scope leakage). |
| `COLDPIN_HOOK_VERBOSE` | No | Set to `1` to log diagnostic `PreToolUse` hook decisions to `stderr` without altering `stdout` JSON. |

## Enterprise Private Registry Overlay (Antigravity Variables)

Default `mcp_config.json` declares zero mandatory `variables` so public installs work immediately. Enterprise teams routing internal scopes to Artifactory, Verdaccio, or GitHub Packages can apply `examples/mcp_config.private-registry.example.json` (all variables stay in `env` — never CLI `args`, verified by `SS-12`):

```json
{
  "mcpServers": {
    "coldpin": {
      "command": "node",
      "args": ["--no-warnings", "${PLUGIN_ROOT}/lib/mcp.mjs"],
      "env": {
        "COLDPIN_CACHE_DIR": "${PLUGIN_DATA}",
        "COLDPIN_PRIVATE_SCOPES": "${COLDPIN_PRIVATE_SCOPES}",
        "COLDPIN_PRIVATE_REGISTRY_URL": "${COLDPIN_PRIVATE_REGISTRY_URL}",
        "COLDPIN_REGISTRY_TOKEN": "${COLDPIN_REGISTRY_TOKEN}"
      },
      "timeoutSeconds": 300,
      "variables": [
        {
          "name": "COLDPIN_PRIVATE_SCOPES",
          "title": "Private npm Scopes (comma-separated)",
          "description": "Internal npm scopes routed exclusively to your private registry (for example @acme,@acme-internal). Never queried against public registry.npmjs.org or api.osv.dev."
        },
        {
          "name": "COLDPIN_PRIVATE_REGISTRY_URL",
          "title": "Private npm Registry URL (HTTPS)",
          "description": "HTTPS private npm registry endpoint (for example https://artifactory.acme.internal/api/npm/npm-local). Must be HTTPS and non-metadata/non-loopback."
        },
        {
          "name": "COLDPIN_REGISTRY_TOKEN",
          "title": "Private Registry Read-Only Token",
          "description": "Least-privilege read-only bearer token sent strictly over HTTPS to the exact configured private registry host. Never passed via CLI args.",
          "link": "https://artifactory.acme.internal/docs/npm-tokens"
        }
      ],
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

*Coldpin v1.6.1 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
