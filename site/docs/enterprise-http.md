# Self-Hosted HTTP MCP, MCP App & Weekly Sidecar (v1.6+)

> **Coldpin v1.6.0** · Section: MCP & CLI · Available on: Self-Hosted VPC / Cloud Run, Antigravity >= v2.34.0 (MCP App), MCP 2025-11-25
> Canonical HTML: https://coldpin-docs.pages.dev/docs/enterprise-http/

Introduced in `v1.6.0` (Phase E), all three enterprise extensions are strictly opt-in and preserve Coldpin's **$0/mo** maintainer cost and default local `stdio`-only zero-socket posture (`mcp_config.json` → `lib/mcp.mjs`).

## Opt-In Streamable HTTP MCP Adapter (coldpin-mcp-http)

Binary `coldpin-mcp-http` (`lib/mcp-http.mjs`, POSIX `0100755`) exposes Coldpin's exact 7 read-only MCP tools over Streamable HTTP (`MCP 2025-11-25`) on your own VPC or Cloud Run infrastructure. It is isolated from `lib/mcp.mjs` and enforced by SkillSpector rule `SS-16-HTTP-ADAPTER-HARDENING`.

> **CAUTION — Fail-Closed Startup Requirements:** `coldpin-mcp-http` refuses to start unless BOTH `COLDPIN_HTTP_RESOURCE_URL` (must be `https://`) and `COLDPIN_HTTP_AUTH_MODE` (`oauth`, `api_key`, or `both`) are explicitly configured. Plaintext `http://` is rejected unless loopback-bound with `COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE=1`.

- **OAuth 2.1 + PKCE (S256) + CIMD: **Serves RFC 9728 Protected Resource Metadata on both `/.well-known/oauth-protected-resource` and path-inserted forms, supports Antigravity CIMD (`https://antigravity.google/oauth/client-metadata.json`), verifies `RS256` / `ES256` JWTs via pure Node 24 `node:crypto` against pinned JWKS (strictly rejecting `alg: none` and `HS*`), and enforces RFC 8707 `aud` + required scope (`403 insufficient_scope`).
- **Constant-Time SHA-256 API Keys: **Accepts `>= 32`-char `cpk_live_*` bearer keys compared against `COLDPIN_MCP_API_KEY_SHA256` via `crypto.timingSafeEqual` (rejecting unexpanded `${VAR}` placeholders).
- **Transport Hardening: **Anti-DNS-rebinding `Host` + browser `Origin` allowlists (`403`), `1 MiB` request body cap (`413`), per-principal rate limiting (`429` + `Retry-After`), and principal-bound cryptographic `Mcp-Session-Id` (`403` on cross-principal reuse, `DELETE /mcp` returns `204`).

## HTTP & OAuth 2.1 Environment Variables

| Environment Variable | Default / Required | Purpose & Hardening Behavior |
| --- | --- | --- |
| `COLDPIN_HTTP_RESOURCE_URL` | Required | Canonical `https://` MCP endpoint URI (e.g. `https://coldpin.acme.internal/mcp`) used for RFC 9728 metadata and RFC 8707 `aud` validation. |
| `COLDPIN_HTTP_AUTH_MODE` | Required | Authentication policy: `oauth`, `api_key`, or `both`. |
| `COLDPIN_HTTP_HOST` | `127.0.0.1` | Bind address (keep `127.0.0.1` behind a TLS reverse proxy / Cloud Run ingress). |
| `COLDPIN_HTTP_PORT` | `8787` | TCP listen port (`0..65535`). |
| `COLDPIN_HTTP_ALLOWED_HOSTS` | Resource host | Comma-separated additional `Host` headers permitted by anti-DNS-rebinding policy. |
| `COLDPIN_HTTP_ALLOWED_ORIGINS` | None (non-browser) | Comma-separated browser `Origin` allowlist (requests without `Origin` pass; unknown browser origins get `403`). |
| `COLDPIN_HTTP_RATE_LIMIT_PER_MIN` | `60` | Per-principal sliding-window request limit per minute (returns `429` + `Retry-After`). |
| `COLDPIN_HTTP_ALLOW_LOOPBACK_INSECURE` | `0` (false) | Set to `1` strictly for local loopback testing over `http://127.0.0.1`. |
| `COLDPIN_OAUTH_ISSUER` | Required (oauth/both) | Expected JWT `iss` claim (exact match after trailing-slash normalization). |
| `COLDPIN_OAUTH_AUTH_SERVERS` | Falls back to issuer | Comma-separated RFC 9728 `authorization_servers` URIs advertised to MCP clients. |
| `COLDPIN_OAUTH_REQUIRED_SCOPE` | `coldpin:read` | Required JWT `scope` or `scp` entry; missing scope returns `403 insufficient_scope`. |
| `COLDPIN_OAUTH_JWKS_URL` | OAuth (XOR path) | HTTPS JWKS endpoint fetched via SSRF-guarded `fetchJwksJson()` (5-min TTL, 10s min refresh). |
| `COLDPIN_OAUTH_JWKS_PATH` | OAuth (XOR URL) | Local filesystem JWKS JSON file for offline or air-gapped OAuth key pinning. |
| `COLDPIN_MCP_API_KEY_SHA256` | Required (api_key/both) | Comma-separated 64-hex SHA-256 digests of `>= 32`-char `cpk_live_*` read-only keys (raw keys never stored on server). |

## Antigravity Remote HTTP & Cloud Run Config Templates

Coldpin ships three ready-to-adapt client entries in `examples/mcp_config.http-remote.example.json` covering OAuth 2.1 CIMD, scoped API key `variables`, and Google Cloud Run `google_credentials` ADC:

```json
{
  "mcpServers": {
    "coldpin-oauth-cimd": {
      "serverUrl": "https://coldpin.acme.internal/mcp",
      "timeoutSeconds": 300
    },
    "coldpin-api-key": {
      "serverUrl": "https://coldpin.acme.internal/mcp",
      "headers": {
        "Authorization": "Bearer ${COLDPIN_MCP_API_KEY}"
      },
      "timeoutSeconds": 300,
      "variables": [
        {
          "name": "COLDPIN_MCP_API_KEY",
          "title": "Coldpin Scoped MCP API Key (Optional)",
          "description": "Read-only >=256-bit cpk_live_* bearer key verified via constant-time SHA-256 on self-hosted lib/mcp-http.mjs. Leave unset when using OAuth 2.1 CIMD or Google Cloud Run ADC.",
          "sensitive": true,
          "required": false,
          "link": "https://coldpin-docs.pages.dev/#configuration"
        }
      ]
    },
    "coldpin-cloud-run-adc": {
      "serverUrl": "https://coldpin.acme.internal/mcp",
      "authProviderType": "google_credentials",
      "timeoutSeconds": 300
    }
  }
}
```

## Zero-Dependency Inline MCP App (ui://coldpin/evidence-card.html)

Resource `ui://coldpin/evidence-card.html` (`text/html;profile=mcp-app`, `SEP-1865` / `io.modelcontextprotocol/ui`) renders interactive read-only `Title + Info + Evidence` cards inline in Antigravity (`>= v2.34.0`) while hosts without MCP App support continue receiving compact JSON/Markdown summaries automatically.

- **Linked tools (4): **`inspect_package_artifact`, `resolve_safe_anchor`, `verify_confusion`, and `audit_manifest_batch` declare `_meta.ui.resourceUri` while holding `tools/list` at `1,628 <= 1,800` tokens.
- **Security invariants (SS-18): **Default-deny CSP (`csp: {}`, `default-src 'none'`), zero external URLs, strict `createElement`/`textContent` DOM rendering (zero `innerHTML`), copy-only command button (never executes), Antigravity `--color-*` theme tokens, and read-only `get_artifact_report` paging.

> **TIP — Try the Real MCP App Card Live:** Interact with Coldpin's real compiled `ui://coldpin/evidence-card.html` card across all 4 verdicts and test live `get_artifact_report` paging in the [Interactive Policy Lab](https://coldpin-docs.pages.dev/docs/policy-lab/#verdict-explorer).

## Disabled-by-Default Scheduled Weekly Audit Sidecar

Organizations wanting recurring weekly supply-chain audits can opt into `examples/sidecar.weekly-audit.example.json`. Per `SS-17-SIDECAR-LEAST-PRIV`, no active `sidecars/` directory ships at the plugin root, and `agent_permissions.access_grants` permits strictly three read-only Coldpin MCP tools (zero shell or file-write grants):

```json
{
  "display_name": "Coldpin Weekly Dependency Audit",
  "description": "Read-only weekly supply-chain screening of package.json and .npmrc using Coldpin MCP (disabled by default; copy to ~/.gemini/config/sidecars/coldpin-weekly-audit/sidecar.json and enable explicitly).",
  "builtin": "schedule",
  "restart_policy": "always",
  "args": [
    "CRON_TZ=UTC 0 9 * * 1",
    "agentapi",
    "new-conversation",
    "--",
    "In ${workspace_dir}, run Coldpin audit_manifest_batch and verify_confusion on package.json in strictly read-only mode. Summarize flagged dependencies, private-scope confusion findings, unknowns, and exact pinned upgrade candidates without running shell commands or editing files."
  ],
  "arguments": [
    {
      "key": "workspace_dir",
      "description": "Workspace folder containing package.json to screen weekly",
      "workspace_arg": {}
    }
  ],
  "agent_permissions": {
    "workspace_uris": [
      "${workspace_dir}"
    ],
    "access_grants": [
      "mcp(coldpin_coldpin/audit_manifest_batch)",
      "mcp(coldpin_coldpin/verify_confusion)",
      "mcp(coldpin_coldpin/get_artifact_report)"
    ]
  }
}
```

```sh
mkdir -p ~/.gemini/config/sidecars/coldpin-weekly-audit
cp examples/sidecar.weekly-audit.example.json ~/.gemini/config/sidecars/coldpin-weekly-audit/sidecar.json
```

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
