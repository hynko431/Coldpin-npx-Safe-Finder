# Privacy & Data Handling

> **Coldpin v1.6.0** · Section: Enterprise & Security · Available on: Local CLI & stdio MCP, Offline Mode, Self-Hosted HTTP MCP
> Canonical HTML: https://coldpin-docs.pages.dev/docs/privacy/

Coldpin operates no hosted backend service, telemetry endpoint, analytics collector, cookies, or external database. No account or license key is required, and this documentation portal itself collects zero analytics and sets zero cookies.

## Local Inputs & Persistence Boundaries

- **Split-Plane SQLite Cache: **Stored locally at `%LOCALAPPDATA%\coldpin\cache.sqlite` (Windows), `~/.cache/coldpin/cache.sqlite` (POSIX), or `${PLUGIN_DATA}/cache.sqlite` (Antigravity) with owner-only `0700`/`0600` permissions and direct `:memory:` fallback (never shared `/tmp`). Caches structural static facts and base-URL-namespaced TTL-bounded OSV payloads.
- **Ephemeral Session LRU: **MCP server report paging keeps at most `25` reports (`30-minute` TTL, `15 MiB` cap) strictly in process memory — never persisted to SQLite.
- **Optional Local Audit Trail: **Written only when `--audit-log` or `COLDPIN_AUDIT_LOG` is explicitly set; records a pseudonymous SHA-256 `actor_id_hash` rather than raw usernames or email addresses.
- **Retention Control: **Coldpin enforces no remote retention; local cache and JSONL logs stay under operator control until purged or archived to enterprise WORM storage.

## Outbound Network Egress & Secrets Handling

| Mode / Target | Endpoints Contacted | Privacy & Token Controls |
| --- | --- | --- |
| Offline (`--offline` / `COLDPIN_OFFLINE=1`) | None (0 outbound requests; remote `git clone` blocked) | Fails closed as `UNVERIFIABLE_UNKNOWN` / `OFFLINE_MODE_GIT_CLONE_BLOCKED` |
| Public Package Inspection | `registry.npmjs.org`, `api.osv.dev`, declared HTTPS Git remote (on `resolve-anchor`) | Pre-flight DNS IP guard blocks loopback, IMDS, RFC 1918, CGNAT, ULA; streaming byte caps before `JSON.parse`; Git HTTP redirects disabled |
| Private Scope / Prefix Inspection | Configured HTTPS private registry ONLY (zero public npm or OSV queries) | Token parsed only from `$HOME/.npmrc` or operator `COLDPIN_REGISTRY_TOKEN` (never untrusted workspace `.npmrc`), exact-host HTTPS only, stripped on cross-origin redirect (`CWE-200`) |

## Host Agent Processing

When invoked inside an AI host (Antigravity, Claude Code, Codex, Cursor), prompts and tool responses are governed by that host's privacy policy. Coldpin's default MCP server is local `stdio`-only, its inline MCP App enforces default-deny CSP (`csp: {}`) with zero network calls, and self-hosted `lib/mcp-http.mjs` runs entirely on the customer's own VPC/Cloud Run under their own IdP — Coldpin's maintainer never receives tokens, prompts, or scan telemetry.

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
