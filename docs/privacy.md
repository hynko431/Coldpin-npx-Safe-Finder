<!-- SPDX-License-Identifier: Apache-2.0 -->

# Data Handling & Privacy Notice (`coldpin`)

`coldpin` is a local Node.js CLI, zero-dependency `stdio` MCP server (`lib/mcp.mjs`), and agent skill package. It does not operate a hosted backend service, telemetry endpoint, analytics collector, or external database. It requires no separate `coldpin` account or license key.

## Local Inputs and Outputs

- **Inputs read locally:** CLI arguments or MCP tool parameters, operator startup environment variables (`COLDPIN_POLICY_PATH`, `COLDPIN_ALLOWED_ROOTS`, `COLDPIN_AUDIT_LOG`, `COLDPIN_CACHE_DIR`, `COLDPIN_OFFLINE`, and optional enterprise `COLDPIN_PRIVATE_SCOPES`, `COLDPIN_PRIVATE_REGISTRY_URL`, `COLDPIN_REGISTRY_TOKEN` — rejecting any literal unexpanded `${VAR}` placeholder), `.npmrc` (`:_authToken` read strictly from `$HOME/.npmrc` or operator-pinned config, never untrusted workspace `.npmrc`), `.coldpin.policy.json` (or legacy `.npx-guard.policy.json`), local `package.json`, `package-lock.json`, `pnpm-lock.yaml`, and `yarn.lock` (when running `verify-confusion` or workspace compromise checks), local tarballs (`--tarball` / `tarball_path`), and local Git directories (`--git-dir` / `git_dir`).
- **Local persistence:**
  - Split-Plane SQLite cache (`%LOCALAPPDATA%\coldpin\cache.sqlite` on Windows, `~/.cache/coldpin/cache.sqlite` on POSIX, or `${PLUGIN_DATA}/cache.sqlite` in Antigravity, with owner-only `0700`/`0600` POSIX permissions and direct `:memory:` fallback — never shared `/tmp`) storing structural static observations and base-URL-namespaced TTL-bounded OSV advisory payloads.
  - Ephemeral session-only bounded LRU report store in MCP server memory (max `25` reports, `30`-minute TTL, `15 MiB` total cap) — never persisted to SQLite.
  - Optional local append-only `audit.jsonl` (only written when `--audit-log <file>` or operator `COLDPIN_AUDIT_LOG` is explicitly set), storing a SHA-256 pseudonymous `actor_id_hash` instead of raw usernames or emails.
- **No automatic retention enforcement locally:** Local cache and audit files remain on disk until deleted or shipped to an enterprise WORM log archive by the user or organization.

## Outbound Network Egress & Private-Scope Isolation

- **Offline mode (`--offline` / `COLDPIN_OFFLINE=1`):** Performs zero outbound network requests (including blocking remote `git clone`) and fails closed (`UNVERIFIABLE_UNKNOWN` / `OFFLINE_MODE_GIT_CLONE_BLOCKED`) when live threat intelligence is unavailable.
- **Public package inspection (online):** Contacts the configured npm registry (`https://registry.npmjs.org` by default) to retrieve package metadata, tarballs, and declared SLSA attestation bundles (`dist.attestations.url`, suppressed if off-origin for private scopes), `https://api.osv.dev` for OSV/OpenSSF `MAL-*` advisories, and the declared HTTPS Git remote only when `resolve-anchor` is invoked with a remote URL (with Git HTTP redirects disabled).
- **Private-scope non-leakage guarantee:** Any package matching `private_scopes`, `private_prefixes`, or private `.npmrc` scoped registries NEVER queries public `registry.npmjs.org` or `api.osv.dev`. Scopes within 1 edit or adjacent transposition of a configured private scope (`@amce` vs `@acme`) are hard-blocked (`blocked_typo`) before any network request is made. In MCP mode, `verify_confusion(check_public: true)` is suppressed unless the operator explicitly sets `COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE=1`.
- **Secrets handling:** Registry authentication tokens (`_authToken=${ENV_VAR}` in `$HOME/.npmrc` or optional operator `COLDPIN_REGISTRY_TOKEN`) are read strictly from process environment variables, rejected if they contain unexpanded `${VAR}` placeholders, matched only by exact host or `/`-segment boundary, sent only over `https://` to their matching private registry origin (never to public `registry.npmjs.org`), and never written to stdout, stderr, SQLite cache, SARIF, SBOM, audit logs, or LLM prompt context.

## Host Agent Processing

When invoked through an AI agent harness (Antigravity, Claude Code, Codex, Cursor), the selected host processes prompts and tool/CLI outputs under that host's own account terms and privacy policy. `coldpin` exposes a strictly local `stdio`-only default MCP server (`lib/mcp.mjs`, zero listening network sockets, operator-only control plane), an inline zero-network MCP App (`ui://coldpin/evidence-card.html`, default-deny CSP `csp: {}`), read-only aspect subagents, and fail-safe `PreToolUse` guarding hooks with zero auto-approval (`hooks.json` → `lib/hook.mjs`, zero network calls). Organizations choosing to self-host the opt-in Streamable HTTP adapter (`lib/mcp-http.mjs`) operate it on their own infrastructure (VPC / Cloud Run) under their own OAuth 2.1 IdP or SHA-256-hashed API keys; Coldpin's maintainer never receives tokens, prompts, or scan telemetry.

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
