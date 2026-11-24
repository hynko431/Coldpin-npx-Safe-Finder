# 7 MCP Tools, Resources & Prompts

> **Coldpin v1.6.0** · Section: MCP & CLI · Available on: Local stdio (lib/mcp.mjs), Self-Hosted HTTP (lib/mcp-http.mjs), Official MCP Registry
> Canonical HTML: https://coldpin-docs.pages.dev/docs/mcp-tools/

Coldpin exposes a static, plain-English MCP catalog (`MCP 2025-11-25`, `2025-06-18`, `2025-03-26`) pinned cryptographically in `catalog/mcp-schema-pin.json` at `1,628 <= 1,800` estimated tokens (`6,509 chars`). Control-plane parameters (`policy_path`, writable `audit_log_path`, `override_ticket_id`) are permanently omitted from tool schemas.

## 7 Read-Only MCP Tools

| Tool Name | Description | Parameters (* = required) | Posture |
| --- | --- | --- | --- |
| `discover_packages` | Search npm packages by query, org, creator, or category with slopsquat, cooldown, policy, and OSV preview verdicts. | `query*, org, creator, category, limit, detail` | Read-only |
| `inspect_package_artifact` | Inspect an npm package or local .tgz cold in memory for taint, lifecycle hooks, Git parity, provenance, and OSV/KEV. | `package_spec, tarball_path, git_dir, subdir, offline, detail, format` | Read-only · MCP App Card |
| `resolve_safe_anchor` | Walk Git history to locate patient-zero compromise commit and recommend a clean pre-compromise release or alternative. | `package_name*, git_dir, repo_url, subdir, window, detail` | Read-only · MCP App Card |
| `verify_confusion` | Audit a root-confined package.json and .npmrc for unpinned private scopes or dependency confusion risks (T1195.001). | `manifest_path, check_public` | Read-only · MCP App Card |
| `audit_verify` | Read-only verification of a root-confined hash-chained Coldpin audit.jsonl log for sequence gaps or tampering. | `audit_log_path*` | Read-only |
| `audit_manifest_batch` | Batch-screen up to 50 direct dependencies from a root-confined package.json for squats, policy, private scopes, and OSV/KEV. | `manifest_path, include_dev, max_deps, offline, detail` | Read-only · MCP App Card |
| `get_artifact_report` | Page through a session-scoped Coldpin report section (observations, iocs, unknowns, commits, card, sarif, sbom) by report_id. | `report_id*, section*, offset, limit` | Read-only |

## Resources, Templates & Prompts

| Type | URI / Name | MIME / Arguments | Purpose |
| --- | --- | --- | --- |
| Resource | `coldpin://policy/active` | `application/json` | Sanitized active operator policy, SHA-256 hash, authorized root count, and host capabilities (zero secrets). |
| Resource | `ui://coldpin/evidence-card.html` | `text/html;profile=mcp-app` | Zero-dependency interactive read-only Title + Info + Evidence card (default-deny CSP, copy-only commands). |
| Template | `coldpin://reports/{report_id}` | `application/json` | Read-only summary of a session-scoped Coldpin report stored in ephemeral memory. |
| Prompt | `vet_before_npx` | `package_spec*, git_dir` | Vet an npm package cold with Coldpin before approving any pinned npx command. |
| Prompt | `investigate_compromised_org` | `package_name*, repo_url` | Identify patient-zero compromise commit and safe rollback anchor or vetted alternative for an npm package. |

## Transport, Concurrency & Schema Pin Guarantees

- **Framing & stdio safety: **Byte-buffered LF/CRLF framing with `1 MiB` cap, `stdout` hijack guard, and `drain` backpressure.
- **3-tier workspace root confinement: **Resolves allowed local roots from operator `COLDPIN_ALLOWED_ROOTS` and MCP `roots/list` (blocking symlink escapes, path traversal, and NTFS ADS).
- **Bounded concurrency & session LRU: **Semaphore caps `maxConcurrent=4` / `maxQueue=16` with `notifications/cancelled` support; ephemeral LRU holds max `25` reports / `30 min` TTL / `15 MiB` cap (never persisted to SQLite).
- **Rug-pull schema pin (SS-11): **Live `tools/list` + `resources/list` + `prompts/list` canonical SHA-256 `9e997561b1a4dd1f...` is verified automatically on every build and self-audit.

---

*Coldpin v1.6.0 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
