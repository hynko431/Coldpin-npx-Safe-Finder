# CLI Reference & Exit Codes

> **Coldpin v1.6.1** · Section: MCP & CLI · Available on: Standalone CLI, GitHub Actions / CI, Node.js >= 24
> Canonical HTML: https://coldpin-docs.pages.dev/docs/cli-reference/

Both the standalone CLI (`lib/cli.mjs` / `coldpin`) and the MCP servers execute the exact same pure async workflows under `src/core/workflows.ts`.

## 6 Canonical CLI Verbs (+ mcp Dispatch)

| CLI Verb | MCP Equivalent | Exit Codes | Description |
| --- | --- | --- | --- |
| `discover [query]` | `discover_packages` | `0 / 2 / 1` | Search npm by capability, category, org, or creator with org allow/deny policy, release cooldown, and 7-primitive typosquat/slopsquat filters. |
| `inspect <pkg[@ver]>` | `inspect_package_artifact` | `0 / 2 / 3 / 1` | Zero-execution tarball inspection, SHA-512 check, lexical JS/TS taint, hidden-Unicode scan, OSV/MAL-*, and 3-tier tarball-to-Git parity. |
| `resolve-anchor <pkg>` | `resolve_safe_anchor` | `0 / 2 / 3 / 1` | Walk `--first-parent` Git history with blob-cached SQLite scans to locate patient-zero and verify a clean npm tarball rollback or alternative. |
| `verify-confusion [path]` | `verify_confusion` | `0 / 3 / 1` | Audit `package.json` and `.npmrc` for unpinned private scopes and claimable internal names (`T1195.001`). |
| `audit-batch [path]` | `audit_manifest_batch` | `0 / 2 / 3 / 1` | Batch-screen up to 50 direct dependencies from `package.json` with private-scope OSV non-leakage. |
| `audit-verify <jsonl>` | `audit_verify` | `0 / 3 / 1` | Verify sequence continuity, extra-field tamper protection, and SHA-256 hash chain of local `audit.jsonl` files. |
| `mcp` | Server entrypoint | `0 / 1` | Start local zero-dependency JSON-RPC 2.0 `stdio` MCP server (`lib/mcp.mjs`). |

## Deterministic Exit Codes

| Exit Code | Meaning | Typical Verdicts / CI Action |
| --- | --- | --- |
| `0` | Clean within scope / Pass | `VERIFIED_CLEAN_WITHIN_SCOPE`, `USE_PINNED_LATEST`, valid `audit.jsonl`, `--version` / `-V` |
| `2` | Suspicious, quarantined, or unverifiable | `QUARANTINE_SUSPICIOUS`, `UNVERIFIABLE_UNKNOWN`, `FORENSIC_COMMIT_ONLY` — fail closed in CI until reviewed |
| `3` | Malicious indicators or policy block | `MALICIOUS_INDICATORS_FOUND`, dependency confusion found, tampered `audit.jsonl` — halt build immediately |
| `1` | Invalid usage or operational error | Unknown flag, missing required value, Node < 24, or unreadable local target |

## Common Flags & Output Formats

| Flag | Applies To | Behavior |
| --- | --- | --- |
| `--json` | All verbs | Emit canonical JSON report to `stdout` |
| `--sarif` | `inspect` | Emit OASIS SARIF 2.1.0 JSON for GitHub Code Scanning |
| `--sbom` | `inspect` | Emit OWASP CycloneDX 1.5 SBOM + VEX JSON (with `coldpin:provenance-status`) |
| `--tarball <file.tgz>` | `inspect` | Inspect a local `.tgz` archive directly in memory |
| `--git-dir <dir>` / `--repo-url <url>` | `inspect`, `resolve-anchor` | Local Git checkout or HTTPS remote (redirects & Git hooks disabled) |
| `--offline` | All network verbs | Forbid all outbound HTTP requests and remote `git clone` (fails closed) |
| `--limit <1..50>` / `--include-dev` | `discover`, `audit-batch` | Bound result count (max 50 direct deps for `audit-batch`) or include `devDependencies` |
| `--policy <file>` / `--audit-log <file>` | All verbs | Explicit `.coldpin.policy.json` path or append-only hash-chained `audit.jsonl` |
| `--override-ticket <id>` | `inspect` | Record approval ticket ID in `audit.jsonl` (never alters deterministic verdict) |
| `--verbose` / `--version` (`-V`) | All verbs | Structured JSON operational logs on `stderr` or print `coldpin v1.6.1` |

---

*Coldpin v1.6.1 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
