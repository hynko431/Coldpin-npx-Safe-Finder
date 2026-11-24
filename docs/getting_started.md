# Getting Started with `coldpin` (Coldpin)

## Prerequisites

- **Node.js `>= 24.0.0`** (verified on `v24.1.0`; uses native TypeScript type-stripping, `node:sqlite`, `node:zlib`, `node:crypto`, `node:module`, `node:test`, and `fetch` — zero `npm install` required).
- **Git `>= 2.25`** (required for `resolve-anchor` commit history walks and local tarball-vs-Git parity checks).
- **Python `>= 3.11`** (zero external pip packages; used only for skill lint, hygiene, staleness, static eval, SkillSpector self-audit, and reproducible bundle packaging).
- **Optional Tier-2 Deep Forensics:** A pre-registered REA (`rea-agents`) MCP server or pre-installed `rea` binary on `PATH` when inspecting obfuscated bundles or native `.node`/WASM/ELF/PE/Mach-O artifacts. Never bootstrap REA with `npx -y rea-agents`.

## Setup

Clone the repository directly (no `npm install` step required):

```sh
git clone https://github.com/hynko431/Coldpin-npx-Safe-Finder.git
cd Coldpin-npx-Safe-Finder
node --no-warnings lib/cli.mjs --help
node --no-warnings lib/mcp.mjs   # or: coldpin mcp
```

## Core Workflow Loop

1. **Configure Enterprise Policy (Optional for Public Use, Required for Private Orgs):**
   Copy [examples/.coldpin.policy.example.json](../examples/.coldpin.policy.example.json) and [examples/.npmrc.example](../examples/.npmrc.example) into your repository root declaring `private_scopes`, `private_prefixes`, `private_registries`, `cooldown_hours`, and CVE/KEV thresholds. In MCP mode, pin operator policy via `COLDPIN_POLICY_PATH` and allowed local roots via `COLDPIN_ALLOWED_ROOTS` (or use [examples/mcp_config.private-registry.example.json](../examples/mcp_config.private-registry.example.json) with Antigravity `variables`). See [enterprise-policy-schema.md](../skills/coldpin/references/enterprise-policy-schema.md).
2. **Discover Candidates (`discover`):**
   ```sh
   node --no-warnings src/cli.ts discover "lint" --category cli --limit 10
   ```
   Filters out denied orgs and flags 7 typosquatting/slopsquatting mutation primitives before any tarball is downloaded.
3. **Inspect Before Running (`inspect`):**
   ```sh
   node --no-warnings src/cli.ts inspect <pkg>@<ver>
   ```
   Or offline against a downloaded tarball and local Git checkout:
   ```sh
   node --no-warnings src/cli.ts inspect --tarball ./pkg.tgz --git-dir ./repo --offline --audit-log ./audit.jsonl
   ```
   Inspect the returned `Title + Info + Evidence` card, verify the `verdict` and `unknowns`, and export `--sarif` (GitHub Code Scanning) or `--sbom` (CycloneDX 1.5) when needed.
4. **Recover When Compromised (`resolve-anchor`):**
   When `inspect` returns exit code `3` (`MALICIOUS_INDICATORS_FOUND`) or `2` (`QUARANTINE_SUSPICIOUS`), run:
   ```sh
   node --no-warnings src/cli.ts resolve-anchor <pkg> --git-dir ./repo --window 200
   ```
   This pinpoints the patient-zero commit, scans unique Git blobs once via the Split-Plane SQLite cache, checks residual CVEs/KEV on the last clean commit, and tells you whether a verified npm tarball rollback (`ROLLBACK_TO_SAFE_ANCHOR`) is safe or whether you must switch to an alternative (`SWITCH_TO_ALTERNATIVE`).
5. **Audit Workspace Dependency Confusion (`verify-confusion`):**
   ```sh
   node --no-warnings src/cli.ts verify-confusion ./package.json
   ```
6. **Verify Local Audit Trail (`audit-verify`):**
   ```sh
   node --no-warnings src/cli.ts audit-verify ./audit.jsonl
   ```

## Full Verification Suite

Run all automated pipeline commands (`42/42` core/MCP/plugin/Phase-E tests + docs-site verification suite, 13-manifest & vertical-slice lint, hygiene, staleness, static eval, SkillSpector `SS-03`–`SS-18` self-audit, 49-fixture/38-mutation benchmark verification, dual DSSE signature verification, and reproducible multi-host packaging) with one command:

```sh
npm run verify:all
```

See [TESTING.md](../TESTING.md) for the exact scope of each gate and what remains outside offline automated coverage.
