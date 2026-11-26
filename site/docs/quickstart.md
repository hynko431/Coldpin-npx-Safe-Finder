# Quickstart Install

> **Coldpin v1.6.2** · Section: Get Started · Available on: Antigravity >= v1.5.13, Node.js >= 24, Git >= 2.25, Offline / Air-Gapped
> Canonical HTML: https://coldpin-docs.pages.dev/docs/quickstart/

Coldpin runs 100% locally with zero mandatory credentials, zero npm runtime dependencies, and **$0/mo** steady-state cost. Pick an install method and run your first cold tarball inspection.

## Prerequisites

- **Node.js **`>= 24.0.0` — uses native TypeScript type-stripping, `node:sqlite`, `node:zlib`, `node:crypto`, and `fetch` with zero `npm install` required.
- **Git **`>= 2.25` — required for `resolve-anchor` commit history walks and local tarball-vs-Git parity checks.
- **Antigravity **`>= v1.5.13` — required for native `PreToolUse` hooks; `>= v2.34.0` enables inline SEP-1865 MCP App evidence cards.
- **Optional Tier-2 Forensics (REA): **A pre-registered `rea-agents` MCP server or pre-installed `rea` binary on `PATH` for compiled `.node`/WASM/ELF/PE/Mach-O binaries. Never run `npx -y rea-agents`.

## Install Methods

### Antigravity Plugin

```sh
agy plugin install https://github.com/hynko431/Coldpin-npx-Safe-Finder
agy plugin list
agy --agent coldpin-auditor
```

Enables immediately with zero required variables: 3 skills, 7 read-only aspect agents, 3 Markdown rules, 3 `PreToolUse` hook groups, and 1 local `stdio` MCP server.

### npm / Standalone CLI

```sh
npx --ignore-scripts coldpin@1.6.2 mcp
npx --ignore-scripts coldpin@1.6.2 inspect semver@7.7.1
npx --ignore-scripts coldpin@1.6.2 audit-batch ./package.json --limit 50
```

Published as [coldpin@1.6.2](https://npmjs.com/package/coldpin) on npm and indexed in the [Official MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.hynko431/coldpin) as `io.github.hynko431/coldpin`.

### SLSA Release Bundle

```sh
sha256sum -c SHA256SUMS.txt
python -m zipfile -e coldpin-antigravity.zip ./coldpin-antigravity
agy plugin validate --strict ./coldpin-antigravity
agy plugin install ./coldpin-antigravity
```

### Offline / Air-Gapped

```sh
COLDPIN_OFFLINE=1 node --no-warnings lib/cli.mjs inspect \
  --tarball ./vendor/pkg.tgz \
  --git-dir ./vendor/repo \
  --offline --sarif --audit-log ./audit.jsonl
```

## Core 5-Step Audit Workflow

1. **Configure private-scope isolation (optional for public repos, required for enterprises)**
   Declare internal `private_scopes` and `private_prefixes` in `.coldpin.policy.json` or `COLDPIN_PRIVATE_SCOPES` so internal names never leak to public `registry.npmjs.org` or `api.osv.dev`. See [Configuration & Private Scopes](https://coldpin-docs.pages.dev/docs/configuration/).

2. **Discover candidates with 7-primitive slopsquat defense**
   Filter out denied orgs, young cooldown releases, and typosquats before downloading any archive.

```sh
node --no-warnings lib/cli.mjs discover "json formatter" --category cli --limit 10
```

3. **Inspect a package or offline tarball cold in memory**
   Verifies SHA-512 integrity, unpacks strictly in memory, runs linear-time JS/TS lexical taint and hidden-Unicode triage, checks OSV/`MAL-*`, and verifies 3-tier tarball-to-Git parity.

```sh
node --no-warnings lib/cli.mjs inspect semver@7.7.1
node --no-warnings lib/cli.mjs inspect --tarball ./pkg.tgz --git-dir ./repo --offline --sarif
```

4. **Batch-screen package.json & audit dependency confusion**
   Screen up to 50 direct dependencies locally and check `.npmrc` for `T1195.001` dependency confusion risks.

```sh
node --no-warnings lib/cli.mjs audit-batch ./package.json --limit 50
node --no-warnings lib/cli.mjs verify-confusion ./package.json
```

5. **Recover a clean pre-compromise anchor & verify audit trail**
   When `inspect` returns exit code `3` (`MALICIOUS_INDICATORS_FOUND`), pinpoint the patient-zero commit and verify hash-chained `audit.jsonl` logs.

```sh
node --no-warnings lib/cli.mjs resolve-anchor @org/tool --git-dir ./repo --window 200
node --no-warnings lib/cli.mjs audit-verify ./audit.jsonl
```

> **NOTE — Keyboard Shortcuts in This Portal:** Press `Ctrl` + `K` (or `/`) anywhere to open instant documentation search, use `↑` / `↓` and `Enter` to jump directly to any section, and `Esc` to close.

---

*Coldpin v1.6.2 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
