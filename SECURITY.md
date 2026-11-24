<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy (`SECURITY.md`)

## Supported Versions

| Version | Supported |
|---|---|
| `1.6.x` | Yes (active maintenance; requires Antigravity `>= v1.5.13` for `PreToolUse` hooks and `>= v2.34.0` for inline MCP Apps) |
| `1.5.x` | Security fixes via upgrade to `1.6.x` |
| `1.4.x` | Security fixes via upgrade to `1.6.x` |
| `1.3.x` | Security fixes via upgrade to `1.6.x` |
| `1.2.x` | Security fixes via upgrade to `1.6.x` |
| `1.1.x` | Security fixes via upgrade to `1.6.x` |
| `1.0.x` | Security fixes via upgrade to `1.6.x` |

## Reporting a Vulnerability

If you discover a security bypass in `coldpin` (for example: an archive extraction escape, a static taint evasion, a Git argument injection, a private-scope leak, or a skill prompt-injection bypass):

1. **Do not** open a public issue containing weaponized exploit chains or live malicious package URLs.
2. Submit a confidential report via [GitHub Private Vulnerability Reporting](https://github.com/hynko431/Coldpin-npx-Safe-Finder/security/advisories/new).
3. Provide a minimal, defensive reproduction (synthetic fixture tarball, redacted CLI command, expected verdict vs. observed verdict).
4. Include your Node.js version (`node --version`), OS, and commit SHA.
5. Maintainer triage target: acknowledge within 2 business days `[Typical]`, deliver a regression test + fix before disclosure.

## Hard Security Boundaries of `coldpin`

- **Zero-Execution Inspection:** `coldpin` never runs `npm install`, `npm pack`, package lifecycle hooks, or untrusted package binaries during inspection.
- **No Self-Bootstrap:** `coldpin` never executes `npx -y rea-agents` or installs third-party analyzers silently.
- **Deterministic Verdict Authority:** The 4-state `TrustVerdict` is computed deterministically in TypeScript code outside LLM context; untrusted `README.md` or metadata strings cannot override verdicts.
- **Fail-Safe `PreToolUse` Hook Boundaries (Antigravity `>= v1.5.13`):** `lib/hook.mjs` runs as pure ES2020 with top-level error trapping exiting `0` in 100% of code paths, emitting strictly `allow`, `deny`, or `force_ask` (never auto-approval). Because Antigravity fails open if `node` is missing on `PATH` or a hook times out, and because Layer-1 argument inspection cannot catch compiled binaries or shell aliases, always pair Coldpin hooks with OS sandboxing and `catalog/sigma/` EDR detections.
- **Static Coverage Bounds:** Static analysis cannot observe runtime-only remote C2 payloads; compiled native/WASM artifacts and obfuscated bundles fail closed until inspected with REA or isolated dynamic analysis.

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
