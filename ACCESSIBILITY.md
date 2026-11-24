<!-- SPDX-License-Identifier: Apache-2.0 -->

# Accessibility Statement (`ACCESSIBILITY.md`)

`coldpin` aims to keep CLI outputs, Evidence Cards, documentation, and bundled SVG assets accessible across terminals, screen readers, and AI coding harnesses.

## Implemented Practices

- **No Color-Only Signalling:** CLI verdicts (`VERIFIED_CLEAN_WITHIN_SCOPE`, `QUARANTINE_SUSPICIOUS`, `MALICIOUS_INDICATORS_FOUND`, `UNVERIFIABLE_UNKNOWN`) and exit codes (`0`, `1`, `2`, `3`) are conveyed via explicit text labels and machine-readable JSON/SARIF/SBOM fields, never via ANSI color alone.
- **Plain Structured Markdown:** `Title + Info + Evidence` cards use semantic headings (`#`, `##`, `###`), structured tables with escaped pipe characters, and plain bullet lists compatible with screen readers and Braille displays.
- **Icon Alternatives:** Canonical SVG icons (`assets/icon.svg`, `skills/coldpin/assets/icon.svg`, `site/icon.svg`) carry explicit link-purpose `alt` text when interactive (such as the header link in `README.md`) or decorative empty `alt=""` when paired with adjacent text labels. Legacy `docs/assets/readme-header.svg` (`480x116` high-contrast dark slate pill, `18.45:1` AAA, `@media (forced-colors: active)`) is retained on `main` for already-published npm `v1.5.0`–`v1.5.2` pages.
- **Deterministic Non-Interactive CLI:** All 6 CLI verbs (`discover`, `inspect`, `resolve-anchor`, `verify-confusion`, `audit-batch`, `audit-verify`) plus `mcp` work non-interactively via flags and stdin/stdout without requiring TUI cursor navigation or mouse input.
- **Accessible Static Documentation Portal (`site/`):** Meets WCAG 2.2 AA/AAA contrast across Light and Dark modes (3-way `Auto | Light | Dark` blocking `theme-init.js`), zero horizontal overflow down to `320px` (`SC 1.4.10`) with mobile `Cards | Table` switchers, `Skip to main content` landmark navigation, keyboard-accessible `Ctrl+K` / `/` search dialog with focus restoration, and `@media (prefers-reduced-motion: reduce)`, `@media (forced-colors: active)`, and `@media print` stylesheets.

## Known Limits

- Output accessibility inside third-party AI agent harnesses (Antigravity, Claude Code, Codex CLI) depends in part on each host's own terminal or IDE UI rendering.
- Report any accessibility barrier by opening an issue describing the assistive technology, harness, and affected command or document.
