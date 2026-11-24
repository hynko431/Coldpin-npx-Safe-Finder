# Interactive Policy Lab

> **Coldpin v1.6.1** · Section: Get Started · Available on: Browser Sandbox (0 Network), Exact lib/hook.mjs Engine, Live SEP-1865 MCP App
> Canonical HTML: https://coldpin-docs.pages.dev/docs/policy-lab/

Everything below runs 100% locally in your browser with zero outbound network requests. The Hook Simulator executes `site/hook-eval.js` compiled directly from Coldpin's real `src/hook-core.ts` engine (100% parity with `lib/hook.mjs`), and the Verdict Explorer feeds live SEP-1865 JSON-RPC messages into Coldpin's real `ui://coldpin/evidence-card.html` MCP App.

## PreToolUse Hook Simulator (Exact lib/hook.mjs Engine)

Choose an intercepted tool and type any command, file path, subagent delegation payload, or raw JSON stdin. Coldpin's pure ES2020 hook engine always exits `0` and returns strictly `allow`, `force_ask`, or `deny` — never auto-approval.

Interactive browser PreToolUse simulator running `site/hook-eval.js` compiled directly from `src/hook-core.ts` (100% parity with `lib/hook.mjs`). Always exits `0` with `allow`, `force_ask`, or `deny`.

## 4-State Verdict Explorer & Live SEP-1865 MCP App

Switch between Coldpin's 4 deterministic `TrustVerdict` states (plus `audit_manifest_batch` and `resolve_safe_anchor` responses) to inspect both the accessible text card and the live sandboxed `ui://coldpin/evidence-card.html` MCP App frame (synchronized live with your Light/Dark theme and `get_artifact_report` paging).

Interactive 4-state Verdict Explorer (`VERIFIED_CLEAN_WITHIN_SCOPE`, `QUARANTINE_SUSPICIOUS`, `MALICIOUS_INDICATORS_FOUND`, `UNVERIFIABLE_UNKNOWN`) with live sandboxed SEP-1865 MCP App preview (`ui://coldpin/evidence-card.html`).

---

*Coldpin v1.6.1 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
