# Fail-Safe PreToolUse Hooks

> **Coldpin v1.6.2** · Section: Plugin & Guardrails · Available on: Antigravity >= v1.5.13, Node 18/20/22/24/26 (ES2020)
> Canonical HTML: https://coldpin-docs.pages.dev/docs/hooks/

Coldpin ships 3 default-enabled `PreToolUse` hook groups in root `hooks.json` backed by pure ES2020 `src/hook-core.ts` + `src/hook.ts` → `./lib/hook.mjs`. The exact same engine powers the browser [Interactive Policy Lab](https://coldpin-docs.pages.dev/docs/policy-lab/).

## Binary-Verified Antigravity Hook Contract

- **Explicit allow pass-through: **Benign commands emit `{"decision":"allow"}` (exit `0`) — emitting `{}` is rewritten to `deny` by Antigravity's `applyPreToolHooks`, whereas `allow` delegates cleanly to default policy without auto-approval.
- **Zero auto-approval tokens: **`SS-08-HOOK-LEAST-PRIV` forbids `auto_approve`, `permissionOverrides`, `overwrite`, `allowTool`, and any network/subprocess API in both `src/hook.ts` and `src/hook-core.ts`.
- **Exit 0 in 100% of paths: **Top-level `uncaughtException`, `unhandledRejection`, empty stdin, and malformed JSON all emit `{"decision":"force_ask",...}` and exit `0` to neutralize host fail-open on non-zero exit.
- **Bounded stdin + fast-path edits: **Commands over `256 KiB` fail closed with `deny`; legitimate file edits over `256 KiB` (up to `8 MiB`) scan the first `16 KiB` JSON header linearly so large source-code writes never trigger false prompts.

## Root hooks.json Configuration

```json
{
  "coldpin-npx-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command|manage_task",
        "hooks": [
          {
            "type": "command",
            "command": "node --no-warnings ./lib/hook.mjs",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "coldpin-config-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "write_to_file|replace_file_content|multi_replace_file_content|write_file|edit_file|sed_file",
        "hooks": [
          {
            "type": "command",
            "command": "node --no-warnings ./lib/hook.mjs",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "coldpin-delegation-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "define_subagent",
        "hooks": [
          {
            "type": "command",
            "command": "node --no-warnings ./lib/hook.mjs",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

## Multi-Shell Evasion & Config Tamper Matrix

| Vector / Category | Example Input | Hook Decision | Hook Group |
| --- | --- | --- | --- |
| Quoted / escaped / backtick / path-qualified `npx` | `n""px evil-pkg`, `n`px evil`, `C:\nodejs\npx.cmd evil` | `deny` | `coldpin-npx-guard` |
| Shell wrappers & subshells | `sh -c "npx evil"`, `cmd /c npx evil`, `echo $(npx evil)` | `deny` | `coldpin-npx-guard` |
| Alternative runners & remote initializers | `pnpm dlx`, `yarn dlx`, `bunx`, `corepack`, `npm init create-x` | `deny` | `coldpin-npx-guard` |
| Download-and-execute pipes & interactive stdin | `curl https://... \| sh`, `irm ... \| iex`, `manage_task(send_input)` | `deny` | `coldpin-npx-guard` |
| Exact-pinned Coldpin `--ignore-scripts` standalone | `npx --ignore-scripts coldpin@1.6.2 mcp`, `npx --yes --ignore-scripts --package=semver@7.7.1 -- semver` | `force_ask` | `coldpin-npx-guard` |
| Sensitive config edits (all 6 file-edit tools + shell) | `.npmrc`, `.coldpin.policy.json`, `hooks.json`, `mcp_config.json`, `lib/hook.mjs`, `agy plugin disable` | `force_ask` | `coldpin-config-guard` |
| Writable dynamic subagent requests | `define_subagent({ EnableWriteTools: true })` | `force_ask` | `coldpin-delegation-guard` |

> **CAUTION — Layer-1 Guardrail Boundaries:** Because Antigravity fails open if `node` is missing on `PATH` or a hook times out, and because argument inspection cannot observe compiled binaries or pre-existing shell aliases, always pair Coldpin hooks with OS sandboxing and the companion `catalog/sigma/` EDR rules.

---

*Coldpin v1.6.2 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
