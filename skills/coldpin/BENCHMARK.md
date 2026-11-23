<!-- SPDX-License-Identifier: Apache-2.0 -->

# Skill Benchmark: `coldpin`

> **Tier 1–2 Verdict: PASS (Local Deterministic Gates Verified)** · **Tier 3 Live Multi-Agent Uplift: NOT RUN (N/A)**

## Publication Recommendation

Tier 1 (static validation, hygiene, SkillSpector self-audit) and Tier 2 (49-fixture adversarial/benign corpus, cold vs. warm Split-Plane SQLite cache, 38 mutation proofs, and positive/decoy trigger selection) passed with **100.0% adversarial recall**, **0.0% false-positive rate**, and **38/38 mutation proofs**. Tier 3 live multi-agent sandbox evaluation (Antigravity / Claude Code / Codex token uplift vs. no-skill baseline) has **not** been executed in this offline environment and is recorded as `N/A` without estimation.

## Evaluation Metadata

- Skill: `coldpin` (`v1.5.2`)
- Evaluation date: `2026-11-22`
- Host runtime: `Node v24.1.0` on `win32/x64`
- Corpus: 49 deterministic fixtures (21 benign CLI archetypes + 28 adversarial/fail-closed attacks) + 38 mutation checks + 10 trigger selection prompts (5 positive + 5 negative decoys)
- Dataset digest: `sha256:fd98df56d512949385d20fa76262f124ae86e692bc5d62a98ac65167cdd67366` (`evals/evals.json` + `tests/selection.jsonl` + `tests/benchmark-corpus.ts` + `catalog/triage-rules.json`)
- Peak process RSS observed: `41.2 MiB`
- Tier 1 evidence: **Executed locally**
- Tier 2 evidence: **Executed locally**
- Tier 3 evidence: **Not run** (requires live LLM API keys + isolated sandbox containers)

## Tier Status

| Tier | Purpose | Status | Evidence |
|---|---|---|---|
| Tier 1 | Static lint, hygiene, link, secret, Unicode, manifest sync & SkillSpector self-audit | **PASSED** | `lint_skill.py`, `verify_hygiene.py`, `staleness_check.py`, `self_audit_skillspector.py` |
| Tier 2 | Deterministic 49-fixture security corpus, Git cache timings, 38 mutation proofs & trigger selection | **PASSED** | Recall `100.0%` (28/28), FPR `0.0%` (0/21), Mutations `38/38`, Selection `10/10` (5 pos + 5 decoys) |
| Tier 3 | Live multi-agent sandbox evaluation (Antigravity / Claude Code / Codex vs. no-skill baseline) | **NOT RUN (N/A)** | Requires live LLM API & isolated container sandbox; coverage is never estimated |

## Results at a Glance

| Dimension | Tier 1–2 Measured Result | Tier 3 Live Agent Uplift |
|---|---|---|
| Security (Adversarial Recall) | `100.0%` (28/28 adversarial & fail-closed fixtures caught) | `N/A` (not run) |
| Security (False-Positive Rate) | `0.0%` (0/21 benign CLIs misclassified; target `< 5%`) | `N/A` (not run) |
| Correctness (Mutation Proofs) | `100.0%` (38/38 regressions caught red) | `N/A` (not run) |
| Discoverability (Trigger Proxy) | `100.0%` (5/5 positive matched, 5/5 decoys avoided) | `N/A` (not run) |
| Latency (Tier 1 In-Memory Unpack + Triage) | Benign p50 `6.17 ms`, p95 `19.13 ms` · Adv p95 `8.81 ms` | `N/A` (not run) |
| Efficiency (Git Bisect Split-Plane SQLite Cache) | Cold `8278.1 ms` (84 intra-run hits) → Warm `3269.4 ms` (104 hits across 8 walked commits) | `N/A` (not run) |

## Executed Corpus Breakdown

| Case ID | Category | Verdict | Pass | Elapsed (ms) |
|---|---|---|---:|---:|
| `benign-01-json-formatter` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 63.84 |
| `benign-02-comments-mentioning-eval` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 18.02 |
| `benign-03-color-env-vars` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 16.92 |
| `benign-04-typescript-source` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 8.17 |
| `benign-05-short-cli-tsx` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 6.07 |
| `benign-06-short-cli-zx` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 3.86 |
| `benign-07-scoped-org-cli` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.27 |
| `benign-08-localhost-dev-server` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.25 |
| `benign-09-readme-markdown` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 6.26 |
| `benign-10-legit-eslint-target` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 3.78 |
| `benign-11-regex-url-parser` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 6.17 |
| `benign-12-map-get-cache` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.68 |
| `benign-13-template-logging` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.80 |
| `benign-14-http-client-no-creds` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 7.09 |
| `benign-15-esm-cli-args` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.97 |
| `benign-16-multifile-esm-path-join` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.60 |
| `benign-17-static-import-and-aliased-git` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 7.28 |
| `benign-18-multihop-clean-fetch-helper` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.61 |
| `benign-19-regex-var-and-array-literal` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 6.24 |
| `benign-20-esbuild-scoped-env-alias` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 9.38 |
| `benign-21-unicode-regexp-parser` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 19.13 |
| `adv-01-postinstall-curl-pipe-sh` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.62 |
| `adv-02-cred-taint-exfiltration` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.81 |
| `adv-03-folded-computed-eval` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 6.84 |
| `adv-04-base64-hidden-shell` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.67 |
| `adv-05-zip-slip-traversal` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.19 |
| `adv-06-duplicate-tar-differential` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 6.67 |
| `adv-07-zip-bomb-cap` | adversarial | `QUARANTINE_SUSPICIOUS` | PASS | 27.11 |
| `adv-08-indirect-prompt-injection-bidi` | adversarial | `QUARANTINE_SUSPICIOUS` | PASS | 5.90 |
| `adv-09-typosquat-homoglyph-es1int` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.45 |
| `adv-10-uninspected-wasm-fail-closed` | adversarial | `UNVERIFIABLE_UNKNOWN` | PASS | 5.46 |
| `adv-11-template-literal-taint-exfil` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.20 |
| `adv-12-unicode-escape-eval` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.96 |
| `adv-13-multihop-taint-dns-exfil` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.68 |
| `adv-14-child-process-curl-pipe` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 6.13 |
| `adv-15-hex-obfuscator-0x` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.13 |
| `adv-16-cross-file-split-taint` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.52 |
| `adv-17-manifest-bin-shell-injection` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.81 |
| `adv-18-path-join-ssh-key-steal` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.23 |
| `adv-19-reflect-env-and-wrapper-sink` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.70 |
| `adv-20-tar-eof-polyglot-smuggling` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.98 |
| `adv-21-computed-dynamic-import-data-uri` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.86 |
| `adv-22-aliased-esm-child-process-exec` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.31 |
| `adv-23-multihop-wrapper-and-indirect-eval` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.93 |
| `adv-24-cross-file-exported-sink-wrapper` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.71 |
| `adv-25-no-semi-indirect-call-opt-chain` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.42 |
| `adv-26-create-require-and-barrel-reexport` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.18 |
| `adv-27-closure-captured-taint` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.46 |
| `adv-28-dense-hex-escape-obfuscation` | adversarial | `QUARANTINE_SUSPICIOUS` | PASS | 6.84 |

## Mutation / Anti-Drift Verification (REA `rea-ci-tests-audit` Pattern)

| Mutation Check | Result | Observed State Transition |
|---|---|---|
| `mut-01-taint-injection-flips-verdict` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-02-audit-tamper-flips-valid` | PASS | `valid=true -> valid=false` |
| `mut-03-private-scope-typo-blocks-egress` | PASS | `private -> blocked_typo` |
| `mut-04-tarball-hook-drift-flips-parity` | PASS | `MANIFEST_PARITY_VERIFIED -> TARBALL_SOURCE_DRIFT` |
| `mut-05-template-literal-exfil-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-06-git-arg-injection-rejected` | PASS | `https=true -> opt=false, ext=false` |
| `mut-07-tarball-only-compromise-blocks-latest` | PASS | `USE_PINNED_LATEST -> ROLLBACK_TO_SAFE_ANCHOR@1.0.0` |
| `mut-08-tar-checksum-corruption-rejected` | PASS | `ok=true -> ok=false` |
| `mut-09-bin-shell-injection-blocked` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-10-cross-file-split-taint-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-11-tar-eof-smuggling-rejected` | PASS | `ok=true -> ok=false` |
| `mut-12-ipv6-mapped-ssrf-blocked` | PASS | `pub=true -> meta=false, gitLoop=false` |
| `mut-13-aliased-esm-exec-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-14-multihop-wrapper-global-env-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-15-provenance-epistemic-and-digest-tamper` | PASS | `strict_unanchored=UNVERIFIABLE_UNKNOWN -> tampered=MALICIOUS_INDICATORS_FOUND` |
| `mut-16-no-semi-opt-chain-and-prov-purl-strict` | PASS | `asi=VERIFIED_CLEAN_WITHIN_SCOPE->MALICIOUS_INDICATORS_FOUND, nonPurl=verification_failed, wrongVer=verification_failed` |
| `mut-17-scoped-shadow-vs-closure-taint` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-18-unicode-regex-vs-dense-escape-obfuscation` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> QUARANTINE_SUSPICIOUS` |
| `mut-19-mcp-workspace-policy-downgrade-blocked` | PASS | `kev=true, osv=https://api.osv.dev, added_scope=true` |
| `mut-20-mcp-audit-attribution-tamper-caught` | PASS | `valid=true -> valid=false` |
| `mut-21-offline-resolve-anchor-blocks-git-clone` | PASS | `BLOCK_NO_SAFE_PATH (OFFLINE_MODE_GIT_CLONE_BLOCKED)` |
| `mut-22-discover-fields-and-git-url-exfil-blocked` | PASS | `creator=blocked_typo, secret=blocked_secret, gitQ=false, gitUser=false` |
| `mut-23-root-confinement-blocks-escape-and-ads` | PASS | `inside=true, escape=false, ads=false` |
| `mut-24-npmrc-auth-exfil-and-prefix-confusion-blocked` | PASS | `wsIgnored=true, exact=true, prefix=undefined, http=undefined` |
| `mut-25-ssrf-cgnat-unspecified-and-http-blocked` | PASS | `cgnat=false, unspec=false, v6=false, http=false` |
| `mut-26-sqlite-no-shared-tmp-fallback` | PASS | `resolvedPath=:memory:` |
| `mut-27-compiled-lib-parity-and-mcp-schema-pin` | PASS | `libParity=true, pinMatch=true, tokens=1628` |
| `mut-28-batch-manifest-malicious-and-private-isolation` | PASS | `eval=50/57, blocked=1, susp=1, offline=48` |
| `mut-29-batch-summary-token-cap` | PASS | `bytes=1787<=2000, flaggedTotal=25` |
| `mut-30-hook-denies-evasion-and-gates-delegation` | PASS | `evasionsDenied=true, manageDenied=true, subWriteAsk=true, subRoAllow=true` |
| `mut-31-hook-allows-benign-and-force-asks-pinned-never-auto-approve` | PASS | `benignAllow=true, pinnedForceAsk=true, noAutoApprove=true` |
| `mut-32-hook-fail-closed-exit-zero-on-corrupt-and-oversized-stdin` | PASS | `corrupt=force_ask(0), empty=force_ask(0), bigCmd=deny(0), bigEdit=allow(0)` |
| `mut-33-hook-config-tamper-force-ask-across-all-6-edit-tools` | PASS | `editToolsVerified=6/6, allGated=true` |
| `mut-34-placeholder-env-var-never-sent-as-bearer-token` | PASS | `placeholderBlocked=true, validScoped=true, opPlaceholderDropped=true` |
| `mut-35-vertical-slice-hygiene-and-0755-zip-modes` | PASS | `rules=3(AGENTS=1599B), agents=7, hooks=3, skills3=true, zip0755=true` |
| `mut-36-http-auth-rejects-alg-none-hs256-aud-scope-and-placeholder` | PASS | `es256=true, none=false, hs256=false, aud=false, scope=403, key=true` |
| `mut-37-mcp-app-zero-innerhtml-default-deny-csp-and-token-budget` | PASS | `linked=4/4, cspDefaultDeny=true, noUnsafeDom=true, tokens=1628<=1800` |
| `mut-38-sidecar-template-read-only-and-default-stdio-only` | PASS | `noActiveSidecars=true, grantsRo=true(3), rootStdioOnly=true` |

## Findings and Observations

<details>
<summary>Show observed coverage limits and non-blocking notes</summary>

- **INFO** TIER3/not_run: Live multi-agent sandbox runs (token uplift & model trajectory scoring) were not executed in this offline local run.
- **INFO** ENGINE/rea_absent: External `rea-agents` MCP/CLI binary is not installed on this host; `adv-10-uninspected-wasm-fail-closed` properly fails closed to `UNVERIFIABLE_UNKNOWN`.
- **INFO** SIGNING/local_dev_key: Local `skill.oms.sig` uses an explicit `local-dev-self-signed` ECDSA P-256 key; production distribution should swap to CI Sigstore Fulcio keyless OIDC.

</details>

## Scoring Methodology

<details>
<summary>Show dimension definitions, thresholds, and anti-fabrication rules</summary>

| Dimension | Question | Target Threshold |
|---|---|---|
| Security (Recall) | Are malicious/adversarial/fail-closed fixtures caught deterministically? | `>= 95%` (PASS) |
| Security (FPR) | Are legitimate CLIs (including TypeScript, regexes, short names, comments) spared? | `< 5%` (PASS) |
| Correctness (Mutation) | Do perturbed attacks reliably turn green checks red? | `100%` (PASS) |
| Discoverability | Are positive prompts matched and unrelated decoys rejected? | `>= 90%` (PASS) |
| Efficiency | Does Split-Plane SQLite caching reduce repeated Git history scan time? | Warm `< Cold` (PASS) |

- `N/A` indicates that live multi-agent trajectory counters were not executed; coverage and token deltas are never estimated or fabricated.

</details>

## Freshness

Regenerate this benchmark via `npm run bench` whenever `src/`, `skills/`, `catalog/`, `evals/evals.json`, or `tests/selection.jsonl` changes.
