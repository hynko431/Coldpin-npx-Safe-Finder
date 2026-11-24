# FAQ

#### Q: Are there alternatives?

**A**: Yes. Many.

`Socket.dev`, `Snyk`, `GuardDog`, `OSV-Scanner`, and private npm proxies (Verdaccio, Artifactory) solve overlapping parts of npm supply-chain security. `coldpin` focuses specifically on the agentic pre-`npx` workflow: zero-execution in-memory discovery and triage, 3-tier tarball-vs-Git parity, patient-zero commit bisection, and honest pinned commands with zero external runtime dependencies. Regardless of the tool you choose, *you own the execution decision.*

#### Q: Does `VERIFIED_CLEAN_WITHIN_SCOPE` prove a package has zero malware?

**A**: No.

Static analysis cannot prove absence of malware on dynamically fetched remote payloads, time-bombed triggers, or uninspected compiled binaries. `VERIFIED_CLEAN_WITHIN_SCOPE` means only that no malicious, suspicious, policy-violating, or uninspected-binary indicators were observed within the stated static inspection boundary.

#### Q: Why does the emitted `npx` command carry a SHA-512 and transitive caveat?

**A**: Stock `npx` (`npm exec`) has no `--integrity <sha512>` command-line flag and ignores any `package-lock.json` inside a published npm package, resolving floating `^x.y.z` transitive dependencies live at runtime. Pretending a bare `npx` command enforces SHA-512 or transitive locks would be dishonest. Always combine `--ignore-scripts` and exact version pins with a private caching proxy or shrinkwrapped install for regulated builds.

#### Q: Why doesn't `resolve-anchor` tell me to run `npx github:org/repo#<clean_sha>` when a clean Git commit has no npm tarball?

**A**: Running `npx` directly from a Git commit executes `prepare`/`postinstall` build scripts on your machine and pulls live floating transitive dependencies. When a clean commit has no matching verified npm release tarball, `coldpin` emits `FORENSIC_COMMIT_ONLY` (suppressing runnable commands) and recommends either building in an isolated sandbox or switching to a vetted category alternative (`SWITCH_TO_ALTERNATIVE`).

#### Q: Do I need `rea-agents` installed to use `coldpin`?

**A**: No.

Tier-0 metadata/OSV checks, Tier-1 in-memory unpacking, JS/TS lexical taint analysis, hidden-Unicode detection, 3-tier tarball parity, and Git commit bisection all run locally on pure Node.js 24 with zero external packages. When an artifact contains obfuscated bundles or compiled `.node`/WASM/ELF/PE/Mach-O binaries, the CLI fails closed (`QUARANTINE_SUSPICIOUS` / `UNVERIFIABLE_UNKNOWN`) and points you to a pre-registered REA MCP server or pre-installed `rea` binary—never auto-downloading `rea-agents` via `npx -y`.

#### Q: Why does `BENCHMARK.md` mark Tier 3 Live Multi-Agent Evaluation as `NOT RUN`?

**A**: Epistemic honesty. Running Tier 3 requires live LLM API calls in isolated sandbox containers across multiple agent harnesses (Antigravity, Claude Code, Codex). Rather than fabricating synthetic uplift numbers, `BENCHMARK.md` reports real measured Tier 1–2 execution metrics (49-fixture security corpus recall/FPR, latency, cache speedup, 38 mutation proofs, and positive+decoy trigger selection) and leaves Tier 3 explicitly `N/A` until run in CI/sandbox.
