# FAQ & Epistemic Limits

> **Coldpin v1.6.1** · Section: Verification & Releases · Available on: Epistemic Rigor, All Harnesses
> Canonical HTML: https://coldpin-docs.pages.dev/docs/faq/

Security tooling should never overstate what static analysis can prove. These answers define Coldpin's exact epistemic boundaries and how it complements runtime isolation and private registries.

## Frequently Asked Questions

### Does VERIFIED_CLEAN_WITHIN_SCOPE prove a package has zero malware?

**No.** Static analysis cannot prove absence of malware on dynamically fetched remote payloads, time-bombed triggers, or uninspected compiled binaries. `VERIFIED_CLEAN_WITHIN_SCOPE` means only that no malicious, suspicious, policy-violating, or uninspected-binary indicators were observed within the stated static inspection boundary.

### Why does the recommended npx command carry a SHA-512 and transitive caveat?

Stock `npx` (`npm exec`) has no `--integrity <sha512>` CLI flag and ignores lockfiles inside published npm packages, resolving floating `^x.y.z` transitive dependencies live at runtime. Coldpin states that boundary honestly rather than implying a bare `npx` command enforces full transitive locks. Combine `--ignore-scripts` and exact pins with a private caching proxy or shrinkwrapped install for regulated builds.

### Why does resolve-anchor emit FORENSIC_COMMIT_ONLY when no npm tarball matches?

Running `npx github:org/repo#<clean_sha>` executes `prepare` and `postinstall` build scripts locally and pulls floating transitive dependencies. When a clean Git commit has no matching published npm release tarball, Coldpin suppresses runnable commands and recommends either building inside an isolated sandbox or switching to a vetted alternative (`SWITCH_TO_ALTERNATIVE`).

### Do I need REA (rea-agents) installed to use Coldpin?

**No.** Discovery, in-memory archive quarantine, JS/TS lexical taint analysis, hidden-Unicode detection, 3-tier tarball parity, and Git commit bisection all run on pure Node.js 24 with zero external packages. When an artifact contains obfuscated bundles or compiled `.node`/WASM/ELF/PE/Mach-O binaries, Coldpin fails closed and points to a pre-registered REA server — never auto-bootstrapping `npx -y rea-agents`.

### Why does BENCHMARK.md mark Tier 3 Live Multi-Agent Evaluation as NOT RUN?

Epistemic honesty. Tier 3 requires live LLM API calls in isolated sandbox containers across Antigravity, Claude Code, and Codex. Instead of fabricating uplift numbers, `BENCHMARK.md` reports real measured Tier 1–2 metrics (`49`-fixture corpus recall/FPR, latency, cache speedup, `38` mutation proofs, and positive/decoy trigger selection) and leaves Tier 3 honestly `N/A`.

### Does v1.6.0 HTTP MCP or the Weekly Sidecar open ports or run daemons by default?

**No.** Default `mcp_config.json` runs strictly local `stdio` (`lib/mcp.mjs`, zero listening sockets), and no active `sidecars/` directory ships at the plugin root. Both `coldpin-mcp-http` and `examples/sidecar.weekly-audit.example.json` are strictly opt-in.

### Are there alternatives, and where do I get support?

Yes: Socket.dev, Snyk, GuardDog, OSV-Scanner, and private registries (Verdaccio, Artifactory) solve overlapping parts of npm supply-chain security. Coldpin focuses specifically on the zero-dependency local agentic pre-`npx` workflow. Report bugs or detection gaps publicly on [GitHub Issues](https://github.com/hynko431/Coldpin-npx-Safe-Finder/issues); report security vulnerabilities confidentially via [Security Policy](https://coldpin-docs.pages.dev/docs/security/).

---

*Coldpin v1.6.1 (Apache-2.0). Static triage does not replace runtime isolation or human judgment.*
