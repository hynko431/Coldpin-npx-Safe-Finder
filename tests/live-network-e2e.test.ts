/**
 * Live-Network Real End-to-End Verification Suite (`npm run test:live`).
 *
 * Zero mocks: executes the compiled `lib/cli.mjs` binary and a real spawned
 * `lib/mcp.mjs` child process over stdio JSON-RPC 2.0 against live
 * `https://registry.npmjs.org` and `https://api.osv.dev`.
 *
 * Executed via `npm run test:live` locally and in the read-only non-fork
 * `live-network-smoke` CI job (PRs from this repo, `main`, weekly schedule,
 * and `workflow_dispatch`), separate from the offline `verify` matrix.
 */
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const CLI_MJS = resolve("lib", "cli.mjs");
const MCP_MJS = resolve("lib", "mcp.mjs");

async function runCompiledCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ["--no-warnings", CLI_MJS, ...args], {
      encoding: "utf8",
      timeout: 45_000,
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
    });
    return { code: 0, stdout, stderr };
  } catch (err: unknown) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return {
      code: typeof e.code === "number" ? e.code : 1,
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? "",
    };
  }
}

describe("Live-Network E2E: Real Compiled CLI & Spawned Stdio MCP Against registry.npmjs.org + api.osv.dev", () => {
  it("inspects live semver@7.7.1 via lib/cli.mjs with verified SHA-512, OSV query, and exit 0", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "coldpin-live-cli-"));
    try {
      const res = await runCompiledCli(["inspect", "semver@7.7.1", "--json", "--cache-dir", cacheDir]);
      assert.equal(res.code, 0, `Expected exit 0 for semver@7.7.1, got ${res.code}: ${res.stderr}`);
      const report = JSON.parse(res.stdout) as {
        title: { package_name: string; version: string };
        info: { lifecycle_scripts: string[] };
        verdict: string;
        pinned_execution: { command: string | null; tarball_sha512?: string };
      };
      assert.equal(report.title.package_name, "semver");
      assert.equal(report.title.version, "7.7.1");
      assert.equal(report.verdict, "VERIFIED_CLEAN_WITHIN_SCOPE");
      assert.equal(report.info.lifecycle_scripts.length, 0);
      assert.match(report.pinned_execution.tarball_sha512 ?? "", /^sha512-/);
      assert.ok(report.pinned_execution.command?.includes("--ignore-scripts"));
      assert.ok(report.pinned_execution.command?.includes("semver@7.7.1"));
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it("dogfoods live coldpin@1.6.0 from registry.npmjs.org and verifies npm Sigstore SLSA provenance", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "coldpin-live-dogfood-"));
    try {
      const res = await runCompiledCli(["inspect", "coldpin@1.6.0", "--json", "--cache-dir", cacheDir]);
      assert.ok(res.code === 0 || res.code === 2, `Unexpected exit code ${res.code}: ${res.stderr}`);
      const report = JSON.parse(res.stdout) as {
        title: { package_name: string; version: string };
        info: { provenance_attested: boolean; provenance_status: string; parity_tier: string };
        verdict: string;
        pinned_execution: { tarball_sha512?: string };
      };
      assert.equal(report.title.package_name, "coldpin");
      assert.equal(report.title.version, "1.6.0");
      assert.match(report.pinned_execution.tarball_sha512 ?? "", /^sha512-/);
      assert.notEqual(report.verdict, "MALICIOUS_INDICATORS_FOUND");
      assert.ok(
        report.info.provenance_attested === true || report.info.provenance_status === "dsse_leaf_verified_unanchored",
        `Expected live npm SLSA provenance attestation on coldpin@1.6.0, got status=${report.info.provenance_status}`,
      );
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it("runs live npm discovery via lib/cli.mjs discover against registry.npmjs.org", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "coldpin-live-discover-"));
    try {
      const res = await runCompiledCli(["discover", "semver", "--category", "cli", "--limit", "3", "--json", "--cache-dir", cacheDir]);
      assert.ok(res.code === 0 || res.code === 2, `Unexpected discover exit ${res.code}: ${res.stderr}`);
      const data = JSON.parse(res.stdout) as {
        query: string;
        candidates: Array<{ package_name: string; version: string }>;
      };
      assert.equal(data.query, "semver");
      assert.ok(Array.isArray(data.candidates) && data.candidates.length >= 1, "Expected >= 1 live npm candidate");
      assert.ok(data.candidates.some((c) => typeof c.package_name === "string" && c.package_name.length > 0));
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it("spawns real lib/mcp.mjs over stdio and executes live inspect_package_artifact + get_artifact_report + MTC-CAP-007 check", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "coldpin-live-mcp-"));
    const child = spawn(process.execPath, ["--no-warnings", MCP_MJS], {
      env: { ...process.env, COLDPIN_CACHE_DIR: cacheDir },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    let stdoutBuf = "";
    const queue: Array<Record<string, unknown>> = [];
    const waiters: Array<(msg: Record<string, unknown>) => void> = [];
    const stderrChunks: string[] = [];

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8");
      let nl = stdoutBuf.indexOf("\n");
      while (nl !== -1) {
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (line) {
          const parsed = JSON.parse(line) as Record<string, unknown>;
          const w = waiters.shift();
          if (w) w(parsed);
          else queue.push(parsed);
        }
        nl = stdoutBuf.indexOf("\n");
      }
    });
    child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk.toString("utf8")));

    const nextMsg = (timeoutMs = 45_000): Promise<Record<string, unknown>> => {
      if (queue.length > 0) return Promise.resolve(queue.shift()!);
      return new Promise((resolveMsg, rejectMsg) => {
        const t = setTimeout(
          () => rejectMsg(new Error(`Timed out waiting for live lib/mcp.mjs response. stderr=${stderrChunks.join("")}`)),
          timeoutMs,
        );
        waiters.push((m) => {
          clearTimeout(t);
          resolveMsg(m);
        });
      });
    };

    const request = async (id: number, method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      while (true) {
        const msg = await nextMsg();
        if (msg["id"] === id) return msg;
      }
    };

    try {
      const init = await request(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "coldpin-live-e2e", version: "1.0.0" },
      });
      assert.equal((init["result"] as { serverInfo: { name: string } }).serverInfo.name, "coldpin");
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

      const toolsRes = await request(2, "tools/list");
      const tools = (toolsRes["result"] as { tools: Array<{ name: string; inputSchema: { properties?: Record<string, { pattern?: string }> } }> }).tools;
      assert.equal(tools.length, 7);
      const anchor = tools.find((t) => t.name === "resolve_safe_anchor");
      assert.equal(typeof anchor?.inputSchema.properties?.["repo_url"]?.pattern, "string");

      const inspectRes = await request(3, "tools/call", {
        name: "inspect_package_artifact",
        arguments: { package_spec: "semver@7.7.1", detail: "summary" },
      });
      const inspectResult = inspectRes["result"] as {
        isError: boolean;
        structuredContent: { verdict: string; report_id: string; package_name: string };
      };
      assert.equal(inspectResult.isError, false);
      assert.equal(inspectResult.structuredContent.package_name, "semver");
      assert.equal(inspectResult.structuredContent.verdict, "VERIFIED_CLEAN_WITHIN_SCOPE");
      assert.match(inspectResult.structuredContent.report_id, /^rpt_/);

      const pageRes = await request(4, "tools/call", {
        name: "get_artifact_report",
        arguments: { report_id: inspectResult.structuredContent.report_id, section: "observations" },
      });
      assert.equal((pageRes["result"] as { isError: boolean }).isError, false);

      // Verify MTC-CAP-007 live schema gate on spawned lib/mcp.mjs
      const badRepoRes = await request(5, "tools/call", {
        name: "resolve_safe_anchor",
        arguments: { package_name: "semver", repo_url: "http://169.254.169.254/latest/meta-data" },
      });
      assert.equal((badRepoRes["error"] as { code: number }).code, -32602);
    } finally {
      const closed = new Promise<void>((resolveClose) => {
        if (child.exitCode !== null || child.killed) return resolveClose();
        child.once("close", () => resolveClose());
        child.stdin.end();
        setTimeout(() => {
          child.kill();
          resolveClose();
        }, 1500);
      });
      await closed;
      rmSync(cacheDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("audits this repository's real package.json cleanly via lib/cli.mjs verify-confusion and audit-batch", async () => {
    const conf = await runCompiledCli(["verify-confusion", "./package.json", "--json"]);
    assert.equal(conf.code, 0, `verify-confusion failed: ${conf.stderr}`);
    const confJson = JSON.parse(conf.stdout) as { passed: boolean };
    assert.equal(confJson.passed, true);

    const batch = await runCompiledCli(["audit-batch", "./package.json", "--json"]);
    assert.equal(batch.code, 0, `audit-batch failed: ${batch.stderr}`);
    const batchJson = JSON.parse(batch.stdout) as {
      total_declared: number;
      evaluated_count: number;
      flagged: unknown[];
    };
    assert.equal(batchJson.total_declared, 0);
    assert.equal(batchJson.evaluated_count, 0);
    assert.equal(batchJson.flagged.length, 0);
  });
});
