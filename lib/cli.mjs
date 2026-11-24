#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";

function checkNodeVersionFloor()       {
  const major = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  if (!Number.isFinite(major) || major < 24) {
    process.stderr.write(
      `Coldpin requires Node.js >= 24.0.0; detected ${process.version}. Upgrade to Node 24+ LTS.\n`,
    );
    process.exit(1);
  }
}

checkNodeVersionFloor();

const { defaultCacheDbPath, SplitPlaneCache } = await import("./cache/sqlite-store.mjs");
const { logOperationalEvent } = await import("./compliance/audit-log.mjs");
const { loadNpmrc, loadPolicy, probeHostCapabilitiesAsync } = await import("./config/policy.mjs");
const {
  runAuditManifestBatch,
  runAuditVerify,
  runDiscover,
  runInspect,
  runResolveAnchor,
  runVerifyConfusion,
} = await import("./core/workflows.mjs");
const { ENGINE_VERSION } = await import("./types.mjs");
const {
  formatAnchorMarkdown,
  formatCycloneDxSbom,
  formatDiscoveryMarkdown,
  formatInspectionMarkdownCard,
  formatSarif210,
} = await import("./verdict/engine-and-formatters.mjs");

                                           

                      
                  
                        
                                          
                 
 

const BOOLEAN_FLAGS = new Set([
  "json",
  "sarif",
  "sbom",
  "offline",
  "verbose",
  "check-public",
  "include-dev",
  "help",
  "version",
]);

const VALUE_FLAGS = new Set([
  "tarball",
  "git-dir",
  "repo-url",
  "subdir",
  "org",
  "creator",
  "category",
  "limit",
  "window",
  "policy",
  "cache-dir",
  "audit-log",
  "override-ticket",
]);

function parseCliArgs(argv          )             {
  const positionals           = [];
  const flags                                   = {};
  const args = argv.slice(2);
  let i = 0;
  let afterDoubleDash = false;
  while (i < args.length) {
    const a = args[i] ;
    if (afterDoubleDash) {
      positionals.push(a);
      i++;
      continue;
    }
    if (a === "--") {
      afterDoubleDash = true;
      i++;
      continue;
    }
    if (a === "-h") {
      flags["help"] = true;
      i++;
      continue;
    }
    if (a === "-V") {
      flags["version"] = true;
      i++;
      continue;
    }
    if (a.startsWith("--")) {
      const eqIdx = a.indexOf("=");
      if (eqIdx > 2) {
        const key = a.slice(2, eqIdx);
        const val = a.slice(eqIdx + 1);
        if (BOOLEAN_FLAGS.has(key)) {
          flags[key] = val === "true" || val === "1";
        } else if (VALUE_FLAGS.has(key)) {
          flags[key] = val;
        } else {
          return { command: "help", positionals, flags, error: `Unknown flag: --${key}` };
        }
      } else {
        const key = a.slice(2);
        if (BOOLEAN_FLAGS.has(key)) {
          flags[key] = true;
        } else if (VALUE_FLAGS.has(key)) {
          const next = args[i + 1];
          if (next === undefined || next.startsWith("--")) {
            return { command: "help", positionals, flags, error: `Flag --${key} requires a value` };
          }
          flags[key] = next;
          i++;
        } else {
          return { command: "help", positionals, flags, error: `Unknown flag: --${key}` };
        }
      }
    } else {
      positionals.push(a);
    }
    i++;
  }
  const command = positionals.shift() ?? "help";
  return { command, positionals, flags };
}

function strFlag(flags                                  , name        )                     {
  const v = flags[name];
  return typeof v === "string" ? v : undefined;
}

function boolFlag(flags                                  , name        )          {
  return flags[name] === true || flags[name] === "true";
}

function printHelp()       {
  const help = `coldpin v${ENGINE_VERSION} — Inspect npx packages cold in memory; pin clean releases with verifiable evidence

USAGE:
  node src/cli.ts <command> [target] [flags]
  coldpin <command> [target] [flags]

COMMANDS:
  discover [query]          Search npm packages by query/category/creator/org with slopsquat & policy guards
  inspect <pkg[@ver]>       Zero-exec tarball inspection, AST taint triage, parity & verdict card
  resolve-anchor <pkg>      Identify patient-zero commit and safe pre-compromise release/alternative
  verify-confusion [path]   Audit package.json & .npmrc for dependency confusion (T1195.001)
  audit-batch [path]        Batch-screen up to 50 direct dependencies from package.json (squat/policy/OSV)
  audit-verify <jsonl>      Verify local hash-chained audit.jsonl integrity
  mcp                       Start local zero-dependency JSON-RPC 2.0 MCP server over stdio

COMMON FLAGS:
  --json                    Emit canonical JSON to stdout
  --sarif                   Emit SARIF 2.1.0 JSON (inspect)
  --sbom                    Emit CycloneDX 1.5 SBOM + VEX JSON (inspect)
  --tarball <file.tgz>      Inspect a local tarball offline (inspect)
  --git-dir <dir>           Local Git repository path for parity or commit bisect
  --repo-url <url>          Git repository URL for treeless commit bisect (resolve-anchor)
  --subdir <path>           Monorepo subdirectory inside Git repo
  --org <scope>             Filter by npm org/scope (discover)
  --creator <handle>        Filter by maintainer/creator (discover)
  --category <keyword>      Filter by capability/category keyword (discover)
  --limit <n>               Max discovery results (default 10) or batch deps (audit-batch, 1..50)
  --include-dev             Include devDependencies in batch screening (audit-batch)
  --window <n>              Max commits to bisect (overrides policy bisect_max_commits)
  --policy <file>           Explicit .coldpin.policy.json path
  --cache-dir <dir>         Cache directory (or :memory:)
  --audit-log <file>        Append local hash-chained audit event to JSONL file
  --override-ticket <id>    Record security approval ticket ID in audit.jsonl (does not alter verdict)
  --verbose                 Emit structured operational JSON telemetry to stderr (zero secrets/PII)
  --offline                 Disable all outbound network queries (fail closed)
  --check-public            Probe public npmjs.org for unscoped claimability (verify-confusion)
  --version, -V             Print coldpin CLI version and exit
  --help, -h                Print this help message and exit

EXIT CODES:
  0 = VERIFIED_CLEAN_WITHIN_SCOPE / check passed
  2 = QUARANTINE_SUSPICIOUS or UNVERIFIABLE_UNKNOWN
  3 = MALICIOUS_INDICATORS_FOUND / confusion or audit integrity failure
  1 = CLI usage or runtime error

DOCS:
  https://coldpin-docs.pages.dev/  (AI/LLM index: https://coldpin-docs.pages.dev/llms.txt)`;
  process.stdout.write(`${help}\n`);
}

async function main()                    {
  const parsed = parseCliArgs(process.argv);
  if (parsed.error) {
    process.stderr.write(`Error: ${parsed.error}\n`);
    return 1;
  }
  if (boolFlag(parsed.flags, "version")) {
    process.stdout.write(`coldpin v${ENGINE_VERSION}\n`);
    return 0;
  }
  if (parsed.command === "help" || boolFlag(parsed.flags, "help")) {
    printHelp();
    return 0;
  }

  // Early handoff to MCP stdio server before CLI policy/cache/capability initialization
  if (parsed.command === "mcp") {
    const { startMcpServerFromEnv } = await import("./mcp/server.mjs");
    return (await startMcpServerFromEnv())            ;
  }

  const cwd = process.cwd();
  const { policy, policy_sha256 } = loadPolicy(cwd, strFlag(parsed.flags, "policy"));
  if (boolFlag(parsed.flags, "offline")) policy.offline_mode = true;
  const windowArg = strFlag(parsed.flags, "window");
  let parsedWindow                    ;
  if (windowArg !== undefined) {
    const n = Number(windowArg);
    if (!Number.isInteger(n) || n < 1) {
      process.stderr.write(`Error: --window must be a positive integer (got '${windowArg}')\n`);
      return 1;
    }
    parsedWindow = n;
    policy.bisect_max_commits = n;
  }

  const npmrc = loadNpmrc(cwd);
  const hostCaps = await probeHostCapabilitiesAsync();
  const cacheDir = strFlag(parsed.flags, "cache-dir");
  const cache = new SplitPlaneCache(cacheDir ? defaultCacheDbPath(cacheDir) : defaultCacheDbPath());
  const auditLogPath = strFlag(parsed.flags, "audit-log");
  const overrideTicketId = strFlag(parsed.flags, "override-ticket");
  const verbose = boolFlag(parsed.flags, "verbose");
  const requestId = `req_${randomUUID().slice(0, 12)}`;
  const asJson = boolFlag(parsed.flags, "json");
  const stderrWriter = (line        ) => {
    process.stderr.write(line);
  };

  logOperationalEvent(
    verbose,
    {
      request_id: requestId,
      stage: "cli_start",
      command: parsed.command,
      offline: policy.offline_mode,
    },
    stderrWriter,
  );

  const ctx = {
    cwd,
    workspaceRoots: [cwd],
    enforceRootConfinement: false,
    policy,
    policy_sha256,
    npmrc,
    host_capabilities: hostCaps,
    cache,
    auditLogPath: auditLogPath ? resolve(auditLogPath) : undefined,
    overrideTicketId,
    invokerSurface: "cli"         ,
    requestId,
    onTelemetry: verbose
      ? (ev                         ) => {
          logOperationalEvent(true, ev, stderrWriter);
        }
      : undefined,
  };

  try {
    if (parsed.command === "discover") {
      const query = parsed.positionals.join(" ");
      const limitStr = strFlag(parsed.flags, "limit");
      let limit = 10;
      if (limitStr !== undefined) {
        const parsedLimit = Number(limitStr);
        if (!Number.isInteger(parsedLimit) || parsedLimit < 1) {
          process.stderr.write(`Error: --limit must be a positive integer (got '${limitStr}')\n`);
          return 1;
        }
        limit = parsedLimit;
      }
      const res = await runDiscover(ctx, {
        query,
        org: strFlag(parsed.flags, "org"),
        creator: strFlag(parsed.flags, "creator"),
        category: strFlag(parsed.flags, "category"),
        limit,
      });
      process.stdout.write(asJson ? `${JSON.stringify(res.report, null, 2)}\n` : `${formatDiscoveryMarkdown(res.report)}\n`);
      return res.exitCode;
    }

    if (parsed.command === "inspect") {
      const res = await runInspect(ctx, {
        packageSpec: parsed.positionals[0],
        tarballPath: strFlag(parsed.flags, "tarball"),
        localGitDir: strFlag(parsed.flags, "git-dir"),
        subdir: strFlag(parsed.flags, "subdir"),
        offline: boolFlag(parsed.flags, "offline"),
      });
      if (!res.ok) {
        process.stderr.write(`${res.error}\n`);
        return res.exitCode;
      }
      if (boolFlag(parsed.flags, "sarif")) {
        process.stdout.write(`${JSON.stringify(formatSarif210(res.report), null, 2)}\n`);
      } else if (boolFlag(parsed.flags, "sbom")) {
        process.stdout.write(`${JSON.stringify(formatCycloneDxSbom(res.report, res.dependencies), null, 2)}\n`);
      } else if (asJson) {
        process.stdout.write(`${JSON.stringify(res.report, null, 2)}\n`);
      } else {
        process.stdout.write(`${formatInspectionMarkdownCard(res.report)}\n`);
      }
      return res.exitCode;
    }

    if (parsed.command === "resolve-anchor") {
      const res = await runResolveAnchor(ctx, {
        packageName: parsed.positionals[0],
        localGitDir: strFlag(parsed.flags, "git-dir"),
        repoUrl: strFlag(parsed.flags, "repo-url"),
        subdir: strFlag(parsed.flags, "subdir"),
        window: parsedWindow,
      });
      if (!res.ok) {
        process.stderr.write(`${res.error}\n`);
        return res.exitCode;
      }
      process.stdout.write(asJson ? `${JSON.stringify(res.decision, null, 2)}\n` : `${formatAnchorMarkdown(res.decision)}\n`);
      return res.exitCode;
    }

    if (parsed.command === "verify-confusion") {
      const res = await runVerifyConfusion(ctx, {
        manifestPath: parsed.positionals[0],
        checkPublic: boolFlag(parsed.flags, "check-public"),
        allowPublicProbe: true,
      });
      if (!res.ok) {
        process.stderr.write(`${res.error}\n`);
        return res.exitCode;
      }
      process.stdout.write(`${JSON.stringify(res.report, null, 2)}\n`);
      return res.exitCode;
    }

    if (parsed.command === "audit-batch") {
      const limitStr = strFlag(parsed.flags, "limit");
      let maxDeps                    ;
      if (limitStr !== undefined) {
        const parsedLimit = Number(limitStr);
        if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 50) {
          process.stderr.write(`Error: --limit for audit-batch must be an integer between 1 and 50 (got '${limitStr}')\n`);
          return 1;
        }
        maxDeps = parsedLimit;
      }
      const res = await runAuditManifestBatch(ctx, {
        manifestPath: parsed.positionals[0],
        includeDev: boolFlag(parsed.flags, "include-dev"),
        maxDeps,
        offline: boolFlag(parsed.flags, "offline"),
      });
      if (!res.ok) {
        process.stderr.write(`${res.error}\n`);
        return res.exitCode;
      }
      if (asJson) {
        process.stdout.write(`${JSON.stringify(res.report, null, 2)}\n`);
      } else {
        const r = res.report;
        const lines           = [
          `# Coldpin Batch Dependency Screening`,
          `- Manifest: \`${r.manifest_path}\``,
          `- Evaluated: ${r.evaluated_count} / ${r.total_declared}${r.truncated_at_cap ? " (capped)" : ""}`,
          `- Clean screened: ${r.summary_counts.clean_screened} | Suspicious: ${r.summary_counts.flagged_suspicious} | Malicious/Blocked: ${r.summary_counts.malicious_or_blocked} | Unverifiable/Offline: ${r.summary_counts.unverifiable_offline}`,
        ];
        if (r.flagged.length > 0) {
          lines.push("", "| Package | Status | Route | Primary Reason |", "| --- | --- | --- | --- |");
          for (const f of r.flagged) {
            const safeReason = (f.reasons[0] ?? "").replace(/\|/g, "\\|").slice(0, 120);
            lines.push(`| \`${f.package_name}\` | ${f.status} | ${f.route} | ${safeReason} |`);
          }
        }
        if (r.unknowns.length > 0) {
          lines.push("", "## Unknowns", ...r.unknowns.map((u) => `- ${u}`));
        }
        process.stdout.write(`${lines.join("\n")}\n`);
      }
      return res.exitCode;
    }

    if (parsed.command === "audit-verify") {
      const target = parsed.positionals[0];
      if (!target) {
        process.stderr.write("Error: audit-verify requires <path-to-audit.jsonl>\n");
        return 1;
      }
      const res = await runAuditVerify(ctx, { auditLogPath: target });
      if (!res.ok) {
        // Preserve existing CLI JSON output on unreadable/missing audit file
        const payload = { valid: false, total_events: 0, reason: res.error };
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
        return 3;
      }
      process.stdout.write(`${JSON.stringify(res.result, null, 2)}\n`);
      return res.exitCode;
    }

    process.stderr.write(`Unknown command: ${parsed.command}\n`);
    printHelp();
    return 1;
  } finally {
    cache.close();
  }
}

process.exitCode = await main();


//# sourceURL=cli.ts
