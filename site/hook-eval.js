/* Coldpin PreToolUse Browser Evaluator — compiled verbatim from src/hook-core.ts.
 * Pure ES2020 | 100% parity with lib/hook.mjs | Do not edit manually; run `npm run build:docs`.
 */
(function (globalScope) {
  "use strict";
/**
 * Coldpin Fail-Safe PreToolUse Pure Evaluation Core (Pure ES2020, Zero Node/External Imports).
 *
 * Shared single source of truth imported by `src/hook.ts` (`lib/hook.mjs`) and compiled directly
 * to `site/hook-eval.js` for the Coldpin Documentation Portal Interactive Policy Lab so browser
 * simulation and live Antigravity PreToolUse enforcement stay at 100% parity.
 *
 * Security invariants:
 * - Pure ES2020 only (zero `node:*` imports, zero network/subprocess/filesystem/eval APIs).
 * - Linear-time bounded command & path evaluation (`MAX_COMMAND_CHARS`, `MAX_WRAPPER_DEPTH`).
 * - Emits strictly `allow`, `deny`, or `force_ask` (never auto-approval).
 */

                               
                                           
                  
 

const MAX_COMMAND_CHARS = 65536;
const MAX_WRAPPER_DEPTH = 4;

const FILE_EDIT_TOOLS = new Set([
  "write_to_file",
  "replace_file_content",
  "multi_replace_file_content",
  "write_file",
  "edit_file",
  "sed_file",
]);

const SENSITIVE_BASENAMES = new Set([
  ".npmrc",
  ".coldpin.policy.json",
  ".npx-guard.policy.json",
  "hooks.json",
  "mcp_config.json",
]);

const SENSITIVE_SUFFIXES = [
  "/.agents/plugins.json",
  "/.agents/rules.json",
  "/lib/hook.mjs",
  "/catalog/triage-rules.json",
  "/.gemini/config/config.json",
];

const POST_DASH_BLOCKED_INTERPRETERS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ash",
  "ksh",
  "csh",
  "tcsh",
  "fish",
  "cmd",
  "pwsh",
  "powershell",
  "node",
  "nodejs",
  "deno",
  "bun",
  "python",
  "python3",
  "py",
  "perl",
  "ruby",
  "php",
  "awk",
  "gawk",
  "env",
  "eval",
  "exec",
  "xargs",
  "find",
  "wsl",
]);

const DOWNLOAD_CMDS = new Set([
  "curl",
  "wget",
  "iwr",
  "irm",
  "invoke-webrequest",
  "invoke-restmethod",
]);

const PIPE_EXEC_SINKS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ash",
  "ksh",
  "iex",
  "invoke-expression",
  "pwsh",
  "powershell",
  "cmd",
  "node",
  "python",
  "python3",
  "perl",
  "ruby",
]);

const EXACT_PINNED_SPEC_RE =
  /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SAFE_BIN_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=(.*)$/;
const WIN_DRIVE_PATH_RE = /^[A-Za-z]:\\/;

function normalizeToken(raw        )         {
  const s = raw.trim();
  if (!s) return "";

  // Strip quote pairs and shell escapes linearly in a single O(n) pass
  let unquoted = "";
  let inSingle = false;
  let inDouble = false;
  const looksLikePath =
    s.startsWith("/") ||
    s.startsWith("./") ||
    s.startsWith("../") ||
    s.startsWith(".\\") ||
    s.startsWith("..\\") ||
    WIN_DRIVE_PATH_RE.test(s) ||
    s.includes("/");

  for (let i = 0; i < s.length; i++) {
    const ch = s[i] ;
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (ch === "\\" && !inSingle && !looksLikePath) {
      if (i + 1 < s.length) {
        unquoted += s[i + 1] ;
        i++;
      }
      continue;
    }
    if (ch === "`" && !inSingle) {
      // PowerShell backtick escape (e.g., n`px)
      continue;
    }
    unquoted += ch;
  }

  return unquoted;
}

function normalizeExecutableName(raw        )         {
  const cleaned = normalizeToken(raw);
  if (!cleaned) return "";
  const slashIdx = Math.max(cleaned.lastIndexOf("/"), cleaned.lastIndexOf("\\"));
  const base = slashIdx >= 0 ? cleaned.slice(slashIdx + 1) : cleaned;
  const lower = base.toLowerCase();
  if (lower.endsWith(".cmd")) return lower.slice(0, -4);
  if (lower.endsWith(".exe")) return lower.slice(0, -4);
  if (lower.endsWith(".ps1")) return lower.slice(0, -4);
  if (lower.endsWith(".bat")) return lower.slice(0, -4);
  return lower;
}

                          
                                                                
                      
                       
 

function splitShellCommand(cmd        )                 {
  const segments                                                      = [];
  const subshells           = [];
  let curTokens           = [];
  let curTok = "";
  let inSingle = false;
  let inDouble = false;
  let hasCompound = false;

  const pushTok = () => {
    if (curTok.length > 0) {
      curTokens.push(curTok);
      curTok = "";
    }
  };
  const pushSeg = (piped         ) => {
    pushTok();
    if (curTokens.length > 0) {
      segments.push({ tokens: curTokens, pipedIntoNext: piped });
      curTokens = [];
    }
  };

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i] ;
    const next = i + 1 < cmd.length ? cmd[i + 1]  : "";

    if (inSingle) {
      curTok += ch;
      if (ch === "'") inSingle = false;
      continue;
    }

    if (ch === "\\" && !inDouble) {
      curTok += ch;
      if (i + 1 < cmd.length) {
        curTok += cmd[i + 1] ;
        i++;
      }
      continue;
    }

    // Extract $(...) subshell payloads even inside double quotes
    if (ch === "$" && next === "(") {
      hasCompound = true;
      let depth = 1;
      let j = i + 2;
      let inner = "";
      let sQ = false;
      let dQ = false;
      while (j < cmd.length && depth > 0) {
        const c = cmd[j] ;
        if (c === "'" && !dQ) sQ = !sQ;
        else if (c === '"' && !sQ) dQ = !dQ;
        else if (!sQ && !dQ) {
          if (c === "(") depth++;
          else if (c === ")") depth--;
        }
        if (depth > 0) inner += c;
        j++;
      }
      if (inner.trim()) subshells.push(inner.trim());
      curTok += "$(SUB)";
      i = j - 1;
      continue;
    }

    // Distinguish POSIX paired backticks (`cmd arg`) from PowerShell escape (n`px)
    if (ch === "`") {
      const closeIdx = cmd.indexOf("`", i + 1);
      if (closeIdx > i + 1) {
        const inner = cmd.slice(i + 1, closeIdx);
        // If interior has whitespace or slash/semicolon/pipe, treat as POSIX subshell; otherwise PS escape
        if (/[\s;|&]/.test(inner)) {
          hasCompound = true;
          subshells.push(inner.trim());
          curTok += "`SUB`";
          i = closeIdx;
          continue;
        }
      }
      curTok += ch;
      continue;
    }

    if (inDouble) {
      curTok += ch;
      if (ch === "\\" && i + 1 < cmd.length) {
        curTok += cmd[i + 1] ;
        i++;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }

    if (ch === "'") {
      inSingle = true;
      curTok += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      curTok += ch;
      continue;
    }

    if (ch === "\n" || ch === "\r" || ch === ";") {
      hasCompound = true;
      pushSeg(false);
      continue;
    }
    if (ch === "&" && next === "&") {
      hasCompound = true;
      pushSeg(false);
      i++;
      continue;
    }
    if (ch === "|" && next === "|") {
      hasCompound = true;
      pushSeg(false);
      i++;
      continue;
    }
    if (ch === "|") {
      hasCompound = true;
      pushSeg(true);
      continue;
    }
    if (ch === "&") {
      hasCompound = true;
      pushSeg(false);
      continue;
    }
    if (ch === " " || ch === "\t") {
      pushTok();
      continue;
    }
    curTok += ch;
  }

  pushSeg(false);
  if (segments.length > 1) hasCompound = true;
  return { segments, subshells, hasCompound };
}

function isSensitiveConfigCommand(tokens          , rawCmd        )          {
  const lowerRaw = rawCmd.toLowerCase();
  if (/\bagy(?:\.exe)?\s+plugin\s+(?:disable|uninstall|remove)\b/.test(lowerRaw)) {
    return true;
  }
  const normalizedJoined = tokens.map((t) => normalizeToken(t).toLowerCase()).join(" ");
  const writeHints = [">", "tee", "sed", "rm", "del", "mv", "move", "cp", "copy", "set-content", "out-file", "add-content"];
  const hasWriteHint = writeHints.some((w) => normalizedJoined.includes(w));
  if (!hasWriteHint) return false;
  for (const name of SENSITIVE_BASENAMES) {
    if (normalizedJoined.includes(name)) return true;
  }
  for (const suf of SENSITIVE_SUFFIXES) {
    if (normalizedJoined.includes(suf.slice(1))) return true;
  }
  return false;
}

function evaluateNpxInvocation(
  args          ,
  envFlags                                                              ,
  hasCompound         ,
)               {
  if (envFlags.disableIgnoreScripts) {
    return {
      decision: "deny",
      reason: "Blocked npx invocation with npm_config_ignore_scripts disabled; vet with Coldpin first.",
    };
  }
  if (envFlags.registryOverride) {
    return {
      decision: "deny",
      reason: "Blocked npx invocation with registry/config environment override.",
    };
  }

  let hasIgnoreScripts = false;
  let sawDoubleDash = false;
  const packageSpecs           = [];
  let postDashCmd                = null;

  for (let i = 0; i < args.length; i++) {
    const raw = args[i] ;
    const tok = normalizeToken(raw);
    const lower = tok.toLowerCase();

    if (sawDoubleDash) {
      if (postDashCmd === null) postDashCmd = tok;
      if (lower.includes("rea-agents")) {
        return {
          decision: "deny",
          reason: "Blocked self-bootstrap of rea-agents via npx; use pre-installed REA only.",
        };
      }
      continue;
    }

    if (tok === "--") {
      sawDoubleDash = true;
      continue;
    }

    if (lower.includes("rea-agents")) {
      return {
        decision: "deny",
        reason: "Blocked self-bootstrap of rea-agents via npx; use pre-installed REA only.",
      };
    }

    if (lower === "--ignore-scripts" || lower === "--ignore-scripts=true") {
      hasIgnoreScripts = true;
      continue;
    }
    if (lower === "--ignore-scripts=false" || lower === "--no-ignore-scripts") {
      return {
        decision: "deny",
        reason: "Blocked npx invocation disabling --ignore-scripts.",
      };
    }
    if (
      lower === "-c" ||
      lower === "--call" ||
      lower.startsWith("--call=") ||
      lower === "--shell" ||
      lower.startsWith("--shell=") ||
      lower === "--registry" ||
      lower.startsWith("--registry=") ||
      lower === "--userconfig" ||
      lower.startsWith("--userconfig=") ||
      lower === "--globalconfig" ||
      lower.startsWith("--globalconfig=")
    ) {
      return {
        decision: "deny",
        reason: `Blocked unsafe npx flag '${tok}' (shell/registry/config override).`,
      };
    }
    if (lower === "-y" || lower === "--yes" || lower === "-q" || lower === "--quiet" || lower === "--no" || lower === "--no-install") {
      continue;
    }
    if (lower === "-p" || lower === "--package") {
      const nextVal = i + 1 < args.length ? normalizeToken(args[i + 1] ) : "";
      if (!nextVal) {
        return { decision: "deny", reason: "Blocked npx invocation with missing --package specifier." };
      }
      packageSpecs.push(nextVal);
      i++;
      continue;
    }
    if (lower.startsWith("--package=")) {
      packageSpecs.push(tok.slice("--package=".length));
      continue;
    }
    if (lower.startsWith("-p=")) {
      packageSpecs.push(tok.slice("-p=".length));
      continue;
    }
    if (tok.startsWith("-")) {
      // Unknown flags on npx cannot bypass verification
      return {
        decision: "deny",
        reason: `Blocked npx invocation with unvetted flag '${tok}'; use Coldpin's exact pinned command.`,
      };
    }

    // Positional package/command token before `--`: only the first positional is the package spec
    if (packageSpecs.length === 0) {
      packageSpecs.push(tok);
      // Remaining positional args after direct package spec belong to the invoked binary
      break;
    }
  }

  if (!hasIgnoreScripts) {
    return {
      decision: "deny",
      reason: "Blocked npx without --ignore-scripts; inspect with Coldpin (inspect_package_artifact) first.",
    };
  }
  if (packageSpecs.length === 0) {
    return {
      decision: "deny",
      reason: "Blocked npx invocation with no pinned package specifier.",
    };
  }
  for (const spec of packageSpecs) {
    const specLower = spec.toLowerCase();
    if (specLower.includes("rea-agents")) {
      return {
        decision: "deny",
        reason: "Blocked self-bootstrap of rea-agents via npx; use pre-installed REA only.",
      };
    }
    if (!EXACT_PINNED_SPEC_RE.test(spec)) {
      return {
        decision: "deny",
        reason: `Blocked unpinned or remote npx package '${spec}'; pin exact X.Y.Z after Coldpin inspection.`,
      };
    }
  }
  if (postDashCmd !== null) {
    const binNorm = normalizeExecutableName(postDashCmd);
    if (!SAFE_BIN_RE.test(postDashCmd) || POST_DASH_BLOCKED_INTERPRETERS.has(binNorm)) {
      return {
        decision: "deny",
        reason: `Blocked shell or interpreter '${postDashCmd}' after npx '--' separator.`,
      };
    }
  }
  if (hasCompound) {
    return {
      decision: "deny",
      reason: "Blocked compound/chained shell command containing npx; run Coldpin's pinned command standalone.",
    };
  }

  return {
    decision: "force_ask",
    reason: "Coldpin exact-pinned npx command with --ignore-scripts; explicit human confirmation required before execution.",
  };
}

function evaluatePackageManagerInstall(
  mgr        ,
  subcmd        ,
  args          ,
  envFlags                                                              ,
)               {
  if (envFlags.disableIgnoreScripts || envFlags.registryOverride) {
    return {
      decision: "deny",
      reason: `Blocked ${mgr} ${subcmd} with unsafe npm_config environment override.`,
    };
  }
  let hasIgnoreScripts = false;
  for (const raw of args) {
    const lower = normalizeToken(raw).toLowerCase();
    if (lower === "--ignore-scripts" || lower === "--ignore-scripts=true") {
      hasIgnoreScripts = true;
    } else if (
      lower === "--ignore-scripts=false" ||
      lower === "--no-ignore-scripts" ||
      lower === "--registry" ||
      lower.startsWith("--registry=") ||
      lower === "--userconfig" ||
      lower.startsWith("--userconfig=")
    ) {
      return {
        decision: "deny",
        reason: `Blocked ${mgr} ${subcmd} with unsafe flag '${lower}'.`,
      };
    }
  }
  if (!hasIgnoreScripts) {
    return {
      decision: "deny",
      reason: `Blocked ${mgr} ${subcmd} without --ignore-scripts; untrusted lifecycle scripts may execute. Audit with Coldpin first.`,
    };
  }
  return {
    decision: "force_ask",
    reason: `${mgr} ${subcmd} with --ignore-scripts requires explicit human confirmation.`,
  };
}

function extractShellWrapperPayload(exe        , args          )                {
  if (exe === "sh" || exe === "bash" || exe === "zsh" || exe === "dash" || exe === "ash" || exe === "ksh") {
    for (let i = 0; i < args.length; i++) {
      const t = normalizeToken(args[i] );
      if (t === "-c" || t === "-lc" || t === "-ic" || t === "-ec") {
        return i + 1 < args.length ? normalizeToken(args[i + 1] ) : null;
      }
    }
  }
  if (exe === "cmd") {
    for (let i = 0; i < args.length; i++) {
      const l = normalizeToken(args[i] ).toLowerCase();
      if (l === "/c" || l === "/k") {
        return args.slice(i + 1).map(normalizeToken).join(" ").trim() || null;
      }
    }
  }
  if (exe === "pwsh" || exe === "powershell") {
    for (let i = 0; i < args.length; i++) {
      const l = normalizeToken(args[i] ).toLowerCase();
      if (l === "-c" || l === "-command" || l === "-cmd") {
        return args.slice(i + 1).map(normalizeToken).join(" ").trim() || null;
      }
    }
  }
  if (exe === "wsl") {
    for (let i = 0; i < args.length; i++) {
      const l = normalizeToken(args[i] ).toLowerCase();
      if (l === "--" || l === "-e" || l === "--exec") {
        return args.slice(i + 1).map(normalizeToken).join(" ").trim() || null;
      }
    }
  }
  return null;
}

function mergeDecision(current              , next              )               {
  if (current.decision === "deny") return current;
  if (next.decision === "deny") return next;
  if (current.decision === "force_ask") return current;
  if (next.decision === "force_ask") return next;
  return { decision: "allow" };
}

function evaluateCommandText(commandText        , depth = 0)               {
  if (!commandText || !commandText.trim()) return { decision: "allow" };
  if (commandText.length > MAX_COMMAND_CHARS) {
    return {
      decision: "deny",
      reason: "Oversized command line (>64 KiB) blocked by Coldpin fail-closed hook policy.",
    };
  }
  if (depth > MAX_WRAPPER_DEPTH) {
    return {
      decision: "deny",
      reason: "Excessively nested shell wrapper depth blocked by Coldpin hook policy.",
    };
  }

  const parsed = splitShellCommand(commandText);
  let verdict               = { decision: "allow" };

  // Inspect extracted subshells ($(...) and `...`) recursively
  for (const sub of parsed.subshells) {
    const subDecision = evaluateCommandText(sub, depth + 1);
    if (subDecision.decision === "deny") return subDecision;
    // Any npx inside a subshell must be denied (cannot run standalone pinned command inside subshell)
    if (subDecision.decision === "force_ask" && /\bnpx\b/i.test(sub)) {
      return {
        decision: "deny",
        reason: "Blocked npx invocation inside shell subshell.",
      };
    }
    verdict = mergeDecision(verdict, subDecision);
  }

  // Inspect pipe chains (download | shell) and each segment
  for (let sIdx = 0; sIdx < parsed.segments.length; sIdx++) {
    const seg = parsed.segments[sIdx] ;
    const tokens = seg.tokens;
    if (tokens.length === 0) continue;

    // Strip leading env / command / sudo / VAR=val assignments
    let idx = 0;
    const envFlags = { disableIgnoreScripts: false, registryOverride: false };
    while (idx < tokens.length) {
      const rawTok = tokens[idx] ;
      const normTok = normalizeToken(rawTok);
      const envMatch = ENV_ASSIGN_RE.exec(normTok);
      if (envMatch) {
        const keyLower = normTok.slice(0, normTok.indexOf("=")).toLowerCase();
        const valLower = (envMatch[1] ?? "").trim().toLowerCase();
        if (keyLower === "npm_config_ignore_scripts" && (valLower === "false" || valLower === "0" || valLower === "no")) {
          envFlags.disableIgnoreScripts = true;
        }
        if (keyLower === "npm_config_registry" || keyLower === "npm_config_userconfig" || keyLower === "npm_config_globalconfig") {
          envFlags.registryOverride = true;
        }
        idx++;
        continue;
      }
      const exeCandidate = normalizeExecutableName(rawTok);
      if (exeCandidate === "env" || exeCandidate === "command" || exeCandidate === "sudo" || exeCandidate === "nohup" || exeCandidate === "time") {
        idx++;
        // Skip short flags on env/sudo (e.g., env -i, sudo -E)
        while (idx < tokens.length && normalizeToken(tokens[idx] ).startsWith("-")) {
          idx++;
        }
        continue;
      }
      break;
    }

    if (idx >= tokens.length) continue;
    const exe = normalizeExecutableName(tokens[idx] );
    const rest = tokens.slice(idx + 1);

    // Download-and-execute pipe check (curl/wget/iwr/irm | sh/bash/iex/pwsh)
    if (DOWNLOAD_CMDS.has(exe) && seg.pipedIntoNext && sIdx + 1 < parsed.segments.length) {
      const nextSeg = parsed.segments[sIdx + 1] ;
      const nextExe = nextSeg.tokens[0] ? normalizeExecutableName(nextSeg.tokens[0]) : "";
      if (PIPE_EXEC_SINKS.has(nextExe)) {
        return {
          decision: "deny",
          reason: `Blocked download-and-execute pipe (${exe} | ${nextExe}) under Coldpin supply-chain policy.`,
        };
      }
    }

    // Shell wrapper recursion (sh -c, bash -c, cmd /c, pwsh -c, wsl --)
    const wrapped = extractShellWrapperPayload(exe, rest);
    if (wrapped !== null) {
      const innerDecision = evaluateCommandText(wrapped, depth + 1);
      if (innerDecision.decision === "deny") return innerDecision;
      if (innerDecision.decision === "force_ask" && parsed.hasCompound) {
        return {
          decision: "deny",
          reason: "Blocked wrapped compound package-runner invocation.",
        };
      }
      verdict = mergeDecision(verdict, innerDecision);
      continue;
    }

    // Direct npx
    if (exe === "npx") {
      const d = evaluateNpxInvocation(rest, envFlags, parsed.hasCompound || depth > 0);
      if (d.decision === "deny") return d;
      verdict = mergeDecision(verdict, d);
      continue;
    }

    // Alternative package runners: pnpx, bunx, corepack
    if (exe === "pnpx" || exe === "bunx" || exe === "corepack") {
      return {
        decision: "deny",
        reason: `Blocked unvetted package runner '${exe}'; inspect with Coldpin and use Coldpin's exact pinned command.`,
      };
    }

    // npm / pnpm / yarn / bun subcommands
    if (exe === "npm" || exe === "pnpm" || exe === "yarn" || exe === "bun") {
      const subIdx = rest.findIndex((t) => !normalizeToken(t).startsWith("-"));
      const sub = subIdx >= 0 ? normalizeToken(rest[subIdx] ).toLowerCase() : "";
      const subArgs = subIdx >= 0 ? [...rest.slice(0, subIdx), ...rest.slice(subIdx + 1)] : rest;

      if (
        (exe === "npm" && (sub === "exec" || sub === "x" || sub === "create")) ||
        (exe === "pnpm" && (sub === "dlx" || sub === "exec" || sub === "create")) ||
        (exe === "yarn" && (sub === "dlx" || sub === "create")) ||
        (exe === "bun" && (sub === "x" || sub === "create"))
      ) {
        return {
          decision: "deny",
          reason: `Blocked unvetted package runner '${exe} ${sub}'; inspect with Coldpin first.`,
        };
      }

      if (exe === "npm" && sub === "init") {
        // `npm init <pkg>` invokes create-<pkg> from npm registry! Allow only bare `npm init -y`
        const hasInitializer = subArgs.some((a) => !normalizeToken(a).startsWith("-"));
        if (hasInitializer) {
          return {
            decision: "deny",
            reason: "Blocked 'npm init <initializer>' remote package execution; inspect with Coldpin first.",
          };
        }
      }

      if (sub === "install" || sub === "i" || sub === "ci" || sub === "add") {
        const d = evaluatePackageManagerInstall(exe, sub, subArgs, envFlags);
        if (d.decision === "deny") return d;
        verdict = mergeDecision(verdict, d);
        continue;
      }
    }

    // Security control tampering via shell
    if (isSensitiveConfigCommand(tokens, commandText)) {
      verdict = mergeDecision(verdict, {
        decision: "force_ask",
        reason: "Command modifies Coldpin or npm security configuration; explicit human confirmation required.",
      });
    }
  }

  return verdict;
}

function evaluateFileEditPath(rawPath                    )               {
  if (!rawPath || typeof rawPath !== "string") return { decision: "allow" };
  const norm = rawPath.replace(/\\/g, "/").trim().toLowerCase();
  if (!norm) return { decision: "allow" };
  const slashIdx = norm.lastIndexOf("/");
  const base = slashIdx >= 0 ? norm.slice(slashIdx + 1) : norm;

  if (SENSITIVE_BASENAMES.has(base)) {
    return {
      decision: "force_ask",
      reason: `Editing security-sensitive file '${base}' requires explicit human confirmation.`,
    };
  }
  for (const suffix of SENSITIVE_SUFFIXES) {
    if (norm.endsWith(suffix) || norm === suffix.slice(1)) {
      return {
        decision: "force_ask",
        reason: `Editing security-sensitive path '${suffix.slice(1)}' requires explicit human confirmation.`,
      };
    }
  }
  return { decision: "allow" };
}

function getStringProp(obj                         , keys          )                     {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string") return v;
  }
  return undefined;
}

function isTrueFlag(val         )          {
  if (val === true) return true;
  if (typeof val === "string") return val.trim().toLowerCase() === "true";
  return false;
}

function evaluatePreToolUsePayload(payload         )               {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return {
      decision: "force_ask",
      reason: "Malformed hook payload; requiring explicit human confirmation (fail-closed).",
    };
  }

  const root = payload                           ;
  const toolCallObj =
    root["toolCall"] && typeof root["toolCall"] === "object" && !Array.isArray(root["toolCall"])
      ? (root["toolCall"]                           )
      : root;

  const toolName = getStringProp(toolCallObj, ["name", "tool_name", "toolName"]) ?? "";
  const rawArgs =
    toolCallObj["args"] ?? toolCallObj["arguments"] ?? toolCallObj["tool_input"] ?? toolCallObj["input"] ?? {};
  const args                          =
    rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs) ? (rawArgs                           ) : {};

  if (toolName === "run_command") {
    const cmd = getStringProp(args, ["CommandLine", "command", "cmd"]);
    if (!cmd) return { decision: "allow" };
    return evaluateCommandText(cmd);
  }

  if (toolName === "manage_task") {
    const action = (getStringProp(args, ["Action", "action"]) ?? "").toLowerCase();
    if (action === "send_input") {
      const input = getStringProp(args, ["Input", "input"]);
      if (!input) return { decision: "allow" };
      return evaluateCommandText(input);
    }
    return { decision: "allow" };
  }

  if (FILE_EDIT_TOOLS.has(toolName)) {
    const targetPath = getStringProp(args, ["TargetFile", "Path", "path", "file_path", "AbsolutePath", "FilePath"]);
    return evaluateFileEditPath(targetPath);
  }

  if (toolName === "define_subagent") {
    if (isTrueFlag(args["EnableWriteTools"]) || isTrueFlag(args["enable_write_tools"])) {
      return {
        decision: "force_ask",
        reason: "Dynamic subagent requests write/shell tools (EnableWriteTools=true); explicit human confirmation required.",
      };
    }
    return { decision: "allow" };
  }

  return { decision: "allow" };
}


//# sourceURL=hook-core.ts
  globalScope.ColdpinHookCore = Object.freeze({
    MAX_COMMAND_CHARS: MAX_COMMAND_CHARS,
    MAX_WRAPPER_DEPTH: MAX_WRAPPER_DEPTH,
    FILE_EDIT_TOOLS: FILE_EDIT_TOOLS,
    SENSITIVE_BASENAMES: SENSITIVE_BASENAMES,
    SENSITIVE_SUFFIXES: SENSITIVE_SUFFIXES,
    evaluateCommandText: evaluateCommandText,
    evaluateFileEditPath: evaluateFileEditPath,
    evaluatePreToolUsePayload: evaluatePreToolUsePayload
  });
})(typeof globalThis !== "undefined" ? globalThis : window);
