#!/usr/bin/env node
/**
 * Coldpin Fail-Safe PreToolUse Lifecycle Hook (Pure ES2020, Zero External Dependencies).
 *
 * Binary-verified contract for Antigravity >= v1.5.13:
 * - Benign pass-through MUST emit `{"decision":"allow"}` (exit 0) — emitting `{}` is rewritten to
 *   `"deny"` by `applyPreToolHooks`, whereas `"allow"` delegates cleanly to default policy without
 *   auto-approval (`EnsurePermissions.func1`).
 * - Provably unsafe/evasive/oversized commands emit `{"decision":"deny","reason":"..."}` (exit 0).
 * - Exact-pinned `--ignore-scripts` single-segment `npx`, sensitive config edits, `define_subagent`
 *   requests with write tools, and fail-closed parse/runtime errors emit
 *   `{"decision":"force_ask","reason":"..."}` (exit 0).
 * - Exits 0 in 100% of code paths to neutralize host fail-open on non-zero exit.
 * - Pure ES2020 only (compatible with Node 18/20/22/24/26; zero network or subprocess APIs).
 */

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  evaluateCommandText,
  evaluateFileEditPath,
  evaluatePreToolUsePayload,
  FILE_EDIT_TOOLS,
  type HookDecision,
} from "./hook-core.ts";

export {
  evaluateCommandText,
  evaluateFileEditPath,
  evaluatePreToolUsePayload,
  type HookDecision,
};

const MAX_COMMAND_STDIN_BYTES = 256 * 1024;
const MAX_EDIT_HEADER_SCAN_BYTES = 16 * 1024;
const MAX_EDIT_FALLBACK_BYTES = 8 * 1024 * 1024;

/**
 * Linear prefix JSON string extractor for oversized file-edit payloads (`>256 KiB` `CodeContent`).
 * Extracts a JSON string value for a given property key without parsing megabytes of source code.
 */
function extractJsonStringFieldFromPrefix(prefix: string, keys: string[]): string | undefined {
  for (const key of keys) {
    const needle = `"${key}"`;
    let pos = 0;
    while (pos < prefix.length) {
      const idx = prefix.indexOf(needle, pos);
      if (idx < 0) break;
      let j = idx + needle.length;
      while (j < prefix.length && (prefix[j] === " " || prefix[j] === "\t" || prefix[j] === "\r" || prefix[j] === "\n")) j++;
      if (prefix[j] !== ":") {
        pos = idx + needle.length;
        continue;
      }
      j++;
      while (j < prefix.length && (prefix[j] === " " || prefix[j] === "\t" || prefix[j] === "\r" || prefix[j] === "\n")) j++;
      if (prefix[j] !== '"') {
        pos = j;
        continue;
      }
      j++;
      let rawStr = '"';
      let closed = false;
      while (j < prefix.length) {
        const ch = prefix[j]!;
        rawStr += ch;
        if (ch === "\\" && j + 1 < prefix.length) {
          rawStr += prefix[j + 1]!;
          j += 2;
          continue;
        }
        if (ch === '"') {
          closed = true;
          break;
        }
        j++;
      }
      if (closed) {
        try {
          const parsed = JSON.parse(rawStr);
          if (typeof parsed === "string") return parsed;
        } catch {
          return undefined;
        }
      }
      pos = j;
    }
  }
  return undefined;
}

function runCliHook(): void {
  let emitted = false;
  const verbose = process.env["COLDPIN_HOOK_VERBOSE"] === "1";

  const emitAndExit = (result: HookDecision, diag?: string): void => {
    if (emitted) return;
    emitted = true;
    if (verbose && diag) {
      try {
        process.stderr.write(`[coldpin-hook] ${diag}\n`);
      } catch {
        // Ignore stderr errors
      }
    }
    try {
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } catch {
      // Best-effort stdout write
    }
    process.exit(0);
  };

  process.on("uncaughtException", (err) => {
    emitAndExit(
      { decision: "force_ask", reason: "Coldpin hook encountered an internal error; explicit human confirmation required." },
      `uncaughtException: ${err instanceof Error ? err.message : String(err)}`,
    );
  });
  process.on("unhandledRejection", (reason) => {
    emitAndExit(
      { decision: "force_ask", reason: "Coldpin hook encountered an async error; explicit human confirmation required." },
      `unhandledRejection: ${String(reason)}`,
    );
  });

  const chunks: Buffer[] = [];
  let totalBytes = 0;
  let detectedToolName: string | undefined;

  process.stdin.on("data", (chunk: Buffer | string) => {
    if (emitted) return;
    const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    totalBytes += buf.length;
    chunks.push(buf);

    if (detectedToolName === undefined && totalBytes >= 64) {
      const prefix = Buffer.concat(chunks).subarray(0, MAX_EDIT_HEADER_SCAN_BYTES).toString("utf8");
      detectedToolName = extractJsonStringFieldFromPrefix(prefix, ["name", "tool_name", "toolName"]);
    }

    if (totalBytes > MAX_COMMAND_STDIN_BYTES) {
      if (detectedToolName && FILE_EDIT_TOOLS.has(detectedToolName)) {
        const prefix = Buffer.concat(chunks).subarray(0, MAX_EDIT_HEADER_SCAN_BYTES).toString("utf8");
        const fastPath = extractJsonStringFieldFromPrefix(prefix, [
          "TargetFile",
          "Path",
          "path",
          "file_path",
          "AbsolutePath",
          "FilePath",
        ]);
        if (fastPath !== undefined) {
          emitAndExit(evaluateFileEditPath(fastPath), `fast-path edit decision for ${detectedToolName}`);
          return;
        }
        if (totalBytes > MAX_EDIT_FALLBACK_BYTES) {
          emitAndExit(
            {
              decision: "force_ask",
              reason: "Oversized file-edit payload (>8 MiB) without resolvable target path; confirmation required.",
            },
            `oversized edit payload (${totalBytes} bytes)`,
          );
          return;
        }
      } else {
        emitAndExit(
          {
            decision: "deny",
            reason: "Oversized command payload (>256 KiB) blocked by Coldpin fail-closed hook policy.",
          },
          `oversized non-edit payload (${totalBytes} bytes)`,
        );
        return;
      }
    }
  });

  process.stdin.on("end", () => {
    if (emitted) return;
    try {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) {
        emitAndExit(
          { decision: "force_ask", reason: "Empty hook stdin payload; explicit human confirmation required." },
          "empty stdin",
        );
        return;
      }
      const parsed: unknown = JSON.parse(raw);
      emitAndExit(evaluatePreToolUsePayload(parsed), "evaluated payload");
    } catch (err) {
      emitAndExit(
        { decision: "force_ask", reason: "Malformed JSON on hook stdin; explicit human confirmation required." },
        `parse error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  });

  process.stdin.on("error", (err) => {
    emitAndExit(
      { decision: "force_ask", reason: "Hook stdin read error; explicit human confirmation required." },
      `stdin error: ${err instanceof Error ? err.message : String(err)}`,
    );
  });
}

const isEntrypoint =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isEntrypoint) {
  runCliHook();
}
