#!/usr/bin/env python3
"""Reproducible multi-harness allowlist packager for Coldpin (Google EGM pattern).

Builds host-targeted runtime bundles (`antigravity`, `claude`, `openai`, or `all`) from one
canonical source tree (`skills/coldpin/` + `lib/` + `src/` + `catalog/` + `examples/` + docs):
- Explicit allowlist only (excludes .git, node_modules, tests, caches, audit logs).
- Rejects symlinks, manifest auto-approval hooks, and paths escaping the repository root.
- Validates manifest asset references, MCP `${PLUGIN_ROOT}` / `${CLAUDE_PLUGIN_ROOT}` targets,
  and EVERY relative Markdown / image link inside each generated archive.
- Supports `--no-overwrite` (EGM overwrite-refusal guard) for safe CI/release staging.
- Sorts archive entries and uses fixed timestamps (2026-01-01 00:00:00 UTC) and POSIX modes
  (`create_system=3`, `0100755` for `lib/{cli,mcp,mcp-http,hook}.mjs`, `0100644` otherwise)
  for byte-for-byte reproducibility under the same toolchain.
- Syncs `.agents/skills/coldpin/` when `--sync-workspace` is passed.
"""

import argparse
import hashlib
import json
import posixpath
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)

SHARED_GLOBS = [
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "MAINTENANCE.md",
    "TESTING.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "ACCESSIBILITY.md",
    "plugin.json",
    "mcp_config.json",
    "server.json",
    "package.json",
    "tsconfig.json",
    "assets/icon.svg",
    "docs/*.md",
    "docs/designs/*.md",
    "docs/verification/*.md",
    "examples/*",
    "examples/.*",
    "catalog/triage-rules.json",
    "catalog/mcp-schema-pin.json",
    "catalog/sigma/*.yml",
    "lib/**/*.mjs",
    "src/**/*.ts",
    "skills/coldpin/SKILL.md",
    "skills/coldpin/skill-card.md",
    "skills/coldpin/BENCHMARK.md",
    "skills/coldpin/TEST.md",
    "skills/coldpin/test_scenarios.yaml",
    "skills/coldpin/skill.oms.sig",
    "skills/coldpin/assets/*",
    "skills/coldpin/agents/*",
    "skills/coldpin/references/*.md",
    "skills/coldpin/evals/*.json",
]

HOST_GLOBS = {
    "antigravity": [
        "rules/*.md",
        "agents/*.md",
        "hooks.json",
        "skills/coldpin-audit/SKILL.md",
        "skills/coldpin-incident/SKILL.md",
        "catalog/plugin.oms.sig",
    ],
    "claude": [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"],
    "openai": [".codex-plugin/plugin.json", ".agents/plugins/marketplace.json"],
}

EXEC_ARCHIVE_PATHS = {
    "lib/cli.mjs",
    "lib/mcp.mjs",
    "lib/mcp-http.mjs",
    "lib/hook.mjs",
}

REQUIRED_ARCHIVE_PATHS = {
    "plugin.json",
    "mcp_config.json",
    "server.json",
    "package.json",
    "README.md",
    "LICENSE",
    "assets/icon.svg",
    "lib/cli.mjs",
    "lib/mcp.mjs",
    "lib/mcp-http.mjs",
    "lib/hook.mjs",
    "lib/hook-core.mjs",
    "src/cli.ts",
    "src/mcp.ts",
    "src/mcp-http.ts",
    "src/hook.ts",
    "src/hook-core.ts",
    "catalog/triage-rules.json",
    "catalog/mcp-schema-pin.json",
    "skills/coldpin/SKILL.md",
    "skills/coldpin/assets/runtime-contract.yaml",
    "skills/coldpin/skill.oms.sig",
}

MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
HTML_REF_RE = re.compile(r"""\b(?:href|src|srcset)=["']([^"']+)["']""")


def slugify_heading(heading: str) -> str:
    s = re.sub(r"`([^`]*)`", r"\1", heading)
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = s.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"\s+", "-", s)
    return s


def extract_heading_anchors(text: str) -> set[str]:
    stripped = re.sub(r"```[\s\S]*?```", "", text)
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    for line in stripped.splitlines():
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m:
            base = slugify_heading(m.group(1))
            if base in counts:
                counts[base] += 1
                anchors.add(f"{base}-{counts[base]}")
            else:
                counts[base] = 0
                anchors.add(base)
    return anchors


def collect_target_files(target: str) -> list[tuple[str, Path]]:
    found: dict[str, Path] = {}
    root_resolved = ROOT.resolve()
    patterns = SHARED_GLOBS + HOST_GLOBS[target]
    for pattern in patterns:
        for p in ROOT.glob(pattern):
            if p.is_symlink():
                raise ValueError(f"Symlink rejected in package allowlist: {p}")
            if not p.is_file():
                continue
            resolved = p.resolve()
            try:
                rel = resolved.relative_to(root_resolved).as_posix()
            except ValueError as exc:
                raise ValueError(f"Path escapes repo root: {p}") from exc
            found[rel] = resolved
    return [(k, found[k]) for k in sorted(found.keys())]


def render_archive_bytes(arc_name: str, fpath: Path) -> bytes:
    # Keep direct byte-exact passthrough (preserves signed skill.oms.sig and tests/hardening-and-packaging.test.ts:1522)
    _ = arc_name
    return fpath.read_bytes()


def validate_archive_contents(target: str, file_bytes: dict[str, bytes]) -> list[str]:
    errors: list[str] = []
    arc_names = set(file_bytes.keys())

    # 1. Verify required core paths exist (+ Antigravity-only vertical-slice isolation)
    for req in sorted(REQUIRED_ARCHIVE_PATHS):
        if req not in arc_names:
            errors.append(f"[{target}] missing required archive path: {req}")
    if target == "antigravity":
        for ag_req in (
            "hooks.json",
            "rules/AGENTS.md",
            "agents/coldpin-auditor.md",
            "skills/coldpin-audit/SKILL.md",
            "skills/coldpin-incident/SKILL.md",
            "catalog/plugin.oms.sig",
        ):
            if ag_req not in arc_names:
                errors.append(f"[antigravity] missing required Antigravity plugin path: {ag_req}")
    else:
        for ag_only in ("hooks.json", "catalog/plugin.oms.sig", "skills/coldpin-audit/SKILL.md", "skills/coldpin-incident/SKILL.md"):
            if ag_only in arc_names:
                errors.append(f"[{target}] Antigravity-only path leaked into non-Antigravity bundle: {ag_only}")

    # 2. Verify manifest paths, MCP entrypoints & zero hooks
    for manifest_name in ("plugin.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        if manifest_name not in file_bytes:
            continue
        m = json.loads(file_bytes[manifest_name].decode("utf-8"))
        if "hooks" in m:
            errors.append(f"[{target}] manifest {manifest_name} must not declare lifecycle hooks")
        logo = m.get("logo")
        if isinstance(logo, str):
            norm_logo = posixpath.normpath(logo)
            if norm_logo not in arc_names:
                errors.append(f"[{target}] {manifest_name} logo '{logo}' missing from archive")
        skills_dir = m.get("skills")
        if isinstance(skills_dir, str):
            prefix = skills_dir.strip("./") + "/"
            if not any(n.startswith(prefix) and n.endswith("/SKILL.md") for n in arc_names):
                errors.append(f"[{target}] {manifest_name} skills dir '{skills_dir}' has no packaged SKILL.md")
        ext_iface = m.get("extensions", {}).get("com.openai", {}).get("interface", {})
        for icon_key in ("composerIcon", "logo"):
            icon_val = ext_iface.get(icon_key)
            if isinstance(icon_val, str):
                norm_icon = posixpath.normpath(icon_val)
                if norm_icon not in arc_names:
                    errors.append(f"[{target}] {manifest_name} interface.{icon_key} '{icon_val}' missing from archive")
        for srv_name, srv_obj in (m.get("mcpServers") or {}).items():
            for arg in srv_obj.get("args", []):
                if isinstance(arg, str) and ("${CLAUDE_PLUGIN_ROOT}/" in arg or "${PLUGIN_ROOT}/" in arg):
                    rel_t = posixpath.normpath(
                        arg.replace("${CLAUDE_PLUGIN_ROOT}/", "").replace("${PLUGIN_ROOT}/", "")
                    )
                    if rel_t not in arc_names:
                        errors.append(f"[{target}] {manifest_name} mcpServers.{srv_name} target '{rel_t}' missing from archive")

    # 2a. Verify root mcp_config.json targets exist inside archive
    if "mcp_config.json" in file_bytes:
        mc = json.loads(file_bytes["mcp_config.json"].decode("utf-8"))
        for srv_name, srv_obj in (mc.get("mcpServers") or {}).items():
            for arg in srv_obj.get("args", []):
                if isinstance(arg, str) and "${PLUGIN_ROOT}/" in arg:
                    rel_t = posixpath.normpath(arg.replace("${PLUGIN_ROOT}/", ""))
                    if rel_t not in arc_names:
                        errors.append(f"[{target}] mcp_config.json mcpServers.{srv_name} target '{rel_t}' missing from archive")

    # 2b. Verify YAML skill metadata references inside archive
    openai_yaml = "skills/coldpin/agents/openai.yaml"
    if openai_yaml in file_bytes:
        oy_text = file_bytes[openai_yaml].decode("utf-8")
        for m in re.finditer(r'(?:icon_small|icon_large):\s*["\']?([^"\'\s]+)["\']?', oy_text):
            rel_icon = posixpath.normpath(posixpath.join("skills/coldpin", m.group(1)))
            if rel_icon not in arc_names:
                errors.append(f"[{target}] {openai_yaml}: missing icon '{m.group(1)}' (resolved '{rel_icon}')")
    scenarios_yaml = "skills/coldpin/test_scenarios.yaml"
    if scenarios_yaml in file_bytes:
        sc_text = file_bytes[scenarios_yaml].decode("utf-8")
        for m in re.finditer(r'skill_file:\s*["\']([^"\']+)["\']', sc_text):
            sf = posixpath.normpath(m.group(1))
            if sf not in arc_names:
                errors.append(f"[{target}] {scenarios_yaml}: missing skill_file '{m.group(1)}'")

    # 3. Validate relative Markdown & HTML links and #heading anchors inside packaged Markdown docs
    anchor_cache: dict[str, set[str]] = {}

    def get_anchors(name: str) -> set[str]:
        if name not in anchor_cache:
            anchor_cache[name] = extract_heading_anchors(file_bytes[name].decode("utf-8"))
        return anchor_cache[name]

    for arc_name, raw in sorted(file_bytes.items()):
        if not arc_name.endswith(".md"):
            continue
        text = raw.decode("utf-8")
        stripped = re.sub(r"```[\s\S]*?```", "", text)
        base_dir = posixpath.dirname(arc_name)
        refs = [m.group(1).strip() for m in MD_LINK_RE.finditer(stripped)]
        refs.extend(m.group(1).strip() for m in HTML_REF_RE.finditer(stripped))
        for ref in refs:
            if not ref or ref.startswith(("http://", "https://", "mailto:", "<")):
                continue
            if ref.startswith("#"):
                frag = ref[1:].strip().lower()
                if frag and frag not in get_anchors(arc_name):
                    errors.append(f"[{target}] {arc_name}: broken packaged in-page anchor '{ref}'")
                continue
            path_part, _, frag_part = ref.partition("#")
            target_part = path_part.split("?", 1)[0].strip()
            if not target_part:
                continue
            resolved = posixpath.normpath(posixpath.join(base_dir, target_part)) if base_dir else posixpath.normpath(target_part)
            if resolved.startswith(".."):
                errors.append(f"[{target}] {arc_name}: relative link escapes archive root: {ref}")
                continue
            if resolved not in arc_names and not any(n.startswith(resolved + "/") for n in arc_names):
                errors.append(f"[{target}] {arc_name}: broken packaged relative link '{ref}' (resolved '{resolved}')")
                continue
            frag = frag_part.strip().lower()
            if frag and resolved in file_bytes and resolved.endswith(".md"):
                if frag not in get_anchors(resolved):
                    errors.append(f"[{target}] {arc_name}: broken packaged cross-file anchor '{ref}' (resolved '{resolved}#{frag}')")

    return errors


def build_reproducible_zip(dest_zip: Path, items: list[tuple[str, Path]], target: str) -> str:
    file_bytes: dict[str, bytes] = {arc_name: render_archive_bytes(arc_name, fpath) for arc_name, fpath in items}
    errors = validate_archive_contents(target, file_bytes)
    if errors:
        raise ValueError("Packaged archive validation failed:\n  - " + "\n  - ".join(errors))

    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arc_name in sorted(file_bytes.keys()):
            info = zipfile.ZipInfo(filename=arc_name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o100755 if arc_name in EXEC_ARCHIVE_PATHS else 0o100644
            info.external_attr = mode << 16
            zf.writestr(info, file_bytes[arc_name])
    return hashlib.sha256(dest_zip.read_bytes()).hexdigest()


def sync_workspace_skill_mirror() -> Path:
    src_skill = ROOT / "skills" / "coldpin"
    dest_skill = ROOT / ".agents" / "skills" / "coldpin"
    legacy_skill = ROOT / ".agents" / "skills" / "npx-safe-finder"
    if legacy_skill.exists():
        shutil.rmtree(legacy_skill)
    if dest_skill.exists():
        shutil.rmtree(dest_skill)
    dest_skill.parent.mkdir(parents=True, exist_ok=True)
    for fpath in sorted(src_skill.rglob("*")):
        if fpath.is_symlink():
            raise ValueError(f"Symlink rejected in skills/coldpin: {fpath}")
        if not fpath.is_file():
            continue
        rel = fpath.relative_to(src_skill)
        out = dest_skill / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(fpath.read_bytes())
    return dest_skill


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reproducible multi-harness Coldpin bundles.")
    parser.add_argument("--target", choices=["antigravity", "claude", "openai", "all"], default="all")
    parser.add_argument("--out-dir", default=str(ROOT / "dist"))
    parser.add_argument("--verify", action="store_true", help="Build twice and assert identical SHA-256 bytes.")
    parser.add_argument("--no-overwrite", action="store_true", help="Refuse to overwrite existing target zip archives (EGM pattern).")
    parser.add_argument("--sync-workspace", action="store_true", help="Mirror skills/coldpin into .agents/skills/coldpin.")
    args = parser.parse_args()

    targets = ["antigravity", "claude", "openai"] if args.target == "all" else [args.target]
    out_dir = Path(args.out_dir)

    for target in targets:
        out_zip = out_dir / f"coldpin-{target}.zip"
        if args.no_overwrite and out_zip.exists():
            print(f"FAIL: refusing to overwrite existing archive (--no-overwrite): {out_zip}", file=sys.stderr)
            return 1
        items = collect_target_files(target)
        sha1 = build_reproducible_zip(out_zip, items, target)
        if args.verify:
            verify_zip = out_zip.with_suffix(".verify.zip")
            try:
                sha2 = build_reproducible_zip(verify_zip, items, target)
            finally:
                verify_zip.unlink(missing_ok=True)
            if sha1 != sha2:
                print(f"FAIL: non-reproducible archive for {target} ({sha1} != {sha2})", file=sys.stderr)
                return 1
            print(f"PACK REPRODUCIBLE OK [{target}]: {len(items)} files -> {out_zip.name} (sha256={sha1[:16]}...)")
        else:
            print(f"PACK OK [{target}]: {len(items)} files -> {out_zip} (sha256={sha1[:16]}...)")

    # Remove legacy stale bundle zips if present in default dist dir
    for legacy_name in ("npx-safe-finder-antigravity.zip", "npx-safe-finder-claude.zip", "npx-safe-finder-openai.zip"):
        (out_dir / legacy_name).unlink(missing_ok=True)

    if args.sync_workspace:
        dest = sync_workspace_skill_mirror()
        print(f"WORKSPACE MIRROR SYNCED: {dest.relative_to(ROOT).as_posix()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
