#!/usr/bin/env python3
"""Deep Enterprise Skill Hygiene, Reference, & URL Allow-List Validator
(Enterprise Commons `tools/verify.py` parity).

Checks across skills/coldpin/ and docs/:
1. Zero UTF-8 BOM, zero hidden/bidi/Tag Unicode, zero ASCII control chars.
2. Zero embedded prompt-injection or exploit-payload strings inside operational docs.
3. Zero hardcoded secrets / credentialed URIs.
4. Every backticked *.md path resolves cleanly.
5. Reference files carry `last_reviewed:`, `review_by:`, and `status:`.
6. Every referenced URL host appears in docs/fact-ledger.md allow-list.
"""

import datetime
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "skills" / "coldpin"
TODAY = datetime.date.today()

HIDDEN_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\U000e0000-\U000e007f]")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
INJECT_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts)"
    r"|disregard (the )?(system|previous) (prompt|instructions)"
    r"|you are now (dan|in developer mode)"
    r"|reveal (your|the) system prompt",
    re.I,
)
SECRET_RE = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{25,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\bAIza[0-9A-Za-z_-]{33,}"
)
PAYLOAD_RE = re.compile(r"msfvenom|(\\x90){6,}|shellcode\s*=\s*b?[\"']\\x", re.I)
MDREF_RE = re.compile(r"`([\w./\-]+\.md)`")
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
HTML_REF_RE = re.compile(r"""\b(?:href|src|srcset)=["']([^"']+)["']""")
URL_RE = re.compile(r"https?://([\w.\-]+)")


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


def resolve_md_ref(source_file: Path, ref: str) -> bool:
    if ref in (
        "SKILL.md",
        "README.md",
        "CHANGELOG.md",
        "BENCHMARK.md",
        "TESTING.md",
        "TEST.md",
        "MAINTENANCE.md",
        "SITEMAP.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "ACCESSIBILITY.md",
        "AGENTS.md",
        "GEMINI.md",
    ):
        return True
    candidates = [
        source_file.parent / ref,
        SKILL_DIR / ref,
        SKILL_DIR / "references" / ref,
        ROOT / ref,
        ROOT / "rules" / ref,
        ROOT / "agents" / ref,
        ROOT / "docs" / ref,
        ROOT / "docs" / "designs" / ref,
    ]
    return any(c.resolve().exists() for c in candidates)


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    hosts: dict[str, set[str]] = {}

    files_to_check: list[tuple[Path, bool]] = [
        (SKILL_DIR / "SKILL.md", False),
        (SKILL_DIR / "skill-card.md", False),
        (SKILL_DIR / "BENCHMARK.md", False),
        (SKILL_DIR / "TEST.md", False),
        (ROOT / "README.md", False),
        (ROOT / "CHANGELOG.md", False),
        (ROOT / "TESTING.md", False),
        (ROOT / "SECURITY.md", False),
        (ROOT / "CONTRIBUTING.md", False),
        (ROOT / "ACCESSIBILITY.md", False),
        (ROOT / "MAINTENANCE.md", True),
        (ROOT / "docs" / "fact-ledger.md", True),
        (ROOT / "docs" / "getting_started.md", False),
        (ROOT / "docs" / "harnesses.md", False),
        (ROOT / "docs" / "privacy.md", False),
        (ROOT / "docs" / "faq.md", False),
        (ROOT / "docs" / "designs" / "coldpin.md", False),
        (ROOT / "docs" / "designs" / "SITEMAP.md", False),
        (ROOT / "docs" / "verification" / "skill-inspector-self-audit.md", False),
    ]
    for ref in sorted((SKILL_DIR / "references").glob("*.md")):
        files_to_check.append((ref, True))
    for extra_skill in ("coldpin-audit", "coldpin-incident"):
        sp = ROOT / "skills" / extra_skill / "SKILL.md"
        if sp.exists():
            files_to_check.append((sp, False))
    for extra_dir in (ROOT / "rules", ROOT / "agents"):
        if extra_dir.is_dir():
            for md_f in sorted(extra_dir.glob("*.md")):
                files_to_check.append((md_f, False))
    hooks_json = ROOT / "hooks.json"
    if hooks_json.exists():
        files_to_check.append((hooks_json, False))
    examples_dir = ROOT / "examples"
    if examples_dir.is_dir():
        for ex_f in sorted(examples_dir.glob("*.json")):
            files_to_check.append((ex_f, False))
    gh_pr_tpl = ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
    if gh_pr_tpl.exists():
        files_to_check.append((gh_pr_tpl, False))
    gh_issue_dir = ROOT / ".github" / "ISSUE_TEMPLATE"
    if gh_issue_dir.is_dir():
        for tpl in sorted(gh_issue_dir.glob("*.yml")):
            files_to_check.append((tpl, False))

    for fpath, require_ref_meta in files_to_check:
        if not fpath.exists():
            errors.append(f"Missing expected doc: {fpath.relative_to(ROOT).as_posix()}")
            continue
        rel = fpath.relative_to(ROOT).as_posix()
        raw = fpath.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            errors.append(f"{rel}: UTF-8 BOM present")
        txt = raw.decode("utf-8")
        if HIDDEN_RE.search(txt):
            errors.append(f"{rel}: hidden/bidi/Tag Unicode present")
        if CTRL_RE.search(txt):
            errors.append(f"{rel}: ASCII control characters present")
        if INJECT_RE.search(txt):
            errors.append(f"{rel}: embedded prompt-injection phrase present")
        if SECRET_RE.search(txt):
            errors.append(f"{rel}: secret-like token present")
        if PAYLOAD_RE.search(txt):
            errors.append(f"{rel}: exploit-payload pattern present")

        for m in MDREF_RE.finditer(txt):
            ref_str = m.group(1)
            if not resolve_md_ref(fpath, ref_str):
                errors.append(f"{rel}: unresolved backticked markdown reference `{ref_str}`")

        # Validate all relative Markdown links, HTML href/src asset references, and #heading anchors on disk
        stripped_code = re.sub(r"```[\s\S]*?```", "", txt)
        rel_refs = [m.group(1).strip() for m in MD_LINK_RE.finditer(stripped_code)]
        rel_refs.extend(m.group(1).strip() for m in HTML_REF_RE.finditer(stripped_code))
        self_anchors: set[str] | None = None
        for ref in rel_refs:
            if not ref or ref.startswith(("http://", "https://", "mailto:", "<")):
                continue
            if ref.startswith("#"):
                frag = ref[1:].strip().lower()
                if frag:
                    if self_anchors is None:
                        self_anchors = extract_heading_anchors(txt)
                    if frag not in self_anchors:
                        errors.append(f"{rel}: broken in-page heading anchor '{ref}'")
                continue
            path_part, _, frag_part = ref.partition("#")
            target_part = path_part.split("?", 1)[0].strip()
            if not target_part:
                continue
            resolved_target = (fpath.parent / target_part).resolve()
            try:
                resolved_target.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"{rel}: relative link escapes repo root: {ref}")
                continue
            if not resolved_target.exists():
                errors.append(f"{rel}: broken relative link '{ref}'")
                continue
            frag = frag_part.strip().lower()
            if frag and resolved_target.is_file() and resolved_target.suffix.lower() == ".md":
                target_anchors = extract_heading_anchors(resolved_target.read_text(encoding="utf-8"))
                if frag not in target_anchors:
                    errors.append(f"{rel}: broken cross-file heading anchor '{ref}'")

        for m in URL_RE.finditer(txt):
            hosts.setdefault(m.group(1).lower(), set()).add(rel)

        if require_ref_meta:
            head = txt.replace("\r\n", "\n")[:1200]
            for field in ("last_reviewed:", "review_by:", "status:"):
                if field not in head:
                    errors.append(f"{rel}: missing required metadata '{field}'")
            rm = re.search(r"review_by:\s*(\d{4}-\d{2}-\d{2})", head)
            if rm and datetime.date.fromisoformat(rm.group(1)) < TODAY:
                warnings.append(f"{rel}: STALE review_by {rm.group(1)}")

    ledger_txt = (ROOT / "docs" / "fact-ledger.md").read_text(encoding="utf-8").lower()
    unlisted_hosts = sorted(h for h in hosts if h not in ledger_txt and not h.startswith("<"))
    if unlisted_hosts:
        for h in unlisted_hosts:
            errors.append(f"URL host '{h}' not listed in docs/fact-ledger.md allow-list (used in {sorted(hosts[h])[:2]})")

    # Validate bundled SVG assets: valid XML, UTF-8 without BOM, LF-only, zero active script/external URLs,
    # canonical icon byte-parity, and legacy npm v1.5.0-v1.5.2 banner contract.
    svg_paths = [
        ROOT / "assets" / "icon.svg",
        ROOT / "skills" / "coldpin" / "assets" / "icon.svg",
        ROOT / "site" / "icon.svg",
        ROOT / "docs" / "assets" / "readme-header.svg",
    ]
    svg_bytes_map: dict[str, bytes] = {}
    for sp in svg_paths:
        rel_svg = sp.relative_to(ROOT).as_posix()
        if not sp.exists():
            errors.append(f"{rel_svg}: missing expected SVG asset")
            continue
        raw_svg = sp.read_bytes()
        svg_bytes_map[rel_svg] = raw_svg
        if raw_svg.startswith(b"\xef\xbb\xbf"):
            errors.append(f"{rel_svg}: UTF-8 BOM present")
        if b"\r\n" in raw_svg:
            errors.append(f"{rel_svg}: CRLF line endings present (must be LF)")
        try:
            svg_txt = raw_svg.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{rel_svg}: invalid UTF-8 encoding")
            continue
        if HIDDEN_RE.search(svg_txt):
            errors.append(f"{rel_svg}: hidden/bidi/Tag Unicode present")
        try:
            root_el = ET.fromstring(svg_txt)
        except ET.ParseError as exc:
            errors.append(f"{rel_svg}: malformed SVG XML ({exc})")
            continue
        for el in root_el.iter():
            tag_local = el.tag.rsplit("}", 1)[-1].lower()
            if tag_local in ("script", "foreignobject", "iframe", "object", "embed"):
                errors.append(f"{rel_svg}: disallowed active SVG element <{tag_local}>")
            for attr_k, attr_v in el.attrib.items():
                attr_local = attr_k.rsplit("}", 1)[-1].lower()
                if attr_local.startswith("on"):
                    errors.append(f"{rel_svg}: disallowed SVG event handler '{attr_local}'")
                if attr_local in ("href", "src") and re.search(r"^\s*(?:https?:|javascript:|data:)", attr_v, re.I):
                    errors.append(f"{rel_svg}: disallowed external/active URI in '{attr_local}'")
        if rel_svg == "docs/assets/readme-header.svg":
            if root_el.attrib.get("viewBox") != "0 0 480 116":
                errors.append(f"{rel_svg}: legacy npm v1.5.0-v1.5.2 banner must keep viewBox='0 0 480 116'")
            if "prefers-color-scheme" in svg_txt:
                errors.append(f"{rel_svg}: must not use prefers-color-scheme inside sandboxed <img> SVG")
            if not any(el.tag.rsplit("}", 1)[-1].lower() == "title" and (el.text or "").strip() for el in root_el.iter()):
                errors.append(f"{rel_svg}: missing non-empty <title> element")
    canonical_icon = svg_bytes_map.get("assets/icon.svg")
    if canonical_icon is not None:
        for mirror_rel in ("skills/coldpin/assets/icon.svg", "site/icon.svg"):
            if mirror_rel in svg_bytes_map and svg_bytes_map[mirror_rel] != canonical_icon:
                errors.append(f"{mirror_rel}: byte mismatch against canonical assets/icon.svg")

    # Validate static documentation portal under site/: zero BOM, LF-only, valid UTF-8,
    # zero hidden/bidi/control/secret/injection strings, dual-CSP sync, zero 'unsafe-inline',
    # and zero innerHTML sinks in site/*.js.
    site_dir = ROOT / "site"
    site_files_checked = 0
    if not site_dir.is_dir():
        errors.append("site/: missing documentation portal directory")
    else:
        required_site_files = (
            "index.html",
            "404.html",
            "robots.txt",
            "sitemap.xml",
            "llms.txt",
            "search-index.json",
            "theme-init.js",
            "hook-eval.js",
            "styles.css",
            "app.js",
            "evidence-card-app/index.html",
            "evidence-card-app.css",
            "evidence-card-app.js",
            "_headers",
            ".nojekyll",
            "icon.svg",
        )
        for req_name in required_site_files:
            if not (site_dir / req_name).exists():
                errors.append(f"site/{req_name}: missing required documentation portal asset")
        if (site_dir / "evidence-card-app.html").exists():
            errors.append("site/evidence-card-app.html: legacy flat HTML route must not exist (use site/evidence-card-app/index.html)")

        headers_path = site_dir / "_headers"
        expected_meta_csp = None
        expected_app_meta_csp = None
        if headers_path.exists():
            h_txt = headers_path.read_text(encoding="utf-8")
            m_csp = re.search(r"(?m)^/\*\n[\s\S]*?^\s+Content-Security-Policy:\s*(.+)$", h_txt)
            if not m_csp:
                errors.append("site/_headers: missing /* Content-Security-Policy header")
            else:
                edge_csp = m_csp.group(1).strip()
                if "unsafe-inline" in edge_csp or "unsafe-eval" in edge_csp:
                    errors.append("site/_headers: disallowed 'unsafe-inline'/'unsafe-eval' in /* CSP")
                if "connect-src 'self'" not in edge_csp:
                    errors.append("site/_headers: /* CSP must include connect-src 'self'")
                # Derive expected HTML <meta> CSP by stripping HTTP-header-only directives
                meta_parts = [
                    d.strip()
                    for d in edge_csp.split(";")
                    if d.strip()
                    and not d.strip().startswith("frame-ancestors ")
                    and d.strip() != "upgrade-insecure-requests"
                ]
                expected_meta_csp = "; ".join(meta_parts) + ";"

            if "/evidence-card-app.html" in h_txt:
                errors.append("site/_headers: must not reference legacy /evidence-card-app.html")
            app_edge_csps: dict[str, str] = {}
            for app_route in ("/evidence-card-app", "/evidence-card-app/", "/evidence-card-app/index.html"):
                block_re = re.compile(
                    r"(?m)^"
                    + re.escape(app_route)
                    + r"\n"
                    + r"  ! Content-Security-Policy\n"
                    + r"  ! X-Frame-Options\n"
                    + r"  Content-Security-Policy: ([^\n]+)\n"
                    + r"  X-Frame-Options: SAMEORIGIN\n"
                    + r"  Cache-Control: public, max-age=0, must-revalidate$"
                )
                m_app = block_re.search(h_txt)
                if not m_app:
                    errors.append(f"site/_headers: missing exact Cloudflare frame-override block for {app_route}")
                    continue
                if m_csp and m_app.start() <= m_csp.start():
                    errors.append(f"site/_headers: {app_route} override block must appear after /* rule")
                app_csp = m_app.group(1).strip()
                if "unsafe-inline" in app_csp or "unsafe-eval" in app_csp:
                    errors.append(f"site/_headers: disallowed 'unsafe-inline'/'unsafe-eval' in {app_route} CSP")
                if "frame-ancestors 'self'" not in app_csp:
                    errors.append(f"site/_headers: {app_route} CSP must allow frame-ancestors 'self'")
                app_edge_csps[app_route] = app_csp
            if len(set(app_edge_csps.values())) > 1:
                errors.append("site/_headers: /evidence-card-app* routes declare divergent CSP values")
            elif "/evidence-card-app/" in app_edge_csps:
                app_meta_parts = [
                    d.strip()
                    for d in app_edge_csps["/evidence-card-app/"].split(";")
                    if d.strip()
                    and not d.strip().startswith("frame-ancestors ")
                    and d.strip() != "upgrade-insecure-requests"
                ]
                expected_app_meta_csp = "; ".join(app_meta_parts) + ";"

        meta_csp_re = re.compile(
            r'<meta\s+http-equiv=["\']Content-Security-Policy["\']\s+content="([^"]+)"',
            re.I,
        )
        for sf in sorted(site_dir.rglob("*")):
            if sf.is_symlink():
                errors.append(f"{sf.relative_to(ROOT).as_posix()}: symlink not permitted inside site/")
                continue
            if not sf.is_file():
                continue
            site_files_checked += 1
            srel = sf.relative_to(ROOT).as_posix()
            sraw = sf.read_bytes()
            if sraw.startswith(b"\xef\xbb\xbf"):
                errors.append(f"{srel}: UTF-8 BOM present")
            if b"\r\n" in sraw:
                errors.append(f"{srel}: CRLF line endings present (must be LF)")
            try:
                stxt = sraw.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(f"{srel}: invalid UTF-8 encoding")
                continue
            if HIDDEN_RE.search(stxt):
                errors.append(f"{srel}: hidden/bidi/Tag Unicode present")
            if CTRL_RE.search(stxt):
                errors.append(f"{srel}: ASCII control characters present")
            if INJECT_RE.search(stxt):
                errors.append(f"{srel}: embedded prompt-injection phrase present")
            if SECRET_RE.search(stxt):
                errors.append(f"{srel}: secret-like token present")
            if PAYLOAD_RE.search(stxt):
                errors.append(f"{srel}: exploit-payload pattern present")

            if sf.suffix.lower() == ".html":
                mm = meta_csp_re.search(stxt)
                if not mm:
                    errors.append(f"{srel}: missing <meta http-equiv='Content-Security-Policy'>")
                else:
                    mcsp = mm.group(1).strip()
                    if "unsafe-inline" in mcsp or "unsafe-eval" in mcsp:
                        errors.append(f"{srel}: disallowed 'unsafe-inline'/'unsafe-eval' in <meta> CSP")
                    if srel == "site/evidence-card-app/index.html":
                        if expected_app_meta_csp and mcsp != expected_app_meta_csp:
                            errors.append(f"{srel}: <meta> CSP drifted from site/_headers /evidence-card-app/ ({mcsp} != {expected_app_meta_csp})")
                    elif expected_meta_csp and mcsp != expected_meta_csp:
                        errors.append(f"{srel}: <meta> CSP drifted from site/_headers ({mcsp} != {expected_meta_csp})")
            elif sf.suffix.lower() == ".js":
                js_nc = re.sub(r"/\*[\s\S]*?\*/|//[^\n]*", "", stxt)
                for bad_sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
                    if bad_sink in js_nc:
                        errors.append(f"{srel}: forbidden DOM sink '{bad_sink}' in site JS")

    desc_txt = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    dm = re.search(r"description:\s*(?:>-?\s*)?(.*?)\n(?:[a-z_-]+:|---)", desc_txt, re.S)
    desc_len = len(" ".join(dm.group(1).split())) if dm else 0

    print(
        f"Hygiene audit: {len(files_to_check)} docs + {len(svg_bytes_map)} SVGs + {site_files_checked} site files checked | "
        f"URL hosts: {len(hosts)} (unlisted: {len(unlisted_hosts)}) | SKILL.md description: {desc_len} chars"
    )
    if warnings:
        for w in warnings:
            print(f"  WARN: {w}")
    if errors:
        print("VERIFY HYGIENE FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("VERIFY HYGIENE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
