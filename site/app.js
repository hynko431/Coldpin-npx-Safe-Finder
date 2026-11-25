/* Coldpin Documentation Portal v2 Runtime
 * Pure ES2020 | Zero innerHTML | Strict CSP ('self') | WCAG 2.2 AA
 * Features: 3-way Theme + BroadcastChannel sync, 4-Harness Master Selector,
 * Native Popover Markdown menu, Mobile Cards|Table switcher, WAI-ARIA Ctrl+K RRF Search,
 * CSS.highlights zero-XSS highlighting, Exact hook-eval.js Policy Lab, Live SEP-1865 MCP App,
 * Safe read-only Antigravity Prompt Composer, and Read-only WebMCP (document.modelContext).
 */
(function () {
  "use strict";

  var DOC_VERSION = "1.6.1";
  var VALID_SLUGS = ["overview","quickstart","harnesses","policy-lab","antigravity-plugin","agents-and-rules","hooks","slash-commands","mcp-tools","cli-reference","enterprise-http","configuration","privacy","security","verification","changelog","faq"];
  var RELEASE_CHECKSUMS = "7983b4d4f02cf556de1de458e986d0d6394030f360722bc6e645feeee0ef2822  coldpin-antigravity.zip\n3b520c6688d56f88dcd213470f9d10d9e1345fd73d16909c6055989d65f9e50a  coldpin-claude.zip\n723fc06ed8a8989c738d7f8e216b5f12e018efd2a0ae82a6f6b901dd988223df  coldpin-openai.zip\n929682d1dd7ef2b40b82e8e8cce3ac25344631399987ab9493cbd0a98a73caf9  skillspector-self-audit.sarif";
  var RELEASE_URL = "https://github.com/hynko431/Coldpin-npx-Safe-Finder/releases/tag/v1.6.1";
  var MAX_INPUT_LEN = 4096;
  var WEBMCP_MAX_CHARS = 1500;

  var root = document.documentElement;
  var docsRoot = root.getAttribute("data-docs-root") || ".";
  var announcer = document.getElementById("live-announcer");
  var senderId = (typeof crypto !== "undefined" && crypto.randomUUID)
    ? crypto.randomUUID()
    : ("tab-" + String(Date.now()) + "-" + String(Math.random()).slice(2, 10));

  var bc = null;
  try {
    if (typeof BroadcastChannel === "function") {
      bc = new BroadcastChannel("coldpin-docs-sync");
    }
  } catch (_) {}

  function announce(msg) {
    if (!announcer) return;
    announcer.textContent = "";
    window.setTimeout(function () {
      announcer.textContent = msg;
    }, 30);
  }

  function resolveRelHref(logicalHref) {
    if (!logicalHref) return docsRoot + "/";
    if (/^https?:\/\//.test(logicalHref) || logicalHref.charAt(0) === "#") return logicalHref;
    if (logicalHref === "/") return docsRoot === "." ? "./" : docsRoot + "/";
    return docsRoot + "/" + logicalHref.replace(/^\/+/, "");
  }

  /* ========================================================================
     1. 3-WAY THEME SELECTOR (Auto | Light | Dark) + BROADCASTCHANNEL SYNC
     ======================================================================== */
  var themeButtons = Array.prototype.slice.call(document.querySelectorAll("[data-theme-set]"));

  function systemPrefersDark() {
    return Boolean(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  }

  function resolveTheme(mode) {
    var m = mode || root.getAttribute("data-theme-mode") || "auto";
    if (m === "light" || m === "dark") return m;
    return systemPrefersDark() ? "dark" : "light";
  }

  function notifyMcpAppTheme(resolvedTheme) {
    var frame = document.getElementById("mcp-app-frame");
    if (frame && frame.contentWindow) {
      try {
        frame.contentWindow.postMessage({
          jsonrpc: "2.0",
          method: "ui/notifications/host-context-changed",
          params: { theme: resolvedTheme }
        }, "*");
      } catch (_) {}
    }
  }

  function applyThemeMode(mode, shouldPersist, shouldBroadcast) {
    var valid = (mode === "auto" || mode === "light" || mode === "dark") ? mode : "auto";
    var resolved = resolveTheme(valid);
    root.setAttribute("data-theme-mode", valid);
    root.setAttribute("data-theme", resolved);
    themeButtons.forEach(function (btn) {
      btn.setAttribute("aria-pressed", btn.getAttribute("data-theme-set") === valid ? "true" : "false");
    });
    if (shouldPersist) {
      try {
        window.localStorage.setItem("coldpin-docs-theme-mode", valid);
      } catch (_) {}
    }
    if (shouldBroadcast && bc) {
      try {
        bc.postMessage({ sender: senderId, type: "theme", mode: valid });
      } catch (_) {}
    }
    notifyMcpAppTheme(resolved);
  }

  applyThemeMode(root.getAttribute("data-theme-mode") || "auto", false, false);

  themeButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var mode = btn.getAttribute("data-theme-set") || "auto";
      applyThemeMode(mode, true, true);
      announce("Theme set to " + mode);
    });
  });

  if (window.matchMedia) {
    var mediaQ = window.matchMedia("(prefers-color-scheme: dark)");
    var onSystemChange = function () {
      if ((root.getAttribute("data-theme-mode") || "auto") === "auto") {
        applyThemeMode("auto", false, false);
      }
    };
    if (typeof mediaQ.addEventListener === "function") {
      mediaQ.addEventListener("change", onSystemChange);
    }
  }

  /* ========================================================================
     2. DISMISSIBLE ANNOUNCEMENT BAR
     ======================================================================== */
  var announceBar = document.getElementById("announcement-bar");
  var announceDismiss = document.getElementById("announcement-dismiss");
  if (announceBar && announceDismiss) {
    announceDismiss.addEventListener("click", function () {
      root.setAttribute("data-announce-dismissed", "true");
      announceBar.hidden = true;
      try {
        window.localStorage.setItem("coldpin-docs-announce-v" + DOC_VERSION, "dismissed");
      } catch (_) {}
      announce("Release announcement dismissed");
    });
  }

  /* ========================================================================
     3. MOBILE SIDEBAR DRAWER + SESSIONSTORAGE STATE PERSISTENCE
     ======================================================================== */
  var sidebar = document.getElementById("docs-sidebar");
  var menuBtn = document.getElementById("mobile-menu-btn");
  var sidebarBackdrop = document.getElementById("sidebar-backdrop");

  function setMenuOpen(open) {
    if (!sidebar || !menuBtn) return;
    sidebar.classList.toggle("is-open", open);
    menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    menuBtn.textContent = open ? "Close" : "Menu";
    if (sidebarBackdrop) sidebarBackdrop.hidden = !open;
  }

  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", function () {
      setMenuOpen(!sidebar.classList.contains("is-open"));
    });
    if (sidebarBackdrop) {
      sidebarBackdrop.addEventListener("click", function () {
        setMenuOpen(false);
        menuBtn.focus();
      });
    }
    sidebar.addEventListener("click", function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest("a.nav-link")) {
        setMenuOpen(false);
      }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && sidebar.classList.contains("is-open")) {
        setMenuOpen(false);
        menuBtn.focus();
      }
    });

    // Persist sidebar scroll & collapsible group state in sessionStorage
    try {
      var savedScroll = Number(window.sessionStorage.getItem("coldpin-sidebar-scroll") || "0");
      if (savedScroll > 0) sidebar.scrollTop = savedScroll;
      sidebar.addEventListener("scroll", function () {
        try {
          window.sessionStorage.setItem("coldpin-sidebar-scroll", String(sidebar.scrollTop));
        } catch (_) {}
      }, { passive: true });

      var groups = sidebar.querySelectorAll("details[data-nav-group]");
      var activePillar = root.getAttribute("data-pillar") || "";
      for (var g = 0; g < groups.length; g++) {
        (function (det) {
          var gid = det.getAttribute("data-nav-group") || "";
          var st = window.sessionStorage.getItem("coldpin-nav-" + gid);
          if (st === "open") det.open = true;
          else if (st === "closed" && gid !== activePillar) det.open = false;
          det.addEventListener("toggle", function () {
            try {
              window.sessionStorage.setItem("coldpin-nav-" + gid, det.open ? "open" : "closed");
            } catch (_) {}
          });
        })(groups[g]);
      }
    } catch (_) {}
  }

  /* ========================================================================
     4. SYNCED 4-HARNESS MASTER SELECTOR (?surface=, localStorage, Dynamic TOC)
     ======================================================================== */
  var VALID_SURFACES = { antigravity: true, "npm-cli": true, "mcp-hosts": true, "enterprise-http": true };
  var surfaceCards = Array.prototype.slice.call(document.querySelectorAll("[data-surface-select]"));
  var surfacePanes = Array.prototype.slice.call(document.querySelectorAll("[data-surface-pane]"));
  var tocSurfaceItems = Array.prototype.slice.call(document.querySelectorAll("[data-toc-surface]"));

  function applySurface(surfaceId, updateUrl, shouldPersist, shouldBroadcast) {
    var chosen = VALID_SURFACES[surfaceId] ? surfaceId : "antigravity";
    surfaceCards.forEach(function (card) {
      card.setAttribute("aria-pressed", card.getAttribute("data-surface-select") === chosen ? "true" : "false");
    });
    surfacePanes.forEach(function (pane) {
      pane.hidden = pane.getAttribute("data-surface-pane") !== chosen;
    });
    tocSurfaceItems.forEach(function (li) {
      li.hidden = li.getAttribute("data-toc-surface") !== chosen;
    });
    if (shouldPersist) {
      try {
        window.localStorage.setItem("coldpin-docs-surface", chosen);
      } catch (_) {}
    }
    if (updateUrl && window.history && typeof window.history.replaceState === "function") {
      try {
        var u = new URL(window.location.href);
        u.searchParams.set("surface", chosen);
        window.history.replaceState(null, "", u.pathname + u.search + u.hash);
      } catch (_) {}
    }
    if (shouldBroadcast && bc) {
      try {
        bc.postMessage({ sender: senderId, type: "surface", surface: chosen });
      } catch (_) {}
    }
  }

  if (surfaceCards.length > 0) {
    var initSurface = "antigravity";
    try {
      var sp = new URLSearchParams(window.location.search).get("surface");
      if (sp && VALID_SURFACES[sp]) {
        initSurface = sp;
      } else {
        var savedSurf = window.localStorage.getItem("coldpin-docs-surface");
        if (savedSurf && VALID_SURFACES[savedSurf]) initSurface = savedSurf;
      }
    } catch (_) {}
    applySurface(initSurface, false, false, false);

    surfaceCards.forEach(function (card) {
      card.addEventListener("click", function () {
        var s = card.getAttribute("data-surface-select") || "antigravity";
        applySurface(s, true, true, true);
        announce("Selected harness: " + s);
      });
    });
  }

  if (bc) {
    bc.addEventListener("message", function (ev) {
      var d = ev.data;
      if (!d || typeof d !== "object" || d.sender === senderId) return;
      if (d.type === "theme") applyThemeMode(d.mode, false, false);
      if (d.type === "surface" && surfaceCards.length > 0) applySurface(d.surface, false, false, false);
    });
  }

  /* ========================================================================
     5. NATIVE POPOVER MARKDOWN MENU + COPY MARKDOWN
     ======================================================================== */
  var mdBtn = document.getElementById("md-menu-btn");
  var mdPopover = document.getElementById("md-menu-popover");
  var hasNativePopover = Boolean(mdPopover && typeof mdPopover.showPopover === "function");

  if (mdBtn && mdPopover) {
    if (hasNativePopover) {
      mdPopover.addEventListener("toggle", function (ev) {
        var isOpen = ev.newState === "open";
        mdBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      });
    } else {
      mdBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var open = !mdPopover.classList.contains("is-fallback-open");
        mdPopover.classList.toggle("is-fallback-open", open);
        mdBtn.setAttribute("aria-expanded", open ? "true" : "false");
      });
      document.addEventListener("click", function (ev) {
        if (!mdPopover.contains(ev.target) && ev.target !== mdBtn) {
          mdPopover.classList.remove("is-fallback-open");
          mdBtn.setAttribute("aria-expanded", "false");
        }
      });
    }
  }

  function closeMdPopover() {
    if (!mdPopover) return;
    if (hasNativePopover) {
      try { mdPopover.hidePopover(); } catch (_) {}
    } else {
      mdPopover.classList.remove("is-fallback-open");
      if (mdBtn) mdBtn.setAttribute("aria-expanded", "false");
    }
  }

  var copyMdBtns = document.querySelectorAll("[data-copy-md]");
  for (var mIdx = 0; mIdx < copyMdBtns.length; mIdx++) {
    copyMdBtns[mIdx].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var mdUrl = btn.getAttribute("data-copy-md");
      if (!mdUrl || typeof fetch !== "function") return;
      btn.textContent = "Copying...";
      fetch(mdUrl, { credentials: "same-origin" })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.text();
        })
        .then(function (mdText) {
          if (!navigator.clipboard || !navigator.clipboard.writeText) {
            throw new Error("Clipboard unavailable");
          }
          return navigator.clipboard.writeText(mdText);
        })
        .then(function () {
          btn.textContent = "Copied Markdown";
          announce("Copied raw Markdown to clipboard");
          window.setTimeout(function () {
            btn.textContent = "Copy Markdown";
            closeMdPopover();
          }, 900);
        })
        .catch(function () {
          btn.textContent = "Copy failed";
          announce("Unable to copy Markdown; use View Markdown link");
          window.setTimeout(function () {
            btn.textContent = "Copy Markdown";
          }, 1500);
        });
    });
  }

  /* ========================================================================
     6. WAI-ARIA TAB GROUPS, COPY BUTTONS, HEADING ANCHORS, DETAILS TOOLBAR
     ======================================================================== */
  var tablists = document.querySelectorAll('[role="tablist"]');
  function activateTab(tablist, targetTab, shouldFocus) {
    var tabs = tablist.querySelectorAll('[role="tab"]');
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i];
      var selected = tab === targetTab;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.setAttribute("tabindex", selected ? "0" : "-1");
      var panelId = tab.getAttribute("aria-controls");
      var panel = panelId ? document.getElementById(panelId) : null;
      if (panel) panel.hidden = !selected;
    }
    if (shouldFocus) targetTab.focus();
  }

  for (var t = 0; t < tablists.length; t++) {
    (function (tablist) {
      var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
      tabs.forEach(function (tab, idx) {
        tab.addEventListener("click", function () {
          activateTab(tablist, tab, false);
        });
        tab.addEventListener("keydown", function (ev) {
          var nextIdx = -1;
          if (ev.key === "ArrowRight") nextIdx = (idx + 1) % tabs.length;
          else if (ev.key === "ArrowLeft") nextIdx = (idx - 1 + tabs.length) % tabs.length;
          else if (ev.key === "Home") nextIdx = 0;
          else if (ev.key === "End") nextIdx = tabs.length - 1;
          if (nextIdx !== -1) {
            ev.preventDefault();
            activateTab(tablist, tabs[nextIdx], true);
          }
        });
      });
    })(tablists[t]);
  }

  var copyButtons = document.querySelectorAll(".copy-btn[data-copy]");
  for (var c = 0; c < copyButtons.length; c++) {
    copyButtons[c].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var origLabel = btn.textContent || "Copy";
      var targetId = btn.getAttribute("data-copy");
      var el = targetId ? document.getElementById(targetId) : null;
      if (!el) return;
      var text = el.textContent || "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = "Copied";
          announce("Copied snippet to clipboard");
          window.setTimeout(function () { btn.textContent = origLabel; }, 1600);
        }, function () {
          announce("Copy failed: select the text manually");
        });
      } else {
        announce("Clipboard API unavailable: select the text manually");
      }
    });
  }

  var anchorBtns = document.querySelectorAll(".heading-anchor-btn[data-copy-anchor]");
  for (var a = 0; a < anchorBtns.length; a++) {
    anchorBtns[a].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var id = btn.getAttribute("data-copy-anchor");
      if (!id) return;
      var url = window.location.href.split("#")[0] + "#" + id;
      if (window.history && typeof window.history.replaceState === "function") {
        window.history.replaceState(null, "", "#" + id);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function () {
          btn.textContent = "✓";
          announce("Copied section link #" + id);
          window.setTimeout(function () { btn.textContent = "#"; }, 1400);
        }, function () {});
      }
    });
  }

  var detailsToolbars = document.querySelectorAll(".details-toolbar[data-details-target]");
  for (var dt = 0; dt < detailsToolbars.length; dt++) {
    (function (bar) {
      var targetId = bar.getAttribute("data-details-target");
      var container = targetId ? document.getElementById(targetId) : null;
      if (!container) return;
      var btns = bar.querySelectorAll("[data-details-action]");
      for (var b = 0; b < btns.length; b++) {
        btns[b].addEventListener("click", function (ev) {
          var action = ev.currentTarget.getAttribute("data-details-action");
          var items = container.querySelectorAll("details");
          var open = action === "expand";
          for (var k = 0; k < items.length; k++) items[k].open = open;
          announce(open ? "Expanded all releases" : "Collapsed all releases");
        });
      }
    })(detailsToolbars[dt]);
  }

  /* ========================================================================
     7. MOBILE CARDS | TABLE VIEW SWITCHER
     ======================================================================== */
  var tableSwitchers = document.querySelectorAll('[data-table-switcher="true"]');
  for (var ts = 0; ts < tableSwitchers.length; ts++) {
    (function (wrap) {
      var btns = Array.prototype.slice.call(wrap.querySelectorAll("[data-table-view]"));
      btns.forEach(function (btn) {
        btn.addEventListener("click", function () {
          var view = btn.getAttribute("data-table-view") === "table" ? "table" : "cards";
          wrap.setAttribute("data-view", view);
          btns.forEach(function (b) {
            b.setAttribute("aria-pressed", b.getAttribute("data-table-view") === view ? "true" : "false");
          });
          announce("Switched mobile table view to " + view);
        });
      });
    })(tableSwitchers[ts]);
  }

  /* ========================================================================
     8. SAFE READ-ONLY ANTIGRAVITY PROMPT DEEP-LINK LAUNCHER (ZERO npx LINKS)
     ======================================================================== */
  var agyBtns = document.querySelectorAll(".agy-deeplink-btn[data-agy-prompt]");
  for (var dIdx = 0; dIdx < agyBtns.length; dIdx++) {
    agyBtns[dIdx].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var prompt = btn.getAttribute("data-agy-prompt") || "";
      var fbId = btn.getAttribute("data-fallback-id");
      var fbEl = fbId ? document.getElementById(fbId) : null;
      // Defense-in-depth: never emit npx execution deep links
      if (!prompt || /\bnpx\b/i.test(prompt)) return;

      var handled = false;
      function markHandled() {
        handled = true;
        window.removeEventListener("blur", markHandled);
        document.removeEventListener("visibilitychange", onVis);
      }
      function onVis() {
        if (document.hidden) markHandled();
      }
      window.addEventListener("blur", markHandled);
      document.addEventListener("visibilitychange", onVis);

      var deepUrl = "antigravity://open?prompt=" + encodeURIComponent(prompt);
      window.location.href = deepUrl;

      window.setTimeout(function () {
        window.removeEventListener("blur", markHandled);
        document.removeEventListener("visibilitychange", onVis);
        if (!handled && fbEl) {
          fbEl.hidden = false;
          announce("Antigravity desktop app did not respond; copy the prompt manually.");
        }
      }, 1500);
    });
  }

  /* ========================================================================
     9. INTERACTIVE POLICY LAB: EXACT src/hook-core.ts ENGINE (100% PARITY)
     ======================================================================== */
  var toolSelect = document.getElementById("sim-tool");
  var payloadInput = document.getElementById("sim-payload");
  var decisionBadge = document.getElementById("sim-decision-badge");
  var metaEl = document.getElementById("sim-meta");
  var reasonEl = document.getElementById("sim-reason");
  var stdinEl = document.getElementById("sim-stdin-json");
  var jsonEl = document.getElementById("sim-json");

  function hookGroupForTool(toolName) {
    if (toolName === "define_subagent") return "coldpin-delegation-guard";
    if (
      toolName === "write_to_file" ||
      toolName === "replace_file_content" ||
      toolName === "multi_replace_file_content" ||
      toolName === "write_file" ||
      toolName === "edit_file" ||
      toolName === "sed_file"
    ) {
      return "coldpin-config-guard";
    }
    if (toolName === "raw_json") return "fail-closed-parser";
    return "coldpin-npx-guard";
  }

  function buildHookPayloadObject(toolName, rawValue) {
    var val = String(rawValue || "").slice(0, MAX_INPUT_LEN);
    if (toolName === "raw_json") {
      var trimmed = val.trim();
      if (!trimmed) return { parseError: "Empty hook stdin payload; explicit human confirmation required.", rawText: "" };
      try {
        return { payload: JSON.parse(trimmed), rawText: trimmed };
      } catch (_) {
        return { parseError: "Malformed JSON on hook stdin; explicit human confirmation required.", rawText: trimmed };
      }
    }
    if (toolName === "run_command") {
      return { payload: { toolCall: { name: "run_command", args: { CommandLine: val } } } };
    }
    if (toolName === "manage_task") {
      return { payload: { toolCall: { name: "manage_task", args: { Action: "send_input", Input: val } } } };
    }
    if (toolName === "define_subagent") {
      var trimmedSub = val.trim();
      var argsObj = {};
      try {
        var parsed = JSON.parse(trimmedSub || "{}");
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) argsObj = parsed;
      } catch (_) {
        if (trimmedSub.charAt(0) === "{" || trimmedSub.charAt(0) === "[") {
          return { parseError: "Malformed JSON in define_subagent payload; explicit human confirmation required.", rawText: trimmedSub };
        }
        if (/\b(EnableWriteTools|enable_write_tools)\s*:\s*true\b/i.test(val)) {
          argsObj = { EnableWriteTools: true };
        } else {
          argsObj = { EnableWriteTools: false };
        }
      }
      return { payload: { toolCall: { name: "define_subagent", args: argsObj } } };
    }
    return { payload: { toolCall: { name: toolName, args: { TargetFile: val } } } };
  }

  function evaluateRealHook(toolName, rawValue) {
    var built = buildHookPayloadObject(toolName, rawValue);
    if (built.parseError) {
      return {
        hookGroup: hookGroupForTool(toolName),
        stdinDisplay: built.rawText || "(empty stdin)",
        result: { decision: "force_ask", reason: built.parseError }
      };
    }
    var core = window.ColdpinHookCore;
    var res = (core && typeof core.evaluatePreToolUsePayload === "function")
      ? core.evaluatePreToolUsePayload(built.payload)
      : { decision: "force_ask", reason: "Hook engine failed to load; failing closed." };
    return {
      hookGroup: hookGroupForTool(toolName),
      stdinDisplay: JSON.stringify(built.payload, null, 2),
      result: res
    };
  }

  function renderHookSimulation() {
    if (!toolSelect || !payloadInput || !decisionBadge || !metaEl || !reasonEl || !jsonEl) return;
    var out = evaluateRealHook(toolSelect.value, payloadInput.value);
    var dec = out.result.decision;
    decisionBadge.className = "decision-pill";
    if (dec === "allow") {
      decisionBadge.classList.add("decision-allow");
      decisionBadge.textContent = "ALLOW";
    } else if (dec === "force_ask") {
      decisionBadge.classList.add("decision-ask");
      decisionBadge.textContent = "FORCE_ASK";
    } else {
      decisionBadge.classList.add("decision-deny");
      decisionBadge.textContent = "DENY";
    }
    metaEl.textContent = out.hookGroup + " · real src/hook-core.ts engine · exit 0";
    reasonEl.textContent = out.result.reason || "Allowed cleanly under default Antigravity host policy (zero auto-approval).";
    if (stdinEl) stdinEl.textContent = out.stdinDisplay;
    jsonEl.textContent = JSON.stringify(out.result, null, 2);
  }

  if (toolSelect && payloadInput) {
    var simPresetBtns = Array.prototype.slice.call(document.querySelectorAll(".preset-btn[data-sim-tool]"));
    function syncSimPresetPressed() {
      simPresetBtns.forEach(function (b) {
        var match = b.getAttribute("data-sim-tool") === toolSelect.value && b.getAttribute("data-sim-payload") === payloadInput.value;
        b.setAttribute("aria-pressed", match ? "true" : "false");
      });
    }
    toolSelect.addEventListener("change", function () { syncSimPresetPressed(); renderHookSimulation(); });
    payloadInput.addEventListener("input", function () { syncSimPresetPressed(); renderHookSimulation(); });
    simPresetBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        toolSelect.value = btn.getAttribute("data-sim-tool") || "run_command";
        payloadInput.value = btn.getAttribute("data-sim-payload") || "";
        syncSimPresetPressed();
        renderHookSimulation();
        announce("Simulated " + btn.textContent);
      });
    });
    renderHookSimulation();
  }

  /* ========================================================================
     10. 4-STATE VERDICT EXPLORER + LIVE SEP-1865 MCP APP SANDBOX BRIDGE
     ======================================================================== */
  var VERDICTS = {
    clean: {
      title: "semver@7.7.1",
      badgeClass: "decision-allow",
      badgeText: "VERIFIED_CLEAN_WITHIN_SCOPE (exit 0)",
      sha512: "sha512-verified (in-memory stream, 14 files, 0 lifecycle hooks)",
      parity: "Tier 1 + Tier 2 verified (Git tag matches tarball files)",
      findings: "0 malicious indicators, 0 OSV/MAL-* advisories, 0 hidden Unicode or taint chains",
      unknowns: "Runtime behavior of floating transitive dependencies is outside static tarball scope.",
      command: "npx --yes --ignore-scripts --package=semver@7.7.1 -- semver --help",
      mcpPayload: {
        report_id: "rep_clean_semver771",
        package_name: "semver",
        version: "7.7.1",
        verdict: "VERIFIED_CLEAN_WITHIN_SCOPE",
        parity_tier: "TIER_1_AND_2_VERIFIED",
        provenance_status: "PROVENANCE_UNANCHORED_DSSE",
        integrity_sha512: "sha512-4L2fQ9a8V7rB9mN3pK1xZ0wT6yH2cD5eJ8uS1vA4bC7dE9fG==",
        pinned_execution: {
          command: "npx --yes --ignore-scripts --package=semver@7.7.1 -- semver --help",
          caveat: "Stock npx has no --integrity flag and resolves floating transitive ranges at runtime."
        },
        counts: { observations: 1, unknowns: 1, iocs: 0 },
        top_observations: [
          { code: "IN_MEMORY_QUARANTINE_OK", severity: "INFO", detail: "14 archive entries verified; 0 lifecycle hooks, 0 taint chains, 0 OSV advisories." }
        ],
        unknowns: [
          "Runtime behavior of floating transitive dependencies is outside static tarball scope."
        ],
        iocs: []
      }
    },
    suspicious: {
      title: "fast-json-helper@2.4.1",
      badgeClass: "decision-ask",
      badgeText: "QUARANTINE_SUSPICIOUS (exit 2)",
      sha512: "sha512-verified (42 files; postinstall script present)",
      parity: "Tarball drift detected: dist/loader.js absent from Git tag v2.4.1",
      findings: "High-entropy escape density (6.12 bits/char) and dynamic Function() invocation",
      unknowns: "Obfuscated bundle requires Tier-2 REA inspection before human decision.",
      command: "# Command suppressed. Run: coldpin resolve-anchor fast-json-helper --git-dir ./repo",
      mcpPayload: {
        report_id: "rep_susp_fastjson",
        package_name: "fast-json-helper",
        version: "2.4.1",
        verdict: "QUARANTINE_SUSPICIOUS",
        parity_tier: "TARBALL_SOURCE_DRIFT",
        provenance_status: "PROVENANCE_ABSENT",
        integrity_sha512: "sha512-9X7mP2kL4qR8vN1wC5tB6yF3hJ0dS8uA2cE4gK6mN9pQ1rT==",
        counts: { observations: 3, unknowns: 2, iocs: 0 },
        top_observations: [
          { code: "TARBALL_SOURCE_DRIFT", severity: "HIGH", path: "dist/loader.js", detail: "Compiled file absent from Git tag v2.4.1." },
          { code: "HIGH_ENTROPY_OBFUSCATION", severity: "MEDIUM", path: "dist/loader.js", line: 1, detail: "Dense hex/unicode escape obfuscation (6.12 bits/char)." }
        ],
        unknowns: [
          "Obfuscated dist/loader.js requires Tier-2 REA decompilation before approval."
        ],
        iocs: [],
        pagedMore: {
          observations: [
            { code: "LIFECYCLE_HOOK_PRESENT", severity: "MEDIUM", path: "package.json", detail: "postinstall script executes node dist/loader.js." }
          ],
          unknowns: [
            "No SLSA provenance attestation found on npm registry response."
          ]
        }
      }
    },
    malicious: {
      title: "react-cli-utils@1.9.4",
      badgeClass: "decision-deny",
      badgeText: "MALICIOUS_INDICATORS_FOUND (exit 3)",
      sha512: "sha512-verified (OSV advisory MAL-2026-00419 matched)",
      parity: "Tarball-only injection in preinstall.js; source repo HEAD uncompromised",
      findings: "TAINT_CRED_TO_NETWORK_OR_EXEC: process.env -> https.request(hxxps://collect[.]evil[.]example/ingest)",
      unknowns: "Check local package-lock.json and rotate exposed CI/developer tokens immediately.",
      command: "# Execution blocked. Run /coldpin-incident or coldpin resolve-anchor react-cli-utils",
      mcpPayload: {
        report_id: "rep_mal_reactcli",
        package_name: "react-cli-utils",
        version: "1.9.4",
        verdict: "MALICIOUS_INDICATORS_FOUND",
        parity_tier: "TARBALL_ONLY_INJECTION",
        provenance_status: "PROVENANCE_DIGEST_MISMATCH",
        local_workspace_compromised: true,
        integrity_sha512: "sha512-0A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zA4bC5dE==",
        counts: { observations: 2, unknowns: 1, iocs: 2 },
        top_observations: [
          { code: "TAINT_CRED_TO_NETWORK_OR_EXEC", severity: "CRITICAL", path: "scripts/preinstall.js", line: 14, detail: "process.env serialized into https.request body." },
          { code: "OSV_MALICIOUS_ADVISORY", severity: "CRITICAL", detail: "Matched OpenSSF MAL-2026-00419." }
        ],
        unknowns: [
          "Verify whether prior CI runs installed 1.9.4 and rotate npm/GitHub/cloud tokens."
        ],
        iocs: [
          { kind: "url", tlp: "TLP:CLEAR", value: "hxxps://collect[.]evil[.]example/ingest" }
        ],
        pagedMore: {
          iocs: [
            { kind: "domain", tlp: "TLP:CLEAR", value: "collect[.]evil[.]example" }
          ]
        }
      }
    },
    unknown: {
      title: "native-crypto-cli@0.8.0",
      badgeClass: "decision-ask",
      badgeText: "UNVERIFIABLE_UNKNOWN (exit 2)",
      sha512: "sha512-verified (offline mode or compiled native binary)",
      parity: "Contains prebuilt ELF/PE .node binary (bin/addon.node)",
      findings: "0 JS taint findings, but native binary payload is opaque to JS/TS static analysis",
      unknowns: "Fail-closed: escalate binary to pre-registered REA server before execution.",
      command: "# Command suppressed under fail-closed policy (uninspected native artifact)",
      mcpPayload: {
        report_id: "rep_unk_native",
        package_name: "native-crypto-cli",
        version: "0.8.0",
        verdict: "UNVERIFIABLE_UNKNOWN",
        parity_tier: "UNINSPECTED_BINARY_ARTIFACT",
        provenance_status: "PROVENANCE_ABSENT",
        counts: { observations: 1, unknowns: 1, iocs: 0 },
        top_observations: [
          { code: "UNINSPECTED_NATIVE_BINARY", severity: "HIGH", path: "bin/addon.node", detail: "Compiled ELF/PE native addon is opaque to JS/TS static taint analysis." }
        ],
        unknowns: [
          "Escalate bin/addon.node to pre-registered REA server (never bootstrap rea-agents via npx)."
        ],
        iocs: []
      }
    },
    batch: {
      title: "package.json (audit_manifest_batch)",
      badgeClass: "decision-deny",
      badgeText: "MALICIOUS_OR_BLOCKED (exit 3)",
      sha512: "50 / 50 direct dependencies screened locally ($0/mo)",
      parity: "Private @acme/* scopes isolated from public registry & OSV",
      findings: "1 MALICIOUS_OR_BLOCKED (es1int homoglyph), 1 FLAGGED_SUSPICIOUS, 48 CLEAN_SCREENED",
      unknowns: "Batch triage screens metadata, squats, policy & OSV; run inspect_package_artifact on flagged deps.",
      command: "# Run: coldpin inspect es1int@1.0.2 --offline",
      mcpPayload: {
        report_id: "rep_batch_demo",
        manifest_path: "./package.json",
        total_declared: 50,
        evaluated_count: 50,
        summary_counts: { clean_screened: 48, flagged_suspicious: 1, malicious_or_blocked: 1 },
        counts: { observations: 2, unknowns: 1, iocs: 0 },
        top_flagged: [
          { package_name: "es1int", status: "MALICIOUS_OR_BLOCKED", reason: "Homoglyph typosquat of popular package 'eslint'." },
          { package_name: "@acme-internal/ui", status: "FLAGGED_SUSPICIOUS", reason: "Private scope unconfigured in .npmrc (T1195.001 confusion risk)." }
        ],
        unknowns: [
          "Private-scope packages were withheld from public api.osv.dev per non-leakage policy."
        ],
        iocs: []
      }
    },
    anchor: {
      title: "@org/cli (resolve_safe_anchor)",
      badgeClass: "decision-allow",
      badgeText: "ROLLBACK_TO_SAFE_ANCHOR (exit 0)",
      sha512: "Patient-zero commit 8f4c12a9b0e1 isolated via --first-parent SQLite cache",
      parity: "Verified npm tarball @org/cli@2.3.0 matches pre-compromise commit 3b9e41d0f2a7",
      findings: "0 residual CVEs / 0 CISA KEV advisories on 2.3.0",
      unknowns: "Verify local lockfiles do not pin 2.3.1+ and rotate exposed tokens if compromised version ran.",
      command: "npx --yes --ignore-scripts --package=@org/cli@2.3.0 -- cli --version",
      mcpPayload: {
        report_id: "rep_anchor_orgcli",
        package_name: "@org/cli",
        recommended_action: "ROLLBACK_TO_SAFE_ANCHOR",
        patient_zero_commit: "8f4c12a9b0e14492d10a",
        safe_anchor_version: "2.3.0",
        commit_sha: "3b9e41d0f2a78813c90e",
        pinned_execution: {
          command: "npx --yes --ignore-scripts --package=@org/cli@2.3.0 -- cli --version",
          caveat: "Rollback target verified clean in static scope with 0 KEV/CVE advisories."
        },
        counts: { observations: 1, unknowns: 1, iocs: 0 },
        top_observations: [
          { code: "SAFE_ANCHOR_VERIFIED", severity: "INFO", detail: "Commit 3b9e41d0f2a7 precedes patient-zero 8f4c12a9b0e1 and matches published npm tarball 2.3.0." }
        ],
        unknowns: [
          "Confirm local package-lock.json and CI caches purge version 2.3.1."
        ],
        iocs: []
      }
    }
  };

  var activeVerdictKey = "clean";
  var mcpAppReady = false;
  var mcpAppFrame = document.getElementById("mcp-app-frame");
  var vTitle = document.getElementById("vc-title");
  var vBadge = document.getElementById("vc-badge");
  var vSha = document.getElementById("vc-sha");
  var vParity = document.getElementById("vc-parity");
  var vFindings = document.getElementById("vc-findings");
  var vUnknowns = document.getElementById("vc-unknowns");
  var vCmd = document.getElementById("vc-cmd");
  var verdictBtns = Array.prototype.slice.call(document.querySelectorAll(".preset-btn[data-verdict]"));

  function pushVerdictToMcpApp(key) {
    if (!mcpAppFrame || !mcpAppFrame.contentWindow) return;
    var entry = VERDICTS[key] || VERDICTS.clean;
    try {
      mcpAppFrame.contentWindow.postMessage({
        jsonrpc: "2.0",
        method: "ui/notifications/tool-result",
        params: { structuredContent: entry.mcpPayload }
      }, "*");
    } catch (_) {}
  }

  function renderVerdictCard(key) {
    activeVerdictKey = VERDICTS[key] ? key : "clean";
    var data = VERDICTS[activeVerdictKey];
    verdictBtns.forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-verdict") === activeVerdictKey ? "true" : "false");
    });
    if (vTitle) {
      vTitle.textContent = data.title;
      vBadge.className = "decision-pill " + data.badgeClass;
      vBadge.textContent = data.badgeText;
      vSha.textContent = data.sha512;
      vParity.textContent = data.parity;
      vFindings.textContent = data.findings;
      vUnknowns.textContent = data.unknowns;
      vCmd.textContent = data.command;
    }
    if (mcpAppReady) pushVerdictToMcpApp(activeVerdictKey);
  }

  if (verdictBtns.length > 0) {
    verdictBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var key = btn.getAttribute("data-verdict") || "clean";
        renderVerdictCard(key);
        announce("Loaded " + key + " evidence card sample");
      });
    });
    renderVerdictCard("clean");
  }

  if (mcpAppFrame) {
    window.addEventListener("message", function (ev) {
      if (ev.source !== mcpAppFrame.contentWindow) return;
      var msg = ev.data;
      if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") return;

      if (msg.method === "ui/initialize" && msg.id !== undefined) {
        mcpAppFrame.contentWindow.postMessage({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            protocolVersion: "2026-01-26",
            hostInfo: { name: "Coldpin Docs Policy Lab", version: DOC_VERSION },
            hostContext: { theme: resolveTheme() }
          }
        }, "*");
        return;
      }

      if (msg.method === "ui/notifications/initialized") {
        mcpAppReady = true;
        pushVerdictToMcpApp(activeVerdictKey);
        return;
      }

      if (msg.method === "ui/notifications/size-changed" && msg.params && typeof msg.params.height === "number") {
        var clamped = Math.max(260, Math.min(680, Math.ceil(msg.params.height) + 16));
        mcpAppFrame.style.height = String(clamped) + "px";
        return;
      }

      if (msg.method === "tools/call" && msg.id !== undefined && msg.params && msg.params.name === "get_artifact_report") {
        var callArgs = msg.params.arguments || {};
        var sec = callArgs.section || "observations";
        var cur = VERDICTS[activeVerdictKey] || VERDICTS.clean;
        var extra = (cur.mcpPayload.pagedMore && cur.mcpPayload.pagedMore[sec]) || [];
        var base = sec === "observations"
          ? (cur.mcpPayload.top_observations || cur.mcpPayload.top_flagged || [])
          : sec === "unknowns"
            ? (cur.mcpPayload.unknowns || [])
            : (cur.mcpPayload.iocs || []);
        mcpAppFrame.contentWindow.postMessage({
          jsonrpc: "2.0",
          id: msg.id,
          result: {
            structuredContent: {
              report_id: cur.mcpPayload.report_id,
              section: sec,
              items: base.concat(extra),
              next_offset: null
            }
          }
        }, "*");
      }
    });

    function isMcpAppDocumentLoaded() {
      try {
        var doc = mcpAppFrame.contentDocument;
        return Boolean(
          doc &&
          doc.readyState === "complete" &&
          doc.location &&
          doc.location.href &&
          doc.location.href !== "about:blank"
        );
      } catch (_) {
        return true;
      }
    }

    function ensureMcpAppBootstrapped() {
      if (!isMcpAppDocumentLoaded()) return;
      window.setTimeout(function () {
        if (!mcpAppReady && isMcpAppDocumentLoaded()) {
          mcpAppReady = true;
          notifyMcpAppTheme(resolveTheme());
          pushVerdictToMcpApp(activeVerdictKey);
        }
      }, 250);
    }
    mcpAppFrame.addEventListener("load", ensureMcpAppBootstrapped);
    if (isMcpAppDocumentLoaded()) {
      ensureMcpAppBootstrapped();
    }
  }

  /* ========================================================================
     11. WAI-ARIA COMMAND PALETTE SEARCH (Ctrl+K / '/', Zero-ReDoS RRF)
     ======================================================================== */
  var searchDialog = document.getElementById("search-dialog");
  var searchTrigger = document.getElementById("search-trigger");
  var searchInput = document.getElementById("search-input");
  var searchClose = document.getElementById("search-close");
  var searchList = document.getElementById("search-results");
  var searchStatus = document.getElementById("search-status");
  var searchChipBtns = Array.prototype.slice.call(document.querySelectorAll(".search-chip[data-search-pillar]"));

  var searchData = null;
  var searchLoadPromise = null;
  var activePillarFilter = "all";
  var activeResultIdx = -1;
  var currentRenderedItems = [];
  var lastTriggerFocus = null;

  function loadSearchIndex() {
    if (searchData) return Promise.resolve(searchData);
    if (searchLoadPromise) return searchLoadPromise;
    var url = docsRoot + "/search-index.json";
    searchLoadPromise = fetch(url, { credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (json) {
        searchData = json;
        return json;
      })
      .catch(function () {
        searchData = { version: DOC_VERSION, synonyms: {}, discovery: [], entries: [] };
        return searchData;
      });
    return searchLoadPromise;
  }

  function scoreRrfSearch(indexObj, rawQuery, pillarFilter) {
    var q = String(rawQuery || "").slice(0, 128).trim().toLowerCase();
    var entries = (indexObj && Array.isArray(indexObj.entries)) ? indexObj.entries : [];
    var synonyms = (indexObj && indexObj.synonyms) || {};

    var filtered = entries.filter(function (item) {
      return !pillarFilter || pillarFilter === "all" || item.pillar === pillarFilter;
    });
    if (!q) return [];

    var rawTokens = q.split(/\s+/).filter(Boolean).slice(0, 8);
    var expandedSet = {};
    rawTokens.forEach(function (tok) {
      if (Array.isArray(synonyms[tok])) {
        synonyms[tok].forEach(function (syn) { expandedSet[String(syn).toLowerCase()] = true; });
      }
    });
    var synTokens = Object.keys(expandedSet);

    var titleRanks = [];
    var bodyRanks = [];
    var synRanks = [];

    filtered.forEach(function (item) {
      var tLow = item.title.toLowerCase();
      var pLow = item.pageTitle.toLowerCase();
      var kLow = item.keywords;
      var sLow = item.snippet.toLowerCase();

      var titleScore = 0;
      if (tLow === q) titleScore += 100;
      else if (tLow.indexOf(q) === 0) titleScore += 65;
      else if (tLow.indexOf(q) !== -1) titleScore += 45;
      rawTokens.forEach(function (tok) {
        if (tLow.indexOf(tok) !== -1) titleScore += 18;
        if (pLow.indexOf(tok) !== -1) titleScore += 8;
      });
      if (titleScore > 0) titleRanks.push({ item: item, score: titleScore });

      var bodyScore = 0;
      rawTokens.forEach(function (tok) {
        if (kLow.indexOf(tok) !== -1) bodyScore += 14;
        if (sLow.indexOf(tok) !== -1) bodyScore += 10;
      });
      if (bodyScore > 0) bodyRanks.push({ item: item, score: bodyScore });

      if (synTokens.length > 0) {
        var synScore = 0;
        synTokens.forEach(function (syn) {
          if (tLow.indexOf(syn) !== -1) synScore += 10;
          if (kLow.indexOf(syn) !== -1 || sLow.indexOf(syn) !== -1) synScore += 6;
        });
        if (synScore > 0) synRanks.push({ item: item, score: synScore });
      }
    });

    function sortDesc(a, b) { return b.score - a.score; }
    titleRanks.sort(sortDesc);
    bodyRanks.sort(sortDesc);
    synRanks.sort(sortDesc);

    var rrfK = 30;
    var combined = {};
    var byId = {};

    function foldList(list, weight) {
      for (var i = 0; i < list.length; i++) {
        var id = list[i].item.id;
        byId[id] = list[i].item;
        combined[id] = (combined[id] || 0) + (weight / (rrfK + i + 1));
      }
    }
    foldList(titleRanks, 1.5);
    foldList(bodyRanks, 1.0);
    foldList(synRanks, 0.7);

    return Object.keys(combined)
      .map(function (id) { return { item: byId[id], rrf: combined[id] }; })
      .sort(function (a, b) { return b.rrf - a.rrf; })
      .slice(0, 14)
      .map(function (x) { return x.item; });
  }

  function clearChildren(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function setSelectedResult(idx) {
    if (!searchList || !searchInput) return;
    var opts = searchList.querySelectorAll('[role="option"]');
    if (opts.length === 0) {
      activeResultIdx = -1;
      searchInput.removeAttribute("aria-activedescendant");
      return;
    }
    var bounded = Math.max(0, Math.min(opts.length - 1, idx));
    activeResultIdx = bounded;
    for (var i = 0; i < opts.length; i++) {
      var sel = i === bounded;
      opts[i].setAttribute("aria-selected", sel ? "true" : "false");
      if (sel) {
        searchInput.setAttribute("aria-activedescendant", opts[i].id);
        if (typeof opts[i].scrollIntoView === "function") {
          opts[i].scrollIntoView({ block: "nearest" });
        }
      }
    }
  }

  function buildSearchHref(logicalHref, queryText) {
    var rel = resolveRelHref(logicalHref);
    var q = String(queryText || "").trim();
    if (!q) return rel;
    var parts = rel.split("#");
    var sep = parts[0].indexOf("?") >= 0 ? "&" : "?";
    return parts[0] + sep + "hl=" + encodeURIComponent(q.slice(0, 64)) + (parts[1] ? "#" + parts[1] : "");
  }

  function renderSearchPalette(query) {
    if (!searchList) return;
    clearChildren(searchList);
    currentRenderedItems = [];
    var q = String(query || "").slice(0, 128).trim();

    if (!q && searchData && Array.isArray(searchData.discovery)) {
      var disc = searchData.discovery.filter(function (d) {
        return activePillarFilter === "all" || d.pillarId === activePillarFilter;
      });
      var toShow = disc.length > 0 ? disc : searchData.discovery;
      toShow.forEach(function (card, idx) {
        var li = document.createElement("li");
        li.className = "search-result-option";
        li.id = "search-opt-" + String(idx);
        li.setAttribute("role", "option");
        li.setAttribute("aria-selected", idx === 0 ? "true" : "false");

        var a = document.createElement("a");
        a.className = "search-result-link";
        a.href = resolveRelHref(card.href);

        var top = document.createElement("span");
        top.className = "search-result-top";
        var tSpan = document.createElement("span");
        tSpan.className = "search-result-title";
        tSpan.textContent = card.title;
        var mSpan = document.createElement("span");
        mSpan.className = "search-result-meta";
        mSpan.textContent = card.pillar;
        top.appendChild(tSpan);
        top.appendChild(mSpan);

        var snip = document.createElement("span");
        snip.className = "search-result-snippet";
        snip.textContent = card.note;

        a.appendChild(top);
        a.appendChild(snip);
        a.addEventListener("click", function () {
          if (searchDialog && searchDialog.open) searchDialog.close();
        });
        li.appendChild(a);
        searchList.appendChild(li);
        currentRenderedItems.push(a);
      });
      if (searchStatus) searchStatus.textContent = "Showing " + String(currentRenderedItems.length) + " discovery guides.";
      setSelectedResult(0);
      return;
    }

    var matches = scoreRrfSearch(searchData, q, activePillarFilter);
    if (matches.length === 0) {
      var empty = document.createElement("li");
      empty.className = "search-empty";
      empty.textContent = "No Coldpin documentation matched '" + q + "'. Try 'hooks', 'oauth', 'sbom', 'offline', or 'sha256sums'.";
      searchList.appendChild(empty);
      if (searchStatus) searchStatus.textContent = "No documentation matched.";
      setSelectedResult(-1);
      return;
    }

    matches.forEach(function (item, idx) {
      var li = document.createElement("li");
      li.className = "search-result-option";
      li.id = "search-opt-" + String(idx);
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", idx === 0 ? "true" : "false");

      var a = document.createElement("a");
      a.className = "search-result-link";
      a.href = buildSearchHref(item.href, q);

      var top = document.createElement("span");
      top.className = "search-result-top";
      var tSpan = document.createElement("span");
      tSpan.className = "search-result-title";
      tSpan.textContent = item.title;
      var mSpan = document.createElement("span");
      mSpan.className = "search-result-meta";
      mSpan.textContent = item.pillarLabel + " · " + item.pageTitle;
      top.appendChild(tSpan);
      top.appendChild(mSpan);

      var snip = document.createElement("span");
      snip.className = "search-result-snippet";
      snip.textContent = item.snippet;

      a.appendChild(top);
      a.appendChild(snip);
      a.addEventListener("click", function () {
        if (searchDialog && searchDialog.open) searchDialog.close();
      });
      li.appendChild(a);
      searchList.appendChild(li);
      currentRenderedItems.push(a);
    });
    if (searchStatus) searchStatus.textContent = String(matches.length) + " results available.";
    setSelectedResult(0);
  }

  function openSearch() {
    if (!searchDialog || typeof searchDialog.showModal !== "function") return;
    if (searchDialog.open) {
      searchDialog.close();
      return;
    }
    lastTriggerFocus = document.activeElement;
    searchDialog.showModal();
    if (searchInput) {
      searchInput.focus();
      searchInput.select();
    }
    loadSearchIndex().then(function () {
      renderSearchPalette(searchInput ? searchInput.value : "");
    });
  }

  if (searchTrigger) searchTrigger.addEventListener("click", openSearch);
  if (searchClose && searchDialog) {
    searchClose.addEventListener("click", function () { searchDialog.close(); });
  }
  if (searchDialog) {
    searchDialog.addEventListener("click", function (ev) {
      if (ev.target === searchDialog) searchDialog.close();
    });
    searchDialog.addEventListener("close", function () {
      if (lastTriggerFocus && typeof lastTriggerFocus.focus === "function") {
        lastTriggerFocus.focus();
      }
      lastTriggerFocus = null;
    });
  }
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      renderSearchPalette(searchInput.value);
    });
    searchInput.addEventListener("keydown", function (ev) {
      if (ev.key === "ArrowDown") {
        ev.preventDefault();
        setSelectedResult(activeResultIdx + 1);
      } else if (ev.key === "ArrowUp") {
        ev.preventDefault();
        setSelectedResult(activeResultIdx - 1);
      } else if (ev.key === "Home") {
        ev.preventDefault();
        setSelectedResult(0);
      } else if (ev.key === "End") {
        ev.preventDefault();
        setSelectedResult(currentRenderedItems.length - 1);
      } else if (ev.key === "Enter" && activeResultIdx >= 0 && currentRenderedItems[activeResultIdx]) {
        ev.preventDefault();
        currentRenderedItems[activeResultIdx].click();
      }
    });
  }

  searchChipBtns.forEach(function (chip) {
    chip.addEventListener("click", function () {
      activePillarFilter = chip.getAttribute("data-search-pillar") || "all";
      searchChipBtns.forEach(function (b) {
        b.setAttribute("aria-pressed", b.getAttribute("data-search-pillar") === activePillarFilter ? "true" : "false");
      });
      renderSearchPalette(searchInput ? searchInput.value : "");
    });
  });

  document.addEventListener("keydown", function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault();
      openSearch();
    } else if (ev.key === "/" && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      var tag = document.activeElement ? document.activeElement.tagName : "";
      if (tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") {
        ev.preventDefault();
        openSearch();
      }
    }
  });

  /* ========================================================================
     12. ZERO-XSS CSS.highlights IN-PAGE MATCH HIGHLIGHTING (?hl=...)
     ======================================================================== */
  (function applySearchHighlight() {
    if (typeof CSS === "undefined" || !CSS.highlights || typeof window.Highlight !== "function") return;
    var rawTerm = "";
    try {
      rawTerm = (new URLSearchParams(window.location.search).get("hl") || "").slice(0, 64).trim().toLowerCase();
    } catch (_) { return; }
    if (rawTerm.length < 2) return;
    var article = document.querySelector(".docs-article");
    if (!article) return;

    var seenTok = {};
    var terms = [];
    rawTerm.split(/\s+/).forEach(function (tok) {
      if (tok.length >= 2 && !seenTok[tok] && terms.length < 6) {
        seenTok[tok] = true;
        terms.push(tok);
      }
    });
    if (terms.length === 0) return;

    var ranges = [];
    var walker = document.createTreeWalker(article, NodeFilter.SHOW_TEXT);
    var node;
    while ((node = walker.nextNode()) && ranges.length < 40) {
      var parentEl = node.parentElement;
      if (parentEl && typeof parentEl.closest === "function" && parentEl.closest("[hidden]")) continue;
      var text = node.nodeValue || "";
      var lower = text.toLowerCase();
      for (var tIdx = 0; tIdx < terms.length && ranges.length < 40; tIdx++) {
        var term = terms[tIdx];
        var pos = 0;
        while (pos < lower.length && ranges.length < 40) {
          var idx = lower.indexOf(term, pos);
          if (idx === -1) break;
          var r = document.createRange();
          r.setStart(node, idx);
          r.setEnd(node, idx + term.length);
          ranges.push(r);
          pos = idx + term.length;
        }
      }
    }
    if (ranges.length > 0) {
      var hl = new window.Highlight();
      for (var i = 0; i < ranges.length; i++) hl.add(ranges[i]);
      CSS.highlights.set("coldpin-search-match", hl);
    }
  })();

  /* ========================================================================
     13. DESKTOP + MOBILE TOC SCROLL-SPY & TARGETED <details> AUTO-OPEN
     ======================================================================== */
  function openTargetDetails(hashStr) {
    if (!hashStr || hashStr.length < 2) return;
    var targetId = hashStr.charAt(0) === "#" ? hashStr.slice(1) : hashStr;
    var targetEl = document.getElementById(targetId);
    if (!targetEl) return;
    if (targetEl.tagName === "DETAILS") {
      targetEl.open = true;
    } else if (typeof targetEl.closest === "function") {
      var parentDet = targetEl.closest("details");
      if (parentDet) parentDet.open = true;
    }
  }
  if (window.location && window.location.hash) {
    openTargetDetails(window.location.hash);
  }
  window.addEventListener("hashchange", function () {
    if (window.location && window.location.hash) openTargetDetails(window.location.hash);
  });

  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc-link[href^='#']"));
  var observedTargets = [];
  tocLinks.forEach(function (link) {
    var href = link.getAttribute("href");
    var el = href ? document.getElementById(href.slice(1)) : null;
    if (el && observedTargets.indexOf(el) === -1) observedTargets.push(el);
    link.addEventListener("click", function () {
      if (href) openTargetDetails(href);
    });
  });

  function setActiveToc(id) {
    tocLinks.forEach(function (link) {
      link.classList.toggle("is-active", link.getAttribute("href") === "#" + id);
    });
  }

  if ("IntersectionObserver" in window && observedTargets.length > 0) {
    var spy = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting && !entries[i].target.hidden) {
          setActiveToc(entries[i].target.id);
          break;
        }
      }
    }, { rootMargin: "-15% 0px -70% 0px", threshold: 0 });
    for (var s = 0; s < observedTargets.length; s++) spy.observe(observedTargets[s]);
  }

  /* ========================================================================
     14. READ-ONLY WEBMCP (document.modelContext, <= 1,500-CHAR VALID JSON)
     ======================================================================== */
  function capWebMcpText(obj) {
    var text = typeof obj === "string" ? obj : JSON.stringify(obj);
    if (text.length <= WEBMCP_MAX_CHARS) return text;
    return JSON.stringify({ truncated: true, max_chars: WEBMCP_MAX_CHARS, preview: text.slice(0, WEBMCP_MAX_CHARS - 96) });
  }

  function packSearchResultsJson(queryText, rawMatches) {
    var snippetCaps = [100, 64, 0];
    for (var sc = 0; sc < snippetCaps.length; sc++) {
      var cap = snippetCaps[sc];
      for (var take = Math.min(6, rawMatches.length); take >= 0; take--) {
        var list = rawMatches.slice(0, take).map(function (r) {
          var rec = { title: r.title, pillar: r.pillarLabel, href: r.href, md: "/docs/" + r.slug + ".md" };
          if (cap > 0) rec.snippet = r.snippet.slice(0, cap);
          return rec;
        });
        var payload = {
          version: DOC_VERSION,
          query: queryText,
          count: list.length,
          truncated: take < rawMatches.length,
          results: list
        };
        var encoded = JSON.stringify(payload);
        if (encoded.length <= WEBMCP_MAX_CHARS) return encoded;
      }
    }
    return JSON.stringify({ version: DOC_VERSION, query: queryText.slice(0, 40), count: 0, truncated: true, results: [] });
  }

  function packMarkdownSliceJson(slug, md, offset) {
    var remaining = md.length - offset;
    if (remaining <= 0) {
      return JSON.stringify({ slug: slug, offset: offset, total_chars: md.length, next_offset: null, markdown: "" });
    }
    var low = 0;
    var high = Math.min(remaining, WEBMCP_MAX_CHARS);
    var best = "";
    while (low <= high) {
      var mid = Math.floor((low + high) / 2);
      var chunk = md.slice(offset, offset + mid);
      var nextOff = offset + chunk.length < md.length ? offset + chunk.length : null;
      var encoded = JSON.stringify({ slug: slug, offset: offset, total_chars: md.length, next_offset: nextOff, markdown: chunk });
      if (encoded.length <= WEBMCP_MAX_CHARS) {
        best = encoded;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return best || JSON.stringify({ slug: slug, offset: offset, total_chars: md.length, next_offset: null, markdown: "" });
  }

  var simulateHookTool = {
    name: "simulate_coldpin_hook",
    description: "Read-only PreToolUse hook simulation using Coldpin's exact ES2020 src/hook-core.ts evaluator (zero execution, <=1500 chars).",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    inputSchema: {
      type: "object",
      required: ["tool_name", "payload"],
      properties: {
        tool_name: { type: "string", enum: ["run_command", "write_to_file", "replace_file_content", "edit_file", "define_subagent", "manage_task"] },
        payload: { type: "string", maxLength: 1024 }
      }
    },
    execute: function (args) {
      var toolName = String((args && args.tool_name) || "run_command");
      var payload = String((args && args.payload) || "").slice(0, 1024);
      var res = evaluateRealHook(toolName, payload);
      return Promise.resolve({
        content: [{ type: "text", text: capWebMcpText({ tool_name: toolName, hook_group: res.hookGroup, exit_code: 0, output: res.result }) }]
      });
    }
  };

  var webMcpTools = [
    {
      name: "search_coldpin_docs",
      description: "Read-only search across Coldpin v" + DOC_VERSION + " documentation pages and sections (synonym-aware RRF, <=1500 chars).",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        type: "object",
        required: ["query"],
        properties: {
          query: { type: "string", maxLength: 128 },
          pillar: { type: "string", enum: ["all", "get-started", "plugin-guardrails", "mcp-cli", "enterprise-security", "verification-releases"] }
        }
      },
      execute: function (args) {
        var q = String((args && args.query) || "").slice(0, 128);
        var p = String((args && args.pillar) || "all");
        return loadSearchIndex().then(function (idx) {
          var matches = scoreRrfSearch(idx, q, p);
          return { content: [{ type: "text", text: packSearchResultsJson(q, matches) }] };
        });
      }
    },
    {
      name: "get_coldpin_doc_markdown",
      description: "Fetch a read-only raw Markdown slice (<=1500 chars) for an allowlisted Coldpin documentation slug.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        type: "object",
        required: ["slug"],
        properties: {
          slug: { type: "string", enum: VALID_SLUGS },
          offset: { type: "integer", minimum: 0, default: 0 }
        }
      },
      execute: function (args) {
        var slug = String((args && args.slug) || "").trim().toLowerCase();
        if (VALID_SLUGS.indexOf(slug) === -1) {
          return Promise.resolve({ content: [{ type: "text", text: capWebMcpText({ error: "invalid_slug", allowed: VALID_SLUGS }) }] });
        }
        var offset = Math.max(0, Number((args && args.offset) || 0) || 0);
        return fetch(docsRoot + "/docs/" + slug + ".md", { credentials: "same-origin" })
          .then(function (r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.text();
          })
          .then(function (md) {
            return {
              content: [{ type: "text", text: packMarkdownSliceJson(slug, md, offset) }]
            };
          });
      }
    },
    {
      name: "get_coldpin_release_checksums",
      description: "Return verified Coldpin v" + DOC_VERSION + " SHA256SUMS.txt digests and SLSA provenance links (read-only, <=1500 chars).",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: { type: "object", properties: {} },
      execute: function () {
        return Promise.resolve({
          content: [{ type: "text", text: capWebMcpText({ version: DOC_VERSION, release_url: RELEASE_URL, sha256sums: RELEASE_CHECKSUMS }) }]
        });
      }
    }
  ];

  if (window.ColdpinHookCore && typeof window.ColdpinHookCore.evaluatePreToolUsePayload === "function") {
    webMcpTools.push(simulateHookTool);
  }

  window.ColdpinWebMcpTools = Object.freeze(webMcpTools);

  function registerOnContext(ctx) {
    if (!ctx || typeof ctx.registerTool !== "function") return;
    webMcpTools.forEach(function (tool) {
      try { ctx.registerTool(tool); } catch (_) {}
    });
  }
  try {
    if (document.modelContext) registerOnContext(document.modelContext);
    else if (typeof navigator !== "undefined" && navigator.modelContext) registerOnContext(navigator.modelContext);
  } catch (_) {}
})();
