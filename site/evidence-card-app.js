/* Extracted verbatim from src/mcp/evidence-card-app.ts */
(function () {
  "use strict";
  const PROTOCOL_VERSION = "2026-01-26";
  let nextRpcId = 1;
  const pendingRpc = new Map();
  let currentReportId = null;
  let activeTab = "observations";
  let currentData = null;
  let extraItems = { observations: [], unknowns: [], iocs: [], commits: [] };
  let pagingOffsets = { observations: 0, unknowns: 0, iocs: 0, commits: 0 };

  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v !== undefined && v !== null) node.setAttribute(k, String(v));
      }
    }
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function sendPostMessage(payload) {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage(payload, "*");
    }
  }

  function rpcRequest(method, params) {
    const id = nextRpcId++;
    return new Promise((resolve, reject) => {
      pendingRpc.set(id, { resolve, reject });
      sendPostMessage({ jsonrpc: "2.0", id, method, params: params || {} });
      setTimeout(() => {
        if (pendingRpc.has(id)) {
          pendingRpc.delete(id);
          reject(new Error("RPC timeout: " + method));
        }
      }, 15000);
    });
  }

  function rpcNotify(method, params) {
    sendPostMessage({ jsonrpc: "2.0", method, params: params || {} });
  }

  function reportSize() {
    const h = Math.max(150, Math.min(800, Math.ceil(document.documentElement.scrollHeight)));
    rpcNotify("ui/notifications/size-changed", { height: h });
  }

  function applyHostContext(ctx) {
    if (!ctx || typeof ctx !== "object") return;
    if (ctx.theme === "dark" || ctx.theme === "light") {
      document.documentElement.setAttribute("data-theme", ctx.theme);
    }
    const vars = ctx.styles && ctx.styles.variables;
    if (vars && typeof vars === "object") {
      for (const [k, v] of Object.entries(vars)) {
        if (typeof k === "string" && k.startsWith("--") && typeof v === "string") {
          document.documentElement.style.setProperty(k, v);
        }
      }
    }
  }

  function badgeClassFor(verdict) {
    const v = String(verdict || "").toUpperCase();
    if (v === "VERIFIED_CLEAN_WITHIN_SCOPE" || v === "PASS" || v === "CLEAN") return "badge b-ok";
    if (v.includes("MALICIOUS") || v.includes("BLOCK") || v.includes("RISK")) return "badge b-bad";
    if (v.includes("SUSPICIOUS") || v.includes("QUARANTINE") || v.includes("UNKNOWN") || v.includes("UNVERIFIABLE")) return "badge b-warn";
    return "badge b-info";
  }

  function addKv(grid, label, value) {
    if (value === undefined || value === null || value === "") return;
    const box = el("div", { class: "kv" });
    box.appendChild(el("div", { class: "kv-k" }, label));
    box.appendChild(el("div", { class: "kv-v" }, String(value)));
    grid.appendChild(box);
  }

  function renderListItems(container, list, kind) {
    if (!list || list.length === 0) {
      container.appendChild(el("div", { class: "empty" }, "None recorded in this section."));
      return;
    }
    for (const entry of list) {
      const card = el("div", { class: "item" });
      if (typeof entry === "string") {
        card.appendChild(el("div", null, entry));
      } else if (entry && typeof entry === "object") {
        const head = el("div", { class: "item-head" });
        const leftLabel = entry.code || entry.package_name || entry.issue || entry.kind || entry.sha || kind;
        const rightLabel = entry.severity || entry.status || entry.tlp || entry.location || "";
        head.appendChild(el("strong", null, String(leftLabel)));
        if (rightLabel) head.appendChild(el("span", { class: badgeClassFor(rightLabel) }, String(rightLabel)));
        card.appendChild(head);
        const detail = entry.detail || entry.value || entry.reason || entry.message || entry.remediation || JSON.stringify(entry);
        card.appendChild(el("div", null, String(detail)));
        if (entry.path) {
          const locText = entry.line !== undefined ? String(entry.path) + ":" + String(entry.line) : String(entry.path);
          card.appendChild(el("div", { class: "sub" }, "Location: " + locText));
        } else if (entry.location && entry.location !== rightLabel) {
          card.appendChild(el("div", { class: "sub" }, "Location: " + String(entry.location)));
        }
        if (entry.remediation && entry.remediation !== detail) {
          card.appendChild(el("div", { class: "sub" }, "Remediation: " + String(entry.remediation)));
        }
      }
      container.appendChild(card);
    }
  }

  async function loadMore(section) {
    if (!currentReportId) return;
    const btn = document.getElementById("load-more-btn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Loading...";
    }
    try {
      const offset = pagingOffsets[section] || 0;
      const res = await rpcRequest("tools/call", {
        name: "get_artifact_report",
        arguments: { report_id: currentReportId, section, offset, limit: 20 }
      });
      const sc = res && res.structuredContent;
      if (sc && Array.isArray(sc.items)) {
        extraItems[section] = (extraItems[section] || []).concat(sc.items);
        pagingOffsets[section] = sc.next_offset === null ? -1 : sc.next_offset;
      }
      renderCard(currentData);
    } catch (_err) {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Retry Load More";
      }
    }
  }

  function renderCard(data) {
    currentData = data;
    const titleEl = document.getElementById("title");
    const subEl = document.getElementById("subtitle");
    const verdictEl = document.getElementById("verdict");
    const bodyEl = document.getElementById("body");
    const rightEl = document.getElementById("meta-right");
    clearNode(bodyEl);

    if (!data || typeof data !== "object") {
      titleEl.textContent = "Coldpin Evidence Card";
      subEl.textContent = "No structured payload returned.";
      verdictEl.className = "badge b-warn";
      verdictEl.textContent = "NO_DATA";
      reportSize();
      return;
    }

    currentReportId = typeof data.report_id === "string" ? data.report_id : null;
    const basePkg = data.package || data.package_name || data.manifest_path || "Coldpin Audit";
    const pkgTitle = data.version && data.package_name && !String(basePkg).includes("@" + data.version)
      ? String(data.package_name) + "@" + String(data.version)
      : String(basePkg);
    const verdict = data.verdict
      || (data.passed === true ? "PASS" : data.passed === false ? "CONFUSION_RISK_FOUND" : null)
      || data.recommended_action
      || (data.summary_counts && data.summary_counts.malicious_or_blocked > 0 ? "MALICIOUS_OR_BLOCKED" : data.summary_counts && data.summary_counts.flagged_suspicious > 0 ? "FLAGGED_SUSPICIOUS" : data.summary_counts ? "VERIFIED_CLEAN_WITHIN_SCOPE" : "INSPECTED");

    titleEl.textContent = pkgTitle;
    const commitSha = data.commit_sha || (data.safe_anchor && data.safe_anchor.commit_sha) || null;
    subEl.textContent = [
      data.report_id ? "report_id=" + data.report_id : null,
      data.recommended_action ? "action=" + data.recommended_action : null,
      commitSha ? "commit=" + String(commitSha).slice(0, 12) : null
    ].filter(Boolean).join(" · ") || "Deterministic static verdict";
    verdictEl.className = badgeClassFor(verdict);
    verdictEl.textContent = String(verdict);
    rightEl.textContent = data.report_id ? "Session LRU: " + data.report_id : "Read-only view";

    const grid = el("div", { class: "grid" });
    addKv(grid, "Parity Tier", data.parity_tier);
    addKv(grid, "npm Provenance", data.provenance_status);
    const sha512 = data.integrity_sha512 || (data.pinned_execution && data.pinned_execution.tarball_sha512);
    addKv(grid, "SHA-512", sha512 ? String(sha512).slice(0, 28) + "..." : undefined);
    const pZero = data.patient_zero_commit || (data.compromised_latest && data.compromised_latest.patient_zero_sha);
    addKv(grid, "Patient-Zero Commit", pZero ? String(pZero).slice(0, 12) : undefined);
    const safeAnchorVer = data.safe_anchor_version || (data.safe_anchor && data.safe_anchor.version);
    addKv(grid, "Safe Anchor", safeAnchorVer);
    if (data.summary_counts) {
      addKv(grid, "Declared / Screened", String(data.total_declared || 0) + " / " + String(data.evaluated_count || 0));
      addKv(grid, "Clean / Flagged / Blocked", [data.summary_counts.clean_screened || 0, data.summary_counts.flagged_suspicious || 0, data.summary_counts.malicious_or_blocked || 0].join(" / "));
    }
    if (data.local_workspace_compromised) {
      addKv(grid, "Workspace Exposure", "LOCKFILE COMPROMISE DETECTED");
    }
    if (grid.childNodes.length > 0) bodyEl.appendChild(grid);

    const pinnedCmd = (data.pinned_execution && data.pinned_execution.command)
      || (data.safe_anchor && data.safe_anchor.pinned_command)
      || null;
    const pinnedCaveat = (data.pinned_execution && data.pinned_execution.caveat) || null;
    if (pinnedCmd) {
      const cmdBox = el("div", { class: "cmd-box" });
      const top = el("div", { class: "cmd-top" });
      top.appendChild(el("strong", null, "Pinned Execution Command (Copy-Only · Human Gate)"));
      const copyBtn = el("button", { type: "button", class: "btn" }, "Copy Command");
      copyBtn.addEventListener("click", () => {
        const txt = String(pinnedCmd);
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(txt).then(() => {
            copyBtn.textContent = "Copied";
            setTimeout(() => { copyBtn.textContent = "Copy Command"; }, 1800);
          }).catch(() => { copyBtn.textContent = "Copy failed"; });
        }
      });
      top.appendChild(copyBtn);
      cmdBox.appendChild(top);
      cmdBox.appendChild(el("code", { class: "cmd-code" }, String(pinnedCmd)));
      if (pinnedCaveat) {
        cmdBox.appendChild(el("p", { class: "caveat" }, String(pinnedCaveat)));
      }
      bodyEl.appendChild(cmdBox);
    }

    const baseObs = Array.isArray(data.top_observations) ? data.top_observations
      : Array.isArray(data.top_flagged) ? data.top_flagged
      : Array.isArray(data.findings) ? data.findings
      : Array.isArray(data.observations) ? data.observations : [];
    const baseUnk = Array.isArray(data.unknowns) ? data.unknowns : [];
    const baseIocs = Array.isArray(data.iocs) ? data.iocs : [];

    const tabs = el("div", { class: "tabs", role: "tablist" });
    const tabDefs = [
      { id: "observations", label: "Findings (" + ((data.counts && data.counts.observations) || baseObs.length) + ")" },
      { id: "unknowns", label: "Unknowns (" + ((data.counts && data.counts.unknowns) || baseUnk.length) + ")" },
      { id: "iocs", label: "Defanged IOCs (" + ((data.counts && data.counts.iocs) || baseIocs.length) + ")" }
    ];
    for (const td of tabDefs) {
      const t = el("button", { type: "button", class: "tab", role: "tab", "aria-selected": String(activeTab === td.id) }, td.label);
      t.addEventListener("click", () => { activeTab = td.id; renderCard(currentData); });
      tabs.appendChild(t);
    }
    bodyEl.appendChild(tabs);

    const listWrap = el("div", { class: "list", role: "tabpanel" });
    const items = activeTab === "observations"
      ? (extraItems.observations.length > 0 ? extraItems.observations : baseObs)
      : activeTab === "unknowns"
        ? (extraItems.unknowns.length > 0 ? extraItems.unknowns : baseUnk)
        : (extraItems.iocs.length > 0 ? extraItems.iocs : baseIocs);
    renderListItems(listWrap, items, activeTab);
    bodyEl.appendChild(listWrap);

    const totalForTab = data.counts && typeof data.counts[activeTab] === "number" ? data.counts[activeTab] : items.length;
    if (currentReportId && pagingOffsets[activeTab] !== -1 && (items.length < totalForTab || (activeTab === "iocs" && totalForTab > 0 && items.length === 0))) {
      const moreBtn = el("button", { type: "button", id: "load-more-btn", class: "btn" }, "Load More via get_artifact_report");
      moreBtn.addEventListener("click", () => { void loadMore(activeTab); });
      bodyEl.appendChild(moreBtn);
    }

    reportSize();
  }

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") return;

    if (msg.id !== undefined && pendingRpc.has(msg.id)) {
      const h = pendingRpc.get(msg.id);
      pendingRpc.delete(msg.id);
      if (msg.error) h.reject(new Error(msg.error.message || "RPC error"));
      else h.resolve(msg.result);
      return;
    }

    if (msg.method === "ping" && msg.id !== undefined) {
      sendPostMessage({ jsonrpc: "2.0", id: msg.id, result: {} });
      return;
    }

    if (msg.method === "ui/notifications/host-context-changed") {
      applyHostContext(msg.params);
      return;
    }

    if (msg.method === "ui/notifications/tool-input") {
      const args = (msg.params && msg.params.arguments) || {};
      const target = args.package_spec || args.tarball_path || args.manifest_path || args.package_name || "target";
      document.getElementById("title").textContent = String(target);
      document.getElementById("subtitle").textContent = "Inspecting cold in memory...";
      const v = document.getElementById("verdict");
      v.className = "badge b-info";
      v.textContent = "INSPECTING";
      reportSize();
      return;
    }

    if (msg.method === "ui/notifications/tool-cancelled") {
      const v = document.getElementById("verdict");
      v.className = "badge b-warn";
      v.textContent = "CANCELLED";
      document.getElementById("subtitle").textContent = "Inspection cancelled by host.";
      reportSize();
      return;
    }

    if (msg.method === "ui/notifications/tool-result") {
      extraItems = { observations: [], unknowns: [], iocs: [], commits: [] };
      pagingOffsets = { observations: 0, unknowns: 0, iocs: 0, commits: 0 };
      activeTab = "observations";
      const res = msg.params || {};
      if (res.structuredContent && typeof res.structuredContent === "object") {
        renderCard(res.structuredContent);
      } else if (Array.isArray(res.content) && res.content[0] && typeof res.content[0].text === "string") {
        try {
          renderCard(JSON.parse(res.content[0].text));
        } catch (_e) {
          renderCard({ package: "Coldpin Result", verdict: res.isError ? "OPERATIONAL_ERROR" : "INFO", unknowns: [res.content[0].text] });
        }
      }
    }
  });

  if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => reportSize()).observe(document.body);
  }

  rpcRequest("ui/initialize", {
    protocolVersion: PROTOCOL_VERSION,
    appInfo: { name: "Coldpin Evidence Card", version: "1.6.1" },
    appCapabilities: {}
  }).then((initRes) => {
    if (initRes && initRes.hostContext) applyHostContext(initRes.hostContext);
    rpcNotify("ui/notifications/initialized", {});
    reportSize();
  }).catch(() => {
    reportSize();
  });
})();
