/* Coldpin Docs Anti-FOUC 3-Way Theme Bootstrap & Legacy #hash Redirect Shim
 * Blocking external script under strict zero-'unsafe-inline' CSP.
 */
(function () {
  "use strict";
  var root = document.documentElement;
  var mode = "auto";
  try {
    var saved = window.localStorage.getItem("coldpin-docs-theme-mode");
    if (saved === "auto" || saved === "light" || saved === "dark") {
      mode = saved;
    } else {
      var legacy = window.localStorage.getItem("coldpin-docs-theme");
      if (legacy === "light" || legacy === "dark") mode = legacy;
    }
    if (window.localStorage.getItem("coldpin-docs-announce-v1.6.0") === "dismissed") {
      root.setAttribute("data-announce-dismissed", "true");
    }
  } catch (_) {}

  var prefersDark = false;
  try {
    prefersDark = Boolean(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  } catch (_) {}
  var resolved = mode === "auto" ? (prefersDark ? "dark" : "light") : mode;
  root.setAttribute("data-theme-mode", mode);
  root.setAttribute("data-theme", resolved);

  if (root.getAttribute("data-page-slug") === "overview" && window.location && window.location.hash) {
    var h = window.location.hash.toLowerCase();
    var map = {
      "#quickstart": "./docs/quickstart/",
      "#simulator": "./docs/policy-lab/",
      "#policy-lab": "./docs/policy-lab/",
      "#antigravity-plugin": "./docs/antigravity-plugin/",
      "#agents-and-hooks": "./docs/agents-and-rules/",
      "#hooks": "./docs/hooks/",
      "#slash-commands": "./docs/slash-commands/",
      "#mcp-and-cli": "./docs/mcp-tools/",
      "#cli": "./docs/cli-reference/",
      "#enterprise-http": "./docs/enterprise-http/",
      "#harnesses": "./docs/harnesses/",
      "#configuration": "./docs/configuration/",
      "#privacy": "./docs/privacy/",
      "#security": "./docs/security/",
      "#verification": "./docs/verification/",
      "#changelog": "./docs/changelog/",
      "#faq": "./docs/faq/"
    };
    if (Object.prototype.hasOwnProperty.call(map, h)) {
      window.location.replace(map[h]);
    }
  }
})();
