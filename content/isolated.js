// NULL200OK_fetch_DomXss — ISOLATED world bridge + overlay
(() => {
  "use strict";
  const BRIDGE = "__NULL200OK_BRIDGE__";
  const OVERLAY_ID = "n2ok-overlay";
  const FINDINGS = [];
  const SEEN_IDS = new Set();
  let env = { trustedTypesEnforced: null, cspStrict: null };

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data[BRIDGE] !== true) return;
    const msg = event.data;
    delete msg[BRIDGE];
    chrome.runtime
      .sendMessage(msg)
      .then((res) => {
        if (res?.finding && !SEEN_IDS.has(res.finding.id)) {
          SEEN_IDS.add(res.finding.id);
          FINDINGS.push(res.finding);
          renderOverlay();
        }
      })
      .catch(() => {});
  });

  function runStaticAnalysis() {
    (async () => {
      try {
        const acornUrl = chrome.runtime.getURL("vendor/acorn.js");
        const acorn = await import(acornUrl);
        const fg = await import(chrome.runtime.getURL("lib/flow-graph.js"));
        const out = [];
        for (const s of document.querySelectorAll("script:not([src])")) {
          const code = s.textContent || "";
          if (code.length < 50 || code.length > 300_000) continue;
          let ast;
          try {
            ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script" });
          } catch {
            continue;
          }
          const cfg = fg.buildCFG(ast);
          const pdg = fg.buildPDG(ast, cfg);
          const flows = fg.findFlows(ast, cfg, pdg);
          for (const f of flows) {
            out.push({
              id: crypto.randomUUID(),
              severity: "medium",
              sink: { type: `static:${f.sink}`, element: null, selector: null },
              sources: [{ type: `static:${f.source}`, value: "", confidence: "ast" }],
              evidence: code.slice(f.start, f.end).slice(0, 300),
              timestamp: new Date().toISOString(),
              env: { ...env },
              extra: { static: true },
            });
          }
        }
        if (out.length) {
          chrome.runtime.sendMessage({ type: "STATIC_ANALYSIS_RESULT", findings: out });
        }
      } catch {}
    })();
  }

  function ensureOverlay() {
    let panel = document.getElementById(OVERLAY_ID);
    if (panel) return panel;
    panel = document.createElement("div");
    panel.id = OVERLAY_ID;
    panel.setAttribute(
      "style",
      "all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;width:380px;max-height:65vh;background:#0d1117;color:#c9d1d9;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;border:1px solid #30363d;border-radius:10px;box-shadow:0 10px 40px rgba(0,0,0,.6);overflow:hidden;display:flex;flex-direction:column;"
    );
    const head = document.createElement("div");
    head.setAttribute(
      "style",
      "padding:8px 12px;background:#161b22;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #30363d;font-family:system-ui,sans-serif;font-weight:600;cursor:move;"
    );
    const title = document.createElement("span");
    title.textContent = "NULL200OK · DomXss";
    title.setAttribute("style", "color:#58a6ff;");
    const close = document.createElement("button");
    close.textContent = "×";
    close.setAttribute(
      "style",
      "background:none;border:none;color:#c9d1d9;font-size:18px;cursor:pointer;"
    );
    close.addEventListener("click", () => (panel.style.display = "none"));
    head.append(title, close);
    const body = document.createElement("div");
    body.id = "n2ok-body";
    body.setAttribute("style", "overflow:auto;padding:8px;flex:1;");
    panel.append(head, body);
    draggable(panel, head);
    document.documentElement.appendChild(panel);
    return panel;
  }

  function draggable(panel, handle) {
    let sx, sy, ox, oy, on = false;
    handle.addEventListener("mousedown", (e) => {
      on = true;
      sx = e.clientX;
      sy = e.clientY;
      const r = panel.getBoundingClientRect();
      ox = r.left;
      oy = r.top;
      e.preventDefault();
    });
    window.addEventListener("mousemove", (e) => {
      if (!on) return;
      panel.style.left = ox + e.clientX - sx + "px";
      panel.style.top = oy + e.clientY - sy + "px";
      panel.style.right = "auto";
    });
    window.addEventListener("mouseup", () => (on = false));
  }

  function renderOverlay() {
    const panel = ensureOverlay();
    const body = panel.querySelector("#n2ok-body");
    body.textContent = "";
    if (!FINDINGS.length) {
      const p = document.createElement("div");
      p.textContent = "No findings yet.";
      p.setAttribute("style", "color:#8b949e;padding:10px;text-align:center;");
      body.appendChild(p);
      return;
    }
    const rank = { high: 0, medium: 1, low: 2 };
    const sorted = [...FINDINGS].sort(
      (a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9)
    );
    for (const f of sorted.slice(-25).reverse()) {
      const card = document.createElement("div");
      card.setAttribute(
        "style",
        "border:1px solid #30363d;border-radius:6px;padding:8px;margin-bottom:6px;"
      );
      const h = document.createElement("div");
      h.setAttribute(
        "style",
        "display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;"
      );
      const sev = document.createElement("span");
      sev.textContent = (f.severity || "medium").toUpperCase();
      const color = { HIGH: "#f85149", MEDIUM: "#d29922", LOW: "#58a6ff" }[
        sev.textContent
      ];
      sev.setAttribute("style", `color:${color};font-weight:700;`);
      const sink = document.createElement("code");
      sink.textContent = f.sink?.type || "unknown";
      sink.setAttribute("style", "color:#79c0ff;");
      h.append(sev, sink);
      const ev = document.createElement("div");
      ev.textContent = String(f.evidence || "").slice(0, 150);
      ev.setAttribute(
        "style",
        "color:#c9d1d9;word-break:break-all;font-size:11px;margin-top:4px;"
      );
      const chain = document.createElement("div");
      chain.textContent =
        "chain: " + (f.taintChain || []).map((c) => c.source).join(" → ");
      chain.setAttribute("style", "color:#6e7681;font-size:10px;margin-top:2px;");
      card.append(h, ev, chain);
      body.appendChild(card);
    }
  }

  window.addEventListener(
    "load",
    () => setTimeout(runStaticAnalysis, 1500),
    { once: true }
  );

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;
    if (msg.type === "GET_FINDINGS") {
      sendResponse({ findings: FINDINGS, env, url: location.href });
      return true;
    }
    if (msg.type === "TOGGLE_OVERLAY") {
      const p = ensureOverlay();
      p.style.display = p.style.display === "none" ? "flex" : "none";
      sendResponse({ visible: p.style.display !== "none" });
      return true;
    }
  });
})();
