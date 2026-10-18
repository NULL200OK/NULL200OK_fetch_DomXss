let payload = null;

async function activeTab() {
  const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
  return t;
}

async function refresh() {
  const t = await activeTab();
  if (!t?.id) return;
  try {
    const res = await chrome.tabs.sendMessage(t.id, { type: "GET_FINDINGS" });
    const findings = res?.findings || [];
    const env = res?.env || {};
    document.getElementById("count").textContent = findings.length;
    document.getElementById("tt").textContent =
      env.trustedTypesEnforced == null
        ? "?"
        : env.trustedTypesEnforced
        ? "enforced"
        : "off";
    document.getElementById("csp").textContent =
      env.cspStrict == null ? "?" : env.cspStrict ? "strict" : "loose";
    payload = {
      scan_id: crypto.randomUUID(),
      tool: "NULL200OK_fetch_DomXss",
      version: "4.0.0",
      url: res?.url || t.url,
      timestamp: new Date().toISOString(),
      environment: env,
      findings,
    };
  } catch {
    payload = null;
  }
}

document.getElementById("toggle").addEventListener("click", async () => {
  const t = await activeTab();
  if (t?.id) chrome.tabs.sendMessage(t.id, { type: "TOGGLE_OVERLAY" }).catch(() => {});
});

async function download(content, mime, filename) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  try {
    await chrome.downloads.download({ url, filename, saveAs: true });
  } catch {
    chrome.tabs.create({ url });
  }
}

document.getElementById("export-json").addEventListener("click", async () => {
  if (!payload) await refresh();
  if (!payload) return;
  await download(
    JSON.stringify(payload, null, 2),
    "application/json",
    `n2ok-domxss-${Date.now()}.json`
  );
});

document.getElementById("export-sarif").addEventListener("click", async () => {
  if (!payload) await refresh();
  if (!payload) return;
  await download(
    JSON.stringify(toSarif(payload), null, 2),
    "application/sarif+json",
    `n2ok-domxss-${Date.now()}.sarif`
  );
});

// تم التعديل هنا: لم يعد يطلب صلاحية، بل ينفذ الأمر مباشرة
document.getElementById("enable-debugger").addEventListener("click", async () => {
  const t = await activeTab();
  if (!t?.id) return;
  
  chrome.runtime
    .sendMessage({ type: "ENABLE_DEBUGGER", tabId: t.id })
    .then(() => alert("Deep DOMPurify instrumentation enabled for this tab.\n\nNote: Chrome may show a yellow warning bar at the top. This is expected and required for deep inspection."))
    .catch(() => alert("Failed to enable debugger."));
});

function toSarif(p) {
  const RULES = new Map();
  function ruleFor(sinkType) {
    if (RULES.has(sinkType)) return RULES.get(sinkType).id;
    const id = `N2OK-${sinkType.replace(/[^a-z0-9]+/gi, "-").toUpperCase()}`;
    RULES.set(sinkType, {
      id,
      name: sinkType,
      shortDescription: { text: `DOM issue via ${sinkType}` },
      fullDescription: {
        text: `User-controllable data flows into ${sinkType} without safe handling.`,
      },
      help: {
        text: "Use safe DOM APIs (textContent), sanitize with DOMPurify, or enforce Trusted Types.",
      },
      defaultConfiguration: { level: "warning" },
      properties: { tags: ["dom-xss", "security", "client-side"] },
    });
    return id;
  }
  const SEV_TO_LEVEL = { high: "error", medium: "warning", low: "note" };
  const results = p.findings.map((f) => ({
    ruleId: ruleFor(f.sink?.type || "unknown"),
    level: SEV_TO_LEVEL[f.severity] || "warning",
    message: {
      text: `${f.sink?.type} reached from ${(f.sources || [])
        .map((s) => s.type)
        .join(", ")} — evidence: ${String(f.evidence).slice(0, 200)}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: p.url },
          region: f.sink?.selector ? { snippet: { text: f.sink.selector } } : {},
        },
      },
    ],
    properties: {
      severity: f.severity,
      sources: f.sources,
      sink: f.sink,
      cvss: f.cvss || null,
      taintChain: f.taintChain || [],
      timestamp: f.timestamp,
    },
  }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "NULL200OK_fetch_DomXss",
            version: "4.0.0",
            informationUri: "https://github.com/null200ok/NULL200OK_fetch_DomXss",
            rules: Array.from(RULES.values()),
          },
        },
        invocations: [{ executionSuccessful: true, startTimeUtc: p.timestamp }],
        results,
      },
    ],
  };
}

refresh();
