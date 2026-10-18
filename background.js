// NULL200OK_fetch_DomXss — Service Worker (central taint engine)
import { DebuggerAdapter } from "./lib/debugger-adapter.js";

const TAINT_TTL_MS = 30_000;
const TAINT_CAP = 1024;

const TAINT_STORE = new Map();
const FINDINGS = new Map();
// تم الإصلاح: استخدام Map بدلاً من WeakMap لدعم أرقام التبويبات
const SEEN = new Map(); 
const DEBUGGERS = new Map();

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  }
  return h.toString(16);
}

function bucket(origin) {
  let b = TAINT_STORE.get(origin);
  if (!b) {
    b = new Map();
    TAINT_STORE.set(origin, b);
  }
  return b;
}

function recordTaint(origin, { sourceType, value, taintId }) {
  const b = bucket(origin);
  const now = Date.now();
  for (const [id, rec] of b) if (now - rec.createdAt > TAINT_TTL_MS) b.delete(id);
  while (b.size > TAINT_CAP) b.delete(b.keys().next().value);
  
  b.set(taintId, {
    id: taintId,
    source: sourceType,
    valueHash: simpleHash(value),
    preview: String(value).slice(0, 200),
    createdAt: now,
    children: [],
  });
}

function resolveTaint(origin, value, extra = {}) {
  const b = TAINT_STORE.get(origin);
  const s = String(value);
  
  // الخوارزمية الذكية: فحص الرابط الملتقط مباشرة لتجاوز قيود المتصفح
  if (extra && extra.search) {
    try {
      const params = new URLSearchParams(extra.search);
      for (const [key, val] of params.entries()) {
        if (val && val.length > 1 && s.includes(val)) {
          return {
            id: 'dynamic-fallback',
            source: 'location.search',
            preview: extra.search.slice(0, 200),
            valueHash: simpleHash(extra.search),
            createdAt: Date.now(),
            children: [],
          };
        }
      }
    } catch (e) {}
  }

  if (!b) return null;
  const hash = simpleHash(value);
  
  for (const rec of b.values()) if (rec.valueHash === hash) return rec;
  
  for (const rec of b.values()) {
    if (!rec.preview) continue;
    if (s.includes(rec.preview)) return rec;
    
    try {
      let qs = rec.preview;
      if (qs.includes('?')) qs = '?' + qs.split('?')[1];
      if (qs.startsWith('?') || qs.startsWith('#')) {
        const content = qs.substring(1);
        const params = new URLSearchParams(qs.startsWith('?') ? qs : `?${content}`);
        for (const [key, val] of params.entries()) {
          if (val && val.length > 1 && s.includes(decodeURIComponent(val))) return rec;
          if (val && val.length > 1 && s.includes(val)) return rec;
        }
        if (qs.startsWith('#') && content.length > 1 && s.includes(content)) return rec;
      }
    } catch (e) {}
  }
  return null;
}

function buildChain(origin, leafId) {
  const b = TAINT_STORE.get(origin);
  if (!b) return [];
  const chain = [];
  let cur = b.get(leafId);
  let guard = 0;
  while (cur && guard++ < 12) {
    chain.push({ id: cur.id, source: cur.source, operation: cur.operation || null });
    cur = cur.parent ? b.get(cur.parent) : null;
  }
  return chain.reverse();
}

function pushFinding(tabId, finding) {
  let seen = SEEN.get(tabId);
  if (!seen) {
    seen = new Set();
    SEEN.set(tabId, seen);
  }
  if (seen.has(finding.id)) return;
  seen.add(finding.id);
  
  const list = FINDINGS.get(tabId) || [];
  list.push(finding);
  FINDINGS.set(tabId, list);
  chrome.storage.local.set({ [`n2ok_findings_${tabId}`]: list }).catch(() => {});
  chrome.runtime.sendMessage({ type: "NEW_FINDING", tabId, finding }).catch(() => {});
}

function computeCVSS(finding) {
  const sink = finding.sink?.type || "";
  const sev = finding.severity;
  let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
  if (sink === "eval" || sink === "Function")
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N";
  if (finding.env?.trustedTypesEnforced)
    vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N";
  const scores = { high: 8.1, medium: 5.4, low: 3.1 };
  return { vector, score: scores[sev] ?? 5.0 };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  const origin = sender.origin || (sender.tab?.url ? new URL(sender.tab.url).origin : "unknown");

  if (msg.type === "SOURCE_READ") {
    recordTaint(origin, msg);
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "PROPAGATE") {
    const b = bucket(origin);
    if (!b.has(msg.parentTaintId)) return sendResponse({ taintId: null });
    const childId = crypto.randomUUID();
    const parent = b.get(msg.parentTaintId);
    parent.children.push(childId);
    b.set(childId, {
      id: childId,
      source: parent.source,
      valueHash: simpleHash(msg.value),
      preview: String(msg.value).slice(0, 200),
      createdAt: Date.now(),
      operation: msg.operation,
      parent: msg.parentTaintId,
      children: [],
    });
    sendResponse({ taintId: childId });
    return true;
  }

  if (msg.type === "SINK_WRITE") {
    const taint = resolveTaint(origin, msg.value, msg.extra);
    if (!taint) return sendResponse({ finding: null });
    
    const finding = {
      id: crypto.randomUUID(),
      severity: msg.severity || (msg.exploitable ? "high" : "medium"),
      sink: msg.sink,
      sources: [{ type: taint.source, value: taint.preview, confidence: "sw-taint" }],
      evidence: String(msg.value).slice(0, 500),
      taintChain: buildChain(origin, taint.id),
      cvss: computeCVSS({ sink: msg.sink, severity: msg.severity || "high", env: msg.env }),
      timestamp: new Date().toISOString(),
      env: msg.env || {},
    };
    pushFinding(sender.tab.id, finding);
    sendResponse({ finding });
    return true;
  }

  if (msg.type === "STATIC_ANALYSIS_RESULT") {
    for (const f of msg.findings || []) pushFinding(sender.tab.id, f);
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "GET_FINDINGS_FOR_TAB") {
    sendResponse({ findings: FINDINGS.get(msg.tabId) || [] });
    return true;
  }

  if (msg.type === "CLEAR_FINDINGS") {
    FINDINGS.delete(msg.tabId);
    SEEN.delete(msg.tabId);
    chrome.storage.local.remove(`n2ok_findings_${msg.tabId}`).catch(() => {});
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "ENABLE_DEBUGGER") {
    (async () => {
      if (DEBUGGERS.has(msg.tabId)) return sendResponse({ ok: true });
      const adapter = new DebuggerAdapter(msg.tabId);
      const ok = await adapter.attach();
      if (ok) DEBUGGERS.set(msg.tabId, adapter);
      sendResponse({ ok });
    })();
    return true;
  }

  if (msg.type === "DOMPURIFY_DEBUG") {
    const dirty = String(msg.dirtyPreview || "");
    const cfg = String(msg.configPreview || "");
    const dangerousInput = /<\s*(script|iframe|svg|img|body)\b|on\w+\s*=/i.test(dirty);
    const dangerousConfig = /ADD_ATTR|ADD_TAGS|USE_PROFILES|SAFE_FOR_TEMPLATES|SAFE_FOR_XML/i.test(cfg);
    if (dangerousInput || dangerousConfig) {
      const finding = {
        id: crypto.randomUUID(),
        severity: dangerousInput && dangerousConfig ? "high" : "medium",
        sink: { type: "DOMPurify.sanitize (CDP)", element: null, selector: null },
        sources: [{ type: "debugger-instrumented", value: dirty.slice(0, 200), confidence: "cdp" }],
        evidence: `dirty=${dirty.slice(0, 200)} | config=${cfg.slice(0, 200)}`,
        taintChain: [],
        cvss: computeCVSS({ sink: "DOMPurify", severity: "high" }),
        timestamp: new Date().toISOString(),
        env: {},
      };
      if (msg.tabId) pushFinding(msg.tabId, finding);
    }
    sendResponse({ ok: true });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  FINDINGS.delete(tabId);
  SEEN.delete(tabId);
  chrome.storage.local.remove(`n2ok_findings_${tabId}`).catch(() => {});
  const adapter = DEBUGGERS.get(tabId);
  if (adapter) {
    adapter.detach().catch(() => {});
    DEBUGGERS.delete(tabId);
  }
});
