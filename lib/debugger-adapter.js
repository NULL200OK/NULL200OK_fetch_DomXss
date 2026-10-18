// NULL200OK_fetch_DomXss — CDP-based DOMPurify instrumentation (optional)
export class DebuggerAdapter {
  constructor(tabId) {
    this.tabId = tabId;
    this.debuggeeId = { tabId };
    this.attached = false;
    this.breakpoints = new Set();
    this._onEvent = this._onEvent.bind(this);
  }

  async attach() {
    try {
      await chrome.debugger.attach(this.debuggeeId, "1.3");
      this.attached = true;
      await chrome.debugger.sendCommand(this.debuggeeId, "Debugger.enable");
      await chrome.debugger.sendCommand(this.debuggeeId, "Runtime.enable");
      chrome.debugger.onEvent.addListener(this._onEvent);
      return true;
    } catch (e) {
      console.warn("[N2OK] debugger attach failed:", e);
      this.attached = false;
      return false;
    }
  }

  async _onEvent(source, method, params) {
    if (source.tabId !== this.tabId) return;
    if (method === "Debugger.scriptParsed") {
      await this._instrumentScript(params).catch(() => {});
    }
    if (method === "Debugger.paused") {
      await this._inspectPaused(params).catch(() => {});
    }
  }

  async _instrumentScript({ scriptId, url }) {
    if (!url || url.startsWith("chrome-extension://")) return;
    const src = await chrome.debugger
      .sendCommand(this.debuggeeId, "Debugger.getScriptSource", { scriptId })
      .catch(() => null);
    if (!src?.scriptSource) return;
    const code = src.scriptSource;
    if (code.length > 2_000_000) return;
    if (!/sanitize/i.test(code) && !/DOMPurify/i.test(code)) return;
    const idx = code.search(/function\s+sanitize\s*\(|sanitize\s*[:=]\s*function/);
    if (idx < 0) return;
    const before = code.slice(0, idx);
    const line = before.split("\n").length - 1;
    const col = idx - before.lastIndexOf("\n") - 1;
    const bp = await chrome.debugger
      .sendCommand(this.debuggeeId, "Debugger.setBreakpointByUrl", {
        lineNumber: line,
        url,
        columnNumber: col,
      })
      .catch(() => null);
    if (bp?.breakpointId) this.breakpoints.add(bp.breakpointId);
  }

  async _inspectPaused(params) {
    const frame = params.callFrames?.[0];
    if (!frame) {
      await this._resume();
      return;
    }
    const args = [];
    for (let i = 0; i < Math.min(frame.arguments?.length || 0, 3); i++) {
      const a = frame.arguments[i];
      if (a.type === "string") args.push(a.value);
      else if (a.type === "object" && a.objectId) {
        const props = await chrome.debugger
          .sendCommand(this.debuggeeId, "Runtime.getProperties", {
            objectId: a.objectId,
            ownProperties: true,
          })
          .catch(() => null);
        const preview = (props?.result || [])
          .map((p) => `${p.name}:${p.value?.value ?? "?"}`)
          .join(",");
        args.push(preview);
      } else args.push("");
    }
    if (args.length) {
      chrome.runtime
        .sendMessage({
          type: "DOMPURIFY_DEBUG",
          tabId: this.tabId,
          dirtyPreview: String(args[0] || "").slice(0, 300),
          configPreview: String(args[1] || "").slice(0, 300),
          url: frame.url,
        })
        .catch(() => {});
    }
    await this._resume();
  }

  async _resume() {
    await chrome.debugger
      .sendCommand(this.debuggeeId, "Debugger.resume")
      .catch(() => {});
  }

  async detach() {
    if (!this.attached) return;
    chrome.debugger.onEvent.removeListener(this._onEvent);
    for (const bp of this.breakpoints) {
      await chrome.debugger
        .sendCommand(this.debuggeeId, "Debugger.removeBreakpoint", { breakpointId: bp })
        .catch(() => {});
    }
    await chrome.debugger.detach(this.debuggeeId).catch(() => {});
    this.attached = false;
  }
}