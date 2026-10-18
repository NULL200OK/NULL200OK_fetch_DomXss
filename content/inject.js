// NULL200OK_fetch_DomXss — PAGE world hooks (Ultimate Coverage)
(() => {
  "use strict";
  const BRIDGE = "__NULL200OK_BRIDGE__";
  let seq = 0;

  function send(msg) {
    window.postMessage({ [BRIDGE]: true, ...msg }, "*");
  }

  function captureSource(type, val) {
    if (typeof val !== "string" || val.length < 3) return;
    send({
      type: "SOURCE_READ",
      sourceType: type,
      value: val.slice(0, 2000),
      taintId: `t-${Date.now()}-${++seq}`,
    });
  }

  // 1. اعتراض المصادر (URL Sources)
  const NativeURLSearchParams = window.URLSearchParams;
  window.URLSearchParams = function(init) {
    if (typeof init === "string") captureSource("location.search", init);
    return new NativeURLSearchParams(init);
  };

  function hookAccessor(owner, prop, type) {
    try {
      const d = Object.getOwnPropertyDescriptor(owner, prop);
      if (!d?.get) return;
      Object.defineProperty(owner, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get() {
          const v = d.get.call(this);
          captureSource(type, v);
          return v;
        },
        set: d.set,
      });
    } catch {}
  }
  try { hookAccessor(Location.prototype, "hash", "location.hash"); } catch {}
  try { hookAccessor(Location.prototype, "href", "location.href"); } catch {}
  try { hookAccessor(Document.prototype, "referrer", "document.referrer"); } catch {}
  try { hookAccessor(Document.prototype, "URL", "document.URL"); } catch {}
  try { hookAccessor(Window.prototype, "name", "window.name"); } catch {}

  // 2. اعتراض المصادر المخزنة (Storage & Cookies)
  const origGetItem = Storage.prototype.getItem;
  Storage.prototype.getItem = function(key) {
    const val = origGetItem.call(this, key);
    const type = this === window.localStorage ? "localStorage" : "sessionStorage";
    captureSource(`${type}.getItem`, val);
    return val;
  };

  try {
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    Object.defineProperty(Document.prototype, "cookie", {
      configurable: true,
      get: function() {
        const v = cookieDesc.get.call(this);
        captureSource("document.cookie", v);
        return v;
      },
      set: cookieDesc.set
    });
  } catch {}

  // 3. اعتراض المصادر التاريخية والـ Base64
  const origPushState = history.pushState;
  history.pushState = function(state, title, url) {
    if (state) captureSource("history.state", JSON.stringify(state));
    return origPushState.apply(this, arguments);
  };

  const origAtob = window.atob;
  window.atob = function(str) {
    const decoded = origAtob.call(window, str);
    captureSource("atob(Base64)", decoded);
    return decoded;
  };

  // 4. اعتراض المصارف (Sinks)
  const EXPLOITABLE = /<\s*(script|iframe|svg|img|body|object|embed|math)\b|on\w+\s*=|javascript\s*:|data\s*:\s*text\/html/i;

  function reportSink(sink, value, element, extra = {}) {
    if (typeof value !== "string" || value.length < 3) return;
    let searchData = '';
    try { searchData = location.search || ''; } catch(e) {}
    
    send({
      type: "SINK_WRITE",
      sink: { type: sink, element: element?.tagName?.toLowerCase?.() || null, selector: null },
      value: value.slice(0, 2000),
      exploitable: EXPLOITABLE.test(value),
      extra: { ...extra, search: searchData },
    });
  }

  const ih = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
  Object.defineProperty(Element.prototype, "innerHTML", {
    configurable: true, enumerable: ih.enumerable, get: ih.get,
    set(v) { reportSink("innerHTML", v, this); return ih.set.call(this, v); },
  });

  const oh = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
  Object.defineProperty(Element.prototype, "outerHTML", {
    configurable: true, enumerable: oh.enumerable, get: oh.get,
    set(v) { reportSink("outerHTML", v, this); return oh.set.call(this, v); },
  });

  const iah = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (pos, v) {
    reportSink("insertAdjacentHTML", v, this, { position: pos });
    return iah.call(this, pos, v);
  };

  // إضافة اعتراض setAttribute (لاكتشاف onclick و onmouseover)
  const origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    if (name.toLowerCase().startsWith("on") || name.toLowerCase() === "href" || name.toLowerCase() === "src") {
      reportSink("setAttribute", value, this, { attribute: name });
    }
    return origSetAttribute.call(this, name, value);
  };

  const dw = Document.prototype.write;
  Document.prototype.write = function (...a) {
    reportSink("document.write", a.join(""), null);
    return dw.apply(this, a);
  };
  
  const dwl = Document.prototype.writeln;
  Document.prototype.writeln = function (...a) {
    reportSink("document.writeln", a.join(""), null);
    return dwl.apply(this, a);
  };

  const nativeEval = window.eval;
  window.eval = function (c) {
    if (typeof c === "string") reportSink("eval", c, null);
    return nativeEval.call(window, c);
  };

  for (const name of ["setTimeout", "setInterval"]) {
    const orig = window[name];
    window[name] = function (h, ...rest) {
      if (typeof h === "string") reportSink(`${name}(string)`, h, null);
      return orig.call(window, h, ...rest);
    };
  }

  const nativeFunction = window.Function;
  window.Function = new Proxy(nativeFunction, {
    apply(t, thisArg, args) {
      const code = args.join(",");
      if (code.length > 4) reportSink("Function", code, null);
      return Reflect.apply(t, thisArg, args);
    },
  });

  const srcdoc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "srcdoc");
  if (srcdoc?.set) {
    Object.defineProperty(HTMLIFrameElement.prototype, "srcdoc", {
      configurable: true, enumerable: srcdoc.enumerable, get: srcdoc.get,
      set(v) { reportSink("srcdoc", v, this); return srcdoc.set.call(this, v); },
    });
  }

  for (const m of ["assign", "replace"]) {
    const orig = Location.prototype[m];
    Location.prototype[m] = function (u) {
      if (typeof u === "string") reportSink(`location.${m}`, u, null);
      return orig.call(this, u);
    };
  }

  // 5. اعتراض طلبات POST (XHR & Fetch)
  const origXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    if (typeof body === "string" && body.length > 3) {
      captureSource("XHR_POST_BODY", body);
    }
    return origXHRSend.call(this, body);
  };

  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    if (init && init.body && typeof init.body === "string") {
      captureSource("FETCH_POST_BODY", init.body);
    }
    return origFetch.apply(this, arguments);
  };

  // 6. كشف DOMPurify و Prototype Pollution
  (function hookDOMPurify() {
    let _dp = null;
    try { _dp = window.DOMPurify; } catch {}
    try {
      Object.defineProperty(window, "DOMPurify", {
        configurable: true, get() { return _dp; },
        set(v) { _dp = v; if (v && typeof v.sanitize === "function") hookInstance(v); },
      });
    } catch {}
    if (_dp && typeof _dp.sanitize === "function") hookInstance(_dp);

    function hookInstance(dp) {
      if (dp.__n2okHooked) return;
      try { dp.__n2okHooked = true; } catch {}
      const orig = dp.sanitize.bind(dp);
      dp.sanitize = function (dirty, config) {
        const issues = inspectConfig(config);
        if (issues.length) {
          send({
            type: "SINK_WRITE",
            sink: { type: "DOMPurify.dangerous-config", element: null, selector: null },
            value: String(dirty).slice(0, 500), exploitable: true, extra: { dompurify_flags: issues },
          });
        }
        return orig(dirty, config);
      };
    }

    function inspectConfig(cfg) {
      if (!cfg || typeof cfg !== "object") return [];
      const issues = [];
      if (typeof cfg.ADD_ATTR === "function") issues.push("ADD_ATTR(fn)");
      if (typeof cfg.ADD_TAGS === "function") issues.push("ADD_TAGS(fn)");
      if (cfg.USE_PROFILES) issues.push("USE_PROFILES");
      if (cfg.SAFE_FOR_TEMPLATES && (cfg.RETURN_DOM || cfg.IN_PLACE)) issues.push("SAFE_FOR_TEMPLATES+RETURN_DOM");
      if (cfg.SAFE_FOR_XML === false) issues.push("SAFE_FOR_XML(false)");
      return issues;
    }
  })();

  const PROTOS = [[Object.prototype, "Object"], [Array.prototype, "Array"], [Function.prototype, "Function"]];
  const BASELINE = PROTOS.map(([p]) => new Set(Object.getOwnPropertyNames(p)));
  const POLLUTED = new Set();

  setInterval(() => {
    for (let i = 0; i < PROTOS.length; i++) {
      const [proto, name] = PROTOS[i];
      for (const k of Object.getOwnPropertyNames(proto)) {
        const key = `${name}::${k}`;
        if (!BASELINE[i].has(k) && !POLLUTED.has(key)) {
          POLLUTED.add(key);
          send({
            type: "SINK_WRITE",
            sink: { type: "prototype-pollution", element: null, selector: null },
            value: `${name}.prototype.${k}`, exploitable: true, extra: { prototype: name, key: k },
          });
        }
      }
    }
  }, 1500);

  const origParse = JSON.parse;
  JSON.parse = function (t, r) {
    const res = origParse.call(this, t, r);
    if (typeof t === "string" && /"__proto__"\s*:/.test(t)) {
      send({ type: "SINK_WRITE", sink: { type: "JSON.parse(__proto__)", element: null, selector: null }, value: t.slice(0, 300), exploitable: true });
    }
    return res;
  };

  const origAssign = Object.assign;
  Object.assign = function (target, ...sources) {
    for (const s of sources) {
      if (s && typeof s === "object" && Object.prototype.hasOwnProperty.call(s, "__proto__")) {
        send({ type: "SINK_WRITE", sink: { type: "Object.assign(__proto__)", element: null, selector: null }, value: "__proto__", exploitable: true });
      }
    }
    return origAssign.call(this, target, ...sources);
  };
})();
