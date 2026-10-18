// NULL200OK_fetch_DomXss — CFG + PDG builder

export function buildCFG(ast) {
  const cfg = { nodes: [], edges: [], entry: null, exit: null };
  let nid = 0;

  const newNode = (type, label, pos = -1) => {
    const n = { id: `n${nid++}`, type, label, pos, succ: [], pred: [] };
    cfg.nodes.push(n);
    return n;
  };
  const addEdge = (from, to) => {
    if (!from || !to) return;
    from.succ.push(to.id);
    to.pred.push(from.id);
    cfg.edges.push({ from: from.id, to: to.id });
  };

  const functions = [];
  walkAll(ast, (n) => {
    if (
      n.type === "FunctionDeclaration" ||
      n.type === "FunctionExpression" ||
      n.type === "ArrowFunctionExpression"
    ) {
      functions.push(n);
    }
  });

  for (const fn of functions) {
    const entry = newNode("entry", fn.id?.name || "<anonymous>", fn.start);
    const exit = newNode("exit", "return", fn.end);
    if (!cfg.entry) cfg.entry = entry;
    cfg.exit = exit;
    const body = fn.body.type === "BlockStatement" ? fn.body.body : [fn.body];
    let current = entry;
    for (const stmt of body) {
      const next = buildStatement(stmt, newNode, addEdge, current);
      if (next === null) break;
      current = next;
    }
    if (current) addEdge(current, exit);
  }
  return cfg;
}

function buildStatement(stmt, newNode, addEdge, current) {
  switch (stmt.type) {
    case "BlockStatement": {
      let cur = current;
      for (const s of stmt.body) {
        const next = buildStatement(s, newNode, addEdge, cur);
        if (next === null) return null;
        cur = next;
      }
      return cur;
    }
    case "IfStatement": {
      const cond = newNode("condition", "if", stmt.start);
      addEdge(current, cond);
      const thenEntry = newNode("branch", "then", stmt.consequent.start);
      addEdge(cond, thenEntry);
      const thenExit = buildStatement(stmt.consequent, newNode, addEdge, thenEntry);
      let elseExit = null;
      if (stmt.alternate) {
        const elseEntry = newNode("branch", "else", stmt.alternate.start);
        addEdge(cond, elseEntry);
        elseExit = buildStatement(stmt.alternate, newNode, addEdge, elseEntry);
      }
      const merge = newNode("merge", "join", stmt.end);
      if (thenExit) addEdge(thenExit, merge);
      if (elseExit) addEdge(elseExit, merge);
      if (!stmt.alternate) addEdge(cond, merge);
      return merge;
    }
    case "WhileStatement":
    case "ForStatement":
    case "ForInStatement":
    case "ForOfStatement": {
      const loop = newNode("loop", stmt.type, stmt.start);
      addEdge(current, loop);
      const bodyEntry = newNode("body", "loop-body", stmt.body.start);
      addEdge(loop, bodyEntry);
      const bodyExit = buildStatement(stmt.body, newNode, addEdge, bodyEntry);
      if (bodyExit) addEdge(bodyExit, loop);
      const after = newNode("after-loop", "exit-loop", stmt.end);
      addEdge(loop, after);
      return after;
    }
    case "ReturnStatement": {
      const ret = newNode("return", "return", stmt.start);
      addEdge(current, ret);
      return null;
    }
    case "ThrowStatement": {
      const thr = newNode("throw", "throw", stmt.start);
      addEdge(current, thr);
      return null;
    }
    default: {
      const n = newNode("stmt", stmt.type, stmt.start);
      addEdge(current, n);
      return n;
    }
  }
}

export function buildPDG(ast, cfg) {
  const pdg = { nodes: cfg.nodes, edges: [] };
  const defs = new Map();
  const uses = new Map();

  function posToNode(pos) {
    let best = null;
    let bestDist = Infinity;
    for (const n of cfg.nodes) {
      if (n.pos < 0) continue;
      const d = Math.abs(n.pos - pos);
      if (d < bestDist) {
        bestDist = d;
        best = n;
      }
    }
    return best;
  }

  walkAll(ast, (n) => {
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier") {
      const arr = defs.get(n.id.name) || [];
      arr.push({ node: posToNode(n.start), expr: n.init });
      defs.set(n.id.name, arr);
    }
    if (n.type === "AssignmentExpression" && n.left.type === "Identifier") {
      const arr = defs.get(n.left.name) || [];
      arr.push({ node: posToNode(n.start), expr: n.right });
      defs.set(n.left.name, arr);
    }
    if (n.type === "Identifier") {
      const arr = uses.get(n.name) || [];
      arr.push({ node: posToNode(n.start), expr: n });
      uses.set(n.name, arr);
    }
  });

  for (const [name, defList] of defs) {
    const useList = uses.get(name) || [];
    for (const d of defList) {
      for (const u of useList) {
        if (d.node && u.node && d.node.id !== u.node.id) {
          pdg.edges.push({ from: d.node.id, to: u.node.id, type: "data", var: name });
        }
      }
    }
  }

  const branches = cfg.nodes.filter(
    (n) => n.type === "condition" || n.type === "loop"
  );
  for (const b of branches) {
    const reachable = reachableFrom(cfg, b.id);
    for (const r of reachable) {
      if (r.id !== b.id) {
        pdg.edges.push({ from: b.id, to: r.id, type: "control" });
      }
    }
  }
  return pdg;
}

function reachableFrom(cfg, id) {
  const seen = new Set();
  const stack = [id];
  while (stack.length) {
    const cur = stack.pop();
    if (seen.has(cur)) continue;
    seen.add(cur);
    const node = cfg.nodes.find((n) => n.id === cur);
    (node?.succ || []).forEach((s) => stack.push(s));
  }
  return cfg.nodes.filter((n) => seen.has(n.id));
}

function walkAll(ast, visit) {
  const stack = [ast];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node.type !== "string") continue;
    visit(node);
    for (const key in node) {
      if (key === "type" || key === "start" || key === "end") continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const c of child) {
          if (c && typeof c.type === "string") stack.push(c);
        }
      } else if (child && typeof child.type === "string") {
        stack.push(child);
      }
    }
  }
}

const SOURCES = [
  "location.hash",
  "location.search",
  "location.href",
  "document.referrer",
  "document.URL",
  "window.name",
];

const SINKS = [
  "innerHTML",
  "outerHTML",
  "insertAdjacentHTML",
  "document.write",
  "document.writeln",
  "eval",
  "Function",
  "setTimeout",
  "setInterval",
  "assign",
  "replace",
  "srcdoc",
];

export function findFlows(ast, cfg, pdg) {
  const results = [];
  walkAll(ast, (n) => {
    if (n.type !== "CallExpression") return;
    const sink = sinkName(n);
    if (!sink || !SINKS.includes(sink)) return;
    for (const arg of n.arguments || []) {
      const src = sourceOf(arg);
      if (src) {
        results.push({ sink, source: src, start: n.start, end: n.end });
      }
    }
  });
  return results;
}

function sinkName(call) {
  const c = call.callee;
  if (c.type === "MemberExpression" && c.property.type === "Identifier") {
    return c.property.name;
  }
  if (c.type === "Identifier") return c.name;
  return null;
}

function sourceOf(node) {
  if (!node) return null;
  if (node.type === "MemberExpression") {
    const path = memberPath(node);
    for (const s of SOURCES) if (path.startsWith(s)) return path;
  }
  if (node.type === "TemplateLiteral") {
    for (const e of node.expressions || []) {
      const r = sourceOf(e);
      if (r) return r;
    }
  }
  return null;
}

function memberPath(n) {
  if (n.type === "Identifier") return n.name;
  if (n.type === "MemberExpression") {
    const o = memberPath(n.object);
    const p = n.property.type === "Identifier" ? n.property.name : "";
    return o ? `${o}.${p}` : p;
  }
  return "";
}