const tabId = chrome.devtools.inspectedWindow.tabId;
const findings = [];
const seen = new Set();

function rowFor(f) {
  const tr = document.createElement("tr");
  const sev = document.createElement("td");
  sev.textContent = (f.severity || "medium").toUpperCase();
  sev.className = "sev-" + (f.severity || "medium");
  const sink = document.createElement("td");
  sink.textContent = f.sink?.type || "unknown";
  const src = document.createElement("td");
  src.className = "src";
  src.textContent = (f.sources || []).map((s) => `${s.type} (${s.confidence})`).join(", ");
  const ev = document.createElement("td");
  ev.className = "ev";
  ev.textContent = String(f.evidence || "");
  const ts = document.createElement("td");
  ts.className = "src";
  ts.textContent = new Date(f.timestamp).toLocaleTimeString();
  const act = document.createElement("td");
  if (f.sink?.selector) {
    const b = document.createElement("button");
    b.textContent = "Locate";
    b.onclick = () => {
      chrome.devtools.inspectedWindow.eval(
        `(function(){var e=document.querySelector(${JSON.stringify(f.sink.selector)});if(e){e.scrollIntoView({behavior:'smooth',block:'center'});e.style.outline='3px solid #f85149';setTimeout(function(){e.style.outline='';},2000);return true;}return false;})()`
      );
    };
    act.appendChild(b);
  }
  tr.append(sev, sink, src, ev, ts, act);
  return tr;
}

function addFinding(f) {
  if (seen.has(f.id)) return;
  seen.add(f.id);
  findings.push(f);
  document.getElementById("empty").style.display = "none";
  document.getElementById("tbl").style.display = "table";
  document.getElementById("tbody").appendChild(rowFor(f));
  document.getElementById("count").textContent = findings.length;
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "NEW_FINDING" && msg.tabId === tabId) addFinding(msg.finding);
});

chrome.runtime.sendMessage(
  { type: "GET_FINDINGS_FOR_TAB", tabId },
  (res) => (res?.findings || []).forEach(addFinding)
);

document.getElementById("clear").addEventListener("click", () => {
  findings.length = 0;
  seen.clear();
  document.getElementById("tbody").textContent = "";
  document.getElementById("tbl").style.display = "none";
  document.getElementById("empty").style.display = "block";
  document.getElementById("count").textContent = "0";
  chrome.runtime.sendMessage({ type: "CLEAR_FINDINGS", tabId });
});