#!/usr/bin/env node
// Builds dist/ from source. Cross-platform.
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");

const required = [
  "icons/icon16.png",
  "icons/icon48.png",
  "icons/icon128.png",
  "vendor/acorn.js",
];
for (const r of required) {
  if (!fs.existsSync(path.join(ROOT, r))) {
    console.error(`✗ Missing ${r}. Run "npm run assets" first.`);
    process.exit(1);
  }
}

fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });

const items = [
  "manifest.json",
  "background.js",
  "content",
  "popup",
  "devtools",
  "lib",
  "vendor",
  "icons",
];

for (const item of items) {
  const src = path.join(ROOT, item);
  if (!fs.existsSync(src)) {
    console.warn(`⚠ ${item} not found, skipping`);
    continue;
  }
  fs.cpSync(src, path.join(DIST, item), { recursive: true });
  console.log(`✓ dist/${item}`);
}

const distManifest = path.join(DIST, "manifest.json");
if (!fs.existsSync(distManifest)) {
  console.error("✗ dist/manifest.json missing");
  process.exit(1);
}
const m = JSON.parse(fs.readFileSync(distManifest, "utf8"));
if (m.name !== "NULL200OK_fetch_DomXss") {
  console.error(`✗ Extension name mismatch in manifest: ${m.name}`);
  process.exit(1);
}

let totalBytes = 0;
(function walk(dir) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p);
    else totalBytes += st.size;
  }
})(DIST);

console.log(`\n✓ Build complete: ${m.name} v${m.version}`);
console.log(`  dist/ size: ${(totalBytes / 1024).toFixed(1)} KB`);
console.log(`\n  Next: chrome://extensions → Load unpacked → ${DIST}`);