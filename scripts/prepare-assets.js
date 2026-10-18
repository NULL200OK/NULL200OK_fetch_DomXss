#!/usr/bin/env node
// Auto-generates icons (16/48/128 PNG) and fetches Acorn. Idempotent.
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const ROOT = path.resolve(__dirname, "..");
const ICONS = path.join(ROOT, "icons");
const VENDOR = path.join(ROOT, "vendor");

fs.mkdirSync(ICONS, { recursive: true });
fs.mkdirSync(VENDOR, { recursive: true });

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, "ascii");
  const c = Buffer.alloc(4);
  c.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, c]);
}

function makePNG(size, pixelFn) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.writeUInt8(8, 8);
  ihdr.writeUInt8(6, 9);
  ihdr.writeUInt8(0, 10);
  ihdr.writeUInt8(0, 11);
  ihdr.writeUInt8(0, 12);

  const rowSize = 1 + size * 4;
  const raw = Buffer.alloc(size * rowSize);
  for (let y = 0; y < size; y++) {
    raw[y * rowSize] = 0;
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixelFn(x, y, size);
      const off = y * rowSize + 1 + x * 4;
      raw[off] = r;
      raw[off + 1] = g;
      raw[off + 2] = b;
      raw[off + 3] = a ?? 255;
    }
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    sig,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function iconPixel(x, y, s) {
  const cx = s / 2;
  const cy = s / 2;
  const dx = x + 0.5 - cx;
  const dy = y + 0.5 - cy;
  const dist = Math.sqrt(dx * dx + dy * dy);
  const cornerR = s * 0.22;
  const bx = Math.min(x, s - 1 - x);
  const by = Math.min(y, s - 1 - y);
  if (bx < cornerR && by < cornerR) {
    const cd = Math.sqrt((cornerR - bx) ** 2 + (cornerR - by) ** 2);
    if (cd > cornerR) return [0, 0, 0, 0];
  }
  const outerR = s * 0.46;
  const innerR = s * 0.40;
  if (dist > innerR && dist < outerR) return [88, 166, 255, 255];
  const thickness = Math.max(1, s * 0.07);
  const halfS = s * 0.23;
  if (
    (Math.abs(dx - dy) < thickness || Math.abs(dx + dy) < thickness) &&
    Math.abs(dx) < halfS &&
    Math.abs(dy) < halfS
  ) {
    return [248, 81, 73, 255];
  }
  return [13, 17, 23, 255];
}

for (const size of [16, 48, 128]) {
  const buf = makePNG(size, iconPixel);
  fs.writeFileSync(path.join(ICONS, `icon${size}.png`), buf);
  console.log(`✓ icons/icon${size}.png (${buf.length} bytes)`);
}

async function fetchAcorn() {
  const target = path.join(VENDOR, "acorn.js");
  if (fs.existsSync(target) && fs.statSync(target).size > 1000) {
    console.log("✓ vendor/acorn.js already present");
    return;
  }
  const url = "https://unpkg.com/acorn@8.14.0/dist/acorn.mjs";
  console.log(`↓ fetching ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching acorn`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(target, buf);
  console.log(`✓ vendor/acorn.js (${buf.length} bytes)`);
}

fetchAcorn().catch((e) => {
  console.error("✗ Failed to fetch acorn:", e.message);
  process.exit(1);
});