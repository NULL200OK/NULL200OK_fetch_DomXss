import { test, expect } from "@playwright/test";

test("benign page has no HIGH findings", async ({ page }) => {
  await page.goto("https://example.com", { waitUntil: "networkidle" });
  await page.waitForTimeout(3000);
  const text = await page.locator("#n2ok-overlay").innerText().catch(() => "");
  expect(text).not.toMatch(/HIGH/);
});

test("safe DOMPurify → MEDIUM", async ({ page }) => {
  const html = `<div id="out"></div>
    <script src="https://cdn.jsdelivr.net/npm/dompurify@3.2.4/dist/purify.min.js"></script>
    <script>
      document.addEventListener('DOMContentLoaded', () => {
        const dirty = location.hash.slice(1);
        document.getElementById('out').innerHTML = DOMPurify.sanitize(dirty);
      });
    </script>`;
  await page.goto("data:text/html," + encodeURIComponent(html));
  await page.evaluate(() => {
    location.hash = '<img src=x onerror=alert(1)>';
  });
  await page.waitForTimeout(3000);
  const text = await page.locator("#n2ok-overlay").innerText().catch(() => "");
  expect(text).toMatch(/MEDIUM/);
});