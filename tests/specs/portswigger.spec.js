import { test, expect } from "@playwright/test";

const LABS = {
  L1: { url: process.env.LAB_L1, expect: "HIGH" },
  L2: { url: process.env.LAB_L2, expect: "HIGH" },
  L3: { url: process.env.LAB_L3, expect: "HIGH" },
  L8: { url: process.env.LAB_L8, expect: "HIGH" },
  L9: { url: process.env.LAB_L9, expect: "HIGH" },
  L10: { url: process.env.LAB_L10, expect: "MEDIUM" },
};

for (const [id, cfg] of Object.entries(LABS)) {
  test(`[${id}] detection`, async ({ page }) => {
    if (!cfg.url) test.skip(true, `LAB_${id} not set`);
    await page.goto(cfg.url, { waitUntil: "networkidle" });
    await page.evaluate(() => {
      location.hash = '<img src=x onerror=alert(1)>';
    });
    await page.waitForTimeout(3000);
    const text = await page.locator("#n2ok-overlay").innerText().catch(() => "");
    expect(text).toMatch(new RegExp(cfg.expect));
  });
}