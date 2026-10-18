import { defineConfig } from "@playwright/test";
import path from "node:path";

export default defineConfig({
  testDir: "./specs",
  timeout: 60_000,
  retries: 1,
  reporter: [["html", { outputFolder: "report" }], ["list"]],
  use: {
    headless: false,
    viewport: { width: 1280, height: 800 },
    launchOptions: {
      args: [
        `--disable-extensions-except=${path.resolve("../dist")}`,
        `--load-extension=${path.resolve("../dist")}`,
      ],
    },
  },
});