import { defineConfig } from "@playwright/test";

// Browser tests live in watchfloor/tests/e2e (run from here: npm run e2e). Smoke-tests the static replay build (the GitHub Pages artefact). Build it first: npm run build:demo.
// PW_CHROMIUM lets CI or a sandbox point at a preinstalled browser instead of downloading one.
export default defineConfig({
  testDir: "../tests/e2e",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:4173/",
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {},
  },
  webServer: {
    command: "npx vite preview --outDir dist-demo --port 4173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:4173/",
    reuseExistingServer: !process.env.CI,
  },
});
