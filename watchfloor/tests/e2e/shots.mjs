// Captures README screenshots from the demo build: node e2e/shots.mjs (with `vite preview` of dist-demo on :4173).
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const out = process.argv[2] ?? "../docs/img";
mkdirSync(out, { recursive: true });
const browser = await chromium.launch(process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {});
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
const base = process.env.SHOTS_BASE ?? "http://127.0.0.1:4173/";
const shoot = async (hash, name, prep) => {
  await page.goto(`${base}#${hash}`);
  await page.waitForTimeout(1200);
  if (prep) await prep();
  await page.screenshot({ path: `${out}/${name}.png`, fullPage: false });
};
await shoot("/", "watch-floor");
await shoot("/scenarios/ssh-bruteforce-to-persistence", "playback", async () => {
  await page.getByRole("button", { name: "Skip to end" }).click();
  await page.waitForTimeout(600);
});
const incidents = await (await fetch(`${base}demo/incidents.json`)).json();
await shoot(`/incidents/${incidents[0].id}`, "incident");
await shoot("/coverage", "coverage");
await shoot("/exposure", "exposure");
await shoot("/analyst", "analyst");
await shoot("/", "terminal", async () => {
  await page.keyboard.press("Control+k");
  const t = page.getByRole("textbox", { name: "Terminal command" });
  await t.fill("/hunt T1110.001");
  await t.press("Enter");
  await page.waitForTimeout(300);
  await t.fill("/isolate web01 --reason \"brute force then sudo\"");
  await t.press("Enter");
  await page.waitForTimeout(500);
});
await page.keyboard.press("Escape");
await shoot("/", "phosphor", async () => {
  await page.keyboard.press("Escape");
  for (const k of ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"]) await page.keyboard.press(k);
  await page.waitForTimeout(900);
});
await browser.close();
