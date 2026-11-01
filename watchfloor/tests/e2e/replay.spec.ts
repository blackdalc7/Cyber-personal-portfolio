import { expect, test } from "@playwright/test";

test.describe("replay demo", () => {
  test.beforeEach(({ page }) => {
    page.on("pageerror", (err) => {
      throw err;
    });
  });

  test("watch floor shows the recorded KPIs", async ({ page }) => {
    await page.goto("./");
    await expect(page.getByRole("heading", { name: "Watch floor" })).toBeVisible();
    await expect(page.getByText("REPLAY DEMO", { exact: true })).toBeVisible();
    await expect(page.getByText("Activity events").first()).toBeVisible();
    await expect(page.getByRole("img", { name: "Findings by severity" })).toBeVisible();
  });

  test("scenario playback scores every stage", async ({ page }) => {
    await page.goto("./#/scenarios");
    await page.getByRole("link", { name: /Play SSH/i }).click();
    await page.getByRole("button", { name: "Skip to end" }).click();
    await expect(page.getByText("Detection gaps to close")).toBeVisible();
    await expect(page.getByText(/\d\/6/).first()).toBeVisible();
  });

  test("incident detail shows the response record", async ({ page }) => {
    await page.goto("./#/incidents");
    await page.locator("tbody a").first().click();
    await expect(page.getByRole("list", { name: "Response progress" })).toBeVisible();
    // Both recorded incidents are already contained, so slide-to-isolate must refuse to move.
    await expect(page.getByRole("button", { name: /Slide to isolate .*: slide to execute/ })).toBeDisabled();
    await expect(page.getByText("Timeline")).toBeVisible();
  });

  test("exposure what-if closes attack paths", async ({ page }) => {
    await page.goto("./#/exposure");
    await expect(page.getByText("Crown jewels reachable")).toBeVisible();
    const boxes = page.getByRole("checkbox");
    for (let i = 0; i < (await boxes.count()); i++) await boxes.nth(i).check();
    await expect(page.getByText("none", { exact: true })).toBeVisible();
  });

  test("terminal palette runs commands and gates isolation behind a hold", async ({ page }) => {
    await page.goto("./");
    await page.keyboard.press("Control+k");
    const term = page.getByRole("textbox", { name: "Terminal command" });
    await term.fill("/help");
    await term.press("Enter");
    await expect(page.getByText(/\/isolate\s+<host>/)).toBeVisible();
    await term.fill("/isolate web01 --reason test");
    await term.press("Enter");
    const hold = page.getByRole("button", { name: /isolate web01 \(press and hold/ });
    await hold.click(); // a click is too short: nothing may happen
    await expect(page.getByText(/approval card for web01/)).toHaveCount(0);
    const box = await hold.boundingBox();
    if (!box) throw new Error("no button");
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.waitForTimeout(2300);
    await page.mouse.up();
    await expect(page.getByText(/\[simulated\] approval card for web01/)).toBeVisible();
  });

  test("konami code and deface mode are cosmetic and reversible", async ({ page }) => {
    await page.goto("./");
    await expect(page.getByRole("heading", { name: "Watch floor" })).toBeVisible();
    for (const k of ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"]) {
      await page.keyboard.press(k);
    }
    await expect(page.locator("html")).toHaveAttribute("data-mode", "phosphor");
    await page.getByRole("button", { name: "Settings" }).click();
    await page.getByRole("switch", { name: /Simulate console compromise/ }).click();
    await expect(page.getByRole("dialog", { name: "Deface mode simulation" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog", { name: "Deface mode simulation" })).toHaveCount(0);
  });

  test("coverage, rules and analyst pages render", async ({ page }) => {
    for (const [hash, heading] of [["coverage", "ATT&CK coverage"], ["rules", /Detection rules|No rules index/], ["analyst", "Analyst engine"]] as const) {
      await page.goto(`./#/${hash}`);
      await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
    }
  });
});
