import { expect, test } from "@playwright/test";

test("real local workflow, denied action and evidence rendering", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(page.locator("#input")).toContainText("");
  await expect.poll(() => page.locator("#input").inputValue()).toContain('"operation": "ingest"');
  await page.locator("#submit").click();
  await expect(page.locator("#decision")).toHaveText("Tenant records");
  await page.locator("#next").click();
  await page.locator("#submit").click();
  await expect(page.locator("#decision")).toHaveText("awaiting_approval");
  await page.locator("#next").click();
  await page.locator("#submit").click();
  await expect(page.locator("#decision")).toHaveText("Role not authorized");
  await page.locator("#identity").selectOption("demo-approver");
  await page.locator("#submit").click();
  await expect(page.locator("#decision")).toHaveText("approved");
  await page.locator("#identity").selectOption("demo-verifier");
  await page.locator("#next").click();
  await page.locator("#submit").click();
  await expect(page.locator("#decision")).toHaveText("succeeded");

  await page.locator("#evidence").click();
  await expect(page.locator("#decision")).toHaveText("verified_local_chain");
  await page.screenshot({ path: "docs/workbench.png", fullPage: true });
  await page.locator("#identity").selectOption("demo-other-tenant");
  await page.locator("#list").click();
  await expect(page.locator("#output")).toContainText('"records": []');
  expect(errors).toEqual([]);
});
