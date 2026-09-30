const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

async function main() {
  const options = { headless: true };
  if (process.env.PLAYWRIGHT_CHANNEL)
    options.channel = process.env.PLAYWRIGHT_CHANNEL;
  const browser = await chromium.launch(options);
  const output = path.resolve(__dirname, "../test-results");
  fs.mkdirSync(output, { recursive: true });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
      reducedMotion: "reduce",
    });
    const errors = [];
    const externalRequests = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const url = process.env.PREVIEW_URL || "http://127.0.0.1:8765/";
    const origin = new URL(url).origin;
    // Forward real server responses through Playwright's HTTP client to avoid
    // system antivirus rewriting Edge traffic. No fixture responses are used.
    if (process.env.PREVIEW_ISOLATE_HTTP === "1") {
      await page.route(`${origin}/**`, async route => {
        const response = await route.fetch();
        await route.fulfill({ response });
      });
    }
    page.on("request", (request) => {
      if (new URL(request.url()).origin !== origin)
        externalRequests.push(request.url());
    });
    await page.goto(url);
    await page.waitForLoadState("networkidle");
    assert.equal(await page.locator("#metrics .metric").count(), 4);
    await page.screenshot({
      path: path.join(output, "overview.png"),
      fullPage: true,
    });
    await page.locator('.nav-link[data-page="runs"]').click();
    await page.locator("#run-status").selectOption("inconclusive");
    assert.equal(await page.locator("#run-list .run-row").count(), 1);
    assert.match(await page.locator("#run-detail").innerText(), /budget_wall/);
    await page.locator("#run-search").fill("no-matches");
    assert.match(await page.locator("#run-detail").innerText(), /没有可显示/);
    await page.locator('.nav-link[data-page="overview"]').click();
    await page.locator("#overview-runs .run-row").first().click();
    assert.match(await page.locator("#run-detail").innerText(), /DEMO-005/);
    assert.equal(await page.locator("#run-status").inputValue(), "");
    await page.locator('.nav-link[data-page="findings"]').click();
    await page.locator("#finding-search").fill("write_data");
    assert.equal(await page.locator("#finding-list .finding-row").count(), 1);
    assert.match(
      await page.locator("#finding-detail").innerText(),
      /绝对路径写入/,
    );
    assert.equal(
      await page.locator("#finding-detail details").getAttribute("open"),
      null,
    );
    await page.locator("#finding-search").fill("no-matches");
    assert.match(
      await page.locator("#finding-detail").innerText(),
      /没有可显示/,
    );
    await page.locator("#finding-search").fill("");
    await page.locator("#finding-severity").selectOption("中");
    assert.equal(await page.locator("#finding-list .finding-row").count(), 1);
    await page.locator("#finding-severity").selectOption("");
    await page.screenshot({
      path: path.join(output, "findings.png"),
      fullPage: true,
    });
    await page.locator(".top-action").click();
    await page.locator('[data-preset="deep"]').click();
    assert.match(await page.locator("#budget-summary").innerText(), /40,000/);
    assert.equal(await page.locator(".primary-button").isDisabled(), true);
    await page.goBack();
    assert.equal(
      await page
        .locator("#page-findings")
        .evaluate((n) => n.classList.contains("active")),
      true,
    );
    await page.goForward();
    assert.equal(
      await page
        .locator("#page-new-scan")
        .evaluate((n) => n.classList.contains("active")),
      true,
    );
    await page.locator('.nav-link[data-page="offline"]').click();
    async function upload(data) {
      await page
        .locator("#artifact-file")
        .setInputFiles({
          name: "test.json",
          mimeType: "application/json",
          buffer: Buffer.from(JSON.stringify(data)),
        });
    }
    await upload({
      findings: [
        {
          title: '<img src=x onerror="window.PWNED=true">',
          result_text: "<script>window.PWNED=true</script>",
        },
      ],
    });
    await page.waitForFunction(
      () => !document.getElementById("import-results").hidden,
    );
    assert.match(await page.locator("#import-list").innerText(), /<img/);
    assert.equal(await page.evaluate(() => window.PWNED), undefined);
    assert.equal(
      await page.locator("#import-list img, #import-list script").count(),
      0,
    );
    for (const malformed of [
      null,
      { findings: [null] },
      { findings: ["invalid"] },
    ]) {
      await upload(malformed);
      await page.waitForFunction(() =>
        document
          .getElementById("import-status")
          .textContent.startsWith("导入失败"),
      );
      assert.equal(await page.locator("#import-results").isVisible(), false);
    }
    await upload({ findings: [] });
    await page.waitForFunction(() =>
      document.getElementById("import-status").textContent.includes("共 0 个"),
    );
    for (const width of [768, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const id of [
        "overview",
        "targets",
        "runs",
        "findings",
        "new-scan",
        "offline",
      ]) {
        await page.evaluate(
          (id) => document.querySelector(`[data-page="${id}"]`).click(),
          id,
        );
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth > innerWidth,
          ),
          false,
          `${id} overflows at ${width}`,
        );
      }
      const nav = page.getByRole("button", { name: "运行记录", exact: true });
      await nav.focus();
      await page.keyboard.press("Enter");
      assert.equal(
        await page
          .locator("#page-runs")
          .evaluate((n) => n.classList.contains("active")),
        true,
      );
      await page.evaluate(() =>
        document.querySelector('[data-page="overview"]').click(),
      );
      await page.screenshot({
        path: path.join(output, `${width}.png`),
        fullPage: true,
      });
    }
    await page.goto(`${url.split("#")[0]}#constructor`);
    assert.equal(
      await page
        .locator("#page-overview")
        .evaluate((n) => n.classList.contains("active")),
      true,
    );
    assert.deepEqual(errors, []);
    assert.deepEqual(
      externalRequests,
      [],
      "offline import must not upload or request external content",
    );
    console.log(
      "PASS: layout, navigation/history, keyboard, filters/empty details, budgets, local import validation and XSS; no external requests or page errors",
    );
  } finally {
    await browser.close();
  }
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
