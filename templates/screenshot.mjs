// Generates full-page screenshots of each templates/<slug>/index.html at 1280x800.
// Usage: node templates/screenshot.mjs
// Idempotent: re-running overwrites templates/screenshots/<slug>.png.
import { chromium } from "playwright";
import { readdirSync, existsSync, mkdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = __dirname;
const OUT_DIR = join(TEMPLATES_DIR, "screenshots");
const MAX_CONSOLE_ERRORS_TO_PRINT = 20;

function findTemplateSlugs() {
  const entries = readdirSync(TEMPLATES_DIR, { withFileTypes: true });
  const slugs = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name === "screenshots") continue;
    const indexPath = join(TEMPLATES_DIR, entry.name, "index.html");
    if (existsSync(indexPath) && statSync(indexPath).isFile()) {
      slugs.push(entry.name);
    }
  }
  slugs.sort();
  return slugs;
}

async function main() {
  if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

  const slugs = findTemplateSlugs();
  if (slugs.length === 0) {
    console.error("No templates/<slug>/index.html found. Nothing to screenshot.");
    process.exitCode = 1;
    return;
  }

  const browser = await chromium.launch();
  let hadErrors = false;

  try {
    for (const slug of slugs) {
      const indexPath = join(TEMPLATES_DIR, slug, "index.html");
      const url = pathToFileURL(indexPath).href;
      const outPath = join(OUT_DIR, `${slug}.png`);

      const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      const consoleErrors = [];
      page.on("console", (msg) => {
        if (msg.type() === "error") consoleErrors.push(msg.text());
      });
      page.on("pageerror", (err) => {
        consoleErrors.push(String(err));
      });

      await page.goto(url, { waitUntil: "networkidle" });
      await page.screenshot({ path: outPath, fullPage: true });
      await page.close();

      const errCount = consoleErrors.length;
      if (errCount > 0) hadErrors = true;
      console.log(`[${slug}] console errors: ${errCount} -> ${outPath}`);
      for (const line of consoleErrors.slice(0, MAX_CONSOLE_ERRORS_TO_PRINT)) {
        console.log(`  [${slug}] ${line}`);
      }
    }
  } finally {
    await browser.close();
  }

  if (hadErrors) {
    console.error("One or more templates produced console errors. See output above.");
    process.exitCode = 1;
  } else {
    console.log(`Done. ${slugs.length} screenshot(s) written to ${OUT_DIR}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
