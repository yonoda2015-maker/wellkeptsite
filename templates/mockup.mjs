// Generates a company-specific mockup from an existing templates/<base>/index.html sample:
// a DOM-based token replacement (via Playwright) of the [data-mock] business
// name/city/phone/tagline fields, plus a full-page JPEG screenshot.
//
// Usage:
//   node templates/mockup.mjs --base accountant --name "Riverside Tax & Accounting" \
//     --domain riversidetaxoh.com --city "Columbus, OH" --phone "(614) 555-0148" \
//     [--tagline "..."]
//
// Output (idempotent, overwrites on re-run):
//   templates/mockups/<domain>/index.html   — full replaced HTML, servable as-is
//   templates/mockups/<domain>.jpg          — 1280x800 viewport, full-page JPEG, quality 82
//
// Exits 2 with a clear message on: missing --name, unknown --base, invalid --domain.

import { chromium } from "playwright";
import { readFileSync, existsSync, mkdirSync, writeFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = __dirname;
const MOCKUPS_DIR = join(TEMPLATES_DIR, "mockups");
const MAX_DOMAIN_LENGTH = 80;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

function fail(message) {
  console.error(`Error: ${message}`);
  process.exit(2);
}

function slugifyDomain(rawDomain) {
  const lowered = String(rawDomain).toLowerCase();
  const cleaned = lowered.replace(/[^a-z0-9.-]/g, "_");
  if (cleaned.length === 0) fail("--domain resolved to an empty string after slugifying");
  return cleaned.slice(0, MAX_DOMAIN_LENGTH);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const base = args.base;
  const name = args.name;
  const domainRaw = args.domain;
  const city = args.city || "";
  const phone = args.phone || "";
  const tagline = args.tagline || "";

  if (!base || typeof base !== "string") fail("--base is required (an existing templates/<slug> name)");
  if (!name || typeof name !== "string") fail("--name is required (the business name to insert)");
  if (!domainRaw || typeof domainRaw !== "string") fail("--domain is required");

  const basePath = join(TEMPLATES_DIR, base, "index.html");
  if (!existsSync(basePath) || !statSync(basePath).isFile()) {
    fail(`--base "${base}" does not exist (expected ${basePath})`);
  }

  const domain = slugifyDomain(domainRaw);
  if (!/^[a-z0-9.-]+$/.test(domain)) fail(`--domain produced an invalid slug: "${domain}"`);

  const outDir = join(MOCKUPS_DIR, domain);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

  const sourceUrl = pathToFileURL(basePath).href;
  const browser = await chromium.launch();
  let hadConsoleError = false;

  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        hadConsoleError = true;
        console.error(`[${domain}] console error: ${msg.text()}`);
      }
    });
    page.on("pageerror", (err) => {
      hadConsoleError = true;
      console.error(`[${domain}] page error: ${err}`);
    });

    await page.goto(sourceUrl, { waitUntil: "networkidle" });

    const replaced = await page.evaluate(
      ({ name, city, phone, tagline, domain }) => {
        const counts = { name: 0, city: 0, phone: 0, tagline: 0, email: 0 };
        const values = { name, city, phone, tagline };
        document.querySelectorAll("[data-mock]").forEach((el) => {
          const field = el.getAttribute("data-mock");
          const value = values[field];
          if (value === undefined || value === "") return;
          el.textContent = value;
          counts[field] = (counts[field] || 0) + 1;
        });
        if (name) document.title = name;
        // Contact email: every base sample has a fictional mailto (e.g.
        // consult@ashfordvale.com). Leaving it in a mockup that carries a real
        // prospect's name would look like a typo at best — rewrite both the
        // href and the visible text to info@<their domain>.
        const email = `info@${domain}`;
        let emails = 0;
        document.querySelectorAll('a[href^="mailto:"]').forEach((a) => {
          a.setAttribute("href", `mailto:${email}`);
          if (/@/.test(a.textContent || "")) a.textContent = email;
          emails += 1;
        });
        counts.email = emails;
        return counts;
      },
      { name, city, phone, tagline, domain }
    );

    // Force eager-load of any lazy images so the saved HTML and the screenshot
    // both render fully without relying on scroll-triggered loading.
    await page.evaluate(() => {
      document.querySelectorAll("img[loading='lazy']").forEach((img) => (img.loading = "eager"));
    });
    await page.waitForTimeout(200);

    const finalHtml = await page.content();
    writeFileSync(join(outDir, "index.html"), finalHtml, "utf-8");

    await page.screenshot({
      path: join(MOCKUPS_DIR, `${domain}.jpg`),
      type: "jpeg",
      quality: 82,
      fullPage: true,
    });

    console.log(
      `[${domain}] base=${base} replaced=${JSON.stringify(replaced)} -> ` +
        `templates/mockups/${domain}/index.html, templates/mockups/${domain}.jpg`
    );
  } finally {
    await browser.close();
  }

  if (hadConsoleError) {
    console.error(`[${domain}] completed with console errors — see above.`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
