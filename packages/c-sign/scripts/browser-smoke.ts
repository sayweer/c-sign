// Bundles test/browser/smoke.ts for the browser, without a Buffer polyfill, and runs it in headless Chrome.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";

const CANDIDATES = [
  process.env.CHROME_PATH,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];
const chrome = CANDIDATES.find((p) => p && existsSync(p));
if (!chrome) throw new Error("Chrome not found; set CHROME_PATH");

const bundle = await build({
  entryPoints: [new URL("../test/browser/smoke.ts", import.meta.url).pathname],
  bundle: true,
  platform: "browser",
  format: "iife",
  write: false,
  logLevel: "warning",
});
const dir = mkdtempSync(join(tmpdir(), "c-sign-browser-"));
const page = join(dir, "index.html");
writeFileSync(join(dir, "smoke.js"), bundle.outputFiles[0]!.text);
writeFileSync(page, `<!doctype html><html><body><script src="smoke.js"></script></body></html>`);

const dom = execFileSync(chrome, ["--headless=new", "--disable-gpu", "--no-sandbox", "--dump-dom", `file://${page}`], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
});
const result = /data-result="([^"]*)"/.exec(dom)?.[1] ?? "FAIL no result (script did not run)";
console.log(`browser smoke: ${result}`);
if (result !== "PASS") process.exit(1);
