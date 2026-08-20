// Downloads vendor favicons for every icon-less vendor in web/lib/vendors.ts.
// Writes web/public/vendors/<slug>.png and the web/lib/vendor-favicons.json
// manifest the site uses to know which files exist. Both are committed.
//
// Run from web/:  node --experimental-strip-types ../scripts/fetch_vendor_icons.mjs

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { faviconTargets } from "../web/lib/vendors.ts";

const OUT_DIR = join(process.cwd(), "public", "vendors");
const MANIFEST = join(process.cwd(), "lib", "vendor-favicons.json");
const SIZE = 128;

const s2 = (domain) =>
  `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=${SIZE}`;

// OSS projects whose site favicon is unusable; their GitHub org avatar is the logo.
const GITHUB_ORGS = {
  tianocore: "tianocore",
  "u-boot": "u-boot",
  "llama-cpp": "ggml-org",
  spdk: "spdk",
  "oauth2-proxy": "oauth2-proxy",
  haproxy: "haproxy",
  ampere: "AmpereComputing",
};

async function fetchIcon(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) return null;
  return Buffer.from(await res.arrayBuffer());
}

mkdirSync(OUT_DIR, { recursive: true });

// Google serves a generic globe for unknown domains; hash it so it can be rejected.
const fallback = await fetchIcon(s2("no-such-domain-a7f3b9c1e5.com"));
const fallbackHash = fallback ? createHash("sha256").update(fallback).digest("hex") : "";

const manifest = {};
const failed = [];
for (const { slug, domain } of faviconTargets()) {
  let buf = await fetchIcon(s2(domain));
  const isDefault = !buf || createHash("sha256").update(buf).digest("hex") === fallbackHash;
  if (isDefault || buf.length < 200) buf = null;

  if (!buf && GITHUB_ORGS[slug]) {
    buf = await fetchIcon(`https://github.com/${GITHUB_ORGS[slug]}.png?size=${SIZE}`);
  }
  if (!buf) {
    // DuckDuckGo serves whatever the site ships; keep it only if it is a PNG.
    const ddg = await fetchIcon(`https://icons.duckduckgo.com/ip3/${domain}.ico`);
    if (ddg && ddg.length > 200 && ddg.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) {
      buf = ddg;
    }
  }
  if (!buf) {
    failed.push(`${slug} (${domain})`);
    continue;
  }
  writeFileSync(join(OUT_DIR, `${slug}.png`), buf);
  manifest[slug] = true;
}

// Manifest reflects the directory, so hand-added icons survive re-runs.
const { readdirSync } = await import("node:fs");
for (const f of readdirSync(OUT_DIR)) {
  if (f.endsWith(".png")) manifest[f.slice(0, -4)] = true;
}
writeFileSync(MANIFEST, JSON.stringify(manifest, null, 0) + "\n");
console.log(`saved ${Object.keys(manifest).length} favicons to ${OUT_DIR}`);
if (failed.length) console.log("no favicon for:", failed.join(", "));
