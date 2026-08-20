import "server-only";

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Entry } from "./schema";

const ENTRIES_DIR = join(process.cwd(), "..", "entries");
const DATES_FILE = join(process.cwd(), "data", "nvd-dates.json");

let cache: Entry[] | null = null;

/** Reads the database straight off disk at build time. The repo is the source of truth. */
export function getAllEntries(): Entry[] {
  if (cache) return cache;

  let dates: Record<string, string> = {};
  try {
    dates = JSON.parse(readFileSync(DATES_FILE, "utf8"));
  } catch {
    // Dates are an enrichment; the site must build without them.
  }
  const entries: Entry[] = [];
  for (const year of readdirSync(ENTRIES_DIR, { withFileTypes: true })) {
    if (!year.isDirectory()) continue;
    const dir = join(ENTRIES_DIR, year.name);
    for (const file of readdirSync(dir)) {
      if (!file.endsWith(".json")) continue;
      const entry = JSON.parse(readFileSync(join(dir, file), "utf8")) as Entry;
      if (entry.cve && dates[entry.cve]) entry.published = dates[entry.cve];
      entries.push(entry);
    }
  }

  entries.sort((a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1) || a.id.localeCompare(b.id));
  cache = entries;
  return entries;
}

export function getEntry(id: string): Entry | undefined {
  return getAllEntries().find((e) => e.id === id);
}
