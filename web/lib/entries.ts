import "server-only";

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Entry } from "./schema";

const ENTRIES_DIR = join(process.cwd(), "..", "entries");

let cache: Entry[] | null = null;

/** Reads the database straight off disk at build time. The repo is the source of truth. */
export function getAllEntries(): Entry[] {
  if (cache) return cache;

  const entries: Entry[] = [];
  for (const year of readdirSync(ENTRIES_DIR, { withFileTypes: true })) {
    if (!year.isDirectory()) continue;
    const dir = join(ENTRIES_DIR, year.name);
    for (const file of readdirSync(dir)) {
      if (!file.endsWith(".json")) continue;
      entries.push(JSON.parse(readFileSync(join(dir, file), "utf8")) as Entry);
    }
  }

  entries.sort((a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1) || a.id.localeCompare(b.id));
  cache = entries;
  return entries;
}

export function getEntry(id: string): Entry | undefined {
  return getAllEntries().find((e) => e.id === id);
}
