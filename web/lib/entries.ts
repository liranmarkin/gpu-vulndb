import "server-only";

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Entry } from "./schema";

const ENTRIES_DIR = join(process.cwd(), "..", "entries");
const DATES_FILE = join(process.cwd(), "data", "nvd-dates.json");
const UPDATED_FILE = join(process.cwd(), "data", "entry-updated.json");

let cache: Entry[] | null = null;

/** Reads the database straight off disk at build time. The repo is the source of truth. */
export function getAllEntries(): Entry[] {
  if (cache) return cache;

  // Dates are an enrichment, joined from the fetch_nvd_dates.py output; the site must build without them.
  let dates: Record<string, string> = {};
  try {
    dates = JSON.parse(readFileSync(DATES_FILE, "utf8"));
  } catch {}
  // When each entry last changed here. Written by scripts/seo_dates.py off git history;
  // it drives <lastmod>, the feed order, and the dateModified a crawler reads.
  let updated: Record<string, string> = {};
  try {
    updated = JSON.parse(readFileSync(UPDATED_FILE, "utf8"));
  } catch {}
  const entries: Entry[] = [];
  for (const year of readdirSync(ENTRIES_DIR, { withFileTypes: true })) {
    if (!year.isDirectory()) continue;
    const dir = join(ENTRIES_DIR, year.name);
    for (const file of readdirSync(dir)) {
      if (!file.endsWith(".json")) continue;
      const entry = JSON.parse(readFileSync(join(dir, file), "utf8")) as Entry;
      if (entry.cve && dates[entry.cve]) entry.published = dates[entry.cve];
      if (updated[entry.id]) entry.updated = updated[entry.id];
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

let byCve: Map<string, Entry> | null = null;

/**
 * Every id that should resolve to an entry page, including the CVEs folded into a consolidated
 * entry. Those ids were separate pages before they were merged, and are linked from NVD and
 * indexed by search engines; resolving them here is what keeps a merge from turning into a
 * few dozen 404s.
 */
export function resolveEntry(id: string): Entry | undefined {
  if (!byCve) {
    byCve = new Map();
    for (const e of getAllEntries()) {
      byCve.set(e.id, e);
      for (const cve of e.additional_cves ?? []) byCve.set(cve, e);
    }
  }
  return byCve.get(id);
}

/** Canonical ids plus the folded-in CVEs - what the entry route has to build pages for. */
export function getAllEntryPaths(): string[] {
  return getAllEntries().flatMap((e) => [e.id, ...(e.additional_cves ?? [])]);
}

let index: { component: Map<string, Entry[]>; layer: Map<string, Entry[]> } | null = null;

function getIndex() {
  if (index) return index;
  index = { component: new Map(), layer: new Map() };
  for (const e of getAllEntries()) {
    // getAllEntries() is ordered by CVSS descending, so each bucket inherits that order.
    index.component.set(e.component, [...(index.component.get(e.component) ?? []), e]);
    index.layer.set(e.layer, [...(index.layer.get(e.layer) ?? []), e]);
  }
  return index;
}

/**
 * Neighbours worth a click from an entry page: the same component first, then the rest of
 * the layer. Entry pages otherwise link nothing but hubs, which leaves 4,500 pages one hop
 * from the root and nothing pointing between them.
 */
export function getRelated(entry: Entry, limit = 6): Entry[] {
  const { component, layer } = getIndex();
  const picked: Entry[] = [];
  const seen = new Set([entry.id]);
  const take = (pool: Entry[]) => {
    for (const e of pool) {
      if (picked.length >= limit) return;
      if (seen.has(e.id)) continue;
      seen.add(e.id);
      picked.push(e);
    }
  };

  // Both pools are walked outward from this entry's own position rather than read from
  // the top: taking the six worst CVEs every time would point 1,200 pages at the same
  // six URLs and leave the rest linked from nowhere but the hub. Buckets are ordered by
  // CVSS, so a neighbour is also a comparable one.
  const around = (pool: Entry[]) => {
    const i = pool.findIndex((e) => e.id === entry.id);
    return i < 0 ? pool : pool.slice(i + 1).concat(pool.slice(0, i));
  };
  take(around(component.get(entry.component) ?? []));
  take(around(layer.get(entry.layer) ?? []));
  return picked;
}
