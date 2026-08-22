import type { MetadataRoute } from "next";
import { getAllEntries } from "@/lib/entries";
import { LAYERS } from "@/lib/schema";

export const dynamic = "force-static";

const SITE = "https://gpuvulndb.org";

/** Every URL carries a lastmod: it is the only recrawl signal Google still honours. */
export default function sitemap(): MetadataRoute.Sitemap {
  const entries = getAllEntries();
  const changed = (id?: string) => entries.filter((e) => !id || e.layer === id).map(touched);
  const newest = (dates: (string | undefined)[]) =>
    dates.filter(Boolean).sort().at(-1) as string | undefined;

  return [
    {
      url: `${SITE}/`,
      lastModified: newest(changed()),
      changeFrequency: "daily",
      priority: 1,
    },
    ...LAYERS.map((l) => ({
      url: `${SITE}/layer/${l.id}`,
      lastModified: newest(changed(l.id)),
      changeFrequency: "daily" as const,
      priority: 0.8,
    })),
    ...entries.map((e) => ({
      url: `${SITE}/vuln/${e.id}`,
      lastModified: touched(e),
      changeFrequency: "monthly" as const,
      priority: e.kev || e.severity === "critical" ? 0.7 : 0.5,
    })),
  ];
}

/** When this page last had something new on it, not when the CVE was disclosed. */
function touched(e: { updated?: string; published?: string }): string | undefined {
  return e.updated ?? e.published;
}
