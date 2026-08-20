import type { MetadataRoute } from "next";
import { getAllEntries } from "@/lib/entries";
import { LAYERS } from "@/lib/schema";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: "https://gpuvulndb.org/", changeFrequency: "daily", priority: 1 },
    ...LAYERS.map((l) => ({
      url: `https://gpuvulndb.org/layer/${l.id}`,
      changeFrequency: "daily" as const,
      priority: 0.8,
    })),
    ...getAllEntries().map((e) => ({
      url: `https://gpuvulndb.org/vuln/${e.id}`,
      ...(e.published && { lastModified: e.published }),
    })),
  ];
}
