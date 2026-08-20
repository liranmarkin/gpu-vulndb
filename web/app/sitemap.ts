import type { MetadataRoute } from "next";
import { getAllEntries } from "@/lib/entries";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: "https://gpuvulndb.org/", changeFrequency: "daily", priority: 1 },
    ...getAllEntries().map((e) => ({ url: `https://gpuvulndb.org/vuln/${e.id}` })),
  ];
}
