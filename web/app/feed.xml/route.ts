import { getAllEntries } from "@/lib/entries";
import type { Entry } from "@/lib/schema";

export const dynamic = "force-static";

const SITE = "https://gpuvulndb.org";
const SIZE = 50;

function esc(s: string) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** RFC 822, which is what RSS 2.0 wants. Dates here are days, so noon UTC avoids tz drift. */
function rfc822(iso?: string) {
  if (!iso) return "";
  const d = new Date(`${iso}T12:00:00Z`);
  return isNaN(d.getTime()) ? "" : d.toUTCString();
}

/** Newest first by when the entry landed here - the feed is "what the database just learned". */
function added(e: Entry) {
  return e.updated ?? e.published ?? e.year;
}

export function GET() {
  const entries = getAllEntries();
  const recent = [...entries]
    .sort(
      (a, b) =>
        added(b).localeCompare(added(a)) ||
        (b.published ?? b.year).localeCompare(a.published ?? a.year) ||
        (b.cvss_score ?? -1) - (a.cvss_score ?? -1),
    )
    .slice(0, SIZE);

  const items = recent
    .map((e) => {
      const url = `${SITE}/vuln/${e.id}`;
      const date = rfc822(e.updated ?? e.published);
      const sev = e.cvss_score != null ? `CVSS ${e.cvss_score.toFixed(1)}` : e.severity;
      return (
        `<item><title>${esc(`${e.cve ?? e.id} - ${e.title}`)}</title>` +
        `<link>${url}</link><guid isPermaLink="true">${url}</guid>` +
        (date ? `<pubDate>${date}</pubDate>` : "") +
        `<description>${esc(`${sev}${e.kev ? ", known exploited" : ""}. ${e.impact || e.title}`)}</description>` +
        `<category>${esc(e.layer_name)}</category>` +
        `<category>${esc(e.component)}</category></item>`
      );
    })
    .join("");

  const built = rfc822(recent[0] ? added(recent[0]) : undefined);
  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>` +
    `<title>GPU Vulnerability Database</title><link>${SITE}/</link>` +
    `<atom:link href="${SITE}/feed.xml" rel="self" type="application/rss+xml"/>` +
    `<description>Vulnerabilities in the stack that GPU infrastructure runs on. ` +
    `The ${SIZE} entries most recently added or revised.</description>` +
    `<language>en</language>` +
    (built ? `<lastBuildDate>${built}</lastBuildDate>` : "") +
    `<ttl>360</ttl>` +
    `${items}</channel></rss>`;

  return new Response(xml, { headers: { "Content-Type": "application/rss+xml; charset=utf-8" } });
}
