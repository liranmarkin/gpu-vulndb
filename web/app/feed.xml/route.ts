import { getAllEntries } from "@/lib/entries";

export const dynamic = "force-static";

const SITE = "https://gpuvulndb.org";

function esc(s: string) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function GET() {
  const recent = [...getAllEntries()]
    .sort((a, b) => b.year.localeCompare(a.year) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
    .slice(0, 50);

  const items = recent
    .map((e) => {
      const url = `${SITE}/vuln/${e.id}`;
      return (
        `<item><title>${esc(`${e.cve ?? e.id} — ${e.title}`)}</title>` +
        `<link>${url}</link><guid isPermaLink="true">${url}</guid>` +
        `<description>${esc(e.impact || e.title)}</description>` +
        `<category>${esc(e.layer_name)}</category></item>`
      );
    })
    .join("");

  const xml =
    `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>` +
    `<title>GPU Vulnerability Database</title><link>${SITE}/</link>` +
    `<description>Vulnerabilities in the stack that GPU infrastructure runs on.</description>` +
    `${items}</channel></rss>`;

  return new Response(xml, { headers: { "Content-Type": "application/rss+xml; charset=utf-8" } });
}
