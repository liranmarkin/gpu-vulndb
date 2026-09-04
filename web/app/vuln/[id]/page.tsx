import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import VendorIcon from "@/app/_components/VendorIcon";
import { getAllEntryPaths, getRelated, resolveEntry } from "@/lib/entries";
import { PAIN_HINT, SEVERITY_LABEL, fmtDate } from "@/lib/schema";

export const dynamicParams = false;

export function generateStaticParams() {
  // Includes the CVEs folded into consolidated entries, so their pre-merge URLs still build.
  return getAllEntryPaths().map((id) => ({ id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const entry = resolveEntry(decodeURIComponent(id));
  if (!entry) return {};

  const ident = entry.cve ?? entry.id;
  const alias = entry.aliases[0];
  const title = `${ident}${alias ? ` (${alias})` : ""} - ${entry.title}`;
  const sev =
    entry.cvss_score != null
      ? `CVSS ${entry.cvss_score.toFixed(1)} ${SEVERITY_LABEL[entry.severity].toLowerCase()}`
      : SEVERITY_LABEL[entry.severity];
  const description = clip(
    `${sev}${entry.kev ? ", known exploited (CISA KEV)" : ""}. ${entry.impact || entry.title}`,
    158,
  );

  return {
    title,
    description,
    alternates: { canonical: `/vuln/${entry.id}` },
    openGraph: {
      title,
      description,
      url: `/vuln/${entry.id}`,
      type: "article",
      ...(entry.published && { publishedTime: entry.published }),
      ...((entry.updated ?? entry.published) && {
        modifiedTime: entry.updated ?? entry.published,
      }),
    },
  };
}

function clip(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max).replace(/\s+\S*$/, "");
}

export default async function VulnPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const entry = resolveEntry(decodeURIComponent(id));
  if (!entry) notFound();

  const ident = entry.cve ?? entry.id;
  const covered = entry.additional_cves ?? [];
  const score = entry.cvss_score != null ? entry.cvss_score.toFixed(1) : "—";
  const fleet = entry.fleet ?? {};
  const hasFleet = Boolean(fleet.ubiquity || fleet.remediation_pain || fleet.why_fleet_wide);
  const pageUrl = `https://gpuvulndb.org/vuln/${entry.id}`;

  const related = getRelated(entry);

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    headline: entry.title,
    url: pageUrl,
    mainEntityOfPage: pageUrl,
    identifier: [ident, ...(entry.additional_cves ?? [])],
    ...(entry.published && { datePublished: entry.published }),
    ...((entry.updated ?? entry.published) && { dateModified: entry.updated ?? entry.published }),
    description: entry.impact || entry.title,
    keywords: [ident, ...(entry.additional_cves ?? []), ...entry.aliases, entry.component, entry.layer_name].join(", "),
    about: { "@type": "SoftwareApplication", name: entry.component },
    ...(entry.references.length && { citation: entry.references }),
    isPartOf: {
      "@type": "Dataset",
      name: "GPU Vulnerability Database",
      url: "https://gpuvulndb.org/",
    },
    author: { "@type": "Organization", name: "GPU Vulnerability Database", url: "https://gpuvulndb.org" },
    publisher: { "@type": "Organization", name: "GPU Vulnerability Database", url: "https://gpuvulndb.org" },
  };
  const breadcrumbLd = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Database", item: "https://gpuvulndb.org/" },
      { "@type": "ListItem", position: 2, name: entry.layer_name, item: `https://gpuvulndb.org/layer/${entry.layer}` },
      { "@type": "ListItem", position: 3, name: ident, item: pageUrl },
    ],
  };

  return (
    <main className="mx-auto max-w-[1200px] px-[22px]">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbLd) }} />
      <div className="grid items-start gap-10 pt-10 lg:grid-cols-[minmax(0,1fr)_300px] lg:gap-14">
        <article className="min-w-0">
          <p className="mb-5 font-mono text-[12px] text-faint">
            <Link href="/#database" className="text-muted hover:text-ink">Database</Link>
            <span className="mx-1.5 text-line-strong">/</span>
            <Link href={`/layer/${entry.layer}`} className="text-muted hover:text-ink">
              {entry.layer_name}
            </Link>
          </p>

          <div className="mb-5 flex items-start gap-4">
            <VendorIcon component={entry.component} size={46} />
            <h1 className="font-display text-[clamp(26px,3.5vw,38px)] font-bold leading-[1.15] tracking-[-0.015em]">
              {entry.title}
            </h1>
          </div>

          <div className="mb-10 flex flex-wrap gap-2">
            <Tag mono>{ident}</Tag>
            <Tag>{entry.layer_name}</Tag>
            {entry.kev && <Tag tone="kev">Known exploited</Tag>}
            {covered.length > 0 && <Tag mono>+{covered.length} more CVEs</Tag>}
            {entry.aliases.map((a) => <Tag key={a} tone="alias">{a}</Tag>)}
            <Tag>{entry.status}</Tag>
          </div>

          <Field heading="Impact" value={entry.impact} />
          <Field heading="Who can reach it" value={entry.attack_vector} />
          <Field heading="What to do" value={entry.remediation} />

          {covered.length > 0 && (
            <section className="mb-9">
              <h2 className="mb-3 font-mono text-[11px] font-medium uppercase tracking-[0.15em] text-faint">
                Also covers {covered.length} CVE{covered.length > 1 ? "s" : ""}
              </h2>
              <p className="mb-3 text-[15px] leading-relaxed text-muted">
                The vendor assigned a separate id to each affected code path. They share this
                advisory, this score and this fix, so they are one entry here.
              </p>
              <div className="flex flex-wrap gap-2">
                {covered.map((c) => <Tag key={c} mono>{c}</Tag>)}
              </div>
            </section>
          )}


          {hasFleet && (
            <section className="mb-9">
              <h2 className="mb-3 font-mono text-[11px] font-medium uppercase tracking-[0.15em] text-faint">
                Fleet impact
              </h2>
              <div className="rounded-2xl border border-tint-line bg-tint/45 px-6 py-5">
                <Field heading="How widespread" value={fleet.ubiquity} tight />
                <Field heading="Cost to remediate" value={fleet.remediation_pain} tight />
                <Field heading="Why it hits the whole fleet" value={fleet.why_fleet_wide} tight last />
              </div>
            </section>
          )}

          {entry.references.length > 0 && (
            <section className="mb-9">
              <h2 className="mb-3 font-mono text-[11px] font-medium uppercase tracking-[0.15em] text-faint">
                References
              </h2>
              <div className="grid gap-2 [overflow-wrap:anywhere] font-mono text-[13px]">
                {entry.references.map((u) => (
                  <a key={u} href={u} rel="noopener nofollow" target="_blank" className="min-w-0 break-all text-brand-ink hover:underline">
                    {u}
                  </a>
                ))}
              </div>
            </section>
          )}

          {related.length > 0 && (
            <section className="mb-9">
              <h2 className="mb-3 font-mono text-[11px] font-medium uppercase tracking-[0.15em] text-faint">
                Related entries
              </h2>
              {/* Deliberately text-only: the vendor mark is 2 KB of SVG path each, and this
                  block ships on all 4,500 entry pages. */}
              <ul className="grid gap-1">
                {related.map((r) => (
                  <li key={r.id}>
                    <Link
                      href={`/vuln/${r.id}`}
                      className="group grid grid-cols-[1fr_auto] items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-card"
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-[14px] text-ink group-hover:text-brand-ink">
                          {r.title}
                        </span>
                        <span className="block truncate font-mono text-[11.5px] text-faint">
                          {r.cve ?? r.id} · {r.component}
                        </span>
                      </span>
                      <span className={`font-mono text-[11.5px] font-semibold capitalize sev-${r.severity}`}>
                        {SEVERITY_LABEL[r.severity]}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
              <Link
                href={`/layer/${entry.layer}`}
                className="mt-3 inline-block font-mono text-[12.5px] text-brand-ink hover:underline"
              >
                All {entry.layer_name} entries
              </Link>
            </section>
          )}

          <p className="mt-12 rounded-2xl border border-line bg-card px-5 py-4 text-[13.5px] text-muted shadow-[var(--shadow-card)]">
            This entry is <strong className="font-semibold text-ink">{entry.status}</strong>
            {entry.status === "curated"
              ? ": imported from vendor advisories with machine assistance, not yet individually verified."
              : ": verified by a maintainer against primary sources."}{" "}
            Confirm against your vendor&apos;s advisory before acting, and{" "}
            <a
              href="https://github.com/liranmarkin/gpu-vulndb/issues/new?template=correction.yml"
              className="font-medium text-brand-ink hover:underline"
            >
              report anything wrong
            </a>
            .
          </p>
        </article>

        <aside className="overflow-hidden rounded-2xl border border-line bg-card shadow-[var(--shadow-card)] lg:sticky lg:top-22">
          <div className={`border-b px-5 py-5 sev-tile-${entry.severity}`}>
            <p className="mb-1 font-mono text-[10.5px] font-medium uppercase tracking-[0.13em] opacity-80">
              CVSS
            </p>
            <p className="font-mono text-[34px] font-semibold leading-none tabular-nums">
              {score}
              <span className="ml-2.5 text-[13px] uppercase tracking-[0.09em] opacity-85">
                {SEVERITY_LABEL[entry.severity]}
              </span>
            </p>
          </div>
          <dl className="divide-y divide-line">
            <Row label="Identifier"><span className="font-mono">{ident}</span></Row>
            <Row label="Component">{entry.component}</Row>
            <Row label="Layer">{entry.layer_name}</Row>
            {entry.published ? (
              <Row label="Published"><span className="font-mono tabular-nums">{fmtDate(entry.published)}</span></Row>
            ) : entry.year ? (
              <Row label="Year"><span className="font-mono tabular-nums">{entry.year}</span></Row>
            ) : null}
            {entry.updated && entry.updated !== entry.published && (
              <Row label="Updated here">
                <span className="font-mono tabular-nums">{fmtDate(entry.updated)}</span>
              </Row>
            )}
            {fleet.pain_class && (
              <Row label="Remediation cost">
                <span className="font-mono">{fleet.pain_class}</span>
                {PAIN_HINT[fleet.pain_class] && (
                  <span className="mt-1 block text-[12.5px] text-faint">{PAIN_HINT[fleet.pain_class]}</span>
                )}
              </Row>
            )}
            {entry.kev && (
              <Row label="CISA KEV"><span className="font-medium sev-critical">Listed as exploited</span></Row>
            )}
          </dl>
        </aside>
      </div>
    </main>
  );
}

/** Renders the curated prose, turning its backtick spans into real code. */
function Field({
  heading, value, tight, last,
}: { heading: string; value?: string; tight?: boolean; last?: boolean }) {
  if (!value) return null;
  const parts = value.split(/`([^`]+)`/g);
  return (
    <section className={last ? "" : tight ? "mb-4.5" : "mb-9"}>
      <h2 className={`mb-2.5 font-mono font-medium uppercase tracking-[0.15em] text-faint ${tight ? "text-[10.5px]" : "text-[11px]"}`}>
        {heading}
      </h2>
      <p className={`prose-field ${tight ? "text-[14.5px]" : "text-[16px]"} leading-[1.7] text-ink/90`}>
        {parts.map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part))}
      </p>
    </section>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="px-5 py-3.5">
      <dt className="mb-1 font-mono text-[10.5px] uppercase tracking-[0.13em] text-faint">{label}</dt>
      <dd className="text-[14px] text-ink">{children}</dd>
    </div>
  );
}

function Tag({ children, tone, mono }: { children: React.ReactNode; tone?: "kev" | "alias"; mono?: boolean }) {
  const cls =
    tone === "kev"
      ? "border-critical bg-critical text-white"
      : tone === "alias"
        ? "border-tint-line bg-tint text-silicon-800"
        : "border-line bg-card text-muted";
  return (
    <span className={`max-w-full truncate rounded-full border px-2.5 py-0.5 text-[11.5px] font-medium ${mono ? "font-mono" : ""} ${cls}`}>
      {children}
    </span>
  );
}
