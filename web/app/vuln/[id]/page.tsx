import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAllEntries, getEntry } from "@/lib/entries";
import { PAIN_HINT, SEVERITY_LABEL } from "@/lib/schema";

export const dynamicParams = false;

export function generateStaticParams() {
  return getAllEntries().map((e) => ({ id: e.id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const entry = getEntry(decodeURIComponent(id));
  if (!entry) return {};

  const ident = entry.cve ?? entry.id;
  const title = `${ident} — ${entry.component}`;
  const description = (entry.impact || entry.title).slice(0, 180);

  return {
    title,
    description,
    alternates: { canonical: `/vuln/${entry.id}` },
    openGraph: { title, description, url: `/vuln/${entry.id}`, type: "article" },
  };
}

export default async function VulnPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const entry = getEntry(decodeURIComponent(id));
  if (!entry) notFound();

  const ident = entry.cve ?? entry.id;
  const score = entry.cvss_score != null ? entry.cvss_score.toFixed(1) : "—";
  const fleet = entry.fleet ?? {};
  const hasFleet = Boolean(fleet.ubiquity || fleet.remediation_pain || fleet.why_fleet_wide);

  return (
    <main className="mx-auto max-w-[1200px] px-[22px]">
      <div className="grid items-start gap-9 pt-11 lg:grid-cols-[minmax(0,1fr)_296px] lg:gap-13">
        <article>
          <p className="mb-5 font-mono text-[12px] text-dimmer">
            <Link href="/#database" className="text-dim hover:text-ink">Database</Link>
            {" · "}
            <Link href={`/?layer=${entry.layer}#database`} className="text-dim hover:text-ink">
              {entry.layer_name}
            </Link>
          </p>

          <h1 className="mb-4.5 font-display text-[clamp(25px,3.6vw,36px)] font-bold leading-[1.18] tracking-[-0.015em]">
            {entry.title}
          </h1>

          <div className="mb-10 flex flex-wrap gap-2">
            <Tag>{ident}</Tag>
            <Tag>{entry.layer_name}</Tag>
            {entry.kev && <Tag tone="kev">Known exploited</Tag>}
            {entry.aliases.map((a) => <Tag key={a} tone="alias">{a}</Tag>)}
            <Tag>{entry.status}</Tag>
          </div>

          <Field heading="Impact" value={entry.impact} />
          <Field heading="Who can reach it" value={entry.attack_vector} />
          <Field heading="What to do" value={entry.remediation} />

          {hasFleet && (
            <section className="mb-8.5">
              <h2 className="mb-2.5 font-mono text-[11px] font-medium uppercase tracking-[0.15em] text-dimmer">
                Fleet impact
              </h2>
              <div className="rounded-lg border border-rail border-l-[3px] border-l-rail-lit bg-rack px-5.5 py-5">
                <Field heading="How widespread" value={fleet.ubiquity} tight />
                <Field heading="Cost to remediate" value={fleet.remediation_pain} tight />
                <Field heading="Why it hits the whole fleet" value={fleet.why_fleet_wide} tight last />
              </div>
            </section>
          )}

          {entry.references.length > 0 && (
            <section className="mb-8.5">
              <h2 className="mb-2.5 font-mono text-[11px] font-medium uppercase tracking-[0.15em] text-dimmer">
                References
              </h2>
              <div className="grid gap-2 break-words font-mono text-[13px]">
                {entry.references.map((u) => (
                  <a key={u} href={u} rel="noopener nofollow" target="_blank" className="text-link hover:underline">
                    {u}
                  </a>
                ))}
              </div>
            </section>
          )}

          <p className="mt-11 rounded-lg border border-rail bg-rack px-4.5 py-4 text-[13.5px] text-dimmer">
            This entry is <strong className="font-medium text-ink">{entry.status}</strong>.{" "}
            {entry.status === "curated"
              ? "It was imported from vendor advisories with machine assistance and has not been individually verified against primary sources."
              : "A maintainer verified it against primary sources."}{" "}
            Confirm against your vendor&apos;s advisory before acting on it, and{" "}
            <a
              href="https://github.com/liranmarkin/gpu-vulndb/issues/new?template=correction.yml"
              className="text-link hover:underline"
            >
              report anything wrong
            </a>
            .
          </p>
        </article>

        <aside className="grid gap-px overflow-hidden rounded-lg border border-rail bg-rail lg:sticky lg:top-21">
          <Row label="CVSS">
            <span className={`font-mono text-[30px] font-semibold leading-tight tabular-nums sev-${entry.severity}`}>
              {score}{" "}
              <small className="text-[12px] uppercase tracking-[0.09em] opacity-75">
                {SEVERITY_LABEL[entry.severity]}
              </small>
            </span>
          </Row>
          <Row label="Identifier"><span className="font-mono">{ident}</span></Row>
          <Row label="Component">{entry.component}</Row>
          <Row label="Layer">{entry.layer_name}</Row>
          {entry.year && <Row label="Year"><span className="font-mono tabular-nums">{entry.year}</span></Row>}
          {fleet.pain_class && (
            <Row label="Remediation cost">
              <span className="font-mono">{fleet.pain_class}</span>
              {PAIN_HINT[fleet.pain_class] && (
                <span className="mt-1 block text-[12.5px] text-dimmer">{PAIN_HINT[fleet.pain_class]}</span>
              )}
            </Row>
          )}
          {entry.kev && (
            <Row label="CISA KEV"><span className="sev-critical">Listed as exploited</span></Row>
          )}
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
    <section className={last ? "" : tight ? "mb-4" : "mb-8.5"}>
      <h2 className={`mb-2.5 font-mono font-medium uppercase tracking-[0.15em] text-dimmer ${tight ? "text-[10.5px]" : "text-[11px]"}`}>
        {heading}
      </h2>
      <p className={`prose-field ${tight ? "text-[14.5px]" : "text-[16px]"} leading-[1.68]`}>
        {parts.map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part))}
      </p>
    </section>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="bg-rack px-4 py-3.5">
      <dt className="mb-1 font-mono text-[10.5px] uppercase tracking-[0.13em] text-dimmer">{label}</dt>
      <dd className="text-[14px]">{children}</dd>
    </div>
  );
}

function Tag({ children, tone }: { children: React.ReactNode; tone?: "kev" | "alias" }) {
  const cls =
    tone === "kev"
      ? "border-critical/45 bg-critical/[0.08] text-critical"
      : tone === "alias"
        ? "border-rail-lit text-ink"
        : "border-rail bg-rack text-dim";
  return (
    <span className={`whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-[11.5px] ${cls}`}>
      {children}
    </span>
  );
}
