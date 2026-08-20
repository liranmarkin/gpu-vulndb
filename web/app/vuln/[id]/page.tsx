import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import VendorIcon from "@/app/_components/VendorIcon";
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
  const title = `${ident} - ${entry.component}`;
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
      <div className="grid items-start gap-10 pt-10 lg:grid-cols-[minmax(0,1fr)_300px] lg:gap-14">
        <article>
          <p className="mb-5 font-mono text-[12px] text-faint">
            <Link href="/#database" className="text-muted hover:text-ink">Database</Link>
            <span className="mx-1.5 text-line-strong">/</span>
            <Link href={`/?layer=${entry.layer}#database`} className="text-muted hover:text-ink">
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
            {entry.aliases.map((a) => <Tag key={a} tone="alias">{a}</Tag>)}
            <Tag>{entry.status}</Tag>
          </div>

          <Field heading="Impact" value={entry.impact} />
          <Field heading="Who can reach it" value={entry.attack_vector} />
          <Field heading="What to do" value={entry.remediation} />

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
              <div className="grid gap-2 break-words font-mono text-[13px]">
                {entry.references.map((u) => (
                  <a key={u} href={u} rel="noopener nofollow" target="_blank" className="text-brand-ink hover:underline">
                    {u}
                  </a>
                ))}
              </div>
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
            {entry.year && <Row label="Year"><span className="font-mono tabular-nums">{entry.year}</span></Row>}
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
