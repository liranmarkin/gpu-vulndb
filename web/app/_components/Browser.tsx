"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { IndexEntry, Severity } from "@/lib/schema";
import { LAYERS, SEVERITIES, fmtDate } from "@/lib/schema";
import VendorIcon from "./VendorIcon";

const PAGE = 60;
const SEV_VAR: Record<Severity, string> = {
  critical: "var(--color-critical)", high: "var(--color-high)", medium: "var(--color-medium)",
  low: "var(--color-low)", unscored: "var(--color-unscored)",
};

type Sort = "score" | "year" | "component";

export default function Browser({ entries }: { entries: IndexEntry[] }) {
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [sev, setSev] = useState<Set<Severity>>(new Set());
  const [kev, setKev] = useState(false);
  const [layer, setLayer] = useState<string | null>(null);
  const [year, setYear] = useState("");
  const [sort, setSort] = useState<Sort>("year");
  const [shown, setShown] = useState(PAGE);
  // Must be state, not a ref: the write-back effect below has to be blocked until
  // this read has actually committed a render, or it writes an empty query string
  // over the very URL the read depends on.
  const [ready, setReady] = useState(false);

  // Read filters from the URL once, so a filtered view is a shareable link.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    setQ(p.get("q") ?? "");
    setDebouncedQ(p.get("q") ?? "");
    setLayer(p.get("layer"));
    setYear(p.get("year") ?? "");
    setKev(p.get("kev") === "1");
    setSort((p.get("sort") as Sort) ?? "year");
    setSev(new Set((p.get("severity") ?? "").split(",").filter(Boolean) as Severity[]));
    setReady(true);
  }, []);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim().toLowerCase()), 140);
    return () => clearTimeout(t);
  }, [q]);

  const params = useMemo(() => {
    const p = new URLSearchParams();
    if (debouncedQ) p.set("q", debouncedQ);
    if (layer) p.set("layer", layer);
    if (year) p.set("year", year);
    if (kev) p.set("kev", "1");
    if (sort !== "year") p.set("sort", sort);
    if (sev.size) p.set("severity", [...sev].join(","));
    return p.toString();
  }, [debouncedQ, layer, year, kev, sort, sev]);

  useEffect(() => {
    if (!ready) return;
    window.history.replaceState(null, "", params ? `?${params}#database` : window.location.pathname);
    setShown(PAGE);
  }, [params, ready]);

  const years = useMemo(
    () => [...new Set(entries.map((e) => e.year).filter((y) => /^\d{4}$/.test(y)))].sort().reverse(),
    [entries],
  );

  const counts = useMemo(
    () =>
      LAYERS.map((l) => {
        const rows = entries.filter((e) => e.layer === l.id);
        return {
          ...l,
          total: rows.length,
          segments: SEVERITIES.map((s) => ({
            severity: s,
            pct: rows.length ? (rows.filter((e) => e.severity === s).length / rows.length) * 100 : 0,
          })).filter((s) => s.pct > 0),
        };
      }),
    [entries],
  );
  const maxLayer = Math.max(...counts.map((c) => c.total));

  const view = useMemo(() => {
    const out = entries.filter((e) => {
      if (layer && e.layer !== layer) return false;
      if (sev.size && !sev.has(e.severity)) return false;
      if (kev && !e.kev) return false;
      if (year && e.year !== year) return false;
      if (debouncedQ) {
        const hay = `${e.id} ${(e.additional_cves ?? []).join(" ")} ${e.component} ${e.title} ${e.aliases.join(" ")} ${e.layer_name}`.toLowerCase();
        if (!hay.includes(debouncedQ)) return false;
      }
      return true;
    });
    const by: Record<Sort, (a: IndexEntry, b: IndexEntry) => number> = {
      score: (a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1) || a.id.localeCompare(b.id),
      year: (a, b) =>
        (b.published ?? b.year).localeCompare(a.published ?? a.year) ||
        (b.cvss_score ?? -1) - (a.cvss_score ?? -1),
      component: (a, b) => a.component.localeCompare(b.component) || (b.cvss_score ?? -1) - (a.cvss_score ?? -1),
    };
    return out.sort(by[sort]);
  }, [entries, layer, sev, kev, year, debouncedQ, sort]);

  const critical = view.filter((e) => e.severity === "critical").length;
  const exploited = view.filter((e) => e.kev).length;
  const totalCritical = entries.filter((e) => e.severity === "critical").length;
  const totalExploited = entries.filter((e) => e.kev).length;
  const filtered = params.length > 0;

  function toggleSev(s: Severity) {
    setSev((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  }

  function clearAll() {
    setQ(""); setDebouncedQ(""); setSev(new Set()); setKev(false);
    setLayer(null); setYear(""); setSort("year");
  }

  return (
    <>
      {/* ---------- the wafer hero, with the stack elevation resting on it ---------- */}
      <section className="wafer relative mt-6 overflow-hidden rounded-[28px] px-6 pb-16 pt-10 text-white sm:mt-8 sm:px-12 sm:pb-20 sm:pt-14">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,1fr)_440px] lg:gap-14">
          <div>
            <h1 className="mb-5 font-display text-[clamp(32px,3.9vw,52px)] font-extrabold leading-[1.06] tracking-[-0.02em]">
              The Open GPU Vulnerability Database
            </h1>
            <p className="mb-7 max-w-[46ch] text-[16.5px] leading-[1.6] text-white/80 sm:text-[18px]">
              An open project to list all known vulnerabilities in the stack GPU datacenters run on.
            </p>
            <p className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-[13px] text-lavender">
              <span><b className="font-semibold text-white">{entries.length.toLocaleString()}</b> entries</span>
              <span><b className="font-semibold text-white">{totalCritical}</b> critical</span>
              <span><b className="font-semibold text-white">{totalExploited}</b> known exploited</span>
            </p>
          </div>

          {/* the stack, top to bottom: a rack elevation that is also the primary filter */}
          <div className="overflow-hidden rounded-2xl bg-card shadow-[var(--shadow-float)]">
            <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
              <span className="font-mono text-[10.5px] uppercase tracking-[0.15em] text-faint">
                The stack, top to bottom
              </span>
              <span className="font-mono text-[10.5px] uppercase tracking-[0.15em] text-faint tabular-nums">
                6 layers
              </span>
            </div>

            {counts.map((l, i) => {
              const active = layer === l.id;
              return (
                <button
                  key={l.id}
                  onClick={() => setLayer(active ? null : l.id)}
                  aria-pressed={active}
                  style={{ animationDelay: `${i * 55}ms` }}
                  className={`group grid w-full grid-cols-[24px_1fr_86px_44px] items-center gap-3 border-t border-line px-4 py-2.5 text-left transition-colors duration-150 first:border-t-0 motion-safe:animate-[rackIn_.5s_ease-out_backwards] sm:px-5 ${
                    active ? "bg-tint/60 shadow-[inset_3px_0_0_var(--color-brand)]" : "hover:bg-paper"
                  }`}
                >
                  <DepthGlyph index={i} active={active} />

                  <span className="min-w-0">
                    <span className={`block truncate text-[13.5px] font-medium ${active ? "text-silicon-800" : "text-ink"}`}>
                      {l.name}
                    </span>
                    <span className="mt-px block truncate font-mono text-[9.5px] uppercase tracking-[0.08em] text-faint">
                      {l.depth}
                    </span>
                  </span>

                  <span className="hidden h-1.5 overflow-hidden rounded-full bg-line/70 min-[380px]:flex" aria-hidden>
                    <span className="flex h-full overflow-hidden rounded-full" style={{ width: `${Math.max(10, (l.total / maxLayer) * 100)}%` }}>
                      {l.segments.map((s) => (
                        <i key={s.severity} style={{ width: `${s.pct}%`, background: SEV_VAR[s.severity] }} />
                      ))}
                    </span>
                  </span>

                  <span className={`text-right font-mono text-[13px] tabular-nums ${active ? "text-silicon-800" : "text-muted"} group-hover:text-ink`}>
                    {l.total}
                  </span>
                </button>
              );
            })}

            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line bg-paper/60 px-4 py-2.5 font-mono text-[10px] text-faint sm:px-5">
              <span className="flex flex-wrap gap-3">
                {SEVERITIES.filter((s) => s !== "unscored").map((s) => (
                  <span key={s} className="inline-flex items-center gap-1.5">
                    <i className="block h-1.5 w-1.5 rounded-[2px]" style={{ background: SEV_VAR[s] }} />
                    {s}
                  </span>
                ))}
              </span>
              <span>{layer ? "Selected - click again to clear" : "Select a layer to filter"}</span>
            </div>
          </div>
        </div>
      </section>

      {/* ---------- the search floats out of the wafer, right above what it filters ---------- */}
      <div className="relative z-10 mx-auto -mt-7 max-w-[720px]">
        <label className="relative flex items-center">
          <svg viewBox="0 0 24 24" aria-hidden className="pointer-events-none absolute left-5 h-4.5 w-4.5 fill-none stroke-faint stroke-2">
            <circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" />
          </svg>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            type="search"
            aria-label="Search entries"
            placeholder="Search GPU vulnerabilities..."
            className="h-14 w-full rounded-full border border-line bg-card pl-12.5 pr-6 text-[15px] text-ink shadow-[var(--shadow-float)] placeholder:text-faint focus:border-brand focus:outline-none focus:ring-4 focus:ring-brand/12"
          />
        </label>
      </div>

      {/* ---------- controls ---------- */}
      <div
        id="database"
        className="sticky top-16 z-40 -mx-[22px] mt-8 scroll-mt-16 border-y border-line bg-paper/92 px-[22px] py-3.5 backdrop-blur-md"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          {(["critical", "high", "medium"] as Severity[]).map((s) => (
            <button
              key={s}
              onClick={() => toggleSev(s)}
              aria-pressed={sev.has(s)}
              className={`rounded-full border px-3.5 py-1.5 text-[13px] font-medium capitalize transition ${
                sev.has(s)
                  ? `sev-tile-${s}`
                  : "border-line bg-card text-muted hover:border-line-strong hover:text-ink"
              }`}
            >
              {s}
            </button>
          ))}

          <button
            onClick={() => setKev((v) => !v)}
            aria-pressed={kev}
            className={`rounded-full border px-3.5 py-1.5 text-[13px] font-medium transition ${
              kev ? "border-critical bg-critical text-white" : "border-line bg-card text-muted hover:border-line-strong hover:text-ink"
            }`}
          >
            Exploited
          </button>

          <span aria-hidden className="mx-1 hidden h-5 w-px bg-line-strong sm:block" />

          <select
            value={year}
            onChange={(e) => setYear(e.target.value)}
            aria-label="Filter by year"
            className="rounded-full border border-line bg-card px-3.5 py-1.5 text-[13px] font-medium text-muted hover:border-line-strong hover:text-ink"
          >
            <option value="">All years</option>
            {years.map((y) => <option key={y} value={y}>{y}</option>)}
          </select>

          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as Sort)}
            aria-label="Sort order"
            className="rounded-full border border-line bg-card px-3.5 py-1.5 text-[13px] font-medium text-muted hover:border-line-strong hover:text-ink"
          >
            <option value="year">Newest first</option>
            <option value="score">Highest CVSS</option>
            <option value="component">Component A-Z</option>
          </select>

          {filtered && (
            <button onClick={clearAll} className="ml-auto text-[13px] font-medium text-brand-ink hover:underline">
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* ---------- results ---------- */}
      <p className="py-5 font-mono text-[12.5px] text-faint">
        {view.length === 0 ? (
          ""
        ) : (
          <>
            Showing <b className="font-semibold text-ink">{Math.min(shown, view.length)}</b> of{" "}
            <b className="font-semibold text-ink">{view.length.toLocaleString()}</b> entries · {critical} critical ·{" "}
            {exploited} known exploited
          </>
        )}
      </p>

      {view.length === 0 ? (
        <p className="py-16 text-muted">No entries match these filters. Clear a filter to widen the search.</p>
      ) : (
        <div className="grid gap-3">
          {view.slice(0, shown).map((e) => <Card key={e.id} entry={e} />)}
        </div>
      )}

      {shown < view.length && (
        <button
          onClick={() => setShown((s) => s + PAGE)}
          className="mt-7 w-full rounded-full border border-line bg-card py-3.5 text-[13.5px] font-medium text-muted shadow-[var(--shadow-card)] transition hover:border-line-strong hover:text-ink"
        >
          Show more ({(view.length - shown).toLocaleString()} remaining)
        </button>
      )}
    </>
  );
}

/** Six slabs, top of stack to silicon; the row's own layer is the lit one. */
function DepthGlyph({ index, active }: { index: number; active: boolean }) {
  return (
    <svg width="18" height="20" viewBox="0 0 18 20" aria-hidden className="justify-self-center">
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <rect
          key={i}
          x={i === index ? 0 : 2}
          y={i * 3.3}
          width={i === index ? 18 : 14}
          height="2.2"
          rx="1.1"
          fill={i === index ? (active ? "var(--color-brand)" : "var(--color-silicon-700)") : "var(--color-line-strong)"}
        />
      ))}
    </svg>
  );
}

function Card({ entry: e }: { entry: IndexEntry }) {
  return (
    <Link
      href={`/vuln/${e.id}`}
      className="relative grid grid-cols-[38px_minmax(0,1fr)_auto] items-start gap-3.5 overflow-hidden rounded-2xl border border-line bg-card p-4 pl-5 shadow-[var(--shadow-card)] transition duration-150 hover:-translate-y-px hover:border-line-strong hover:shadow-[var(--shadow-card-hover)] sm:gap-4 sm:p-5 sm:pl-6"
    >
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 w-[3px]"
        style={{ background: SEV_VAR[e.severity] }}
      />
      <VendorIcon component={e.component} size={38} />
      <span className="min-w-0">
        <span className="mb-2 block text-[15.5px] font-medium leading-normal text-ink">{e.title}</span>
        <span className="flex flex-wrap items-center gap-1.5">
          <span
            className={`max-w-full truncate rounded-full border px-2.5 py-0.5 text-[11.5px] font-semibold capitalize sev-tile-${e.severity}`}
          >
            {e.severity}
          </span>
          <Tag mono>{e.cve ?? e.id}</Tag>
          <Tag>{e.layer_name}</Tag>
          {e.kev && <Tag tone="kev">Known exploited</Tag>}
          {e.aliases.slice(0, 2).map((a) => <Tag key={a} tone="alias">{a}</Tag>)}
        </span>
      </span>
      {(e.published || e.year) && (
        <span className="pt-[3px] font-mono text-[12px] tabular-nums text-faint">
          {e.published ? fmtDate(e.published) : e.year}
        </span>
      )}
    </Link>
  );
}

function Tag({ children, tone, mono }: { children: React.ReactNode; tone?: "kev" | "alias"; mono?: boolean }) {
  const cls =
    tone === "kev"
      ? "border-critical bg-critical text-white"
      : tone === "alias"
        ? "border-tint-line bg-tint text-silicon-800"
        : "border-line bg-paper text-muted";
  return (
    <span className={`max-w-full truncate rounded-full border px-2.5 py-0.5 text-[11.5px] font-medium ${mono ? "font-mono" : ""} ${cls}`}>
      {children}
    </span>
  );
}
