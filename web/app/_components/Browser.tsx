"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import type { IndexEntry, Severity } from "@/lib/schema";
import { LAYERS, SEVERITIES } from "@/lib/schema";

const PAGE = 60;
const SHORT: Record<Severity, string> = {
  critical: "Crit", high: "High", medium: "Med", low: "Low", unscored: "n/a",
};
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
  const [sort, setSort] = useState<Sort>("score");
  const [shown, setShown] = useState(PAGE);
  const hydrated = useRef(false);

  // Read filters from the URL once, so a filtered view is a shareable link.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    setQ(p.get("q") ?? "");
    setDebouncedQ(p.get("q") ?? "");
    setLayer(p.get("layer"));
    setYear(p.get("year") ?? "");
    setKev(p.get("kev") === "1");
    setSort((p.get("sort") as Sort) ?? "score");
    const s = p.get("severity");
    if (s) setSev(new Set(s.split(",").filter(Boolean) as Severity[]));
    hydrated.current = true;
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
    if (sort !== "score") p.set("sort", sort);
    if (sev.size) p.set("severity", [...sev].join(","));
    return p.toString();
  }, [debouncedQ, layer, year, kev, sort, sev]);

  useEffect(() => {
    if (!hydrated.current) return;
    window.history.replaceState(null, "", params ? `?${params}#database` : window.location.pathname);
    setShown(PAGE);
  }, [params]);

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
        const hay = `${e.id} ${e.component} ${e.title} ${e.aliases.join(" ")} ${e.layer_name}`.toLowerCase();
        if (!hay.includes(debouncedQ)) return false;
      }
      return true;
    });
    const by: Record<Sort, (a: IndexEntry, b: IndexEntry) => number> = {
      score: (a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1) || a.id.localeCompare(b.id),
      year: (a, b) => b.year.localeCompare(a.year) || (b.cvss_score ?? -1) - (a.cvss_score ?? -1),
      component: (a, b) => a.component.localeCompare(b.component) || (b.cvss_score ?? -1) - (a.cvss_score ?? -1),
    };
    return out.sort(by[sort]);
  }, [entries, layer, sev, kev, year, debouncedQ, sort]);

  const critical = view.filter((e) => e.severity === "critical").length;
  const exploited = view.filter((e) => e.kev).length;
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
    setLayer(null); setYear(""); setSort("score");
  }

  return (
    <>
      {/* ---------- the stack: a rack elevation that is also the primary filter ---------- */}
      <div className="overflow-hidden rounded-lg border border-rail bg-rack shadow-[0_24px_60px_-36px_rgba(0,0,0,1)]">
        <div className="flex items-center justify-between gap-3 border-b border-rail bg-white/[0.012] px-[18px] py-3 font-mono text-[11px] uppercase tracking-[0.13em] text-dimmer">
          <span>The stack, top to bottom</span>
          <span className="tabular-nums">{entries.length.toLocaleString()} entries</span>
        </div>

        {counts.map((l, i) => {
          const active = layer === l.id;
          return (
            <button
              key={l.id}
              onClick={() => setLayer(active ? null : l.id)}
              aria-pressed={active}
              style={{ animationDelay: `${i * 55}ms` }}
              className={`group grid w-full grid-cols-[1fr_58px] items-center gap-4 border-t border-rail px-[18px] py-3.5 text-left transition-colors duration-150 first:border-t-0 motion-safe:animate-[rackIn_.5s_ease-out_backwards] sm:grid-cols-[1fr_190px_58px] ${
                active ? "bg-rack-2 shadow-[inset_3px_0_0_var(--color-link)]" : "hover:bg-rack-2"
              }`}
            >
              <span className="min-w-0">
                <span className="block truncate text-[14.5px] text-ink">{l.name}</span>
                <span className="mt-0.5 block font-mono text-[10.5px] uppercase tracking-[0.1em] text-dimmer">
                  {l.depth}
                </span>
              </span>

              <span
                className="hidden h-2 overflow-hidden rounded-sm bg-rail sm:flex"
                style={{ opacity: 0.42 + 0.58 * (l.total / maxLayer) }}
                aria-hidden
              >
                {l.segments.map((s) => (
                  <i key={s.severity} style={{ width: `${s.pct}%`, background: SEV_VAR[s.severity] }} />
                ))}
              </span>

              <span className="text-right font-mono text-[14.5px] tabular-nums text-dim group-hover:text-ink">
                {l.total}
              </span>
            </button>
          );
        })}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rail px-[18px] py-3 font-mono text-[11.5px] text-dimmer">
          <span className="flex flex-wrap gap-4">
            {SEVERITIES.filter((s) => s !== "unscored").map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5">
                <i className="block h-2 w-2 rounded-sm" style={{ background: SEV_VAR[s] }} />
                {s}
              </span>
            ))}
          </span>
          <span>{layer ? "Selected — click again to clear" : "Select a layer to filter"}</span>
        </div>
      </div>

      <p className="mt-3.5 font-mono text-[11.5px] text-dimmer">
        Serving sits at the top. Firmware sits under everything, and reboots the slowest.
      </p>

      {/* ---------- controls ---------- */}
      <div
        id="database"
        className="sticky top-15 z-40 -mx-[22px] mt-11 scroll-mt-15 border-y border-rail bg-void/95 px-[22px] py-3.5 backdrop-blur-md"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <label className="relative flex min-w-0 flex-[1_1_300px] items-center">
            <svg viewBox="0 0 24 24" aria-hidden className="pointer-events-none absolute left-3 h-3.5 w-3.5 fill-none stroke-dimmer stroke-2">
              <circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" />
            </svg>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              type="search"
              aria-label="Search entries"
              placeholder="Search — try NVIDIAScape, BMC, runc, vLLM"
              className="w-full rounded-lg border border-rail bg-rack py-2.5 pl-8.5 pr-3 font-mono text-[13.5px] text-ink placeholder:text-dimmer focus:border-rail-lit focus:shadow-[0_0_0_3px_rgba(99,165,255,0.13)] focus:outline-none"
            />
          </label>

          {(["critical", "high", "medium"] as Severity[]).map((s) => (
            <button
              key={s}
              onClick={() => toggleSev(s)}
              aria-pressed={sev.has(s)}
              className="rounded-lg border border-rail bg-rack px-3 py-2 font-mono text-[12px] capitalize text-dim transition hover:border-rail-lit hover:text-ink"
              style={sev.has(s) ? { borderColor: SEV_VAR[s], color: SEV_VAR[s] } : undefined}
            >
              {s}
            </button>
          ))}

          <button
            onClick={() => setKev((v) => !v)}
            aria-pressed={kev}
            className="rounded-lg border border-rail bg-rack px-3 py-2 font-mono text-[12px] text-dim transition hover:border-rail-lit hover:text-ink"
            style={kev ? { borderColor: SEV_VAR.critical, color: SEV_VAR.critical } : undefined}
          >
            Exploited
          </button>

          <select
            value={year}
            onChange={(e) => setYear(e.target.value)}
            aria-label="Filter by year"
            className="rounded-lg border border-rail bg-rack px-3 py-2 font-mono text-[12px] text-dim hover:border-rail-lit hover:text-ink"
          >
            <option value="">All years</option>
            {years.map((y) => <option key={y} value={y}>{y}</option>)}
          </select>

          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as Sort)}
            aria-label="Sort order"
            className="rounded-lg border border-rail bg-rack px-3 py-2 font-mono text-[12px] text-dim hover:border-rail-lit hover:text-ink"
          >
            <option value="score">Highest CVSS</option>
            <option value="year">Newest first</option>
            <option value="component">Component A–Z</option>
          </select>

          {filtered && (
            <button onClick={clearAll} className="ml-auto font-mono text-[12px] text-dimmer hover:text-ink hover:underline">
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* ---------- results ---------- */}
      <p className="py-5 font-mono text-[12.5px] text-dimmer">
        {view.length === 0 ? (
          ""
        ) : (
          <>
            Showing <b className="font-medium text-ink">{Math.min(shown, view.length)}</b> of{" "}
            <b className="font-medium text-ink">{view.length.toLocaleString()}</b> entries · {critical} critical ·{" "}
            {exploited} known exploited
          </>
        )}
      </p>

      {view.length === 0 ? (
        <p className="py-16 text-dim">No entries match these filters. Clear a filter to widen the search.</p>
      ) : (
        <div className="grid gap-2.5">
          {view.slice(0, shown).map((e) => <Card key={e.id} entry={e} />)}
        </div>
      )}

      {shown < view.length && (
        <button
          onClick={() => setShown((s) => s + PAGE)}
          className="mt-6.5 w-full rounded-lg border border-rail bg-rack py-3.5 font-mono text-[12.5px] text-dim transition hover:border-rail-lit hover:text-ink"
        >
          Show more ({(view.length - shown).toLocaleString()} remaining)
        </button>
      )}
    </>
  );
}

function Card({ entry: e }: { entry: IndexEntry }) {
  return (
    <Link
      href={`/vuln/${e.id}`}
      className="grid grid-cols-[48px_1fr] items-start gap-3.5 rounded-lg border border-rail bg-rack p-4 transition duration-150 hover:-translate-y-px hover:border-rail-lit hover:bg-rack-2 sm:grid-cols-[58px_1fr] sm:gap-[18px] sm:px-[18px]"
    >
      <span className={`text-right font-mono text-[19px] font-semibold leading-tight tabular-nums sev-${e.severity}`}>
        {e.cvss_score != null ? e.cvss_score.toFixed(1) : "—"}
        <small className="mt-0.5 block text-[9.5px] font-medium uppercase tracking-[0.1em] opacity-70">
          {SHORT[e.severity]}
        </small>
      </span>
      <span className="min-w-0">
        <span className="mb-2 block text-[15px] leading-normal text-ink">{e.title}</span>
        <span className="flex flex-wrap items-center gap-1.5">
          <Tag>{e.cve ?? e.id}</Tag>
          <Tag>{e.layer_name}</Tag>
          {e.kev && <Tag tone="kev">Known exploited</Tag>}
          {e.aliases.slice(0, 2).map((a) => <Tag key={a} tone="alias">{a}</Tag>)}
        </span>
      </span>
    </Link>
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
