import { ImageResponse } from "next/og";
import { getEntry } from "@/lib/entries";
import { OG_BG, OG_SEV, Wordmark, ogFonts } from "@/lib/og";
import { SEVERITY_LABEL, fmtDate } from "@/lib/schema";

export const alt = "GPU Vulnerability Database entry";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function EntryOGImage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const entry = getEntry(decodeURIComponent(id));
  if (!entry) return new Response("Not found", { status: 404 });

  const ident = entry.cve ?? entry.id;
  const sev = OG_SEV[entry.severity] ?? OG_SEV.unscored;
  const score = entry.cvss_score != null ? entry.cvss_score.toFixed(1) : null;
  const title = entry.title.length > 130 ? `${entry.title.slice(0, 127)}…` : entry.title;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: OG_BG,
          padding: 64,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Wordmark markSize={44} fontSize={26} />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 14,
              background: sev.bg,
              color: sev.text,
              borderRadius: 999,
              padding: "12px 28px",
              fontFamily: "Spline Sans Mono",
              fontSize: 26,
            }}
          >
            {score && <span>{score}</span>}
            <span style={{ textTransform: "uppercase", letterSpacing: "0.06em" }}>
              {SEVERITY_LABEL[entry.severity]}
            </span>
            {entry.kev && <span>· exploited</span>}
          </div>
        </div>

        <div style={{ display: "flex", flex: 1 }} />

        <div
          style={{
            fontFamily: "Spline Sans Mono",
            fontSize: 24,
            color: "#c3b2f2",
            display: "flex",
            gap: 22,
          }}
        >
          <span>{ident}</span>
          <span style={{ color: "rgba(255,255,255,0.38)" }}>·</span>
          <span>{entry.layer_name}</span>
          {entry.published && (
            <>
              <span style={{ color: "rgba(255,255,255,0.38)" }}>·</span>
              <span>{fmtDate(entry.published)}</span>
            </>
          )}
        </div>

        <div
          style={{
            marginTop: 20,
            fontFamily: "Bricolage Grotesque",
            fontSize: title.length > 90 ? 44 : 52,
            lineHeight: 1.12,
            letterSpacing: "-0.015em",
            color: "#ffffff",
            display: "flex",
          }}
        >
          {title}
        </div>

        <div
          style={{
            marginTop: 40,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontFamily: "Instrument Sans",
            fontSize: 23,
            color: "rgba(255,255,255,0.62)",
          }}
        >
          <span>{entry.component}</span>
          <span style={{ fontFamily: "Spline Sans Mono", color: "#c3b2f2" }}>gpuvulndb.org</span>
        </div>
      </div>
    ),
    { ...size, fonts: await ogFonts() },
  );
}
