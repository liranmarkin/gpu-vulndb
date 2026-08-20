import { ImageResponse } from "next/og";
import { getAllEntries } from "@/lib/entries";
import { Mark, OG_BG, Wordmark, ogFonts } from "@/lib/og";

export const alt = "The Open GPU Vulnerability Database";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OGImage() {
  const entries = getAllEntries();
  const exploited = entries.filter((e) => e.kev).length;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          background: OG_BG,
          padding: 72,
          position: "relative",
        }}
      >
        {/* the big defect map, catching light on the right */}
        <div
          style={{
            position: "absolute",
            right: 72,
            top: 155,
            display: "flex",
            transform: "rotate(8deg)",
          }}
        >
          <Mark size={320} glow />
        </div>

        <div style={{ display: "flex", flexDirection: "column", width: 760 }}>
          <Wordmark markSize={46} fontSize={27} />

          <div style={{ display: "flex", flex: 1 }} />

          <div
            style={{
              fontFamily: "Bricolage Grotesque",
              fontSize: 72,
              lineHeight: 1.04,
              letterSpacing: "-0.02em",
              color: "#ffffff",
              display: "flex",
            }}
          >
            The Open GPU Vulnerability Database
          </div>

          <div
            style={{
              marginTop: 28,
              fontFamily: "Instrument Sans",
              fontSize: 27,
              lineHeight: 1.4,
              color: "rgba(255,255,255,0.72)",
              display: "flex",
              width: 680,
            }}
          >
            An open project to list all known vulnerabilities in the stack GPU datacenters run on.
          </div>

          <div
            style={{
              marginTop: 36,
              fontFamily: "Spline Sans Mono",
              fontSize: 21,
              color: "#c3b2f2",
              display: "flex",
              gap: 36,
            }}
          >
            <span>{entries.length.toLocaleString("en-US")} entries</span>
            <span>{exploited} known exploited</span>
            <span>gpuvulndb.org</span>
          </div>
        </div>
      </div>
    ),
    { ...size, fonts: await ogFonts() },
  );
}
