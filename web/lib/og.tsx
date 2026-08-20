import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** Deep-silicon ground shared by every generated image. */
export const OG_BG =
  "radial-gradient(760px 500px at 82% -10%, rgba(34,211,238,0.16), rgba(34,211,238,0) 62%), " +
  "radial-gradient(680px 520px at 8% 110%, rgba(232,121,249,0.14), rgba(232,121,249,0) 60%), " +
  "linear-gradient(150deg, #2b1663 0%, #1f0f45 46%, #150a2e 100%)";

/** Severity colours tuned for the dark OG ground, not the light site. */
export const OG_SEV: Record<string, { bg: string; text: string }> = {
  critical: { bg: "#ff5a48", text: "#2b0703" },
  high: { bg: "#ff9440", text: "#2b1203" },
  medium: { bg: "#ffc83d", text: "#2b1e03" },
  low: { bg: "#6aa8ff", text: "#04122b" },
  unscored: { bg: "#9691a6", text: "#171522" },
};

export async function ogFonts() {
  const dir = join(process.cwd(), "assets", "fonts");
  const [display, sans, mono] = await Promise.all([
    readFile(join(dir, "BricolageGrotesque-ExtraBold.ttf")),
    readFile(join(dir, "InstrumentSans-Medium.ttf")),
    readFile(join(dir, "SplineSansMono-SemiBold.ttf")),
  ]);
  return [
    { name: "Bricolage Grotesque", data: display, weight: 800 as const, style: "normal" as const },
    { name: "Instrument Sans", data: sans, weight: 500 as const, style: "normal" as const },
    { name: "Spline Sans Mono", data: mono, weight: 600 as const, style: "normal" as const },
  ];
}

/** The wafer defect-map mark, drawn with flexbox so Satori can rasterise it. */
export function Mark({ size, glow = false }: { size: number; glow?: boolean }) {
  const cell = size * 0.19;
  const gap = size * 0.062;
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: size * 0.22,
        background: "linear-gradient(135deg, #3b2187, #1f0f45)",
        border: "1px solid rgba(255,255,255,0.16)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap,
      }}
    >
      {[0, 1, 2].map((r) => (
        <div key={r} style={{ display: "flex", gap }}>
          {[0, 1, 2].map((c) => {
            const defect = r === 1 && c === 2;
            return (
              <div
                key={c}
                style={{
                  width: cell,
                  height: cell,
                  borderRadius: cell * 0.28,
                  background: defect ? "#ff4d3d" : "rgba(255,255,255,0.22)",
                  boxShadow: defect && glow ? `0 0 ${size * 0.18}px rgba(255,77,61,0.8)` : "none",
                }}
              />
            );
          })}
        </div>
      ))}
    </div>
  );
}

export function Wordmark({ markSize = 44, fontSize = 26 }: { markSize?: number; fontSize?: number }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: markSize * 0.32 }}>
      <Mark size={markSize} />
      <span
        style={{
          fontFamily: "Bricolage Grotesque",
          fontSize,
          color: "#ffffff",
          letterSpacing: "-0.01em",
        }}
      >
        GPU VulnDB
      </span>
    </div>
  );
}
