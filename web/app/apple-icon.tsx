import { ImageResponse } from "next/og";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

/** iOS applies its own corner mask, so the tile fills the full square. */
export default function AppleIcon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: 180,
          height: 180,
          background: "linear-gradient(135deg, #3b2187, #1f0f45)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 11,
        }}
      >
        {[0, 1, 2].map((r) => (
          <div key={r} style={{ display: "flex", gap: 11 }}>
            {[0, 1, 2].map((c) => (
              <div
                key={c}
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 9,
                  background: r === 1 && c === 2 ? "#ff4d3d" : "rgba(255,255,255,0.26)",
                }}
              />
            ))}
          </div>
        ))}
      </div>
    ),
    size,
  );
}
