import { ImageResponse } from "next/og";

export const size = { width: 64, height: 64 };
export const contentType = "image/png";

/** The favicon drops the chip pins: at 16px only the die grid and its flaw survive. */
export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: 64,
          height: 64,
          borderRadius: 14,
          background: "linear-gradient(135deg, #3b2187, #1f0f45)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 4,
        }}
      >
        {[0, 1, 2].map((r) => (
          <div key={r} style={{ display: "flex", gap: 4 }}>
            {[0, 1, 2].map((c) => (
              <div
                key={c}
                style={{
                  width: 12,
                  height: 12,
                  borderRadius: 3.5,
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
