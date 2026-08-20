/**
 * The mark is a wafer defect map: a chip whose die grid has one flawed die.
 * The same geometry is redrawn in app/icon.tsx and the OG images — keep them in sync.
 */
export default function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="chip" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#3b2187" />
          <stop offset="1" stopColor="#1f0f45" />
        </linearGradient>
      </defs>
      {/* pins */}
      {[20, 32, 44].map((c) => (
        <g key={c} fill="#a290e0">
          <rect x={c - 2.5} y={3} width="5" height="9" rx="2.5" />
          <rect x={c - 2.5} y={52} width="5" height="9" rx="2.5" />
          <rect x={3} y={c - 2.5} width="9" height="5" rx="2.5" />
          <rect x={52} y={c - 2.5} width="9" height="5" rx="2.5" />
        </g>
      ))}
      {/* body */}
      <rect x="8" y="8" width="48" height="48" rx="11" fill="url(#chip)" />
      <rect x="8.5" y="8.5" width="47" height="47" rx="10.5" fill="none" stroke="#ffffff" strokeOpacity="0.14" />
      {/* die grid, one defective die */}
      {[18, 28.75, 39.5].map((y) =>
        [18, 28.75, 39.5].map((x) => (
          <rect
            key={`${x}-${y}`}
            x={x}
            y={y}
            width="6.5"
            height="6.5"
            rx="1.8"
            fill={x === 39.5 && y === 28.75 ? "#ff4d3d" : "#ffffff"}
            fillOpacity={x === 39.5 && y === 28.75 ? 1 : 0.3}
          />
        )),
      )}
    </svg>
  );
}
