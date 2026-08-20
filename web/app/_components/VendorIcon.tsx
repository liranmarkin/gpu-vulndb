import { vendorFor } from "@/lib/vendors";

/** Brand icon for the component's vendor, or a monogram when there is none. */
export default function VendorIcon({ component, size = 38 }: { component: string; size?: number }) {
  const v = vendorFor(component);
  return (
    <span
      className="flex shrink-0 items-center justify-center rounded-[10px] border border-line bg-card"
      style={{ width: size, height: size }}
      title={v.name}
    >
      {v.icon ? (
        <svg viewBox="0 0 24 24" width={size * 0.55} height={size * 0.55} aria-hidden>
          <path d={v.icon.path} fill={`#${v.icon.hex}`} />
        </svg>
      ) : (
        <span
          className="font-display font-bold text-muted"
          style={{ fontSize: size * 0.37 }}
          aria-hidden
        >
          {v.name[0]?.toUpperCase()}
        </span>
      )}
    </span>
  );
}
