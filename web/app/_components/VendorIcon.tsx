import { vendorFor, vendorSlug } from "@/lib/vendors";
import favicons from "@/lib/vendor-favicons.json";

const FAVICONS = new Set(Object.keys(favicons));

/**
 * Brand icon for the component's vendor: a simple-icons mark, a downloaded
 * favicon, or a monogram for named vendors with no usable logo. Components
 * that are specs or generic hardware rather than a vendor get a chip glyph.
 */
export default function VendorIcon({ component, size = 38 }: { component: string; size?: number }) {
  const v = vendorFor(component);
  const slug = vendorSlug(v.name);
  return (
    <span
      className="flex shrink-0 items-center justify-center overflow-hidden rounded-[10px] border border-line bg-card"
      style={{ width: size, height: size }}
      title={v.name}
    >
      {v.icon ? (
        <svg viewBox="0 0 24 24" width={size * 0.55} height={size * 0.55} aria-hidden>
          <path d={v.icon.path} fill={`#${v.icon.hex}`} />
        </svg>
      ) : FAVICONS.has(slug) ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={`/vendors/${slug}.png`}
          alt=""
          width={size * 0.62}
          height={size * 0.62}
          className="rounded-[4px] object-contain"
        />
      ) : v.generic ? (
        <svg viewBox="0 0 24 24" width={size * 0.55} height={size * 0.55} aria-hidden>
          <rect x="6" y="6" width="12" height="12" rx="2.5" fill="none" stroke="var(--color-faint)" strokeWidth="1.6" />
          <rect x="10" y="10" width="4" height="4" rx="1" fill="var(--color-faint)" />
          <g stroke="var(--color-faint)" strokeWidth="1.6" strokeLinecap="round">
            <path d="M9 6V3.5M15 6V3.5M9 20.5V18M15 20.5V18M6 9H3.5M6 15H3.5M20.5 9H18M20.5 15H18" />
          </g>
        </svg>
      ) : (
        <span className="font-display font-bold text-muted" style={{ fontSize: size * 0.37 }} aria-hidden>
          {v.name[0]?.toUpperCase()}
        </span>
      )}
    </span>
  );
}
