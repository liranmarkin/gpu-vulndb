import { Analytics } from "@vercel/analytics/next";
import type { Metadata, Viewport } from "next";
import { Bricolage_Grotesque, Instrument_Sans, Spline_Sans_Mono } from "next/font/google";
import Link from "next/link";
import Logo from "./_components/Logo";
import { LAYERS } from "@/lib/schema";
import "./globals.css";

const display = Bricolage_Grotesque({
  subsets: ["latin"],
  weight: ["600", "700", "800"],
  variable: "--font-bricolage",
});
const sans = Instrument_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-instrument",
});
const mono = Spline_Sans_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-spline-mono",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://gpuvulndb.org"),
  title: {
    default: "GPU Vulnerability Database - CVEs across the GPU infrastructure stack",
    template: "%s · GPU VulnDB",
  },
  description:
    "An open project to list all known vulnerabilities in the stack GPU datacenters run on. Free, open source, community maintained.",
  openGraph: {
    title: "GPU Vulnerability Database",
    description:
      "An open project to list all known vulnerabilities in the stack GPU datacenters run on.",
    url: "https://gpuvulndb.org",
    siteName: "GPU Vulnerability Database",
    type: "website",
  },
  twitter: { card: "summary_large_image" },
  alternates: { types: { "application/rss+xml": "/feed.xml" } },
};

export const viewport: Viewport = {
  themeColor: "#1f0f45",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`}>
      <body>
        <header className="sticky top-0 z-50 border-b border-line bg-paper/85 backdrop-blur-md">
          <div className="mx-auto flex h-16 max-w-[1200px] items-center gap-6 px-[22px]">
            <Link href="/" className="flex items-center gap-2.5 text-ink hover:opacity-85">
              <Logo size={28} />
              <span className="font-display text-[17px] font-bold tracking-[-0.01em]">
                GPU VulnDB
              </span>
            </Link>
            <nav className="ml-auto flex items-center gap-5 text-[14px] font-medium text-muted">
              <Link href="/#database" className="hidden hover:text-ink min-[440px]:inline">Database</Link>
              <Link href="/data.json" className="hidden hover:text-ink sm:inline">JSON</Link>
              <Link href="/feed.xml" className="hidden hover:text-ink sm:inline">RSS</Link>
              <a href="https://github.com/liranmarkin/gpu-vulndb" className="hidden hover:text-ink sm:inline">
                GitHub
              </a>
              <a
                href="https://github.com/liranmarkin/gpu-vulndb/blob/main/CONTRIBUTING.md"
                className="rounded-full bg-brand px-4 py-2 text-[13.5px] font-semibold text-white transition hover:bg-brand-deep"
              >
                Contribute
              </a>
            </nav>
          </div>
        </header>

        {children}

        <footer className="mt-20 border-t border-line bg-card py-12 text-[13.5px] text-muted">
          <div className="mx-auto flex max-w-[1200px] flex-col gap-8 px-[22px] sm:flex-row sm:items-start sm:justify-between">
            <div>
              <div className="mb-5 flex items-center gap-2.5">
                <Logo size={24} />
                <span className="font-display text-[15.5px] font-bold text-ink">GPU VulnDB</span>
              </div>
              <nav aria-label="Browse by layer" className="grid gap-1.5 text-[13px]">
                {LAYERS.map((l) => (
                  <Link key={l.id} href={`/layer/${l.id}`} className="text-muted hover:text-brand-ink">
                    {l.name}
                  </Link>
                ))}
              </nav>
            </div>
            <div className="max-w-[64ch]">
              <p className="mb-2.5">
                <strong className="font-semibold text-ink">GPU Vulnerability Database</strong> is an
                open community project. Entries are curated from vendor advisories, NVD and CISA KEV,
                then annotated for operators running GPU fleets. Corrections and additions are welcome{" "}
                <a href="https://github.com/liranmarkin/gpu-vulndb" className="font-medium text-brand-ink hover:underline">
                  on GitHub
                </a>
                .
              </p>
              <p className="text-faint">
                Data is CC BY 4.0, tooling is MIT. Always confirm against your vendor&apos;s advisory
                before acting.
              </p>
            </div>
          </div>
        </footer>
        <Analytics />
      </body>
    </html>
  );
}
