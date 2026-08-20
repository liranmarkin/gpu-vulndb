import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://gpuvulndb.org"),
  title: {
    default: "GPU Vulnerability Database",
    template: "%s · GPU VulnDB",
  },
  description:
    "An open database of vulnerabilities in the stack that GPU infrastructure runs on — BMC and GPU firmware through to model serving. Free, open source, community maintained.",
  openGraph: {
    title: "GPU Vulnerability Database",
    description:
      "Vulnerabilities in the stack that GPU infrastructure runs on — BMC and GPU firmware through to model serving.",
    url: "https://gpuvulndb.org",
    siteName: "GPU Vulnerability Database",
    type: "website",
  },
  twitter: { card: "summary_large_image" },
  alternates: { types: { "application/rss+xml": "/feed.xml" } },
};

const FONT_LINK =
  "https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link rel="stylesheet" href={FONT_LINK} />
      </head>
      <body>
        <header className="sticky top-0 z-50 border-b border-rail bg-void/85 backdrop-blur-md">
          <div className="mx-auto flex h-15 max-w-[1200px] items-center gap-5 px-[22px]">
            <Link
              href="/"
              className="font-display text-[15.5px] font-extrabold uppercase tracking-[0.05em] text-ink hover:text-white"
            >
              GPU<span className="text-rail-lit">/</span>VulnDB
            </Link>
            <nav className="ml-auto flex gap-5 font-mono text-[13px] text-dim">
              <Link href="/#database" className="hover:text-ink">Database</Link>
              <Link href="/data.json" className="hover:text-ink">JSON</Link>
              <Link href="/feed.xml" className="hover:text-ink">RSS</Link>
              <a href="https://github.com/liranmarkin/gpu-vulndb" className="hover:text-ink">GitHub</a>
            </nav>
          </div>
        </header>

        {children}

        <footer className="mt-18 border-t border-rail py-10 text-[13.5px] text-dimmer">
          <div className="mx-auto max-w-[1200px] px-[22px]">
            <p className="mb-2.5 max-w-[72ch]">
              <strong className="font-medium text-ink">GPU Vulnerability Database</strong> — an open
              community project. Entries are curated from vendor advisories, NVD and CISA KEV, then
              annotated for operators running GPU fleets. Corrections and additions are welcome{" "}
              <a href="https://github.com/liranmarkin/gpu-vulndb" className="text-link hover:underline">
                on GitHub
              </a>
              .
            </p>
            <p className="max-w-[72ch]">
              Data is licensed CC BY 4.0; tooling is MIT. This database is informational and makes no
              warranty of completeness — always confirm against your vendor&apos;s advisory before acting.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
