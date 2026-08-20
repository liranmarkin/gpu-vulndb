import type { Metadata } from "next";
import Browser from "./_components/Browser";
import { getAllEntries } from "@/lib/entries";
import { toIndex } from "@/lib/schema";

export const metadata: Metadata = {
  alternates: { canonical: "/" },
};

export default function Home() {
  const entries = getAllEntries().map(toIndex);

  const websiteLd = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: "GPU Vulnerability Database",
    alternateName: "GPU VulnDB",
    url: "https://gpuvulndb.org/",
    potentialAction: {
      "@type": "SearchAction",
      target: { "@type": "EntryPoint", urlTemplate: "https://gpuvulndb.org/?q={search_term_string}" },
      "query-input": "required name=search_term_string",
    },
  };
  const datasetLd = {
    "@context": "https://schema.org",
    "@type": "Dataset",
    name: "GPU Vulnerability Database",
    description:
      "An open database of vulnerabilities in the stack GPU datacenters run on: BMC and GPU firmware, drivers, CUDA, container runtimes, Kubernetes, and model serving. Every entry carries impact, attack vector, and operator remediation.",
    url: "https://gpuvulndb.org/",
    sameAs: "https://github.com/liranmarkin/gpu-vulndb",
    license: "https://creativecommons.org/licenses/by/4.0/",
    isAccessibleForFree: true,
    creator: { "@type": "Organization", name: "GPU Vulnerability Database", url: "https://gpuvulndb.org" },
    keywords: [
      "GPU vulnerabilities", "CVE", "NVIDIA security", "BMC security", "GPU datacenter",
      "Kubernetes security", "AI infrastructure security", "firmware vulnerabilities",
    ],
    temporalCoverage: "2011/2026",
    distribution: [
      {
        "@type": "DataDownload",
        encodingFormat: "application/json",
        contentUrl: "https://gpuvulndb.org/data.json",
      },
    ],
  };

  return (
    <main className="mx-auto max-w-[1200px] px-[22px]">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteLd) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(datasetLd) }} />
      <Browser entries={entries} />
    </main>
  );
}
