import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import VendorIcon, { VendorIconDefs } from "@/app/_components/VendorIcon";
import { getAllEntries } from "@/lib/entries";
import type { IndexEntry } from "@/lib/schema";
import { LAYERS, SEVERITY_LABEL, fmtDate, toIndex } from "@/lib/schema";

export const dynamicParams = false;

/** Search-facing copy per layer. Factual and short; the numbers come from the data. */
const HUB: Record<string, { title: string; blurb: string }> = {
  "ai-serving": {
    title: "AI/ML framework and model serving vulnerabilities",
    blurb:
      "CVEs and advisories in inference servers, training frameworks, and model formats: Triton, vLLM, TorchServe, Ray, MLflow, Jupyter, and the rest of the tenant-facing AI layer. On shared GPU infrastructure these are the bugs a tenant can reach first.",
  },
  "container-orchestration": {
    title: "Container and Kubernetes vulnerabilities for GPU clusters",
    blurb:
      "Container escapes, Kubernetes privilege escalation, and scheduler and service mesh flaws: Docker, containerd, runc, kubelet, Argo, Istio, and the isolation boundary every multi-tenant GPU cluster depends on.",
  },
  "control-plane": {
    title: "Control plane, storage and DevOps vulnerabilities",
    blurb:
      "Cluster management, storage systems, CI/CD, and observability tooling: GitLab, Harbor, Grafana, MinIO, Ceph, and the operator-facing services that hold the keys to a GPU fleet.",
  },
  "kernel-hypervisor": {
    title: "Linux kernel and hypervisor vulnerabilities for GPU hosts",
    blurb:
      "Host kernel, userspace, virtualization, and CPU microcode flaws that break the line between tenant and host: KVM, Xen, QEMU, VMware, and the kernel every GPU node boots.",
  },
  "gpu-stack": {
    title: "NVIDIA and GPU stack vulnerabilities",
    blurb:
      "GPU driver, firmware, CUDA, Container Toolkit, vGPU, and accelerator software CVEs, including NVIDIAScape and the rest of the escapes specific to shared GPU hardware. The layer no other vulnerability database treats as a first-class target.",
  },
  "firmware-bmc-fabric": {
    title: "BMC, firmware and network fabric vulnerabilities",
    blurb:
      "BMC/IPMI/Redfish, BIOS/UEFI, NVLink, InfiniBand, DPU, PDU, and cooling-plant flaws: the management plane under every GPU datacenter. Reboots the slowest, patched the least, and reachable more often than anyone plans for.",
  },
};

export function generateStaticParams() {
  return LAYERS.map((l) => ({ id: l.id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const hub = HUB[id];
  const layer = LAYERS.find((l) => l.id === id);
  if (!hub || !layer) return {};
  return {
    title: hub.title,
    description: hub.blurb.slice(0, 160),
    alternates: { canonical: `/layer/${id}` },
    openGraph: { title: hub.title, description: hub.blurb, url: `/layer/${id}` },
  };
}

export default async function LayerPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const hub = HUB[id];
  const layer = LAYERS.find((l) => l.id === id);
  if (!hub || !layer) notFound();

  const entries = getAllEntries()
    .filter((e) => e.layer === id)
    .map(toIndex)
    .sort(
      (a, b) =>
        (b.published ?? b.year).localeCompare(a.published ?? a.year) ||
        (b.cvss_score ?? -1) - (a.cvss_score ?? -1),
    );
  const critical = entries.filter((e) => e.severity === "critical").length;
  const exploited = entries.filter((e) => e.kev).length;

  const byYear = new Map<string, IndexEntry[]>();
  for (const e of entries) {
    const y = e.year || "Undated";
    byYear.set(y, [...(byYear.get(y) ?? []), e]);
  }

  const pageUrl = `https://gpuvulndb.org/layer/${id}`;
  const collectionLd = {
    "@context": "https://schema.org",
    "@type": "CollectionPage",
    name: hub.title,
    description: hub.blurb,
    url: pageUrl,
    isPartOf: { "@type": "Dataset", name: "GPU Vulnerability Database", url: "https://gpuvulndb.org/" },
    ...(entries[0]?.published && { dateModified: entries[0].published }),
    mainEntity: {
      "@type": "ItemList",
      numberOfItems: entries.length,
      // The 50 most recent, not all of them: enough to describe the page without
      // shipping a second copy of the listing to every crawler.
      itemListElement: entries.slice(0, 50).map((e, i) => ({
        "@type": "ListItem",
        position: i + 1,
        name: `${e.cve ?? e.id} - ${e.title}`,
        url: `https://gpuvulndb.org/vuln/${e.id}`,
      })),
    },
  };
  const breadcrumbLd = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Database", item: "https://gpuvulndb.org/" },
      { "@type": "ListItem", position: 2, name: layer.name, item: pageUrl },
    ],
  };

  return (
    <main className="mx-auto max-w-[880px] px-[22px]">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(collectionLd) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbLd) }} />
      <VendorIconDefs components={entries.map((e) => e.component)} />
      <p className="mb-5 pt-10 font-mono text-[12px] text-faint">
        <Link href="/" className="text-muted hover:text-ink">Database</Link>
        <span className="mx-1.5 text-line-strong">/</span>
        <span className="text-muted">{layer.name}</span>
      </p>

      <h1 className="mb-4 font-display text-[clamp(26px,3.5vw,38px)] font-bold leading-[1.12] tracking-[-0.015em]">
        {hub.title}
      </h1>
      <p className="mb-5 max-w-[70ch] text-[16px] leading-[1.65] text-muted">{hub.blurb}</p>
      <p className="mb-10 flex flex-wrap gap-x-6 gap-y-2 font-mono text-[13px] text-faint">
        <span><b className="font-semibold text-ink">{entries.length.toLocaleString()}</b> entries</span>
        <span><b className="font-semibold text-ink">{critical}</b> critical</span>
        <span><b className="font-semibold text-ink">{exploited}</b> known exploited</span>
        <Link href={`/?layer=${id}#database`} className="text-brand-ink hover:underline">
          Filter and search this layer
        </Link>
      </p>

      {[...byYear.entries()].map(([year, rows]) => (
        <section key={year} className="mb-10">
          <h2 className="mb-3 border-b border-line pb-2 font-display text-[19px] font-bold text-ink">
            {year}
          </h2>
          <ul className="grid gap-1">
            {rows.map((e) => (
              <li key={e.id}>
                <Link
                  href={`/vuln/${e.id}`}
                  className="group grid grid-cols-[26px_1fr_auto] items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-card"
                >
                  <VendorIcon component={e.component} size={26} sprite />
                  <span className="min-w-0">
                    <span className="block truncate text-[14px] text-ink group-hover:text-brand-ink">
                      {e.title}
                    </span>
                  </span>
                  <span className="flex items-center gap-2.5 font-mono text-[11.5px] text-faint">
                    <span className={`font-semibold capitalize sev-${e.severity}`}>
                      {SEVERITY_LABEL[e.severity]}
                    </span>
                    <span className="hidden tabular-nums sm:inline">
                      {e.published ? fmtDate(e.published) : e.year}
                    </span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </main>
  );
}
