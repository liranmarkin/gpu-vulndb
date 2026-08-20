/** Types and constants shared by server and client. Must stay free of Node imports. */

export type Severity = "critical" | "high" | "medium" | "low" | "unscored";

export type Fleet = {
  ubiquity?: string;
  remediation_pain?: string;
  pain_class?: string;
  why_fleet_wide?: string;
};

export type Entry = {
  id: string;
  cve: string | null;
  /** NVD published date, joined from web/data/nvd-dates.json at load. */
  published?: string;
  aliases: string[];
  title: string;
  layer: string;
  layer_name: string;
  component: string;
  year: string;
  cvss_score: number | null;
  severity: Severity;
  kev: boolean;
  impact: string;
  attack_vector: string;
  remediation: string;
  references: string[];
  fleet?: Fleet;
  status: "stub" | "curated" | "reviewed";
  contributor?: string | null;
};

/** What the browse view needs. Kept separate so the client never ships the full prose. */
export type IndexEntry = Pick<
  Entry,
  | "id" | "cve" | "aliases" | "title" | "layer" | "layer_name"
  | "component" | "year" | "cvss_score" | "severity" | "kev" | "published"
>;

/** Ordered top of stack to silicon. The order is the point: it is a rack elevation. */
export const LAYERS = [
  { id: "ai-serving", name: "AI/ML frameworks & serving", depth: "Tenant workload" },
  { id: "container-orchestration", name: "Container, Kubernetes & orchestration", depth: "Scheduling & isolation" },
  { id: "control-plane", name: "Control plane, storage & DevOps", depth: "Operator tooling" },
  { id: "kernel-hypervisor", name: "Kernel, userspace & hypervisor", depth: "Host OS" },
  { id: "gpu-stack", name: "NVIDIA / GPU stack", depth: "Driver & accelerator" },
  { id: "firmware-bmc-fabric", name: "Firmware, BMC & network fabric", depth: "Silicon & management plane" },
] as const;

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unscored"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unscored: "Unscored",
};

/** Plain-language gloss for what a remediation class costs to roll out across a fleet. */
export const PAIN_HINT: Record<string, string> = {
  "hot-patch": "Patchable without interrupting workloads.",
  "daemon-restart": "Needs a service restart on affected nodes.",
  "node-drain": "Needs tenant workloads evicted from each node.",
  "node-reboot": "Needs a full reboot of each affected node.",
  "microcode + reboot": "Needs a microcode update and a reboot.",
  "firmware-flash": "Needs a firmware flash, usually with the node out of service.",
  "physical access": "Needs someone physically at the machine.",
  "unpatchable / mitigate-only": "No vendor fix. Mitigation is the only option.",
};

export function toIndex(e: Entry): IndexEntry {
  return {
    id: e.id,
    cve: e.cve,
    aliases: e.aliases,
    title: e.title,
    layer: e.layer,
    layer_name: e.layer_name,
    component: e.component,
    year: e.year,
    cvss_score: e.cvss_score,
    severity: e.severity,
    kev: e.kev,
    published: e.published,
  };
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "2026-01-14" -> "Jan 14, 2026". Deterministic, so server and client markup agree. */
export function fmtDate(iso: string): string {
  const [y, m, d] = iso.split("-");
  return `${MONTHS[Number(m) - 1]} ${Number(d)}, ${y}`;
}
