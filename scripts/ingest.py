#!/usr/bin/env python3
"""Merge researched vulnerabilities from research/*.json into the entry corpus.

Research files are arrays of loosely-shaped objects. This normalizes them to the
schema, drops anything already in the database, and refuses anything it cannot
make valid rather than writing a broken entry.

    python3 scripts/ingest.py                 # dry run, prints what would change
    python3 scripts/ingest.py --write         # actually write the entries
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
RESEARCH = ROOT / "research"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
VECTOR_RE = re.compile(r"^CVSS:[34]\.\d/")
CWE_RE = re.compile(r"^CWE-\d+$")

PAIN_CLASSES = {
    "hot-patch", "daemon-restart", "node-drain", "node-reboot",
    "microcode + reboot", "firmware-flash", "physical access",
    "unpatchable / mitigate-only", "other",
}

LAYER_NAMES = {
    "gpu-stack": "NVIDIA / GPU stack",
    "firmware-bmc-fabric": "Firmware, BMC & network fabric",
    "container-orchestration": "Container, Kubernetes & orchestration",
    "ai-serving": "AI/ML frameworks & serving",
    "control-plane": "Control plane, storage & DevOps",
    "kernel-hypervisor": "Kernel, userspace & hypervisor",
}

# Consumer and workstation products that ride along in vendor advisory feeds. A GPU cloud does
# not run GeForce Experience, and carrying those entries is what makes a database look like an
# NVD mirror. Matched before anything else, and dropped.
OUT_OF_SCOPE = re.compile(
    r"geforce experience|geforce now|nvidia control panel|nvidia app\b|shield tv|shield tablet|"
    r"nvidia broadcast|rtx (?:voice|remix|experience)|omniverse launcher|studio driver|"
    r"jetson nano|nintendo|drive (?:px|agx|hyperion)|automotive|tegra (?:x1|k1)",
    re.I,
)

# A management controller is firmware even when the vendor name says GPU, so this is checked
# before the GPU rule. "NVIDIA DGX BMC" belongs with the other BMCs, not with the drivers.
MANAGEMENT_PLANE = re.compile(r"\bbmc\b|\bipmi\b|redfish|\bilo\b|idrac|xclarity|megarac|aspeed", re.I)

# Ordered: the first pattern that matches a component wins.
LAYER_RULES: list[tuple[str, str]] = [
    (r"nvidia|cuda|cudnn|nccl|dcgm|vgpu|nvswitch|nvlink|gsp|vbios|nvflash|dgx|hgx|grid|"
     r"mig\b|gpu operator|container toolkit|libnvidia|tensorrt|triton|nemo|amdgpu|rocm|"
     r"instinct|mi\d{3}|gaudi|habana|nvml|fabric manager|leftoverlocals", "gpu-stack"),
    (r"bmc|ipmi|redfish|idrac|ilo\b|xclarity|xcc\b|megarac|aspeed|openbmc|bios|uefi|"
     r"aptio|insyde|phoenix|coreboot|edk|tianocore|secure boot|boot guard|grub|shim|"
     r"tpm|firmware|microcode|psp\b|csme|\bme\b|sev-snp|sev\b|tdx|sgx|"
     r"connectx|bluefield|infiniband|opensm|ufm\b|rdma|roce|nvlink switch|"
     r"switch|eos\b|nx-os|junos|sonic|cumulus|pdu|ups\b|dcim|cooling|"
     r"nvme.*firmware|ssd|opal|raid controller|megaraid|console server|kvm-over-ip",
     "firmware-bmc-fabric"),
    (r"kubernetes|containerd|runc|docker|cri-o|podman|helm|argo|cilium|istio|envoy|"
     r"ingress|calico|kubelet|etcd", "container-orchestration"),
    (r"vllm|pytorch|tensorflow|keras|jax|onnx|bentoml|ray\b|mlflow|jupyter|"
     r"transformers|huggingface|langchain|ollama|llama\.cpp", "ai-serving"),
    (r"kernel|hypervisor|kvm|qemu|xen|vmware|esxi|firecracker|libvirt|systemd|glibc|"
     r"proxmox|nutanix", "kernel-hypervisor"),
    (r"slurm|lustre|beegfs|ceph|weka|vast|prometheus|grafana|terraform|ansible|"
     r"gitlab|jenkins|vault|openmanage|oneview|xclarity administrator|intersight|"
     r"storage|backup", "control-plane"),
]


def infer_layer(component: str, hint: str | None) -> str:
    text = component or ""
    if MANAGEMENT_PLANE.search(text):
        return "firmware-bmc-fabric"
    if hint in LAYER_NAMES:
        return hint
    for pattern, layer in LAYER_RULES:
        if re.search(pattern, text.lower()):
            return layer
    return "firmware-bmc-fabric"


def bucket(score):
    if score is None:
        return "unscored"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unscored"


def truncate_words(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-") + "…"


def make_title(component, impact):
    head = re.split(r"\s*(?:→|->|;)\s*", (impact or "").strip())[0].strip().rstrip(".")
    head = truncate_words(head, 110)
    return f"{component}: {head}" if head else component


def slugify(text, maxlen=32):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:maxlen].strip("-") or "entry"


def content_key(component: str, impact: str) -> tuple[str, str]:
    """Identity for an entry with no CVE.

    A CVE-less design weakness has no external identifier, so re-ingesting the same research
    would otherwise mint a fresh sequential id every run and quietly duplicate it. Component
    plus the head of the impact is stable enough to collapse those.
    """
    return (
        re.sub(r"\W+", "", (component or "").lower()),
        re.sub(r"\W+", "", (impact or "").lower())[:90],
    )


def existing_ids() -> tuple[set[str], set[str], set[tuple[str, str]]]:
    ids, cves, keys = set(), set(), set()
    for path in ENTRIES.rglob("*.json"):
        entry = json.loads(path.read_text())
        ids.add(entry["id"])
        if entry.get("cve"):
            cves.add(entry["cve"])
        else:
            keys.add(content_key(entry.get("component", ""), entry.get("impact", "")))
    return ids, cves, keys


def normalize(raw: dict, source: str, seq: Counter) -> tuple[dict | None, str | None]:
    """Returns (entry, None) or (None, reason-it-was-rejected)."""
    component = (raw.get("component") or "").strip()
    if not component:
        return None, "missing component"
    if OUT_OF_SCOPE.search(component):
        return None, f"{component}: consumer/workstation product, out of scope"

    impact = (raw.get("impact") or "").strip()
    if len(impact) < 3:
        return None, f"{component}: impact too short"

    refs = [u.strip() for u in (raw.get("references") or [])
            if isinstance(u, str) and u.strip().startswith("http")]
    if not refs:
        return None, f"{component}: no usable reference"

    cve = (raw.get("cve") or "").strip() or None
    if cve and not CVE_RE.match(cve):
        return None, f"{component}: malformed cve {cve!r}"

    score = raw.get("cvss_score")
    if isinstance(score, str):
        m = re.search(r"\d+(?:\.\d+)?", score)
        score = float(m.group(0)) if m else None
    if score is not None:
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None
        if score is not None and not 0 <= score <= 10:
            score = None

    year = str(raw.get("year") or "").strip()
    if cve:
        year = cve.split("-")[1]
    if not re.fullmatch(r"\d{4}", year):
        year = ""

    if cve:
        entry_id = cve
    else:
        y = year or "0000"
        seq[y] += 1
        entry_id = f"NCVD-{y}-{seq[y]:03d}-{slugify(component)}"

    layer = infer_layer(component, raw.get("layer_hint"))

    # Structured fields a research batch may supply directly. Preferred over deriving them
    # afterwards: the researcher read the advisory, the extractor only reads prose.
    extra: dict = {}

    vector = (raw.get("cvss_vector") or "").strip()
    if VECTOR_RE.match(vector):
        extra["cvss_vector"] = vector

    cwes = [c.strip() for c in (raw.get("cwe") or []) if isinstance(c, str)]
    cwes = [c for c in cwes if CWE_RE.match(c)]
    if cwes:
        extra["cwe"] = list(dict.fromkeys(cwes))

    pain = (raw.get("pain_class") or "").strip()
    if pain in PAIN_CLASSES:
        extra["fleet"] = {"pain_class": pain}
    elif pain:
        # Silently dropping a bad value would hide a mislabelled batch.
        return None, f"{component}: unknown pain_class {pain!r}"

    return {
        **extra,
        "id": entry_id,
        "cve": cve,
        "aliases": [a.strip() for a in (raw.get("aliases") or []) if isinstance(a, str) and a.strip()],
        "title": make_title(component, impact),
        "layer": layer,
        "layer_name": LAYER_NAMES[layer],
        "component": component,
        "year": year,
        "cvss_score": score,
        "severity": bucket(score),
        "kev": bool(raw.get("kev")),
        "impact": impact,
        "attack_vector": (raw.get("attack_vector") or "").strip(),
        "remediation": (raw.get("remediation") or "").strip(),
        "references": list(dict.fromkeys(refs)),
        "status": "curated",
        "source_batch": source,
    }, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write entries instead of a dry run")
    args = ap.parse_args()

    if not RESEARCH.exists():
        sys.exit("no research/ directory")

    have_ids, have_cves, have_keys = existing_ids()
    seq: Counter = Counter()
    accepted: dict[str, dict] = {}
    rejected: list[str] = []
    dupes = 0
    per_source: Counter = Counter()

    for path in sorted(RESEARCH.glob("*.json")):
        try:
            batch = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            rejected.append(f"{path.name}: invalid JSON ({e})")
            continue
        if not isinstance(batch, list):
            rejected.append(f"{path.name}: expected a JSON array")
            continue

        for raw in batch:
            if not isinstance(raw, dict):
                continue
            entry, reason = normalize(raw, path.stem, seq)
            if reason:
                rejected.append(f"{path.name}: {reason}")
                continue
            assert entry is not None
            if entry["id"] in have_ids or (entry["cve"] and entry["cve"] in have_cves):
                dupes += 1
                continue
            if entry["id"] in accepted:
                dupes += 1
                continue
            if not entry["cve"]:
                ck = content_key(entry["component"], entry["impact"])
                if ck in have_keys:
                    dupes += 1
                    continue
                have_keys.add(ck)
            accepted[entry["id"]] = entry
            per_source[path.stem] += 1

    print(f"research files : {len(list(RESEARCH.glob('*.json')))}")
    print(f"new entries    : {len(accepted)}")
    print(f"already present: {dupes}")
    print(f"rejected       : {len(rejected)}")
    for r in rejected[:15]:
        print(f"   - {r}")
    if len(rejected) > 15:
        print(f"   ... and {len(rejected) - 15} more")

    print("\nby source:")
    for src, n in per_source.most_common():
        print(f"  {n:4d}  {src}")

    print("\nby layer:")
    for layer, n in Counter(e["layer"] for e in accepted.values()).most_common():
        print(f"  {n:4d}  {layer}")

    print("\nby severity:")
    for sev, n in Counter(e["severity"] for e in accepted.values()).most_common():
        print(f"  {n:4d}  {sev}")

    if not args.write:
        print("\ndry run — pass --write to apply")
        return

    for entry in accepted.values():
        year = entry["year"] if re.fullmatch(r"\d{4}", entry["year"]) else "undated"
        out = ENTRIES / year
        out.mkdir(parents=True, exist_ok=True)
        payload = {k: v for k, v in entry.items() if k != "source_batch"}
        (out / f"{entry['id']}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"\nwrote {len(accepted)} entries")


if __name__ == "__main__":
    main()
