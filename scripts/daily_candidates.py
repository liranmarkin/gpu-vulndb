"""Pull the last few days of CVE activity from NVD and keep only what might belong here.

This is the deterministic half of the daily update: it fetches, filters on vocabulary,
and drops anything the corpus already has. It deliberately errs toward recall - the
judgement call about whether something really affects GPU infrastructure is made
downstream, by a model reading the full record, not by this regex.

    python3 scripts/daily_candidates.py --days 3
    python3 scripts/daily_candidates.py --days 3 --out research/candidates-2026-08-20.json

NVD_API_KEY is honoured if set (50 requests/30s instead of 5), but is not required.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
RESEARCH = ROOT / "research"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PAGE = 2000

# Consumer and automotive NVIDIA products. Same list ingest.py rejects on, applied earlier
# so these never reach the model at all.
OUT_OF_SCOPE = re.compile(
    r"geforce experience|geforce now|nvidia control panel|nvidia app\b|shield tv|shield tablet|"
    r"nvidia broadcast|rtx (?:voice|remix|experience)|omniverse launcher|studio driver|"
    r"jetson nano|nintendo|drive (?:px|agx|hyperion)|automotive|tegra (?:x1|k1)",
    re.I,
)

# High-signal names. Matched against description, vendor and product together - every one of
# these is specific enough that a hit is worth a look even in prose.
IN_SCOPE = re.compile(
    r"\bnvidia\b|\bcuda\b|cudnn|\bnccl\b|\bdcgm\b|nvswitch|nvlink|\bvgpu\b|\bnvml\b|"
    r"triton inference|tensorrt|\bnemo\b|gpu operator|container toolkit|libnvidia|nvflash|"
    r"\bdgx\b|\bhgx\b|\bmig\b|fabric manager|base command|nvidia ai enterprise|"
    r"amdgpu|\brocm\b|instinct|\bmi\d{3}x?\b|\bgaudi\b|habana|intel gpu|level zero|"
    r"mellanox|connectx|bluefield|\bdpu\b|infiniband|\brdma\b|\broce\b|opensm|\bufm\b|"
    r"\bmlx5\b|\bmlx4\b|\bnvme-?of\b|nvme over fabric|\bsmc-r\b|"
    # firmware / platform / management plane
    r"\bbmc\b|\bipmi\b|redfish|\bidrac\b|\bilo\b|xclarity|\bxcc\b|megarac|aspeed|openbmc|"
    r"\bbios\b|\buefi\b|aptio|insyde|phoenix ?bios|coreboot|\bedk2?\b|tianocore|secure boot|"
    r"boot guard|\btpm\b|\bspdm\b|microcode|\bpsp\b|\bcsme\b|sev-snp|"
    # bare "firmware" matches every consumer router advisory, so it has to be qualified
    r"(?:bmc|bios|uefi|system|platform|server|baseboard|nic|gpu|ssd|nvme|drive|adapter|"
    r"controller|switch|power systems) firmware\b|firmware (?:flash|image|update)\b|"
    r"\btdx\b|\bsgx\b|\bcxl\b|\biommu\b|\bvfio\b|\bsr-iov\b|\bbaseboard\b|"
    r"supermicro|poweredge|proliant|thinksystem|asrock rack|gigabyte server|quanta|wiwynn|"
    r"\bpdu\b|\bups\b|\bdcim\b|liquid cooling|\bcdu\b|"
    # fabric / NICs / switches
    r"arista|\beos\b software|nx-os|\bjunos\b|sonic-?os|cumulus|smartfabric|\bos10\b|"
    r"broadcom|marvell|netxtreme|\bbnxt\b|\bi40e\b|\bixgbe\b|\bice driver\b|intel ethernet|"
    # container / orchestration
    r"kubernetes|kubelet|kube-?apiserver|containerd|\brunc\b|cri-o|podman|\bdocker\b|"
    r"buildkit|\bhelm\b|argo ?cd|\bcilium\b|\bistio\b|\benvoy\b|calico|\betcd\b|"
    r"harbor|crossplane|flux ?cd|kubeedge|kyverno|opa gatekeeper|"
    # AI serving / frameworks
    r"\bvllm\b|pytorch|tensorflow|\bkeras\b|\bjax\b|\bonnx\b|bentoml|\bray\b|mlflow|"
    r"jupyter|transformers|hugging ?face|langchain|\bollama\b|llama\.cpp|sglang|"
    r"text-generation-inference|deepspeed|megatron|safetensors|gguf|"
    # control plane, schedulers, storage
    r"\bslurm\b|\blustre\b|beegfs|\bceph\b|\bweka\b|vast data|prometheus|grafana|terraform|"
    r"ansible|gitlab|jenkins|hashicorp vault|openmanage|oneview|xclarity administrator|"
    r"intersight|htcondor|\bmunge\b|pbs ?pro|openpbs|grid engine|\blsf\b|volcano|kueue|"
    r"run:?ai|determined ai|skypilot|flyte|airflow|glusterfs|\bminio\b|openzfs|\bzfs\b|"
    r"\bnfsd?\b|sunrpc|autofs|globus|netapp|\bontap\b|pure storage|qumulo|panasas|quobyte|"
    r"spectrum scale|\bgpfs\b|\bs3 api\b|\bradosgw?\b|"
    # kernel / hypervisor substrate
    r"linux kernel|\bkvm\b|\bqemu\b|\bxen\b|vmware|\besxi\b|vcenter|firecracker|libvirt|"
    r"proxmox|nutanix|\bsystemd\b|\bglibc\b|openssh|openssl|\bsudo\b|\bpolkit\b|"
    r"\bio_uring\b|\bebpf\b|\bcgroup",
    re.I,
)

# Linux kernel CVEs arrive in batches of dozens a day and most touch hardware no datacenter
# owns. Matched against the subsystem prefix only, never the body: the subsystems below are
# the ones a GPU node's isolation, fabric, storage and platform actually rest on.
KERNEL_SUBSYS = re.compile(
    r"^(?:drm|amdgpu|radeon|nouveau|i915|xe|accel|habanalabs|iommu|iommufd|vfio|pci|cxl|"
    r"nvme|nvmet|nvme-\w+|scsi|megaraid|mpt3sas|target|"
    r"rdma|ib|infiniband|srp|iser|isert|rxe|siw|mlx[45]|mlxsw|net/mlx|net/smc|smc|net/rds|"
    r"rds|bnxt|i40e|ixgbe|ice|mana|efa|irdma|hns|qedr|bnxt_re|"
    r"kvm|xen|virtio|vhost|vdpa|iomap|"
    r"cgroup|cgroup\w*|io_uring|bpf|seccomp|overlayfs|fuse|nfs|nfsd|sunrpc|ceph|libceph|"
    r"mm|slab|slub|hugetlb|dmaengine|dma|dma-buf|udmabuf|"
    r"acpi|efi|efivarfs|firmware|tpm|tpm2|hwmon|ipmi|ipmb|edac|mei|ntb|pmdomain|"
    r"crypto|keys|integrity|ima|sched|sched_ext|perf|x86|x86/\w+|arm64|powerpc|"
    r"platform/x86|thermal|soundwire)\b",
    re.I,
)

# Distro vendors list an umbrella product against every library they ship, so a random
# JavaScript CVE arrives tagged "Red Hat Ansible Automation Platform 2.6". Product names are
# therefore only trusted for hardware and platform vendors, which nothing gets tagged with
# by accident. Everything else has to earn its place in the description.
STRONG_PRODUCT = re.compile(
    r"nvidia|mellanox|connectx|bluefield|\bcuda\b|\bdgx\b|\bhgx\b|amd instinct|\brocm\b|"
    r"gaudi|habana|supermicro|poweredge|proliant|thinksystem|\bidrac\b|integrated lights-out|"
    r"\bilo\b|xclarity|megarac|aspeed|openbmc|\bbmc\b|\bipmi\b|redfish|infiniband|"
    r"arista|nx-os|\bjunos\b|cumulus|smartfabric|openmanage|oneview|intersight|"
    r"power systems firmware|\bufm\b|nvswitch|nvlink",
    re.I,
)

KERNEL_HINT = re.compile(r"in the linux kernel|linux kernel", re.I)

# Kernel CVE descriptions open with the maintainer's subject line - "drm/amdgpu/vce: fix
# integer overflow". That prefix names the subsystem far more reliably than anything else in
# the text, so the kernel gate reads it rather than scanning the whole description, where a
# word like "firmware" in a Bluetooth fix would otherwise look like a match.
KERNEL_SUBJECT = re.compile(
    r"following vulnerability has been resolved:\s*(.+)", re.I | re.S)


def kernel_subsystem(desc: str) -> str:
    m = KERNEL_SUBJECT.search(desc)
    subject = (m.group(1) if m else desc).strip().splitlines()[0] if desc.strip() else ""
    # "scsi: libiscsi_tcp: Bound ..." -> "scsi: libiscsi_tcp"; keep at most two segments.
    return ":".join(subject.split(":")[:2])


def http_json(url: str, timeout: int = 120, tries: int = 5, headers: dict | None = None):
    """NVD rate-limits aggressively and 503s under load; a bare urlopen is not enough."""
    last = None
    for attempt in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": "gpu-vulndb-daily/1.0",
                                                   **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            wait = min(60, 6 * 2**attempt)
            print(f"  {type(e).__name__}: {e} — retrying in {wait}s", file=sys.stderr, flush=True)
            time.sleep(wait)
    raise SystemExit(f"NVD request failed after {tries} attempts: {last}")


def fetch_window(start: datetime, end: datetime, api_key: str | None) -> list[dict]:
    """Every CVE whose record changed in the window.

    lastModified is used rather than published on purpose: it is a superset (a newly
    published CVE is also newly modified) and it also catches older CVEs that only just
    received a score, a CPE list, or a vendor advisory - which is often the first moment
    one of these becomes recognisable as in scope.
    """
    headers = {"apiKey": api_key} if api_key else {}
    pause = 1.0 if api_key else 6.5
    out: list[dict] = []
    index = 0
    while True:
        params = urllib.parse.urlencode({
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": PAGE,
            "startIndex": index,
        })
        print(f"  NVD startIndex={index} ...", flush=True)
        data = http_json(f"{NVD_API}?{params}", headers=headers)
        batch = data.get("vulnerabilities", [])
        out.extend(batch)
        total = data.get("totalResults", 0)
        index += len(batch)
        if not batch or index >= total:
            print(f"  fetched {len(out)} of {total}", flush=True)
            return out
        time.sleep(pause)


def fetch_kev() -> dict[str, dict]:
    try:
        feed = http_json(KEV_FEED, tries=2)
    except SystemExit:
        print("  KEV feed unavailable — continuing without it", file=sys.stderr)
        return {}
    return {v["cveID"]: v for v in feed.get("vulnerabilities", []) if v.get("cveID")}


def corpus_cves() -> set[str]:
    return {e["cve"] for p in ENTRIES.rglob("*.json")
            if (e := json.loads(p.read_text())).get("cve")}


def best_metric(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Prefer CVSS 4.0, then 3.1/3.0, and the CNA's own vector over NIST's secondary one."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        candidates = metrics.get(key) or []
        for wanted in ("Primary", "Secondary"):
            for m in candidates:
                if m.get("type") == wanted:
                    d = m.get("cvssData", {})
                    return d.get("baseScore"), d.get("vectorString"), m.get("source")
    return None, None, None


def surface(item: dict) -> tuple[str, list[str]]:
    """The text the filters read: description plus every vendor and product name."""
    cve = item.get("cve", {})
    desc = " ".join(d.get("value", "") for d in cve.get("descriptions", [])
                    if d.get("lang") == "en")
    names: list[str] = []
    for aff in cve.get("affected", []):
        for a in aff.get("affectedData", []):
            for field in ("vendor", "product"):
                if a.get(field):
                    names.append(a[field])
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 5:
                    names.extend(p.replace("_", " ") for p in parts[3:6] if p not in ("*", "-"))
    return desc, list(dict.fromkeys(names))


def keep(item: dict, kev: dict, fresh_kev: set[str]) -> tuple[bool, str, str]:
    """Returns (keep, reason, the term that matched) - the term is kept for tuning this filter."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if cve.get("vulnStatus") == "Rejected":
        return False, "rejected", ""

    desc, names = surface(item)
    blob = f"{desc} {' '.join(names)}"

    if OUT_OF_SCOPE.search(blob):
        return False, "consumer/automotive product", ""

    # A CVE that was already on KEV and merely had its NVD record touched is not news; one
    # added to KEV this week is, whatever it affects, because it changes what to patch first.
    if cve_id in fresh_kev:
        return True, "new on cisa-kev", "kev"

    if KERNEL_HINT.search(desc) or any("linux_kernel" in n or n.lower() == "linux" for n in names):
        subsys = kernel_subsystem(desc)
        if KERNEL_SUBSYS.match(subsys):
            return True, "kernel subsystem", subsys
        return False, "kernel, unrelated subsystem", subsys

    m = IN_SCOPE.search(desc)
    if m:
        return True, "vocabulary", m.group(0).strip().lower()
    m = STRONG_PRODUCT.search(" ".join(names))
    if m:
        return True, "affected product", m.group(0).strip().lower()
    return False, "no scope signal", ""


def candidate(item: dict, kev: dict, why: str, term: str) -> dict:
    cve = item.get("cve", {})
    cve_id = cve["id"]
    desc, names = surface(item)
    score, vector, source = best_metric(cve.get("metrics", {}))
    refs = [r["url"] for r in cve.get("references", []) if r.get("url")]
    # NVD's own page is always worth carrying; vendor links are what make the entry useful.
    refs = list(dict.fromkeys([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] + refs))[:8]
    cwes = sorted({d["value"] for w in cve.get("weaknesses", [])
                   for d in w.get("descriptions", [])
                   if re.fullmatch(r"CWE-\d+", d.get("value", ""))})
    return {
        "cve": cve_id,
        "matched_on": why,
        "matched_term": term,
        "published": (cve.get("published") or "")[:10],
        "last_modified": (cve.get("lastModified") or "")[:10],
        "vuln_status": cve.get("vulnStatus"),
        "cna": cve.get("sourceIdentifier"),
        "description": desc,
        "products": names[:12],
        "cvss_score": score,
        "cvss_vector": vector,
        "cvss_source": source,
        "cwe": cwes,
        "kev": cve_id in kev,
        "kev_due": kev.get(cve_id, {}).get("dueDate"),
        "kev_ransomware": kev.get(cve_id, {}).get("knownRansomwareCampaignUse"),
        "references": refs,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=float, default=3.0,
                    help="how far back to look; 2 days of coverage plus a day of padding")
    ap.add_argument("--out", type=Path, help="defaults to research/candidates-<today>.json")
    ap.add_argument("--limit", type=int, default=120,
                    help="cap on candidates handed downstream, highest severity first")
    ap.add_argument("--raw-cache", type=Path,
                    help="save the raw NVD response here, or reuse it if it exists "
                         "(for tuning the filter without re-fetching)")
    args = ap.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    print(f"window: {start:%Y-%m-%d %H:%M} .. {end:%Y-%m-%d %H:%M} UTC")

    kev = fetch_kev()
    cutoff = start.strftime("%Y-%m-%d")
    fresh_kev = {c for c, v in kev.items() if (v.get("dateAdded") or "") >= cutoff}
    print(f"KEV catalog: {len(kev)} CVEs, {len(fresh_kev)} added in the window")

    if args.raw_cache and args.raw_cache.exists():
        print(f"reusing raw NVD data from {args.raw_cache}")
        raw = json.loads(args.raw_cache.read_text())
    else:
        raw = fetch_window(start, end, os.environ.get("NVD_API_KEY"))
        if args.raw_cache:
            args.raw_cache.write_text(json.dumps(raw))

    have = corpus_cves()
    print(f"corpus: {len(have)} CVEs already present")

    kept, reasons = [], {}
    for item in raw:
        cve_id = item.get("cve", {}).get("id", "")
        if cve_id in have:
            reasons["already in corpus"] = reasons.get("already in corpus", 0) + 1
            continue
        ok, why, term = keep(item, kev, fresh_kev)
        reasons[why] = reasons.get(why, 0) + 1
        if ok:
            kept.append(candidate(item, kev, why, term))

    # Severity first so that if the cap bites, it drops the least consequential records.
    kept.sort(key=lambda c: (not c["kev"], -(c["cvss_score"] or 0), c["cve"]))
    dropped = max(0, len(kept) - args.limit)
    if dropped:
        print(f"NOTE: capping at {args.limit}; {dropped} lower-severity candidates not passed on")
    kept = kept[:args.limit]

    print("\nfilter:")
    for why, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {n:5d}  {why}")
    print(f"\ncandidates: {len(kept)}")

    out = args.out or RESEARCH / f"candidates-{end:%Y-%m-%d}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "generated_at": end.isoformat(timespec="seconds"),
        "window_days": args.days,
        "dropped_by_cap": dropped,
        "candidates": kept,
    }, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
