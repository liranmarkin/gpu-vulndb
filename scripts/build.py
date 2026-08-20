#!/usr/bin/env python3
"""Build the entry corpus and the site data file from the curated source CSVs."""

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})")
# In the cve column a parenthetical is always the marketing name: CVE-2023-43654 (ShellTorch).
PAREN_RE = re.compile(r"\(([^)]{2,60})\)")
# In the component column only a *quoted* parenthetical is a name; bare ones such as
# "Linux kernel (uvcvideo)" are scope qualifiers and must stay part of the component.
QUOTED_RE = re.compile(r'["“]([^"”]{2,60})["”]')
QUOTED_PAREN_RE = re.compile(r'\s*\(\s*["“][^"”]{2,60}["”]\s*\)')

LAYERS = {
    "NVIDIA / GPU stack": "gpu-stack",
    "Firmware, BMC & network fabric": "firmware-bmc-fabric",
    "Container, Kubernetes & orchestration": "container-orchestration",
    "AI/ML frameworks & serving": "ai-serving",
    "Control plane, storage & DevOps": "control-plane",
    "Kernel, userspace & hypervisor": "kernel-hypervisor",
}

SEVERITY = {
    "Critical (9.0-10.0)": "critical",
    "High (7.0-8.9)": "high",
    "Medium (4.0-6.9)": "medium",
    "Low (0.1-3.9)": "low",
    "Unscored": "unscored",
}


def slugify(text, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen].strip("-") or "entry"


def parse_score(raw):
    if not raw:
        return None
    m = re.search(r"\d+(?:\.\d+)?", raw)
    return float(m.group(0)) if m else None


def split_refs(raw):
    if not raw:
        return []
    return [u.strip() for u in re.split(r"[\s,;]+", raw) if u.strip().startswith("http")]


def clean_component(component):
    """Drop the quoted alias, keeping qualifiers like "(uvcvideo)" that narrow the component."""
    return QUOTED_PAREN_RE.sub("", component).strip() or component


def truncate_words(text, limit):
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return cut + "…"


def make_title(component, impact):
    """Titles are derived, not invented: component plus the curated impact summary.

    Splitting on '.' would break `re.compile` and version strings like 3.11, so
    only explicit clause separators are treated as boundaries.
    """
    head = (impact or "").strip()
    head = re.sub(r"^\[KEV\]\s*", "", head)
    head = re.sub(r"\s*[-–—]?\s*\[KEV\b[^\]]*\]?\s*$", "", head)
    head = re.split(r"\s*(?:→|->|;)\s*", head)[0].strip().rstrip(".")
    head = truncate_words(head, 110)
    return f"{component}: {head}" if head else component


def load_fleet():
    """Blast-radius annotations, keyed by CVE id."""
    path = ROOT.parent / "go-big-go-home/directions/datacenter-security/fleet-patch-surface.csv"
    fleet = {}
    if not path.exists():
        return fleet
    for row in csv.DictReader(path.open()):
        m = CVE_RE.search(row.get("cve") or "")
        if not m:
            continue
        fleet[m.group(1)] = {
            k: v.strip()
            for k, v in (
                ("ubiquity", row.get("ubiquity") or ""),
                ("remediation_pain", row.get("remediation_pain") or ""),
                ("pain_class", row.get("pain_class") or ""),
                ("why_fleet_wide", row.get("why_fleet_wide") or ""),
            )
            if v.strip()
        }
    return fleet


def build():
    src = ROOT.parent / "go-big-go-home/directions/datacenter-security/neocloud-cve-catalogue.csv"
    if not src.exists():
        sys.exit(f"source corpus not found: {src}")

    fleet = load_fleet()
    entries, seen, seq = [], set(), {}

    for row in csv.DictReader(src.open()):
        raw_cve = (row.get("cve") or "").strip()
        component = (row.get("component") or "").strip()
        year = (row.get("year") or "").strip()
        layer_name = (row.get("layer") or "").strip()

        m = CVE_RE.search(raw_cve)
        cve = m.group(1) if m else None

        # The CVE id is authoritative for the year, so CVE-2025-33229 files under 2025
        # even when the source row recorded the advisory batch it arrived in.
        if cve:
            year = cve.split("-")[1]

        # Named-vulnerability aliases ("NVIDIAScape", "ShellTorch") appear in either column.
        aliases = []
        for a in PAREN_RE.findall(raw_cve) + QUOTED_RE.findall(component):
            a = a.strip().strip('"“”')
            if a and not CVE_RE.search(a) and a not in aliases:
                aliases.append(a)
        component = clean_component(component)

        if cve:
            entry_id = cve
        else:
            # Design-level weaknesses that have no CVE and never will.
            y = year if re.fullmatch(r"\d{4}", year) else "0000"
            seq[y] = seq.get(y, 0) + 1
            entry_id = f"NCVD-{y}-{seq[y]:03d}-{slugify(component, 32)}"

        if entry_id in seen:
            continue
        seen.add(entry_id)

        score = parse_score(row.get("cvss"))
        sev_raw = (row.get("severity") or "").strip()

        entry = {
            "id": entry_id,
            "cve": cve,
            "aliases": aliases,
            "title": make_title(component, row.get("impact")),
            "layer": LAYERS.get(layer_name, slugify(layer_name)),
            "layer_name": layer_name,
            "component": component,
            "year": year,
            "cvss_score": score,
            "severity": SEVERITY.get(sev_raw, slugify(sev_raw) if sev_raw else "unscored"),
            "kev": (row.get("kev") or "").strip().lower() == "yes",
            "impact": (row.get("impact") or "").strip(),
            "attack_vector": (row.get("attack_vector") or "").strip(),
            "remediation": (row.get("remediation") or "").strip(),
            "references": split_refs(row.get("reference")),
            # Honesty tier. The seed corpus was bulk-curated from vendor advisories with
            # machine assistance; "reviewed" is earned once a human confirms an entry
            # against primary sources. Never set "reviewed" from this script.
            "status": "curated",
        }
        if cve and cve in fleet:
            entry["fleet"] = fleet[cve]

        entries.append(entry)

    entries.sort(key=lambda e: (-(e["cvss_score"] or 0), e["id"]))
    write_entries(entries)
    return entries


def write_entries(entries):
    for old in ENTRIES.rglob("*.json"):
        old.unlink()
    for e in entries:
        year = e["year"] if re.fullmatch(r"\d{4}", e["year"]) else "undated"
        d = ENTRIES / year
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{e['id']}.json").write_text(json.dumps(e, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    built = build()
    kev = sum(1 for e in built if e["kev"])
    crit = sum(1 for e in built if e["severity"] == "critical")
    print(f"entries: {len(built)}  critical: {crit}  kev: {kev}")
