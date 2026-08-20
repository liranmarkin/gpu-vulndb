#!/usr/bin/env python3
"""Replace bulk-CSV references with the actual NVIDIA bulletin, and capture NVIDIA's own scoring.

307 entries cite `.../CVE_index.csv` — the index they were imported from — rather than the
advisory that describes them. NVIDIA's index carries the bulletin id, the CVSS vector and the
CWE for each CVE, so all three are recoverable.

Capturing the vector matters beyond tidiness: since April 2026 NIST only fully enriches CVEs
that reach KEV, so for most of this corpus the vendor's vector is the only one that exists.

    python3 scripts/enrich_nvidia.py --csv-dir <dir>            # dry run
    python3 scripts/enrich_nvidia.py --csv-dir <dir> --write
"""

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"

# NVIDIA's old custhelp.com bulletin URLs no longer resolve. The product-security repo keeps
# one directory per bulletin and is stable, so link there instead. A bulletin does not always
# sit under the year of the index that cites it, hence the explicit map.
BULLETIN_URL = "https://github.com/NVIDIA/product-security/tree/main/{year}/{bulletin}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
STALE_HOSTS = ("nvidia.custhelp.com",)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
VECTOR_RE = re.compile(r"^CVSS:[34]\.\d/")


def load_index(csv_dir: Path) -> dict[str, dict]:
    """CVE -> {bulletin, vector, cwe}. Later years win; a CVE can span several product rows."""
    index: dict[str, dict] = {}
    for path in sorted(csv_dir.glob("nv-*.csv")):
        with path.open(newline="") as fh:
            for row in csv.DictReader(fh, delimiter=";"):
                cve = (row.get("CVE") or "").strip()
                if not CVE_RE.match(cve):
                    continue
                entry = index.setdefault(cve, {"bulletin": None, "vector": None, "cwe": []})

                bulletin = (row.get("Bulletin") or "").strip()
                if bulletin.isdigit():
                    entry["bulletin"] = bulletin

                vector = (row.get("Vector") or "").strip()
                if VECTOR_RE.match(vector):
                    entry["vector"] = vector

                for cwe in re.findall(r"CWE-\d+", row.get("CWE") or ""):
                    if cwe not in entry["cwe"]:
                        entry["cwe"].append(cwe)
    return index


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-dir", required=True, type=Path)
    ap.add_argument("--bulletin-map", required=True, type=Path,
                    help="JSON map of bulletin id -> year, built from the product-security repo")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    index = load_index(args.csv_dir)
    bulletin_year = json.loads(args.bulletin_map.read_text())
    print(f"NVIDIA index: {len(index)} distinct CVEs, {len(bulletin_year)} bulletins")

    stats = Counter()
    changed: list[tuple[Path, dict]] = []

    for path in sorted(ENTRIES.rglob("*.json")):
        entry = json.loads(path.read_text())
        cve = entry.get("cve")
        if not cve:
            continue

        cites_bulk = any(
            u.endswith(".csv") or any(h in u for h in STALE_HOSTS)
            for u in entry["references"]
        )
        info = index.get(cve)
        if not info:
            if cites_bulk:
                stats["bulk ref but not in index"] += 1
            continue

        before = json.dumps(entry, sort_keys=True)

        if cites_bulk:
            refs = [
                u for u in entry["references"]
                if not u.endswith(".csv") and not any(h in u for h in STALE_HOSTS)
            ]
            year = bulletin_year.get(info["bulletin"] or "")
            if info["bulletin"] and year:
                refs.append(BULLETIN_URL.format(year=year, bulletin=info["bulletin"]))
                stats["bulletin recovered"] += 1
            elif info["bulletin"]:
                stats["bulletin id not in repo"] += 1
            else:
                stats["no bulletin id in index"] += 1
            refs.append(NVD_URL.format(cve))
            entry["references"] = list(dict.fromkeys(refs))

        if info["vector"] and not entry.get("cvss_vector"):
            entry["cvss_vector"] = info["vector"]
            stats["vector added"] += 1
        if info["cwe"] and not entry.get("cwe"):
            entry["cwe"] = info["cwe"]
            stats["cwe added"] += 1

        if json.dumps(entry, sort_keys=True) != before:
            changed.append((path, entry))

    for k, v in stats.most_common():
        print(f"  {v:5d}  {k}")
    print(f"\nentries changed: {len(changed)}")

    if not args.write:
        print("dry run — pass --write to apply")
        return

    for path, entry in changed:
        path.write_text(json.dumps(entry, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(changed)} entries")


if __name__ == "__main__":
    main()
