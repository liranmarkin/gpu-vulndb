#!/usr/bin/env python3
"""Fold today's NVD published dates into web/data/nvd-dates.json.

scripts/fetch_nvd_dates.py rebuilds that file by downloading every yearly NVD feed, which is
hundreds of megabytes and the wrong tool to reach for once a day. The daily candidate fetch
already carries the published date for every CVE it saw, so this just merges those in.

    python3 scripts/daily_dates.py --candidates research/candidates-2026-08-20.json
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
DATES = ROOT / "web" / "data" / "nvd-dates.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", type=Path, required=True)
    args = ap.parse_args()

    data = json.loads(args.candidates.read_text())
    candidates = data["candidates"] if isinstance(data, dict) else data
    published = {c["cve"]: c["published"] for c in candidates if c.get("published")}

    # Only dates for CVEs that actually made it into the corpus; the site joins on entry ids.
    in_corpus = {e["cve"] for p in ENTRIES.rglob("*.json")
                 if (e := json.loads(p.read_text())).get("cve")}

    dates = json.loads(DATES.read_text()) if DATES.exists() else {}
    added = {c: d for c, d in published.items() if c in in_corpus and c not in dates}
    dates.update(added)

    DATES.parent.mkdir(parents=True, exist_ok=True)
    with DATES.open("w") as f:
        json.dump(dict(sorted(dates.items())), f, indent=0, separators=(",", ":"))
        f.write("\n")
    print(f"nvd-dates.json: +{len(added)} dates, {len(dates)} total")


if __name__ == "__main__":
    main()
