#!/usr/bin/env python3
"""Build web/data/nvd-dates.json: CVE id -> NVD published date (YYYY-MM-DD).

Downloads the NVD 2.0 yearly feeds for every year that appears in the corpus
and keeps only the CVEs the database actually references. Run it after seeding
new entries; the output file is committed.
"""

import glob
import gzip
import io
import json
import os
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), "..")
OUT = os.path.join(ROOT, "web", "data", "nvd-dates.json")
FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

wanted = set()
for path in glob.glob(os.path.join(ROOT, "entries", "*", "*.json")):
    with open(path) as f:
        cve = json.load(f).get("cve")
    if cve:
        wanted.add(cve)

years = sorted({c.split("-")[1] for c in wanted})
print(f"{len(wanted)} CVEs across {len(years)} feed years")

dates: dict[str, str] = {}
for year in years:
    url = FEED.format(year=year)
    print(f"fetching {url} ...", flush=True)
    with urllib.request.urlopen(url, timeout=120) as resp:
        raw = gzip.decompress(resp.read())
    feed = json.loads(raw)
    del raw
    for item in feed.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if cve_id in wanted and cve.get("published"):
            dates[cve_id] = cve["published"][:10]
    del feed
    print(f"  matched so far: {len(dates)}", flush=True)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    json.dump(dict(sorted(dates.items())), f, indent=0, separators=(",", ":"))
    f.write("\n")

missing = wanted - set(dates)
print(f"wrote {len(dates)} dates to {OUT}; {len(missing)} CVEs not in feeds")
if missing:
    print("missing:", ", ".join(sorted(missing)[:20]), "..." if len(missing) > 20 else "")
