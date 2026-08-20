#!/usr/bin/env python3
"""Write the commit message for a daily run, from what actually landed in entries/.

Reads the new files out of git rather than being told what was added, so the message can
never claim something the commit does not contain.

    python3 scripts/daily_message.py --candidates research/candidates-2026-08-20.json
"""

import argparse
import collections
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def new_entry_files() -> list[Path]:
    out = subprocess.run(["git", "status", "--porcelain", "entries/"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    paths = []
    for line in out.splitlines():
        status, _, name = line.partition(" ")
        name = (name or line[3:]).strip()
        if line.startswith("??") and name.endswith(".json"):
            paths.append(ROOT / name)
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", type=Path)
    args = ap.parse_args()

    entries = []
    for path in new_entry_files():
        try:
            entries.append(json.loads(path.read_text()))
        except (OSError, json.JSONDecodeError):
            continue

    day = f"{datetime.now(timezone.utc):%Y-%m-%d}"
    if not entries:
        print(f"Daily update {day}: no new entries")
        return

    layers = collections.Counter(e["layer"] for e in entries)
    notable = sorted(
        (e for e in entries if e.get("kev") or (e.get("cvss_score") or 0) >= 8.0),
        key=lambda e: (not e.get("kev"), -(e.get("cvss_score") or 0)),
    )[:5]

    lines = [f"Add {len(entries)} entries from the {day} sweep", ""]
    if args.candidates and args.candidates.exists():
        meta = json.loads(args.candidates.read_text())
        seen = len(meta.get("candidates", []))
        lines.append(f"Screened {seen} CVEs modified in NVD over the previous "
                     f"{meta.get('window_days', 3):g} days.")
        lines.append("")

    for layer, n in layers.most_common():
        lines.append(f"  {n:3d}  {layer}")

    if notable:
        lines.append("")
        lines.append("Worth a look first:")
        for e in notable:
            mark = "[KEV] " if e.get("kev") else ""
            score = f"{e['cvss_score']:.1f}" if e.get("cvss_score") is not None else "unscored"
            lines.append(f"  {mark}{e['id']} ({score}) {e['title']}")

    lines += ["", "All at status 'curated' - machine-assisted from NVD and vendor advisories,",
              "not individually verified against primary sources."]
    print("\n".join(lines))


if __name__ == "__main__":
    main()
