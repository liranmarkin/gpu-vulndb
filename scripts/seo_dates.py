#!/usr/bin/env python3
"""Rebuild web/data/entry-updated.json: when each entry last changed.

The sitemap needs a <lastmod> per URL, and NVD's published date is the wrong answer -
it says when the CVE was disclosed, not when this database last had something new to
say about it. A 2019 CVE ingested today is new content for a crawler, and 1,144 entries
carry no NVD date at all, so without this file they reach the sitemap with no lastmod.

The answer git already knows: the commit date of the last change to the entry file.
Files that are still dirty in the working tree (the ones the daily run just wrote)
have no commit yet, so they are stamped today - this script is meant to run just
before the commit that ships them.

    python3 scripts/seo_dates.py           # rewrite the file
    python3 scripts/seo_dates.py --check   # exit 1 if it is out of date
"""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
UPDATED = ROOT / "web" / "data" / "entry-updated.json"

MARK = "__C__ "


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def commit_dates() -> dict[str, str]:
    """Repo-relative entry path -> date of the commit that last touched it.

    One `git log` walk over the whole history instead of 4,500 `git log -1` calls.
    The log is newest first, so the first date seen for a path is the one to keep.
    """
    out = git(
        "log", "--format=%s%%cs" % MARK, "--name-only", "--diff-filter=AMR", "--", "entries/"
    )
    dates: dict[str, str] = {}
    date = ""
    for line in out.splitlines():
        if line.startswith(MARK):
            date = line[len(MARK):].strip()
        elif line.endswith(".json"):
            dates.setdefault(line, date)
    return dates


def dirty_paths() -> set[str]:
    """Entry files added or modified in the working tree, not yet committed."""
    out = git("status", "--porcelain", "--untracked-files=all", "--", "entries/")
    paths = set()
    for line in out.splitlines():
        path = line[3:].strip()
        if " -> " in path:  # rename: take the destination
            path = path.split(" -> ")[-1]
        if path.endswith(".json") and not line.startswith(" D") and not line.startswith("D"):
            paths.add(path)
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify without writing")
    args = ap.parse_args()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dates = commit_dates()
    dirty = dirty_paths()

    updated: dict[str, str] = {}
    for path in sorted(ENTRIES.rglob("*.json")):
        rel = path.relative_to(ROOT).as_posix()
        entry_id = json.loads(path.read_text()).get("id") or path.stem
        updated[entry_id] = today if rel in dirty else dates.get(rel, today)

    body = json.dumps(dict(sorted(updated.items())), indent=0, separators=(",", ":")) + "\n"

    if args.check:
        current = UPDATED.read_text() if UPDATED.exists() else ""
        if current != body:
            raise SystemExit("entry-updated.json is stale - run scripts/seo_dates.py")
        print(f"entry-updated.json: up to date, {len(updated)} entries")
        return

    UPDATED.parent.mkdir(parents=True, exist_ok=True)
    UPDATED.write_text(body)
    fresh = sum(1 for d in updated.values() if d == today)
    print(f"entry-updated.json: {len(updated)} entries, {fresh} stamped {today}")


if __name__ == "__main__":
    main()
