#!/usr/bin/env python3
"""Rewrite the README's counts from the entry corpus, so they cannot drift out of date."""

import collections
import glob
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
rows = [json.loads(pathlib.Path(f).read_text())
        for f in glob.glob(str(ROOT / "entries/**/*.json"), recursive=True)]

layers = collections.Counter(e["layer"] for e in rows)
pain = collections.Counter(
    e["fleet"]["pain_class"] for e in rows if e.get("fleet", {}).get("pain_class"))
years = sorted({e["year"] for e in rows if e["year"]})
# Every CVE the database answers for, not every CVE that has a file. A consolidated entry
# speaks for its whole set, so counting files here would make merging duplicates look like
# losing coverage.
cves = {e["cve"] for e in rows if e["cve"]} | {
    c for e in rows for c in e.get("additional_cves", [])}

path = ROOT / "README.md"
text = path.read_text()
before = text

text = re.sub(r"[\d,]+ entries covering [\d,]* distinct CVEs, spanning \d{4} to \d{4}",
              f"{len(rows):,} entries covering {len(cves):,} distinct CVEs, "
              f"spanning {years[0]} to {years[-1]}", text)
# The shields.io badge carries the same number, URL-encoded, and drifts the moment it is not
# rewritten alongside the prose.
text = re.sub(r"(badge/entries-)[\d%A-C]+(-\w+\))",
              rf"\g<1>{len(rows):,}\g<2>".replace(",", "%2C"), text)
for layer, n in layers.items():
    text = re.sub(rf"(\| `{re.escape(layer)}` \|[^|]*\| )[\d,]+( \|)", rf"\g<1>{n:,}\g<2>", text)
for cls, n in pain.items():
    text = re.sub(rf"(\| `{re.escape(cls)}` \| )[\d,]+( \|)", rf"\g<1>{n:,}\g<2>", text)
text = re.sub(r"There are \d+ of them",
              f"There are {sum(1 for e in rows if not e['cve'])} of them", text)
text = re.sub(r"[\d,]+ entries carry a `fleet\.pain_class`",
              f"{sum(pain.values()):,} entries carry a `fleet.pain_class`", text)
text = re.sub(r"— [\d,]+ entries\nare in that state",
              f"— {len(rows) - sum(pain.values()):,} entries\nare in that state", text)
path.write_text(text)
print(f"README: {len(rows):,} entries, {len(cves):,} CVEs, {sum(pain.values()):,} with a cost class")
if text == before:
    # A silent no-op here is how the README came to claim 3,566 entries for months: the prose
    # was reworded and the substitutions stopped matching anything. Say so rather than exit 0.
    print("WARNING: nothing in README.md matched - the counts above were not written anywhere")
