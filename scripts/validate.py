#!/usr/bin/env python3
"""Validate every entry against the schema and the repo's own consistency rules.

Runs in CI on every pull request. Exits non-zero on any error.
Schema validation uses jsonschema when available; the structural checks below run either way.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
SCHEMA = ROOT / "schema" / "entry.schema.json"

# Hosts that no longer serve the advisory they used to. Checked without network access so CI
# stays fast; a full link check is a separate, slower job.
DEAD_REFS = {
    "nvidia.custhelp.com": "retired, use github.com/NVIDIA/product-security/tree/main/<year>/<bulletin>",
}

errors, warnings = [], []


def err(path, msg):
    errors.append(f"{path.relative_to(ROOT)}: {msg}")


def warn(path, msg):
    warnings.append(f"{path.relative_to(ROOT)}: {msg}")


def main():
    files = sorted(ENTRIES.rglob("*.json"))
    if not files:
        sys.exit("no entries found — run scripts/build.py first")

    schema = json.loads(SCHEMA.read_text())
    validator = None
    try:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(schema)
    except ImportError:
        warnings.append("jsonschema not installed — schema checks skipped, structural checks still ran")

    seen_ids, seen_cves = {}, {}

    for path in files:
        try:
            entry = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            err(path, f"invalid JSON: {e}")
            continue

        if validator:
            for v in sorted(validator.iter_errors(entry), key=lambda e: list(e.path)):
                loc = "/".join(str(p) for p in v.path) or "(root)"
                err(path, f"{loc}: {v.message}")

        eid = entry.get("id")
        if not eid:
            continue

        # Filename is the key. Wiz let these drift apart and it broke their URLs.
        if path.stem != eid:
            err(path, f"filename does not match id {eid!r}")

        year = entry.get("year") or ""
        expected_dir = year if re.fullmatch(r"\d{4}", year) else "undated"
        if path.parent.name != expected_dir:
            err(path, f"filed under {path.parent.name}/ but year is {year!r}")

        if eid in seen_ids:
            err(path, f"duplicate id, already defined in {seen_ids[eid]}")
        seen_ids[eid] = path.relative_to(ROOT)

        cve = entry.get("cve")
        if cve:
            if cve in seen_cves:
                err(path, f"duplicate CVE {cve}, already in {seen_cves[cve]}")
            seen_cves[cve] = path.relative_to(ROOT)
            if entry.get("year") and not cve.startswith(f"CVE-{entry['year']}"):
                warn(path, f"cve {cve} disagrees with year {entry['year']}")

        # A consolidated entry speaks for several CVEs. Those ids have to be as exclusive as
        # the canonical one: if two entries both claimed CVE-2026-61755, a reader looking it up
        # would get a different answer depending on which entry they found first.
        for extra in entry.get("additional_cves", []):
            if extra == cve:
                err(path, f"additional_cves repeats the canonical cve {extra}")
            elif extra in seen_cves:
                err(path, f"CVE {extra} is claimed twice, already in {seen_cves[extra]}")
            else:
                seen_cves[extra] = path.relative_to(ROOT)
        if entry.get("additional_cves") and not cve:
            err(path, "additional_cves needs a canonical cve to be additional to")

        score, sev = entry.get("cvss_score"), entry.get("severity")
        if score is not None and sev != bucket(score):
            err(path, f"severity {sev!r} does not match score {score} (expected {bucket(score)!r})")

        if entry.get("status") == "reviewed" and not entry.get("contributor"):
            err(path, "status 'reviewed' requires a contributor to attribute the review to")

        for ref in entry.get("references", []):
            if " " in ref:
                err(path, f"reference contains a space: {ref!r}")
            for host, why in DEAD_REFS.items():
                if host in ref:
                    err(path, f"reference points at {host} — {why}")
            if ref.endswith(".csv"):
                err(path, "reference is a bulk index, not the advisory for this entry")
            if "services.nvd.nist.gov/rest/json" in ref or "keywordSearch=" in ref:
                err(path, "reference is an API search query, not a citation")

    report(files, seen_cves)


def bucket(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unscored"


def report(files, cves):
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")

    print(f"\nchecked {len(files)} entries, {len(cves)} distinct CVEs")
    if errors:
        print(f"FAILED with {len(errors)} error(s)")
        sys.exit(1)
    print(f"OK ({len(warnings)} warning(s))")


if __name__ == "__main__":
    main()
