#!/usr/bin/env python3
"""Merge entries that are one issue split across several CVE ids.

Vendors routinely assign a CVE per code path. NVIDIA bulletin 2026/5868 carries thirty of
them for the same unsafe deserialization in Megatron Bridge: same score, same advisory, same
one-line remediation. Thirty entries that say the same sentence is not thirty facts, and it
buries everything around it in the browse view.

The hard part is that the opposite case looks identical from a distance. The eight grub2 CVEs
in one oss-security post are genuinely eight different bugs, and the sixty-eight amdgpu
display-core entries share a title only because the seed import derived it from a boilerplate
`impact`. Merging either would destroy real records.

So nothing is merged on a heuristic alone. This collects buckets - same specific advisory, same
component, same score - and a model partitions each one, with instructions to keep ids apart
when unsure. Keeping them apart costs a duplicate; merging wrongly costs a CVE that no longer
has its own answer, which is the more expensive mistake.

    python3 scripts/consolidate.py                    # propose only, print what it would ask
    python3 scripts/consolidate.py --adjudicate       # ask the model, print verdicts
    python3 scripts/consolidate.py --adjudicate --write
"""

import argparse
import concurrent.futures
import difflib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"

MODEL = "claude-opus-5"

# References that identify a CVE rather than an advisory. Two entries sharing only these have
# nothing in common but being CVEs, which is what every entry here has.
GENERIC_REF = re.compile(
    r"nvd\.nist\.gov|cve\.org|cve\.mitre|security-tracker\.debian|"
    r"access\.redhat\.com/security/cve/|ubuntu\.com/security/CVE|"
    r"/torvalds/linux\.git/?$|kernel\.org/?$|official-cve-feed",
    re.I,
)

TITLE_SIMILARITY = 0.72


def specific_refs(entry: dict) -> list[str]:
    return sorted({r for r in entry.get("references", []) if not GENERIC_REF.search(r)})


def norm_component(component: str) -> str:
    component = re.sub(r"\(.*?\)", "", component or "").lower()
    component = re.sub(r"\b(nvidia|amd|intel)\b", "", component)
    return re.sub(r"[^a-z0-9]+", "", component)


def title_words(entry: dict) -> list[str]:
    """The title minus its component prefix - the part that says what actually goes wrong."""
    title = (entry.get("title") or "").lower()
    title = title.split(":", 1)[1] if ":" in title else title
    return re.sub(r"[^a-z0-9 ]+", " ", title).split()


def cve_sort_key(cve: str) -> tuple[int, int]:
    _, year, num = cve.split("-", 2)
    return int(year), int(num)


def load() -> list[tuple[Path, dict]]:
    return sorted(((p, json.loads(p.read_text())) for p in ENTRIES.rglob("*.json")),
                  key=lambda pe: pe[1]["id"])


def propose(rows: list[tuple[Path, dict]]) -> list[list[tuple[Path, dict]]]:
    """Buckets of entries that share one advisory, one component and one score.

    Deliberately not clustered any finer than that. An earlier version grouped by title
    similarity too, which split NVIDIA bulletin 2026/5868 into an 18 and a 12 purely because
    three sweeps had phrased "code execution in the training job" three ways - and one advisory
    would have become two entries. Where to draw the line inside a bucket is the judgement
    call, so the bucket is handed over whole and the model draws it.
    """
    buckets: dict[tuple, list] = defaultdict(list)
    for path, entry in rows:
        if not entry.get("cve") or entry.get("status") == "reviewed":
            continue                      # never touch an entry a human signed off on
        refs = specific_refs(entry)
        if len(refs) != 1:
            continue                      # one shared advisory, unambiguously
        buckets[(refs[0], norm_component(entry["component"]), entry.get("cvss_score"))].append(
            (path, entry))

    return sorted((b for b in buckets.values() if len(b) > 1 and worth_asking(b)),
                  key=len, reverse=True)


def worth_asking(bucket: list[tuple[Path, dict]]) -> bool:
    """Cheap gate on whether to spend a model call on this bucket at all.

    Title similarity is a bad way to *draw* the groups but a fine way to decide there is
    nothing here to draw: a bucket where no two entries describe remotely the same thing -
    eight distinct grub2 flaws in one mailing-list post - is one the model would only ever
    keep apart, and asking costs a dollar to be told so.
    """
    words = [title_words(e) for _, e in bucket]
    return any(difflib.SequenceMatcher(None, a, b).ratio() >= TITLE_SIMILARITY
               for i, a in enumerate(words) for b in words[i + 1:])


PROMPT = """You are cleaning up the GPU Vulnerability Database (gpuvulndb.org).

Vendors often assign one CVE per affected code path. When a single advisory, a single fix and a
single remediation cover all of them, thirty near-identical entries are noise, and the database
should carry one entry that lists all thirty ids. But CVEs disclosed *together* are frequently
still distinct bugs - eight different grub2 memory-safety flaws in one mailing-list post, or a
year of ingress-nginx issues on one vendor page - and those must stay separate.

Below are entries that share one advisory, one component and one CVSS score. That is a hint,
not an answer. **Partition them.**

Put two ids in the same group ONLY if all of these hold:
- one underlying flaw, or one indistinguishable class of flaw, in one component,
- the same fix and the same remediation for every id in the group,
- an operator would take exactly the same action for every one of them, and would gain nothing
  from seeing them listed separately.

Keep ids apart when they describe different mechanisms, different attack paths, different
affected subsystems, or different fixed versions - even though they share an advisory and a
score. **If you are not sure, keep them apart.** A duplicate entry is untidy; a merged entry
that hides a distinct vulnerability means a CVE lookup returns the wrong answer.

Note that near-identical wording is weak evidence on its own: these entries were drafted from
terse advisories, so two different bugs can end up described in the same words. Ask what the
advisory actually says, not whether the sentences match.

Reply with JSON only, no prose and no code fence:

{"groups": [
   {"cves": ["CVE-...", "CVE-..."],
    "why": "one clause on why these are one issue",
    "title": "one line, at most 115 chars, 'Component: what goes wrong'",
    "impact": "operator-facing impact for the whole set, saying the vendor split it across N ids",
    "remediation": "what the operator does, once, for all of them"}
 ],
 "keep_apart": ["CVE-...", "..."]}

Every id below must appear exactly once, in one group or in keep_apart. A group needs at least
two ids; anything you would leave alone goes in keep_apart. Returning every id in keep_apart is
a perfectly good answer.

## The entries
"""


def adjudicate(group: list[tuple[Path, dict]], timeout: int) -> dict | None:
    payload = [{
        "cve": e["cve"],
        "title": e["title"],
        "component": e["component"],
        "cvss_score": e.get("cvss_score"),
        "impact": e["impact"][:700],
        "remediation": e.get("remediation", "")[:400],
        "references": e["references"],
    } for _, e in group]
    prompt = PROMPT + "\n```json\n" + json.dumps(payload, indent=1, ensure_ascii=False) + "\n```\n"
    try:
        proc = subprocess.run(["claude", "-p", "--model", MODEL, "--output-format", "json"],
                              input=prompt, capture_output=True, text=True,
                              timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    try:
        reply = json.loads(proc.stdout).get("result", "")
    except json.JSONDecodeError:
        reply = proc.stdout
    fence = re.search(r"```(?:json)?\s*(.+?)```", reply, re.S)
    if fence:
        reply = fence.group(1)
    start, end = reply.find("{"), reply.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(reply[start:end + 1])
    except json.JSONDecodeError:
        return None


def partition(bucket: list[tuple[Path, dict]], verdict: dict
              ) -> list[tuple[list[tuple[Path, dict]], dict]]:
    """Turn the model's answer into groups of ≥2 real entries, ignoring anything it invented."""
    by_cve = {e["cve"]: (p, e) for p, e in bucket}
    out, claimed = [], set()
    for group in verdict.get("groups", []):
        if not isinstance(group, dict):
            continue
        members = []
        for cve in group.get("cves", []):
            if cve in by_cve and cve not in claimed:
                claimed.add(cve)
                members.append(by_cve[cve])
        if len(members) > 1:
            out.append((members, group))
    return out


def merge(group: list[tuple[Path, dict]], verdict: dict) -> tuple[Path, dict, list[Path]]:
    """Fold the group into its lowest-numbered CVE. Returns (path, entry, files to delete)."""
    ordered = sorted(group, key=lambda pe: cve_sort_key(pe[1]["cve"]))
    (keep_path, keep), rest = ordered[0], ordered[1:]
    entry = dict(keep)

    every = {e["cve"] for _, e in ordered}
    for _, e in ordered:
        every.update(e.get("additional_cves", []))
    entry["additional_cves"] = sorted(every - {entry["cve"]}, key=cve_sort_key)

    for field in ("title", "impact", "remediation"):
        text = (verdict.get(field) or "").strip()
        if text:
            entry[field] = text

    # Keep every advisory anyone cited, but not thirty near-identical NVD links: the ids are in
    # additional_cves and each one's NVD page is one predictable URL away.
    seen, refs = set(), []
    for _, e in ordered:
        for r in e["references"]:
            if r not in seen and (not GENERIC_REF.search(r) or e is keep):
                seen.add(r)
                refs.append(r)
    entry["references"] = refs
    entry["kev"] = any(e.get("kev") for _, e in ordered)
    if any(e.get("known_exploited") for _, e in ordered):
        entry["known_exploited"] = True

    return keep_path, entry, [p for p, _ in rest]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adjudicate", action="store_true", help="ask the model about each group")
    ap.add_argument("--write", action="store_true", help="apply the merges it approved")
    ap.add_argument("--limit", type=int, default=0, help="only the N largest groups")
    ap.add_argument("--touching", type=Path,
                    help="a JSON list of CVE ids, or a research batch; only adjudicate buckets "
                         "containing one of them. What the daily run passes, so it re-examines "
                         "where new entries landed instead of re-asking about settled ones.")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    rows = load()
    buckets = propose(rows)

    if args.touching:
        raw = json.loads(args.touching.read_text())
        records = raw.get("candidates", raw) if isinstance(raw, dict) else raw
        fresh = {r["cve"] for r in records if isinstance(r, dict) and r.get("cve")}
        before = len(buckets)
        buckets = [b for b in buckets
                   if any(e["cve"] in fresh for _, e in b)]
        print(f"{len(fresh)} ids from {args.touching.name}: "
              f"{len(buckets)} of {before} buckets touched")

    if args.limit:
        buckets = buckets[:args.limit]

    print(f"{len(rows)} entries -> {len(buckets)} candidate buckets covering "
          f"{sum(len(b) for b in buckets)} entries")
    if not args.adjudicate:
        for b in buckets:
            print(f"\n  {len(b):3d}  {b[0][1]['component'][:50]}")
            print(f"       {b[0][1]['title'][:100]}")
            print(f"       {', '.join(e['cve'] for _, e in b[:6])}"
                  f"{' ...' if len(b) > 6 else ''}")
        print("\nproposal only - pass --adjudicate to have the model partition each")
        return 0

    # Adjudication is IO-bound on the model; the merges themselves stay on this thread so the
    # files are only ever written from one place. Verdicts are collected as they land rather
    # than with pool.map, which returns nothing until the slowest bucket is done and leaves a
    # long run looking hung.
    verdicts: list[dict | None] = [None] * len(buckets)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(adjudicate, b, args.timeout): i for i, b in enumerate(buckets)}
        for n, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            i = futures[fut]
            try:
                verdicts[i] = fut.result()
            except Exception as e:
                print(f"  bucket {i + 1}: {type(e).__name__}: {e}", flush=True)
            print(f"  ...{n}/{len(buckets)} adjudicated", end="\r", flush=True)
    print(" " * 40, end="\r")

    merged = untouched = failed = removed = 0
    for i, (bucket, verdict) in enumerate(zip(buckets, verdicts), 1):
        label = f"{bucket[0][1]['component'][:36]:36} ({len(bucket)})"
        if verdict is None:
            failed += 1
            print(f"  {i:3d}. ?? {label} no usable verdict - left alone")
            continue

        groups = partition(bucket, verdict)
        if not groups:
            untouched += 1
            print(f"  {i:3d}. -- {label} kept apart")
            continue

        for members, group_verdict in groups:
            keep_path, entry, drop = merge(members, group_verdict)
            merged += 1
            removed += len(drop)
            print(f"  {i:3d}. ++ {label} -> {entry['cve']} "
                  f"+{len(entry['additional_cves'])} ids: {group_verdict.get('why', '')[:52]}")
            if args.write:
                keep_path.write_text(json.dumps(entry, indent=2, ensure_ascii=False) + "\n")
                for path in drop:
                    path.unlink()
        left = len(bucket) - sum(len(m) for m, _ in groups)
        if left:
            print(f"       ({left} of the {len(bucket)} kept apart)")

    print(f"\nmerged into {merged} entries, {untouched} buckets left intact, {failed} unresolved")
    print(f"{'removed' if args.write else 'would remove'} {removed} entry files")
    if not args.write:
        print("dry run - pass --write to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
