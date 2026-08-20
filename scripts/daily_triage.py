"""Turn candidate CVE records into research entries, using Claude Code as the judgement step.

The keyword filter upstream is deliberately loose; this is where something that has read the
whole record decides whether a CVE belongs in a GPU infrastructure database, and writes the
operator-facing fields that make an entry worth more than an NVD lookup.

Candidates are sent in small batches, several at a time, each to its own `claude -p` process.
Batching keeps a single malformed reply from costing the whole day, and the output of every
batch is written as it lands, so a partial run is still a usable run.

    python3 scripts/daily_triage.py --candidates research/candidates-2026-08-20.json
    python3 scripts/daily_triage.py --candidates ... --batch 8 --workers 4 --dry-run

The output is a research batch in the shape scripts/ingest.py reads; ingest is what actually
writes entries/, and it re-validates everything here.
"""

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESEARCH = ROOT / "research"
PROMPT = ROOT / "scripts" / "daily_prompt.md"

MODEL = "claude-opus-5"
ALLOWED_TOOLS = "WebFetch,WebSearch"
LAYERS = {"gpu-stack", "firmware-bmc-fabric", "kernel-hypervisor",
          "container-orchestration", "ai-serving", "control-plane"}
PAIN_CLASSES = {"hot-patch", "daemon-restart", "node-drain", "node-reboot",
                "microcode + reboot", "firmware-flash", "physical access",
                "unpatchable / mitigate-only", "other"}

# Fields the model may set. Anything else it invents is dropped rather than passed to ingest.
PASSTHROUGH = ("cve", "component", "title", "layer_hint", "impact", "attack_vector",
               "remediation", "references", "cvss_score", "cvss_vector", "cwe", "kev",
               "pain_class", "aliases")


def slim(c: dict) -> dict:
    """What the model sees. Descriptions are long and the batch is what costs tokens."""
    return {
        "cve": c["cve"],
        "published": c.get("published"),
        "cna": c.get("cna"),
        "description": (c.get("description") or "")[:3000],
        "affected_products": c.get("products", [])[:8],
        "cvss_score": c.get("cvss_score"),
        "cvss_vector": c.get("cvss_vector"),
        "cwe": c.get("cwe", []),
        "kev": c.get("kev", False),
        "references": c.get("references", [])[:6],
        "why_it_was_flagged": c.get("matched_term") or c.get("matched_on"),
    }


def extract_json(text: str) -> dict | None:
    """The contract says JSON only; a stray fence or preamble should not cost a batch."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def run_batch(batch: list[dict], index: int, timeout: int
              ) -> tuple[list[dict], list[dict], str, float]:
    prompt = (PROMPT.read_text()
              + "\n\n## Candidates\n\n```json\n"
              + json.dumps([slim(c) for c in batch], indent=1, ensure_ascii=False)
              + "\n```\n")
    cmd = ["claude", "-p", "--model", MODEL, "--output-format", "json",
           "--allowedTools", ALLOWED_TOOLS]
    try:
        proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                              timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return [], [], f"batch {index}: timed out after {timeout}s", 0.0
    if proc.returncode != 0:
        return [], [], f"batch {index}: claude exited {proc.returncode}: {proc.stderr[-300:]}", 0.0

    cost = 0.0
    try:
        envelope = json.loads(proc.stdout)
        reply = envelope.get("result", "")
        cost = float(envelope.get("total_cost_usd") or 0)
    except json.JSONDecodeError:
        reply = proc.stdout

    payload = extract_json(reply)
    if payload is None:
        return [], [], f"batch {index}: reply was not JSON ({reply[:200]!r})", cost

    wanted = {c["cve"] for c in batch}
    entries, problems = [], []
    for raw in payload.get("entries", []):
        entry, why = clean(raw, wanted)
        if entry:
            entries.append(entry)
        else:
            problems.append(f"batch {index}: dropped {raw.get('cve')}: {why}")

    rejected = [r for r in payload.get("rejected", []) if isinstance(r, dict)]
    seen = {e["cve"] for e in entries} | {r.get("cve") for r in rejected}
    missing = wanted - seen
    if missing:
        problems.append(f"batch {index}: no verdict for {', '.join(sorted(missing))}")
    return entries, rejected, "; ".join(problems), cost


def clean(raw: dict, wanted: set[str]) -> tuple[dict | None, str]:
    """Keep the model inside the contract. ingest.py validates again; this catches it earlier."""
    if not isinstance(raw, dict):
        return None, "not an object"
    cve = (raw.get("cve") or "").strip()
    if cve not in wanted:
        return None, "cve was not in this batch"
    entry = {k: raw[k] for k in PASSTHROUGH if raw.get(k) not in (None, "", [])}
    entry["cve"] = cve

    for field in ("component", "impact", "attack_vector", "remediation"):
        if not isinstance(entry.get(field), str) or len(entry.get(field, "")) < 3:
            return None, f"missing {field}"

    if entry.get("layer_hint") not in LAYERS:
        entry.pop("layer_hint", None)          # ingest infers it from the component instead
    if entry.get("pain_class") not in PAIN_CLASSES:
        entry.pop("pain_class", None)

    refs = [r for r in entry.get("references", [])
            if isinstance(r, str) and r.startswith("http") and " " not in r]
    # A reference the model produced from memory is worse than no reference at all.
    refs = [r for r in refs if not r.endswith(".csv")
            and "keywordSearch=" not in r
            and "services.nvd.nist.gov/rest/json" not in r]
    if not refs:
        return None, "no usable reference"
    entry["references"] = refs[:4]
    entry["year"] = cve.split("-")[1]
    return entry, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", type=Path, required=True)
    ap.add_argument("--out", type=Path, help="defaults to research/daily-<today>.json")
    ap.add_argument("--audit", type=Path,
                    help="where the rejections and problems go; keep it out of --out's "
                         "directory, which ingest.py reads wholesale")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=1200, help="seconds per batch")
    ap.add_argument("--dry-run", action="store_true", help="one batch only, print the result")
    args = ap.parse_args()

    data = json.loads(args.candidates.read_text())
    candidates = data["candidates"] if isinstance(data, dict) else data
    if not candidates:
        print("no candidates — nothing to triage")
        return 0

    batches = [candidates[i:i + args.batch] for i in range(0, len(candidates), args.batch)]
    if args.dry_run:
        batches = batches[:1]
    print(f"{len(candidates)} candidates in {len(batches)} batches "
          f"of {args.batch}, {args.workers} at a time")

    entries: list[dict] = []
    rejected: list[dict] = []
    failures: list[str] = []
    spend = 0.0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_batch, b, i, args.timeout): i
                   for i, b in enumerate(batches, 1)}
        for fut in concurrent.futures.as_completed(futures):
            i = futures[fut]
            try:
                got, skipped, problem, cost = fut.result()
            except Exception as e:                      # a worker dying must not end the run
                failures.append(f"batch {i}: {type(e).__name__}: {e}")
                continue
            entries.extend(got)
            rejected.extend(skipped)
            spend += cost
            if problem:
                failures.append(problem)
            print(f"  batch {i}: {len(got)} kept, {len(skipped)} rejected"
                  + (f" — {problem}" if problem else ""), flush=True)

    print(f"\nkept     : {len(entries)}")
    print(f"rejected : {len(rejected)}")
    print(f"model    : ${spend:.2f} across {len(batches)} batches")
    if failures:
        print(f"problems : {len(failures)}")
        for f in failures[:10]:
            print(f"   - {f}")

    if args.dry_run:
        print(json.dumps(entries, indent=2, ensure_ascii=False)[:6000])
        return 0

    out = args.out or RESEARCH / f"daily-{datetime.now(timezone.utc):%Y-%m-%d}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")

    audit = args.audit or RESEARCH / f"{out.stem}-rejected.json"
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text(json.dumps({"rejected": rejected, "problems": failures},
                                indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {audit}")
    # A batch that failed outright is the one failure mode that silently shrinks the database,
    # so it is worth a non-zero exit even though the entries that did land are still good.
    return 1 if len(failures) > len(batches) // 3 else 0


if __name__ == "__main__":
    sys.exit(main())
