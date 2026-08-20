#!/usr/bin/env python3
"""Derive the remediation cost class from remediation prose that states it explicitly.

This is extraction, not inference: a class is only assigned when the text names the action.
The hard part is negation - roughly a third of these remediations say things like "no GPU
drain", "No VBIOS, BMC or SBIOS flash needed", or "deployable fleet-wide without a flash".
Matching cost words naively would put actively wrong operational guidance on those entries,
which is worse than leaving the field empty, so negated clauses are dropped before matching.

    python3 scripts/derive_pain.py --sample 25     # inspect before trusting it
    python3 scripts/derive_pain.py --write
"""

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"

# Most disruptive first: a remediation needing both a flash and a reboot is a flash.
COST_PATTERNS: list[tuple[str, str]] = [
    ("unpatchable / mitigate-only",
     r"\bno (?:vendor )?(?:fix|patch)\b|\bunpatchable\b|\bcannot be (?:patched|fixed)\b"
     r"|\bmitigat(?:ion|e)[ -]only\b|\bwill not be fixed\b|\bno fix (?:is )?planned\b"
     r"|\bnever be fixed\b|\barchitectural\b"),
    ("firmware-flash",
     r"\bfirmware (?:flash|update|upgrade)\b|\bflash(?:ing|ed)? (?:the|new|updated)\b"
     r"|\bBIOS (?:update|upgrade|flash)\b|\bSBIOS\b|\bVBIOS\b|\bre-?flash\b"
     r"|\bBMC firmware\b|\bAGESA\b|\bUEFI (?:update|capsule)\b"),
    ("microcode + reboot", r"\bmicrocode\b|\bAGESA\b"),
    ("node-reboot", r"\breboot\b|\bpower[ -]cycle\b|\bcold boot\b"),
    ("node-drain", r"\bdrain\b|\bevict\b|\bcordon\b|\bmigrate (?:the )?(?:workloads?|tenants?)\b"),
    ("daemon-restart",
     r"\brestart (?:the )?(?:service|daemon|container runtime|kubelet|agent)\b"
     r"|\bsystemctl restart\b|\bservice restart\b|\brolling restart\b"),
    ("hot-patch",
     r"\blive[ -]patch\b|\bhot[ -]patch\b|\bno (?:reboot|restart|downtime|drain)\b"
     r"|\bwithout (?:a )?(?:reboot|restart|downtime|flash|drain)\b"),
]

# A clause containing one of these near a cost word is asserting the cost is NOT incurred.
NEGATION = re.compile(
    r"\b(?:no|not|without|avoids?|never|neither|nor|doesn'?t|does not|don'?t|"
    r"no need (?:for|to)|not require[sd]?|isn'?t|is not)\b",
    re.I,
)

# Splitting on sentence and clause boundaries keeps "package update; no reboot" from being
# read as a reboot, while not losing "flash the BMC, then reboot".
CLAUSE_SPLIT = re.compile(r"(?<=[.;:!?])\s+|\s+(?:—|–|--)\s+|\s*\n+\s*")


# How far back a negation can sit and still be negating the cost word. Clause-level negation
# is too blunt: "Firmware flash from the server OEM, not from Insyde" negates the source, not
# the flash, and dropping that clause understates the cost as a mere reboot.
NEGATION_WINDOW = 45


def is_negated(clause: str, start: int) -> bool:
    """True when a negation sits just before the cost word rather than elsewhere in the clause."""
    window = clause[max(0, start - NEGATION_WINDOW):start]
    return bool(NEGATION.search(window))


def derive(remediation: str) -> tuple[str | None, str | None]:
    """Returns (pain_class, the evidence clause) or (None, None)."""
    text = remediation or ""
    if not text.strip():
        return None, None

    clauses = [c for c in CLAUSE_SPLIT.split(text) if c.strip()]
    for name, pattern in COST_PATTERNS:
        for clause in clauses:
            for m in re.finditer(pattern, clause, re.I):
                if not is_negated(clause, m.start()):
                    return name, clause.strip()
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0, help="print N derived results and exit")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    derived: list[tuple[Path, dict, str, str]] = []
    skipped = 0
    already = 0

    for path in sorted(ENTRIES.rglob("*.json")):
        entry = json.loads(path.read_text())
        if entry.get("fleet", {}).get("pain_class"):
            already += 1
            continue
        cls, evidence = derive(entry.get("remediation", ""))
        if cls:
            derived.append((path, entry, cls, evidence or ""))
        else:
            skipped += 1

    print(f"already labelled : {already}")
    print(f"derived          : {len(derived)}")
    print(f"left unset       : {skipped}")
    print("\nby class:")
    for k, v in Counter(c for _, _, c, _ in derived).most_common():
        print(f"  {v:5d}  {k}")

    if args.sample:
        random.seed(17)
        print(f"\n=== {args.sample} sampled derivations (check these before trusting) ===")
        for path, entry, cls, evidence in random.sample(derived, min(args.sample, len(derived))):
            print(f"\n[{cls}]  {entry['id']}")
            print(f"   evidence : {evidence[:150]}")
        return

    if not args.write:
        print("\ndry run — use --sample N to inspect, --write to apply")
        return

    for path, entry, cls, _ in derived:
        fleet = entry.setdefault("fleet", {})
        fleet["pain_class"] = cls
        path.write_text(json.dumps(entry, indent=2, ensure_ascii=False) + "\n")
    print(f"\nwrote pain_class to {len(derived)} entries")


if __name__ == "__main__":
    main()
