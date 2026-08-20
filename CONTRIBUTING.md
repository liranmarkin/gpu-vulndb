# Contributing

Thanks for helping. This database is only as good as its entries, and the most valuable
contribution is usually not a new entry — it is verifying an existing one.

## What to work on

**Review a `curated` entry.** Most of this database was bulk-imported and annotated with machine
assistance. Pick an entry in an area you know, check every field against the vendor advisory and
the CVE record, fix what is wrong, set `"status": "reviewed"`, and add your GitHub profile URL as
`contributor`. This is the highest-value contribution available.

**Add a missing vulnerability.** Anything affecting the stack GPU infrastructure runs on, at any
severity. Include design-level weaknesses with no CVE — they get an `NCVD-` id.

**Improve remediation guidance.** The `remediation` field is what makes an entry worth more than
an NVD lookup. If you have rolled a fix across a real fleet and the guidance here is wrong or
naive, correct it. Say what actually had to happen.

**Fix the fleet impact fields.** `ubiquity`, `pain_class`, and `why_fleet_wide` drive how operators
prioritize. They are sparsely populated and often guessed.

## Rules

1. **One entry per pull request.** Bulk edits are hard to review and hard to revert.
2. **Every claim needs a public reference.** Vendor advisory, NVD, CVE record, research writeup, or
   commit. No private sources, no unattributed claims.
3. **This is not a disclosure venue.** Do not submit undisclosed vulnerabilities. Report those to
   the vendor. Entries here must already be public.
4. **No exploit code.** Link to a public proof of concept if one exists; do not vendor it here.
5. **Write for an operator.** "Heap overflow in the parser" is a description. "Any tenant that can
   submit a model file gets host root on the GPU node" is useful. Prefer the second.
6. **Do not disparage vendors or researchers.** Describe the flaw, not the people.
7. **Credit the researchers** in `discovered_by`. `contributor` is you, the person writing the
   entry. They are different fields on purpose.

## Adding an entry

Entries live at `entries/<year>/<id>.json`, one JSON file each. The filename must equal the `id`.

- If it has a CVE, the id **is** the CVE, and the year comes from the CVE, not the advisory date.
  `CVE-2025-33229` lives at `entries/2025/CVE-2025-33229.json`.
- If it has no CVE, use `NCVD-<year>-<seq>-<slug>` and file it under that year, or `undated/` if
  it is a standing design property with no meaningful date.

Copy a nearby entry and edit it. The schema is [`schema/entry.schema.json`](schema/entry.schema.json)
and it is the authority — the fields, enums, and rules are all documented in its `description`
strings.

Fields worth understanding:

| Field | Notes |
| --- | --- |
| `impact` | What the attacker gets. Not a restatement of the CWE. |
| `attack_vector` | Who has to reach what. "Any tenant with a GPU pod" is the useful register. |
| `remediation` | What the operator does, including the rollout cost. |
| `layer` | Which of the six stack layers. One only — pick where the flaw lives, not where it is felt. |
| `severity` | Must agree with `cvss_score`; CI enforces this. Use `unscored` when there is no score. |
| `kev` | CISA KEV listing only. For in-the-wild exploitation not in KEV, use `known_exploited`. |
| `aliases` | Named vulnerabilities only — `NVIDIAScape`, `LogoFAIL`. Not component qualifiers. |

## Before you open the pull request

```bash
python3 -m venv .venv && .venv/bin/pip install jsonschema
.venv/bin/python scripts/validate.py
```

CI runs exactly this. It checks the schema, that filenames match ids, that entries are filed under
the right year, that no id or CVE is duplicated, and that severity agrees with the score.

Do not edit `site/data.json` or run `scripts/build.py` in a pull request. `build.py` regenerates the
corpus from the original source CSVs and will overwrite hand-written entries; it exists for the
initial import and is not part of the contribution flow. Maintainers regenerate `data.json` on
release.

## Review

A maintainer will review within a few days. If your entry is outside our areas of expertise we may
ask for a second reference before merging rather than guess.

Merge rights are held by more than one person, deliberately. If a pull request sits unreviewed for
two weeks, comment and tag the maintainers — a stalled queue is a bug in the project, not in you.
