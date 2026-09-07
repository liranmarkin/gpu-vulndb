# gpu-vulndb

## What this is
The Open GPU Vulnerability Database (gpuvulndb.org): one JSON file per vulnerability in the GPU datacenter stack, firmware to model serving, with fields NVD lacks (what an attacker gets, who must reach it, what the operator must do). `entries/` is the source of truth, `schema/` enforces it in CI, `scripts/` are the Python tooling, `web/` is the Next.js site.

## Runs as
- Daily sweep: systemd user timer `gpu-vulndb-daily.timer` (08:00 Israel time, `Persistent=true`) -> `gpu-vulndb-daily.service` -> `scripts/daily_update.sh` (NVD fetch -> `claude -p` triage -> ingest -> validate -> commit -> push). Timeout 3h.
- `systemctl --user list-timers gpu-vulndb-daily.timer`; `journalctl --user -u gpu-vulndb-daily.service`.
- Website is deployed from the repo (`.vercel/` gitignored), not served from this VM.

## Develop
- Validate (what CI runs): `python3 -m venv .venv && .venv/bin/pip install jsonschema` then `.venv/bin/python scripts/validate.py`. `daily_update.sh` builds the same `.venv` with `uv` if missing.
- Dry-run the sweep: `DRY_RUN=1 scripts/daily_update.sh` (tunables `DAYS`, `BATCH`, `WORKERS`, `LIMIT`). Env: `NVD_API_KEY`.
- Site: `cd web && npm install && npm run dev`; also `npm run build`, `npm run lint`, `npm run typecheck`.
- No unit test suite beyond `scripts/validate.py`.

## Layout
- `entries/<year>/<id>.json` - the database. `schema/entry.schema.json` - the schema.
- `scripts/validate.py`, `ingest.py`, `consolidate.py`, `derive_pain.py`, `seo_dates.py`, `seo_ping.py`, `daily_*.py`, `daily_prompt.md`.
- `web/` - Next.js 16 / React 19 / Tailwind 4; reads `entries/` off disk at build time.
- `research/` - working dir for triage batches (gitignored).
- `CONTRIBUTING.md`, `LICENSE` (MIT, code), `LICENSE-DATA` (CC BY 4.0, data).

## Gotchas
- PUBLIC repo (`liranmarkin/gpu-vulndb`). No personal data, keys, or VM paths in commits.
- `daily_update.sh` refuses to run on a dirty tree and never commits unless `validate.py` passes.
- Nothing generated is committed; the site builds from `entries/` directly.

Docs: README.md is the long-form reference.
