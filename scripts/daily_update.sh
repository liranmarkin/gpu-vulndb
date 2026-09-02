#!/usr/bin/env bash
# The daily refresh, end to end: fetch, triage, ingest, validate, commit, push.
#
#   scripts/daily_update.sh              # the real thing
#   DRY_RUN=1 scripts/daily_update.sh    # everything except the commit and push
#
# Nothing is committed unless scripts/validate.py passes, so the worst a bad day can do is
# leave the working tree dirty and exit non-zero. Tunables: DAYS, BATCH, WORKERS, LIMIT.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DAYS="${DAYS:-3}"
BATCH="${BATCH:-12}"
WORKERS="${WORKERS:-3}"
LIMIT="${LIMIT:-120}"
DRY_RUN="${DRY_RUN:-0}"
TODAY="$(date -u +%F)"

VENV="$REPO/.venv"
# Kept out of research/ itself: scripts/ingest.py merges every *.json in the directory it is
# pointed at, and only the batch of the day belongs in that set.
WORK="$REPO/research/daily"
CANDIDATES="$WORK/candidates-$TODAY.json"
STAGE="$WORK/stage"
BATCH_FILE="$STAGE/daily-$TODAY.json"

step() { printf '\n=== %s — %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '\n!!! %s\n' "$*" >&2; exit 1; }

mkdir -p "$WORK" "$STAGE"
rm -f "$STAGE"/*.json

if [ ! -x "$VENV/bin/python" ]; then
  step "creating $VENV"
  # python3-venv is not installed on this box; uv builds the same thing without ensurepip.
  if command -v uv >/dev/null; then
    uv venv --quiet "$VENV"
    VIRTUAL_ENV="$VENV" uv pip install --quiet jsonschema
  else
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip jsonschema
  fi
fi
PY="$VENV/bin/python"
$PY -c "import jsonschema" 2>/dev/null || fail "$VENV has no jsonschema - validation would silently skip the schema"

step "syncing with origin"
git diff --quiet || fail "working tree is dirty - refusing to run on top of it"
git fetch --quiet origin
git checkout --quiet main
git pull --quiet --ff-only origin main

step "fetching the last $DAYS days from NVD"
$PY scripts/daily_candidates.py --days "$DAYS" --limit "$LIMIT" --out "$CANDIDATES"

count=$($PY -c "import json,sys; print(len(json.load(open(sys.argv[1]))['candidates']))" "$CANDIDATES")
if [ "$count" -eq 0 ]; then
  step "no candidates in scope today - nothing to do"
  exit 0
fi

step "triaging $count candidates with Claude Opus"
# A partial triage is still worth ingesting, so problems here are noted rather than fatal.
$PY scripts/daily_triage.py --candidates "$CANDIDATES" --out "$BATCH_FILE" \
    --audit "$WORK/rejected-$TODAY.json" --batch "$BATCH" --workers "$WORKERS" \
  || step "triage reported problems - continuing with what it produced"

[ -s "$BATCH_FILE" ] || fail "triage produced no batch file"
new=$($PY -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$BATCH_FILE")
if [ "$new" -eq 0 ]; then
  step "every candidate was judged out of scope - nothing to add"
  exit 0
fi

step "ingesting $new entries"
$PY scripts/ingest.py --research "$STAGE" --write

step "consolidating CVEs that are one issue"
# Triage already folds same-advisory ids together within a batch. This catches the case it
# cannot see: a vendor's ids trickling in across several days, which arrive in different runs
# and so were never in front of the model at the same time. Scoped to buckets today's entries
# actually landed in, so settled ones are not re-argued every morning.
$PY scripts/consolidate.py --adjudicate --write --touching "$BATCH_FILE" \
  || step "consolidation reported problems - continuing"

step "deriving remediation cost classes"
$PY scripts/derive_pain.py --write

step "joining NVD published dates"
$PY scripts/daily_dates.py --candidates "$CANDIDATES"

step "validating"
$PY scripts/validate.py \
  || fail "validation failed - nothing committed, entries left in the working tree to inspect"

added=$(git status --porcelain entries/ | grep -c '^??' || true)
if [ "$added" -eq 0 ]; then
  step "no new entry files - nothing to commit"
  exit 0
fi

step "refreshing README counts"
$PY scripts/refresh_readme.py

step "stamping entry change dates for the sitemap"
$PY scripts/seo_dates.py

if [ "$DRY_RUN" = "1" ]; then
  step "DRY_RUN=1 - stopping before the commit. $added new entries in the working tree."
  git status --short | head -20
  exit 0
fi

step "committing $added entries"
message=$($PY scripts/daily_message.py --candidates "$CANDIDATES")
git add -A entries/ web/data/nvd-dates.json web/data/entry-updated.json README.md
git -c user.name="gpu-vulndb daily" -c user.email="liran.markin@gmail.com" \
    commit --quiet -m "$message"

step "pushing"
# A sweep takes minutes and the branch can move underneath it. The commit only adds new files
# under entries/ plus two generated files, so replaying it on top of whatever landed is safe;
# a rebase that does not apply cleanly is a real conflict and should stop the run.
pushed=0
for attempt in 1 2 3; do
  if git push --quiet origin main; then pushed=1; break; fi
  step "push rejected (attempt $attempt) - rebasing onto origin/main and retrying"
  git fetch --quiet origin
  git rebase --quiet origin/main || { git rebase --abort || true; fail "rebase conflicted - resolve by hand"; }
  # Counts and dates are derived from the whole corpus, so they have to be recomputed against
  # the entries that arrived while this run was working.
  $PY scripts/daily_dates.py --candidates "$CANDIDATES"
  $PY scripts/refresh_readme.py
  $PY scripts/seo_dates.py
  if ! git diff --quiet web/data/nvd-dates.json web/data/entry-updated.json README.md; then
    git add web/data/nvd-dates.json web/data/entry-updated.json README.md
    git -c user.name="gpu-vulndb daily" -c user.email="liran.markin@gmail.com" \
        commit --quiet --amend --no-edit
  fi
done
[ "$pushed" = "1" ] || fail "could not push after 3 attempts"

# The batch is the only record of what a run produced, so it is archived rather than deleted.
step "waiting for the deploy, then telling search engines"
# IndexNow is push-side discovery for Bing and friends; Google follows the sitemap's
# lastmod on its own schedule. Never fatal - the entries are already published.
$PY scripts/seo_ping.py --wait "${SEO_WAIT:-900}" || step "IndexNow submission failed - the sitemap still carries the entries"

mv "$BATCH_FILE" "$WORK/" 2>/dev/null || true
step "done - $added entries added and pushed"
