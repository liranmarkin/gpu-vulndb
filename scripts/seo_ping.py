#!/usr/bin/env python3
"""Tell search engines about the pages this run added or changed, via IndexNow.

A sitemap is a passive invitation: Google and Bing recrawl it on their own schedule,
which for a young domain can be days. IndexNow is the push side - one POST names the
changed URLs and Bing, Yandex, Seznam and Naver fan it out between themselves. Google
does not participate (its old sitemap ping endpoint was retired in 2023); for Google
the lever is an accurate <lastmod>, which scripts/seo_dates.py keeps honest.

The submission is only useful once the pages are actually live, so this waits for
Vercel to finish deploying the pushed commit before it fires. It proves the deploy by
polling the live sitemap until it lists the new URLs with today's lastmod.

    python3 scripts/seo_ping.py                     # URLs changed by the last commit
    python3 scripts/seo_ping.py --since <sha>       # URLs changed since <sha>
    python3 scripts/seo_ping.py --all               # every URL in the corpus (seeding)
    python3 scripts/seo_ping.py --dry-run           # print what would be sent

Failure here is never fatal to the pipeline: the entries are already committed and the
sitemap still carries them.
"""

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
PUBLIC = ROOT / "web" / "public"
UPDATED = ROOT / "web" / "data" / "entry-updated.json"

HOST = "gpuvulndb.org"
SITE = f"https://{HOST}"
ENDPOINT = "https://api.indexnow.org/indexnow"
BATCH = 10_000  # IndexNow's per-request URL limit
KEY_RE = re.compile(r"^[0-9a-fA-F]{8,128}$")
UA = "gpu-vulndb-seo-ping/1.0 (+https://gpuvulndb.org)"


def log(msg: str) -> None:
    print(f"    {msg}", flush=True)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def find_key() -> tuple[str, str]:
    """The IndexNow key is a file in web/public/ whose name matches its contents."""
    for path in sorted(PUBLIC.glob("*.txt")):
        if KEY_RE.match(path.stem) and path.read_text().strip() == path.stem:
            return path.stem, f"{SITE}/{path.name}"
    raise SystemExit(
        "no IndexNow key file in web/public/ - create <key>.txt containing exactly <key>"
    )


def entry_layer(entry_id: str) -> str | None:
    for path in ENTRIES.rglob(f"{entry_id}.json"):
        return json.loads(path.read_text()).get("layer")
    return None


def changed_ids(since: str) -> list[str]:
    """Entry ids added or modified between `since` and HEAD."""
    out = git("diff", "--name-only", "--diff-filter=AMR", f"{since}..HEAD", "--", "entries/")
    return [Path(p).stem for p in out.splitlines() if p.endswith(".json")]


def all_ids() -> list[str]:
    return [p.stem for p in ENTRIES.rglob("*.json")]


def urls_for(ids: list[str]) -> list[str]:
    """Entry URLs plus the hubs whose listings those entries changed."""
    layers = {layer for i in ids if (layer := entry_layer(i))}
    return [
        f"{SITE}/",
        *(f"{SITE}/layer/{layer}" for layer in sorted(layers)),
        *(f"{SITE}/vuln/{i}" for i in sorted(set(ids))),
    ]


def fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Cache-Control": "no-cache", "Pragma": "no-cache"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def live_sitemap() -> dict[str, str]:
    """loc -> lastmod, straight off the deployed site. Cache-busted; Vercel varies on query."""
    stamp = int(time.time())
    xml = fetch(f"{SITE}/sitemap.xml?_cb={stamp}", timeout=60)
    out = {}
    for block in re.findall(r"<url>(.*?)</url>", xml, re.S):
        loc = re.search(r"<loc>([^<]+)</loc>", block)
        mod = re.search(r"<lastmod>([^<]+)</lastmod>", block)
        if loc:
            out[loc.group(1).strip()] = mod.group(1).strip()[:10] if mod else ""
    return out


def wait_for_deploy(ids: list[str], wait: int) -> bool:
    """Poll the live sitemap until it shows every changed entry with its new lastmod."""
    expected = json.loads(UPDATED.read_text()) if UPDATED.exists() else {}
    targets = {f"{SITE}/vuln/{i}": expected.get(i, "") for i in ids}
    deadline = time.time() + wait
    attempt = 0
    while True:
        attempt += 1
        try:
            live = live_sitemap()
            missing = [
                url for url, want in targets.items()
                if url not in live or (want and live[url] < want)
            ]
            if not missing:
                log(f"deploy is live (sitemap check passed on attempt {attempt})")
                return True
            log(f"attempt {attempt}: {len(missing)}/{len(targets)} URLs not deployed yet")
        except (urllib.error.URLError, TimeoutError) as e:
            log(f"attempt {attempt}: sitemap fetch failed ({e})")
        if time.time() >= deadline:
            log(f"gave up waiting after {wait}s - submitting anyway")
            return False
        time.sleep(min(20, max(5, int(deadline - time.time()))))


def submit(urls: list[str], key: str, key_location: str) -> list[dict]:
    results = []
    for i in range(0, len(urls), BATCH):
        chunk = urls[i : i + BATCH]
        body = json.dumps(
            {"host": HOST, "key": key, "keyLocation": key_location, "urlList": chunk}
        ).encode()
        req = urllib.request.Request(
            ENDPOINT,
            data=body,
            headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": UA},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                results.append({"urls": len(chunk), "status": r.status, "body": ""})
                log(f"submitted {len(chunk)} URLs - HTTP {r.status}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            results.append({"urls": len(chunk), "status": e.code, "body": detail})
            log(f"submission rejected - HTTP {e.code} {detail}")
        except (urllib.error.URLError, TimeoutError) as e:
            results.append({"urls": len(chunk), "status": 0, "body": str(e)})
            log(f"submission failed - {e}")
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="HEAD~1", help="revision to diff against (default HEAD~1)")
    ap.add_argument("--all", action="store_true", help="submit every entry URL, not just changes")
    ap.add_argument("--wait", type=int, default=900, help="seconds to wait for the deploy")
    ap.add_argument("--no-wait", action="store_true", help="submit immediately")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    key, key_location = find_key()
    ids = all_ids() if args.all else changed_ids(args.since)
    if not ids:
        log("no entry pages changed - nothing to submit")
        return 0

    urls = urls_for(ids)
    log(f"{len(ids)} entries changed -> {len(urls)} URLs")

    if args.dry_run:
        for u in urls[:20]:
            log(u)
        if len(urls) > 20:
            log(f"... and {len(urls) - 20} more")
        log(f"key {key} at {key_location}")
        return 0

    deployed = True
    if not args.no_wait and not args.all:
        deployed = wait_for_deploy(ids, args.wait)

    results = submit(urls, key, key_location)

    stamp = datetime.now(timezone.utc)
    logdir = ROOT / "research" / "daily"
    logdir.mkdir(parents=True, exist_ok=True)
    (logdir / f"indexnow-{stamp:%Y-%m-%d}.json").write_text(
        json.dumps(
            {
                "at": stamp.isoformat(),
                "deploy_confirmed": deployed,
                "urls": urls,
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if all(r["status"] in (200, 202) for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
