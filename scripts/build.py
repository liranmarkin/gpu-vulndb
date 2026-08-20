#!/usr/bin/env python3
"""Build the entry corpus and the site data file from the curated source CSVs."""

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "entries"
SITE = ROOT / "site"

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})")
# In the cve column a parenthetical is always the marketing name: CVE-2023-43654 (ShellTorch).
PAREN_RE = re.compile(r"\(([^)]{2,60})\)")
# In the component column only a *quoted* parenthetical is a name; bare ones such as
# "Linux kernel (uvcvideo)" are scope qualifiers and must stay part of the component.
QUOTED_RE = re.compile(r'["“]([^"”]{2,60})["”]')
QUOTED_PAREN_RE = re.compile(r'\s*\(\s*["“][^"”]{2,60}["”]\s*\)')

LAYERS = {
    "NVIDIA / GPU stack": "gpu-stack",
    "Firmware, BMC & network fabric": "firmware-bmc-fabric",
    "Container, Kubernetes & orchestration": "container-orchestration",
    "AI/ML frameworks & serving": "ai-serving",
    "Control plane, storage & DevOps": "control-plane",
    "Kernel, userspace & hypervisor": "kernel-hypervisor",
}

SEVERITY = {
    "Critical (9.0-10.0)": "critical",
    "High (7.0-8.9)": "high",
    "Medium (4.0-6.9)": "medium",
    "Low (0.1-3.9)": "low",
    "Unscored": "unscored",
}


def slugify(text, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:maxlen].strip("-") or "entry"


def parse_score(raw):
    if not raw:
        return None
    m = re.search(r"\d+(?:\.\d+)?", raw)
    return float(m.group(0)) if m else None


def split_refs(raw):
    if not raw:
        return []
    return [u.strip() for u in re.split(r"[\s,;]+", raw) if u.strip().startswith("http")]


def clean_component(component):
    """Drop the quoted alias, keeping qualifiers like "(uvcvideo)" that narrow the component."""
    return QUOTED_PAREN_RE.sub("", component).strip() or component


def truncate_words(text, limit):
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return cut + "…"


def make_title(component, impact):
    """Titles are derived, not invented: component plus the curated impact summary.

    Splitting on '.' would break `re.compile` and version strings like 3.11, so
    only explicit clause separators are treated as boundaries.
    """
    head = (impact or "").strip()
    head = re.sub(r"^\[KEV\]\s*", "", head)
    head = re.sub(r"\s*[-–—]?\s*\[KEV\b[^\]]*\]?\s*$", "", head)
    head = re.split(r"\s*(?:→|->|;)\s*", head)[0].strip().rstrip(".")
    head = truncate_words(head, 110)
    return f"{component}: {head}" if head else component


def load_fleet():
    """Blast-radius annotations, keyed by CVE id."""
    path = ROOT.parent / "go-big-go-home/directions/datacenter-security/fleet-patch-surface.csv"
    fleet = {}
    if not path.exists():
        return fleet
    for row in csv.DictReader(path.open()):
        m = CVE_RE.search(row.get("cve") or "")
        if not m:
            continue
        fleet[m.group(1)] = {
            k: v.strip()
            for k, v in (
                ("ubiquity", row.get("ubiquity") or ""),
                ("remediation_pain", row.get("remediation_pain") or ""),
                ("pain_class", row.get("pain_class") or ""),
                ("why_fleet_wide", row.get("why_fleet_wide") or ""),
            )
            if v.strip()
        }
    return fleet


def build():
    src = ROOT.parent / "go-big-go-home/directions/datacenter-security/neocloud-cve-catalogue.csv"
    if not src.exists():
        sys.exit(f"source corpus not found: {src}")

    fleet = load_fleet()
    entries, seen, seq = [], set(), {}

    for row in csv.DictReader(src.open()):
        raw_cve = (row.get("cve") or "").strip()
        component = (row.get("component") or "").strip()
        year = (row.get("year") or "").strip()
        layer_name = (row.get("layer") or "").strip()

        m = CVE_RE.search(raw_cve)
        cve = m.group(1) if m else None

        # The CVE id is authoritative for the year, so CVE-2025-33229 files under 2025
        # even when the source row recorded the advisory batch it arrived in.
        if cve:
            year = cve.split("-")[1]

        # Named-vulnerability aliases ("NVIDIAScape", "ShellTorch") appear in either column.
        aliases = []
        for a in PAREN_RE.findall(raw_cve) + QUOTED_RE.findall(component):
            a = a.strip().strip('"“”')
            if a and not CVE_RE.search(a) and a not in aliases:
                aliases.append(a)
        component = clean_component(component)

        if cve:
            entry_id = cve
        else:
            # Design-level weaknesses that have no CVE and never will.
            y = year if re.fullmatch(r"\d{4}", year) else "0000"
            seq[y] = seq.get(y, 0) + 1
            entry_id = f"NCVD-{y}-{seq[y]:03d}-{slugify(component, 32)}"

        if entry_id in seen:
            continue
        seen.add(entry_id)

        score = parse_score(row.get("cvss"))
        sev_raw = (row.get("severity") or "").strip()

        entry = {
            "id": entry_id,
            "cve": cve,
            "aliases": aliases,
            "title": make_title(component, row.get("impact")),
            "layer": LAYERS.get(layer_name, slugify(layer_name)),
            "layer_name": layer_name,
            "component": component,
            "year": year,
            "cvss_score": score,
            "severity": SEVERITY.get(sev_raw, slugify(sev_raw) if sev_raw else "unscored"),
            "kev": (row.get("kev") or "").strip().lower() == "yes",
            "impact": (row.get("impact") or "").strip(),
            "attack_vector": (row.get("attack_vector") or "").strip(),
            "remediation": (row.get("remediation") or "").strip(),
            "references": split_refs(row.get("reference")),
            # Honesty tier. The seed corpus was bulk-curated from vendor advisories with
            # machine assistance; "reviewed" is earned once a human confirms an entry
            # against primary sources. Never set "reviewed" from this script.
            "status": "curated",
        }
        if cve and cve in fleet:
            entry["fleet"] = fleet[cve]

        entries.append(entry)

    entries.sort(key=lambda e: (-(e["cvss_score"] or 0), e["id"]))
    write_entries(entries)
    write_site_data(entries)
    return entries


def write_entries(entries):
    for old in ENTRIES.rglob("*.json"):
        old.unlink()
    for e in entries:
        year = e["year"] if re.fullmatch(r"\d{4}", e["year"]) else "undated"
        d = ENTRIES / year
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{e['id']}.json").write_text(json.dumps(e, indent=2, ensure_ascii=False) + "\n")


def write_site_data(entries):
    """Trimmed payload for the client-side site; full prose stays in the entry files."""
    SITE.mkdir(parents=True, exist_ok=True)
    (SITE / "data.json").write_text(
        json.dumps({"entries": entries}, ensure_ascii=False, separators=(",", ":")) + "\n"
    )


# ----------------------------------------------------------------- page rendering

SITE_URL = "https://gpuvulndb.org"
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "unscored": "Unscored"}
PAIN_HINT = {
    "hot-patch": "Patchable without interrupting workloads.",
    "daemon-restart": "Needs a service restart on affected nodes.",
    "node-drain": "Needs tenant workloads evicted from each node.",
    "node-reboot": "Needs a full reboot of each affected node.",
    "microcode + reboot": "Needs a microcode update and a reboot.",
    "firmware-flash": "Needs a firmware flash, usually with the node out of service.",
    "physical access": "Needs someone physically at the machine.",
    "unpatchable / mitigate-only": "No vendor fix. Mitigation is the only option.",
}


def esc(text):
    return (str(text if text is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def inline_code(text):
    """Render the backtick spans in the curated prose, after escaping."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(text))


def field(heading, value):
    return f"<div class=\"field\"><h3>{heading}</h3><p>{inline_code(value)}</p></div>" if value else ""


def render_page(e):
    score = f"{e['cvss_score']:.1f}" if e.get("cvss_score") is not None else "—"
    sev = e["severity"]
    ident = e.get("cve") or e["id"]

    tags = [f'<span class="tag">{esc(ident)}</span>',
            f'<span class="tag">{esc(e["layer_name"])}</span>']
    if e.get("kev"):
        tags.append('<span class="tag kev">Known exploited</span>')
    tags += [f'<span class="tag alias">{esc(a)}</span>' for a in e.get("aliases", [])]
    tags.append(f'<span class="tag status">{esc(e.get("status", "curated"))}</span>')

    fleet = e.get("fleet") or {}
    fleet_html = ""
    if fleet:
        inner = (field("How widespread", fleet.get("ubiquity"))
                 + field("Cost to remediate", fleet.get("remediation_pain"))
                 + field("Why it hits the whole fleet", fleet.get("why_fleet_wide")))
        if inner:
            fleet_html = ('<div class="field"><h3>Fleet impact</h3>'
                          f'<div class="callout">{inner}</div></div>')

    refs = "".join(
        f'<a href="{esc(u)}" rel="noopener nofollow" target="_blank">{esc(u)}</a>'
        for u in e.get("references", []))
    refs_html = f'<div class="field"><h3>References</h3><div class="refs">{refs}</div></div>' if refs else ""

    side = [
        f'<div class="side-row"><dt>CVSS</dt>'
        f'<dd class="side-score sev-{sev}">{score} <small>{SEV_LABEL.get(sev, "")}</small></dd></div>',
        f'<div class="side-row"><dt>Identifier</dt><dd class="mono">{esc(ident)}</dd></div>',
        f'<div class="side-row"><dt>Component</dt><dd>{esc(e["component"])}</dd></div>',
        f'<div class="side-row"><dt>Layer</dt><dd>{esc(e["layer_name"])}</dd></div>',
    ]
    if e.get("year"):
        side.append(f'<div class="side-row"><dt>Year</dt><dd class="mono">{esc(e["year"])}</dd></div>')
    if fleet.get("pain_class"):
        pc = fleet["pain_class"]
        hint = PAIN_HINT.get(pc, "")
        side.append(f'<div class="side-row"><dt>Remediation cost</dt>'
                    f'<dd class="mono">{esc(pc)}</dd>'
                    + (f'<dd style="color:var(--dimmer);font-size:12.5px;margin-top:4px">{esc(hint)}</dd>'
                       if hint else "") + '</div>')
    if e.get("kev"):
        side.append('<div class="side-row"><dt>CISA KEV</dt>'
                    '<dd class="sev-critical">Listed as exploited</dd></div>')

    desc = (e.get("impact") or e["title"])[:180]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(ident)} — {esc(e['component'])} | GPU VulnDB</title>
<meta name="description" content="{esc(desc)}">
<link rel="canonical" href="{SITE_URL}/vuln/{esc(e['id'])}">
<meta property="og:title" content="{esc(ident)} — {esc(e['component'])}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:type" content="article">
<meta property="og:url" content="{SITE_URL}/vuln/{esc(e['id'])}">
<link rel="alternate" type="application/rss+xml" title="GPU VulnDB" href="/feed.xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<header class="masthead">
  <div class="wrap">
    <a class="brand" href="/">GPU<span>/</span>VulnDB</a>
    <nav>
      <a href="/#database">Database</a>
      <a href="/data.json">JSON</a>
      <a href="/feed.xml">RSS</a>
      <a href="https://github.com/liranmarkin/gpu-vulndb">GitHub</a>
    </nav>
  </div>
</header>

<main class="wrap">
  <div class="detail-wrap">
    <article>
      <p class="crumb"><a href="/#database">Database</a> ·
        <a href="/?layer={esc(e['layer'])}#database">{esc(e['layer_name'])}</a></p>
      <h2 class="detail-title">{esc(e['title'])}</h2>
      <div class="detail-tags">{''.join(tags)}</div>

      {field("Impact", e.get("impact"))}
      {field("Who can reach it", e.get("attack_vector"))}
      {field("What to do", e.get("remediation"))}
      {fleet_html}
      {refs_html}

      <p class="disclaimer">This entry is <strong>{esc(e.get('status', 'curated'))}</strong>.
      {"It was imported from vendor advisories with machine assistance and has not been individually verified against primary sources." if e.get('status') == 'curated' else "A maintainer verified it against primary sources."}
      Confirm against your vendor's advisory before acting on it, and
      <a href="https://github.com/liranmarkin/gpu-vulndb/issues/new?template=correction.yml">report anything wrong</a>.</p>
    </article>

    <aside>
      <dl class="side">{''.join(side)}</dl>
    </aside>
  </div>
</main>

<footer>
  <div class="wrap">
    <p><strong>GPU Vulnerability Database</strong> — an open community project.
    Data CC BY 4.0. Informational only, with no warranty of completeness.</p>
  </div>
</footer>
</body>
</html>
"""


def write_pages(entries):
    out = SITE / "vuln"
    if out.exists():
        for old in out.glob("*.html"):
            old.unlink()
    out.mkdir(parents=True, exist_ok=True)
    for e in entries:
        (out / f"{e['id']}.html").write_text(render_page(e))


def write_sitemap(entries):
    urls = [f"<url><loc>{SITE_URL}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>"]
    urls += [f"<url><loc>{SITE_URL}/vuln/{esc(e['id'])}</loc></url>" for e in entries]
    (SITE / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls) + "\n</urlset>\n")
    (SITE / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n")


def write_feed(entries):
    """Most severe recent entries. Static hosting, so no real publication dates to sort on."""
    recent = sorted(entries, key=lambda e: (e.get("year") or "", e.get("cvss_score") or 0),
                    reverse=True)[:50]
    items = "".join(
        f"<item><title>{esc((e.get('cve') or e['id']) + ' — ' + e['title'])}</title>"
        f"<link>{SITE_URL}/vuln/{esc(e['id'])}</link>"
        f"<guid isPermaLink=\"true\">{SITE_URL}/vuln/{esc(e['id'])}</guid>"
        f"<description>{esc(e.get('impact') or e['title'])}</description>"
        f"<category>{esc(e['layer_name'])}</category></item>"
        for e in recent)
    (SITE / "feed.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0"><channel>'
        "<title>GPU Vulnerability Database</title>"
        f"<link>{SITE_URL}/</link>"
        "<description>Vulnerabilities in the stack that GPU infrastructure runs on.</description>"
        f"{items}</channel></rss>\n")


if __name__ == "__main__":
    built = build()
    write_pages(built)
    write_sitemap(built)
    write_feed(built)
    kev = sum(1 for e in built if e["kev"])
    crit = sum(1 for e in built if e["severity"] == "critical")
    print(f"entries: {len(built)}  critical: {crit}  kev: {kev}")
    print(f"pages:   {len(built)} under site/vuln/ + sitemap, robots, feed")
