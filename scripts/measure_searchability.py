#!/usr/bin/env python3
"""Reproducible measurement of keyword-search invisibility in kernel CVE records.

Corpus: git.kernel.org/pub/scm/linux/security/vulns.git, cve/published/**/CVE-*.json
Each record is a CVE 5.x JSON container published by the Linux kernel CNA.

Selection: a record is IN SCOPE if any string in
  containers.cna.affected[].programFiles[]
starts with one of the PREFIXES below. programFiles is the affected-source-path
list; it is CNA container metadata and is NOT reproduced in the NVD record.

Measurement: of the in-scope records, how many could be found by a keyword search
over the CVE description? NVD's keywordSearch matches the description text, and
NVD carries the CNA English description verbatim, so
  containers.cna.descriptions[lang=en].value
is the correct proxy for what a keyword search can see.
"""
import json, glob, re, sys, collections

ROOT = 'vulns/cve/published/*/CVE-*.json'
PREFIXES = [
    'drivers/infiniband',              # RDMA core, uverbs, HCA drivers, ULPs
    'drivers/nvme/',                   # trailing slash: excludes drivers/nvmem/
    'drivers/net/ethernet/mellanox',   # mlx4/mlx5/mlxsw/mlxfw
    'net/smc',                         # SMC-R / SMC-D (RDMA sockets)
    'net/rds',                         # RDS (Reliable Datagram Sockets over IB)
]

# Keyword sets, from what a vendor-name search would use to what a
# well-informed analyst who already knows the subsystem names would use.
KEYWORD_SETS = {
    'vendor-only (Mellanox|InfiniBand|NVIDIA|ConnectX)':
        r'mellanox|infiniband|nvidia|connectx',
    'vendor + fabric terms (adds RDMA|RoCE|iWARP|NVMe|SMC-R)':
        r'mellanox|infiniband|nvidia|connectx|\brdma\b|\broce\b|iwarp|\bnvme\b|smc-r',
    'subsystem-aware (adds mlx4|mlx5|rxe|siw|nvmet|uverbs|ib_)':
        r'mellanox|infiniband|nvidia|connectx|\brdma\b|\broce\b|iwarp|\bnvme\b|smc-r'
        r'|\bmlx[45]\b|\brxe\b|\bsiw\b|nvmet|uverbs|\bib_',
}

# A description often embeds an oops/KASAN splat that quotes source paths such as
# "drivers/infiniband/sw/rxe/rxe_comp.c:740". That is an incidental substring, not
# a description of the affected product - a keyword search on it is an accident,
# not a method. Measure both with and without those.
PATH_TOKEN = re.compile(r'(?:drivers|net|include)/[A-Za-z0-9_./-]+')


def load():
    recs = []
    for f in glob.glob(ROOT):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        cna = d.get('containers', {}).get('cna', {})
        cid = d.get('cveMetadata', {}).get('cveId')
        if not cid:
            continue
        files = set()
        for a in cna.get('affected', []):
            for p in a.get('programFiles', []) or []:
                files.add(p)
        desc = ''
        for x in cna.get('descriptions', []):
            if x.get('lang') == 'en':
                desc = x.get('value', '')
        recs.append((cid, files, desc))
    return recs


def main():
    recs = load()
    print(f'total published kernel CVE records parsed: {len(recs)}')

    per_prefix = collections.OrderedDict((p, set()) for p in PREFIXES)
    inscope = {}
    for cid, files, desc in recs:
        hit = False
        for p in PREFIXES:
            if any(f.startswith(p) for f in files):
                per_prefix[p].add(cid)
                hit = True
        if hit:
            inscope[cid] = desc

    print(f'\nIN SCOPE (union of prefixes): {len(inscope)}')
    print('per-prefix record counts (a record touching two prefixes is counted in both):')
    for p, s in per_prefix.items():
        print(f'  {p:35s} {len(s)}')
    print(f'  {"sum of per-prefix":35s} {sum(len(s) for s in per_prefix.values())}'
          f'  (> union by {sum(len(s) for s in per_prefix.values()) - len(inscope)} multi-path records)')

    for label, pat in KEYWORD_SETS.items():
        rx = re.compile(pat, re.I)
        raw, stripped = set(), set()
        for cid, desc in inscope.items():
            if rx.search(desc):
                raw.add(cid)
            if rx.search(PATH_TOKEN.sub(' ', desc)):
                stripped.add(cid)
        print(f'\n--- keyword set: {label}')
        print(f'  findable, description as-is:            {len(raw):4d}'
              f'  ({100*len(raw)/len(inscope):.1f}%)   invisible: {len(inscope)-len(raw)}'
              f'  ({100*(len(inscope)-len(raw))/len(inscope):.1f}%)')
        print(f'  findable, quoted source paths removed:  {len(stripped):4d}'
              f'  ({100*len(stripped)/len(inscope):.1f}%)   invisible: {len(inscope)-len(stripped)}'
              f'  ({100*(len(inscope)-len(stripped))/len(inscope):.1f}%)')
        # per-prefix invisibility for the as-is measurement
        print('  per-prefix invisible (description as-is):')
        for p, s in per_prefix.items():
            inv = len(s - raw)
            print(f'    {p:33s} {inv:4d}/{len(s):4d}  ({100*inv/len(s):.1f}%)')

    cov = set(open('covered.txt').read().split())
    print(f'\nin-scope records already in gpu-vulndb: {len(set(inscope) & cov)}')
    print(f'in-scope records NOT already in gpu-vulndb: {len(set(inscope) - cov)}')

    json.dump(sorted(inscope), open('inscope_ids.json', 'w'), indent=0)


if __name__ == '__main__':
    main()
