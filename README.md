# GPU Vulnerability Database

An open, community-maintained database of vulnerabilities in the stack that GPU infrastructure
runs on — from BMC and GPU firmware up through drivers, containers, orchestration, and model
serving.

**Website: [gpuvulndb.org](https://gpuvulndb.org) · Data: [`entries/`](entries) · Schema: [`schema/entry.schema.json`](schema/entry.schema.json)**

It is built for the people who have to operate this stack: GPU clouds, colocation datacenters,
HPC centers, and enterprises running their own accelerator fleets.

## Why this exists

There is no shortage of vulnerability databases. There is a specific and checkable gap in them.

**The package-centric databases cannot represent this hardware.** The [OSV schema](https://ossf.github.io/osv-schema/)
keys every record to a package name inside a registry or distro, its ecosystem list is closed and
curated in a single file, and its top level is `additionalProperties: false`. There is no ecosystem
for firmware, BMC images, BIOS, or a vendor GPU driver shipped as a `.run` installer, and no way to
add one without changing the spec. The GitHub Advisory Database inherits this: its bulk unreviewed
entries carry an empty `affected` array, so they are CVE text with no machine-matchable target at
all.

**NVD tells you a score, not what to do.** A CVSS vector does not tell an operator whether
remediation means a config change, a daemon restart, draining every GPU node, or flashing firmware
across a fleet — and for this stack, that difference is the entire cost of the fix.

**The cloud vulnerability databases cover the provider's services, not the substrate.**
[cloudvulndb.org](https://www.cloudvulndb.org/) catalogues cross-tenant issues in hyperscaler
*services*, where remediation is usually the provider's job and already done. Here, you are the
provider. Nobody patches it for you.

So every entry in this database carries three fields that a CVE record does not: what an attacker
actually gets, who has to be able to reach it, and what the operator has to do about it.

## What's in scope

3,450 entries covering 3,344 distinct CVEs, spanning 2011 to 2026.

| Layer | What it covers | Entries |
| --- | --- | ---: |
| `gpu-stack` | GPU drivers, firmware, CUDA, container toolkit, vGPU, ROCm, Gaudi | 1,170 |
| `firmware-bmc-fabric` | BMC/IPMI/Redfish, BIOS/UEFI, NVLink, InfiniBand, DPUs, PDUs, cooling | 1,136 |
| `container-orchestration` | Container runtimes, Kubernetes, schedulers, service mesh | 380 |
| `kernel-hypervisor` | Host kernel, userspace, virtualization, microcode | 317 |
| `ai-serving` | Inference servers, training frameworks, model formats | 254 |
| `control-plane` | Cluster management, storage, CI/CD, observability | 193 |

Design-level weaknesses that will never receive a CVE — unauthenticated IPMI over LAN, RDMA
fabrics with no cryptographic binding between a packet and its connection, physical DRAM
interposers that both Intel and AMD classify as out of scope — are in scope and carry an `NCVD-`
id. There are 106 of them, and they are frequently a bigger problem than anything with a CVSS
score. They also cannot be represented in NVD, OSV, or any advisory-passthrough database, which
is a large part of why this one exists.

## Cost to remediate

The field that makes this more than an advisory mirror. A CVSS score tells you how bad a
vulnerability is; it does not tell you whether fixing it costs a config change or a firmware
flash across every node you own. 2,090 entries carry a `fleet.pain_class`, ordered here from
cheapest to most disruptive:

| Class | Entries | What it means |
| --- | ---: | --- |
| `hot-patch` | 50 | Fixable without interrupting workloads |
| `daemon-restart` | 54 | Service restart on affected nodes |
| `node-drain` | 160 | Tenant workloads evicted from each node |
| `node-reboot` | 1,163 | Full reboot of each affected node |
| `microcode + reboot` | 54 | Microcode update and a reboot |
| `firmware-flash` | 510 | Firmware flash, usually with the node out of service |
| `physical access` | 2 | Someone has to be at the machine |
| `unpatchable / mitigate-only` | 93 | **No vendor fix exists** |

These are extracted from remediation prose that names the action, never guessed. Where a
remediation does not state a cost, the field is left unset rather than inferred — 1,360 entries
are in that state.

Out of scope: vulnerabilities with no plausible path to GPU infrastructure, undisclosed issues
(this is not a disclosure venue), and anything you cannot back with a public reference.

## Entry status

Every entry declares how much human verification it has had. This is deliberate: it lets the
database ship broad coverage without pretending all of it is hand-checked.

- **`curated`** — imported from vendor advisories, NVD, and CISA KEV with machine assistance, then
  annotated for operators. Not individually verified against primary sources. **The seed corpus is
  all at this tier.**
- **`reviewed`** — a maintainer confirmed every field against primary sources and signed it with
  their GitHub handle.
- **`stub`** — references only, no analysis yet. A good first contribution.

Always confirm against your vendor's advisory before acting on an entry.

## Using the data

Entries are one JSON file each, at `entries/<year>/<id>.json`. The filename is always the id.
There is no build artifact to trust and no API to depend on — clone the repo.

```bash
git clone https://github.com/liranmarkin/gpu-vulndb
jq -r 'select(.kev and .layer=="gpu-stack") | .id + "  " + .title' entries/*/*.json
```

The website also serves the whole corpus as a single file at
[gpuvulndb.org/data.json](https://gpuvulndb.org/data.json), CORS-open so you can fetch it from
anywhere. There is an RSS feed at [/feed.xml](https://gpuvulndb.org/feed.xml).

## Repository layout

```
entries/<year>/<id>.json   the database — one file per entry, the source of truth
schema/entry.schema.json   the schema, enforced in CI
scripts/validate.py        what CI runs; run it before opening a pull request
scripts/ingest.py          merges researched batches into entries/, idempotent
scripts/derive_pain.py     extracts remediation cost from prose that states it
scripts/build.py           one-off importer from the original source CSVs, not part of contributing
web/                       the website (Next.js 16, React 19, Tailwind 4)
```

The site reads `entries/` straight off disk at build time, so nothing generated is ever committed
and the data has no toolchain of its own. Contributing an entry needs a text editor and Python;
only working on the site itself needs Node.

```bash
cd web && npm install && npm run dev
```

## Contributing

Corrections, additions, and promotions from `curated` to `reviewed` are all welcome. Reviewing an
existing entry against its primary sources is the single most useful thing you can do here.

See [CONTRIBUTING.md](CONTRIBUTING.md). Every pull request is validated in CI against the schema —
if `scripts/validate.py` passes locally, it will pass in CI.

```bash
python3 -m venv .venv && .venv/bin/pip install jsonschema
.venv/bin/python scripts/validate.py
```

## License

Data in `entries/` and `schema/` is [CC BY 4.0](LICENSE-DATA). Tooling in `scripts/` and the site
in `web/` is [MIT](LICENSE). Attribution to the GPU Vulnerability Database is required when you
redistribute the data.

This database is informational and carries no warranty of completeness or accuracy.
