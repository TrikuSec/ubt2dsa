# ubt2dsa

Ubuntu `debsecan` feed mirror served via GitHub Pages.

This repository publishes debsecan database files for Ubuntu suites so `debsecan`
works with Ubuntu codenames (`noble`, `jammy`, etc.) instead of Debian-only
tracker endpoints.

## Quickstart

```bash
debsecan --suite "$(lsb_release --codename --short)" \
         --source "https://trikusec.github.io/ubt2dsa/" \
         --format summary
```

Published paths:

- `https://trikusec.github.io/ubt2dsa/release/1/noble`
- `https://trikusec.github.io/ubt2dsa/release/1/jammy`
- `https://trikusec.github.io/ubt2dsa/release/1/focal`
- `https://trikusec.github.io/ubt2dsa/release/1/bionic`
- `https://trikusec.github.io/ubt2dsa/release/1/GENERIC`

## Local generation

```bash
git clone https://github.com/trikusec/ubt2dsa.git
cd ubt2dsa
git clone --depth=1 https://git.launchpad.net/ubuntu-cve-tracker uct
python3 scripts/generate.py --uct uct --out release/1 --metadata metadata.json
```

## Data source and caveats

- Primary source: Canonical Ubuntu CVE Tracker (`active/`, `retired/` files).
- Binary package mapping is resolved from Ubuntu `Packages.gz` indices
  (`main`, `restricted`, `universe`, `multiverse`; release/updates/security).
- ESM-only fixes are not currently split from public fixes in debsecan output.
- Version-based fixed detection can still produce false positives for some
  Ubuntu backports.

## Contributing / reporting issues

If you spot an incorrect CVE/package mapping, open an issue in this repo and
include:

- CVE ID
- Ubuntu suite
- Package name
- Expected status and source reference

## Historical context

This project is a successor in spirit to earlier work such as
`BBVA/ust2dsa` (archived).
