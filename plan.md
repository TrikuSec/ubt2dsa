# plan.md — Implementation Plan

## Goal

A GitHub repository that automatically generates and serves debsecan-compatible
vulnerability databases for Ubuntu codenames via GitHub Pages, refreshed
nightly from Canonical's Ubuntu CVE Tracker.

---

## Phase 1 — Repository Bootstrap

**Objective:** Working skeleton, manual generation, no CI yet.

### 1.1 Create the repository

```bash
gh repo create ubuntu-debsecan-feed --public
cd ubuntu-debsecan-feed
git checkout --orphan gh-pages   # output branch
git checkout -b main             # working branch
```

Configure GitHub Pages in repository Settings → Pages → Source: `gh-pages`
branch, root `/`.

### 1.2 Scaffold directory layout

```
scripts/
  generate.py          # orchestrator
  parse_uct.py         # UCT file parser
  map_packages.py      # source→binary expander
  requirements.txt     # python-apt, requests (or none)
release/1/             # output goes here (on gh-pages branch)
.github/workflows/
  update.yml
README.md
```

### 1.3 Write the UCT parser (`parse_uct.py`)

Clone the Ubuntu CVE Tracker:

```bash
git clone --depth=1 https://git.launchpad.net/ubuntu-cve-tracker uct/
```

Parse each file in `uct/active/` and `uct/retired/`. Each file has the
structure:

```
Candidate: CVE-YYYY-NNNN
Priority: medium
Description: short description here
...
<release>_<srcpkg>: <status> (<version>)
```

Key parsing rules:
- Lines starting with a release codename (`noble_`, `jammy_`, etc.) are
  package-status lines.
- The status is the word before the optional `(version)` in parentheses.
- `upstream_<pkg>:` lines carry the upstream fix version (populate
  `unstable_version`).
- Ignore `Patches_*`, `Tags_*`, `Bugs_*` fields for feed generation.

Output data model per CVE:

```python
{
  "id": "CVE-2024-1234",
  "priority": "medium",
  "desc": "...",
  "packages": {
    "noble": {
      "srcpkg": {"status": "needed", "version": None}
    },
    "jammy": { ... }
  },
  "upstream_versions": {
    "srcpkg": "2.1.3-1"
  }
}
```

**Deliverable:** `parse_uct.py` with unit tests for a handful of representative
UCT files (packages with DNE, released, needed, ignored entries).

### 1.4 Write the package name expander (`map_packages.py`)

debsecan requires binary package names in Section 2. The mapping is built by
querying the Ubuntu archive's `Packages` index files:

```
https://archive.ubuntu.com/ubuntu/dists/<codename>/main/binary-amd64/Packages.gz
https://archive.ubuntu.com/ubuntu/dists/<codename>-security/main/binary-amd64/Packages.gz
```

Parse each stanza for `Package:` (binary name) and `Source:` (source name,
defaulting to binary name when absent). Build and cache a dict:

```python
source_to_binaries = {
  "openssl": ["libssl3", "libssl-dev", "openssl", ...],
  ...
}
```

Cache per codename to avoid re-downloading on every run.

**Deliverable:** `map_packages.py` with a `get_binary_packages(suite, srcpkg)`
function.

### 1.5 Write the generator (`generate.py`)

For each suite in `[noble, jammy, focal, bionic]` and for `GENERIC`:

1. Filter the CVE list:
   - Per-suite: keep CVEs where the suite has at least one package with status
     `needed`, `pending`, or `deferred`.
   - GENERIC: keep CVEs where any suite has such a status.
2. Sort CVEs by name to build Section 1.
3. For each CVE, expand source packages to binary packages. Build Section 2
   rows, computing flags from priority + remoteness heuristic (default to
   `?` for remote unless UCT has explicit data).
4. Build Section 3 source-to-binary map (empty for GENERIC).
5. Write the `VERSION 1\n\n<s1>\n\n<s2>\n\n<s3>` file.

Output files go to `release/1/<suite>`.

**Deliverable:** Running `python scripts/generate.py` produces all feed files
locally. Validate with:

```bash
debsecan --suite noble \
         --source file://$(pwd)/ \
         --format bugs | head -20
```

---

## Phase 2 — GitHub Actions Automation

**Objective:** Nightly automated regeneration and push to `gh-pages`.

### 2.1 Write the workflow (`.github/workflows/update.yml`)

```yaml
name: Update CVE feed

on:
  schedule:
    - cron: '0 4 * * *'   # 04:00 UTC daily
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Checkout gh-pages
        run: git worktree add gh-pages-out gh-pages

      - name: Clone UCT (shallow)
        run: |
          git clone --depth=1 \
            https://git.launchpad.net/ubuntu-cve-tracker uct

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r scripts/requirements.txt

      - name: Generate feeds
        run: python scripts/generate.py --uct uct/ --out gh-pages-out/release/1/

      - name: Write metadata
        run: python scripts/generate.py --metadata gh-pages-out/metadata.json

      - name: Commit and push
        run: |
          cd gh-pages-out
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add -A
          git diff --cached --quiet || \
            git commit -m "chore: update CVE feeds $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push origin gh-pages
```

### 2.2 Validate end-to-end

After the first successful workflow run:

```bash
debsecan --suite noble \
         --source https://<username>.github.io/<repo>/ \
         --format summary
```

Expected: output listing CVEs for installed packages, not a 404.

---

## Phase 3 — Quality & Completeness

**Objective:** Improve flag accuracy, add fix-version detection, handle edge
cases.

### 3.1 Remote-exploitability flag

The UCT files do not have a structured remote field. Apply these heuristics
to set position 2 of the flags:

- If the CVE description or NVD data contains "network", "remote", "HTTP",
  "TCP", "UDP" → `R`
- If it contains "local privilege", "local exploit" → ` ` (space, local)
- Otherwise → `?` (unknown)

Optionally, enrich from the NVD CVE API:

```
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
```

The `cvssMetricV31[].cvssData.attackVector` field gives `NETWORK`, `ADJACENT`,
`LOCAL`, or `PHYSICAL`.

### 3.2 Fix-version accuracy

For per-suite feeds, populate `unstable_version` using the version string from
`released (<version>)` in the `upstream_<pkg>` UCT line. For the `F` flag
(fix available in the current suite):

- Set to `F` only when the suite's package status is `released`.
- Since we already filter those out of the suite feed (Phase 1.5 rule #1),
  `F` flags will be rare — they appear when a package is fixed in one arch
  but the suite line still shows `pending`.

### 3.3 Source-to-binary completeness

`universe` and `multiverse` components should also be scraped:

```
dists/<codename>/universe/binary-amd64/Packages.gz
dists/<codename>/multiverse/binary-amd64/Packages.gz
```

Also include `<codename>-updates` and `<codename>-security` pockets so that
backported fix versions are captured.

### 3.4 ESM annotation

CVEs where only a `released-esm` fix exists (Ubuntu Pro required) should be
flagged in the `desc` field with a `[ESM]` prefix so users are informed.

---

## Phase 4 — Observability & Documentation

### 4.1 `metadata.json`

Published at the root of the gh-pages branch:

```json
{
  "generated_at": "2026-05-02T04:12:33Z",
  "uct_commit": "abc1234",
  "suites": {
    "noble":  { "cves": 312, "packages": 891 },
    "jammy":  { "cves": 289, "packages": 834 },
    "focal":  { "cves": 201, "packages": 612 },
    "bionic": { "cves": 87,  "packages": 243 },
    "GENERIC":{ "cves": 398, "packages": 0   }
  }
}
```

### 4.2 README

The repository README must document:

- Quickstart (`debsecan --source …` command)
- How to contribute / report data errors
- Relationship to upstream UCT and Canonical data
- Caveat: ESM-only fixes, version comparison limitations
- Link to BBVA/ust2dsa (predecessor, archived) for historical context

### 4.3 Diff alerting (optional)

Add a step to the workflow that posts a brief Slack/Discord/email summary
when the total CVE count changes by more than ±50 across any suite, signalling
a large batch update or a data regression.

---

## Milestone Summary

| Milestone | Deliverable | Effort |
|-----------|-------------|--------|
| M1 — Phase 1 | Generator produces valid feed files locally | ~1 day |
| M2 — Phase 2 | Nightly CI pushes feeds; debsecan works end-to-end | ~0.5 day |
| M3 — Phase 3 | Remote flag, fix-version, universe packages | ~1 day |
| M4 — Phase 4 | Metadata, README, diff alerting | ~0.5 day |

Total estimated effort: **~3 developer-days** for a complete, production-ready
feed.

---

## Quick-start Command Reference

```bash
# Clone repo and generate feeds locally
git clone https://github.com/<you>/ubuntu-debsecan-feed
cd ubuntu-debsecan-feed
git clone --depth=1 https://git.launchpad.net/ubuntu-cve-tracker uct/
pip install -r scripts/requirements.txt
python scripts/generate.py --uct uct/ --out release/1/

# Test with debsecan pointing at local files
debsecan --suite noble \
         --source "file://$(pwd)/" \
         --format summary

# Use the published GitHub Pages feed
debsecan --suite $(lsb_release --codename --short) \
         --source "https://<you>.github.io/ubuntu-debsecan-feed/"
```
