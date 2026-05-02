# specs.md — Ubuntu debsecan Feed Repository

## Purpose

Provide a self-hosted, GitHub Pages–served vulnerability database that lets
`debsecan` work correctly on Ubuntu systems (Noble, Jammy, Focal, etc.) by
acting as a drop-in replacement for the Debian security tracker URL that 404s
on Ubuntu codenames.

Usage after deployment:

```bash
debsecan --suite $(lsb_release --codename --short) \
         --source https://<your-github-username>.github.io/<repo-name>/
```

---

## Background: Why the Default URL Fails

`debsecan` fetches its vulnerability database from:

```
https://security-tracker.debian.org/tracker/debsecan/release/1/<SUITE>
```

where `<SUITE>` is the result of `lsb_release --codename --short`. Debian
codenames (`bookworm`, `bullseye`, …) exist there; Ubuntu codenames (`noble`,
`jammy`, …) do not, hence the 404.

The `--source` flag overrides the base URL. debsecan will then fetch:

```
<SOURCE_URL>/release/1/<SUITE>
```

So the repository must serve files at exactly:

```
/release/1/noble
/release/1/jammy
/release/1/focal
/release/1/bionic
/release/1/GENERIC          ← suite-independent generic database
```

---

## debsecan Database Format (Version 1)

Each file must begin with the ASCII header:

```
VERSION 1
```

Any other first line causes debsecan to abort. The rest of the file contains
**three sections** separated by a single blank line:

### Section 1 — Vulnerability list

One entry per line, three comma-separated fields:

```
<name>,<flags>,<desc>
```

| Field   | Notes |
|---------|-------|
| `name`  | CVE identifier, e.g. `CVE-2024-1234` |
| `flags` | Unused by debsecan; use empty string |
| `desc`  | One-line description, max 74 chars |

Entries must be **lexicographically sorted** by name (debsecan does not
require it functionally but the original tracker enforces it).

### Section 2 — Vulnerable package list

One entry per line, five comma-separated fields:

```
<package>,<vnum>,<flags>,<unstable_version>,<other_versions>
```

| Field              | Notes |
|--------------------|-------|
| `package`          | Binary package name |
| `vnum`             | Zero-based index into Section 1 (which CVE this refers to) |
| `flags`            | 4 positional characters (see below) |
| `unstable_version` | First fixed version in Debian unstable; empty if unknown |
| `other_versions`   | Space-separated list of other non-vulnerable versions |

**Flags field** — exactly 4 characters, all positions mandatory:

| Position | Meaning         | Values |
|----------|-----------------|--------|
| 0        | Package type    | `B` = binary, anything else = source |
| 1        | Urgency         | `L` low, `M` medium, `H` high, ` ` undefined |
| 2        | Remote          | `R` remote, ` ` local, `?` unknown |
| 3        | Fix available   | `F` fixed in current suite, anything else = not fixed |

Example: `BH R ` = binary package, high urgency, remotely exploitable, no fix.

In the GENERIC database, the Fix Available flag is always non-`F` because
fix availability is suite-specific.

### Section 3 — Source-to-binary package map

Comma-separated pairs `<source>:<binary>`. Empty for the GENERIC database.

### Full Example

```
VERSION 1

CVE-2024-1234,,Remote code execution in libfoo (heap overflow in parse_)
CVE-2024-5678,,Denial of service in curl (infinite loop on malformed inp)

libfoo2,0,BH RF,2.1.3-1,
curl,1,BM R ,8.5.0-1,8.4.0-2ubuntu1

libfoo:libfoo2,libfoo:libfoo-dev
```

---

## Data Sources

### Primary: Ubuntu CVE Tracker (git)

The canonical source is the Canonical-maintained git repository:

```
git clone https://git.launchpad.net/ubuntu-cve-tracker
```

Each file in `active/` and `retired/` represents one CVE. Key fields in each
file (INI-like format):

```
Candidate: CVE-YYYY-NNNN
Priority: negligible | low | medium | high | critical
Description: <one-line summary>

noble_<pkg>: needed | not-affected | released (<version>) | ignored | DNE | deferred | pending
jammy_<pkg>: …
focal_<pkg>: …
```

The generator script reads these files to build per-suite debsecan feeds.

### Secondary: Ubuntu OVAL

Canonical publishes OVAL XML for every supported release at:

```
https://security-metadata.canonical.com/oval/com.ubuntu.<codename>.cve.oval.xml.bz2
```

OVAL data is richer (includes CVSS, USN links, fix version strings) but
harder to parse. It can be used as a fallback to fill in `unstable_version`
and urgency when the git tracker is unavailable.

### Urgency Mapping

Ubuntu priorities map to debsecan urgency flags as follows:

| Ubuntu priority | debsecan urgency flag |
|----------------|-----------------------|
| `negligible`   | `L`                   |
| `low`          | `L`                   |
| `medium`       | `M`                   |
| `high`         | `H`                   |
| `critical`     | `H`                   |

---

## Repository Structure

```
<repo-root>/
├── README.md
├── release/
│   └── 1/
│       ├── GENERIC          ← suite-agnostic, no fix-version info
│       ├── noble            ← Ubuntu 24.04 LTS
│       ├── jammy            ← Ubuntu 22.04 LTS
│       ├── focal            ← Ubuntu 20.04 LTS
│       └── bionic           ← Ubuntu 18.04 LTS (ESM)
├── scripts/
│   ├── generate.py          ← main generator
│   ├── parse_uct.py         ← ubuntu-cve-tracker parser
│   ├── map_packages.py      ← source→binary package expander
│   └── requirements.txt
└── .github/
    └── workflows/
        └── update.yml       ← nightly CI/CD
```

GitHub Pages is configured to serve from the **root** of the `gh-pages`
branch (or `main` with `/docs` root — root branch is simpler). The
`release/1/<codename>` files are plain UTF-8 text, served without compression
(debsecan does not request gzip for this endpoint).

---

## Supported Suites

| Codename | Ubuntu Release | Status        |
|----------|----------------|---------------|
| `noble`  | 24.04 LTS      | Active        |
| `jammy`  | 22.04 LTS      | Active        |
| `focal`  | 20.04 LTS      | ESM           |
| `bionic` | 18.04 LTS      | ESM (legacy)  |
| `GENERIC`| (any)          | Always built  |

New codenames (e.g. `oracular`, `plucky`) should be added as Ubuntu releases
them. EOL releases can be retained in the repo indefinitely with a static
snapshot.

---

## Content Rules

1. Only include CVEs with status `needed`, `pending`, or `deferred` for a
   given suite in the per-suite feeds. Status `released`, `not-affected`,
   `DNE`, and `ignored` entries are excluded.

2. For the GENERIC database include all CVEs where **any** supported suite has
   a non-resolved status. Set the Fix Available flag to non-`F`.

3. The `unstable_version` field in per-suite feeds should be populated with
   the `released` version string from the `upstream_<pkg>` line in the UCT
   file when available. Leave empty otherwise.

4. The `other_versions` field lists versions from other suites that are known
   to be fixed, space-separated.

5. Package names in Section 2 must be **binary** package names (debsecan
   displays binary names to users). Use the APT/UCT source-to-binary mapping
   to expand source package names.

6. Sections 1 and 2 must each be sorted lexicographically (by CVE name and by
   package name respectively).

---

## Security & Freshness

- The `gh-pages` branch is **public and read-only** for consumers.
- The generator runs in GitHub Actions with read-only access to the UCT git
  clone and no secrets.
- Files are regenerated nightly (or on push to `main`).
- A `metadata.json` file at the repo root records the last successful
  generation timestamp and CVE count per suite.

---

## Limitations vs. Debian's Tracker

- Fix availability detection (`F` flag) is based on the UCT `released` status;
  it does not query the Ubuntu archive for actual package availability in
  every PPA/pocket.
- The `unstable_version` field uses upstream fix versions, not
  Ubuntu-specific version strings. debsecan's version comparison may
  therefore sometimes yield false positives (marking a package as
  unfixed when a backported Ubuntu fix exists without a matching version).
- ESM-only fixes (Ubuntu Pro) are not distinguished from public fixes in
  the feed. Consider adding a note in `desc` for ESM-only coverage.
