#!/usr/bin/env python3
"""Parser for Ubuntu CVE Tracker files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Dict, Iterable, Optional

KEY_VALUE_RE = re.compile(r"^([A-Za-z0-9_.+:-]+):\s*(.*)$")
SUITE_PKG_RE = re.compile(r"^([a-z0-9]+)_([A-Za-z0-9+.-]+)$")
TRAILING_PARENS_RE = re.compile(r"\(([^()]*)\)\s*$")


@dataclass
class PackageStatus:
    status: str
    version: Optional[str] = None


@dataclass
class CVERecord:
    cve_id: str
    priority: str = "medium"
    description: str = ""
    packages: Dict[str, Dict[str, PackageStatus]] = field(default_factory=dict)
    upstream_versions: Dict[str, str] = field(default_factory=dict)


def parse_status_value(raw_value: str) -> PackageStatus:
    value = raw_value.strip()
    version = None

    m = TRAILING_PARENS_RE.search(value)
    if m:
        version = m.group(1).strip() or None
        value = value[: m.start()].rstrip()

    status = (value.split() or [""])[0].strip().lower()
    return PackageStatus(status=status, version=version)


def parse_uct_file(path: Path, suites: Optional[set[str]] = None) -> Optional[CVERecord]:
    candidate = None
    priority = "medium"
    description = ""
    packages: Dict[str, Dict[str, PackageStatus]] = {}
    upstream_versions: Dict[str, str] = {}

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith(" ") or line.startswith("\t"):
            continue

        kv = KEY_VALUE_RE.match(line)
        if not kv:
            continue

        key, value = kv.group(1), kv.group(2)

        if key == "Candidate":
            candidate = value.strip()
            continue

        if key == "Priority":
            priority = value.strip().lower() or "medium"
            continue

        if key == "Description":
            description = value.strip()
            continue

        if key.startswith("upstream_"):
            srcpkg = key.split("_", 1)[1]
            parsed = parse_status_value(value)
            if parsed.version and parsed.status in {"released", "released-esm"}:
                upstream_versions[srcpkg] = parsed.version
            continue

        suite_match = SUITE_PKG_RE.match(key)
        if not suite_match:
            continue

        suite, srcpkg = suite_match.group(1), suite_match.group(2)
        if suites and suite not in suites:
            continue

        parsed = parse_status_value(value)
        packages.setdefault(suite, {})[srcpkg] = parsed

    if not candidate or not candidate.startswith("CVE-"):
        return None

    return CVERecord(
        cve_id=candidate,
        priority=priority,
        description=description,
        packages=packages,
        upstream_versions=upstream_versions,
    )


def iter_uct_files(uct_root: Path) -> Iterable[Path]:
    for subdir in ("active", "retired"):
        d = uct_root / subdir
        if not d.exists():
            continue
        for path in sorted(d.iterdir()):
            if path.is_file():
                yield path


def parse_uct_repository(uct_root: str | Path, suites: Optional[set[str]] = None) -> list[CVERecord]:
    root = Path(uct_root)
    records: list[CVERecord] = []

    for path in iter_uct_files(root):
        record = parse_uct_file(path, suites=suites)
        if record is not None:
            records.append(record)

    return records
