#!/usr/bin/env python3
"""Generate debsecan-compatible feeds for Ubuntu suites."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from map_packages import PackageMapper
from parse_uct import CVERecord, parse_uct_repository

UNRESOLVED_STATUSES = {"needed", "pending", "deferred"}
URGENCY_MAP = {
    "negligible": "L",
    "low": "L",
    "medium": "M",
    "high": "H",
    "critical": "H",
}
REMOTE_NETWORK_HINTS = ("network", "remote", "http", "https", "tcp", "udp", "socket", "dns")
REMOTE_LOCAL_HINTS = ("local privilege", "local exploit", "local user", "locally")


@dataclass
class FeedResult:
    cve_count: int
    package_rows: int


def sanitize_description(desc: str, max_len: int = 74) -> str:
    text = " ".join(desc.replace(",", ";").split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def detect_remote_flag(description: str) -> str:
    d = description.lower()
    if any(token in d for token in REMOTE_LOCAL_HINTS):
        return " "
    if any(token in d for token in REMOTE_NETWORK_HINTS):
        return "R"
    return "?"


def build_flags(priority: str, description: str, fix_available: bool) -> str:
    urgency = URGENCY_MAP.get(priority.lower(), " ")
    remote = detect_remote_flag(description)
    fixed = "F" if fix_available else " "
    return f"B{urgency}{remote}{fixed}"


def get_uct_commit(uct_path: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(uct_path), "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()
        return out
    except Exception:
        return "unknown"


def collect_other_fixed_versions(cve: CVERecord, srcpkg: str, current_suite: str | None) -> str:
    versions: set[str] = set()
    for suite, pkg_map in cve.packages.items():
        if current_suite and suite == current_suite:
            continue
        status = pkg_map.get(srcpkg)
        if not status:
            continue
        if status.status in {"released", "released-esm"} and status.version:
            versions.add(status.version)
    return " ".join(sorted(versions))


def write_feed(
    out_file: Path,
    cves: list[CVERecord],
    rows: list[tuple[str, int, str, str, str]],
    source_binary_pairs: list[str],
) -> FeedResult:
    section1 = [f"{cve.cve_id},,{sanitize_description(cve.description)}" for cve in cves]
    section2 = [
        f"{pkg},{vnum},{flags},{unstable_version},{other_versions}"
        for pkg, vnum, flags, unstable_version, other_versions in sorted(rows, key=lambda r: (r[0], r[1]))
    ]
    section3 = "" if not source_binary_pairs else ",".join(sorted(set(source_binary_pairs)))

    content = "VERSION 1\n\n"
    content += "\n".join(section1)
    content += "\n\n"
    content += "\n".join(section2)
    content += "\n\n"
    content += section3
    content += "\n"

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(content, encoding="utf-8")

    return FeedResult(cve_count=len(cves), package_rows=len(section2))


def build_suite_feed(
    suite: str,
    records: list[CVERecord],
    suite_map: dict[str, list[str]],
) -> tuple[list[CVERecord], list[tuple[str, int, str, str, str]], list[str]]:
    selected: list[CVERecord] = []
    row_keys: set[tuple[str, int]] = set()
    rows: list[tuple[str, int, str, str, str]] = []
    source_binary_pairs: list[str] = []

    for cve in sorted(records, key=lambda r: r.cve_id):
        suite_pkgs = cve.packages.get(suite, {})
        unresolved = {
            srcpkg: status
            for srcpkg, status in suite_pkgs.items()
            if status.status in UNRESOLVED_STATUSES
        }
        if not unresolved:
            continue
        selected.append(cve)

    cve_to_idx = {cve.cve_id: idx for idx, cve in enumerate(selected)}

    for cve in selected:
        vnum = cve_to_idx[cve.cve_id]
        suite_pkgs = cve.packages.get(suite, {})
        for srcpkg, status in sorted(suite_pkgs.items()):
            if status.status not in UNRESOLVED_STATUSES:
                continue

            unstable_version = cve.upstream_versions.get(srcpkg, "")
            other_versions = collect_other_fixed_versions(cve, srcpkg, current_suite=suite)
            flags = build_flags(cve.priority, cve.description, fix_available=(status.status == "released"))

            binaries = suite_map.get(srcpkg, [srcpkg])
            for binary in binaries:
                row_key = (binary, vnum)
                if row_key in row_keys:
                    continue
                row_keys.add(row_key)
                rows.append((binary, vnum, flags, unstable_version, other_versions))
                source_binary_pairs.append(f"{srcpkg}:{binary}")

    return selected, rows, source_binary_pairs


def build_generic_feed(
    records: list[CVERecord],
    suite_maps: dict[str, dict[str, list[str]]],
    suites: list[str],
) -> tuple[list[CVERecord], list[tuple[str, int, str, str, str]], list[str]]:
    selected: list[CVERecord] = []
    rows: list[tuple[str, int, str, str, str]] = []
    row_keys: set[tuple[str, int]] = set()

    for cve in sorted(records, key=lambda r: r.cve_id):
        unresolved_sources: set[str] = set()
        for suite in suites:
            for srcpkg, status in cve.packages.get(suite, {}).items():
                if status.status in UNRESOLVED_STATUSES:
                    unresolved_sources.add(srcpkg)

        if not unresolved_sources:
            continue

        selected.append(cve)

    cve_to_idx = {cve.cve_id: idx for idx, cve in enumerate(selected)}

    for cve in selected:
        vnum = cve_to_idx[cve.cve_id]
        unresolved_sources: set[str] = set()

        for suite in suites:
            for srcpkg, status in cve.packages.get(suite, {}).items():
                if status.status in UNRESOLVED_STATUSES:
                    unresolved_sources.add(srcpkg)

        for srcpkg in sorted(unresolved_sources):
            unstable_version = cve.upstream_versions.get(srcpkg, "")
            other_versions = collect_other_fixed_versions(cve, srcpkg, current_suite=None)
            flags = build_flags(cve.priority, cve.description, fix_available=False)

            binaries: set[str] = set()
            for suite in suites:
                binaries.update(suite_maps[suite].get(srcpkg, []))
            if not binaries:
                binaries = {srcpkg}

            for binary in sorted(binaries):
                row_key = (binary, vnum)
                if row_key in row_keys:
                    continue
                row_keys.add(row_key)
                rows.append((binary, vnum, flags, unstable_version, other_versions))

    return selected, rows, []


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uct", default="uct", help="Path to ubuntu-cve-tracker clone")
    parser.add_argument("--out", default="release/1", help="Output directory for feed files")
    parser.add_argument(
        "--suites",
        default="noble,jammy,focal,bionic",
        help="Comma-separated Ubuntu suites",
    )
    parser.add_argument("--metadata", help="Optional metadata.json output path")
    parser.add_argument("--cache-dir", default=".cache/packages", help="Package index cache dir")
    parser.add_argument(
        "--refresh-package-cache",
        action="store_true",
        help="Refresh package mapping cache",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    out_dir = Path(args.out)
    records = parse_uct_repository(args.uct, suites=set(suites))

    mapper = PackageMapper(cache_dir=Path(args.cache_dir))
    suite_maps = {
        suite: mapper.get_source_to_binaries(suite, refresh=args.refresh_package_cache)
        for suite in suites
    }

    metadata: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "uct_commit": get_uct_commit(Path(args.uct)),
        "suites": {},
    }

    for suite in suites:
        cves, rows, pairs = build_suite_feed(
            suite=suite,
            records=records,
            suite_map=suite_maps[suite],
        )
        result = write_feed(out_dir / suite, cves, rows, pairs)
        metadata["suites"][suite] = {"cves": result.cve_count, "packages": result.package_rows}

    cves, rows, pairs = build_generic_feed(
        records=records,
        suite_maps=suite_maps,
        suites=suites,
    )
    result = write_feed(out_dir / "GENERIC", cves, rows, pairs)
    metadata["suites"]["GENERIC"] = {"cves": result.cve_count, "packages": result.package_rows}

    if args.metadata:
        metadata_path = Path(args.metadata)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
