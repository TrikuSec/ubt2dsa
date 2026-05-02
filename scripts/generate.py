#!/usr/bin/env python3
"""Generate debsecan-compatible feeds for Ubuntu suites."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

from map_packages import PackageMapper
from parse_uct import CVERecord, PackageStatus, parse_uct_file, parse_uct_repository

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
KERNEL_VERSIONED_RE = re.compile(r"-\d+\.\d+\.\d+-\d+")
EXCLUDED_BINARY_SUFFIXES = ("-dbgsym", "-dbg", ".udeb")


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


def build_flags(priority: str, description: str, fix_available: bool, package_type: str = "B") -> str:
    urgency = URGENCY_MAP.get(priority.lower(), " ")
    remote = detect_remote_flag(description)
    fixed = "F" if fix_available else " "
    return f"{package_type}{urgency}{remote}{fixed}"


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


def select_binaries_for_feed(srcpkg: str, binaries: list[str], max_per_source: int) -> tuple[list[str], str]:
    filtered: list[str] = []
    seen: set[str] = set()

    for pkg in sorted(binaries):
        if pkg in seen:
            continue
        seen.add(pkg)

        if pkg.endswith(EXCLUDED_BINARY_SUFFIXES):
            continue
        if pkg.startswith("linux-") and KERNEL_VERSIONED_RE.search(pkg):
            continue
        filtered.append(pkg)

    if not filtered:
        return [srcpkg], "S"

    if len(filtered) > max_per_source:
        if srcpkg.startswith("linux"):
            return [srcpkg], "S"
        return filtered[:max_per_source], "B"

    return filtered, "B"


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


def sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def serialize_record(record: CVERecord) -> dict[str, object]:
    return {
        "cve_id": record.cve_id,
        "priority": record.priority,
        "description": record.description,
        "packages": {
            suite: {
                srcpkg: {"status": ps.status, "version": ps.version}
                for srcpkg, ps in pkg_map.items()
            }
            for suite, pkg_map in record.packages.items()
        },
        "upstream_versions": record.upstream_versions,
    }


def deserialize_record(data: dict[str, object]) -> CVERecord:
    packages: dict[str, dict[str, PackageStatus]] = {}
    for suite, pkg_map in (data.get("packages") or {}).items():
        packages[suite] = {}
        for srcpkg, ps in pkg_map.items():
            packages[suite][srcpkg] = PackageStatus(
                status=str(ps.get("status", "")),
                version=ps.get("version"),
            )

    return CVERecord(
        cve_id=str(data.get("cve_id", "")),
        priority=str(data.get("priority", "medium")),
        description=str(data.get("description", "")),
        packages=packages,
        upstream_versions={k: str(v) for k, v in (data.get("upstream_versions") or {}).items()},
    )


def load_records_incremental(
    uct_root: Path,
    suites: set[str],
    include_retired: bool,
    state_file: Path | None,
    use_state_cache: bool,
) -> list[CVERecord]:
    if not use_state_cache or state_file is None:
        return parse_uct_repository(uct_root, suites=suites, include_retired=include_retired)

    state: dict[str, object] = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            state = {}

    old_files = state.get("files", {}) if isinstance(state, dict) else {}
    if not isinstance(old_files, dict):
        old_files = {}

    cached_suites = state.get("suites") if isinstance(state, dict) else None
    if sorted(suites) != sorted(cached_suites or []):
        old_files = {}

    subdirs = ["active"]
    if include_retired:
        subdirs.append("retired")

    new_files: dict[str, dict[str, object]] = {}

    for subdir in subdirs:
        directory = uct_root / subdir
        if not directory.exists():
            continue

        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue

            rel = str(path.relative_to(uct_root))
            digest = sha1_file(path)
            prev = old_files.get(rel)

            if isinstance(prev, dict) and prev.get("sha1") == digest and "record" in prev:
                new_files[rel] = prev
                continue

            record = parse_uct_file(path, suites=suites)
            new_files[rel] = {
                "sha1": digest,
                "record": serialize_record(record) if record else None,
            }

    records = [
        deserialize_record(entry["record"])
        for entry in new_files.values()
        if isinstance(entry, dict) and entry.get("record")
    ]

    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps(
            {
                "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "suites": sorted(suites),
                "files": new_files,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return records


def build_suite_feed(
    suite: str,
    records: list[CVERecord],
    suite_map: dict[str, list[str]],
    max_binaries_per_source: int,
) -> tuple[list[CVERecord], list[tuple[str, int, str, str, str]], list[str]]:
    selected: list[CVERecord] = []
    row_keys: set[tuple[str, int]] = set()
    rows: list[tuple[str, int, str, str, str]] = []
    source_binary_pairs: list[str] = []

    for cve in sorted(records, key=lambda r: r.cve_id):
        suite_pkgs = cve.packages.get(suite, {})
        if any(status.status in UNRESOLVED_STATUSES for status in suite_pkgs.values()):
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

            binaries, package_type = select_binaries_for_feed(
                srcpkg,
                suite_map.get(srcpkg, [srcpkg]),
                max_per_source=max_binaries_per_source,
            )
            flags = build_flags(
                cve.priority,
                cve.description,
                fix_available=(status.status == "released"),
                package_type=package_type,
            )

            for binary in binaries:
                row_key = (binary, vnum)
                if row_key in row_keys:
                    continue
                row_keys.add(row_key)
                rows.append((binary, vnum, flags, unstable_version, other_versions))
                source_binary_pairs.append(f"{srcpkg}:{binary}")

    return selected, rows, source_binary_pairs


def build_generic_feed(records: list[CVERecord], suites: list[str]) -> list[CVERecord]:
    selected: list[CVERecord] = []

    for cve in sorted(records, key=lambda r: r.cve_id):
        unresolved = False
        for suite in suites:
            for status in cve.packages.get(suite, {}).values():
                if status.status in UNRESOLVED_STATUSES:
                    unresolved = True
                    break
            if unresolved:
                break

        if unresolved:
            selected.append(cve)

    return selected


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
    parser.add_argument(
        "--state-file",
        default=".cache/uct-state.json",
        help="Incremental parse state cache file",
    )
    parser.add_argument(
        "--no-state-cache",
        action="store_true",
        help="Disable incremental parse state and parse everything",
    )
    parser.add_argument(
        "--include-retired",
        action="store_true",
        help="Include retired/ CVE files (default: only active/ for performance)",
    )
    parser.add_argument(
        "--max-binaries-per-source",
        type=int,
        default=25,
        help="Cap binary package expansion per source package",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    out_dir = Path(args.out)
    uct_root = Path(args.uct)

    records = load_records_incremental(
        uct_root=uct_root,
        suites=set(suites),
        include_retired=args.include_retired,
        state_file=Path(args.state_file),
        use_state_cache=not args.no_state_cache,
    )

    mapper = PackageMapper(cache_dir=Path(args.cache_dir))

    metadata: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "uct_commit": get_uct_commit(uct_root),
        "include_retired": bool(args.include_retired),
        "state_cache": not args.no_state_cache,
        "max_binaries_per_source": max(1, args.max_binaries_per_source),
        "suites": {},
    }

    for suite in suites:
        suite_map = mapper.get_source_to_binaries(suite, refresh=args.refresh_package_cache)
        cves, rows, pairs = build_suite_feed(
            suite=suite,
            records=records,
            suite_map=suite_map,
            max_binaries_per_source=max(1, args.max_binaries_per_source),
        )
        result = write_feed(out_dir / suite, cves, rows, pairs)
        metadata["suites"][suite] = {"cves": result.cve_count, "packages": result.package_rows}

    generic_cves = build_generic_feed(records=records, suites=suites)
    result = write_feed(out_dir / "GENERIC", generic_cves, [], [])
    metadata["suites"]["GENERIC"] = {"cves": result.cve_count, "packages": result.package_rows}

    if args.metadata:
        metadata_path = Path(args.metadata)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
