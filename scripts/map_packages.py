#!/usr/bin/env python3
"""Source-to-binary mapping for Ubuntu archive packages."""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

DEFAULT_COMPONENTS = ("main", "restricted", "universe", "multiverse")
DEFAULT_POCKETS = ("", "-updates", "-security")


@dataclass
class PackageMapper:
    cache_dir: Path
    base_url: str = "https://archive.ubuntu.com/ubuntu"
    components: tuple[str, ...] = DEFAULT_COMPONENTS
    pockets: tuple[str, ...] = DEFAULT_POCKETS

    def __post_init__(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache: dict[str, dict[str, list[str]]] = {}

    def _cache_path(self, suite: str) -> Path:
        return self.cache_dir / f"{suite}.json"

    def _download_packages_index(self, suite: str) -> str:
        chunks: list[str] = []
        for pocket_suffix in self.pockets:
            pocket = f"{suite}{pocket_suffix}"
            for component in self.components:
                url = (
                    f"{self.base_url}/dists/{pocket}/"
                    f"{component}/binary-amd64/Packages.gz"
                )
                try:
                    with urlopen(url, timeout=30) as resp:
                        compressed = resp.read()
                    text = gzip.decompress(compressed).decode("utf-8", errors="replace")
                    chunks.append(text)
                except (HTTPError, URLError, TimeoutError, OSError):
                    continue
        return "\n".join(chunks)

    @staticmethod
    def _parse_packages_text(packages_text: str) -> dict[str, set[str]]:
        source_to_bins: dict[str, set[str]] = {}
        package_name = None
        source_name = None

        def flush() -> None:
            nonlocal package_name, source_name
            if not package_name:
                return
            src = source_name or package_name
            source_to_bins.setdefault(src, set()).add(package_name)
            package_name = None
            source_name = None

        for line in packages_text.splitlines():
            if not line.strip():
                flush()
                continue

            if line.startswith("Package:"):
                package_name = line.split(":", 1)[1].strip()
            elif line.startswith("Source:"):
                raw_source = line.split(":", 1)[1].strip()
                source_name = raw_source.split()[0]

        flush()
        return source_to_bins

    def get_source_to_binaries(self, suite: str, refresh: bool = False) -> dict[str, list[str]]:
        if suite in self._memory_cache and not refresh:
            return self._memory_cache[suite]

        cache_file = self._cache_path(suite)

        if cache_file.exists() and not refresh:
            mapping = json.loads(cache_file.read_text(encoding="utf-8"))
            self._memory_cache[suite] = mapping
            return mapping

        text = self._download_packages_index(suite)
        mapping = {
            src: sorted(bins)
            for src, bins in self._parse_packages_text(text).items()
        }

        cache_file.write_text(json.dumps(mapping, sort_keys=True), encoding="utf-8")
        self._memory_cache[suite] = mapping
        return mapping

    def get_binary_packages(self, suite: str, srcpkg: str, refresh: bool = False) -> list[str]:
        mapping = self.get_source_to_binaries(suite, refresh=refresh)
        return mapping.get(srcpkg, [srcpkg])
