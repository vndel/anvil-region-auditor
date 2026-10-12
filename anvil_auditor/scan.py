"""Filesystem discovery and report aggregation."""

from __future__ import annotations

from pathlib import Path
from .region import RegionReport, inspect_region


def discover_regions(root: Path, include_entities: bool = False, include_poi: bool = False) -> list[tuple[str, Path]]:
    if root.is_file():
        return [("region", root)] if root.suffix == ".mca" else []
    if not root.is_dir():
        raise FileNotFoundError(root)

    directories = []
    if root.name in {"region", "entities", "poi"}:
        directories.append((root.name, root))
    else:
        directories.append(("region", root / "region"))
        if include_entities:
            directories.append(("entities", root / "entities"))
        if include_poi:
            directories.append(("poi", root / "poi"))

    found = []
    for kind, directory in directories:
        if directory.is_dir():
            for path in sorted(directory.glob("r.*.*.mca")):
                if path.is_symlink() or not path.is_file():
                    continue
                found.append((kind, path))
    return found


def scan(root: Path, include_entities: bool = False, include_poi: bool = False) -> list[tuple[str, RegionReport]]:
    return [(kind, inspect_region(path)) for kind, path in discover_regions(root, include_entities, include_poi)]
