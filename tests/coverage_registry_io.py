#!/usr/bin/env python3
"""Load and fingerprint the fail-closed sharded coverage registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX = ROOT / "tests/coverage_registry.json"
FORMAT_VERSION = 1
REGISTRY_SCHEMA_VERSION = 3
FILE_LINE_LIMIT = 5000
SECTIONS = (
    "reference_versions",
    "inventories",
    "catalog",
    "state_labels",
    "hardware_conditions",
)


class CoverageRegistryError(ValueError):
    """The registry index or one of its shards is incomplete or ambiguous."""


def _read_object(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text()
    except OSError as error:
        raise CoverageRegistryError(f"cannot read registry file {path}: {error}") from error
    line_count = len(text.splitlines())
    if line_count >= FILE_LINE_LIMIT:
        raise CoverageRegistryError(
            f"registry file has {line_count} lines, limit is {FILE_LINE_LIMIT - 1}: {path}"
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise CoverageRegistryError(f"invalid registry JSON {path}: {error}") from error
    if not isinstance(payload, dict):
        raise CoverageRegistryError(f"registry file is not an object: {path}")
    return payload


def _layout(index_path: Path) -> tuple[int, list[Path]]:
    index_path = index_path.resolve()
    index = _read_object(index_path)
    expected_fields = {"format_version", "schema_version", "shard_root", "shards"}
    if set(index) != expected_fields:
        raise CoverageRegistryError(
            "registry index fields differ: "
            f"expected {sorted(expected_fields)}, got {sorted(index)}"
        )
    if index["format_version"] != FORMAT_VERSION:
        raise CoverageRegistryError(
            f"unsupported registry format version: {index['format_version']!r}"
        )
    schema_version = index["schema_version"]
    if schema_version != REGISTRY_SCHEMA_VERSION:
        raise CoverageRegistryError(
            f"unsupported registry schema version: {schema_version!r}"
        )
    shard_root_value = index["shard_root"]
    if not isinstance(shard_root_value, str) or not shard_root_value:
        raise CoverageRegistryError("registry shard_root must be a nonempty relative path")
    shard_root_relative = Path(shard_root_value)
    if shard_root_relative.is_absolute():
        raise CoverageRegistryError("registry shard_root must be relative")
    index_root = index_path.parent
    shard_root = (index_root / shard_root_relative).resolve()
    if shard_root == index_root or not shard_root.is_relative_to(index_root):
        raise CoverageRegistryError("registry shard_root escapes the index directory")
    shard_values = index["shards"]
    if not isinstance(shard_values, list) or not shard_values:
        raise CoverageRegistryError("registry shards must be a nonempty list")
    paths: list[Path] = []
    seen: set[Path] = set()
    for value in shard_values:
        if not isinstance(value, str) or not value:
            raise CoverageRegistryError("registry shard path must be a nonempty string")
        relative = Path(value)
        if relative.is_absolute() or relative.suffix != ".json":
            raise CoverageRegistryError(f"invalid registry shard path: {value!r}")
        path = (index_root / relative).resolve()
        if not path.is_relative_to(shard_root):
            raise CoverageRegistryError(f"registry shard escapes shard_root: {value}")
        if path in seen:
            raise CoverageRegistryError(f"duplicate registry shard path: {value}")
        seen.add(path)
        paths.append(path)
    if not shard_root.is_dir():
        raise CoverageRegistryError(f"registry shard root is not a directory: {shard_root}")
    discovered = {
        path.resolve() for path in shard_root.rglob("*.json") if path.is_file()
    }
    missing = sorted(str(path) for path in seen - discovered)
    unindexed = sorted(str(path) for path in discovered - seen)
    if missing:
        raise CoverageRegistryError(f"missing registry shards: {', '.join(missing)}")
    if unindexed:
        raise CoverageRegistryError(f"unindexed registry shards: {', '.join(unindexed)}")
    return schema_version, paths


def load_registry(index_path: Path = DEFAULT_INDEX) -> dict[str, Any]:
    """Load every indexed shard and reject omissions or duplicate keys."""
    schema_version, paths = _layout(index_path)
    merged: dict[str, dict[str, Any]] = {section: {} for section in SECTIONS}
    for path in paths:
        shard = _read_object(path)
        if not shard:
            raise CoverageRegistryError(f"empty registry shard: {path}")
        unknown = sorted(set(shard) - set(SECTIONS))
        if unknown:
            raise CoverageRegistryError(
                f"unknown registry sections in {path}: {', '.join(unknown)}"
            )
        for section, values in shard.items():
            if not isinstance(values, dict) or not values:
                raise CoverageRegistryError(
                    f"registry section {section} must be a nonempty object: {path}"
                )
            duplicates = sorted(set(merged[section]) & set(values))
            if duplicates:
                raise CoverageRegistryError(
                    f"duplicate registry keys in {section}: {', '.join(duplicates)}"
                )
            merged[section].update(values)
    empty = [section for section, values in merged.items() if not values]
    if empty:
        raise CoverageRegistryError(
            f"registry sections have no indexed data: {', '.join(empty)}"
        )
    return {"schema_version": schema_version, **merged}


def registry_sha256(index_path: Path = DEFAULT_INDEX) -> str:
    """Hash the index and every shard, including relative path boundaries."""
    load_registry(index_path)
    index_path = index_path.resolve()
    _, shards = _layout(index_path)
    digest = hashlib.sha256()
    for path in sorted([index_path, *shards]):
        relative = path.relative_to(index_path.parent).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def self_test() -> dict[str, Any]:
    checks = {
        "current_registry_loads": bool(load_registry()),
        "current_registry_hashes": len(registry_sha256()) == 64,
    }
    with tempfile.TemporaryDirectory(prefix="mcrypto-registry-test-") as raw:
        temporary = Path(raw)
        index_path = temporary / "index.json"
        shard_root = temporary / "parts"
        base_shard = shard_root / "base.json"
        sections = {section: {f"{section}-key": {}} for section in SECTIONS}
        index = {
            "format_version": FORMAT_VERSION,
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "shard_root": "parts",
            "shards": ["parts/base.json"],
        }
        _write_json(base_shard, sections)
        _write_json(index_path, index)
        checks["minimal_registry_loads"] = bool(load_registry(index_path))

        orphan = shard_root / "orphan.json"
        _write_json(orphan, {"catalog": {"orphan": {}}})
        try:
            load_registry(index_path)
        except CoverageRegistryError:
            checks["unindexed_shard_rejected"] = True
        else:
            checks["unindexed_shard_rejected"] = False
        orphan.unlink()

        duplicate = shard_root / "duplicate.json"
        _write_json(duplicate, {"catalog": {"catalog-key": {}}})
        sections["catalog"] = {"catalog-key": {}}
        _write_json(base_shard, sections)
        index["shards"].append("parts/duplicate.json")
        _write_json(index_path, index)
        try:
            load_registry(index_path)
        except CoverageRegistryError:
            checks["duplicate_key_rejected"] = True
        else:
            checks["duplicate_key_rejected"] = False

        duplicate.unlink()
        index["shards"] = ["parts/base.json"]
        _write_json(index_path, index)
        base_shard.write_text(
            "\n".join(["{", *([""] * (FILE_LINE_LIMIT - 2)), "}"]) + "\n"
        )
        try:
            load_registry(index_path)
        except CoverageRegistryError:
            checks["oversized_shard_rejected"] = True
        else:
            checks["oversized_shard_rejected"] = False
        _write_json(base_shard, sections)

        index["shards"] = ["../escape.json"]
        _write_json(index_path, index)
        try:
            load_registry(index_path)
        except CoverageRegistryError:
            checks["escaping_path_rejected"] = True
        else:
            checks["escaping_path_rejected"] = False

        index["shards"] = ["parts/base.json"]
        index["schema_version"] = REGISTRY_SCHEMA_VERSION + 1
        _write_json(index_path, index)
        try:
            load_registry(index_path)
        except CoverageRegistryError:
            checks["unsupported_version_rejected"] = True
        else:
            checks["unsupported_version_rejected"] = False
    return {"status": "pass" if all(checks.values()) else "fail", "checks": checks}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
    else:
        registry = load_registry(args.index)
        result = {
            "status": "pass",
            "schema_version": registry["schema_version"],
            "sections": {section: len(registry[section]) for section in SECTIONS},
            "sha256": registry_sha256(args.index),
        }
    print(json.dumps(result, indent=2))
    if result["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
