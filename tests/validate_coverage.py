#!/usr/bin/env python3
"""Validate the executed-evidence registry and its test-runner bindings."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
from coverage_registry_io import (
    CoverageRegistryError,
    load_registry,
    registry_sha256,
)

REGISTRY = ROOT / "tests/coverage_registry.json"
INVENTORY_PREFIXES = ("REFERENCE_", "INTEROP_")
REFERENCE_NAMES = {
    "REFERENCE_SUITE_VERSION",
    "INTEROP_SUITE_VERSION",
}
OPERATION_FIELDS = {
    "unit",
    "vectors",
    "comparator",
    "negative",
    "state",
    "paths",
    "conditions",
}
OPTIONAL_OPERATION_FIELDS = {"path_targets"}
TARGETS = {"x86_64", "arm64"}
COMPARATORS = {
    "byte-exact",
    "cross-open",
    "cross-verify",
    "normalized-components",
    "semantic-decode",
    "invariant",
}
PATHS = {
    "scalar",
    "prepared",
    "simd",
    "platform:aes-pclmul",
    "platform:aes-pmull",
    "platform:rdrand",
    "platform:rdseed",
}


class CoverageError(RuntimeError):
    """The registry does not close over executable evidence."""


def _duplicates(items: Iterable[str]) -> list[str]:
    values = list(items)
    return sorted({item for item in values if values.count(item) > 1})


def discover_test_ids(root: Path = ROOT) -> tuple[set[str], dict[str, bool]]:
    """Discover every Mojo unit test and whether its module executes discovery."""
    ids: set[str] = set()
    runners: dict[str, bool] = {}
    for path in sorted((root / "tests").glob("test_*.mojo")):
        text = path.read_text()
        runners[path.name] = "TestSuite.discover_tests" in text
        for name in re.findall(r"(?m)^def\s+(test_[A-Za-z0-9_]+)\s*\(", text):
            test_id = f"{path.name}::{name}"
            if test_id in ids:
                raise CoverageError(f"duplicate unit test id: {test_id}")
            ids.add(test_id)
    return ids, runners


def _require_all_runners(runners: dict[str, bool]) -> None:
    missing = sorted(name for name, present in runners.items() if not present)
    if missing:
        raise CoverageError(
            "test modules lack TestSuite.discover_tests runner: "
            + ", ".join(missing)
        )


def _require_test_ids(ids: Iterable[str], known: set[str], context: str) -> None:
    values = list(ids)
    if any(
        not isinstance(value, str)
        or not re.fullmatch(r"test_[A-Za-z0-9_]+\.mojo::test_[A-Za-z0-9_]+", value)
        for value in values
    ):
        raise CoverageError(f"invalid test id for {context}")
    unknown = sorted(set(values) - known)
    if unknown:
        raise CoverageError(f"unknown test ids for {context}: {', '.join(unknown)}")
    duplicates = _duplicates(values)
    if duplicates:
        raise CoverageError(
            f"duplicate test bindings for {context}: {', '.join(duplicates)}"
        )




def _require_string_list(
    value: object,
    *,
    context: str,
    nonempty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "nonempty " if nonempty else ""
        raise CoverageError(f"{context} must be a {qualifier}list")
    if any(not isinstance(item, str) or not item for item in value):
        raise CoverageError(f"{context} contains an invalid value")
    duplicates = _duplicates(value)
    if duplicates:
        raise CoverageError(
            f"duplicate bindings for {context}: {', '.join(duplicates)}"
        )
    return value


def validate_registry(
    data: dict[str, Any],
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Validate inventory closure and every executable evidence binding."""
    references = data.get("reference_versions")
    if (
        not isinstance(references, dict)
        or set(references) != REFERENCE_NAMES
        or any(not isinstance(value, str) or not value for value in references.values())
    ):
        raise CoverageError("reference versions are incomplete or invalid")

    inventories = data.get("inventories")
    if not isinstance(inventories, dict) or not inventories:
        raise CoverageError("registry inventories must be a nonempty object")
    expected_catalog_keys: list[str] = []
    inventory_entries = 0
    for inventory_name, raw_values in inventories.items():
        if (
            not isinstance(inventory_name, str)
            or not inventory_name.startswith(INVENTORY_PREFIXES)
        ):
            raise CoverageError(f"invalid inventory name: {inventory_name!r}")
        values = _require_string_list(
            raw_values,
            context=f"inventory {inventory_name}",
            nonempty=True,
        )
        expected_catalog_keys.extend(
            f"{inventory_name}/{value}" for value in values
        )
        inventory_entries += len(values)

    catalog = data.get("catalog")
    if not isinstance(catalog, dict):
        raise CoverageError("registry catalog must be an object")
    missing = sorted(set(expected_catalog_keys) - set(catalog))
    extra = sorted(set(catalog) - set(expected_catalog_keys))
    if missing:
        raise CoverageError(f"missing catalog keys: {', '.join(missing)}")
    if extra:
        raise CoverageError(f"unknown catalog keys: {', '.join(extra)}")

    known_tests, runners = discover_test_ids(root)
    _require_all_runners(runners)
    state_labels = data.get("state_labels")
    hardware_conditions = data.get("hardware_conditions")
    if not isinstance(state_labels, dict) or not state_labels:
        raise CoverageError("state labels must be a nonempty object")
    if not isinstance(hardware_conditions, dict) or not hardware_conditions:
        raise CoverageError("hardware conditions must be a nonempty object")

    state_test_bindings = 0
    for label, bindings in state_labels.items():
        if not isinstance(label, str) or not label:
            raise CoverageError("state label names must be nonempty strings")
        values = _require_string_list(
            bindings,
            context=f"state {label}",
            nonempty=True,
        )
        _require_test_ids(values, known_tests, f"state {label}")
        state_test_bindings += len(values)


    for label, declaration in hardware_conditions.items():
        if (
            not isinstance(label, str)
            or not label
            or not isinstance(declaration, dict)
            or set(declaration) != {"available", "reason", "target"}
            or not isinstance(declaration.get("available"), bool)
            or not isinstance(declaration.get("reason"), str)
            or not declaration.get("reason")
            or declaration.get("target") not in TARGETS
        ):
            raise CoverageError(f"invalid hardware condition: {label}")

    operation_ids: set[str] = set()
    negative_test_bindings = 0
    operation_paths = 0
    for catalog_key in expected_catalog_keys:
        entry = catalog[catalog_key]
        operations = entry.get("operations") if isinstance(entry, dict) else None
        if not isinstance(operations, dict) or not operations:
            raise CoverageError(f"catalog entry has no operations: {catalog_key}")
        for operation_name, operation in operations.items():
            if not isinstance(operation_name, str) or not operation_name:
                raise CoverageError(f"invalid operation name in {catalog_key}")
            operation_id = f"{catalog_key}::{operation_name}"
            if operation_id in operation_ids:
                raise CoverageError(f"duplicate operation id: {operation_id}")
            operation_ids.add(operation_id)
            fields = set(operation) if isinstance(operation, dict) else set()
            if (
                not isinstance(operation, dict)
                or not OPERATION_FIELDS <= fields
                or fields - OPERATION_FIELDS - OPTIONAL_OPERATION_FIELDS
            ):
                raise CoverageError(f"operation fields differ for {operation_id}")

            units = _require_string_list(
                operation["unit"], context=f"{operation_id} unit", nonempty=True
            )
            _require_test_ids(units, known_tests, f"{operation_id} unit")
            negatives = _require_string_list(
                operation["negative"],
                context=f"{operation_id} negative",
                nonempty=True,
            )
            _require_test_ids(negatives, known_tests, f"{operation_id} negative")
            negative_test_bindings += len(negatives)


            if operation["comparator"] not in COMPARATORS:
                raise CoverageError(
                    f"invalid comparator for {operation_id}: "
                    f"{operation['comparator']}"
                )
            states = _require_string_list(
                operation["state"], context=f"{operation_id} state"
            )
            unknown_states = sorted(set(states) - set(state_labels))
            if unknown_states:
                raise CoverageError(
                    f"unknown state labels for {operation_id}: "
                    + ", ".join(unknown_states)
                )
            conditions = _require_string_list(
                operation["conditions"], context=f"{operation_id} conditions"
            )
            unknown_conditions = sorted(
                set(conditions) - set(hardware_conditions)
            )
            if unknown_conditions:
                raise CoverageError(
                    f"unknown hardware conditions for {operation_id}: "
                    + ", ".join(unknown_conditions)
                )

            paths = _require_string_list(
                operation["paths"], context=f"{operation_id} paths", nonempty=True
            )
            unknown_paths = sorted(set(paths) - PATHS)
            if unknown_paths:
                raise CoverageError(
                    f"unknown paths for {operation_id}: {', '.join(unknown_paths)}"
                )
            operation_paths += len(paths)
            path_targets = operation.get("path_targets", {})
            if not isinstance(path_targets, dict):
                raise CoverageError(
                    f"path_targets must be an object for {operation_id}"
                )
            unknown_target_paths = sorted(set(path_targets) - set(paths))
            if unknown_target_paths:
                raise CoverageError(
                    f"path_targets names unknown paths for {operation_id}: "
                    + ", ".join(unknown_target_paths)
                )
            for path, raw_targets in path_targets.items():
                targets = _require_string_list(
                    raw_targets,
                    context=f"{operation_id}@{path} targets",
                    nonempty=True,
                )
                unknown_targets = sorted(set(targets) - TARGETS)
                if unknown_targets:
                    raise CoverageError(
                        f"invalid path targets for {operation_id}@{path}: "
                        + ", ".join(unknown_targets)
                    )
            missing_platform_targets = sorted(
                path
                for path in paths
                if path.startswith("platform:") and path not in path_targets
            )
            if missing_platform_targets:
                raise CoverageError(
                    f"platform paths lack targets for {operation_id}: "
                    + ", ".join(missing_platform_targets)
                )

            vectors = operation["vectors"]
            if not isinstance(vectors, list) or not vectors:
                raise CoverageError(f"operation has no vector evidence: {operation_id}")
            for vector in vectors:
                if (
                    not isinstance(vector, dict)
                    or set(vector) != {"source", "id"}
                    or not isinstance(vector.get("source"), str)
                    or not vector.get("source")
                    or not isinstance(vector.get("id"), str)
                    or not vector.get("id")
                ):
                    raise CoverageError(
                        f"invalid vector declaration for {operation_id}"
                    )
                source = (root / vector["source"]).resolve()
                if (
                    not source.is_relative_to(root.resolve())
                    or not source.is_file()
                ):
                    raise CoverageError(
                        f"missing vector source for {operation_id}: "
                        f"{vector['source']}"
                    )

    return {
        "inventory_entries": inventory_entries,
        "operations": len(operation_ids),
        "negative_test_bindings": negative_test_bindings,
        "state_test_bindings": state_test_bindings,
        "operation_paths": operation_paths,
        "hardware_conditions": len(hardware_conditions),
        "unit_test_functions": len(known_tests),
        "test_modules": len(runners),
        "test_modules_with_runner": sum(runners.values()),
    }


def _first_operation(data: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    catalog_key = next(iter(data["catalog"]))
    operation_name = next(iter(data["catalog"][catalog_key]["operations"]))
    return (
        catalog_key,
        operation_name,
        data["catalog"][catalog_key]["operations"][operation_name],
    )


def _expect_rejected(
    checks: dict[str, bool],
    name: str,
    data: dict[str, Any],
    mutation: Callable[[dict[str, Any]], None],
    expected: str,
) -> None:
    mutant = json.loads(json.dumps(data))
    mutation(mutant)
    try:
        validate_registry(mutant)
    except CoverageError as error:
        if expected not in str(error):
            raise CoverageError(
                f"self-test {name} wrong diagnostic: expected {expected!r}, "
                f"got {str(error)!r}"
            ) from error
        checks[name] = True
    else:
        raise CoverageError(f"self-test {name} accepted invalid metadata")


def _self_test(data: dict[str, Any]) -> dict[str, Any]:
    summary = validate_registry(data)
    checks: dict[str, bool] = {}

    def remove_operations(mutant: dict[str, Any]) -> None:
        key = next(iter(mutant["catalog"]))
        mutant["catalog"][key]["operations"] = {}

    def unknown_negative(mutant: dict[str, Any]) -> None:
        _, _, operation = _first_operation(mutant)
        operation["negative"][0] = "test_missing.mojo::test_missing"


    def duplicate_binding(mutant: dict[str, Any]) -> None:
        _, _, operation = _first_operation(mutant)
        operation["negative"].append(operation["negative"][0])

    def invalid_path_target(mutant: dict[str, Any]) -> None:
        _, _, operation = _first_operation(mutant)
        path = operation["paths"][0]
        operation.setdefault("path_targets", {})[path] = ["riscv64"]

    _expect_rejected(
        checks,
        "missing_inventory_operation_rejected",
        data,
        remove_operations,
        "catalog entry has no operations",
    )
    _expect_rejected(
        checks,
        "unknown_negative_test_rejected",
        data,
        unknown_negative,
        "unknown test ids",
    )
    _expect_rejected(
        checks,
        "duplicate_binding_rejected",
        data,
        duplicate_binding,
        "duplicate bindings",
    )
    _expect_rejected(
        checks,
        "invalid_path_target_rejected",
        data,
        invalid_path_target,
        "invalid path targets",
    )

    with tempfile.TemporaryDirectory(prefix="mcrypto-runner-test-") as raw:
        tests = Path(raw) / "tests"
        tests.mkdir()
        (tests / "test_without_runner.mojo").write_text(
            "def test_example():\n    pass\n"
        )
        _, runners = discover_test_ids(Path(raw))
        try:
            _require_all_runners(runners)
        except CoverageError as error:
            if "test_without_runner.mojo" not in str(error):
                raise
            checks["module_without_runner_rejected"] = True
        else:
            raise CoverageError(
                "self-test module_without_runner_rejected accepted a missing runner"
            )

    return {**summary, "self_test_checks": checks, "self_test_passed": all(checks.values())}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        data = load_registry(args.registry)
        summary = _self_test(data) if args.self_test else validate_registry(data)
    except (CoverageError, CoverageRegistryError, json.JSONDecodeError, OSError) as error:
        print(f"coverage validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    payload = {
        "schema_version": data["schema_version"],
        "status": "pass",
        "complete": True,
        "registry_sha256": registry_sha256(args.registry),
        **summary,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
