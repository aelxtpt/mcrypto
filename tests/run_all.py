#!/usr/bin/env python3
"""Run every discovered Mojo test module."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATTERN = re.compile(r"TestSuite\s*\.\s*discover_tests")
SUMMARY_PATTERN = re.compile(
    r"(?P<tests>\d+) tests run:\s*"
    r"(?P<passed>\d+) passed\s*,\s*"
    r"(?P<failed>\d+) failed\s*,\s*"
    r"(?P<skipped>\d+) skipped"
)
SANITIZER_DIAGNOSTIC_PATTERN = re.compile(
    r"AddressSanitizer|LeakSanitizer|ThreadSanitizer|"
    r"WARNING:\s*ThreadSanitizer|SUMMARY:.*Sanitizer",
    re.IGNORECASE,
)
MOJO_VERSION_PATTERN = re.compile(
    r"^Mojo 1\.0\.0(?: \([0-9a-f]+\))?$"
)


def _mojo_environment() -> dict[str, str]:
    environment = dict(os.environ)
    prefix = environment.get("CONDA_PREFIX")
    path = environment.get("PATH")
    if not prefix or not path:
        return environment
    prefix_bin = str((Path(prefix) / "bin").resolve())
    entries = path.split(os.pathsep)
    environment["PATH"] = os.pathsep.join(
        [entry for entry in entries if str(Path(entry).resolve()) != prefix_bin]
        + [prefix_bin]
    )
    return environment


def _parse_counts(output: str) -> dict[str, int] | None:
    matches = list(SUMMARY_PATTERN.finditer(output))
    if not matches:
        return None
    return {
        name: int(matches[-1].group(name))
        for name in ("tests", "passed", "failed", "skipped")
    }


def _diagnostics(output: str) -> list[str]:
    return [
        line[-1000:]
        for line in output.splitlines()
        if SANITIZER_DIAGNOSTIC_PATTERN.search(line)
    ][:20]


def _run_module(
    mojo: str,
    path: Path,
    optimization: str,
    sanitizer: str | None,
    timeout: float,
    environment: dict[str, str],
) -> dict[str, Any]:
    started = time.monotonic()
    commands: list[list[str]] = []
    stdout = ""
    stderr = ""
    build_returncode: int | None = None
    run_returncode: int | None = None
    try:
        if sanitizer is None:
            command = [
                mojo,
                "run",
                f"-{optimization}",
                "-j",
                "1",
                "-I",
                str(ROOT / "src"),
                str(path),
            ]
            commands.append(command)
            process = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            stdout = process.stdout
            stderr = process.stderr
            run_returncode = process.returncode
        else:
            with tempfile.TemporaryDirectory(
                prefix=f"mcrypto-{sanitizer}-"
            ) as temporary:
                binary = Path(temporary) / path.stem
                build = [
                    mojo,
                    "build",
                    f"-{optimization}",
                    "-j",
                    "1",
                    "--sanitize",
                    sanitizer,
                    "-I",
                    str(ROOT / "src"),
                    str(path),
                    "-o",
                    str(binary),
                ]
                commands.append(build)
                built = subprocess.run(
                    build,
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                stdout = built.stdout
                stderr = built.stderr
                build_returncode = built.returncode
                if built.returncode == 0:
                    execute = [str(binary)]
                    commands.append(execute)
                    process = subprocess.run(
                        execute,
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False,
                    )
                    stdout += process.stdout
                    stderr += process.stderr
                    run_returncode = process.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "test": path.relative_to(ROOT).as_posix(),
            "status": "fail",
            "commands": commands,
            "returncode": -1,
            "counts": None,
            "sanitizer_diagnostics": [],
            "elapsed_seconds": time.monotonic() - started,
            "stdout": stdout[-4000:],
            "stderr": str(error)[-4000:],
            "reason": str(error),
        }

    combined = stdout + "\n" + stderr
    counts = _parse_counts(combined)
    diagnostics = _diagnostics(combined)
    returncode = (
        run_returncode
        if run_returncode is not None
        else build_returncode if build_returncode is not None else -1
    )
    passed = (
        (sanitizer is None or build_returncode == 0)
        and run_returncode == 0
        and counts is not None
        and counts["tests"] > 0
        and counts["passed"] == counts["tests"]
        and counts["failed"] == 0
        and counts["skipped"] == 0
        and not diagnostics
    )
    reason = None
    if sanitizer is not None and build_returncode != 0:
        reason = f"Mojo sanitizer build exited {build_returncode}"
    elif run_returncode != 0:
        reason = f"Mojo test process exited {run_returncode}"
    elif diagnostics:
        reason = "sanitizer diagnostics were emitted"
    elif counts is None:
        reason = "test summary was not emitted"
    elif counts["tests"] == 0:
        reason = "test module discovered zero tests"
    elif counts["failed"]:
        reason = f"{counts['failed']} tests failed"
    elif counts["skipped"]:
        reason = f"{counts['skipped']} tests skipped"
    elif counts["passed"] != counts["tests"]:
        reason = "test summary counts are inconsistent"
    return {
        "test": path.relative_to(ROOT).as_posix(),
        "status": "pass" if passed else "fail",
        "commands": commands,
        "returncode": returncode,
        "counts": counts,
        "sanitizer_diagnostics": diagnostics,
        "elapsed_seconds": time.monotonic() - started,
        "stdout": stdout[-4000:],
        "stderr": stderr[-4000:],
        "reason": reason,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mojo", default="mojo")
    parser.add_argument(
        "--optimization", choices=("O0", "O1", "O3"), default="O3"
    )
    parser.add_argument("--sanitize", choices=("address", "thread"))
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--module",
        action="append",
        help="Run one test module by stem; repeat to select multiple modules",
    )
    args = parser.parse_args()

    environment = _mojo_environment()
    version = subprocess.run(
        [args.mojo, "--version"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    version_text = (version.stdout or version.stderr).strip()
    if version.returncode != 0 or not MOJO_VERSION_PATTERN.fullmatch(version_text):
        raise SystemExit(
            f"expected Mojo 1.0.0, observed {version_text!r}"
        )

    discovered = sorted((ROOT / "tests").glob("test_*.mojo"))
    missing_runners = [
        path.relative_to(ROOT).as_posix()
        for path in discovered
        if RUNNER_PATTERN.search(path.read_text()) is None
    ]
    if missing_runners:
        raise SystemExit(
            "test modules lack TestSuite.discover_tests runner: "
            + ", ".join(missing_runners)
        )
    by_stem = {path.stem: path for path in discovered}
    unknown_modules = sorted(set(args.module or ()) - set(by_stem))
    if unknown_modules:
        parser.error(
            "unknown test modules: " + ", ".join(unknown_modules)
        )
    selected = (
        [by_stem[name] for name in args.module]
        if args.module
        else discovered
    )

    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    for path in selected:
        row = _run_module(
            args.mojo,
            path,
            args.optimization,
            args.sanitize,
            args.timeout,
            environment,
        )
        rows.append(row)
        print(
            f"{row['status'].upper()}: {row['test']} "
            f"({row['elapsed_seconds']:.3f}s)"
        )

    failures = [row for row in rows if row["status"] != "pass"]
    totals = {
        name: sum(
            int(row["counts"][name])
            for row in rows
            if isinstance(row.get("counts"), dict)
        )
        for name in ("tests", "passed", "failed", "skipped")
    }
    complete = (
        not failures
        and len(rows) == len(selected)
        and totals["tests"] > 0
        and totals["tests"] == totals["passed"]
        and totals["failed"] == 0
        and totals["skipped"] == 0
    )
    report = {
        "status": "pass" if complete else "fail",
        "complete": complete,
        "compiler_version": version_text,
        "optimization": args.optimization,
        "sanitizer": args.sanitize,
        "discovered_modules": len(discovered),
        "selected_modules": len(selected),
        "module_failures": len(failures),
        "tests_run": totals["tests"],
        "tests_passed": totals["passed"],
        "tests_failed": totals["failed"],
        "tests_skipped": totals["skipped"],
        "elapsed_seconds": time.monotonic() - started,
        "tests": rows,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in (
        "status",
        "complete",
        "optimization",
        "sanitizer",
        "discovered_modules",
        "selected_modules",
        "module_failures",
        "tests_run",
        "tests_passed",
        "tests_failed",
        "tests_skipped",
        "elapsed_seconds",
    )}, indent=2))
    if not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
