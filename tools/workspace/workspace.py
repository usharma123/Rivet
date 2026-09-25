#!/usr/bin/env python3
"""Workspace governance checks for the Rivet monorepo."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_FILE = ROOT / "rivet.workspace.toml"
SNAPSHOT_FILE = ROOT / "workspace.snapshot.json"
LABELER_FILE = ROOT / ".github" / "labeler.yml"
CI_FILE = ROOT / ".github" / "workflows" / "ci.yml"
GENERATED_BY = "tools/workspace/workspace.py sync"


def main() -> int:
    parser = argparse.ArgumentParser(description="Rivet workspace governance checks")
    parser.add_argument(
        "command",
        choices=["check", "sync", "docs-check", "schema-check", "examples-check", "fixtures-check"],
    )
    args = parser.parse_args()

    workspace = load_workspace()
    if args.command == "sync":
        sync(workspace)
        return 0

    failures: list[str] = []
    if args.command in {"check", "docs-check"}:
        failures.extend(check_docs(workspace))
    if args.command in {"check", "schema-check"}:
        failures.extend(check_schemas(workspace))
    if args.command in {"check", "examples-check"}:
        failures.extend(check_examples())
    if args.command in {"check", "fixtures-check"}:
        failures.extend(check_fixtures())
    if args.command == "check":
        failures.extend(check_workspace_metadata(workspace))
        failures.extend(check_snapshots(workspace))
        failures.extend(check_labeler(workspace))
        failures.extend(check_ci(workspace))

    if failures:
        for failure in failures:
            print(f"workspace-check: {failure}", file=sys.stderr)
        return 1
    print(f"workspace-{args.command}: ok")
    return 0


def load_workspace() -> dict[str, Any]:
    with WORKSPACE_FILE.open("rb") as handle:
        return tomllib.load(handle)


def sync(workspace: dict[str, Any]) -> None:
    write_json(SNAPSHOT_FILE, workspace_snapshot(workspace))
    for path, payload in example_snapshots().items():
        write_json(path, payload)
    for path, payload in fixture_snapshots().items():
        write_json(path, payload)
    print("workspace-sync: updated workspace and fixture snapshots")


def check_workspace_metadata(workspace: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    components = workspace.get("components", [])
    release_groups = {group["id"]: group for group in workspace.get("release_groups", [])}
    make_targets = parse_make_targets()

    seen_ids: set[str] = set()
    for component in components:
        component_id = component.get("id", "")
        if not component_id:
            failures.append("component is missing id")
            continue
        if component_id in seen_ids:
            failures.append(f"duplicate component id {component_id}")
        seen_ids.add(component_id)

        for field in [
            "kind",
            "path",
            "owners",
            "release_group",
            "public_interfaces",
            "validation_commands",
            "docs",
            "schemas",
        ]:
            if field not in component:
                failures.append(f"{component_id}: missing {field}")

        path = ROOT / component.get("path", "")
        if not path.exists():
            failures.append(f"{component_id}: path does not exist: {component.get('path')}")

        release_group = component.get("release_group")
        if release_group not in release_groups:
            failures.append(f"{component_id}: unknown release_group {release_group}")

        if not component.get("validation_commands"):
            failures.append(f"{component_id}: validation_commands cannot be empty")
        for command in component.get("validation_commands", []):
            target = make_target_for_command(command)
            if target and target not in make_targets:
                failures.append(f"{component_id}: Makefile target missing for {command}")

        if not component.get("public_interfaces"):
            failures.append(f"{component_id}: public_interfaces cannot be empty")

    public = workspace.get("public", {})
    if sorted(public.get("cli_commands", [])) != sorted(cli_commands_from_source()):
        failures.append("public.cli_commands is out of sync with cli/src/lib.rs")

    return failures


def check_docs(workspace: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    readme = read_text(ROOT / "README.md")

    for component in workspace.get("components", []):
        component_id = component["id"]
        component_path = component["path"]
        if component_id not in readme:
            failures.append(f"{component_id}: README.md does not mention component id")
        if component_path not in readme:
            failures.append(f"{component_id}: README.md does not mention component path {component_path}")
        for doc in component.get("docs", []):
            doc_path = ROOT / doc
            if not doc_path.exists():
                failures.append(f"{component_id}: doc path missing: {doc}")

    for command in workspace.get("public", {}).get("cli_commands", []):
        if f"`rivet {command}`" not in readme and f"rivet {command}" not in readme:
            failures.append(f"README.md does not document rivet {command}")

    for schema in workspace.get("public", {}).get("schema_files", []):
        if Path(schema).name not in readme:
            failures.append(f"README.md does not document schema {schema}")

    return failures


def check_schemas(workspace: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    expected = sorted(workspace.get("public", {}).get("schema_files", []))
    actual = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "schemas").glob("*.schema.json"))
    if expected != actual:
        failures.append(f"schema_files mismatch: expected {expected}, actual {actual}")

    schema_refs = sorted(
        {
            schema
            for component in workspace.get("components", [])
            for schema in component.get("schemas", [])
        }
    )
    for schema in schema_refs:
        if not (ROOT / schema).exists():
            failures.append(f"component references missing schema {schema}")

    for schema in actual:
        try:
            data = json.loads((ROOT / schema).read_text())
        except json.JSONDecodeError as exc:
            failures.append(f"{schema}: invalid JSON: {exc}")
            continue
        for field in ["$schema", "$id", "title", "type"]:
            if field not in data:
                failures.append(f"{schema}: missing {field}")
    return failures


def check_examples() -> list[str]:
    return compare_snapshot_map(example_snapshots(), "example")


def check_fixtures() -> list[str]:
    return compare_snapshot_map(fixture_snapshots(), "fixture")


def check_snapshots(workspace: dict[str, Any]) -> list[str]:
    failures = compare_snapshot_map({SNAPSHOT_FILE: workspace_snapshot(workspace)}, "workspace")
    expected_paths = {SNAPSHOT_FILE, *example_snapshots().keys(), *fixture_snapshots().keys()}
    actual_paths = {
        path
        for base in [ROOT / "examples", ROOT / "fixtures"]
        if base.exists()
        for path in base.glob("**/.rivet-snapshots/*.json")
    }
    extra = sorted(str(path.relative_to(ROOT)) for path in actual_paths - expected_paths)
    for path in extra:
        failures.append(f"unexpected generated snapshot {path}")
    return failures


def check_labeler(workspace: dict[str, Any]) -> list[str]:
    expected = expected_labeler_yaml(workspace)
    actual = read_text(LABELER_FILE)
    if actual != expected:
        return ["path labeler is out of sync with rivet.workspace.toml"]
    return []


def check_ci(workspace: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    ci = read_text(CI_FILE)
    for command in workspace.get("public", {}).get("ci_required_commands", []):
        if command not in ci:
            failures.append(f"CI does not run required command: {command}")
    workspace_index = ci.find("make workspace-check")
    cli_index = ci.find("make cli-test")
    if workspace_index == -1 or cli_index == -1 or workspace_index > cli_index:
        failures.append("CI must run make workspace-check before product test jobs")
    return failures


def workspace_snapshot(workspace: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_by": GENERATED_BY,
        "version": workspace["version"],
        "workspace": workspace["workspace"],
        "public": workspace["public"],
        "components": sorted(workspace["components"], key=lambda item: item["id"]),
        "release_groups": sorted(workspace["release_groups"], key=lambda item: item["id"]),
    }


def example_snapshots() -> dict[Path, dict[str, Any]]:
    snapshots: dict[Path, dict[str, Any]] = {}
    examples_dir = ROOT / "examples"
    if not examples_dir.exists():
        return snapshots
    for example_dir in sorted(path for path in examples_dir.iterdir() if path.is_dir()):
        rel = str(example_dir.relative_to(ROOT))
        snapshot_dir = example_dir / ".rivet-snapshots"
        manifest = example_dir / "rivet.toml"
        if manifest.exists():
            with manifest.open("rb") as handle:
                manifest_data = tomllib.load(handle)
            snapshots[snapshot_dir / "manifest.snapshot.json"] = {
                "generated_by": GENERATED_BY,
                "example": example_dir.name,
                "path": rel,
                "package": manifest_data.get("package", {}),
                "executables": sorted((manifest_data.get("executables") or {}).keys()),
                "has_publisher": "publisher" in manifest_data,
            }
        readme = example_dir / "README.md"
        if readme.exists():
            snapshots[snapshot_dir / "readme-commands.snapshot.json"] = {
                "generated_by": GENERATED_BY,
                "example": example_dir.name,
                "path": rel,
                "commands": commands_from_markdown(readme),
            }
    return snapshots


def fixture_snapshots() -> dict[Path, dict[str, Any]]:
    packages_dir = ROOT / "fixtures" / "packages"
    fixtures: list[dict[str, Any]] = []
    if packages_dir.exists():
        for package_json in sorted(packages_dir.glob("*/package.json")):
            data = json.loads(package_json.read_text())
            fixtures.append(
                {
                    "path": str(package_json.parent.relative_to(ROOT)),
                    "name": data["name"],
                    "version": data["version"],
                    "has_bin": bool(data.get("bin")),
                    "scripts": sorted((data.get("scripts") or {}).keys()),
                    "expected_verdict": (data.get("rivetFixture") or {}).get("expectedVerdict", "unknown"),
                    "expected_state": (data.get("rivetFixture") or {}).get("expectedState", "active"),
                }
            )
    return {
        ROOT / "fixtures" / ".rivet-snapshots" / "fixture-catalog.snapshot.json": {
            "generated_by": GENERATED_BY,
            "fixtures": fixtures,
        }
    }


def compare_snapshot_map(expected: dict[Path, dict[str, Any]], label: str) -> list[str]:
    failures: list[str] = []
    for path, payload in expected.items():
        expected_text = json_text(payload)
        if not path.exists():
            failures.append(f"{label} snapshot missing: {path.relative_to(ROOT)}")
            continue
        if path.read_text() != expected_text:
            failures.append(f"{label} snapshot stale: {path.relative_to(ROOT)}")
    return failures


def cli_commands_from_source() -> list[str]:
    """Top-level commands from `enum Command`, expanding any command backed
    by a `<Name>Command` subcommand enum into "<name> <sub>" entries."""
    source = read_text(ROOT / "cli" / "src" / "lib.rs")
    variant = re.compile(r"^\s{4}([A-Z][A-Za-z]+)\s*(?:\{|,)", re.M)

    def enum_variants(name: str) -> list[str]:
        body = source.split(f"pub enum {name} {{", 1)[1]
        body = body.split("\n}\n", 1)[0]
        return [match.group(1) for match in variant.finditer(body)]

    subcommand_enums = {
        match.group(1).lower(): match.group(0).split()[-1]
        for match in re.finditer(r"pub enum ([A-Z][A-Za-z]+)Command\b", source)
        if match.group(1)
    }
    commands: list[str] = []
    for name in enum_variants("Command"):
        lowered = name.lower()
        if lowered in subcommand_enums:
            commands.extend(f"{lowered} {sub.lower()}" for sub in enum_variants(subcommand_enums[lowered]))
        else:
            commands.append(lowered)
    return sorted(commands)


def commands_from_markdown(path: Path) -> list[str]:
    commands: list[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("rivet "):
            commands.append(stripped)
    return commands


def parse_make_targets() -> set[str]:
    makefile = read_text(ROOT / "Makefile")
    return {
        match.group(1)
        for match in re.finditer(r"^([A-Za-z0-9_.-]+):", makefile, re.M)
        if not match.group(1).startswith(".")
    }


def make_target_for_command(command: str) -> str | None:
    parts = command.split()
    if len(parts) >= 2 and parts[0] == "make":
        return parts[1]
    return None


def expected_labeler_yaml(workspace: dict[str, Any]) -> str:
    lines: list[str] = []
    for group in sorted(workspace.get("release_groups", []), key=lambda item: item["id"]):
        lines.append(f'"{group["label"]}":')
        lines.append("  - changed-files:")
        for path in group["paths"]:
            lines.append(f"      - any-glob-to-any-file: {path}")
    return "\n".join(lines) + "\n"


def read_text(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_text(payload))


def json_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
