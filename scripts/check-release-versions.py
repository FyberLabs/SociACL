#!/usr/bin/env python3
"""Fail unless the ids-v and sociacl-v release families each have one semver.

ids-v reads typescript/ids and crates/sociacl-ids.
sociacl-v reads the sociacl npm package, workspace.package.version, and every
workspace crate that inherits it. sociacl-ids is the only crate allowed to pin
a different version.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from pathlib import Path

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
ROOT = (
    Path(os.environ["CHECK_RELEASE_ROOT"]).resolve()
    if os.environ.get("CHECK_RELEASE_ROOT")
    else Path(__file__).resolve().parents[1]
)


def die(message: str) -> None:
    print(f"version check: {message}", file=sys.stderr)
    sys.exit(1)


def require_semver(label: str, value: object) -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        die(f"{label} is not MAJOR.MINOR.PATCH: {value!r}")
    return value


def npm_versions(package_path: str, lock_path: str) -> list[tuple[str, str]]:
    package = json.loads((ROOT / package_path).read_text(encoding="utf-8"))
    lock = json.loads((ROOT / lock_path).read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        die(f"{lock_path} is missing packages[\"\"]")
    return [
        (f"{package_path} version", require_semver(f"{package_path} version", package.get("version"))),
        (f"{lock_path} version", require_semver(f"{lock_path} version", lock.get("version"))),
        (
            f'{lock_path} packages[""].version',
            require_semver(f'{lock_path} packages[""].version', packages[""].get("version")),
        ),
    ]


def read_member(rel: str) -> tuple[str, str | None]:
    path = ROOT / rel / "Cargo.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    package = data.get("package")
    label = f"{rel}/Cargo.toml"
    if not isinstance(package, dict):
        die(f"{label} has no [package]")
    name = package.get("name")
    if not isinstance(name, str) or not name:
        die(f"{label} has no package name")
    version = package.get("version")
    if isinstance(version, str):
        return name, require_semver(f"{label} version", version)
    if isinstance(version, dict) and version.get("workspace") is True:
        return name, None
    die(f"{label} version is not an explicit semver or workspace version")


def lock_version(packages: list[object], name: str) -> str:
    found: list[object] = []
    for package in packages:
        if isinstance(package, dict) and package.get("name") == name:
            found.append(package)
    if len(found) != 1 or not isinstance(found[0], dict):
        die(f"Cargo.lock has {len(found)} {name} entries")
    return require_semver(f"Cargo.lock {name}", found[0].get("version"))


def agree(family: str, pairs: list[tuple[str, str]]) -> None:
    versions = {value for _, value in pairs}
    if len(versions) != 1:
        detail = "\n".join(f"  {name}: {value}" for name, value in pairs)
        die(f"{family} versions differ\n{detail}")
    print(f"{family} {pairs[0][1]}")


def main() -> None:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = cargo.get("workspace")
    if not isinstance(workspace, dict):
        die("Cargo.toml has no [workspace]")
    package_table = workspace.get("package")
    if not isinstance(package_table, dict):
        die("Cargo.toml has no [workspace.package]")
    workspace_version = require_semver(
        "Cargo.toml workspace.package.version",
        package_table.get("version"),
    )
    members = workspace.get("members")
    if not isinstance(members, list) or not members:
        die("Cargo.toml has no workspace members")

    explicit: list[tuple[str, str]] = []
    shared: list[str] = []
    for member in members:
        if not isinstance(member, str):
            die("workspace member is not a path")
        name, version = read_member(member)
        if version is None:
            shared.append(name)
        else:
            explicit.append((name, version))

    explicit_names = sorted(name for name, _ in explicit)
    if explicit_names != ["sociacl-ids"]:
        die(
            "only sociacl-ids may pin its own version; "
            f"found {explicit_names or 'none'}"
        )
    if not shared:
        die("sociacl-v has no workspace-versioned crates")

    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    lock_packages = lock.get("package")
    if not isinstance(lock_packages, list):
        die("Cargo.lock has no package list")

    ids_version = dict(explicit)["sociacl-ids"]
    ids_pairs = npm_versions(
        "typescript/ids/package.json",
        "typescript/ids/package-lock.json",
    )
    ids_pairs.append(("crates/sociacl-ids/Cargo.toml version", ids_version))
    ids_pairs.append(("Cargo.lock sociacl-ids", lock_version(lock_packages, "sociacl-ids")))
    agree("ids-v", ids_pairs)

    sociacl_pairs = npm_versions("typescript/package.json", "typescript/package-lock.json")
    sociacl_pairs.append(("Cargo.toml workspace.package.version", workspace_version))
    for name in shared:
        sociacl_pairs.append((f"Cargo.lock {name}", lock_version(lock_packages, name)))
    agree("sociacl-v", sociacl_pairs)


if __name__ == "__main__":
    main()
