#!/usr/bin/env python3
"""Release guard: refuse to publish unless the ref is a tag whose version
matches the package's declared version.

Usage: check_release_version.py <package> <git-ref> [--root DIR]
Prints the version on success; exits non-zero with an ::error:: line otherwise.
"""
import argparse
import json
import sys
import tomllib
from pathlib import Path

# package -> (tag prefix, manifest path, kind)
PACKAGES = {
    "node": ("node-v", "node/package.json", "json"),
    "python": ("python-v", "python/pyproject.toml", "toml"),
    "mcp": ("mcp-v", "mcp-server/pyproject.toml", "toml"),
    "openclaw": ("openclaw-v", "openclaw-plugin/package.json", "json"),
    "schemas": ("schemas-v", "schemas/package.json", "json"),
}


def fail(msg):
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def read_version(root: Path, rel: str, kind: str) -> str:
    path = root / rel
    try:
        if kind == "toml":
            return tomllib.loads(path.read_text())["project"]["version"]
        return json.loads(path.read_text())["version"]
    except (OSError, KeyError, ValueError) as exc:
        fail(f"cannot read version from {rel}: {exc}")


def check_mcp_server_json(root: Path, expected: str) -> None:
    rel = "mcp-server/server.json"
    try:
        data = json.loads((root / rel).read_text())
        found = {"version": data["version"], "packages[0].version": data["packages"][0]["version"]}
    except (OSError, KeyError, IndexError, ValueError) as exc:
        fail(f"cannot read versions from {rel}: {exc}")
    for field, value in found.items():
        if value != expected:
            fail(f"{rel} {field}={value} does not match package version {expected}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("package")
    parser.add_argument("ref")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args()

    if args.package not in PACKAGES:
        fail(f"unknown package {args.package!r}")
    prefix, manifest, kind = PACKAGES[args.package]
    root = Path(args.root)

    tag_ref = "refs/tags/"
    if not args.ref.startswith(tag_ref):
        fail(f"publishing is only allowed from a tag; got ref {args.ref}")
    tag = args.ref[len(tag_ref):]
    if not tag.startswith(prefix):
        fail(f"tag {tag} does not start with {prefix}")
    tag_version = tag[len(prefix):]

    version = read_version(root, manifest, kind)
    if tag_version != version:
        fail(f"tag version {tag_version} does not match {manifest} version {version}")
    if args.package == "mcp":
        check_mcp_server_json(root, version)
    print(version)


if __name__ == "__main__":
    main()
