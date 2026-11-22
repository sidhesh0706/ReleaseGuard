"""Deterministic release manifests and safe release-to-release diffs.

The module intentionally uses only the standard library. A manifest contains
metadata and SHA-256 digests for files in a stable build directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
CHUNK_SIZE = 1024 * 1024


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def build_manifest(root: str | os.PathLike[str]) -> dict[str, Any]:
    """Build a manifest for a stable build directory without traversing links."""
    base = Path(root).expanduser().absolute()
    try:
        metadata = base.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"Release directory does not exist: {root}") from error
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise ValueError(f"Release root must be a directory, with links and reparse points excluded: {root}")

    files: list[dict[str, Any]] = []
    pending = [base]
    while pending:
        for path in pending.pop().iterdir():
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                files.append({"path": _relative(base, path), "kind": "symlink", "target": os.readlink(path)})
            elif _is_reparse_point(metadata):
                continue
            elif stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                files.append({
                    "path": _relative(base, path),
                    "kind": "file",
                    "size": metadata.st_size,
                    "mode": metadata.st_mode & 0o777,
                    "sha256": _digest(path),
                })

    files.sort(key=lambda entry: entry["path"])
    return {"schema": SCHEMA_VERSION, "files": files}


def _validate_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA_VERSION:
        raise ValueError(f"Manifest schema must be {SCHEMA_VERSION}.")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("Manifest files must be a list.")
    indexed: dict[str, dict[str, Any]] = {}
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("Each manifest entry must include a path.")
        path = entry["path"]
        if path in indexed:
            raise ValueError(f"Manifest contains duplicate path: {path}")
        if entry.get("kind") not in {"file", "symlink"}:
            raise ValueError(f"Unsupported entry kind for {path}.")
        indexed[path] = entry
    return indexed


def compare_manifests(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic summary of changes between two manifests."""
    old, new = _validate_manifest(before), _validate_manifest(after)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed: list[dict[str, Any]] = []
    for path in sorted(set(old) & set(new)):
        if old[path] != new[path]:
            changed.append({"path": path, "before": old[path], "after": new[path]})
    return {
        "schema": SCHEMA_VERSION,
        "added": [new[path] for path in added],
        "removed": [old[path] for path in removed],
        "changed": changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(set(old) & set(new)) - len(changed),
        },
    }


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Manifest {path} must contain a JSON object.")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and compare ReleaseGuard manifests.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    make = subparsers.add_parser("manifest", help="Create a manifest for a release directory.")
    make.add_argument("directory", type=Path)
    make.add_argument("--out", type=Path, required=True)
    diff = subparsers.add_parser("diff", help="Compare two release manifests.")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            result = build_manifest(args.directory)
            if args.out.resolve().is_relative_to(args.directory.resolve()):
                raise ValueError("Write the manifest outside the release directory.")
        else:
            result = compare_manifests(_load(args.before), _load(args.after))
        output = json.dumps(result, indent=2) + "\n"
        if args.command == "manifest" or args.out:
            target = args.out
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
