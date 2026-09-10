#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path
from typing import Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "sooryathejas-metatron"
MANIFEST = ROOT / "vendor" / "sooryathejas-metatron.manifest.sha256"
IGNORED_DIRECTORIES = {".git", ".venv", "__pycache__", ".pytest_cache", ".metatron"}


# Iterate maintained files while treating the byte-for-byte vendor snapshot as opaque.
def maintained_files() -> Iterable[Path]:
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        if VENDOR in path.parents:
            continue
        yield path


# Ensure the retired target name is absent from both paths and readable content.
def validate_retired_name() -> List[str]:
    errors = []
    forbidden = ("mou" + "ci").casefold()
    for path in ROOT.rglob("*"):
        if any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
            continue
        relative = str(path.relative_to(ROOT))
        if forbidden in relative.casefold():
            errors.append("retired name in path: %s" % relative)
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if forbidden in content.casefold():
                errors.append("retired name in file: %s" % relative)
    return errors


# Recompute every archived byte so an upstream modification cannot go unnoticed.
def validate_vendor_manifest() -> List[str]:
    errors = []
    expected: Dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        expected[relative] = digest
    actual = {}
    for path in sorted(item for item in VENDOR.rglob("*") if item.is_file()):
        relative = str(path.relative_to(ROOT))
        actual[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if set(actual) != set(expected):
        errors.append("vendor file set differs from manifest")
    for relative in sorted(set(actual) & set(expected)):
        if actual[relative] != expected[relative]:
            errors.append("vendor digest mismatch: %s" % relative)
    return errors


# Require a short README in each maintained durable directory.
def validate_readme_coverage() -> List[str]:
    errors = []
    for directory in ROOT.rglob("*"):
        if not directory.is_dir() or any(part in IGNORED_DIRECTORIES for part in directory.parts):
            continue
        if VENDOR == directory or VENDOR in directory.parents or any(part.startswith(".") for part in directory.parts):
            continue
        if not (directory / "README.md").is_file():
            errors.append("missing README.md: %s" % directory.relative_to(ROOT))
    return errors


# Check the AI Foundation convention that every maintained function states its intent.
def validate_function_comments() -> List[str]:
    errors = []
    for path in sorted((ROOT / "metatron" / "src").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source, filename=str(path))
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for function in functions:
            cursor = function.lineno - 2
            while cursor >= 0 and not lines[cursor].strip():
                cursor -= 1
            if cursor < 0 or not lines[cursor].lstrip().startswith("#"):
                errors.append(
                    "missing intent comment: %s:%d %s" % (path.relative_to(ROOT), function.lineno, function.name)
                )
    return errors


# Require standard frontmatter on maintained Markdown, excluding engine instructions.
def validate_document_metadata() -> List[str]:
    errors = []
    for path in maintained_files():
        if path.suffix.lower() != ".md" or path.name == "AGENTS.md":
            continue
        if not path.read_text(encoding="utf-8").startswith("---\n"):
            errors.append("missing Markdown frontmatter: %s" % path.relative_to(ROOT))
    return errors


# Run all deterministic repository checks and print actionable failures.
def main() -> int:
    checks = [
        validate_retired_name,
        validate_vendor_manifest,
        validate_readme_coverage,
        validate_function_comments,
        validate_document_metadata,
    ]
    errors = [error for check in checks for error in check()]
    if errors:
        for error in errors:
            print("ERROR: %s" % error, file=sys.stderr)
        return 1
    print("repository validation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
