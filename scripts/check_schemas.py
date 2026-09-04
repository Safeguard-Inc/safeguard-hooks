#!/usr/bin/env python3
"""Validate the JSON schemas in schemas/ and the files that instantiate them.

Runs in two modes:

* strict — when the `jsonschema` package is importable, every instance file is
  validated against its schema with full JSON Schema semantics (this is the
  mode CI installs into: `python3 -m pip install jsonschema`). Cross-schema
  references of the form {"$ref": "<name>.schema.json"} are inlined before
  validation so no resolver/registry is needed.
* structural — otherwise, every schema and instance file is parsed, and
  instance files that declare a mapping are checked for their required keys
  and top-level type. This keeps the check meaningful on machines without the
  dependency while the strict path stays authoritative.

Usage: python3 scripts/check_schemas.py
Exit code 0 on success, 1 with a message on the first failure.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"

# Mapping of schema filename -> instance file(s) that must conform to it.
# Instance files not listed here are still required to parse as JSON.
INSTANCES = {
    "token-binding.schema.json": [
        "fixtures/tokens/confidential-token.json",
        "fixtures/tokens/sac-token.json",
        "fixtures/tokens/restricted-token.json",
    ],
    "freeze-state.schema.json": [
        "fixtures/accounts/compliant.json",
        "fixtures/accounts/frozen.json",
    ],
    "authorization-decision.schema.json": [
        "fixtures/accounts/blocked.json",
        "fixtures/accounts/unregistered.json",
        "fixtures/operations/register/expected-decision.json",
        "fixtures/operations/deposit/expected-decision.json",
        "fixtures/operations/merge/expected-decision.json",
        "fixtures/operations/transfer/expected-decision.json",
        "fixtures/operations/transfer-from/expected-decision.json",
        "fixtures/operations/withdraw/expected-decision.json",
    ],
    "policy-request.schema.json": [
        "fixtures/operations/register/request.json",
        "fixtures/operations/deposit/request.json",
        "fixtures/operations/merge/request.json",
        "fixtures/operations/transfer/request.json",
        "fixtures/operations/transfer-from/request.json",
        "fixtures/operations/withdraw/request.json",
    ],
}

# Files that must parse but are not instances of the wire schemas (reference
# data for the DEFINE polyrepo, deployment records, and scenario examples).
PARSE_ONLY_GLOBS = [
    "fixtures/policies/*.json",
    "examples/**/configuration.json",
    "deployments/local/*.json",
    "deployments/testnet/*.json",
]

# Structural sanity checks used when `jsonschema` is unavailable. Mirrors the
# `required` arrays of the schemas (kept deliberately small).
REQUIRED_KEYS = {
    "freeze-state.schema.json": ["token", "account", "frozen"],
    "token-binding.schema.json": ["token"],
    "policy-request.schema.json": ["operation", "token", "account"],
    "authorization-decision.schema.json": ["decision"],
}

REF_RE = re.compile(r"^([\w-]+\.schema\.json)$")


def fail(msg: str) -> None:
    print(f"schema check FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def load_schemas() -> dict[str, dict]:
    schemas = {}
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            fail(f"{path}: not valid JSON: {exc}")
        if not isinstance(data, dict):
            fail(f"{path}: schema must be a JSON object")
        for key in ("$schema", "title", "type"):
            if key not in data:
                fail(f"{path}: missing required top-level key {key!r}")
        if data.get("type") != "object":
            fail(f"{path}: top-level type must be \"object\"")
        schemas[path.name] = data
    if not schemas:
        fail("no *.schema.json files found in schemas/")
    print(f"schemas ok: {len(schemas)} schema(s) parsed")
    return schemas


def inline_refs(node, schemas: dict[str, dict]) -> object:
    """Replace {"$ref": "<name>.schema.json"} with the referenced schema."""
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            match = REF_RE.match(node["$ref"])
            if match and match.group(1) in schemas:
                return copy.deepcopy(schemas[match.group(1)])
        return {key: inline_refs(value, schemas) for key, value in node.items()}
    if isinstance(node, list):
        return [inline_refs(item, schemas) for item in node]
    return node


def check_instances(schemas: dict[str, dict]) -> None:
    try:
        from jsonschema.validators import validator_for  # type: ignore

        mode = "strict"
    except ImportError:
        validator_for = None
        mode = "structural"

    checked = 0
    for schema_name, files in INSTANCES.items():
        for rel in files:
            path = ROOT / rel
            if not path.is_file():
                fail(f"{rel}: instance file for {schema_name} not found")
            try:
                instance = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                fail(f"{rel}: not valid JSON: {exc}")
            if validator_for is not None:
                schema = inline_refs(copy.deepcopy(schemas[schema_name]), schemas)
                validator = validator_for(schema)(schema)
                errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
                if errors:
                    first = errors[0]
                    loc = "/".join(str(p) for p in first.path) or "<root>"
                    fail(f"{rel}: invalid against {schema_name} at {loc}: {first.message}")
            else:
                for key in REQUIRED_KEYS.get(schema_name, []):
                    if key not in instance:
                        fail(f"{rel}: structural check — missing required key {key!r}")
            checked += 1
    print(f"instances ok ({mode}): {checked} file(s) conform to their schema")


def check_parse_only() -> None:
    parsed = 0
    for glob in PARSE_ONLY_GLOBS:
        for path in sorted(ROOT.glob(glob)):
            try:
                json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                fail(f"{path}: not valid JSON: {exc}")
            parsed += 1
    print(f"reference data ok: {parsed} file(s) parse as JSON")


def main() -> None:
    schemas = load_schemas()
    check_instances(schemas)
    check_parse_only()
    print("schema check: all OK")


if __name__ == "__main__":
    main()
