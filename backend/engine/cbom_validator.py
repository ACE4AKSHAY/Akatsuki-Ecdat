"""Validation of emitted CBOM documents against the official CycloneDX schema.

The CycloneDX 1.6 JSON schema is vendored under backend/knowledge/schemas/
so validation works offline and identically in CI. `spdx.schema.json` is
vendored alongside it because the BOM schema references it.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import warnings

from jsonschema import Draft7Validator, RefResolver
from jsonschema.exceptions import SchemaError

_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "knowledge" / "schemas"
SCHEMA_PATH = _SCHEMA_DIR / "bom-1.6.schema.json"


@lru_cache(maxsize=1)
def load_schema() -> dict:
    with SCHEMA_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    schema = load_schema()
    with warnings.catch_warnings():
        # RefResolver is deprecated in favour of the referencing registry but
        # remains the simplest way to resolve the vendored spdx.schema.json.
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver(
            base_uri=_SCHEMA_DIR.resolve().as_uri() + "/",
            referrer=schema,
        )
    return Draft7Validator(schema, resolver=resolver)


def validate_document(document: dict) -> list[str]:
    """Validate a parsed CBOM document. Returns a list of readable problems."""
    try:
        validator = _validator()
    except SchemaError as exc:  # pragma: no cover - the vendored schema is fixed
        return [f"schema error: {exc}"]
    problems = []
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        problems.append(f"{location}: {error.message}")
    return problems


def validate_file(path: str | Path) -> list[str]:
    with Path(path).open(encoding="utf-8") as handle:
        document = json.load(handle)
    problems = validate_document(document)
    if not problems:
        bom_format = document.get("bomFormat")
        spec = document.get("specVersion")
        if bom_format != "CycloneDX" or spec != "1.6":
            problems.append(
                f"document validates but is {bom_format} {spec}; ECDAT emits CycloneDX 1.6"
            )
    return problems
