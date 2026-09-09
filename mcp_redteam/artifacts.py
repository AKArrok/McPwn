"""Validation helpers for McPwn machine-readable artifacts."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

FINDINGS_V1_SCHEMA_PATH = Path(__file__).with_name("schemas") / "findings-v1.schema.json"


class ArtifactValidationError(ValueError):
    """Raised when a machine-readable artifact does not match its schema."""


@lru_cache(maxsize=1)
def findings_v1_schema() -> dict[str, Any]:
    """Load the checked-in JSON Schema for findings.json schema_version=1."""
    return json.loads(FINDINGS_V1_SCHEMA_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _findings_v1_validator() -> Draft202012Validator:
    schema = findings_v1_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_findings_artifact(data: dict[str, Any]) -> None:
    """Validate a loaded findings.json artifact against the v1 JSON Schema."""
    version = data.get("schema_version")
    if version != 1:
        raise ArtifactValidationError(
            f"unsupported schema_version={version!r}; expected 1"
        )
    errors = sorted(_findings_v1_validator().iter_errors(data), key=lambda e: e.path)
    if errors:
        raise ArtifactValidationError(_format_validation_error(errors[0]))


def _format_validation_error(error: ValidationError) -> str:
    location = "$" + "".join(f"[{part!r}]" for part in error.absolute_path)
    return f"{location}: {error.message}"
