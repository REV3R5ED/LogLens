"""Privacy-conscious analysis of structured fields attached to log events."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any
import unicodedata

from .model import LogEvent

_FIELD_SEPARATOR_CATEGORIES = {"Cc", "Zl", "Zp"}


def _normalized_field_name(key: object) -> str:
    """Return a stable, display-safe identity for a structured field key."""
    name = unicodedata.normalize("NFKC", str(key))
    normalized = []
    for char in name:
        category = unicodedata.category(char)
        if category == "Cf":
            continue
        if category in _FIELD_SEPARATOR_CATEGORIES:
            normalized.append(" ")
        else:
            normalized.append(char)
    return " ".join("".join(normalized).split()) or "<empty>"


def _value_type(value: Any) -> str:
    """Return a coarse JSON-oriented type label without exposing a value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, (list, tuple)):
        return "array"
    return "other"


def _type_family(type_name: str) -> str:
    """Return the compatible schema family for one coarse non-null type."""
    return "number" if type_name in {"integer", "number"} else type_name


def _type_families(types: set[str]) -> list[str]:
    """Return deterministic compatible schema families for non-null types."""
    return sorted({_type_family(type_name) for type_name in types})


def _type_family_counts(types: dict[str, int]) -> dict[str, int]:
    """Aggregate non-null coarse type occurrences into schema families."""
    family_counts: Counter[str] = Counter()
    for type_name, count in types.items():
        if type_name != "null":
            family_counts[_type_family(type_name)] += count
    return dict(sorted(family_counts.items()))


def _type_family_rates(family_counts: dict[str, int]) -> dict[str, float]:
    """Return each schema family's share of non-null field occurrences."""
    total = sum(family_counts.values())
    if not total:
        return {}
    return {family: count / total for family, count in family_counts.items()}


def summarize_field_coverage(events: Iterable[LogEvent]) -> dict[str, Any]:
    """Summarize structured-field presence, nullability, and coarse types safely.

    Values are never copied from logs. When incompatible non-null schema families
    are observed, the report includes those coarse families and their occurrence
    prevalence as privacy-safe drift evidence.
    """
    counts: Counter[str] = Counter()
    null_counts: Counter[str] = Counter()
    type_counts: dict[str, Counter[str]] = defaultdict(Counter)
    event_count = 0

    for event in events:
        event_count += 1
        display_keys = {_normalized_field_name(key) for key in event.fields}
        null_candidates = {
            _normalized_field_name(key) for key, value in event.fields.items() if value is None
        }
        populated_keys = {
            _normalized_field_name(key) for key, value in event.fields.items() if value is not None
        }
        counts.update(display_keys)
        null_counts.update(null_candidates - populated_keys)
        for key, value in event.fields.items():
            type_counts[_normalized_field_name(key)][_value_type(value)] += 1

    fields = {}
    for key in sorted(counts):
        types = dict(sorted(type_counts[key].items()))
        non_null_types = {type_name for type_name in types if type_name != "null"}
        type_families = _type_families(non_null_types)
        populated = counts[key] - null_counts[key]
        field = {
            "present": counts[key],
            "missing": event_count - counts[key],
            "coverage": counts[key] / event_count if event_count else 0.0,
            "populated": populated,
            "populated_rate": populated / event_count if event_count else 0.0,
            "nulls": null_counts[key],
            "null_rate": null_counts[key] / counts[key] if counts[key] else 0.0,
            "types": types,
            "type_drift": len(type_families) > 1,
        }
        if field["type_drift"]:
            family_counts = _type_family_counts(types)
            field["type_drift_families"] = type_families
            field["type_drift_family_counts"] = family_counts
            field["type_drift_family_rates"] = _type_family_rates(family_counts)
        fields[key] = field
    return {"events": event_count, "fields": fields}
