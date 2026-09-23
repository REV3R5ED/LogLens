"""Privacy-conscious analysis of structured fields attached to log events."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any
import unicodedata

from .model import LogEvent

_FIELD_SEPARATOR_CATEGORIES = {"Cc", "Zl", "Zp"}


def _normalized_field_name(key: object) -> str:
    """Return a stable, display-safe identity for a structured field key.

    Compatibility-equivalent Unicode spellings are folded together, invisible
    format controls are removed, and structural controls become whitespace
    boundaries. This prevents visually equivalent or control-character-bearing
    keys from fragmenting schema coverage or producing misleading reports.
    """
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


def summarize_field_coverage(events: Iterable[LogEvent]) -> dict[str, Any]:
    """Summarize structured-field presence and coarse types without values.

    The summary is intentionally schema-oriented: it reports how often each
    field is present, which coarse value types were observed, and whether more
    than one non-null type was seen. Null remains visible in type counts but is
    treated as field nullability rather than schema drift by itself. It never
    copies values from logs into the result. This makes it useful for spotting
    schema drift during defensive triage while avoiding request identifiers,
    user data, or other sensitive field contents.

    Field keys are represented by stable display identities in the summary.
    Compatibility-equivalent keys and keys differing only by invisible format
    controls are grouped together. If distinct mapping keys normalize to the
    same display identity, that field is counted at most once per event so
    presence and coverage can never exceed the number of events or 100 percent.
    Type counts describe observed raw field occurrences and can therefore be
    higher than presence when one event contains colliding normalized keys.
    """
    counts: Counter[str] = Counter()
    type_counts: dict[str, Counter[str]] = defaultdict(Counter)
    event_count = 0

    for event in events:
        event_count += 1
        display_keys = {_normalized_field_name(key) for key in event.fields}
        counts.update(display_keys)
        for key, value in event.fields.items():
            type_counts[_normalized_field_name(key)][_value_type(value)] += 1

    fields = {}
    for key in sorted(counts):
        types = dict(sorted(type_counts[key].items()))
        non_null_types = {type_name for type_name in types if type_name != "null"}
        fields[key] = {
            "present": counts[key],
            "coverage": counts[key] / event_count if event_count else 0.0,
            "types": types,
            "type_drift": len(non_null_types) > 1,
        }
    return {"events": event_count, "fields": fields}
