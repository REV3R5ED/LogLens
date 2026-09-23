"""Privacy-conscious analysis of structured fields attached to log events."""

from __future__ import annotations

from collections import Counter
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


def summarize_field_coverage(events: Iterable[LogEvent]) -> dict[str, Any]:
    """Summarize structured-field presence without exposing field values.

    The summary is intentionally schema-oriented: it reports how often each
    field is present, but never copies values from logs into the result. This
    makes it suitable for exploratory defensive triage where structured fields
    may contain request identifiers, user data, or other sensitive context.

    Field keys are represented by stable display identities in the summary.
    Compatibility-equivalent keys and keys differing only by invisible format
    controls are grouped together. If distinct mapping keys normalize to the
    same display identity, that field is counted at most once per event so
    presence and coverage can never exceed the number of events or 100 percent.
    """
    counts: Counter[str] = Counter()
    event_count = 0

    for event in events:
        event_count += 1
        display_keys = {_normalized_field_name(key) for key in event.fields}
        counts.update(display_keys)

    fields = {
        key: {
            "present": counts[key],
            "coverage": counts[key] / event_count if event_count else 0.0,
        }
        for key in sorted(counts)
    }
    return {"events": event_count, "fields": fields}
