"""Privacy-conscious analysis of structured fields attached to log events."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from .model import LogEvent


def summarize_field_coverage(events: Iterable[LogEvent]) -> dict[str, Any]:
    """Summarize structured-field presence without exposing field values.

    The summary is intentionally schema-oriented: it reports how often each
    field is present, but never copies values from logs into the result. This
    makes it suitable for exploratory defensive triage where structured fields
    may contain request identifiers, user data, or other sensitive context.
    """
    counts: Counter[str] = Counter()
    event_count = 0

    for event in events:
        event_count += 1
        counts.update(str(key) for key in event.fields)

    fields = {
        key: {
            "present": counts[key],
            "coverage": counts[key] / event_count if event_count else 0.0,
        }
        for key in sorted(counts)
    }
    return {"events": event_count, "fields": fields}
