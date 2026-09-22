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

    Field keys are represented as strings in the summary. If distinct mapping
    keys normalize to the same display key (for example ``1`` and ``"1"``),
    that field is counted at most once per event so presence and coverage can
    never exceed the number of events or 100 percent.
    """
    counts: Counter[str] = Counter()
    event_count = 0

    for event in events:
        event_count += 1
        display_keys = {str(key) for key in event.fields}
        counts.update(display_keys)

    fields = {
        key: {
            "present": counts[key],
            "coverage": counts[key] / event_count if event_count else 0.0,
        }
        for key in sorted(counts)
    }
    return {"events": event_count, "fields": fields}
