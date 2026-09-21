"""Normalized event types used across LogLens."""

import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _normalize_source(value: str | None) -> str | None:
    """Canonicalize a logical source while removing invisible format controls."""
    if value is None:
        return None
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(char for char in normalized if unicodedata.category(char) != "Cf")
    normalized = normalized.strip()
    return normalized or None


@dataclass(frozen=True, slots=True)
class LogEvent:
    """A normalized representation of one input log record."""

    message: str
    level: str = "UNKNOWN"
    timestamp: datetime | None = None
    source: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Enforce canonical source identity at the normalized event boundary."""
        object.__setattr__(self, "source", _normalize_source(self.source))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the event."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "fields": self.fields,
        }
