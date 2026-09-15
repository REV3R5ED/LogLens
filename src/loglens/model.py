"""Normalized event types used across LogLens."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class LogEvent:
    """A normalized representation of one input log record."""

    message: str
    level: str = "UNKNOWN"
    timestamp: datetime | None = None
    source: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the event."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "fields": self.fields,
        }
