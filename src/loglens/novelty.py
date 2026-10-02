"""Persisted known-message corpus for the novelty detection rule.

The novelty rule complements ``repeated-message``: instead of flagging
messages seen *too often*, it flags messages *never observed* in a reference
corpus. The corpus is a plain JSON file (no database dependency) mapping
``(source, level, normalized message)`` keys to first-seen metadata, so teams
can version it alongside detection policies and rebuild it deterministically.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .detection import _normalize_level, _normalize_message, _normalize_source
from .model import LogEvent

STORE_VERSION = 1


class NoveltyError(ValueError):
    """Raised when a novelty store cannot be read or written."""


def corpus_key(source: str | None, level: str, message: str) -> tuple[str | None, str, str]:
    """Return the canonical ``(source, level, normalized message)`` corpus key."""
    return (_normalize_source(source), _normalize_level(level), _normalize_message(message))


class KnownCorpus:
    """A persisted set of previously observed message keys.

    Keys use the same normalization as the repeated-message rule, so a message
    is novel only when this source has never emitted it at this level before.
    A missing store file loads as an empty corpus; anything else unreadable
    raises :class:`NoveltyError`.
    """

    def __init__(self, entries: Mapping[tuple[str | None, str, str], Mapping[str, Any]] | None = None) -> None:
        self._entries: dict[tuple[str | None, str, str], dict[str, Any]] = {
            key: dict(value) for key, value in (entries or {}).items()
        }

    @classmethod
    def load(cls, path: Path | str) -> "KnownCorpus":
        """Load a corpus; a missing file yields an empty corpus."""
        store = Path(path)
        try:
            raw = json.loads(store.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except OSError as exc:
            raise NoveltyError(f"cannot read novelty store {store}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise NoveltyError(f"invalid JSON in novelty store {store}: {exc}") from exc
        if not isinstance(raw, dict):
            raise NoveltyError(f"novelty store {store} must contain a JSON object")
        version = raw.get("version", STORE_VERSION)
        if version != STORE_VERSION:
            raise NoveltyError(f"novelty store {store} has unsupported version {version!r}")
        raw_messages = raw.get("messages", [])
        if not isinstance(raw_messages, list):
            raise NoveltyError(f"novelty store {store}: messages must be a list")
        entries: dict[tuple[str | None, str, str], dict[str, Any]] = {}
        for record in raw_messages:
            if not isinstance(record, dict):
                raise NoveltyError(f"novelty store {store}: message records must be objects")
            source = record.get("source")
            level = record.get("level")
            message = record.get("message")
            count = record.get("count", 1)
            if source is not None and not isinstance(source, str):
                raise NoveltyError(f"novelty store {store}: message records need a string source")
            if not isinstance(level, str) or not isinstance(message, str):
                raise NoveltyError(f"novelty store {store}: message records need string level and message")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise NoveltyError(f"novelty store {store}: message records need a non-negative integer count")
            key = corpus_key(source or None, level, message)
            entries[key] = {
                "count": count,
                "first_seen": str(record.get("first_seen", "")),
            }
        return cls(entries)

    def __contains__(self, key: tuple[str | None, str, str]) -> bool:
        return key in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def keys(self) -> frozenset[tuple[str | None, str, str]]:
        """Return the known corpus keys for novelty detection."""
        return frozenset(self._entries)

    def learn(self, events: Iterable[LogEvent], *, observed_at: datetime | None = None) -> int:
        """Add events' message keys; return the number of newly learned keys."""
        counts: dict[tuple[str | None, str, str], int] = {}
        for event in events:
            normalized = _normalize_message(event.message)
            if not normalized:
                continue
            key = corpus_key(event.source, event.level, event.message)
            counts[key] = counts.get(key, 0) + 1
        return self.learn_counts(counts, observed_at=observed_at)

    def learn_counts(
        self,
        counts: Mapping[tuple[str | None, str, str], int],
        *,
        observed_at: datetime | None = None,
    ) -> int:
        """Merge pre-aggregated ``(key -> count)`` pairs; return new key count."""
        moment = observed_at or datetime.now(timezone.utc)
        stamped = moment.isoformat()
        new_keys = 0
        for key, count in counts.items():
            entry = self._entries.get(key)
            if entry is None:
                self._entries[key] = {"count": int(count), "first_seen": stamped}
                new_keys += 1
            else:
                entry["count"] = int(entry.get("count", 0)) + int(count)
        return new_keys

    def to_dict(self) -> dict[str, Any]:
        """Return the deterministic serializable store payload."""
        messages = [
            {
                "source": key[0],
                "level": key[1],
                "message": key[2],
                "count": entry["count"],
                "first_seen": entry["first_seen"],
            }
            for key, entry in sorted(
                self._entries.items(), key=lambda item: ((item[0][0] or ""), item[0][1], item[0][2])
            )
        ]
        return {"version": STORE_VERSION, "messages": messages}

    def save(self, path: Path | str) -> None:
        """Write the corpus deterministically; keys sort by (source, level, message)."""
        store = Path(path)
        try:
            store.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError as exc:
            raise NoveltyError(f"cannot write novelty store {store}: {exc}") from exc
