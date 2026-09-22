# Structured field coverage

LogLens can summarize which structured fields are present in normalized events without copying their values into the result. This is useful when assessing a new log source before deciding which fields are safe and useful for deeper analysis.

```python
from loglens.field_analysis import summarize_field_coverage
from loglens.parsers import parse_json_line

events = [
    parse_json_line('{"message":"ok","request_id":"r1","status":200}'),
    parse_json_line('{"message":"failed","request_id":"r2"}'),
]

print(summarize_field_coverage(events))
```

The result reports total event count plus deterministic per-field `present` and `coverage` metrics. It intentionally omits field values, so exploratory schema inspection does not unnecessarily reproduce request identifiers, user data, tokens, or other sensitive log context.

This helper accepts any iterable of `LogEvent` objects, including generators, and consumes it once.
