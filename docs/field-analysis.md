# Structured field coverage

LogLens can summarize which structured fields are present in normalized events without copying their values into the result. This is useful when assessing a new log source before deciding which fields are safe and useful for deeper analysis.

```python
from loglens.field_analysis import summarize_field_coverage
from loglens.parsers import parse_json_line

events = [
    parse_json_line('{"message":"ok","request_id":"r1","status":200}'),
    parse_json_line('{"message":"failed","request_id":"r2","status":"503"}'),
]

print(summarize_field_coverage(events))
```

The result reports total event count plus deterministic per-field `present` and `coverage` metrics. It also reports coarse value-type counts such as `string`, `integer`, `number`, `boolean`, `object`, `array`, and `null`. Field values themselves are intentionally omitted, so exploratory schema inspection does not unnecessarily reproduce request identifiers, user data, tokens, or other sensitive log context.

For the example above, `status` is present in both events but has two observed types: one `integer` and one `string`. That is a useful defensive signal for schema drift: an ingestion change, upstream deployment, parser mismatch, or malformed producer may have changed the shape of a field even when the field remains present. Analysts can use this aggregate signal to decide where deeper source-specific validation is warranted without putting the underlying values into the report.

Type counts describe raw structured-field occurrences. If multiple source keys normalize to the same safe display identity inside one event, presence is still counted at most once for that event while type counts retain the observed occurrences. This keeps coverage bounded at 100% while preserving useful schema evidence.

The same privacy-safe field coverage and type summaries are available in JSON and CSV reports. CSV stores the type summary as compact JSON in the row's details column so downstream tooling can retain the aggregate schema information.

This helper accepts any iterable of `LogEvent` objects, including generators, and consumes it once.
