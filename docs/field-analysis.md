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

The result reports total event count plus deterministic per-field `present` and `coverage` metrics. It also reports coarse value-type counts such as `string`, `integer`, `number`, `boolean`, `object`, `array`, and `null`. Each field includes a `type_drift` boolean that is `true` when more than one non-null coarse type was observed, making mixed-type schema changes easy for downstream tooling and analysts to identify without re-deriving the signal. `null` observations remain visible in `types`, but a nullable field such as `integer` plus `null` is not treated as schema drift by itself. Field values themselves are intentionally omitted, so exploratory schema inspection does not unnecessarily reproduce request identifiers, user data, tokens, or other sensitive log context.

For the example above, `status` is present in both events but has two observed non-null types: one `integer` and one `string`, so its `type_drift` value is `true`. That is a useful defensive signal for schema drift: an ingestion change, upstream deployment, parser mismatch, or malformed producer may have changed the shape of a field even when the field remains present. By contrast, an optional numeric field observed as both `integer` and `null` remains `type_drift: false`, reducing false-positive drift signals for ordinary nullable schemas. Analysts can use this aggregate signal to decide where deeper source-specific validation is warranted without putting the underlying values into the report.

Type counts describe raw structured-field occurrences. If multiple source keys normalize to the same safe display identity inside one event, presence is still counted at most once for that event while type counts retain the observed occurrences. This keeps coverage bounded at 100% while preserving useful schema evidence. `type_drift` is derived only from the set of non-null coarse types, not from field values or occurrence counts.

The same privacy-safe field coverage, type summaries, and explicit drift signal are available in JSON and CSV reports. JSON stores `types` and `type_drift` directly on each field-coverage object. CSV keeps its stable six-column shape and stores a compact JSON details object in the `message` cell, for example `{"type_drift":true,"types":{"integer":1,"string":1}}`. This lets spreadsheet exports and downstream automation consume the drift decision directly without reconstructing it from type counts.

This helper accepts any iterable of `LogEvent` objects, including generators, and consumes it once.
