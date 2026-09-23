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

The result reports total event count plus deterministic per-field `present`, `missing`, and `coverage` metrics. `missing` is the number of analyzed events in which the normalized field identity was absent, so analysts and automation can inspect schema completeness without converting a floating-point coverage ratio back into a count. It also reports coarse value-type counts such as `string`, `integer`, `number`, `boolean`, `object`, `array`, and `null`. Each field includes a `type_drift` boolean that is `true` when more than one non-null coarse type was observed. `null` observations remain visible in `types`, but a nullable field such as `integer` plus `null` is not treated as schema drift by itself. Field values themselves are intentionally omitted.

For the example above, `status` is present in both events and therefore has `missing: 0`, but it has two observed non-null types: one `integer` and one `string`, so its `type_drift` value is `true`. A field present in only one of those events would instead report `present: 1`, `missing: 1`, and `coverage: 0.5`. These aggregate signals help identify ingestion changes, upstream deployments, parser mismatches, malformed producers, and unexpectedly sparse fields without reproducing sensitive field values.

Type counts describe raw structured-field occurrences. If multiple source keys normalize to the same safe display identity inside one event, presence is still counted at most once for that event while type counts retain the observed occurrences. This keeps coverage bounded at 100% and ensures `present + missing` equals the total analyzed event count for every reported field. `type_drift` is derived only from the set of non-null coarse types.

The same privacy-safe field coverage, missing counts, type summaries, and explicit drift signal are available to report serializers through the field-coverage objects. This lets downstream tooling distinguish a rarely populated field from a consistently populated one using exact counts while retaining the existing normalized coverage ratio.

This helper accepts any iterable of `LogEvent` objects, including generators, and consumes it once.
