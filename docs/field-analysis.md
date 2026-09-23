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

The result reports total event count plus deterministic per-field `present`, `missing`, and `coverage` metrics. `missing` is the number of analyzed events in which the normalized field identity was absent. It also reports `populated` and `populated_rate`: `populated` counts events where the field identity has at least one non-null value, while `populated_rate` divides that count by all analyzed events. This gives analysts a direct completeness signal that includes both missing and explicitly null data. `nulls` and `null_rate` remain available, where `null_rate` is the fraction of present events whose normalized field identity had no populated value. Coarse value-type counts such as `string`, `integer`, `number`, `boolean`, `object`, `array`, and `null` remain available. Each field includes a `type_drift` boolean that is `true` when incompatible non-null coarse types were observed. Field values themselves are intentionally omitted.

When `type_drift` is true, LogLens also emits `type_drift_families`, a sorted list of the incompatible coarse schema families that caused the signal, `type_drift_family_counts` for absolute occurrence counts, and `type_drift_family_rates` for each family's share of all non-null occurrences. For example, observations of integer `503`, float `503.0`, and string `"503"` produce families `["number", "string"]`, counts `{"number": 2, "string": 1}`, and rates `{"number": 0.666..., "string": 0.333...}`. Counts are useful for auditability while rates make drift severity comparable across small and large samples. Stable fields do not receive these extra keys, keeping non-drift reports compact.

For the example above, `status` is present and populated in both events and therefore has `missing: 0`, `populated: 2`, `populated_rate: 1.0`, `nulls: 0`, and `null_rate: 0.0`, but it has incompatible observed types (`integer` and `string`), so its `type_drift` value is `true`. Its family rates are calculated only from non-null occurrences, so explicitly null observations do not dilute schema-drift prevalence. A field present in only one event would instead report `present: 1`, `missing: 1`, and `coverage: 0.5`. If that one present value were null, it would report `populated: 0`, `populated_rate: 0.0`, `nulls: 1`, and `null_rate: 1.0`.

`integer` and `number` are treated as one compatible numeric schema family for drift detection, family counts, and family rates. A field that moves between `12` and `12.5` retains both coarse type counts for diagnostics but does not raise `type_drift`; adding a `string`, `boolean`, object, or other incompatible type still does. This reduces false-positive schema drift when a producer naturally widens a JSON numeric value while preserving visibility into the underlying representation.

Type counts, drift-family counts, and drift-family rates describe raw structured-field occurrences. If multiple source keys normalize to the same safe display identity inside one event, presence is still counted at most once for that event while type counts retain the observed occurrences. Nullability and population follow the normalized identity too: if any alias has a populated value in an event, that event is counted once as populated and is not counted as null for the identity; it is counted as null only when all observed aliases are null. This keeps coverage, population, and nullability bounded at 100%. For every reported field, `present + missing` equals total analyzed events and `populated + nulls` equals `present`. `type_drift` is derived only from non-null coarse types and their compatible type families. `null_rate` uses normalized per-event presence as its denominator, while `populated_rate` uses all analyzed events so reports remain easy to interpret.

The same privacy-safe field coverage, missing counts, populated completeness, nullability metrics, type summaries, and explicit drift evidence are available to report serializers through the field-coverage objects. This lets downstream tooling distinguish absent, explicitly null, and populated fields while retaining the existing normalized coverage ratio.

This helper accepts any iterable of `LogEvent` objects, including generators, and consumes it once.
