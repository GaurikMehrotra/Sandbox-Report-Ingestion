# Evaluation methodology and measured results

## Dataset and annotation

`tests/fixtures/cape.json`, `cuckoo.json`, and `synthetic.json` are self-authored, explicitly synthetic telemetry. Domain names use `example.org`; addresses include documentation/loopback ranges. No malware or real sandbox report was downloaded. `labels.json` independently lists expected normalized type/value IOC pairs, inferred technique IDs, source identity, evidence count, and nine selected source-pointer/normalized-field expectations.

Annotation procedure: read each raw fixture, enumerate context-supported indicators (not arbitrary strings), specify canonical spelling, enumerate observations and supported rule conditions, then record expected fields/techniques. The same developer authored implementation and labels; there is no blinded annotation or independent adjudication. Future real-report evaluation requires sanitized, authorized reports, two annotators, discrepancy resolution and a held-out split. Current fixtures are regression contracts, not a representative malware population.

## Metrics and denominators

| Metric | Numerator / denominator |
| --- | --- |
| Parser success rate | Successfully saved annotated inputs / all three annotated inputs |
| Field extraction accuracy | Exact selected source-pointer/normalized-field matches / nine annotated field expectations |
| IOC precision | Exact predicted `(type,value)` pairs present in annotations / all predicted pairs; micro-averaged across reports |
| IOC recall | Exact predicted expected pairs / all annotated expected pairs |
| Normalization correctness | Predicted canonical values unchanged by their normalizer / all predicted IOC pairs; this measures idempotence, with actual expected spelling additionally covered by labels/tests |
| Provenance completeness | Evidence whose pointer resolves to exact raw value and whose owner matches report / all extracted evidence records |
| Duplicate detection recall | Recognized second-ingestion duplicates / three repeated inputs |
| Distinct input acceptance | Successfully saved first ingestions / three distinct fixture inputs; detects false duplicate suppression on this set |
| ATT&CK precision | Correct inferred unique technique IDs / all inferred unique IDs per report, micro-averaged |
| ATT&CK recall | Correct inferred unique technique IDs / annotated supported IDs per report, micro-averaged |
| Processing time | `perf_counter` duration of complete ingestion including storage, per report |
| Python memory | `tracemalloc` peak during ingestion; excludes native allocations, interpreter baseline and process RSS |
| Malformed/incomplete controls | Rejected malformed JSON / one malformed control; saved incomplete input with coverage warning / one incomplete control |

Source-reported mappings are excluded from inference metrics. Zero-denominator precision/recall is `null`, not an invented score. The primary parser rate excludes the deliberately malformed/incomplete controls, which are reported separately. Security tests cover additional malformed variants. No claim of overall duplicate-classifier accuracy or adversary-detection accuracy follows from these limited denominators.

## Reproduction

From the repository root with the documented environment:

```bash
python -m scripts.evaluate --output .local/evaluation.json --csv .local/evaluation.csv
python -m scripts.benchmark --events 5000 --output .local/benchmark.json
python -m pytest -q
```

Evaluation uses a fresh temporary SQLite store each run and writes actual per-report measurements. JSON preserves summary denominators and per-report counts; CSV contains per-report results. The separate benchmark generates synthetic DNS observations and checks that every event and IOC is retained. It bounds generated event count to 10,000.

## Results measured in this environment

[JSON](evaluation-results.json), [CSV](evaluation-results.csv), and [benchmark](benchmark-results.json) are actual captured runs, not illustrative predictions. The final annotated set contains 18 expected IOC pairs and 21 evidence observations across three reports. All were retained with exact provenance; nine selected normalized fields matched. Parser success, IOC precision/recall, field matches, provenance, duplicate recall and supported inferred ATT&CK precision/recall were 1.0 on this set. Two supported inferred technique instances were evaluated in CAPE; the other fixtures have no annotated inferred techniques. See the numeric files for authoritative denominators.

The initial evaluation had 18 true positives out of 19 predicted IOC pairs (94.7% precision). It exposed extraction of a signature label as a filename. Restricting generic filename fields to sample/file contexts removed that fixture-specific false positive; a regression test now covers it. This is a documented correctness fix, not evidence of general accuracy improvement.

The 5,000-event probe initially measured approximately 1.85 seconds and 41.4 MB peak Python allocations for a 308,934-byte generated report. The committed benchmark file records the latest measured run and may differ slightly. This is one local probe with tracing overhead, not a throughput SLA or proof that all near-limit reports fit every environment.

Optional AI tests validate unavailable/invalid behavior and reference constraints. No real model's summarization quality, resistance to semantic injection, or ATT&CK inference accuracy has been measured. Native Windows execution and real vendor-version compatibility remain unverified.
