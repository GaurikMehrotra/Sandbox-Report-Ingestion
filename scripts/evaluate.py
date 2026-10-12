"""Measured synthetic-fixture evaluation. No real malware or network required."""

import argparse
import csv
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

from src.ioc import normalize
from src.pipeline import ingest
from src.storage import Store


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def evaluate(fixtures):
    fixtures = Path(fixtures)
    annotations = json.loads((fixtures / "labels.json").read_text())
    results = []
    with tempfile.TemporaryDirectory() as directory:
        store = Store(directory)
        try:
            for name, label in annotations.items():
                tracemalloc.start()
                start = time.perf_counter()
                result = ingest(store, fixtures / name)
                elapsed = time.perf_counter() - start
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                row = {
                    "fixture": name,
                    "synthetic": True,
                    "parser_success": int(result["status"] == "saved"),
                    "seconds": elapsed,
                    "python_peak_bytes": peak,
                }
                if result["status"] == "saved":
                    report = store.get(result["report_id"])
                    actual = {(i.type, i.value) for i in report.iocs}
                    expected = {tuple(v) for v in label["iocs"]}
                    tp = len(actual & expected)
                    predicted = {
                        a.technique_id for a in report.attack if a.origin == "system_inferred"
                    }
                    truth = set(label["attack"])
                    document = json.loads((fixtures / name).read_text())
                    proven = 0
                    for e in report.evidence:
                        value = document
                        try:
                            for part in e.source_reference[1:].split("/"):
                                key = part.replace("~1", "/").replace("~0", "~")
                                value = value[int(key)] if isinstance(value, list) else value[key]
                            proven += int(value == e.raw_value and e.report_id == report.report_id)
                        except (KeyError, IndexError, TypeError, ValueError):
                            pass
                    duplicate = ingest(store, fixtures / name)
                    row.update(
                        ioc_tp=tp,
                        ioc_predicted=len(actual),
                        ioc_expected=len(expected),
                        ioc_precision=ratio(tp, len(actual)),
                        ioc_recall=ratio(tp, len(expected)),
                        normalization_correct=sum(
                            normalize(i.type, i.value) == i.value for i in report.iocs
                        ),
                        evidence_proven=proven,
                        evidence_total=len(report.evidence),
                        evidence_expected=label["evidence_count"],
                        fields_correct=sum(
                            any(
                                e.source_reference == f["reference"]
                                and isinstance(e.normalized_value, dict)
                                and e.normalized_value.get(f["field"]) == f["expected"]
                                for e in report.evidence
                            )
                            for f in label["fields"]
                        ),
                        fields_total=len(label["fields"]),
                        attack_tp=len(predicted & truth),
                        attack_predicted=len(predicted),
                        attack_expected=len(truth),
                        attack_precision=ratio(len(predicted & truth), len(predicted)),
                        attack_recall=ratio(len(predicted & truth), len(truth)),
                        duplicate_detected=int(duplicate["status"] == "duplicate"),
                    )
                results.append(row)
            # Distinct inputs and malformed/incomplete controls are independent denominators.
            malformed = Path(directory) / "malformed.json"
            malformed.write_text("{")
            malformed_rejected = int(ingest(store, malformed)["status"] == "failed")
            incomplete = Path(directory) / "incomplete.json"
            incomplete.write_text('{"format":"cape"}')
            partial = ingest(store, incomplete)
            incomplete_warned = int(
                partial["status"] == "saved" and bool(store.get(partial["report_id"]).warnings)
            )
        finally:
            store.close()

    def total(key):
        return sum(r.get(key, 0) for r in results)

    summary = {
        "dataset": "synthetic-v1, manually annotated; not independent real-world validation",
        "reports": len(results),
        "parser_success_rate": ratio(total("parser_success"), len(results)),
        "field_extraction_accuracy": ratio(total("fields_correct"), total("fields_total")),
        "ioc_precision": ratio(total("ioc_tp"), total("ioc_predicted")),
        "ioc_recall": ratio(total("ioc_tp"), total("ioc_expected")),
        "normalization_correctness": ratio(total("normalization_correct"), total("ioc_predicted")),
        "provenance_completeness": ratio(total("evidence_proven"), total("evidence_total")),
        "duplicate_detection_recall": ratio(total("duplicate_detected"), len(results)),
        "distinct_input_acceptance": ratio(total("parser_success"), len(results)),
        "attack_precision": ratio(total("attack_tp"), total("attack_predicted")),
        "attack_recall": ratio(total("attack_tp"), total("attack_expected")),
        "malformed_controls_rejected": malformed_rejected,
        "malformed_controls_total": 1,
        "incomplete_controls_warned": incomplete_warned,
        "incomplete_controls_total": 1,
    }
    return {"summary": summary, "reports": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", default="tests/fixtures")
    parser.add_argument("--output", default=".local/evaluation.json")
    parser.add_argument("--csv", default=None)
    args = parser.parse_args(argv)
    result = evaluate(args.fixtures)
    from src.files import atomic_text, reject_symlink_path

    output = Path(args.output)
    reject_symlink_path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_text(output, json.dumps(result, indent=2) + "\n")
    if args.csv:
        path = Path(args.csv)
        reject_symlink_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=sorted({k for r in result["reports"] for k in r}))
            writer.writeheader()
            writer.writerows(result["reports"])
    print(json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
