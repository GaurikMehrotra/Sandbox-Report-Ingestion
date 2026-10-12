"""Bounded performance probe using generated synthetic observations only."""

import argparse
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

from src.pipeline import ingest
from src.storage import Store


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--output", default=".local/benchmark.json")
    args = parser.parse_args(argv)
    if not 1 <= args.events <= 10000:
        parser.error("events must be between 1 and 10000")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "synthetic.json"
        path.write_text(
            json.dumps(
                {
                    "format": "synthetic-v1",
                    "observations": [
                        {"type": "dns", "value": {"domain": f"host{i}.example.org"}}
                        for i in range(args.events)
                    ],
                }
            )
        )
        store = Store(Path(directory) / "store")
        try:
            tracemalloc.start()
            started = time.perf_counter()
            result = ingest(store, path)
            seconds = time.perf_counter() - started
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            report = store.get(result["report_id"]) if result["status"] == "saved" else None
            metric = {
                "synthetic": True,
                "events": args.events,
                "input_bytes": path.stat().st_size,
                "seconds": seconds,
                "python_peak_bytes": peak,
                "status": result["status"],
                "evidence_count": len(report.evidence) if report else 0,
                "ioc_count": len(report.iocs) if report else 0,
            }
            from src.files import atomic_text, reject_symlink_path

            output = Path(args.output)
            reject_symlink_path(output)
            output.parent.mkdir(parents=True, exist_ok=True)
            atomic_text(output, json.dumps(metric, indent=2) + "\n")
            print(json.dumps(metric, indent=2))
            return int(
                result["status"] != "saved"
                or metric["evidence_count"] != args.events
                or metric["ioc_count"] != args.events
            )
        finally:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
