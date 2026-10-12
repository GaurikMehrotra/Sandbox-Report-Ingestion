"""Demonstrate local ingestion, evidence search, correlation and reporting."""

import argparse
import json
from pathlib import Path

from src.pipeline import ingest
from src.reporting import export
from src.storage import Store


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=".local/demo")
    args = parser.parse_args(argv)
    store = Store(args.store)
    try:
        results = [
            ingest(store, Path("tests/fixtures") / name)
            for name in ("cape.json", "cuckoo.json", "synthetic.json")
        ]
        if any(r["status"] == "failed" for r in results):
            return 1
        outputs = [export(store, r["report_id"], store.root / "outputs") for r in results]
        print(
            json.dumps(
                {
                    "synthetic_only": True,
                    "ingestion": results,
                    "stats": store.stats(),
                    "shared_domain": store.search("example.org"),
                    "correlations": store.correlate(results[0]["report_id"]),
                    "outputs": outputs,
                },
                indent=2,
            )
        )
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
