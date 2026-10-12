"""CLI entry point: python -m src.main --help."""

import argparse
import json
import sqlite3
from pathlib import Path

from .pipeline import ingest
from .redaction import redact
from .reporting import export
from .storage import Store


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local sandbox report ingestion (never executes samples)"
    )
    parser.add_argument("--store", default=".local", help="SQLite and original report directory")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("ingest")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=Path)
    group.add_argument("--directory", type=Path)
    p.add_argument("--format", choices=["cape", "cuckoo", "synthetic"])
    p.add_argument("--reprocess", action="store_true")
    p.add_argument("--exclude-nonpublic", action="store_true")
    llm = p.add_mutually_exclusive_group()
    llm.add_argument("--llm", action="store_true", help="explicitly enable localhost Ollama")
    llm.add_argument("--no-llm", action="store_true")
    p.add_argument("--output", default=".local/outputs")
    p = sub.add_parser("report")
    p.add_argument("--id", required=True)
    p.add_argument("--output", default=".local/outputs")
    p = sub.add_parser("search-ioc")
    p.add_argument("--value", required=True)
    p.add_argument("--evidence", action="store_true")
    p = sub.add_parser("correlate")
    p.add_argument("--id", required=True)
    p = sub.add_parser("list")
    p.add_argument("--source")
    p.add_argument("--since")
    p.add_argument("--until")
    sub.add_parser("stats")
    sub.add_parser("techniques")
    p = sub.add_parser("history")
    p.add_argument("--id")
    args = parser.parse_args(argv)
    store = None
    exit_code = 0
    try:
        store = Store(args.store)
        if args.command == "ingest":
            if args.directory and (args.directory.is_symlink() or not args.directory.is_dir()):
                raise ValueError("directory must be a non-symlink directory")
            paths = [args.file] if args.file else sorted(args.directory.glob("*.json"))
            if not paths:
                raise ValueError("no JSON reports found")
            if len(paths) > 1000:
                raise ValueError("batch limit is 1000 reports")
            counts = {"saved": 0, "duplicate": 0, "failed": 0}
            for path in paths:
                result = ingest(
                    store, path, args.format, args.reprocess, not args.exclude_nonpublic, args.llm
                )
                counts[result["status"]] += 1
                if result["status"] != "failed":
                    try:
                        result["outputs"] = export(store, result["report_id"], args.output)
                    except (OSError, ValueError) as exc:
                        result["output_error"] = type(exc).__name__
                        exit_code = 1
                print(json.dumps(result))
            print(json.dumps({"counts": counts}))
            exit_code = max(exit_code, int(counts["failed"] > 0))
        elif args.command == "report":
            print(json.dumps(export(store, args.id, args.output)))
        elif args.command == "search-ioc":
            print(
                json.dumps(
                    redact(
                        store.indicator_evidence(args.value)
                        if args.evidence
                        else store.search(args.value)
                    ),
                    indent=2,
                )
            )
        elif args.command == "correlate":
            print(
                json.dumps(
                    redact(
                        {
                            "shared_iocs": store.correlate(args.id),
                            "shared_behavior": store.behavior_correlations(args.id),
                        }
                    ),
                    indent=2,
                )
            )
        elif args.command == "list":
            print(json.dumps(store.list(args.source, args.since, args.until), indent=2))
        elif args.command == "history":
            print(json.dumps(store.history(args.id), indent=2))
        elif args.command == "techniques":
            print(json.dumps(store.techniques(), indent=2))
        else:
            print(json.dumps(store.stats(), indent=2))
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": "Operation failed; verify paths, identifiers, and permissions.",
                }
            )
        )
        exit_code = 1
    finally:
        if store is not None:
            store.close()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
