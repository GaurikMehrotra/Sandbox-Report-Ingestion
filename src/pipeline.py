"""Staged ingestion with per-attempt audit history and safe reprocessing."""

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .analysis import analyze
from .input import read_report
from .ioc import extract
from .models import PARSER_VERSION, Report, Stage
from .parsers import choose


def ingest(store, path, explicit=None, reprocess=False, include_nonpublic=True, llm=False):
    ingestion_id = str(uuid4())
    date = datetime.now(UTC).isoformat()
    stages = []
    report_id = None

    def passed(name):
        stages.append(Stage(name=name, status="passed"))

    stage = "validation"
    try:
        raw, data, sha = read_report(Path(path))
        passed(stage)
        # Identity includes adapter choice so explicit reinterpretation cannot be silently deduplicated.
        stage = "format_detection"
        canonical = data.get("schema_version") == "1.0" and "evidence" in data
        parser = None if canonical else choose(data, explicit)
        source = "normalized" if canonical else parser.name
        report_id = hashlib.sha256((sha + ":" + source).encode()).hexdigest()
        passed(stage)
        try:
            previous = store.get(report_id)
        except KeyError:
            previous = None
        if previous and previous.parser_version == PARSER_VERSION and not reprocess:
            store.record(ingestion_id, report_id, date, "duplicate", None)
            return {"status": "duplicate", "report_id": report_id}
        report = Report(
            report_id=report_id,
            ingestion_id=ingestion_id,
            ingested_at=date,
            original_sha256=sha,
            source_sandbox=source,
        )
        stage = "parsing"
        if canonical:
            original = Report.model_validate(data)
            known = {e.evidence_id for e in original.evidence}
            if len(known) != len(original.evidence) or any(
                e.report_id != original.report_id for e in original.evidence
            ):
                raise ValueError("invalid canonical evidence identity")
            if any(set(i.evidence_ids) - known for i in original.iocs) or any(
                set(f.evidence_ids) - known for f in [*original.findings, *original.attack]
            ):
                raise ValueError("dangling canonical evidence references")
            # Re-ingest evidence as observations of the canonical document, maintaining its source pointers.
            from .parsers import add

            report.sample = original.sample
            report.analysis_started_at = original.analysis_started_at
            report.analysis_ended_at = original.analysis_ended_at
            for n, e in enumerate(original.evidence):
                add(
                    report,
                    e.evidence_type,
                    e.raw_value,
                    f"/evidence/{n}/raw_value",
                    normalized=e.normalized_value,
                )
            report.warnings.append(
                "Canonical import re-derives findings from preserved raw observations; source document retained."
            )
        else:
            parser.parse(data, report)
        passed(stage)
        for e in report.evidence:
            report.observations.setdefault(e.evidence_type, []).append(e.evidence_id)
        for stage in ("normalization", "evidence_registration"):
            report = Report.model_validate(report.model_dump())
            passed(stage)
        stage = "ioc_extraction"
        report.iocs = extract(report.evidence, report_id, include_nonpublic)
        passed(stage)
        stage = "behavior_analysis"
        analyze(report)
        passed(stage)
        passed("attack_mapping")
        stages.append(
            Stage(
                name="cross_report_correlation",
                status="skipped",
                detail="queried live after storage so later reports are included",
            )
        )
        stage = "ai"
        if llm:
            from .ai import summarize

            report.ai = summarize(report)
            stages.append(
                Stage(
                    name="ai",
                    status="passed" if report.ai["status"] == "completed" else "failed",
                    detail=report.ai["status"],
                )
            )
        else:
            stages.append(Stage(name="ai", status="skipped", detail="disabled by default"))
        stage = "storage"
        report = Report.model_validate(report.model_dump())
        report.stages = stages + [Stage(name="storage", status="passed")]
        store.save(report, raw)
        return {"status": "saved", "report_id": report_id, "warnings": len(report.warnings)}
    except (ValueError, OSError, TypeError, sqlite3.Error) as exc:
        # Error strings from validators may contain report data: log only category, stage, and safe message.
        detail = {
            "stage": stage,
            "error_type": type(exc).__name__,
            "stages": [s.model_dump() for s in stages]
            + [Stage(name=stage, status="failed", detail=type(exc).__name__).model_dump()],
        }
        import json

        store.record(ingestion_id, report_id, date, "failed", json.dumps(detail))
        return {
            "status": "failed",
            "stage": stage,
            "error": type(exc).__name__,
            "message": {
                "validation": "Invalid input: expected bounded, regular UTF-8 .json file with a unique-key object root.",
                "format_detection": "Unsupported report structure; use --format cape or cuckoo for identified Cuckoo-family reports.",
                "parsing": "Parser rejected source structure or canonical provenance; check documented schema.",
                "storage": "Local persistence failed; verify permissions, integrity, and available space.",
            }.get(stage, "Stage failed; check the recorded audit status."),
        }
