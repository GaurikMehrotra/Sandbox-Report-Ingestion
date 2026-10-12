"""JSON and inert Markdown artifacts, generated from validated stored reports."""

import html
import json
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .files import atomic_text, reject_symlink_path
from .models import Stage
from .redaction import redact


def safe(value):
    text = html.escape(str(value), quote=True).replace(":", "&#58;")
    for char in "\\`*_{}[]()#+-.!|":
        text = text.replace(char, "\\" + char)
    return (
        "".join(
            c if c == "\t" or not unicodedata.category(c).startswith("C") else " " for c in text
        )
        .replace("\n", " ")
        .replace("\r", " ")
    )


def render(report, correlations):
    report = type(report).model_validate(redact(report.model_dump()))
    correlations = redact(correlations)
    lines = [
        "# Sandbox investigation",
        "",
        f"Report: {safe(report.report_id)}",
        f"Source: {safe(report.source_sandbox)}",
        f"Original SHA256: {report.original_sha256}",
        f"Parser: {report.parser_version}; schema: {report.schema_version}",
        f"Ingested: {report.ingested_at}",
        "",
        "## Sample metadata",
        "",
        safe(json.dumps(report.sample)),
        "",
        "## Pipeline status",
        "",
    ]
    lines += [f"- {safe(s.name)}: {s.status}" for s in report.stages]
    for title, kind in (
        ("Observed process activity", "process"),
        ("Observed process relationships", "process_tree"),
        ("Observed file activity", "file"),
        ("Observed registry activity", "registry"),
        ("Observed network activity", "network"),
        ("Observed DNS activity", "dns"),
        ("Observed HTTP activity", "http"),
    ):
        lines += ["", "## " + title, "", "Missing observations mean unknown coverage."]
        lines += [
            f"- {safe(json.dumps(e.normalized_value))} Evidence: {e.evidence_id}"
            for e in report.evidence
            if e.evidence_type == kind
        ]
    lines += ["", "## Indicators (syntax validated; maliciousness unconfirmed)", ""]
    lines += [
        f"- {i.type}: {safe(i.value)}; evidence: {', '.join(i.evidence_ids)}" for i in report.iocs
    ]
    lines += ["", "## Interpretations and source detections", ""]
    lines += [
        f"- {f.kind}: {safe(f.description)} — {safe(f.rationale)} Evidence: {', '.join(f.evidence_ids)}"
        for f in report.findings
    ]
    lines += ["", "## Candidate ATT&CK mappings", ""]
    lines += [
        f"- {a.technique_id} {safe(a.name)} ({a.origin}, {a.status}, {a.catalog_version}): {safe(a.rationale)} Evidence: {', '.join(a.evidence_ids)}"
        for a in report.attack
    ]
    lines += [
        "",
        "## Cross-report correlations",
        "",
        safe(json.dumps(correlations)),
        "",
        "## Evidence registry",
        "",
    ]
    lines += [
        f"- {e.evidence_id}: {safe(e.source_reference)} ({safe(e.evidence_type)}), raw: {safe(json.dumps(e.raw_value))}"
        for e in report.evidence
    ]
    lines += ["", "## Warnings and limitations", ""] + ["- " + safe(w) for w in report.warnings]
    lines += [
        "- Source detections and candidate mappings are investigative signals, not verified maliciousness.",
        "- Review original source records and sandbox coverage before drawing conclusions.",
        "- No samples were executed and no indicators were contacted.",
    ]
    if report.ai:
        lines += ["", "## Optional AI hypotheses", "", safe(json.dumps(report.ai))]
    return "\n".join(lines) + "\n"


def export(store, report_id, output):
    # Lookup before using an ID as a filename; stored IDs must match our content-derived format.
    import re

    if not re.fullmatch(r"[a-f0-9]{64}", report_id):
        raise ValueError("invalid report ID")
    report = store.get(report_id)
    directory = Path(output)
    reject_symlink_path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    correlations = {
        "shared_iocs": store.correlate(report_id),
        "shared_behavior": store.behavior_correlations(report_id),
    }
    report.correlations = correlations
    report.stages = [s for s in report.stages if s.name != "cross_report_correlation"] + [
        Stage(name="cross_report_correlation", status="passed"),
        Stage(name="report_generation", status="passed"),
    ]
    paths = []
    attempt = str(uuid4())
    date = datetime.now(UTC).isoformat()
    try:
        for suffix, content in (
            ("json", json.dumps(redact(report.model_dump()), indent=2)),
            ("md", render(report, correlations)),
        ):
            path = directory / (report_id + "." + suffix)
            atomic_text(path, content)
            paths.append(str(path))
    except (OSError, ValueError) as exc:
        store.record(
            attempt,
            report_id,
            date,
            "export_failed",
            json.dumps({"stage": "report_generation", "error_type": type(exc).__name__}),
        )
        raise
    store.record(
        attempt,
        report_id,
        date,
        "exported",
        json.dumps({"stage": "report_generation", "status": "passed"}),
    )
    return paths
