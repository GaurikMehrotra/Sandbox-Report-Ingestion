"""Transactional SQLite records and immutable content-addressed originals."""

import hashlib
import json
import sqlite3
from pathlib import Path

from .files import reject_symlink_path
from .models import Report


class Store:
    def __init__(self, root):
        self.root = Path(root)
        reject_symlink_path(self.root)
        reject_symlink_path(self.root / "reports.sqlite3")
        reject_symlink_path(self.root / "originals")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root / "originals").mkdir(exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.root / "reports.sqlite3")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, sha TEXT, source TEXT, date TEXT, version TEXT, data TEXT);
        CREATE INDEX IF NOT EXISTS report_source ON reports(source,date);
        CREATE TABLE IF NOT EXISTS indicators(report_id TEXT REFERENCES reports(id) ON DELETE CASCADE, type TEXT, value TEXT, evidence TEXT);
        CREATE INDEX IF NOT EXISTS indicator_value ON indicators(value,type);
        CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY, ingestion_id TEXT, report_id TEXT, date TEXT, status TEXT, detail TEXT, data TEXT);
        """)

    def close(self):
        self.db.close()

    def get(self, report_id):
        row = self.db.execute("SELECT data FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise KeyError("report not found")
        return Report.model_validate_json(row[0])

    def save(self, report, raw):
        report = Report.model_validate(report.model_dump())
        if hashlib.sha256(raw).hexdigest() != report.original_sha256:
            raise ValueError("original SHA256 mismatch")
        path = self.root / "originals" / (report.original_sha256 + ".json")
        reject_symlink_path(path)
        try:
            with path.open("xb") as f:
                f.write(raw)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise ValueError("original integrity mismatch")
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO reports VALUES(?,?,?,?,?,?)",
                (
                    report.report_id,
                    report.original_sha256,
                    report.source_sandbox,
                    report.analysis_started_at or report.ingested_at,
                    report.parser_version,
                    report.model_dump_json(),
                ),
            )
            self.db.execute("DELETE FROM indicators WHERE report_id=?", (report.report_id,))
            self.db.executemany(
                "INSERT INTO indicators VALUES(?,?,?,?)",
                [
                    (report.report_id, i.type, i.value, json.dumps(i.evidence_ids))
                    for i in report.iocs
                ],
            )
            self.record(
                report.ingestion_id,
                report.report_id,
                report.ingested_at,
                "saved",
                None,
                report.model_dump_json(),
                commit=False,
            )

    def record(self, ingestion_id, report_id, date, status, detail, data=None, commit=True):
        self.db.execute(
            "INSERT INTO history(ingestion_id,report_id,date,status,detail,data) VALUES(?,?,?,?,?,?)",
            (ingestion_id, report_id, date, status, detail, data),
        )
        if commit:
            self.db.commit()

    def search(self, value):
        return [
            {"report_id": r[0], "type": r[1], "value": r[2], "evidence_ids": json.loads(r[3])}
            for r in self.db.execute(
                "SELECT report_id,type,value,evidence FROM indicators WHERE value=? ORDER BY report_id",
                (value,),
            )
        ]

    def list(self, source=None, since=None, until=None):
        return [
            dict(zip(("id", "sha256", "source", "report_date", "parser_version"), r))
            for r in self.db.execute(
                "SELECT id,sha,source,date,version FROM reports WHERE (? IS NULL OR source=?) AND (? IS NULL OR date>=?) AND (? IS NULL OR date<=?) ORDER BY date,id",
                (source, source, since, since, until, until),
            )
        ]

    def correlate(self, report_id):
        report = self.get(report_id)
        return [
            {"type": i.type, "value": i.value, "reports": matches}
            for i in report.iocs
            if len(matches := [r for r in self.search(i.value) if r["type"] == i.type]) > 1
        ]

    def techniques(self):
        return [
            {"report_id": r["id"], **a.model_dump()}
            for r in self.list()
            for a in self.get(r["id"]).attack
        ]

    def stats(self):
        return {
            "reports": self.db.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
            "unique_iocs": self.db.execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT type,value FROM indicators)"
            ).fetchone()[0],
            "attempts": dict(
                self.db.execute("SELECT status,COUNT(*) FROM history GROUP BY status")
            ),
        }

    def history(self, report_id=None):
        return [
            dict(zip(("ingestion_id", "report_id", "date", "status", "detail"), r))
            for r in self.db.execute(
                "SELECT ingestion_id,report_id,date,status,detail FROM history WHERE (? IS NULL OR report_id=?) ORDER BY seq",
                (report_id, report_id),
            )
        ]

    def indicator_evidence(self, value):
        return [
            {
                "report_id": r["report_id"],
                "evidence": [
                    e.model_dump()
                    for e in self.get(r["report_id"]).evidence
                    if e.evidence_id in r["evidence_ids"]
                ],
            }
            for r in self.search(value)
        ]

    def behavior_correlations(self, report_id):
        target = self.get(report_id)
        rules = {f.rule_id for f in target.findings if f.kind == "deterministic_interpretation"}
        matches = []
        for row in self.list():
            if row["id"] == report_id:
                continue
            other = self.get(row["id"])
            for rule in sorted(
                rules
                & {f.rule_id for f in other.findings if f.kind == "deterministic_interpretation"}
            ):
                matches.append(
                    {
                        "rule_id": rule,
                        "report_id": other.report_id,
                        "target_evidence": sorted(
                            {
                                e
                                for f in target.findings
                                if f.rule_id == rule
                                for e in f.evidence_ids
                            }
                        ),
                        "other_evidence": sorted(
                            {e for f in other.findings if f.rule_id == rule for e in f.evidence_ids}
                        ),
                        "rationale": "Shared deterministic rule result; not a family attribution.",
                    }
                )
        return matches
