"""Deterministic adapters for overlapping Cuckoo-family report schemas."""

import hashlib
from datetime import UTC, datetime
from typing import Protocol

from .models import Evidence, Report
from .normalization import observation


class Parser(Protocol):
    name: str

    def recognizes(self, data: dict) -> bool: ...
    def parse(self, data: dict, report: Report) -> None: ...


def pointer(*parts):
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def timestamp(value, warnings):
    if value is None:
        return None
    if not isinstance(value, str):
        warnings.append("invalid timestamp type")
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            warnings.append("naive timestamp assumed UTC; original retained")
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat()
    except ValueError:
        warnings.append("invalid timestamp retained in raw evidence")
        return None


def add(report, kind, raw, ref, normalized=None):
    eid = hashlib.sha256((report.report_id + ref).encode()).hexdigest()[:24]
    time = (
        timestamp(raw.get("timestamp", raw.get("first_seen")), report.warnings)
        if isinstance(raw, dict)
        else None
    )
    report.evidence.append(
        Evidence(
            evidence_id=eid,
            report_id=report.report_id,
            source_sandbox=report.source_sandbox,
            evidence_type=kind,
            description="Source " + kind + " observation",
            raw_value=raw,
            normalized_value=observation(
                raw if normalized is None else normalized, kind, report.warnings
            ),
            source_reference=ref,
            timestamp=time,
        )
    )


class FamilyParser:
    name = "cuckoo"

    def recognizes(self, data):
        return isinstance(data.get("info"), dict) and any(
            k in data for k in ("target", "behavior", "network")
        )

    def parse(self, data, report):
        info = data.get("info", {})
        if not isinstance(info, dict):
            info = {}
            report.warnings.append("invalid info object")
        if info:
            add(report, "metadata", info, "/info")
        if self.name == "cuckoo":
            report.warnings.append(
                "Cuckoo-family schema detected; CAPE without markers requires explicit format override"
            )
        report.analysis_started_at = timestamp(info.get("started"), report.warnings)
        report.analysis_ended_at = timestamp(info.get("ended"), report.warnings)
        version = info.get("version")
        report.sandbox_version = str(version) if isinstance(version, (str, int, float)) else None
        target = data.get("target")
        if isinstance(target, dict) and isinstance(target.get("file"), dict):
            report.sample = target["file"]
            add(report, "sample", target["file"], "/target/file")
        else:
            report.warnings.append("sample metadata missing or invalid")
        for section in ("behavior", "network"):
            obj = data.get(section)
            if obj is None:
                report.warnings.append(section + " absent; coverage unknown")
                continue
            if not isinstance(obj, dict):
                report.warnings.append(section + " must be an object")
                continue
            known = {"processes", "processtree", "summary", "tcp", "udp", "dns", "http", "hosts"}
            if set(obj) - known:
                report.warnings.append(section + " contains unmodeled fields retained in original")
            groups = {
                "processes": "process",
                "processtree": "process_tree",
                "tcp": "network",
                "udp": "network",
                "dns": "dns",
                "http": "http",
                "hosts": "network",
            }
            for key, kind in groups.items():
                if key not in obj:
                    continue
                entries = obj[key]
                if not isinstance(entries, list):
                    report.warnings.append(pointer(section, key) + " must be an array")
                    continue
                for i, value in enumerate(entries):
                    if isinstance(value, dict) or (key == "hosts" and isinstance(value, str)):
                        add(
                            report,
                            kind,
                            value,
                            pointer(section, key, i),
                            normalized={"ip": value} if isinstance(value, str) else value,
                        )
                        if kind == "process" and isinstance(value, dict):
                            calls = value.get("calls", [])
                            if not isinstance(calls, list):
                                report.warnings.append(
                                    pointer(section, key, i, "calls") + " must be an array"
                                )
                            else:
                                for j, call in enumerate(calls):
                                    if isinstance(call, dict):
                                        add(
                                            report,
                                            "api_call",
                                            call,
                                            pointer(section, key, i, "calls", j),
                                        )
                                    else:
                                        report.warnings.append(
                                            pointer(section, key, i, "calls", j) + " invalid call"
                                        )
                    else:
                        report.warnings.append(pointer(section, key, i) + " invalid record")
            if section == "behavior":
                summary = obj.get("summary", {})
                if not isinstance(summary, dict):
                    report.warnings.append("/behavior/summary must be an object")
                    continue
                for key, entries in summary.items():
                    kind = (
                        "registry"
                        if key.startswith(("reg", "key"))
                        else "mutex"
                        if "mutex" in key
                        else "file"
                        if "file" in key
                        else "summary"
                    )
                    if not isinstance(entries, list):
                        report.warnings.append(
                            pointer(section, "summary", key) + " must be an array"
                        )
                        continue
                    for i, value in enumerate(entries):
                        add(
                            report,
                            kind,
                            value,
                            pointer(section, "summary", key, i),
                            normalized={"operation": key, "path": value}
                            if kind in {"registry", "file"} and isinstance(value, str)
                            else value,
                        )
        for key, kind in (
            ("signatures", "signature"),
            ("dropped", "file"),
            ("ttps", "attack_source"),
        ):
            if key in data:
                if not isinstance(data[key], list):
                    report.warnings.append("/" + key + " must be an array")
                    continue
                for i, value in enumerate(data[key]):
                    add(report, kind, value, pointer(key, i))
        unsupported = set(data) - {
            "info",
            "target",
            "behavior",
            "network",
            "signatures",
            "dropped",
            "ttps",
            "CAPE",
            "cape",
            "format",
        }
        if unsupported:
            report.warnings.append(
                "unmodeled top-level sections (retained in original): "
                + ", ".join(sorted(unsupported))
            )
        if self.name == "cape":
            for key in ("CAPE", "cape"):
                if key in data:
                    add(report, "sandbox_detection", data[key], pointer(key))


class CapeParser(FamilyParser):
    name = "cape"

    def recognizes(self, data):
        return "CAPE" in data or "cape" in data or data.get("format") == "cape"


class SyntheticParser:
    name = "synthetic"

    def recognizes(self, data):
        return data.get("format") == "synthetic-v1"

    def parse(self, data, report):
        observations = data.get("observations")
        if not isinstance(observations, list):
            raise TypeError("synthetic observations must be an array")
        for i, row in enumerate(observations):
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("type"), str)
                or "value" not in row
            ):
                raise ValueError("invalid synthetic observation")
            add(report, row["type"], row["value"], pointer("observations", i, "value"))


PARSERS = [CapeParser(), FamilyParser(), SyntheticParser()]


def choose(data, explicit=None):
    if explicit:
        for parser in PARSERS:
            if parser.name == explicit:
                return parser
        raise ValueError("unsupported parser override")
    for parser in PARSERS:
        if parser.recognizes(data):
            return parser
    raise ValueError(
        "unsupported or ambiguous report structure; use --format for Cuckoo-family reports"
    )
