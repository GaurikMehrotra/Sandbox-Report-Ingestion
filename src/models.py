"""Versioned canonical schema. Absence never implies negative evidence."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0"
PARSER_VERSION = "1.0"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(Model):
    evidence_id: str
    report_id: str
    source_sandbox: str
    evidence_type: str
    description: str
    raw_value: Any
    normalized_value: Any
    source_reference: str
    timestamp: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    normalization_version: str = SCHEMA_VERSION

    @field_validator("source_reference")
    @classmethod
    def pointer(cls, value):
        if not value.startswith("/"):
            raise ValueError("source_reference must be a JSON pointer")
        return value


class IOC(Model):
    type: str
    value: str
    original_values: list[str]
    evidence_ids: list[str]
    report_ids: list[str]
    first_seen: str | None = None
    last_seen: str | None = None
    classification: Literal["syntactically_valid"] = "syntactically_valid"
    public_ip: bool | None = None


class Finding(Model):
    finding_id: str
    kind: Literal["deterministic_interpretation", "source_detection"]
    rule_id: str
    description: str
    rationale: str
    evidence_ids: list[str] = Field(min_length=1)


class AttackMapping(Model):
    technique_id: str
    name: str
    origin: Literal["source_reported", "system_inferred"]
    rationale: str
    evidence_ids: list[str] = Field(min_length=1)
    catalog_version: str = "local-subset-2026-10"
    status: Literal["candidate", "unsupported_source_claim"] = "candidate"


class Stage(Model):
    name: str
    status: Literal["passed", "failed", "skipped"]
    detail: str | None = None


class Report(Model):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    report_id: str
    ingestion_id: str
    ingested_at: str
    original_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_sandbox: str
    sandbox_version: str | None = None
    analysis_started_at: str | None = None
    analysis_ended_at: str | None = None
    observations: dict[str, list[str]] = Field(default_factory=dict)
    parser_version: str = PARSER_VERSION
    sample: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attack: list[AttackMapping] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    stages: list[Stage] = Field(default_factory=list)
    correlations: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    ai: dict[str, Any] | None = None

    @model_validator(mode="after")
    def provenance(self):
        ids = {e.evidence_id for e in self.evidence}
        if len(ids) != len(self.evidence) or any(
            e.report_id != self.report_id for e in self.evidence
        ):
            raise ValueError("invalid evidence identities")
        from .ioc import normalize

        if any(
            not i.evidence_ids
            or not i.original_values
            or normalize(i.type, i.value) != i.value
            or set(i.evidence_ids) - ids
            or i.report_ids != [self.report_id]
            for i in self.iocs
        ):
            raise ValueError("invalid IOC provenance")
        if any(set(f.evidence_ids) - ids for f in [*self.findings, *self.attack]):
            raise ValueError("invalid finding provenance")
        if any(set(values) - ids for values in self.observations.values()):
            raise ValueError("invalid observation references")
        return self
