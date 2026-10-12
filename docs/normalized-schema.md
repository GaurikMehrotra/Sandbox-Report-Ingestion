# Canonical schema 1.0

The executable definition is `src/models.py`. Generate JSON Schema with `Report.model_json_schema()`. Unknown canonical fields are rejected; future extensions require a new schema version or explicit schema update. Raw source dictionaries remain extensible. [Complete synthetic example](example-normalized.json) accompanies [JSON Schema](normalized-schema.json).

| Report field | Requirement and meaning |
| --- | --- |
| `schema_version` | Required/default `1.0` |
| `report_id`, `ingestion_id`, `ingested_at` | Required identity and UTC ingestion provenance |
| `original_sha256` | Required SHA256 of exact original bytes |
| `source_sandbox`, `sandbox_version` | Required source identifier, optional vendor version |
| `parser_version` | Adapter implementation revision; defaults to `1.0` |
| `analysis_started_at`, `analysis_ended_at` | Optional source analysis timestamps normalized to UTC |
| `sample` | Available sample file metadata; empty means missing/unknown |
| `observations` | Evidence-type sections containing evidence IDs, not copied records |
| `evidence` | Source observations, metadata, process relationships, file/registry/network events, calls and detections |
| `iocs` | Syntax-validated indicators with complete source-reference unions |
| `findings` | Deterministic interpretations or source detections |
| `attack` | Candidate inferred mappings and unverified source claims |
| `warnings` | Parsing/coverage limitations, never negative behavioral evidence |
| `stages` | Passed/failed/skipped status per pipeline stage |
| `correlations` | Live shared-IOC/behavior snapshot populated during export |
| `ai` | Optional backend metadata, execution status, structured hypotheses |

Observation section keys include `metadata`, `sample`, `process`, `process_tree`, `api_call`, `file`, `registry`, `mutex`, `network`, `dns`, `http`, `signature`, `sandbox_detection`, and `attack_source`. They appear only when observations exist. Not all vendor fields have canonical interpretations; unsupported content remains in the original.

## Evidence

Required: `evidence_id`, `report_id`, `source_sandbox`, `evidence_type`, `description`, `raw_value`, `normalized_value`, and `source_reference` (RFC 6901 JSON pointer). `normalization_version` defaults to 1.0. `timestamp` and `confidence` are nullable. Confidence is not invented: no implemented rule emits a numeric confidence.

`raw_value` equals the exact source value at its pointer. `normalized_value` may have validated domain/hash/IP/URL spelling, string process identifiers, or summary operation context. Both preserve source meaning. Naive source timestamps assume UTC and emit warnings; invalid timestamps stay raw with null canonical time. Timestamps are not created from report ingestion time to populate event first/last seen.

IDs need not carry malware meaning. Local evidence IDs are stable hashes of report identity plus pointer. A canonical import validates ownership/citations, assigns a new outer report identity, and points to `/evidence/N/raw_value` in the imported document. Its full source document is retained; nested original pointers remain auditable there. Previous derived findings are not blindly trusted: rules run again on observations. Common credential fields are redacted in exports, so an exported canonical document may contain redacted evidence; retrieve the private original/database for a full audit.

## Indicators, findings and mappings

IOC fields: `type`, `value`, `original_values`, `evidence_ids`, `report_ids`, nullable `first_seen`/`last_seen`, `classification=syntactically_valid`, and nullable `public_ip`. Supported kinds: md5, sha1, sha256, ip, domain, url, email, file_path, registry_path, mutex, filename, process_name. Deduplication uses type plus normalized value. Original strings and every source evidence ID are retained. First/last seen are available source event times only. IP policy changes indexing, not original observations.

Domains use IDNA/lowercase and strip a trailing dot; IPs use `ipaddress`; hashes require exact lengths; URLs require HTTP(S), valid host/port, and no embedded credentials. Paths are not resolved or lowercased against the local OS. Email local-part case is preserved. Generic free text and signature names do not become high-confidence indicators.

Findings require kind, rule ID/version, rationale, description and nonempty evidence references. ATT&CK mappings require technique ID/name, origin, rationale, catalog version, evidence references, and status. `system_inferred/candidate` is distinct from `source_reported/unsupported_source_claim`. No field asserts confirmed malware or attacker intent.

## Synthetic input format

```json
{
  "format": "synthetic-v1",
  "observations": [
    {"type": "dns", "value": {"domain": "Example.ORG."}},
    {"type": "process", "value": {"process_id": 123, "process_name": "demo.exe"}}
  ]
}
```

This fixture format is explicitly synthetic and has no claim to vendor compatibility. Each observation requires a string type and a value. Canonical import instead requires a complete validated `Report` document; the abbreviated README example is not a complete input report.
