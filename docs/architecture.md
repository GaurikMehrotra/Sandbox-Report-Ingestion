# Architecture

The repository audit found no existing analyzers or application code. This implementation therefore adds isolated modules rather than replacing functionality.

| Module | Boundary |
| --- | --- |
| `input.py`, `files.py` | UTF-8 JSON validation, resource bounds, regular-file and path checks, atomic output |
| `models.py` | Pydantic schema 1.0, evidence/IOC/finding models, referential consistency |
| `parsers.py` | Common adapter protocol; Cuckoo, CAPE, synthetic extraction; JSON pointers and timestamps |
| `normalization.py`, `ioc.py` | Preserve raw records, canonical values, contextual indicator validation and provenance union |
| `analysis.py` | Versioned deterministic rules, source-label separation, offline ATT&CK subset |
| `pipeline.py` | Stages, ingestion identity, duplicate checks, reprocessing, optional-stage isolation |
| `storage.py` | SQLite metadata/IOC indexes, originals, revision history, search and live correlation |
| `ai.py` | Opt-in localhost Ollama, bounded evidence, structured hypotheses and citation validation |
| `redaction.py`, `reporting.py` | Credential-field redaction, inert Markdown, canonical JSON exports |
| `main.py` | CLI orchestration, batch failure isolation, concise progress and exit status |

## Data flow

```mermaid
flowchart LR
    I[Report JSON] --> V[Bounded validation]
    V --> P[Deterministic adapter]
    P --> E[Canonical evidence and source pointers]
    E --> C[IOC normalization]
    C --> B[Rules and candidate ATT&CK]
    B --> A[Optional local AI]
    A --> S[SQLite and immutable originals]
    S --> R[Live cross-report correlation]
    R --> O[JSON and Markdown]
```

Adapters implement `recognizes(data)` and `parse(data, report)`. Their protocol is intentionally simple; registering another adapter requires recognition tests, annotated fixtures, and coverage documentation. Explicit overrides identify incomplete family reports; they do not fill missing data. Source fields remain in raw values. Normalized values adjust indicator spelling and valid numeric process identifiers, without resolving paths against the analyst's filesystem.

## Evidence and interpretations

A deterministic report ID derives from original SHA256 plus adapter identity. Evidence IDs derive from report ID and exact JSON pointer. Ingestion IDs/times vary per attempt; evidence, IOCs, and deterministic findings remain stable for identical bytes and configuration. Every finding/mapping cites registered evidence. Pydantic validation rejects dangling references and mismatched report ownership. Original source bytes are kept independently of schema transformations.

Process records retain explicit parent identifiers and optional source parent names; process-tree structures remain observations. Summary file/registry records attach their source operation in the normalized value while the raw value is the exact source string. API-call records have individual JSON pointers. Missing process attribution is not guessed.

Source detections are not ground truth. Registry Run-key modifications, explicit Office-child shell records, noteworthy file writes, and repeated network indicator records are narrow, versioned investigative signals. PowerShell process plus command line and autostart modification support candidate ATT&CK mappings. Source mappings remain explicitly unsupported source claims until independently established. The `CATALOG` constant is the local, versioned catalog; no runtime network lookup occurs.

## Persistence and search

`reports` stores current canonical documents and indexed source/date/version metadata. `indicators` indexes `(value,type)` and maps report IDs to evidence IDs. `history` records every attempt, including duplicate/failure status and complete previous canonical documents for successful reprocessing. Queries are parameterized. Foreign keys bind IOC rows to reports. Report replacement, IOC refresh, and the success history row commit together. Content-addressed originals use exclusive creation and byte comparison when already present.

Cross-report indicator joins are exact type/value matches; separate behavioral correlation compares deterministic rule IDs and returns supporting evidence on each side. These queries run after storage, so they include subsequently ingested reports. Markdown exports are snapshots: regenerate them to reflect new correlations. Technique search currently scans canonical documents; it is sufficient for a small local prototype but not a large corpus.

## Failure policy

Validation/parser failures produce safe stage/category messages and persist attempt history. Unrelated batch inputs continue. Optional AI failure produces a failed AI stage, not lost deterministic data. Storage failures cannot claim success; original copies may remain after a database failure and are safe to reuse. Export failures return nonzero CLI status while ingested data remains retrievable. A storage-wide failure (disk full/corrupt SQLite) may prevent audit persistence too; this is not recoverable through per-report retries.

Parsing warnings record absent, invalid, or unsupported coverage. Entire raw reports are not dumped to CLI logs. No services need startup for core operation; SQLite is embedded. The optional Ollama service/model is an independently provisioned user prerequisite.
