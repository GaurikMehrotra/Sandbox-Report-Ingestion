# Implementation milestones

## Phase 0: audit

Actual checkout: clean, empty, unborn branch; no source, datasets, dependencies, tests, or existing analyzer modules. Python 3.12.14 available. No user work was overwritten. Main risks: overlapping source schemas, coverage ambiguity, hostile JSON and strings, loss of source context, and unsupported ATT&CK conclusions. Priorities: deterministic schema/input first; adapters/evidence/IOCs next; storage and CLI; optional local AI; evaluation and documentation. No commits or pushes were made.

Phase 1 acceptance: validated versioned schema; bounded malformed-input rejection; exact-byte original hash/preservation; stable source pointers; per-attempt stages and duplicate handling; isolated parser failures. These are covered by the integrated suite.

| Phase | Added/modified files and delivered functionality | Actual validation | Limits and next milestone |
| --- | --- | --- | --- |
| 1: foundation | `models.py`, `input.py`, `files.py`, `pipeline.py`, project configuration: schema, bounded input, identity, stages, safe files | Foundation checked in the first integrated 29-test run | Core present; vendor adapters needed next |
| 2: adapters | `parsers.py`, CAPE/Cuckoo/synthetic fixtures: source metadata, sample, processes/tree/calls, summary and network parsing | First integrated suite covered three adapters and malformed optional fields | Synthetic representative structures only; real version fixtures needed |
| 3: evidence and IOCs | `normalization.py`, `ioc.py`, `analysis.py`: pointers, original values, dedup provenance, registry/process/file/repeated-network signals | First run caught registry operation spelling; fixed, then 29 passed. Evaluation caught signature-name false positive; fixed with regression test | Conservative context-driven extraction; no universal API semantic analyzer |
| 4: storage/correlation | `storage.py`: SQLite indexes/search, originals, successful revision snapshots, history, exact IOC and rule-result correlations | Persistence, SQL-looking input, correlation and reprocessing tests; storage reopening added in 38-test suite | Single local database, no distributed or graph infrastructure |
| 5: CLI/reporting | `main.py`, `reporting.py`, `redaction.py`, `scripts/demo.py`: batch isolation, queries, inert Markdown, redacted JSON | End-to-end synthetic demo; all CLI queries tested in 43-test suite | Snapshot reports need regeneration after new inputs |
| 6: optional AI | `ai.py`: bounded local Ollama, no tools, validated hypotheses/citations, timeout and graceful failure | Injected valid/invalid/unavailable/prompt-injection responses; actual unavailable local endpoint preserved deterministic report | Real model quality unmeasured; citation existence does not establish entailment |
| 7: evaluation/hardening | `scripts/evaluate.py`, `scripts/benchmark.py`, labels, test suite, README and docs: measured metrics, security controls, reproducible examples | 45 tests passed after final integration; Ruff check/format; actual three-fixture evaluation and 5,000-event memory/time probe | Next: authorized sanitized real reports, independent annotations, broader catalog and native Windows validation |

Tests were integrated across phases, not fabricated as independent phase-specific runs. Later changes are verified by the final 45-test suite and fresh demo. The records above distinguish completed prototype capabilities from external validation and future expansion.
