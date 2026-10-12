# Sandbox Report Ingestion

A local Python prototype that turns existing malware sandbox **reports** into searchable, evidence-grounded investigation artifacts. It does not execute samples, download malware, contact extracted indicators, or upload reports.

Different sandbox schemas obscure shared observations. This pipeline preserves original bytes, attaches JSON-pointer provenance to observations, normalizes indicators, and separates source detections from reproducible investigative interpretations. Missing fields mean unknown coverage, never absence of behavior.

## Installation

Requires Python 3.11+ (tested with Python 3.12.14). From this repository root:

```bash
python -m venv .venv
# Linux / WSL
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.lock
python -m src.main --help
```

Pydantic is the only runtime dependency beyond the standard library; the lock also installs pytest and Ruff. No database server, API key, Ollama installation, or sample files are required. Keep the checkout in its existing isolated task; a worktree is unnecessary.

## Architecture and supported formats

`validation → adapter → normalization/evidence → IOC extraction → rules/ATT&CK candidates → optional AI → SQLite → live correlations → JSON/Markdown`

- CAPE JSON: `CAPE`/`cape` markers or explicit `--format cape`.
- Cuckoo-family JSON: `info` and at least one of `target`, `behavior`, or `network`. CAPE without identifying markers cannot be distinguished automatically; specify its source.
- Canonical normalized JSON: complete schema version `1.0`, described in [normalized-schema](docs/normalized-schema.md).
- Synthetic fixtures: explicit `synthetic-v1`, documented below. All supplied fixtures are synthetic, not real malware reports.

Adapters retain target file metadata, process records/relationships/API calls, summary file/registry/mutex observations, DNS/HTTP/TCP/UDP/host records, dropped records, detections, and source ATT&CK claims. Unknown source sections remain in the immutable original and generate coverage warnings.

See [architecture](docs/architecture.md), [security](docs/security.md), and [evaluation](docs/evaluation.md).

## Reproducible demonstration

```bash
python -m scripts.demo
python -m src.main --store .local/demo stats
python -m src.main --store .local/demo search-ioc --value example.org
python -m src.main --store .local/demo search-ioc --value example.org --evidence
python -m src.main --store .local/demo list --source cape
```

The demo ingests three synthetic fixtures, finds their shared domain, and exports artifacts under `.local/demo/outputs`. Run it twice to demonstrate duplicate detection. Regenerate an individual investigation after adding reports to refresh correlations.

## CLI reference

The global `--store` option precedes the subcommand. The default is `.local`.

```bash
python -m src.main ingest --file tests/fixtures/cape.json --no-llm
python -m src.main ingest --file tests/fixtures/cuckoo.json --format cuckoo
python -m src.main ingest --file tests/fixtures/cape.json --reprocess
python -m src.main list
python -m src.main list --since 2026-01-01 --until 2026-12-31T23:59:59+00:00
python -m src.main techniques
python -m src.main history
python -m src.main stats
```

For your own reports, `ingest --directory data/reports` ingests immediate `.json` children in sorted order (nonrecursive, maximum 1,000). One failure does not prevent unrelated reports from saving. Exit status is nonzero for input/output failures; a duplicate is successful. The fixtures directory also contains annotation metadata, so use the curated demo rather than batch-ingesting that directory.

Copy a `report_id` from ingestion output or `list`, then:

```text
python -m src.main report --id REPORT_ID
python -m src.main correlate --id REPORT_ID
python -m src.main history --id REPORT_ID
```

`REPORT_ID` above is a metavariable, not a literal ID. `report` exports canonical JSON and Markdown; `correlate` returns shared IOCs and deterministic rule results with both reports' evidence references. `search-ioc --value` performs exact normalized-value lookup; `--evidence` returns the related source observations. Report dates use source analysis start time if parseable, otherwise ingestion time. Date filters compare UTC ISO strings; use UTC inputs.

`--exclude-nonpublic` removes private, loopback, reserved, and other nonglobal IPs from the IOC index, but not evidence. Use `--reprocess` when changing extraction policy or enabling AI on an already ingested report. Reprocessing retains previous normalized versions in SQLite history and preserves original bytes.

Outputs default to `.local/outputs`; override with `--output DIRECTORY`. Originals live in `STORE/originals/SHA256.json` and the database in `STORE/reports.sqlite3`. Back up both. These local originals/database can contain sensitive telemetry; derived exports redact common credential keys and URL credentials. Redaction is heuristic, not a guarantee that arbitrary secrets in free text will be detected.

## Evidence and normalized output

[Example complete normalized JSON](docs/example-normalized.json) is generated from the synthetic CAPE fixture. An evidence record looks like:

```json
{
  "evidence_type": "dns",
  "raw_value": {"domain": "Example.ORG.", "answers": [{"ip": "192.0.2.10"}]},
  "normalized_value": {"domain": "example.org", "answers": [{"ip": "192.0.2.10"}]},
  "source_reference": "/network/dns/0"
}
```

This is an abbreviated illustration; full records also require IDs, source, description, and normalization version. An IOC search returns report IDs, indicator type/value, and evidence IDs. Indicator syntax validation **does not establish maliciousness**.

## Optional local AI

Core ingestion defaults to no LLM. To use an already installed local Ollama model:

```bash
python -m src.main ingest --file tests/fixtures/cape.json --reprocess --llm
```

The fixed endpoint is `127.0.0.1:11434`, model `llama3.2:3b`; no model is installed or downloaded automatically. Evidence is bounded and redacted, no tools are provided, structured outputs are validated, and unknown citations are rejected. Responses remain hypotheses: citation validation does not verify semantic entailment. An unavailable model records a failed optional stage while evidence is saved. A real model's quality has not been evaluated.

## Tests and evaluation

```bash
python -m pytest -q
ruff check src tests scripts
ruff format --check src tests scripts
python -m scripts.evaluate --output .local/evaluation.json --csv .local/evaluation.csv
```

Tests use synthetic telemetry and injected AI responses, never malware or network access. [Measured results](docs/evaluation-results.json) and CSV accompany the methodology. Small self-authored fixtures demonstrate contract compliance, not real-world detection accuracy.

## Known limitations

This is a research prototype, not a production detection system. It has no user authentication, remote enrichment, web UI, distributed workers, or sample analysis. Tested source structures are representative synthetic Cuckoo-family shapes; vendor versions need sanitized real-report validation. API calls are retained rather than universally translated into behavior. Summary observations may lack process attribution and timestamps. Filesystem path case and aliases are deliberately not collapsed across operating systems. Rules are narrow signals; the local ATT&CK catalog is a four-entry subset, not the complete official catalog. Correlations show overlap, not causality or family attribution. Very large reports are rejected (16 MiB, 100,000 JSON nodes, depth 40). Linux/WSL execution is verified; native Windows paths are supported in code but native Windows execution has not been tested.
