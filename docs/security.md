# Security model

The adversary controls report bytes, embedded strings, nested records, source names and apparent detections. The defender controls the selected input/output directories and local environment. Reports never select commands, SQL text, filenames for generated artifacts, external destinations, or tools.

## Input bounds and safe files

Only regular `.json` inputs are read, bounded to 16 MiB before decoding. UTF-8/BOM is supported; pickle, YAML, archives, duplicate keys, non-finite numbers, non-object roots, and malformed JSON are rejected. Iterative validation bounds decoded trees to 100,000 nodes and depth 40; Python recursion failures are caught. JSON decoding occurs within the byte bound before the structural bound is evaluated. Batch processing is sequential and limited to 1,000 immediate JSON children. It does not recursively follow directories.

Symlink input/output/store paths are rejected, including parent components. On systems with `O_NOFOLLOW`, input opening also guards the final component against replacement races. Report IDs are hash-derived and strictly checked before output naming; source filenames never determine artifact paths. Outputs use temporary files and atomic replacement. Originals use exclusive creation and verify existing bytes. The input files themselves are never modified. On native Windows, POSIX no-follow flags are unavailable; concurrent malicious local filesystem users are outside this prototype's fully enforced threat boundary. Parent-path race protection is best-effort, not an OS sandbox.

Storage uses parameterized SQLite and foreign keys. New store directories are private on POSIX. Protect and back up originals and SQLite: raw forensic telemetry is deliberately preserved and can contain credentials, personal data, URLs, or offensive strings. There is no built-in authentication, encryption, or multi-tenant isolation. Do not expose the store as a web directory.

## Outputs and secrets

Markdown escapes HTML/Markdown delimiters and control characters; report-supplied links/images are inert text. JSON remains data, not code. CLI output is concise metadata/status and explicitly requested search results. Error logs omit validation representations that can embed raw report strings. Exports and AI input redact common password/token/API-key/authorization/cookie fields, URL userinfo and common secret query parameters, plus obvious secret assignments/Bearer strings. Arbitrary secrets in unstructured text cannot be recognized reliably: review derived artifacts before sharing. The private originals/database remain the authoritative audit records.

## AI and external communication

AI is disabled by default. Opt-in uses only the fixed localhost Ollama endpoint; models are never downloaded automatically. Input is normalized/redacted evidence from at most 50 source records and 32,000 serialized characters. Responses are limited to 64 KiB, 20 claims and 1,200 generated tokens with a 20-second HTTP timeout. Redirects are rejected; there are no tools or report-derived endpoints. The request labels telemetry as untrusted data; the schema rejects extra keys/unknown citations and requires all generated claims to be hypotheses. Prompt injection cannot authorize shell commands or enrichment, because no such execution path exists. It can still influence model prose; citation validation is not semantic verification.

Ordinary ingestion has no network step. No sample execution, sample download, extracted-URL browsing, indicator connections, third-party uploads, external enrichment, or automated VPN/sandbox integration exists. Optional Ollama is user-configured local inference; secure that local service separately. Unit tests inject transport responses and do not require network or an LLM.

## Security tests

Tests cover malformed JSON/encoding, duplicate keys, nesting/node/byte limits, nonfinite numbers, symlinks, output traversal IDs, SQL-looking search input, exact original-byte preservation, provenance ownership, credential-field redaction, hostile Markdown, prompt-injection strings, invalid AI schemas/citations, and optional-stage failure. These are regression controls, not a penetration-test certification.
