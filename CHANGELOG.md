# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-26

Initial public release.

### Added
- `parser-lineage-analyzer` CLI for tracing UDM fields back to the raw-log
  fields, captures, or expressions that populate them in Google SecOps /
  Chronicle parser code.
- `--include-pattern-bodies` flag opts the resolved grok regex body into JSON `details`.
- `PERF_SLOW_FACTOR` env var lets CI runners scale perf-test budgets for variance.
- Public Python API under `parser_lineage_analyzer`:
  - `ReverseParser`, `QueryResult`, `Lineage`, `SourceRef` — analyzer
    entry point and result types.
  - `LineageStatus`, `QueryStatus` — status enums (`exact`,
    `exact_capture`, `conditional`, `derived`, `constant`, `repeated`,
    `dynamic`, `removed`, `unresolved`, plus aggregate `partial`).
  - `OutputAnchor`, `IOAnchor` — `@output` event anchors and top-level
    Logstash-style input/output plugin instances.
  - `QueryResultAggregate` plus `QueryResult.aggregate()` /
    `QueryResult.compute_effective_diagnostics(aggregate)` — single-pass
    snapshot of every cross-mapping derived field, for renderers that
    need more than one of `status`/`is_conditional`/`has_dynamic`/etc.
  - `TaintReason`, `WarningReason`, `DiagnosticRecord`,
    `SyntaxDiagnostic` — structured diagnostic types.
  - `analysis_summary()` returns a `TypedDict`
    (`AnalysisSummaryDict | CompactAnalysisSummaryDict`) so static
    consumers don't need `isinstance` guards on every key read.
- Native acceleration extensions (scanner, config, dedupe, template, branch
  merge) built as abi3 wheels for CPython 3.10+ on Linux, macOS, and Windows.
- Branch-aware lineage with per-path predicates, taint tracking, and
  structured diagnostics.
- Hypothesis property tests, differential fuzzing against the pure-Python
  fallbacks, and Atheris fuzz harnesses (pure-Python and native-extension
  enabled jobs).
- CodeQL, Bandit, pip-audit, and ruff (with B/SIM/UP/I rules) wired into CI.
- PyPI publishing on tag push via OIDC Trusted Publishing (no API tokens
  in GitHub secrets); first release requires one-time configuration at
  https://pypi.org/manage/account/publishing/ with the `pypi` environment.
- Architecture notes in `docs/ARCHITECTURE.md`, security policy in
  `SECURITY.md`, and contributor guide in `CONTRIBUTING.md`.

### Changed
- `--strict` exit-code semantics clarified in `--help`: parser-level warnings and query-level uncertainty both trigger exit 3.
- Plain `--json` always emits `unsupported`, `warnings`, `output_anchors`, `structured_warnings`, `diagnostics` (as `[]` when empty); `--json --strict` adds a `strict_failure` object alongside the existing stderr line.
- Plugin-signature TOML loader: 1 MiB byte cap, malformed TOML wrapped to `ValueError` (no traceback), divergent `[table]` key vs explicit `name` rejected, outward symlink targets in `--plugin-signatures-dir` skipped.
- Grok pattern loader: 1 MiB per-file size cap and outward symlink targets are skipped.
- CLI cold-start: `--help` and `--version` no longer import `analyzer`/`pydantic` (~138 ms → ~22 ms on M-series).
- Re-grok now invalidates a prior implicit grok constraint regardless of body size.

[0.1.0]: https://github.com/JudgeZ/parser-lineage-analyzer/releases/tag/v0.1.0
