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
- `--strict` exit-code semantics: any parser-level warning, taint, or
  unsupported construct, or any query-level uncertainty (unresolved,
  partial, dynamic), triggers exit 3 (clarified in `--help` text).
- Plain `--json` always emits `unsupported`, `warnings`,
  `output_anchors`, `structured_warnings`, `diagnostics` (as `[]` when
  empty); `--json --strict` adds a `strict_failure` object alongside
  the existing stderr line.
- Re-grok invalidates a prior implicit grok constraint regardless of
  body size, so an oversize-body second grok no longer leaves a stale
  shape constraint on the captured token.
- CLI cold-start: `--help` and `--version` skip importing
  `analyzer`/`pydantic`/`render`/the native extensions (~138 ms → ~25
  ms on M-series).

### Security
- Plugin-signature TOML loader: 1 MiB byte cap (enforced via
  `os.fstat` on the open handle so the cap and the read see the same
  file), malformed TOML wrapped to `ValueError` (no traceback),
  divergent `[table]` key vs explicit `name` rejected, and symlinks
  inside `--plugin-signatures-dir` whose targets resolve outside the
  configured directory are skipped (the resolved target is read, not
  the symlink, to defeat retarget races); symlink loops surface as
  skips rather than tracebacks.
- Grok pattern loader: 1 MiB per-file size cap (also `os.fstat`-after-
  open), the same symlink-containment policy, and the same
  read-the-resolved-target rule applied to `--grok-patterns-dir`.
- Warning-text rendering regex (`_QUOTED_OVER_ESCAPE`) is bounded
  ({0,1024} per side) so adversarial parser source can't trigger
  catastrophic backtracking.

[0.1.0]: https://github.com/JudgeZ/parser-lineage-analyzer/releases/tag/v0.1.0
