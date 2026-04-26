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
- Public Python API (`ReverseParser`, `QueryResult`, `Lineage`, status and
  diagnostic models) under `parser_lineage_analyzer`.
- Native acceleration extensions (scanner, config, dedupe, template, branch
  merge) built as abi3 wheels for CPython 3.10+ on Linux, macOS, and Windows.
- Branch-aware lineage with per-path predicates, taint tracking, and
  structured diagnostics.
- Hypothesis property tests, differential fuzzing against the pure-Python
  fallbacks, and Atheris fuzz harnesses.
- CodeQL, Bandit, pip-audit, and ruff (with B/SIM/UP/I rules) wired into CI.
- Architecture notes in `docs/ARCHITECTURE.md` and security policy in
  `SECURITY.md`.

[0.1.0]: https://github.com/JudgeZ/parser-lineage-analyzer/releases/tag/v0.1.0
