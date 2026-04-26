# Architecture

This document describes the analyzer's internals: the parser frontend, the
native acceleration layer, and the test fixture corpus. For user-facing
docs, see the [README](../README.md).

## Parser frontend

The frontend is a [Lark](https://github.com/lark-parser/lark) LALR pipeline
with two grammars:

- **Statement grammar** — `parser_lineage_analyzer/parser.py` plus
  `parser_lineage_analyzer/grammar/statement.lark`. Covers `filter`, `if`,
  `else if`, `else`, `for`, plugin blocks, and unknown-statement recovery.
  A stateful Lex-style scanner (`_SecOpsLexer`) feeds the LALR grammar.
- **Config grammar** — `parser_lineage_analyzer/config_parser.py` plus
  `parser_lineage_analyzer/grammar/config.lark`. Covers plugin configuration
  bodies — duplicate-key maps, arrays, strings, regex literals, bare
  identifiers, and flags.

Parse failures become deterministic `DiagnosticRecord` entries or `Unknown`
AST nodes — never tracebacks. Comment stripping is regex-aware so it
preserves `#` inside conditions, regex literals, and config strings, and
handles C-style block comments.

The semantic phase (`analyzer.py` + `_analysis_*.py`) consumes the AST and
produces reverse lineage. Conditional `@output` propagation, dynamic
destination template matching, JSON `target` scoping, CSV named columns,
XML loop XPath normalization, and loop-variable scope cleanup all live
here.

## Native acceleration

Cython extensions are optional. When wheels include them on Python 3.10
(Windows, Linux, macOS), they accelerate the scanner, config parser,
dedupe, branch-merge, and template helpers. Source installs always keep
pure-Python fallbacks.

| Env var | Effect |
|---|---|
| `PARSER_LINEAGE_ANALYZER_NO_EXT=1` | Disable all native helpers (build and runtime). |
| `PARSER_LINEAGE_ANALYZER_REQUIRE_EXT=1` | Make extension build failures fatal. |
| `PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE=0` | Disable native dedupe at runtime. |
| `PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE=0` | Disable native branch-merge at runtime. |

The differential fuzz suite (`tests/test_native_differential_fuzz.py`)
keeps the native and pure-Python paths in lockstep.

## Determinism contract

The analyzer returns a deterministic over-approximation of possible lineage
for documented parser syntax. It never picks a branch based on unavailable
raw values: when behavior depends on runtime data, the result includes all
static paths with their conditions, `dynamic` lineage, or warnings. This is
safer for production than silently inventing a single source path.

## Fixture corpus

The test suite exercises the analyzer against intentionally tricky parser
files in `examples/` and `tests/fixtures/`.

**Breaker / corpus fixtures** — escaped quotes, escaped terminal
backslashes, `//` comments with fake braces, regex containing `#`, nested
interpolation, drop semantics, unsupported plugin reporting, dynamic
fields, map/array loops, high fan-out conditionals, malformed-parser
recovery, inline comments, bare slash paths, `on_error` fallback bodies,
array-valued anchors, object-valued assignments, indirect dissect
placeholders, malformed `gsub` arrays:

- `breaker_parser.cbn`
- `breaker2_parser.cbn`
- `breaker3_parser.cbn`
- `corner_cases_parser.cbn`
- `dissect_base64_parser.cbn`
- `high_complexity_parser.cbn`
- `json_array_loop_parser.cbn`
- `mega_parser.cbn`

**Trip-up fixtures** — multiline regex conditions, whitespace-delimited
inline comments, bare slash constants, dissect indirect fields, mutate
`add_field`/`update`, standalone `on_error` fallback blocks, unquoted
bracket references, array-valued `@output` and `merge`, object-valued
`replace`, invalid JSON target arrays, nested date format arrays, base64
field maps, extra loop variables, malformed `gsub` arrays:

- `trip_up.cbn`
- `trip_up_2.cbn`
- `trip_up_3.cbn`
- `trip_up_4.cbn`
- `trip_up_5.cbn`

## Suggested production workflow

1. Run `--summary --json --strict` across the parser corpus.
2. Treat unsupported constructs and warnings as review items before
   trusting a parser at production confidence.
3. Compare representative results against SecOps parser-run or statedump
   output where sample logs are available.
4. Keep dynamic fields as symbolic lineage unless a raw-event mode is
   explicitly added for runtime branch and field-name resolution.
