# Parser Lineage Analyzer

Trace a UDM field back to the raw-log field, capture, or expression that
populates it — by reading the parser, not by running it.

Given a Google SecOps / Chronicle parser file and a UDM field name,
`parser-lineage-analyzer` returns every static path the parser could use to
populate that field, with the conditions guarding each path. No sample log
required. When the parser branches, every reachable path is reported with
its predicates rather than guessing one.

## Quickstart

```bash
pip install .
parser-lineage-analyzer examples/example_parser.cbn target.ip
```

```text
UDM field: target.ip
Status: exact_capture

Output anchors: event
Candidate parser fields checked:
  - target.ip
  - event.target.ip
  - event.idm.read_only_udm.target.ip

Mappings:
  [1] status=exact_capture
      expression: dstAddr
      sources:
        - grok_capture:network:dstAddr
          source_token: network
          capture_name: dstAddr
          pattern: %{IP:dstAddr}
```

(Parser-level warnings, when present, follow the mappings under a `Warnings:`
heading; pass `--verbose` for parser locations, notes, taints, and
structured-warning detail.)

A conditional parser returns every reachable mapping with its predicates:

```bash
parser-lineage-analyzer examples/conditional_parser.cbn security_result.action
```

```text
Mappings:
  [1] status=conditional
      expression: ALLOW
      sources:
        - constant:'ALLOW'
      conditions:
        - [action] == "allow"

  [2] status=conditional
      expression: BLOCK
      sources:
        - constant:'BLOCK'
      conditions:
        - NOT([action] == "allow")
        - [action] == "deny" or [action] == "drop"

  [3] status=conditional
      expression: UNKNOWN_ACTION
      sources:
        - constant:'UNKNOWN_ACTION'
      conditions:
        - NOT([action] == "allow")
        - NOT([action] == "deny" or [action] == "drop")
```

## Install

Requires Python 3.10+. Runtime dependencies: `lark>=1.3.1,<2`,
`pydantic>=2.13.3,<3`.

```bash
pip install .             # installs the parser-lineage-analyzer CLI
pip install '.[dev]'      # adds pytest, ruff, mypy, Cython
```

You can also run without installing:

```bash
python3 -m parser_lineage_analyzer examples/example_parser.cbn target.ip
```

The tool reads from a path, or from stdin when the path is `-`:

```bash
cat examples/example_parser.cbn | parser-lineage-analyzer - target.ip
```

## CLI

```
parser-lineage-analyzer PARSER_FILE [UDM_FIELD] [flags]
```

`UDM_FIELD` is required for query mode and omitted for `--list` /
`--summary`. Flags may appear in any position.

| Flag | Purpose |
|---|---|
| `--json` | Machine-readable JSON output. |
| `--list` | List discovered UDM-like parser fields instead of querying. |
| `--summary` | Emit parser/analyzer coverage summary. |
| `--compact-json` | Bound query JSON for high-cardinality output; samples large arrays, preserves `*_total` counters. |
| `--compact-summary` | Bound summary diagnostics; includes counts by code. Implies `--summary`. |
| `--strict` | Exit `3` if the result is unresolved/partial/dynamic, or any warning, taint, or unsupported construct is present. |
| `--verbose` | Include parser locations, notes, taints, and structured warnings in text output. |
| `--max-parser-bytes N` | Cap input size in bytes (default `25000000`; `-1` for unlimited). |
| `--mutate-canonical-order` | Reorder ops within each `mutate{}` block into Logstash's canonical execution order. Default is source order. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | I/O, parser construction, or analysis error. |
| `2` | Argparse / usage error. |
| `3` | `--strict` triggered. |

## Python API

```python
from parser_lineage_analyzer import ReverseParser

parser_code = open("examples/example_parser.cbn").read()
result = ReverseParser(parser_code).query("target.ip")

for mapping in result.mappings:
    print(mapping.status, mapping.sources)
```

Public exports from `parser_lineage_analyzer`:

| Name | What it is |
|---|---|
| `ReverseParser` | Analyzer entry point. Construct with parser source, then call `.query(udm_field)` or `.analyze()`. |
| `QueryResult` | Result of `.query(...)`, including `mappings` and an aggregate `status`. |
| `QueryResultAggregate` | Snapshot of every cross-mapping derived field returned by `QueryResult.aggregate()`. |
| `Lineage` | One static path the parser could use to populate the field. |
| `LineageStatus` | Per-mapping status — see [Output statuses](#output-statuses). |
| `QueryStatus` | Aggregate status across all mappings. |
| `SourceRef` | A source location (raw field, capture, JSON path, XPath, KV key, etc.). |
| `OutputAnchor` | The `@output` event(s) the field is emitted on. |
| `IOAnchor` | Top-level Logstash-style input/output plugin instance. |
| `TaintReason` | Structured reason a path is uncertain. |
| `WarningReason` | Structured reason for a parser-level warning. |
| `DiagnosticRecord`, `SyntaxDiagnostic` | Parser/analyzer diagnostics. |
| `AnalysisSummaryDict` | `TypedDict` shape returned by `ReverseParser.analysis_summary()`. |
| `CompactAnalysisSummaryDict` | `TypedDict` shape returned by `ReverseParser.analysis_summary(compact=True)`. |

Modules whose names start with `_` are private. `QueryResult.status` reports
the dominant outcome — dynamic or unresolved uncertainty takes precedence
over conditionality. For orthogonal gates use `is_conditional`,
`has_dynamic`, `has_unresolved`, and `has_taints`.

## Supported parser features

- **Wrappers**: `filter { ... }`, `if`/`else if`/`else`, `for item in array`,
  `for key, value in object map`, `on_error` flags and standalone fallback blocks.
- **Extractors**: `grok` (with `%{PATTERN:token}`, `(?P<name>...)`, `(?<name>...)`),
  `json` (with `target` scoping and `array_function => "split_columns"`),
  `xml` (with `xpath => { ... }` and `//` paths), `kv`, `csv` (including
  `columns => [...]`), `dissect`.
- **Mutate**: `replace`, `add_field`, `update`, `rename`, `copy`, `merge`,
  `convert`, `lowercase`, `uppercase`, `gsub`, `split`, `remove_field`.
- **Transforms** (symbolic): `date`, `url_decode`, `base64`.
- **References**: bracket forms like `%{[network][dst_ip]}` and
  `[new][field]` are normalized to dotted paths.
- **Loops**: dotted access on loop vars (`alert.name` → `alerts[*].name`),
  nested array/object loop paths, object-token merge projection
  (`label.value` → `...labels.value`), XML loop XPath normalization.
- **Output**: `@output` anchors including multi-event and array-valued
  forms (`["event1", "event2"]`).
- **Diagnostics**: warnings for malformed `gsub` arrays, unsupported JSON
  target arrays, indirect dissect fields, over-wide loop variable lists,
  dynamic destination templates, and parser-level recovery.

## Output statuses

Per-mapping `LineageStatus`:

| Status | Meaning |
|---|---|
| `exact` | One direct source field, JSON path, XPath, KV key, CSV column, or loop key/value. |
| `exact_capture` | Grok or named-regex capture from a source token. |
| `conditional` | Path requires one or more branch predicates. |
| `derived` | Value is transformed or built from multiple tokens/constants. |
| `constant` | Parser assigns a literal. |
| `repeated` | `merge`/append-style semantics. |
| `dynamic` | At least one path depends on runtime data (e.g. destination template). |
| `removed` | Parser removes the field. |
| `unresolved` | Source could not be inferred from the implemented subset. |

`QueryResult.status` (aggregate) takes any value above plus `partial` —
mixed resolved/removed/unresolved paths.

## Limitations

- Does not execute parsers or validate UDM schemas.
- Does not evaluate expressions or regex predicates.
- Dynamic destination names like `"network.%{application_protocol}"` are
  reported with `dynamic` lineage and a warning.
- Custom or undocumented plugins are reported under `unsupported`.
- "Which branch did *this* event take?" requires a sample log and is out of
  scope.

## Testing

```bash
python3 -m pytest -q
```

The suite covers the documented features end-to-end and a corpus of
intentionally tricky fixtures (escaped quotes, regex containing `#`, nested
interpolation, drop semantics, malformed parsers, etc.). See
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for the parser frontend, native
acceleration build/runtime flags, and fixture inventory.

## References

- [Google SecOps parser syntax](https://docs.cloud.google.com/chronicle/docs/reference/parser-syntax)
- [Google SecOps CLI parser commands](https://docs.cloud.google.com/chronicle/docs/administration/cli-user-guide)

## License and trademarks

MIT — see [LICENSE](LICENSE).

This is an independent, community-maintained project. It is not affiliated
with, endorsed by, sponsored by, or supported by Google. Google, Google
Security Operations, SecOps, Chronicle, and related product names are
trademarks of Google LLC; they are used here only to identify the parser
syntax and product ecosystem this tool analyzes.
