"""Validate static lineage against runtime-observation fixtures.

Fixture layout:

    fixture_name/
      parser.cbn
      input.json
      expected.json

``input.json`` is retained as the observed runtime sample, but this script does
not execute parsers. It checks that static analysis covers the fields, tags, and
output anchors listed in ``expected.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TypedDict

from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._analysis_state import AnalyzerState
from parser_lineage_analyzer._plugin_specs import normalize_dialect
from parser_lineage_analyzer._types import JSONValue
from parser_lineage_analyzer.model import LIVE_LINEAGE_STATUSES

DEFAULT_ROOT = Path("tests/fixtures/runtime")


class _FixtureFailures(TypedDict):
    missing_fields: list[str]
    missing_tags: list[str]
    missing_output_anchors: list[str]


class _FixtureExpected(TypedDict):
    touched_fields: list[str]
    tags: list[str]
    output_anchors: list[str]


class _FixtureReport(TypedDict):
    fixture: str
    parser: str
    input: str | None
    dialect: str
    passed: bool
    expected: _FixtureExpected
    failures: _FixtureFailures


class _RuntimeReport(TypedDict):
    root: str
    fixture_count: int
    passed: int
    failed: int
    results: list[_FixtureReport]


def discover_fixtures(root: Path) -> list[Path]:
    return sorted(path.parent for path in root.rglob("expected.json") if (path.parent / "parser.cbn").is_file())


def check_fixture(fixture_dir: Path) -> _FixtureReport:
    parser_path = fixture_dir / "parser.cbn"
    input_path = fixture_dir / "input.json"
    expected_path = fixture_dir / "expected.json"
    expected_value: JSONValue = json.loads(expected_path.read_text(encoding="utf-8"))
    if not isinstance(expected_value, dict):
        raise ValueError(f"{expected_path} must be a JSON object")
    expected: Mapping[str, JSONValue] = expected_value
    code = parser_path.read_text(encoding="utf-8")
    dialect = normalize_dialect(str(expected.get("dialect", "secops")))
    parser = ReverseParser(code, dialect=dialect)
    state = parser.analyze()

    expected_fields = _string_list(expected, "touched_fields")
    expected_tags = _string_list(expected, "tags")
    expected_anchors = _string_list(expected, "output_anchors")

    missing_fields = [field for field in expected_fields if not _field_is_covered(parser, state, field)]
    possible_tags = set(state.tag_state.possibly) | set(state.tag_state.definitely)
    missing_tags = [tag for tag in expected_tags if tag not in possible_tags]
    anchors = {anchor.anchor for anchor in state.output_anchors}
    missing_anchors = [anchor for anchor in expected_anchors if anchor not in anchors]

    failures: _FixtureFailures = {
        "missing_fields": missing_fields,
        "missing_tags": missing_tags,
        "missing_output_anchors": missing_anchors,
    }
    failed = any(failures.values())
    expected_report: _FixtureExpected = {
        "touched_fields": expected_fields,
        "tags": expected_tags,
        "output_anchors": expected_anchors,
    }
    return {
        "fixture": fixture_dir.name,
        "parser": parser_path.as_posix(),
        "input": input_path.as_posix() if input_path.exists() else None,
        "dialect": dialect,
        "passed": not failed,
        "expected": expected_report,
        "failures": failures,
    }


def check_runtime_fixtures(root: Path) -> _RuntimeReport:
    root = root.resolve()
    results = [check_fixture(fixture_dir) for fixture_dir in discover_fixtures(root)]
    failed = [result for result in results if not result["passed"]]
    return {
        "root": root.as_posix(),
        "fixture_count": len(results),
        "passed": len(results) - len(failed),
        "failed": len(failed),
        "results": results,
    }


def _string_list(expected: Mapping[str, JSONValue], key: str) -> list[str]:
    value = expected.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    return [str(item) for item in value]


def _field_is_covered(parser: ReverseParser, state: AnalyzerState, field: str) -> bool:
    if any(lineage.status in LIVE_LINEAGE_STATUSES for lineage in state.tokens.get(field, [])):
        return True
    result = parser.query(field, compact=True)
    return any(mapping.status in LIVE_LINEAGE_STATUSES for mapping in result.mappings)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Runtime fixture root.")
    parser.add_argument("--json-out", type=Path, help="Optional JSON result path.")
    parser.add_argument("--no-fail", action="store_true", help="Return 0 even when fixtures mismatch.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    report = check_runtime_fixtures(args.root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if report["failed"] and not args.no_fail:
        for result in report["results"]:
            if not result["passed"]:
                print(f"{result['fixture']}: runtime fixture mismatch", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
