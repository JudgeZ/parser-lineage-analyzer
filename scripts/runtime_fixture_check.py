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
from pathlib import Path
from typing import Any

from parser_lineage_analyzer import ReverseParser

DEFAULT_ROOT = Path("tests/fixtures/runtime")


def discover_fixtures(root: Path) -> list[Path]:
    return sorted(path.parent for path in root.rglob("expected.json") if (path.parent / "parser.cbn").is_file())


def check_fixture(fixture_dir: Path) -> dict[str, Any]:
    parser_path = fixture_dir / "parser.cbn"
    input_path = fixture_dir / "input.json"
    expected_path = fixture_dir / "expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    code = parser_path.read_text(encoding="utf-8")
    parser = ReverseParser(code)
    state = parser.analyze()

    expected_fields = _string_list(expected, "touched_fields")
    expected_tags = _string_list(expected, "tags")
    expected_anchors = _string_list(expected, "output_anchors")

    missing_fields = [field for field in expected_fields if not _field_is_covered(parser, field)]
    possible_tags = set(state.tag_state.possibly) | set(state.tag_state.definitely)
    missing_tags = [tag for tag in expected_tags if tag not in possible_tags]
    anchors = {anchor.anchor for anchor in state.output_anchors}
    missing_anchors = [anchor for anchor in expected_anchors if anchor not in anchors]

    failures = {
        "missing_fields": missing_fields,
        "missing_tags": missing_tags,
        "missing_output_anchors": missing_anchors,
    }
    failed = any(failures.values())
    return {
        "fixture": fixture_dir.name,
        "parser": parser_path.as_posix(),
        "input": input_path.as_posix() if input_path.exists() else None,
        "passed": not failed,
        "expected": {
            "touched_fields": expected_fields,
            "tags": expected_tags,
            "output_anchors": expected_anchors,
        },
        "failures": failures,
    }


def check_runtime_fixtures(root: Path) -> dict[str, Any]:
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


def _string_list(expected: dict[str, Any], key: str) -> list[str]:
    value = expected.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    return [str(item) for item in value]


def _field_is_covered(parser: ReverseParser, field: str) -> bool:
    state = parser.analyze()
    if field in state.tokens:
        return True
    return bool(parser.query(field, compact=True).mappings)


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
