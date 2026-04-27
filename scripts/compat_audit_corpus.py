"""Batch compatibility audit for parser corpus fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._plugin_signatures import PluginSignatureRegistry, load_bundled_registry

DEFAULT_ROOT = Path("tests/fixtures/test_corpus")
DEFAULT_OUT_DIR = Path("build/compat-audit")
DEFAULT_DIALECTS = ("secops", "logstash")
REGRESSION_TOTAL_KEYS = (
    "unsupported_plugins",
    "unsupported_mutate_operations",
    "unknown_config_keys",
    "dynamic_or_symbolic_warnings",
)


def iter_parser_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.cbn") if path.is_file())


def audit_corpus(
    root: Path, dialects: list[str], plugin_signatures: PluginSignatureRegistry | None = None
) -> dict[str, Any]:
    root = root.resolve()
    parser_files = iter_parser_files(root)
    reports_by_dialect: dict[str, list[dict[str, Any]]] = {}
    totals_by_dialect: dict[str, dict[str, Any]] = {}

    for dialect in dialects:
        reports: list[dict[str, Any]] = []
        unsupported_plugins: Counter[str] = Counter()
        unsupported_mutate_ops: Counter[str] = Counter()
        unknown_config_keys: Counter[str] = Counter()
        warning_counts: Counter[str] = Counter()
        affected_fields: Counter[str] = Counter()
        totals: Counter[str] = Counter()

        for path in parser_files:
            rel_path = path.relative_to(root).as_posix()
            try:
                code = path.read_text(encoding="utf-8-sig")
                report = ReverseParser(code, dialect=dialect, plugin_signatures=plugin_signatures).compat_report(
                    compact=True
                )
            except Exception as exc:  # pragma: no cover - defensive path for malformed external corpora
                report = {
                    "dialect": dialect,
                    "error": f"{type(exc).__name__}: {exc}",
                    "totals": {
                        "unsupported_plugins": 0,
                        "unsupported_mutate_operations": 0,
                        "unknown_config_keys": 0,
                        "failure_tag_routes": 0,
                        "affected_fields": 0,
                        "dynamic_or_symbolic_warnings": 0,
                    },
                    "warning_counts": {"audit_error": 1},
                    "unsupported_plugin_counts": {},
                    "unsupported_mutate_operation_counts": {},
                    "unknown_config_key_counts": {},
                    "affected_field_counts": {},
                }
            reports.append({"path": rel_path, "report": report})
            report_totals = report.get("totals", {})
            if isinstance(report_totals, dict):
                for key, value in report_totals.items():
                    if isinstance(value, int):
                        totals[key] += value
            unsupported_plugins.update(_counter_from_report(report, "unsupported_plugin_counts"))
            unsupported_mutate_ops.update(_counter_from_report(report, "unsupported_mutate_operation_counts"))
            unknown_config_keys.update(_counter_from_report(report, "unknown_config_key_counts"))
            warning_counts.update(_counter_from_report(report, "warning_counts"))
            affected_fields.update(_counter_from_report(report, "affected_field_counts"))

        reports_by_dialect[dialect] = reports
        totals_by_dialect[dialect] = {
            "parser_count": len(parser_files),
            "totals": dict(sorted(totals.items())),
            "unsupported_plugin_counts": _top_counts(unsupported_plugins),
            "unsupported_mutate_operation_counts": _top_counts(unsupported_mutate_ops),
            "unknown_config_key_counts": _top_counts(unknown_config_keys),
            "warning_counts": _top_counts(warning_counts),
            "top_affected_fields": _top_counts(affected_fields),
        }

    return {
        "root": root.as_posix(),
        "dialects": dialects,
        "plugin_signatures": {
            "enabled": plugin_signatures is not None,
            "count": len(plugin_signatures) if plugin_signatures is not None else 0,
        },
        "parser_count": len(parser_files),
        "totals_by_dialect": totals_by_dialect,
        "reports_by_dialect": reports_by_dialect,
    }


def _counter_from_report(report: dict[str, Any], key: str) -> Counter[str]:
    raw = report.get(key, {})
    if not isinstance(raw, dict):
        return Counter()
    out: Counter[str] = Counter()
    for item, count in raw.items():
        if isinstance(count, int):
            out[str(item)] += count
    return out


def _top_counts(counter: Counter[str], limit: int = 25) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit])


def render_markdown(audit: dict[str, Any]) -> str:
    lines = [
        "# Parser Compatibility Audit",
        "",
        f"- Root: `{audit['root']}`",
        f"- Parsers: {audit['parser_count']}",
        f"- Dialects: {', '.join(audit['dialects'])}",
        f"- Plugin signatures: {audit['plugin_signatures']['count'] if audit['plugin_signatures']['enabled'] else 0}",
        "",
    ]
    totals_by_dialect = audit["totals_by_dialect"]
    for dialect in audit["dialects"]:
        dialect_totals = totals_by_dialect[dialect]
        totals = dialect_totals["totals"]
        lines.extend(
            [
                f"## {dialect}",
                "",
                "| Metric | Count |",
                "| --- | ---: |",
            ]
        )
        for key in sorted(totals):
            lines.append(f"| {key} | {totals[key]} |")
        lines.append("")
        for heading, key in (
            ("Unsupported Plugins", "unsupported_plugin_counts"),
            ("Unsupported Mutate Ops", "unsupported_mutate_operation_counts"),
            ("Unknown Config Keys", "unknown_config_key_counts"),
            ("Warning Counts", "warning_counts"),
            ("Top Affected Fields", "top_affected_fields"),
        ):
            lines.extend(_markdown_counts(heading, dialect_totals[key]))
    return "\n".join(lines).rstrip() + "\n"


def _markdown_counts(heading: str, counts: dict[str, int]) -> list[str]:
    lines = [f"### {heading}", ""]
    if not counts:
        return [*lines, "_None_", ""]
    lines.extend(["| Name | Count |", "| --- | ---: |"])
    for name, count in counts.items():
        lines.append(f"| `{name}` | {count} |")
    lines.append("")
    return lines


def regression_messages(current: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    messages: list[str] = []
    current_totals = current.get("totals_by_dialect", {})
    baseline_totals = baseline.get("totals_by_dialect", {})
    if not isinstance(current_totals, dict) or not isinstance(baseline_totals, dict):
        return ["baseline/current audit shape is invalid"]
    for dialect in sorted(current_totals):
        if isinstance(dialect, str) and dialect not in baseline_totals:
            messages.append(f"{dialect}: missing baseline dialect")
    for dialect, baseline_payload in baseline_totals.items():
        if not isinstance(dialect, str) or not isinstance(baseline_payload, dict):
            continue
        current_payload = current_totals.get(dialect)
        if not isinstance(current_payload, dict):
            messages.append(f"{dialect}: missing current dialect")
            continue
        baseline_counts = baseline_payload.get("totals", {})
        current_counts = current_payload.get("totals", {})
        if not isinstance(baseline_counts, dict) or not isinstance(current_counts, dict):
            continue
        for key in REGRESSION_TOTAL_KEYS:
            old = baseline_counts.get(key, 0)
            new = current_counts.get(key, 0)
            if isinstance(old, int) and isinstance(new, int) and new > old:
                messages.append(f"{dialect}: {key} regressed from {old} to {new}")
    return messages


def write_outputs(audit: dict[str, Any], json_out: Path, md_out: Path) -> None:
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_out.write_text(render_markdown(audit), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Corpus root containing .cbn files.")
    parser.add_argument(
        "--dialect",
        action="append",
        choices=DEFAULT_DIALECTS,
        help="Dialect to audit. Repeat to compare multiple dialects. Defaults to secops and logstash.",
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Default output directory.")
    parser.add_argument("--json-out", type=Path, help="JSON artifact path.")
    parser.add_argument("--md-out", type=Path, help="Markdown artifact path.")
    parser.add_argument(
        "--bundled-signatures",
        action="store_true",
        help="Load bundled conservative plugin signatures during the audit.",
    )
    parser.add_argument("--fail-on-regression", type=Path, help="Baseline JSON artifact to compare against.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    dialects = list(dict.fromkeys(args.dialect or list(DEFAULT_DIALECTS)))
    json_out = args.json_out or (args.out_dir / "compat-audit.json")
    md_out = args.md_out or (args.out_dir / "compat-audit.md")

    plugin_signatures = load_bundled_registry() if args.bundled_signatures else None
    audit = audit_corpus(args.root, dialects, plugin_signatures=plugin_signatures)
    write_outputs(audit, json_out, md_out)

    if args.fail_on_regression:
        baseline = json.loads(args.fail_on_regression.read_text(encoding="utf-8"))
        messages = regression_messages(audit, baseline)
        if messages:
            for message in messages:
                print(message, file=sys.stderr)
            return 1

    print(f"Wrote {json_out}")
    print(f"Wrote {md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
