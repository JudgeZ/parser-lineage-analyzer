#!/usr/bin/env python3
"""Repeatable smoke benchmark for native-acceleration target shapes."""

from __future__ import annotations

import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path

# Ensure the project root is on sys.path so the `tests` namespace package is
# importable when this script is invoked as `python scripts/benchmark_native_targets.py`.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from parser_lineage_analyzer import ReverseParser  # noqa: E402
from parser_lineage_analyzer._scanner import strip_comments_keep_offsets  # noqa: E402
from parser_lineage_analyzer.config_parser import parse_config  # noqa: E402
from tests.test_performance_scaling import (  # noqa: E402
    _hot_branch_append_parser,
    _independent_if_parser,
    _secops_routing_chain_parser,
)


def _mutate_only_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.k{i}" => "%{{v{i}}}" }} }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _comment_like_scanner_body(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        body = f'"url{i}" => "http://example.com/a//b/{i}" "xpath{i}" => {{//node{i}}}'
        lines.append(f"  mutate {{ replace => {{ {body} }} }} // trailing")
    lines.append("}")
    return "\n".join(lines)


def _time_call(fn: Callable[[], object], *, rounds: int) -> list[float]:
    values: list[float] = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        values.append(time.perf_counter() - start)
    return values


def _report(name: str, fn: Callable[[], object], *, rounds: int = 3) -> None:
    values = _time_call(fn, rounds=rounds)
    print(f"{name:34s} min={min(values):7.3f}s median={statistics.median(values):7.3f}s")


def main() -> None:
    scanner_body = _comment_like_scanner_body(10_000)
    config_body = 'replace => { "a" => ["b", ["c", "d"]] "url" => "http://example.com/a//b" }'
    if20k = _independent_if_parser(20_000)
    repeated_branch = _hot_branch_append_parser(10_000)
    routing = _secops_routing_chain_parser(4_000)

    _report("scanner strip comments", lambda: strip_comments_keep_offsets(scanner_body), rounds=5)
    _report("config fast path", lambda: [parse_config(config_body) for _ in range(5_000)], rounds=5)
    _report("20k independent ifs", lambda: ReverseParser(if20k).analyze(), rounds=1)
    _report("10k repeated branch appends", lambda: ReverseParser(repeated_branch).analyze(), rounds=1)
    _report("4k routing else-if chain", lambda: ReverseParser(routing).analyze(), rounds=1)


if __name__ == "__main__":
    main()
