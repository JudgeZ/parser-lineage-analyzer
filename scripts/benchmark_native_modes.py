#!/usr/bin/env python3
"""Run focused native-acceleration benchmark gates across runtime modes."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable, Sequence
from typing import Protocol, cast

NATIVE_ENV_FLAGS = (
    "PARSER_LINEAGE_ANALYZER_NO_EXT",
    "PARSER_LINEAGE_ANALYZER_REQUIRE_EXT",
    "PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE",
    "PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE",
)

MODES: tuple[tuple[str, dict[str, str]], ...] = (
    ("default-native", {}),
    ("no-ext", {"PARSER_LINEAGE_ANALYZER_NO_EXT": "1"}),
    ("no-native-dedupe", {"PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE": "0"}),
    ("no-native-branch-merge", {"PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE": "0"}),
)

DEFAULT_MODE_BUDGET_SECONDS = 60.0
DEFAULT_TOTAL_BUDGET_SECONDS = 240.0
MODE_BUDGET_ENV = "PARSER_LINEAGE_ANALYZER_BENCH_MODE_BUDGET_SECONDS"
TOTAL_BUDGET_ENV = "PARSER_LINEAGE_ANALYZER_BENCH_TOTAL_BUDGET_SECONDS"


class _CompletedProcessLike(Protocol):
    returncode: int


class _Runner(Protocol):
    def __call__(self, command: list[str], *, env: dict[str, str], timeout: float | None) -> _CompletedProcessLike: ...


BENCHMARK_DRIVER = r"""
import time

from parser_lineage_analyzer import ReverseParser
from tests.test_performance_scaling import (
    _analysis_seconds,
    _dynamic_mutate_parser,
    _hot_branch_append_parser,
    _independent_if_parser,
    _parse_and_analysis_seconds,
    _repeated_append_parser,
    _secops_routing_chain_parser,
)


def report(name, fn):
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    print(f"{name:34s} {elapsed:8.3f}s")
    return result


report("4k SecOps routing chain", lambda: _parse_and_analysis_seconds(_secops_routing_chain_parser(4_000)))
report("20k independent ifs", lambda: _analysis_seconds(_independent_if_parser(20_000)))
report("10k repeated branch appends", lambda: _analysis_seconds(_hot_branch_append_parser(10_000)))
report("20k repeated same-token appends", lambda: _analysis_seconds(_repeated_append_parser(20_000)))


def dynamic_destination():
    parser = ReverseParser(_dynamic_mutate_parser(20_000))
    parser.analyze()
    parser.query("principal.ip")
    parser.query("additional.fields.anything")


report("dynamic destination analyze+query", dynamic_destination)
"""


def _budget_from_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        print(f"Invalid {name}={raw!r}; expected a number of seconds", file=sys.stderr)
        return default
    return value


def _run_mode(
    name: str,
    updates: dict[str, str],
    *,
    benchmark_driver: str,
    mode_budget_seconds: float,
    timeout_seconds: float | None,
    runner: _Runner,
    clock: Callable[[], float],
) -> int:
    env = dict(os.environ)
    for flag in NATIVE_ENV_FLAGS:
        env.pop(flag, None)
    env.update(updates)
    command = [sys.executable, "-c", textwrap.dedent(benchmark_driver)]
    start = clock()
    print(f"\n== {name} ==", flush=True)
    try:
        result = runner(command, env=env, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        elapsed = clock() - start
        timeout_label = "unknown" if timeout_seconds is None else f"{timeout_seconds:.3f}s"
        print(f"mode={name} exit=timeout elapsed={elapsed:.3f}s")
        print(f"mode={name} timed out after {timeout_label}", file=sys.stderr)
        return 1
    elapsed = clock() - start
    print(f"mode={name} exit={result.returncode} elapsed={elapsed:.3f}s")
    failed = result.returncode
    if mode_budget_seconds >= 0 and elapsed > mode_budget_seconds:
        print(
            f"mode={name} exceeded benchmark budget: {elapsed:.3f}s > {mode_budget_seconds:.3f}s",
            file=sys.stderr,
        )
        failed = 1
    return 1 if failed else 0


def main(
    *,
    modes: Sequence[tuple[str, dict[str, str]]] = MODES,
    benchmark_driver: str = BENCHMARK_DRIVER,
    runner: _Runner | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> int:
    if runner is None:
        runner = cast(_Runner, subprocess.run)
    mode_budget_seconds = _budget_from_env(MODE_BUDGET_ENV, DEFAULT_MODE_BUDGET_SECONDS)
    total_budget_seconds = _budget_from_env(TOTAL_BUDGET_ENV, DEFAULT_TOTAL_BUDGET_SECONDS)
    failures = 0
    start = clock()
    for name, updates in modes:
        elapsed_so_far = clock() - start
        timeout_candidates: list[float] = []
        if mode_budget_seconds >= 0:
            timeout_candidates.append(mode_budget_seconds)
        if total_budget_seconds >= 0:
            timeout_candidates.append(max(0.0, total_budget_seconds - elapsed_so_far))
        timeout_seconds = min(timeout_candidates) if timeout_candidates else None
        failures |= _run_mode(
            name,
            updates,
            benchmark_driver=benchmark_driver,
            mode_budget_seconds=mode_budget_seconds,
            timeout_seconds=timeout_seconds,
            runner=runner,
            clock=clock,
        )
    elapsed = clock() - start
    print(f"\nbenchmark total elapsed={elapsed:.3f}s budget={total_budget_seconds:.3f}s")
    if total_budget_seconds >= 0 and elapsed > total_budget_seconds:
        print(
            f"benchmark total exceeded budget: {elapsed:.3f}s > {total_budget_seconds:.3f}s",
            file=sys.stderr,
        )
        failures = 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
