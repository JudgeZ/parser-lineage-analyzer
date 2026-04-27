"""Loose order-of-magnitude regression gate. Tightening the bounds is intentional
follow-up work — this exists to catch unintentional 10x slowdowns, not to police
percentile drift."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from scripts import benchmark_native_modes
from tests.perf_budgets import PERF_SLOW_FACTOR
from tests.test_performance_scaling import (
    _analysis_seconds,
    _hot_branch_append_parser,
    _independent_if_parser,
    _repeated_append_parser,
)

# Wall-clock budgets are pre-multiplied by ``PERF_SLOW_FACTOR`` (default
# 1.0; CI can export ``PERF_SLOW_FACTOR=N`` to widen the wall budgets
# without editing this file). See ``tests/perf_budgets.py``.
SMOKE_BUDGET_SECONDS = 10.0 * PERF_SLOW_FACTOR


@pytest.mark.parametrize(
    ("shape_factory", "size"),
    [
        pytest.param(_independent_if_parser, 2_000, id="independent_if_2k"),
        pytest.param(_hot_branch_append_parser, 500, id="hot_branch_append_500"),
        pytest.param(_repeated_append_parser, 1_000, id="repeated_append_1k"),
    ],
)
def test_analysis_completes_within_smoke_budget(shape_factory, size: int) -> None:
    elapsed, _ = _analysis_seconds(shape_factory(size))
    assert elapsed < SMOKE_BUDGET_SECONDS, (
        f"Smoke benchmark exceeded {SMOKE_BUDGET_SECONDS}s budget at size={size}: {elapsed:.2f}s"
    )


def test_native_modes_benchmark_fails_when_mode_budget_is_exceeded(monkeypatch, capsys) -> None:
    monkeypatch.setenv(benchmark_native_modes.MODE_BUDGET_ENV, "1")
    monkeypatch.setenv(benchmark_native_modes.TOTAL_BUDGET_ENV, "-1")
    clock_values = iter([0.0, 0.0, 0.0, 2.0, 2.0])

    def fake_runner(command, env, timeout):
        assert timeout == 1.0
        return SimpleNamespace(returncode=0)

    result = benchmark_native_modes.main(
        modes=(("fake-mode", {}),),
        benchmark_driver="print('fast fake benchmark')",
        runner=fake_runner,
        clock=lambda: next(clock_values),
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "fake-mode exceeded benchmark budget" in captured.err


def test_native_modes_benchmark_fails_cleanly_when_runner_times_out(monkeypatch, capsys) -> None:
    monkeypatch.setenv(benchmark_native_modes.MODE_BUDGET_ENV, "3")
    monkeypatch.setenv(benchmark_native_modes.TOTAL_BUDGET_ENV, "-1")
    clock_values = iter([0.0, 0.0, 0.0, 3.0, 3.0])

    def fake_runner(command, env, timeout):
        assert timeout == 3.0
        raise subprocess.TimeoutExpired(command, timeout)

    result = benchmark_native_modes.main(
        modes=(("fake-mode", {}),),
        benchmark_driver="print('hung fake benchmark')",
        runner=fake_runner,
        clock=lambda: next(clock_values),
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "fake-mode timed out after 3.000s" in captured.err


def test_native_modes_ratio_lines_compare_against_default_without_failing() -> None:
    lines = benchmark_native_modes._mode_ratio_lines(
        [
            benchmark_native_modes.ModeResult("default-native", 10.0, 0),
            benchmark_native_modes.ModeResult("no-ext", 12.5, 0),
            benchmark_native_modes.ModeResult("no-native-dedupe", 8.0, 0),
        ]
    )

    assert lines == [
        "\nmode elapsed ratios (baseline=default-native):",
        "  default-native           elapsed=  10.000s ratio=  1.00x",
        "  no-ext                   elapsed=  12.500s ratio=  1.25x",
        "  no-native-dedupe         elapsed=   8.000s ratio=  0.80x",
    ]


def test_native_modes_main_prints_ratio_report_when_default_mode_is_present(monkeypatch, capsys) -> None:
    monkeypatch.setenv(benchmark_native_modes.MODE_BUDGET_ENV, "-1")
    monkeypatch.setenv(benchmark_native_modes.TOTAL_BUDGET_ENV, "-1")
    clock_values = iter([0.0, 0.0, 0.0, 2.0, 2.0, 2.0, 5.0, 5.0])

    def fake_runner(command, env, timeout):
        assert timeout is None
        return SimpleNamespace(returncode=0)

    result = benchmark_native_modes.main(
        modes=(("default-native", {}), ("no-ext", {"PARSER_LINEAGE_ANALYZER_NO_EXT": "1"})),
        benchmark_driver="print('fake benchmark')",
        runner=fake_runner,
        clock=lambda: next(clock_values),
    )

    captured = capsys.readouterr()
    assert result == 0
    assert "mode elapsed ratios (baseline=default-native):" in captured.out
    assert "default-native           elapsed=   2.000s ratio=  1.00x" in captured.out
    assert "no-ext                   elapsed=   3.000s ratio=  1.50x" in captured.out


# Catastrophic-blowup watchdog for the grok pattern resolver. This file's
# stated job is catching unintentional 10x slowdowns, NOT policing
# percentile drift, so the budget is loose enough that runner noise on
# the slowest CI cells doesn't trip it. Local timing on M-series is
# sub-millisecond; the budget below is wide enough for the slowest
# macos-26 / windows-2022 runners we've observed, narrow enough to flag
# a genuine order-of-magnitude regression.
GROK_RESOLVER_BUDGET_SECONDS = 0.500 * PERF_SLOW_FACTOR


def test_grok_resolver_cold_plus_cached_within_budget(monkeypatch) -> None:
    import time

    from parser_lineage_analyzer import _grok_patterns

    # Clear the module-level cache to force a fresh library load + cold
    # expansion path. The LRU cache on `_expand_pattern_cached` is also
    # reset so the first lookup of each pattern truly is cold.
    monkeypatch.setattr(_grok_patterns, "_BUNDLED_LIBRARY_CACHE", None)
    _grok_patterns._expand_pattern_cached.cache_clear()

    targets = ("URI", "IPV6", "COMMONAPACHELOG", "TIMESTAMP_ISO8601", "IP")

    # Cold pass — exercises bundle load + initial expansion.
    cold_start = time.perf_counter()
    for name in targets:
        body = _grok_patterns.expand_pattern(name)
        assert body is not None, f"bundled pattern {name} should expand cleanly"
    cold_elapsed = time.perf_counter() - cold_start

    # Warm pass — 100 cached lookups per pattern. Should be dramatically
    # faster than cold; if the cache regresses (e.g. someone adds a
    # mutating operation that invalidates `lru_cache`), this catches it.
    warm_start = time.perf_counter()
    for _ in range(100):
        for name in targets:
            _grok_patterns.expand_pattern(name)
    warm_elapsed = time.perf_counter() - warm_start

    total_elapsed = cold_elapsed + warm_elapsed
    assert total_elapsed < GROK_RESOLVER_BUDGET_SECONDS, (
        f"grok resolver cold-load + cached lookups exceeded "
        f"{GROK_RESOLVER_BUDGET_SECONDS * 1000:.0f}ms budget: "
        f"cold={cold_elapsed * 1000:.1f}ms, warm={warm_elapsed * 1000:.1f}ms"
    )

    # Cache effectiveness check: 500 warm lookups should be much faster
    # than 5 cold ones. The 3x ratio is conservative enough to survive
    # noisy runners but still catch a regression that breaks LRU sharing
    # (which would force warm lookups to recompute end-to-end).
    if cold_elapsed > 0.0001:  # avoid div-by-zero on absurdly fast machines
        assert warm_elapsed < cold_elapsed * 3, (
            f"warm lookups ({warm_elapsed * 1000:.2f}ms for 500 calls) should be "
            f"meaningfully faster than cold ({cold_elapsed * 1000:.2f}ms for 5 calls); "
            f"LRU cache may be regressing"
        )
