"""Loose order-of-magnitude regression gate. Tightening the bounds is intentional
follow-up work — this exists to catch unintentional 10x slowdowns, not to police
percentile drift."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from scripts import benchmark_native_modes
from tests.test_performance_scaling import (
    _analysis_seconds,
    _hot_branch_append_parser,
    _independent_if_parser,
    _repeated_append_parser,
)

SMOKE_BUDGET_SECONDS = 10.0


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


# Catastrophic-blowup watchdog for the grok pattern resolver. The bundled
# library is loaded once per process; this test triggers a fresh load by
# clearing the module-level cache, then exercises the largest patterns
# (URI, IPV6, COMMONAPACHELOG) cold + 100 cached lookups each. The 50ms
# budget is intentionally generous (5x typical local timing on M-series)
# to absorb CI-runner noise without becoming a flaky timing assertion.
GROK_RESOLVER_BUDGET_SECONDS = 0.050


def test_grok_resolver_cold_plus_cached_within_budget(monkeypatch) -> None:
    import time

    from parser_lineage_analyzer import _grok_patterns

    # Clear the module-level cache to force a fresh library load + cold
    # expansion path. The LRU cache on `_expand_pattern_cached` is also
    # reset so cached lookups truly count as cold first, then warm.
    monkeypatch.setattr(_grok_patterns, "_BUNDLED_LIBRARY_CACHE", None)
    _grok_patterns._expand_pattern_cached.cache_clear()

    targets = ("URI", "IPV6", "COMMONAPACHELOG", "TIMESTAMP_ISO8601", "IP")
    start = time.perf_counter()
    for name in targets:
        body = _grok_patterns.expand_pattern(name)
        assert body is not None, f"bundled pattern {name} should expand cleanly"
    # 100 cached lookups per pattern — the LRU should be warm.
    for _ in range(100):
        for name in targets:
            _grok_patterns.expand_pattern(name)
    elapsed = time.perf_counter() - start

    assert elapsed < GROK_RESOLVER_BUDGET_SECONDS, (
        f"grok resolver cold-load + cached lookups exceeded "
        f"{GROK_RESOLVER_BUDGET_SECONDS * 1000:.0f}ms budget: {elapsed * 1000:.1f}ms"
    )
