"""CI-tunable wall-clock slack multiplier for performance tests.

This module is the canonical source for ``PERF_SLOW_FACTOR``. Tests that
need it (``test_performance_scaling.py``, ``test_benchmark_smoke.py``,
the ReDoS budget assertion in ``test_cli_and_public_model.py``) import
from here rather than from ``conftest.py`` — importing ``conftest`` as a
regular module re-runs its top-level side effects (sys.path mutation,
Hypothesis profile registration) under a different module name than the
one pytest loaded, which is brittle.

Default is ``1.0`` (no behavior change on developer machines). Slow CI
runners can export ``PERF_SLOW_FACTOR=5`` to widen every elapsed-vs-
budget assert without editing the test files. Tests pre-multiply their
literal budgets by this constant at module import time, so set the
variable before pytest starts.
"""

from __future__ import annotations

import os


def _perf_slow_factor() -> float:
    raw = os.environ.get("PERF_SLOW_FACTOR")
    if not raw:
        return 1.0
    try:
        value = float(raw)
    except ValueError:
        return 1.0
    return value if value > 0 else 1.0


PERF_SLOW_FACTOR: float = _perf_slow_factor()
