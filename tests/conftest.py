"""Make the source tree importable when tests are run directly with pytest."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# CI-tunable wall-clock slack multiplier for performance tests. Default is
# 1.0 (no behavior change on developer machines); slow CI runners can
# export ``PERF_SLOW_FACTOR=5`` to widen every elapsed-vs-budget assert
# in ``test_performance_scaling.py`` and ``test_benchmark_smoke.py``
# without editing the test files. Tests pre-multiply their literal
# budgets by this constant at module import time, so set the variable
# before pytest starts. See ``docs/performance-budgets.md`` for guidance
# on when to bump this versus when a regression has actually landed.
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

try:
    from hypothesis import HealthCheck, settings
except ImportError:
    pass
else:
    _HYPOTHESIS_DEADLINE_MS = 2000
    _HYPOTHESIS_SUPPRESS = [HealthCheck.too_slow]
    # CI profile: the default. Cheap, runs on every PR. ~1s per property.
    settings.register_profile(
        "ci",
        max_examples=200,
        deadline=_HYPOTHESIS_DEADLINE_MS,
        suppress_health_check=_HYPOTHESIS_SUPPRESS,
    )
    # Deep profile: local exploration. ~20s per property at current generation rate.
    settings.register_profile(
        "deep",
        max_examples=20000,
        deadline=_HYPOTHESIS_DEADLINE_MS,
        suppress_health_check=_HYPOTHESIS_SUPPRESS,
    )
    # Soak profile: overnight / pre-release. ~3-5min per property.
    settings.register_profile(
        "soak",
        max_examples=200000,
        deadline=_HYPOTHESIS_DEADLINE_MS,
        suppress_health_check=_HYPOTHESIS_SUPPRESS,
    )
    settings.load_profile("ci")


EXAMPLE = r"""
filter {
  json {
    source => "message"
    array_function => "split_columns"
  }
  grok {
    match => {
      "network" => "%{IP:srcAddr}:%{INT:srcPort} -> %{IP:dstAddr}:%{INT:dstPort}"
    }
  }
  mutate {
    convert => { "dstPort" => "integer" }
  }
  mutate {
    replace => {
      "event.idm.read_only_udm.target.ip" => "%{dstAddr}"
      "event.idm.read_only_udm.network.target.port" => "%{dstPort}"
      "event.idm.read_only_udm.metadata.event_type" => "NETWORK_CONNECTION"
    }
    merge => {
      "event.idm.read_only_udm.observer.ip" => "device.ips.0"
      "event.idm.read_only_udm.observer.ip" => "device.ips.1"
      "@output" => "event"
    }
  }
}
"""
