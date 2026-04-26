"""Make the source tree importable when tests are run directly with pytest."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from hypothesis import HealthCheck, settings
except ImportError:
    pass
else:
    _HYPOTHESIS_COMMON = {"deadline": 2000, "suppress_health_check": [HealthCheck.too_slow]}
    # CI profile: the default. Cheap, runs on every PR. ~1s per property.
    settings.register_profile("ci", max_examples=200, **_HYPOTHESIS_COMMON)
    # Deep profile: local exploration. ~20s per property at current generation rate.
    settings.register_profile("deep", max_examples=20000, **_HYPOTHESIS_COMMON)
    # Soak profile: overnight / pre-release. ~3-5min per property.
    settings.register_profile("soak", max_examples=200000, **_HYPOTHESIS_COMMON)
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
