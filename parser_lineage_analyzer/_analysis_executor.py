"""Concrete reverse-lineage executor assembled from internal implementation modules."""

from __future__ import annotations

from ._analysis_assignment import AssignmentMixin
from ._analysis_flow import FlowExecutorMixin
from ._analysis_resolution import ResolutionMixin
from ._plugins_extractors import ExtractorPluginMixin
from ._plugins_mutate import MutatePluginMixin
from ._plugins_signature import SignaturePluginMixin
from ._plugins_transforms import TransformPluginMixin

_EXECUTOR_COMPONENTS = (
    FlowExecutorMixin,
    AssignmentMixin,
    ResolutionMixin,
    ExtractorPluginMixin,
    TransformPluginMixin,
    MutatePluginMixin,
    SignaturePluginMixin,
)


def _component_methods(component: type) -> set[str]:
    return {name for name in component.__dict__ if not name.startswith("__")}


_seen_methods: dict[str, str] = {}
_collisions: list[str] = []
for _component in _EXECUTOR_COMPONENTS:
    for _method in _component_methods(_component):
        owner = _seen_methods.setdefault(_method, _component.__name__)
        if owner != _component.__name__:
            _collisions.append(f"{_method} ({owner}, {_component.__name__})")
if _collisions:
    raise RuntimeError(f"AnalysisExecutor mixin method collision(s): {', '.join(sorted(_collisions))}")


class AnalysisExecutor(
    FlowExecutorMixin,
    AssignmentMixin,
    ResolutionMixin,
    ExtractorPluginMixin,
    TransformPluginMixin,
    MutatePluginMixin,
    SignaturePluginMixin,
):
    """Concrete execution context used by ``ReverseParser``."""
