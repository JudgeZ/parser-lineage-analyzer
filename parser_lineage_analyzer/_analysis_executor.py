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


def _compute_collision_messages(components: tuple[type, ...]) -> list[str]:
    """Return one diagnostic message per (component, method) collision.

    Each message has the form
    ``"<method> (<owner_name> from <owner_module>, <new_name> from <new_module>)"``
    so an operator can identify both offending mixins without spelunking
    through the mixin order. The format string lives here (production
    code) so the regression test in
    ``tests/test_maximal_cleanup_contracts.py`` can pin it by invoking
    this helper rather than re-implementing the loop.

    Identity is the full ``(name, module)`` tuple — two mixins from
    different modules that happen to share a class name (e.g. both
    named ``Helpers``) still register as a collision. Comparing only
    ``__name__`` would have left this real shadowing case undetected.
    """
    seen_methods: dict[str, tuple[str, str]] = {}
    messages: list[str] = []
    for component in components:
        identity = (component.__name__, component.__module__)
        for method in _component_methods(component):
            owner = seen_methods.setdefault(method, identity)
            if owner != identity:
                owner_name, owner_module = owner
                messages.append(
                    f"{method} ({owner_name} from {owner_module}, {component.__name__} from {component.__module__})"
                )
    return messages


_collisions = _compute_collision_messages(_EXECUTOR_COMPONENTS)
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
