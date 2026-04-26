"""Generic plugin handler driven by :class:`PluginSignature` declarations.

When :class:`ReverseParser` is constructed with a
:class:`PluginSignatureRegistry`, the dispatch in
``_analysis_flow.FlowExecutorMixin._exec_plugin`` consults the registry
for any plugin name that doesn't match a built-in handler. A registered
signature routes the invocation here; the absence of one falls through
to the existing ``unsupported_plugin`` taint path (preserving pre-F3
behavior byte-for-byte).

Soundness contract: a signature describes the plugin's *shape* (which
config keys are sources, which are destinations), not its semantics. We
emit a generic ``signature_dispatched`` SourceRef on each declared
destination, attributing it to the resolved sources of the declared
``source_keys``. The ``lineage_status`` on the signature picks the
status (default ``derived``); ``taint_hint`` adds a per-destination
taint when set.
"""

from __future__ import annotations

from typing import Protocol, cast

from ._analysis_helpers import _add_conditions, _location, _normalize_field_ref
from ._analysis_state import AnalyzerState
from ._plugin_config_models import PluginSignature
from .ast_nodes import Plugin
from .config_parser import all_values, as_pairs
from .model import Lineage, LineageStatus, SourceRef


class _SignatureContext(Protocol):
    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _store_destination(self, dest: str, lineages: list[Lineage], loc: str, state: AnalyzerState) -> None: ...


class SignaturePluginMixin:
    """Generic handler for plugins routed through :class:`PluginSignature`."""

    def _exec_signature_dispatched(
        self,
        stmt: Plugin,
        state: AnalyzerState,
        conditions: list[str],
        sig: PluginSignature,
    ) -> None:
        """Build generic lineage for ``stmt`` using ``sig``'s declared shape.

        Resolves every ``source_keys`` config value to lineage, then
        writes a ``signature_dispatched`` SourceRef into every
        ``dest_keys`` value with the signature's declared
        ``lineage_status``. Sources from the resolved upstream lineage
        propagate so a downstream query attributes the destination back
        to the original raw fields.
        """
        context = cast(_SignatureContext, self)
        loc = _location(stmt.line, stmt.name)

        # Aggregate source lineages across every declared source key.
        source_tokens: list[str] = []
        source_lineages: list[Lineage] = []
        for src_key in sig.source_keys:
            for value in all_values(stmt.config, src_key):
                if isinstance(value, str):
                    token = _normalize_field_ref(value)
                    if token:
                        source_tokens.append(token)
                        source_lineages.extend(context._resolve_token(token, state, loc))

        # Resolve destinations. A destination key may be a scalar field
        # name (``target => "x"``) or a map of dest=>source pairs
        # (``replace => { "a" => "%{b}", "c" => "%{d}" }``). For maps we
        # take the *keys* as destinations and merge the value's source
        # lineage into ``source_lineages`` so the per-destination
        # attribution stays accurate.
        destinations: list[str] = []
        for dest_key in sig.dest_keys:
            for value in all_values(stmt.config, dest_key):
                if isinstance(value, str):
                    norm = _normalize_field_ref(value)
                    if norm:
                        destinations.append(norm)
                elif isinstance(value, list):
                    for k, v in as_pairs(value):
                        if isinstance(k, str):
                            norm = _normalize_field_ref(k)
                            if norm:
                                destinations.append(norm)
                        if isinstance(v, str):
                            inner = _normalize_field_ref(v)
                            if inner:
                                source_lineages.extend(context._resolve_token(inner, state, loc))

        if not destinations:
            return  # nothing to record; don't emit empty lineage

        # The signature's declared status drives the LineageStatus we
        # attach. ``conditional`` is auto-applied if there are active
        # branch conditions (preserves existing analyzer convention even
        # when the signature says ``exact``).
        declared_status: LineageStatus = sig.lineage_status
        if conditions and declared_status == "exact":
            declared_status = "conditional"

        # Build the attributing SourceRef. ``source_token`` carries a
        # comma-joined snapshot of resolved source field names so query
        # output stays human-readable; ``details`` exposes the full
        # source-ref list for downstream consumers.
        source_token_label = ",".join(source_tokens) if source_tokens else stmt.name
        sources = [
            SourceRef(
                kind="signature_dispatched",
                source_token=source_token_label,
                expression=stmt.name,
                details={
                    "plugin_name": stmt.name,
                    "semantic_class": sig.semantic_class,
                    "upstream_sources": [src.to_json() for lin in source_lineages for src in lin.sources],
                },
            )
        ]
        # If the signature opts into a taint hint, attach it once per
        # emitted Lineage (ride-along with the lineage rather than the
        # broad ``state.add_taint`` so it scopes to the destination).
        from .model import TaintReason

        taints: list[TaintReason] = []
        if sig.taint_hint != "none":
            taints.append(
                TaintReason(
                    code=f"signature_dispatched_{sig.taint_hint}",
                    message=f"signature-dispatched plugin {stmt.name!r} (semantic_class={sig.semantic_class})",
                    parser_location=loc,
                    source_token=stmt.name,
                )
            )

        for dest in destinations:
            lin = Lineage(
                status=declared_status,
                sources=sources,
                expression=dest,
                conditions=[],
                parser_locations=[loc],
                taints=taints,
            )
            context._store_destination(dest, _add_conditions([lin], conditions), loc, state)
