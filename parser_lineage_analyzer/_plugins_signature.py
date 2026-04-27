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
``source_keys`` plus — for map-style destinations — the per-pair RHS
source. The ``lineage_status`` on the signature picks the status
(default ``derived``); ``taint_hint`` adds a per-destination taint
when set; ``dest_value_kind`` is consulted as a hint to disambiguate
how the destination value should be interpreted.
"""

from __future__ import annotations

from typing import Protocol, cast

from ._analysis_helpers import _add_conditions, _location, _normalize_field_ref, _strip_ref
from ._analysis_state import AnalyzerState
from ._plugin_config_models import PluginSignature
from ._types import ConfigValue
from .ast_nodes import Plugin
from .config_parser import all_values, as_pairs
from .model import Lineage, LineageStatus, SourceRef, TaintReason


class _SignatureContext(Protocol):
    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _store_destination(
        self,
        dest: str,
        lineages: list[Lineage],
        loc: str,
        state: AnalyzerState,
        *,
        append: bool = False,
    ) -> None: ...

    def _apply_post_plugin_decorators(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None: ...


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

        Source resolution accumulates plugin-scope sources from
        ``sig.source_keys`` once. Destination resolution is then
        per-value: scalar destinations attribute to plugin-scope sources;
        map destinations (``replace => { dst => src, ... }``) attribute
        to plugin-scope sources *plus* the per-pair RHS source so each
        destination's lineage names the field it actually came from;
        list destinations (``targets => ["a", "b"]``) attribute each
        entry to plugin-scope sources.

        After all destinations land we call
        ``_apply_post_plugin_decorators`` so a ``add_tag`` /
        ``add_field`` / ``remove_tag`` / ``remove_field`` block on the
        plugin is honored — matching the built-in handlers' behavior.
        """
        context = cast(_SignatureContext, self)
        loc = _location(stmt.line, stmt.name)

        plugin_source_tokens, plugin_source_lineages = self._resolve_signature_sources(
            context, stmt, state, loc, sig.source_keys
        )

        for dest_key in sig.dest_keys:
            for value in all_values(stmt.config, dest_key):
                self._dispatch_destination_value(
                    context,
                    stmt,
                    state,
                    conditions,
                    sig,
                    loc,
                    value,
                    plugin_source_tokens,
                    plugin_source_lineages,
                )

        # Always run post-plugin decorators, even when a signature
        # produces no destinations — built-in handlers do the same so
        # ``add_tag`` etc. fire regardless of the plugin's primary work.
        context._apply_post_plugin_decorators(stmt, state, conditions)

    @staticmethod
    def _resolve_signature_sources(
        context: _SignatureContext,
        stmt: Plugin,
        state: AnalyzerState,
        loc: str,
        source_keys: list[str],
    ) -> tuple[list[str], list[Lineage]]:
        """Walk ``source_keys`` config values and resolve them to lineage.

        Source values commonly use sprintf-style references like
        ``%{message}``; ``_strip_ref`` removes the ``%{...}`` wrapper so
        ``_resolve_token`` looks up the bare token name (it does not
        retry the strip after a literal lookup miss).
        """
        tokens: list[str] = []
        lineages: list[Lineage] = []
        for src_key in source_keys:
            for value in all_values(stmt.config, src_key):
                if isinstance(value, str):
                    token = _strip_ref(value)
                    if token:
                        tokens.append(token)
                        lineages.extend(context._resolve_token(token, state, loc))
        return tokens, lineages

    def _dispatch_destination_value(
        self,
        context: _SignatureContext,
        stmt: Plugin,
        state: AnalyzerState,
        conditions: list[str],
        sig: PluginSignature,
        loc: str,
        value: ConfigValue,
        plugin_source_tokens: list[str],
        plugin_source_lineages: list[Lineage],
    ) -> None:
        """Interpret one ``dest_keys`` config value and emit lineage.

        Supported value shapes:
          * scalar string — single destination, plugin-scope sources.
          * list-of-pairs (``map``) — each pair is ``(dest, source_expr)``;
            destination's lineage attributes to plugin-scope sources
            *plus* the pair's resolved RHS so per-destination
            attribution is preserved.
          * plain list (``list``) — each string entry is a destination,
            attributed to plugin-scope sources.

        ``sig.dest_value_kind`` disambiguates the list-vs-map decision
        when a list value contains no pairs (e.g. ``["a", "b"]``):
        with ``dest_value_kind = "list"`` the entries become destinations,
        otherwise the empty-pairs list is silently a no-op (back-compat
        for callers that intended pairs but supplied none).
        """
        if isinstance(value, str):
            dest = _normalize_field_ref(value)
            if dest:
                self._emit_signature_lineage(
                    context,
                    stmt,
                    state,
                    conditions,
                    sig,
                    loc,
                    dest,
                    plugin_source_tokens,
                    plugin_source_lineages,
                )
            return
        if not isinstance(value, list):
            return

        pairs = as_pairs(value)
        if pairs:
            # Map shape: per-pair attribution.
            for k, v in pairs:
                if not isinstance(k, str):
                    continue
                dest = _normalize_field_ref(k)
                if not dest:
                    continue
                pair_tokens = list(plugin_source_tokens)
                pair_lineages = list(plugin_source_lineages)
                if isinstance(v, str):
                    pair_token = _strip_ref(v)
                    if pair_token:
                        pair_tokens.append(pair_token)
                        pair_lineages.extend(context._resolve_token(pair_token, state, loc))
                self._emit_signature_lineage(
                    context, stmt, state, conditions, sig, loc, dest, pair_tokens, pair_lineages
                )
            return

        # Plain list shape — only honored when the signature declares
        # ``dest_value_kind = "list"``. Without that hint, a non-pairs
        # list is most likely a misshapen map and we leave it alone
        # rather than coercing each entry into a destination.
        if sig.dest_value_kind == "list":
            for item in value:
                if not isinstance(item, str):
                    continue
                dest = _normalize_field_ref(item)
                if dest:
                    self._emit_signature_lineage(
                        context,
                        stmt,
                        state,
                        conditions,
                        sig,
                        loc,
                        dest,
                        plugin_source_tokens,
                        plugin_source_lineages,
                    )

    @staticmethod
    def _emit_signature_lineage(
        context: _SignatureContext,
        stmt: Plugin,
        state: AnalyzerState,
        conditions: list[str],
        sig: PluginSignature,
        loc: str,
        dest: str,
        source_tokens: list[str],
        source_lineages: list[Lineage],
    ) -> None:
        """Emit one ``signature_dispatched`` Lineage at ``dest``.

        Each call builds its own SourceRef (and optional taint) from the
        per-destination ``source_tokens``/``source_lineages`` — never
        reusing a SourceRef across destinations would cross-attribute
        the wrong sources for map-style configs.

        ``append=True`` matches the unsupported-plugin fallback path:
        prior lineage on the destination is preserved instead of
        overwritten, since a generic handler can't know whether the
        plugin's real semantics are replace-style or merge-style.
        """
        declared_status: LineageStatus = sig.lineage_status
        if conditions and declared_status == "exact":
            declared_status = "conditional"

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

        lin = Lineage(
            status=declared_status,
            sources=sources,
            expression=dest,
            conditions=[],
            parser_locations=[loc],
            taints=taints,
        )
        context._store_destination(dest, _add_conditions([lin], conditions), loc, state, append=True)
