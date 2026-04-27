"""Mutate plugin handlers for reverse-lineage analysis."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol, cast

from ._analysis_condition_facts import conditions_are_compatible
from ._analysis_dedupe import _taint_key
from ._analysis_details import ERROR_FLAG_NOTE, OBJECT_LITERAL_MERGED_NOTE, OBJECT_LITERAL_NOTE, removed_field_note
from ._analysis_diagnostics import (
    duplicate_mutate_map_key_warning,
    dynamic_field_removal_warning,
    dynamic_output_anchor_warning,
    malformed_gsub_warning,
    noop_remove_field_warning,
    static_limit_warning,
    template_fanout_warning,
    unsupported_mutate_operation,
)
from ._analysis_helpers import (
    _TOKEN_REF_RE,
    _add_conditions,
    _dedupe_sources,
    _dedupe_strings,
    _dedupe_taints,
    _location,
    _normalize_field_ref,
    _stable_value_repr,
    _strip_ref,
)
from ._analysis_state import AnalyzerState
from ._types import ConfigPair, ConfigValue
from .ast_nodes import Plugin
from .config_parser import as_pairs, first_value
from .model import Lineage, OutputAnchor, SourceRef

_GSUB_BACKREF_RE = re.compile(r"\\[1-9]")
MAX_GSUB_TRANSFORM_PRODUCTS = 50_000
MAX_SELF_REFERENTIAL_TEMPLATE_LINEAGES = 16
MAX_SELF_REFERENTIAL_TEMPLATE_METADATA = 128
MAX_SELF_REFERENTIAL_TEMPLATE_TAINTS = 128
_MutateHandler = Callable[[Plugin, str, ConfigValue, AnalyzerState, list[str]], None]


def _infer_assignment_value_type(expr: ConfigValue) -> str:
    """R1.1: classify a mutate.replace/add_field/update value's runtime type.

    - Literal string with no `%{...}` template → "string"
    - List literal (no pairs) → "array"
    - Anything templated (`%{...}`) or a bare token → "unknown" (we'd need
      to follow the source lineage to know its type, which is what
      branch-merge type union does separately).
    """
    if isinstance(expr, list):
        if as_pairs(expr):
            return "object"
        return "array"
    if isinstance(expr, str) and "%{" not in expr:
        return "string"
    return "unknown"


def _append_unique_limited(
    out: list[str],
    seen: set[str],
    values: tuple[str, ...],
    *,
    limit: int,
    overflow_note: str,
    notes: list[str],
) -> None:
    if len(out) >= limit:
        return
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            notes.append(overflow_note)
            return


class _MutateContext(Protocol):
    def _store_destination(
        self, dest: str, lineages: list[Lineage], loc: str, state: AnalyzerState, *, append: bool = False
    ) -> None: ...

    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _assign_object_literal_subfields(
        self, dest: str, pairs: list[ConfigPair], state: AnalyzerState, conditions: list[str], line: int, mode: str
    ) -> None: ...

    def _lineages_from_config_value(
        self, value: ConfigValue, state: AnalyzerState, loc: str, conditions: list[str], bare_is_token: bool = False
    ) -> list[Lineage]: ...

    def _project_object_merge(
        self, dest: str, src_token: str, loc: str, state: AnalyzerState, conditions: list[str]
    ) -> None: ...


class MutatePluginMixin:
    _MUTATE_OP_HANDLERS = {
        "replace": "_exec_assignment_mutate_op",
        "add_field": "_exec_assignment_mutate_op",
        "update": "_exec_assignment_mutate_op",
        "rename": "_exec_rename_mutate_op",
        "copy": "_exec_copy_mutate_op",
        "merge": "_exec_merge_mutate_op",
        "convert": "_exec_convert_mutate_op",
        "lowercase": "_exec_case_mutate_op",
        "uppercase": "_exec_case_mutate_op",
        "gsub": "_exec_gsub_mutate_op",
        "split": "_exec_split_mutate_op",
        "join": "_exec_join_mutate_op",
        "remove_field": "_exec_remove_field_mutate_op",
        "add_tag": "_exec_tag_mutate_op",
        "remove_tag": "_exec_tag_mutate_op",
        "on_error": "_exec_on_error_mutate_op",
    }

    # Mutate operations whose value is a destination-keyed map (`replace`,
    # `merge`, etc.) — duplicate keys silently produce a `repeated` lineage,
    # which is rarely intentional. Per W1, surface a duplicate-config-key
    # warning consistent with the extractor handlers in _plugins_extractors.py.
    _MUTATE_MAP_OPS = frozenset(
        {"replace", "add_field", "update", "rename", "copy", "merge", "convert", "split", "join"}
    )

    # Logstash executes mutate operations in a fixed canonical order regardless
    # of the order they appear in the config. The analyzer iterates source
    # order (which is what most parser authors actually want), but flags drift
    # so users notice when the two would produce different results.
    # Reference: Logstash's hardcoded order in mutate.rb.
    #
    # T4.2 design decision: this canonical order applies PER MUTATE BLOCK, not
    # per-pipeline. Logstash interleaves canonical-ordered mutate blocks with
    # other plugins in source order — adjacent ``mutate{}`` blocks each run
    # their own canonical-ordered operations and are NOT merged for ordering
    # purposes. The cross-block alternative was investigated and rejected
    # because no real fixture demonstrated the need; revisit only if a
    # corpus fixture surfaces a per-pipeline-ordering bug.
    # C6: ``coerce`` and ``strip`` are not in ``_MUTATE_OP_HANDLERS`` (the
    # analyzer doesn't implement them yet). Listing them here made
    # ``_warn_mutate_ordering_drift`` skip drift checks whenever a parser
    # mixed ``coerce``/``strip`` with supported ops, and the
    # ``--mutate-canonical-order`` flag would sort them into a canonical
    # position only to immediately emit ``unsupported_mutate_operation``.
    # Drop them from the canonical tuple until handlers exist; ordering for
    # unimplemented operations is meaningless.
    _MUTATE_CANONICAL_ORDER = (
        "rename",
        "update",
        "replace",
        "convert",
        "gsub",
        "uppercase",
        "lowercase",
        "remove_field",
        "split",
        "join",
        "merge",
        "add_field",
        "add_tag",
        "remove_tag",
    )

    def _exec_mutate(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        # Preserve ordering of mutate operations as they appear in the config.
        # Note: Logstash uses a fixed canonical order; see _warn_mutate_ordering_drift.
        self._warn_mutate_ordering_drift(stmt, state)
        # Phase 4A: opt-in canonical-order execution. When the flag is on,
        # sort the config tuple by Logstash's canonical order before iterating.
        # Items not in the canonical list (unknown ops) sort to the end in
        # their original relative position.
        if getattr(state, "mutate_canonical_order", False):
            canonical_index = {op: i for i, op in enumerate(self._MUTATE_CANONICAL_ORDER)}
            ops_iter = sorted(
                stmt.config,
                key=lambda pair: canonical_index.get(str(pair[0]), len(canonical_index)),
            )
        else:
            ops_iter = stmt.config
        for op, value in ops_iter:
            op_s = str(op)
            handler_name = self._MUTATE_OP_HANDLERS.get(op_s)
            if handler_name is None:
                warning = unsupported_mutate_operation(stmt.line, op)
                state.add_unsupported(
                    warning,
                    code="unsupported_mutate_operation",
                    parser_location=_location(stmt.line, "mutate"),
                    source_token=str(op),
                )
                state.add_taint("unsupported_mutate_operation", warning, _location(stmt.line, "mutate"), str(op))
                continue
            if op_s in self._MUTATE_MAP_OPS:
                self._warn_duplicate_mutate_keys(stmt, op_s, value, state)
            handler = cast(_MutateHandler, getattr(self, handler_name))
            handler(stmt, op_s, value, state, conditions)

    def _warn_mutate_ordering_drift(self, stmt: Plugin, state: AnalyzerState) -> None:
        """Emit `mutate_ordering_drift` if source order differs from Logstash canonical.

        Many parsers don't care because they only use one mutate operation per
        block. But when a single block mixes ops whose order matters (e.g.
        `replace` + `rename` of the same field), Logstash's canonical order
        produces a different end state than the analyzer's source-order
        evaluation. Flag the drift so the user knows.
        """
        ops = [str(op) for op, _value in stmt.config if str(op) in self._MUTATE_OP_HANDLERS]
        if len(ops) < 2:
            return
        canonical_index = {op: i for i, op in enumerate(self._MUTATE_CANONICAL_ORDER)}
        canonical = sorted(ops, key=lambda op: canonical_index.get(op, len(canonical_index)))
        if ops == canonical:
            return
        loc = _location(stmt.line, "mutate")
        warning = (
            f"{loc}: mutate operations appear in source order {ops!r}; Logstash would "
            f"execute them as {canonical!r}. The analyzer follows source order — when ordering "
            f"matters, reorder your config to match the canonical sequence to avoid runtime drift"
        )
        state.add_warning(
            warning,
            code="mutate_ordering_drift",
            message=warning,
            parser_location=loc,
        )

    def _warn_duplicate_mutate_keys(self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState) -> None:
        pairs = as_pairs(value)
        if not pairs:
            return
        seen_counts: dict[str, int] = {}
        for key, _val in pairs:
            seen_counts[key] = seen_counts.get(key, 0) + 1
        for key, count in seen_counts.items():
            if count > 1:
                plugin_label = f"mutate.{op_l}"
                warning = duplicate_mutate_map_key_warning(stmt.line, plugin_label, key, count)
                state.add_warning(
                    warning,
                    code="duplicate_mutate_map_key",
                    message=warning,
                    parser_location=_location(stmt.line, plugin_label),
                    source_token=key,
                )

    def _exec_assignment_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        for dest, expr in as_pairs(value):
            dest_s = _normalize_field_ref(str(dest))
            loc = _location(stmt.line, f"mutate.{op_l}", f"{dest_s} <= {expr}")
            if op_l == "update" and dest_s not in state.tokens and not state.descendant_tokens(dest_s):
                continue
            expr_pairs = as_pairs(expr)
            if expr_pairs:
                # Map literal — value is an object/sub-field tree.
                root_lin = Lineage(
                    status="derived",
                    sources=[SourceRef(kind="object_literal", expression=_stable_value_repr(expr))],
                    expression=_stable_value_repr(expr),
                    conditions=list(conditions),
                    parser_locations=[loc],
                    notes=[OBJECT_LITERAL_NOTE],
                    value_type="object",
                )
                root_lins = [root_lin]
                self._store_assignment_result(op_l, dest_s, root_lins, loc, state)
                context._assign_object_literal_subfields(dest_s, expr_pairs, state, conditions, stmt.line, op_l)
                continue
            lins = self._summarized_self_referential_template(dest_s, expr, state, loc, conditions)
            if lins is None:
                lins = context._lineages_from_config_value(expr, state, loc, conditions, bare_is_token=False)
            # R1.1: tag value_type when the expression is a literal of a
            # determinable shape. Templated expressions (`%{...}`) leave the
            # type as "unknown" — the analyzer can't conclude the runtime
            # type without evaluating the template.
            inferred_type = _infer_assignment_value_type(expr)
            if inferred_type != "unknown":
                lins = [lin.with_value_type(inferred_type) for lin in lins]
            self._store_assignment_result(op_l, dest_s, lins, loc, state)

    def _store_assignment_result(
        self, op_l: str, dest: str, lineages: list[Lineage], loc: str, state: AnalyzerState
    ) -> None:
        cast(_MutateContext, self)._store_destination(dest, lineages, loc, state, append=op_l == "add_field")
        # PR-C: ``replace`` and ``update`` overwrite the destination's value, so
        # any implicit grok-derived regex constraint on it no longer applies.
        # ``add_field`` only appends a new alternative; the original token's
        # value (and constraint) may still hold, so do not invalidate.
        if op_l in {"replace", "update"}:
            state.invalidate_implicit_path_conditions_for_token(dest)

    def _summarized_self_referential_template(
        self, dest: str, expr: ConfigValue, state: AnalyzerState, loc: str, conditions: list[str]
    ) -> list[Lineage] | None:
        if dest.startswith("event.idm."):
            return None
        expr_s = str(expr)
        refs = {_normalize_field_ref(ref.strip()) for ref in _TOKEN_REF_RE.findall(expr_s)}
        if dest not in refs:
            return None
        prior_lineages = state.tokens.get(dest, [])
        if len(prior_lineages) < MAX_SELF_REFERENTIAL_TEMPLATE_LINEAGES:
            return None
        warning = template_fanout_warning(loc, len(prior_lineages), MAX_SELF_REFERENTIAL_TEMPLATE_LINEAGES)
        state.add_warning(
            warning,
            code="template_fanout",
            message=f"Self-referential template has {len(prior_lineages)} prior lineage alternatives",
            parser_location=loc,
            source_token=expr_s,
        )
        taint = state.add_taint(
            "template_fanout",
            f"Self-referential template for {dest!r} has {len(prior_lineages)} prior lineage alternatives",
            loc,
            expr_s,
        )
        summary_note = "Self-referential template lineage alternatives were summarized after fanout threshold."
        upstream_conditions: list[str] = []
        upstream_locations: list[str] = []
        upstream_transforms: list[str] = []
        upstream_notes: list[str] = []
        upstream_condition_seen: set[str] = set()
        upstream_location_seen: set[str] = set()
        upstream_transform_seen: set[str] = set()
        upstream_note_seen: set[str] = set()
        upstream_taints = [taint]
        upstream_taint_keys = {_taint_key(taint)}
        for lin in prior_lineages:
            _append_unique_limited(
                upstream_conditions,
                upstream_condition_seen,
                tuple(lin.conditions),
                limit=MAX_SELF_REFERENTIAL_TEMPLATE_METADATA,
                overflow_note=(
                    f"{MAX_SELF_REFERENTIAL_TEMPLATE_METADATA}+ upstream conditions summarized after fanout threshold."
                ),
                notes=upstream_notes,
            )
            _append_unique_limited(
                upstream_locations,
                upstream_location_seen,
                tuple(lin.parser_locations),
                limit=MAX_SELF_REFERENTIAL_TEMPLATE_METADATA,
                overflow_note=(
                    f"{MAX_SELF_REFERENTIAL_TEMPLATE_METADATA}+ upstream parser locations "
                    "summarized after fanout threshold."
                ),
                notes=upstream_notes,
            )
            _append_unique_limited(
                upstream_transforms,
                upstream_transform_seen,
                tuple(lin.transformations),
                limit=MAX_SELF_REFERENTIAL_TEMPLATE_METADATA,
                overflow_note=(
                    f"{MAX_SELF_REFERENTIAL_TEMPLATE_METADATA}+ upstream transformations "
                    "summarized after fanout threshold."
                ),
                notes=upstream_notes,
            )
            _append_unique_limited(
                upstream_notes,
                upstream_note_seen,
                tuple(lin.notes),
                limit=MAX_SELF_REFERENTIAL_TEMPLATE_METADATA,
                overflow_note=(
                    f"{MAX_SELF_REFERENTIAL_TEMPLATE_METADATA}+ upstream notes summarized after fanout threshold."
                ),
                notes=upstream_notes,
            )
            if len(upstream_taints) < MAX_SELF_REFERENTIAL_TEMPLATE_TAINTS:
                for upstream_taint in lin.taints:
                    key = _taint_key(upstream_taint)
                    if key in upstream_taint_keys:
                        continue
                    upstream_taint_keys.add(key)
                    upstream_taints.append(upstream_taint)
                    if len(upstream_taints) >= MAX_SELF_REFERENTIAL_TEMPLATE_TAINTS:
                        upstream_notes.append(
                            f"{MAX_SELF_REFERENTIAL_TEMPLATE_TAINTS}+ upstream taints "
                            "summarized after fanout threshold."
                        )
                        break
        summary_conditions = _dedupe_strings(upstream_conditions + list(conditions))
        if not conditions_are_compatible(summary_conditions):
            summary_conditions = _dedupe_strings(conditions)
            upstream_notes.append(
                f"{len(_dedupe_strings(upstream_conditions))} upstream branch conditions "
                "summarized after fanout threshold."
            )
        return [
            Lineage(
                status="dynamic",
                sources=_dedupe_sources(src for lin in prior_lineages for src in lin.sources),
                expression=expr_s,
                transformations=_dedupe_strings(upstream_transforms + ["template_interpolation"]),
                conditions=summary_conditions,
                parser_locations=_dedupe_strings(upstream_locations + [loc]),
                notes=_dedupe_strings(upstream_notes + [summary_note]),
                taints=_dedupe_taints(upstream_taints),
            )
        ]

    def _exec_rename_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        # SecOps docs: rename => { "originalToken" => "newToken" }
        for src, dest in as_pairs(value):
            loc = _location(stmt.line, "mutate.rename", f"{src} -> {dest}")
            dest_s = _normalize_field_ref(str(dest))
            src_s = _normalize_field_ref(str(src))
            descendants = []
            for descendant in state.descendant_tokens(src_s):
                if not descendant.startswith(src_s + "."):
                    continue
                new_token = dest_s + descendant[len(src_s) :]
                child_loc = _location(stmt.line, "mutate.rename", f"{descendant} -> {new_token}")
                child_lins = [
                    lin.with_transform("rename", child_loc)
                    for lin in context._resolve_token(descendant, state, child_loc)
                ]
                descendants.append((descendant, new_token, child_loc, child_lins))
            lins = [lin.with_transform("rename", loc) for lin in context._resolve_token(str(src), state, loc)]
            context._store_destination(dest_s, _add_conditions(lins, conditions), loc, state)
            # PR-C: a token rename carries its implicit grok constraint
            # to the new name. Without this, ``rename src_ip => client_ip``
            # would orphan the ``[src_ip] =~ /<IP>/`` constraint and lose
            # contradiction-detection precision on the renamed field.
            # Descendant tokens (``src_ip.region`` → ``client_ip.region``)
            # follow the same path via the descendant loop above.
            state.rename_implicit_path_conditions(src_s, dest_s)
            for descendant, new_token, _child_loc, _child_lins in descendants:
                state.rename_implicit_path_conditions(descendant, new_token)
            # Project descendants onto the new namespace before deleting the
            # source. `rename: user => target.user` must move not just `user`
            # but also `user.name` -> `target.user.name`, mirroring the way
            # `_exec_copy_mutate_op` handles descendants. Descendant lineages are
            # captured before writing the destination so a destination nested
            # under the source is neither re-projected from the new root nor
            # cleared before its original lineage can be copied.
            for _descendant, new_token, child_loc, child_lins in descendants:
                context._store_destination(new_token, _add_conditions(child_lins, conditions), child_loc, state)
            affected = ([src_s] if src_s in state.tokens else []) + [name for name, *_ in descendants]
            for existing in affected:
                state.tokens.pop(existing, None)

    def _exec_copy_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        # Logstash docs: copy => { "sourceToken" => "destinationToken" }
        for src, dest in as_pairs(value):
            src_s = _normalize_field_ref(_strip_ref(str(src)))
            dest_s = _normalize_field_ref(str(dest))
            loc = _location(stmt.line, "mutate.copy", f"{src_s} -> {dest_s}")
            descendants = []
            for descendant in state.descendant_tokens(src_s):
                if not descendant.startswith(src_s + "."):
                    continue
                new_token = dest_s + descendant[len(src_s) :]
                child_loc = _location(stmt.line, "mutate.copy", f"{descendant} -> {new_token}")
                child_lins = [
                    lin.with_transform("copy", child_loc)
                    for lin in context._resolve_token(descendant, state, child_loc)
                ]
                descendants.append((new_token, child_loc, child_lins))
            lins = [lin.with_transform("copy", loc) for lin in context._resolve_token(src_s, state, loc)]
            context._store_destination(dest_s, _add_conditions(lins, conditions), loc, state)
            # Project descendants: `copy: user => target.user` should also make
            # `target.user.name` reachable when `user.name` exists. Without
            # this, queries against the descendant fields under the new namespace
            # return unresolved. Snapshot descendant lineages before writing the
            # destination so a nested destination is not projected into itself or
            # cleared before its original lineage can be copied.
            for new_token, child_loc, child_lins in descendants:
                context._store_destination(new_token, _add_conditions(child_lins, conditions), child_loc, state)

    def _exec_merge_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        for dest, src in as_pairs(value):
            dest_s = _normalize_field_ref(str(dest))
            loc = _location(stmt.line, "mutate.merge", f"{dest_s} <= {src}")
            if dest_s == "@output":
                self._record_output_anchor(src, state, conditions, loc)
                continue

            src_pairs = as_pairs(src)
            src_tokens = (
                [_strip_ref(str(item)) for item in src]
                if isinstance(src, list) and not src_pairs
                else [_strip_ref(str(src))]
            )
            src_token = "" if isinstance(src, list) else src_tokens[0]
            if dest_s in src_tokens:
                warning = static_limit_warning(loc, "self-referential merge")
                state.add_warning(
                    warning, code="self_referential_merge", message=warning, parser_location=loc, source_token=dest_s
                )
                state.add_taint("self_referential_merge", "Self-referential merge is symbolic", loc, dest_s)
            if src_pairs:
                root_lin = Lineage(
                    status="derived",
                    sources=[SourceRef(kind="object_literal", expression=_stable_value_repr(src))],
                    expression=_stable_value_repr(src),
                    conditions=list(conditions),
                    parser_locations=[loc],
                    notes=[OBJECT_LITERAL_MERGED_NOTE],
                )
                lins = [root_lin]
                context._assign_object_literal_subfields(dest_s, src_pairs, state, conditions, stmt.line, "merge")
            else:
                lins = context._lineages_from_config_value(src, state, loc, conditions, bare_is_token=True)
            merged_lins: list[Lineage] = []
            for lin in lins:
                merged = lin
                if merged.status not in {"conditional", "unresolved"} and dest_s in state.tokens:
                    merged = merged.with_status("repeated")
                # R1.1: merge produces array-valued destinations (Logstash
                # appends the source(s) to the destination's array). Object
                # literals stay "object" — they're a structured replacement.
                if merged.value_type == "unknown" and not src_pairs:
                    merged = merged.with_value_type("array")
                merged_lins.append(merged.with_transformations(["merge"]))
            lins = merged_lins
            context._store_destination(dest_s, lins, loc, state, append=True)
            if not isinstance(src, list) and "%{" not in str(src) and src_token:
                context._project_object_merge(dest_s, src_token, loc, state, conditions)

    def _record_output_anchor(self, src: ConfigValue, state: AnalyzerState, conditions: list[str], loc: str) -> None:
        anchor_values = src if isinstance(src, list) and not as_pairs(src) else [src]
        for anchor_value in anchor_values:
            raw_anchor = str(anchor_value)
            if "%{" in raw_anchor:
                warning = dynamic_output_anchor_warning(loc, raw_anchor)
                state.add_warning(
                    warning, code="dynamic_output_anchor", message=warning, parser_location=loc, source_token=raw_anchor
                )
                state.add_taint(
                    "dynamic_output_anchor", f"Output anchor {raw_anchor!r} is runtime-dependent", loc, raw_anchor
                )
                anchor = raw_anchor
            else:
                anchor = _strip_ref(raw_anchor)
            if not anchor or anchor in {"[]", "{}"}:
                continue
            state.add_output_anchor(OutputAnchor(anchor=anchor, conditions=list(conditions), parser_locations=[loc]))

    def _exec_convert_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        for token, typ in as_pairs(value):
            loc = _location(stmt.line, "mutate.convert", f"{token} -> {typ}")
            # R1.1: convert produces a scalar in the target type. The
            # analyzer doesn't model integer/float as distinct from string at
            # the value_type level (we only track shape categories), so all
            # convert targets end up as "string" — the value is still a
            # single scalar even after the type coercion.
            lins = [
                lin.with_transform(f"convert({typ})", loc).with_value_type("string")
                for lin in context._resolve_token(str(token), state, loc)
            ]
            normalized = _normalize_field_ref(str(token))
            context._store_destination(normalized, _add_conditions(lins, conditions), loc, state)
            # PR-C: type-converted tokens no longer satisfy the
            # original captured-string regex (e.g. an IP captured by
            # grok then ``convert => "integer"`` is no longer a string
            # in IP shape). Drop the implicit constraint so downstream
            # contradiction reasoning falls back to UNKNOWN-as-compatible.
            state.invalidate_implicit_path_conditions_for_token(normalized)

    def _exec_case_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        tokens = value if isinstance(value, list) else [value]
        for token in tokens:
            loc = _location(stmt.line, f"mutate.{op_l}", str(token))
            lins = [lin.with_transform(op_l, loc) for lin in context._resolve_token(str(token), state, loc)]
            normalized = _normalize_field_ref(str(token))
            context._store_destination(normalized, _add_conditions(lins, conditions), loc, state)
            # PR-C: lowercase/uppercase/strip/merge can change which characters
            # are present in the value, so a prior grok-derived regex (e.g.
            # ``[A-Z]+`` after lowercase) may no longer match. Invalidate.
            state.invalidate_implicit_path_conditions_for_token(normalized)

    def _exec_gsub_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        context = cast(_MutateContext, self)
        arr = value if isinstance(value, list) else []
        if len(arr) % 3 != 0:
            warning = malformed_gsub_warning(stmt.line, len(arr))
            state.add_warning(
                warning, code="malformed_gsub", message=warning, parser_location=_location(stmt.line, "mutate.gsub")
            )
            state.add_taint("malformed_gsub", warning, _location(stmt.line, "mutate.gsub"))
        triples: list[tuple[ConfigValue, ConfigValue, ConfigValue, str]] = []
        for i in range(0, len(arr), 3):
            if i + 2 >= len(arr):
                continue
            token = cast(ConfigValue, arr[i])
            regex = cast(ConfigValue, arr[i + 1])
            repl = cast(ConfigValue, arr[i + 2])
            loc = _location(stmt.line, "mutate.gsub", f"{token} /{regex}/ -> {repl}")
            triples.append((token, regex, repl, loc))
        triples_by_token: dict[str, list[tuple[ConfigValue, ConfigValue, ConfigValue, str]]] = {}
        for token, regex, repl, loc in triples:
            triples_by_token.setdefault(str(token), []).append((token, regex, repl, loc))
        summarized_tokens: set[str] = set()
        for token, regex, repl, loc in triples:
            token_s = str(token)
            if token_s in summarized_tokens:
                continue
            token_triples = triples_by_token[token_s]
            if len(token_triples) > 1:
                current_lineages = context._resolve_token(token_s, state, loc)
                product_count = len(current_lineages) * len(token_triples)
                if product_count > MAX_GSUB_TRANSFORM_PRODUCTS:
                    for grouped_token, _grouped_regex, grouped_repl, grouped_loc in token_triples:
                        self._record_gsub_backreference_warning(grouped_token, grouped_repl, grouped_loc, state)
                    warning = static_limit_warning(
                        loc, f"gsub transform fanout {product_count}>{MAX_GSUB_TRANSFORM_PRODUCTS}"
                    )
                    state.add_warning(
                        warning,
                        code="gsub_transform_fanout",
                        message=warning,
                        parser_location=loc,
                        source_token=token_s,
                    )
                    state.add_taint(
                        "gsub_transform_fanout",
                        f"gsub for {token_s!r} has {product_count} transform products",
                        loc,
                        token_s,
                    )
                    transform = f"gsub({len(token_triples)} replacements summarized)"
                    lins = [lin.with_transform(transform, loc) for lin in current_lineages]
                    normalized = _normalize_field_ref(token_s)
                    context._store_destination(normalized, _add_conditions(lins, conditions), loc, state)
                    # PR-C: gsub regex substitution mutates the value, so any
                    # prior grok-derived implicit constraint no longer holds.
                    state.invalidate_implicit_path_conditions_for_token(normalized)
                    summarized_tokens.add(token_s)
                    continue
            self._record_gsub_backreference_warning(token, repl, loc, state)
            lins = [
                lin.with_transform(f"gsub(pattern={regex}, replacement={repl})", loc)
                for lin in context._resolve_token(token_s, state, loc)
            ]
            normalized = _normalize_field_ref(token_s)
            context._store_destination(normalized, _add_conditions(lins, conditions), loc, state)
            # PR-C: see comment above — invalidate post-substitution.
            state.invalidate_implicit_path_conditions_for_token(normalized)

    def _record_gsub_backreference_warning(
        self, token: ConfigValue, repl: ConfigValue, loc: str, state: AnalyzerState
    ) -> None:
        if not isinstance(repl, str) or not _GSUB_BACKREF_RE.search(repl):
            return
        warning = static_limit_warning(loc, "gsub replacement backreferences")
        state.add_warning(
            warning, code="gsub_backreference", message=warning, parser_location=loc, source_token=str(token)
        )
        state.add_taint("gsub_backreference", "gsub replacement backreferences are symbolic", loc, str(token))

    def _exec_split_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        # Logstash mutate.split syntax: `split => { field => separator }`.
        # Each pair specifies a field whose string value should be split into
        # an array, in place. Earlier shape (source/target/separator config keys)
        # was not Logstash-canonical and matched no real parser.
        context = cast(_MutateContext, self)
        for field, sep in as_pairs(value):
            field_s = _normalize_field_ref(str(field))
            loc = _location(stmt.line, "mutate.split", f"{field_s} (sep={sep!r})")
            # Phase 4C: split promotes the field's value_type to "array".
            lins = [
                lin.with_transform(f"split(separator={sep!r})", loc).with_value_type("array")
                for lin in context._resolve_token(field_s, state, loc)
            ]
            context._store_destination(field_s, _add_conditions(lins, conditions), loc, state)
            # PR-C: split changes the field's shape (string -> array); the
            # prior string-regex implicit constraint no longer applies.
            state.invalidate_implicit_path_conditions_for_token(field_s)

    def _exec_join_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        # Logstash mutate.join syntax: `join => { field => separator }`.
        # Joins an array-valued field into a single string in place. Mirrors
        # the structure of `_exec_split_mutate_op` above.
        context = cast(_MutateContext, self)
        for field, sep in as_pairs(value):
            field_s = _normalize_field_ref(str(field))
            loc = _location(stmt.line, "mutate.join", f"{field_s} (sep={sep!r})")
            # Phase 4C: join promotes the field's value_type back to "string".
            lins = [
                lin.with_transform(f"join(separator={sep!r})", loc).with_value_type("string")
                for lin in context._resolve_token(field_s, state, loc)
            ]
            context._store_destination(field_s, _add_conditions(lins, conditions), loc, state)
            # PR-C: join changes the field's shape (array -> string); the
            # prior implicit constraint (typically captured pre-array) no
            # longer reflects the post-join value.
            state.invalidate_implicit_path_conditions_for_token(field_s)

    def _exec_remove_field_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        tokens = value if isinstance(value, list) else [value]
        for token in tokens:
            token_s = str(token)
            loc = _location(stmt.line, "mutate.remove_field", token_s)
            if "%{" in token_s:
                warning = dynamic_field_removal_warning(loc)
                state.add_warning(
                    warning, code="dynamic_field_removal", message=warning, parser_location=loc, source_token=token_s
                )
                state.add_taint(
                    "dynamic_field_removal", f"remove_field target {token_s!r} is runtime-dependent", loc, token_s
                )
                continue
            normalized = _normalize_field_ref(token_s)
            descendants = state.descendant_tokens(normalized)
            affected = ([normalized] if normalized in state.tokens else []) + descendants
            if not affected:
                # C2: there is no prior token at `normalized` and no descendants
                # to cascade to. Inserting a `removed` tombstone here would
                # surface a phantom UDM field in `list_udm_fields()` and
                # `analysis_summary()['udm_fields']` for a name the parser
                # never wrote. Record a structured diagnostic so the no-op
                # stays visible to consumers, but do NOT mutate `state.tokens`.
                noop_warning = noop_remove_field_warning(loc, normalized)
                state.add_warning(
                    noop_warning,
                    code="noop_remove_field",
                    message=noop_warning,
                    parser_location=loc,
                    source_token=token_s,
                )
                continue
            for existing in affected:
                prior_lineages = state.tokens.get(existing, [])
                if prior_lineages:
                    removed_lineages = [
                        self._removed_lineage(
                            existing, token_s, loc, _dedupe_strings(conditions + list(lin.conditions))
                        )
                        for lin in prior_lineages
                    ]
                    if removed_lineages != prior_lineages:
                        state.tokens[existing] = removed_lineages
                else:
                    state.tokens[existing] = [self._removed_lineage(existing, token_s, loc, conditions)]
                # PR-C: a removed field's value no longer exists, so any
                # implicit grok-derived constraint over it is moot. Leaving
                # the constraint in place would let the algebra spuriously
                # flag downstream ``!~`` predicates as contradictory even
                # though the field has no value to match against.
                state.invalidate_implicit_path_conditions_for_token(existing)

    def _removed_lineage(self, removed_token: str, original_token: str, loc: str, conditions: list[str]) -> Lineage:
        return Lineage(
            status="removed",
            sources=[],
            expression=removed_token,
            conditions=list(conditions),
            parser_locations=[loc],
            notes=[removed_field_note(original_token)],
        )

    def _exec_tag_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        # Logstash mutate.add_tag / mutate.remove_tag operate on the special
        # `tags` array-valued field. The analyzer doesn't model individual tag
        # set membership, but it does record that `tags` was mutated so
        # downstream conditional checks like `if "_jsonparsefailure" in [tags]`
        # have a real lineage to point at.
        context = cast(_MutateContext, self)
        tags = value if isinstance(value, list) and not as_pairs(value) else [value]
        rendered = ", ".join(repr(str(t)) for t in tags)
        loc = _location(stmt.line, f"mutate.{op_l}", rendered)
        prior = context._resolve_token("tags", state, loc)
        sources: list[SourceRef] = []
        literal_tags: list[str] = []
        has_dynamic_tag = False
        for tag in tags:
            tag_s = str(tag)
            if "%{" in tag_s:
                has_dynamic_tag = True
            else:
                literal_tags.append(tag_s)
            sources.append(
                SourceRef(
                    kind="constant" if "%{" not in tag_s else "template",
                    expression=tag_s,
                )
            )
        # T2: maintain the structured TagState. add_tag widens both definitely
        # and possibly; remove_tag narrows definitely (and possibly when the
        # remove is purely literal). Conditionally-guarded tag mutations only
        # update the per-branch state — branch merge intersects/unions across
        # surviving branches, so a branch-only add_tag ends up in possibly
        # but NOT in definitely.
        if op_l == "add_tag":
            state.tag_state = state.tag_state.with_added(literal_tags, has_dynamic=has_dynamic_tag)
        elif op_l == "remove_tag":
            state.tag_state = state.tag_state.with_removed(literal_tags, has_dynamic=has_dynamic_tag)
        new_lin = Lineage(
            status="derived",
            sources=_dedupe_sources(sources),
            expression=rendered,
            transformations=[op_l],
            conditions=list(conditions),
            parser_locations=[loc],
            value_type="array",  # R1.1: `tags` is always an array of strings.
        )
        context._store_destination(
            "tags",
            _add_conditions([*prior, new_lin], conditions),
            loc,
            state,
        )

    def _exec_on_error_mutate_op(
        self, stmt: Plugin, op_l: str, value: ConfigValue, state: AnalyzerState, conditions: list[str]
    ) -> None:
        # Handled once after the plugin, but tolerate it in order too.
        return

    def _handle_on_error(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        flag = first_value(stmt.config, "on_error")
        if flag is None:
            return
        flag = str(flag)
        loc = _location(stmt.line, "on_error", flag)
        # C4: previously this overwrote `state.tokens[flag]` outright, silently
        # dropping any prior lineage at the same name (e.g. a mutate.replace
        # that wrote a constant into the flag token earlier in the parser).
        # Append the error_flag lineage to whatever already exists so both the
        # success-path data and the on_error sentinel remain queryable —
        # `query(flag)` then returns both branches the way merges do.
        new_lineage = Lineage(
            status="derived",
            sources=[SourceRef(kind="error_flag", source_token=stmt.name, expression=flag)],
            expression=flag,
            conditions=list(conditions),
            parser_locations=[loc],
            notes=[ERROR_FLAG_NOTE],
        )
        prior = state.tokens.get(flag, [])
        state.tokens[flag] = [*prior, new_lineage]
