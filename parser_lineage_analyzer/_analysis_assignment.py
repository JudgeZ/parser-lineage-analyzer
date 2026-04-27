"""Token assignment and state-mutation helpers for analysis."""

from __future__ import annotations

from itertools import product
from typing import Protocol, cast

from ._analysis_condition_facts import conditions_are_compatible
from ._analysis_details import OBJECT_LITERAL_NOTE
from ._analysis_diagnostics import dynamic_destination_warning, empty_destination_warning, template_fanout_warning
from ._analysis_helpers import (
    MAX_TEMPLATE_COMBINATIONS,
    _add_conditions,
    _dedupe_lineages,
    _dedupe_strings,
    _location,
    _normalize_field_ref,
    _stable_value_repr,
    _static_lineage_value,
)
from ._analysis_state import AnalyzerState
from ._analysis_templates import template_refs
from ._types import ConfigPair, ConfigValue
from .config_parser import as_pairs
from .model import Lineage, SourceRef, TaintReason

MAX_STATIC_DESTINATION_TOTAL_TOKENS = 100_000
MAX_LITERAL_COLLECTION_LINEAGES = 50_000


class _AssignmentContext(Protocol):
    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _lineage_from_expression(
        self, expr: str, state: AnalyzerState, loc: str, conditions: list[str], bare_is_token: bool = False
    ) -> list[Lineage]: ...


class AssignmentMixin:
    def _assign(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None:
        self._clear_descendant_tokens(token, state)
        state.tokens[token] = _dedupe_lineages(lineages)

    def _append(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None:
        state.append_token_lineages(token, lineages)

    def _clear_descendant_tokens(self, token: str, state: AnalyzerState) -> None:
        """Remove child paths made stale by assigning a complete parent token."""
        if not token or "%{" in token:
            return
        for existing in state.descendant_tokens(token):
            state.tokens.pop(existing, None)

    def _mark_dynamic_destination(
        self, dest: str, lineages: list[Lineage], loc: str, state: AnalyzerState
    ) -> list[Lineage]:
        """Flag assignments where the destination field name is data-dependent."""
        if "%{" not in dest:
            return lineages
        warning = dynamic_destination_warning(loc, dest)
        state.add_warning(
            warning,
            code="dynamic_destination",
            message=f"Destination field {dest!r} is runtime-dependent",
            parser_location=loc,
            source_token=dest,
        )
        taint = state.add_taint("dynamic_destination", f"Destination field {dest!r} is runtime-dependent", loc, dest)
        out: list[Lineage] = []
        for lin in lineages:
            clone = lin.with_status("dynamic").with_parser_locations([loc])
            note = f"Dynamic destination field name: {dest}"
            clone = clone.with_notes([note]).with_taints([taint])
            out.append(clone)
        return out

    def _expand_destination_template(
        self,
        dest: str,
        state: AnalyzerState,
        loc: str,
    ) -> tuple[list[tuple[str, list[str], list[str]]], list[tuple[list[str], list[str], list[TaintReason]]]]:
        """Resolve static destination placeholders while preserving dynamic branches."""
        refs = template_refs(dest)
        if not refs:
            return [(dest, [], [])], []
        unique_refs = _dedupe_strings(refs)
        groups: list[list[tuple[str | None, list[str], list[str], list[TaintReason]]]] = []
        count = 1
        for ref in unique_refs:
            lineages = cast(_AssignmentContext, self)._resolve_token(ref.strip(), state, loc)
            values: list[tuple[str | None, list[str], list[str], list[TaintReason]]] = []
            for lin in lineages:
                value = _static_lineage_value(lin)
                values.append(
                    (
                        str(value) if value is not None else None,
                        list(lin.conditions),
                        list(lin.parser_locations),
                        list(lin.taints),
                    )
                )
                if count * len(values) > MAX_TEMPLATE_COMBINATIONS:
                    warning = template_fanout_warning(loc, count * len(values), MAX_TEMPLATE_COMBINATIONS)
                    state.add_warning(
                        warning,
                        code="template_fanout",
                        message=f"Destination template has {count * len(values)} combinations",
                        parser_location=loc,
                        source_token=dest,
                    )
                    state.add_taint(
                        "template_fanout",
                        f"Destination template has {count * len(values)} combinations",
                        loc,
                        dest,
                    )
                    return [], []
            seen_values: set[tuple[str | None, tuple[str, ...], tuple[str, ...], tuple[TaintReason, ...]]] = set()
            deduped_values: list[tuple[str | None, list[str], list[str], list[TaintReason]]] = []
            for value, ref_conditions, ref_locations, ref_taints in values:
                key = (value, tuple(ref_conditions), tuple(ref_locations), tuple(ref_taints))
                if key not in seen_values:
                    seen_values.add(key)
                    deduped_values.append((value, ref_conditions, ref_locations, ref_taints))
            values = deduped_values
            count *= max(1, len(values))
            if count > MAX_TEMPLATE_COMBINATIONS:
                warning = template_fanout_warning(loc, count, MAX_TEMPLATE_COMBINATIONS)
                state.add_warning(
                    warning,
                    code="template_fanout",
                    message=f"Destination template has {count} combinations",
                    parser_location=loc,
                    source_token=dest,
                )
                state.add_taint("template_fanout", f"Destination template has {count} combinations", loc, dest)
                return [], []
            groups.append(values)
        if any(not group for group in groups):
            return [], []
        out: list[tuple[str, list[str], list[str]]] = []
        dynamic_branches: list[tuple[list[str], list[str], list[TaintReason]]] = []
        for combo in product(*groups):
            concrete = dest
            conditions: list[str] = []
            locations: list[str] = []
            taints: list[TaintReason] = []
            all_static = True
            for ref, (value, ref_conditions, ref_locations, ref_taints) in zip(unique_refs, combo, strict=True):
                if value is None:
                    all_static = False
                else:
                    concrete = concrete.replace(f"%{{{ref}}}", value)
                conditions.extend(ref_conditions)
                locations.extend(ref_locations)
                taints.extend(ref_taints)
            # PR-C: implicit grok constraints participate in template-
            # expansion compatibility checks too — a destination expansion
            # whose conditions are now provably contradictory thanks to a
            # captured field's resolved-body constraint should be pruned
            # rather than emitted as a no-op branch.
            if not conditions_are_compatible(conditions, tuple(state.implicit_path_conditions)):
                continue
            if all_static:
                out.append((concrete, _dedupe_strings(conditions), _dedupe_strings(locations)))
            else:
                dynamic_branches.append((_dedupe_strings(conditions), _dedupe_strings(locations), taints))
        return out, dynamic_branches

    def _store_destination(
        self, dest: str, lineages: list[Lineage], loc: str, state: AnalyzerState, *, append: bool = False
    ) -> None:
        if not dest:
            warning = empty_destination_warning(loc)
            state.add_warning(warning, code="empty_destination", message=warning, parser_location=loc)
            state.add_taint("empty_destination", "Empty destination field name was ignored", loc)
            return
        expanded, dynamic_branches = self._expand_destination_template(dest, state, loc)
        if expanded and state._static_destination_total_tokens + len(expanded) > MAX_STATIC_DESTINATION_TOTAL_TOKENS:
            warning = template_fanout_warning(
                loc, state._static_destination_total_tokens + len(expanded), MAX_STATIC_DESTINATION_TOTAL_TOKENS
            )
            state.add_warning(
                warning,
                code="static_destination_total_fanout",
                message=f"Static destination expansion exceeded {MAX_STATIC_DESTINATION_TOTAL_TOKENS} total tokens",
                parser_location=loc,
                source_token=dest,
            )
            state.add_taint(
                "static_destination_total_fanout",
                f"Static destination expansion for {dest!r} was summarized after total fanout limit",
                loc,
                dest,
            )
            expanded = []
            dynamic_branches = [([], [loc], [])]
        if not expanded and not dynamic_branches:
            lineages = self._mark_dynamic_destination(dest, lineages, loc, state)
            if append:
                self._append(dest, lineages, state)
            else:
                self._assign(dest, lineages, state)
            return
        implicit = tuple(state.implicit_path_conditions)
        for concrete_dest, ref_conditions, ref_locations in expanded:
            concrete_lineages = _add_conditions(lineages, ref_conditions)
            concrete_lineages = [
                lin for lin in concrete_lineages if conditions_are_compatible(list(lin.conditions), implicit)
            ]
            if not concrete_lineages:
                continue
            if not ref_locations:
                pass
            elif len(ref_locations) == 1:
                ref_loc = ref_locations[0]
                concrete_lineages = [
                    lin if ref_loc in lin.parser_locations else lin.with_parser_locations(ref_locations)
                    for lin in concrete_lineages
                ]
            else:
                concrete_lineages = [lin.with_parser_locations(ref_locations) for lin in concrete_lineages]
            if append:
                self._append(concrete_dest, concrete_lineages, state)
            else:
                self._assign(concrete_dest, concrete_lineages, state)
            state._static_destination_total_tokens += 1
        if dynamic_branches:
            warning = dynamic_destination_warning(loc, dest)
            state.add_warning(
                warning,
                code="dynamic_destination",
                message=f"Destination field {dest!r} is runtime-dependent",
                parser_location=loc,
                source_token=dest,
            )
            taint = state.add_taint(
                "dynamic_destination", f"Destination field {dest!r} is runtime-dependent", loc, dest
            )
            dynamic_lineages: list[Lineage] = []
            for ref_conditions, ref_locations, ref_taints in dynamic_branches:
                for lin in _add_conditions(lineages, ref_conditions):
                    if not conditions_are_compatible(list(lin.conditions), implicit):
                        continue
                    clone = lin.with_status("dynamic").with_parser_locations(_dedupe_strings(ref_locations + [loc]))
                    clone = clone.with_notes([f"Dynamic destination field name: {dest}"])
                    clone = clone.with_taints([*ref_taints, taint])
                    dynamic_lineages.append(clone)
            if append:
                self._append(dest, dynamic_lineages, state)
            else:
                self._assign(dest, dynamic_lineages, state)

    def _project_object_merge(
        self, dest: str, src_token: str, loc: str, state: AnalyzerState, conditions: list[str]
    ) -> None:
        """Project known subfields from a merged object token onto ``dest.*``.

        Parser code often builds an object token using subfield assignments such
        as ``label.key`` and ``label.value``, then appends that object to a UDM
        repeated field using ``merge``. Static reverse queries usually ask for
        the final UDM subfield (for example ``...labels.value``), so this
        method creates synthetic lineage for ``dest.key``, ``dest.value``, and
        any other known subfields.
        """
        projections: list[tuple[str, list[Lineage]]] = []
        for token in state.descendant_tokens(src_token):
            suffix = token[len(src_token) + 1 :]
            if not suffix:
                continue
            lineages = state.tokens.get(token, [])
            projected_dest = f"{dest}.{suffix}"
            projected_lins: list[Lineage] = []
            for lin in lineages:
                clone = (
                    lin.with_transformations([f"merge_object({src_token}.{suffix})"])
                    .with_parser_locations([loc])
                    .with_conditions([cond for cond in conditions if cond])
                )
                if clone.status not in {"conditional", "unresolved"}:
                    clone = clone.with_status("repeated" if projected_dest in state.tokens else clone.status)
                projected_lins.append(clone)
            projections.append((projected_dest, projected_lins))
        for projected_dest, lineages in projections:
            self._append(projected_dest, lineages, state)

    def _lineages_from_config_value(
        self, value: ConfigValue, state: AnalyzerState, loc: str, conditions: list[str], bare_is_token: bool = False
    ) -> list[Lineage]:
        """Convert a parsed config value into one or more symbolic lineages.

        Config values are not always scalars. ``merge`` and ``replace`` can
        receive arrays or object maps. Returning a list preserves repeated array
        lineage instead of stringifying Python containers.
        """
        pairs = as_pairs(value)
        if pairs:
            return [
                Lineage(
                    status="derived",
                    sources=[SourceRef(kind="object_literal", expression=_stable_value_repr(value))],
                    expression=_stable_value_repr(value),
                    conditions=list(conditions),
                    parser_locations=[loc],
                    notes=[OBJECT_LITERAL_NOTE],
                )
            ]
        if isinstance(value, list):
            if len(value) > MAX_LITERAL_COLLECTION_LINEAGES:
                count = len(value)
                sample = _stable_value_repr(cast(ConfigValue, value[0])) if value else "[]"
                warning = (
                    f"{loc}: literal collection has {count} values; "
                    f"summarized after fanout threshold {MAX_LITERAL_COLLECTION_LINEAGES}"
                )
                state.add_warning(
                    warning,
                    code="literal_collection_fanout",
                    message=warning,
                    parser_location=loc,
                    source_token=sample,
                )
                taint = state.add_taint(
                    "literal_collection_fanout",
                    f"Literal collection has {count} values and was summarized",
                    loc,
                    sample,
                )
                expression = f"[{count} literal values summarized]"
                return [
                    Lineage(
                        status="dynamic",
                        sources=[SourceRef(kind="constant", expression=expression)],
                        expression=expression,
                        conditions=list(conditions),
                        parser_locations=[loc],
                        notes=[f"{count} literal collection values summarized after fanout threshold."],
                        taints=[taint],
                    )
                ]
            out: list[Lineage] = []
            for item in value:
                out.extend(
                    self._lineages_from_config_value(
                        cast(ConfigValue, item), state, loc, conditions, bare_is_token=bare_is_token
                    )
                )
            return out or [
                Lineage(
                    status="constant",
                    sources=[SourceRef(kind="constant", expression="[]")],
                    expression="[]",
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
            ]
        return cast(_AssignmentContext, self)._lineage_from_expression(
            str(value), state, loc, conditions, bare_is_token=bare_is_token
        )

    def _assign_object_literal_subfields(
        self, dest: str, pairs: list[ConfigPair], state: AnalyzerState, conditions: list[str], line: int, mode: str
    ) -> None:
        """Flatten object literal config values into deterministic subfield lineage."""
        for key, value in pairs:
            key_s = _normalize_field_ref(str(key))
            child_dest = f"{dest}.{key_s}" if key_s else dest
            loc = _location(line, f"mutate.{mode}.object", f"{child_dest} <= {value}")
            child_pairs = as_pairs(value)
            if child_pairs:
                self._assign_object_literal_subfields(child_dest, child_pairs, state, conditions, line, mode)
                continue
            lins = self._lineages_from_config_value(value, state, loc, conditions, bare_is_token=False)
            if mode in {"add_field", "merge"}:
                self._store_destination(child_dest, lins, loc, state, append=True)
            else:
                self._store_destination(child_dest, lins, loc, state)
