"""Expression, token, and source-resolution helpers for analysis."""

from __future__ import annotations

from itertools import product

from ._analysis_condition_facts import conditions_are_compatible
from ._analysis_diagnostics import template_fanout_warning, unresolved_bare_token_warning
from ._analysis_helpers import (
    _COLUMN_RE,
    _TOKEN_REF_RE,
    MAX_TEMPLATE_COMBINATIONS,
    _add_conditions,
    _dedupe_lineages,
    _dedupe_sources,
    _dedupe_strings,
    _has_nested_token_reference,
    _is_path_char,
    _is_plausible_data_path,
    _is_plausible_kv_key,
    _lineage_key,
    _looks_like_enum_constant,
    _member_sources_from_ref,
    _starts_identifier,
    _static_lineage_value,
    _status_for_sources,
    _strip_ref,
)
from ._analysis_state import AnalyzerState, ExtractionHint, TokenStore
from .model import Lineage, LineageStatus, SourceRef, TaintReason

MAX_MEMBER_INFERENCE_ALTERNATIVES = 2048
MAX_UNTARGETED_JSON_INFERENCE_ALTERNATIVES = 128
MAX_UNTARGETED_JSON_INFERENCE_SUMMARY_SAMPLES = 8


def _kv_keys_list(value: object) -> tuple[str, ...]:
    """Return a tuple of string keys from a kv config list value, or empty."""
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _kv_hint_admits_token(hint: ExtractionHint, token: str) -> bool:
    """Whether ``token`` should be inferable from this kv hint.

    Logstash kv supports ``include_keys`` / ``exclude_keys`` filters; the
    plugin only emits keys that pass both filters. The resolver must respect
    those filters or it will hallucinate keys the kv block would have
    skipped.

    A hint with no filters (the common case) admits every plausible key —
    same as before this enforcement landed. The token compared is the leaf
    key portion of `token` so callers can pass either bare or path-qualified
    references; for the basic case `token == leaf` so this is a no-op.
    """
    details = hint.details or {}
    include = _kv_keys_list(details.get("include_keys"))
    exclude = _kv_keys_list(details.get("exclude_keys"))
    if not include and not exclude:
        return True
    leaf = token.rsplit(".", 1)[-1]
    if exclude and leaf in exclude:
        return False
    return not include or leaf in include


class ResolutionMixin:
    def _looks_like_bare_token_name(self, expr: str) -> bool:
        if not expr or expr in {"true", "false", "null"} or expr.startswith("@"):
            return False
        return _starts_identifier(expr) and all(_is_path_char(ch) for ch in expr[1:])

    def _lineage_from_expression(
        self, expr: str, state: AnalyzerState, loc: str, conditions: list[str], bare_is_token: bool = False
    ) -> list[Lineage]:
        expr = str(expr)
        if _has_nested_token_reference(expr):
            taint = state.add_taint("nested_interpolation", f"Nested interpolation {expr!r} is runtime-dependent", loc)
            return [
                Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind="dynamic_reference", expression=expr)],
                    expression=expr,
                    conditions=list(conditions),
                    parser_locations=[loc],
                    notes=["Nested interpolation makes the source token name runtime-dependent."],
                    taints=[taint],
                )
            ]
        refs = _TOKEN_REF_RE.findall(expr)
        if not refs and not (expr.startswith("%{") and expr.endswith("}")):
            # In replace contexts a bare value is a constant. In merge/copy/date
            # contexts SecOps commonly uses a bare token.
            if bare_is_token and expr and expr in state.tokens:
                lins = self._resolve_token(expr, state, loc)
                return _add_conditions([lin.with_parser_locations([loc]) for lin in lins], conditions)
            if bare_is_token and expr and not _looks_like_enum_constant(expr) and self._can_infer_token(expr, state):
                lins = self._resolve_token(expr, state, loc)
                return _add_conditions([lin.with_parser_locations([loc]) for lin in lins], conditions)
            if bare_is_token and not _looks_like_enum_constant(expr) and self._looks_like_bare_token_name(expr):
                warning = unresolved_bare_token_warning(loc, expr)
                state.add_warning(
                    warning, code="unresolved_bare_token", message=warning, parser_location=loc, source_token=expr
                )
                taint = state.add_taint("unresolved_bare_token", f"Bare token {expr!r} was not resolved", loc, expr)
                return [
                    Lineage(
                        status="unresolved",
                        sources=[SourceRef(kind="unknown", source_token=expr, expression=expr)],
                        expression=expr,
                        conditions=list(conditions),
                        parser_locations=[loc],
                        notes=["Bare token was not resolved; not treated as a literal constant."],
                        taints=[taint],
                    )
                ]
            return [
                Lineage(
                    status="constant",
                    sources=[SourceRef(kind="constant", expression=expr)],
                    expression=expr,
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
            ]
        if len(refs) == 1 and expr.strip() == f"%{{{refs[0]}}}":
            lins = self._resolve_token(refs[0].strip(), state, loc)
            return _add_conditions([lin.with_parser_locations([loc]) for lin in lins], conditions)
        if refs:
            unique_refs = _dedupe_strings(refs)
            resolved_groups = [self._resolve_token(ref.strip(), state, loc) for ref in unique_refs]
            combination_count = 1
            for group in resolved_groups:
                combination_count *= max(1, len(group))
                if combination_count > MAX_TEMPLATE_COMBINATIONS:
                    warning = template_fanout_warning(loc, combination_count, MAX_TEMPLATE_COMBINATIONS)
                    state.add_warning(
                        warning,
                        code="template_fanout",
                        message=f"Template interpolation has {combination_count} combinations",
                        parser_location=loc,
                        source_token=expr,
                    )
                    taint = state.add_taint(
                        "template_fanout", f"Template interpolation has {combination_count} combinations", loc, expr
                    )
                    sources: list[SourceRef] = []
                    notes: list[str] = ["Template interpolation combinations exceeded static analysis limit."]
                    upstream_conditions: list[str] = []
                    upstream_locations: list[str] = []
                    transforms: list[str] = []
                    taints = [taint]
                    for group_lins in resolved_groups:
                        for lin in group_lins:
                            sources.extend(lin.sources)
                            notes.extend(lin.notes)
                            upstream_conditions.extend(lin.conditions)
                            upstream_locations.extend(lin.parser_locations)
                            transforms.extend(lin.transformations)
                            taints.extend(lin.taints)
                    return [
                        Lineage(
                            status="dynamic",
                            sources=_dedupe_sources(sources),
                            expression=expr,
                            transformations=_dedupe_strings(transforms + ["template_interpolation"]),
                            conditions=_dedupe_strings(upstream_conditions + list(conditions)),
                            parser_locations=_dedupe_strings(upstream_locations + [loc]),
                            notes=_dedupe_strings(notes),
                            taints=taints,
                        )
                    ]
            out: list[Lineage] = []
            for combo in product(*resolved_groups):
                combo_sources: list[SourceRef] = []
                combo_transforms: list[str] = []
                combo_notes: list[str] = []
                combo_conditions: list[str] = []
                combo_locations: list[str] = []
                combo_taints: list[TaintReason] = []
                concrete_expr = expr
                all_static = True
                for ref, lin in zip(unique_refs, combo, strict=True):
                    combo_sources.extend(lin.sources)
                    combo_transforms.extend(lin.transformations)
                    combo_notes.extend(lin.notes)
                    combo_conditions.extend(lin.conditions)
                    combo_locations.extend(lin.parser_locations)
                    combo_taints.extend(lin.taints)
                    static_value = _static_lineage_value(lin)
                    if static_value is None:
                        all_static = False
                    else:
                        concrete_expr = concrete_expr.replace(f"%{{{ref}}}", static_value)
                all_conditions = _dedupe_strings(combo_conditions + list(conditions))
                # PR-C: implicit grok constraints participate so a
                # template expansion whose conditions become provably
                # contradictory (e.g. ``[src_ip] == "FOO"`` against an
                # IP-captured src_ip) is pruned from the resolved
                # combinations rather than emitted with bad lineage.
                if not conditions_are_compatible(all_conditions, tuple(state.implicit_path_conditions)):
                    continue
                if all_static:
                    status: LineageStatus = "conditional" if all_conditions else "constant"
                    expression = concrete_expr
                else:
                    if any(lin.status == "dynamic" for lin in combo):
                        status = "dynamic"
                    elif any(lin.status == "unresolved" for lin in combo):
                        status = "unresolved"
                    elif all_conditions:
                        status = "conditional"
                    else:
                        status = "derived"
                    expression = expr
                out.append(
                    Lineage(
                        status=status,
                        sources=_dedupe_sources(combo_sources),
                        expression=expression,
                        transformations=_dedupe_strings(combo_transforms + ["template_interpolation"]),
                        conditions=all_conditions,
                        parser_locations=_dedupe_strings(combo_locations + [loc]),
                        notes=_dedupe_strings(combo_notes),
                        taints=combo_taints,
                    )
                )
            return _dedupe_lineages(out)
        return [
            Lineage(
                status="unresolved",
                sources=[SourceRef(kind="unknown", expression=expr)],
                expression=expr,
                conditions=list(conditions),
                parser_locations=[loc],
                taints=[state.add_taint("unresolved_expression", f"Expression {expr!r} could not be resolved", loc)],
            )
        ]

    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]:
        lineages = self._lookup_token(token, state, loc)
        if lineages:
            return [lin.clone() for lin in lineages]
        token = _strip_ref(str(token))
        return [
            Lineage(
                status="unresolved",
                sources=[SourceRef(kind="unknown", source_token=token, expression=token)],
                expression=token,
                parser_locations=[loc],
                notes=["Token was referenced before this analyzer could infer its extractor."],
                taints=[
                    state.add_taint(
                        "unresolved_token", f"Token {token!r} was referenced before it could be inferred", loc, token
                    )
                ],
            )
        ]

    def _lookup_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]:
        token = _strip_ref(str(token))
        generation_key = state.inference_generation_key()
        if token in state.tokens:
            # Read both inferred-cache dicts via the ``_data`` backing store to
            # skip the COW shallow-copy in the property getter — this is a pure
            # read, no mutation. The neighboring mutation site at line 301 still
            # goes through the public property so the COW fires before the
            # wholesale set replacement.
            inferred_generation = state._inferred_token_generations_data.get(token)
            if inferred_generation is None or inferred_generation == generation_key:
                return state.tokens[token]
            stale_inferred_keys = state._inferred_token_lineage_keys_data.get(token, set())
            existing_lineages = state.tokens[token]
            if stale_inferred_keys:
                preserved_lineages = [
                    lineage for lineage in existing_lineages if _lineage_key(lineage) not in stale_inferred_keys
                ]
            else:
                store = state.tokens if isinstance(state.tokens, TokenStore) else None
                preserved_lineages = list(store.appended_values(token)) if store is not None else []
            del state.tokens[token]
            state._inferred_token_generations.pop(token, None)
            state._inferred_token_lineage_keys.pop(token, None)
            state._inference_miss_cache.pop(token, None)
            inferred = self._infer_source_for_token(token, state, loc)
            if inferred:
                self._cache_inferred_token(token, inferred, state)
                if preserved_lineages:
                    state.append_token_lineages(token, preserved_lineages)
                return state.tokens[token]
            if preserved_lineages:
                state.tokens[token] = _dedupe_lineages(preserved_lineages)
                return state.tokens[token]
        if token in state.tokens:
            return state.tokens[token]
        if state._inference_miss_cache.get(token) == generation_key:
            return []
        inferred = self._infer_source_for_token(token, state, loc)
        if inferred:
            self._cache_inferred_token(token, inferred, state)
            return inferred
        state._inference_miss_cache[token] = generation_key
        return []

    def _cache_inferred_token(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None:
        token = _strip_ref(str(token))
        deduped = _dedupe_lineages(lineages)
        state.tokens[token] = deduped
        state._inferred_token_generations[token] = state.inference_generation_key()
        state._inferred_token_lineage_keys[token] = {_lineage_key(lineage) for lineage in deduped}

    def _can_infer_token(self, token: str, state: AnalyzerState) -> bool:
        token = _strip_ref(str(token))
        if token in state.tokens:
            return True
        if "." in token and token.split(".", 1)[0] in state.tokens:
            return True
        if _COLUMN_RE.match(token) and state.has_resolved_extractor("csv"):
            return True
        if _is_plausible_data_path(token):
            for h in state.extractor_hints_for_token("json", token):
                if not h.source_resolved:
                    continue
                target = h.details.get("target") if h.details else None
                if not target or token == str(target) or token.startswith(str(target) + "."):
                    return True
        return state.has_resolved_extractor("kv") and _is_plausible_kv_key(token)

    def _infer_source_for_token(
        self, token: str, state: AnalyzerState, loc: str, include_extractor_hints: bool = True
    ) -> list[Lineage]:
        token = _strip_ref(str(token))
        lineages: list[Lineage] = []
        lineages.extend(self._infer_member_source_for_token(token, state, loc))
        if not include_extractor_hints:
            return _dedupe_lineages(lineages)
        col = _COLUMN_RE.match(token)
        if col and state.csv_extractions:
            for hint in state.extractor_hints_for_token("csv", token):
                if not hint.source_resolved:
                    continue
                hint_conditions = list(hint.conditions)
                lineages.append(
                    Lineage(
                        status="conditional" if hint_conditions else "exact",
                        sources=[
                            SourceRef(
                                kind="csv_column",
                                source_token=hint.source_token,
                                column=int(col.group("num")),
                                details=hint.details,
                            )
                        ],
                        expression=token,
                        conditions=hint_conditions,
                        parser_locations=_dedupe_strings(list(hint.parser_locations) + [loc]),
                    )
                )
        if state.json_extractions and _is_plausible_data_path(token):
            untargeted_hints = []
            for hint in state.extractor_hints_for_token("json", token):
                if not hint.source_resolved:
                    continue
                hint_conditions = list(hint.conditions)
                target = hint.details.get("target") if hint.details else None
                if target:
                    target_s = str(target)
                    if token == target_s:
                        path = ""
                    elif token.startswith(target_s + "."):
                        path = token[len(target_s) + 1 :]
                    elif (
                        hint.details
                        and hint.details.get("array_function") == "split_columns"
                        and token.startswith(target_s + "_")
                        and token[len(target_s) + 1 :].isdigit()
                    ):
                        # array_function=split_columns synthesizes indexed
                        # sub-tokens like `<target>_1`, `<target>_2`, …
                        # mapped to message[0], message[1], … (Logstash uses
                        # 1-indexed naming over 0-indexed array positions).
                        index_str = token[len(target_s) + 1 :]
                        index = int(index_str) - 1
                        path = f"[{max(index, 0)}]"
                    else:
                        # A target-scoped JSON extractor does not expose fields
                        # as top-level tokens.
                        continue
                else:
                    untargeted_hints.append(hint)
                    continue
                lineages.append(
                    Lineage(
                        status="conditional" if hint_conditions else "exact",
                        sources=[
                            SourceRef(kind="json_path", source_token=hint.source_token, path=path, details=hint.details)
                        ],
                        expression=token,
                        conditions=hint_conditions,
                        parser_locations=_dedupe_strings(list(hint.parser_locations) + [loc]),
                    )
                )
            if len(untargeted_hints) > MAX_UNTARGETED_JSON_INFERENCE_ALTERNATIVES:
                lineages.extend(self._summarize_untargeted_json_inference(token, untargeted_hints, state, loc))
            else:
                for hint in untargeted_hints:
                    hint_conditions = list(hint.conditions)
                    lineages.append(
                        Lineage(
                            status="conditional" if hint_conditions else "exact",
                            sources=[
                                SourceRef(
                                    kind="json_path",
                                    source_token=hint.source_token,
                                    path=token,
                                    details=hint.details,
                                )
                            ],
                            expression=token,
                            conditions=hint_conditions,
                            parser_locations=_dedupe_strings(list(hint.parser_locations) + [loc]),
                        )
                    )
        if state.kv_extractions and _is_plausible_kv_key(token):
            for hint in state.extractor_hints_for_token("kv", token):
                if not hint.source_resolved:
                    continue
                # Honor include_keys / exclude_keys filters configured on the
                # kv plugin. Without this enforcement the resolver would
                # hallucinate any plausibly-keyed token, even ones the kv
                # plugin would skip at runtime.
                if not _kv_hint_admits_token(hint, token):
                    continue
                hint_conditions = list(hint.conditions)
                lineages.append(
                    Lineage(
                        status="conditional" if hint_conditions else "exact",
                        sources=[
                            SourceRef(kind="kv_key", source_token=hint.source_token, path=token, details=hint.details)
                        ],
                        expression=token,
                        conditions=hint_conditions,
                        parser_locations=_dedupe_strings(list(hint.parser_locations) + [loc]),
                    )
                )
        return _dedupe_lineages(lineages)

    def _summarize_untargeted_json_inference(
        self, token: str, hints: list[ExtractionHint], state: AnalyzerState, loc: str
    ) -> list[Lineage]:
        total = len(hints)
        warning = (
            f"{loc}: untargeted json extractor inference for {token!r} has {total} alternatives; "
            f"summarized after limit {MAX_UNTARGETED_JSON_INFERENCE_ALTERNATIVES}"
        )
        state.add_warning(
            warning,
            code="extractor_hint_fanout",
            message=warning,
            parser_location=loc,
            source_token=token,
        )
        taint = state.add_taint(
            "extractor_hint_fanout",
            f"Untargeted json extractor inference for {token!r} exceeded "
            f"{MAX_UNTARGETED_JSON_INFERENCE_ALTERNATIVES} alternatives",
            loc,
            token,
        )
        sampled = hints[:MAX_UNTARGETED_JSON_INFERENCE_SUMMARY_SAMPLES]
        sources = _dedupe_sources(
            SourceRef(kind="json_path", source_token=hint.source_token, path=token, details=hint.details)
            for hint in sampled
        )
        conditions = [f"extractor hint fanout: {total} untargeted json alternatives summarized"]
        locations = _dedupe_strings(location for hint in sampled for location in (*hint.parser_locations, loc))[
            :MAX_UNTARGETED_JSON_INFERENCE_SUMMARY_SAMPLES
        ]
        return [
            Lineage(
                status="dynamic",
                sources=sources,
                expression=token,
                conditions=conditions,
                parser_locations=locations,
                notes=[f"{total} untargeted json extractor alternatives were summarized after fanout threshold."],
                taints=[taint],
            )
        ]

    def _infer_member_source_for_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]:
        """Infer dotted access from a known loop/map/object variable.

        Example: within ``for alert in alerts { ... }``, ``%{alert.name}``
        should resolve to the raw JSON path ``alerts[*].name`` instead of a
        top-level JSON path called ``alert.name``.
        """
        token = _strip_ref(str(token))
        if "." not in token:
            return []
        base, suffix = token.split(".", 1)
        if not base or not suffix or base not in state.tokens:
            return []

        base_lineages = state.tokens.get(base, [])
        if len(base_lineages) > MAX_MEMBER_INFERENCE_ALTERNATIVES:
            fanout_signature: tuple[tuple[object, ...], ...] = (("fanout", len(base_lineages)),)
            cache_key = (base, suffix, fanout_signature)
            cached = state._member_inference_cache.get(cache_key)
            if cached is not None:
                return cached
            warning = template_fanout_warning(loc, len(base_lineages), MAX_MEMBER_INFERENCE_ALTERNATIVES)
            state.add_warning(
                warning,
                code="member_inference_fanout",
                message=warning,
                parser_location=loc,
                source_token=token,
            )
            taint = state.add_taint(
                "member_inference_fanout",
                f"Member inference for {token!r} exceeded {MAX_MEMBER_INFERENCE_ALTERNATIVES} base alternatives",
                loc,
                token,
            )
            symbolic = [
                Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind="dynamic_reference", source_token=base, path=suffix, expression=token)],
                    expression=token,
                    parser_locations=[loc],
                    notes=["Member inference fanout was bounded symbolically."],
                    taints=[taint],
                )
            ]
            state._member_inference_cache[cache_key] = symbolic
            return symbolic
        signature = tuple(_lineage_key(lin) for lin in base_lineages)
        cache_key = (base, suffix, signature)
        cached = state._member_inference_cache.get(cache_key)
        if cached is not None:
            return cached

        inferred: list[Lineage] = []
        for base_lin in base_lineages:
            member_sources: list[SourceRef] = []
            for src in base_lin.sources:
                member_sources.extend(_member_sources_from_ref(src, suffix))
            member_sources = _dedupe_sources(member_sources)
            if not member_sources:
                continue
            status: LineageStatus = _status_for_sources(member_sources)
            if base_lin.conditions and status in {"exact", "exact_capture", "constant", "derived", "repeated"}:
                status = "conditional"
            inferred.append(
                Lineage(
                    status=status,
                    sources=member_sources,
                    expression=token,
                    transformations=list(base_lin.transformations),
                    conditions=list(base_lin.conditions),
                    parser_locations=list(base_lin.parser_locations) + [loc],
                    notes=list(base_lin.notes) + [f"dotted member access off {base}"],
                    taints=list(base_lin.taints),
                )
            )
        deduped = _dedupe_lineages(inferred)
        state._member_inference_cache[cache_key] = deduped
        return deduped
