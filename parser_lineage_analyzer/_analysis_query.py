"""Query assembly helpers for reverse-lineage analysis."""

from __future__ import annotations

import re
from bisect import insort
from collections import Counter
from typing import Protocol, TypedDict, cast

from ._analysis_helpers import (
    _dedupe_diagnostics,
    _dedupe_lineages,
    _dedupe_strings,
    _dedupe_taints,
    _dedupe_warning_reasons,
    _lineages_with_anchor_conditions,
    _looks_like_udm_field,
    _taint_key,
    _udm_suffixes,
)
from ._analysis_state import AnalyzerState
from ._types import JSONDict, JSONValue
from .model import (
    DiagnosticRecord,
    Lineage,
    OutputAnchor,
    QueryResult,
    QuerySemanticSummary,
    TaintReason,
    WarningReason,
)


class AnalysisSummaryDict(TypedDict, total=False):
    """Static shape of :meth:`AnalysisQueryMixin.analysis_summary` (non-compact).

    Every key is optional (``total=False``) because some entries — notably
    ``value_type_summary`` — are only emitted when the underlying analyzer
    state has anything to report. The runtime values follow the same
    JSON-compatible semantics as ``JSONDict`` (see ``_types.JSONValue``); this
    TypedDict simply pins the per-key types so static consumers don't need to
    rediscover them via ``isinstance`` guards on every read.
    """

    udm_fields: list[str]
    output_anchors: list[JSONDict]
    unsupported: list[str]
    warnings: list[str]
    structured_warnings: list[JSONDict]
    diagnostics: list[JSONDict]
    taints: list[JSONDict]
    token_count: int
    json_extractions: list[JSONDict]
    csv_extractions: list[JSONDict]
    kv_extractions: list[JSONDict]
    xml_extractions: list[JSONDict]
    value_type_summary: dict[str, JSONValue]


class CompactAnalysisSummaryDict(TypedDict, total=False):
    """Static shape of :meth:`AnalysisQueryMixin.analysis_summary` (compact).

    Mirrors :class:`AnalysisSummaryDict` and adds the ``*_total`` counters,
    the ``compact_summary`` envelope, and the per-code count maps emitted only
    by the bounded summary path. ``total=False`` keeps the contract honest:
    not every counter is present in every payload (the implementation only
    emits the keys it actually populates), so callers should still go through
    ``.get()`` / the CLI ``_summary_*`` helpers.
    """

    compact_summary: dict[str, JSONValue]
    udm_fields: list[str]
    udm_fields_total: int
    output_anchors: list[JSONDict]
    unsupported: list[str]
    warnings: list[str]
    structured_warnings: list[JSONDict]
    diagnostics: list[JSONDict]
    taints: list[JSONDict]
    token_count: int
    json_extractions: list[JSONDict]
    csv_extractions: list[JSONDict]
    kv_extractions: list[JSONDict]
    xml_extractions: list[JSONDict]
    warning_counts: dict[str, int]
    taint_counts: dict[str, int]
    diagnostic_counts: dict[str, int]
    unsupported_total: int
    warnings_total: int
    structured_warnings_total: int
    diagnostics_total: int
    taints_total: int
    output_anchors_total: int
    json_extractions_total: int
    csv_extractions_total: int
    kv_extractions_total: int
    xml_extractions_total: int


SUMMARY_SAMPLE_LIMIT = 50
MAX_ANCHOR_CONDITIONED_COMPACT_MAPPINGS = 50_000


def _clamp_query_sample_limit(sample_limit: int) -> int:
    return min(max(int(sample_limit), 0), SUMMARY_SAMPLE_LIMIT)


class _QueryContext(Protocol):
    def analyze(self) -> AnalyzerState: ...


class AnalysisQueryMixin:
    def query(self, udm_field: str, *, compact: bool = False, sample_limit: int = SUMMARY_SAMPLE_LIMIT) -> QueryResult:
        """Trace a UDM field back to its raw-log source(s) according to the parser.

        ``udm_field`` is the UDM destination to look up, written as a dotted
        path such as ``"target.ip"`` or the fully qualified
        ``"event.idm.read_only_udm.target.ip"``. The lookup is normalized
        against the parser's discovered ``@output`` anchors (or the implicit
        ``event`` anchor when none are present), so both the short and long
        forms resolve to the same mappings.

        Returns a ``QueryResult`` containing the dominant ``status``
        (``exact``, ``exact_capture``, ``conditional``, ``derived``,
        ``constant``, ``repeated``, ``dynamic``, ``removed``, ``partial``, or
        ``unresolved``), the list of ``Lineage`` mappings (one per possible
        source path with its predicates and transforms), the normalized
        candidate token list considered, the relevant output anchors, and any
        warnings, structured warnings, taints, unsupported constructs, and
        diagnostics produced while analyzing the parser. Orthogonal flags
        ``is_conditional``, ``has_dynamic``, ``has_unresolved``, and
        ``has_taints`` expose individual gating signals.

        ``compact=True`` bounds high-cardinality outputs by sampling at most
        ``sample_limit`` (default 50, hard-capped at 50) mappings/candidates
        while reporting full ``mappings_total`` /
        ``normalized_candidates_total`` counters; aggregate semantics
        (``status``, ``has_*`` flags) are unchanged. ``sample_limit`` is
        ignored when ``compact`` is ``False``.

        Raises ``TypeError`` if ``udm_field`` is not a ``str``.
        """
        if not isinstance(udm_field, str):
            raise TypeError(f"udm_field must be str, got {type(udm_field).__name__}")
        sample_limit = _clamp_query_sample_limit(sample_limit)
        state = cast(_QueryContext, self).analyze()
        anchors = _coalesce_output_anchors(state.output_anchors)
        anchor_index = _anchor_prefix_index(anchors)
        candidates = self._candidate_tokens(udm_field, state, anchors=anchors)
        has_dynamic_templates = _state_has_dynamic_templates(state)
        mappings: list[Lineage] = []
        mappings_total = 0
        sampled_mappings = False
        candidates_total = len(candidates)
        candidates_for_result = candidates[:sample_limit] if compact else candidates
        query_diagnostics: list[DiagnosticRecord] = []
        semantic_summary = QuerySemanticSummary()
        for cand in candidates:
            candidate_anchors = self._anchors_for_candidate(cand, anchor_index)
            direct = state.tokens.get(cand, [])
            if has_dynamic_templates:
                dynamic, dynamic_total, dynamic_diagnostics, dynamic_summary = self._dynamic_matches_for_candidate(
                    cand, state, limit=max(0, sample_limit - len(mappings)) if compact else None
                )
            else:
                dynamic, dynamic_total, dynamic_diagnostics, dynamic_summary = [], 0, [], QuerySemanticSummary()
            query_diagnostics.extend(dynamic_diagnostics)
            if candidate_anchors:
                if direct or dynamic_total:
                    candidate_summary = QuerySemanticSummary().with_lineages(direct).with_summary(dynamic_summary)
                    semantic_summary = semantic_summary.with_summary(
                        candidate_summary,
                        conditions=(condition for anchor in candidate_anchors for condition in anchor.conditions),
                    )
                fanout = len(candidate_anchors) * (len(direct) + dynamic_total)
                if fanout > MAX_ANCHOR_CONDITIONED_COMPACT_MAPPINGS:
                    mappings_total += fanout
                    sampled_mappings = True
                    result_kind = "compact result" if compact else "query result"
                    warning = (
                        f"Anchor-conditioned query has {fanout} mapping alternatives; {result_kind} is sampled "
                        f"after safety limit {MAX_ANCHOR_CONDITIONED_COMPACT_MAPPINGS}."
                    )
                    query_diagnostics.append(
                        DiagnosticRecord(
                            code="anchor_conditioned_fanout",
                            kind="warning",
                            message=warning,
                            warning=warning,
                            source_token=cand,
                        )
                    )
                    remaining = max(0, sample_limit - len(mappings))
                    if remaining:
                        for anchor in candidate_anchors:
                            for lineage_group in (direct, dynamic):
                                for lineage in _lineages_with_anchor_conditions([*lineage_group[:remaining]], anchor):
                                    mappings.append(lineage)
                                    remaining -= 1
                                    if remaining <= 0:
                                        break
                                if remaining <= 0:
                                    break
                            if remaining <= 0:
                                break
                    continue
                for anchor in candidate_anchors:
                    anchor_total = len(direct) + dynamic_total
                    mappings_total += anchor_total
                    if compact:
                        remaining = max(0, sample_limit - len(mappings))
                        if remaining <= 0:
                            sampled_mappings = True
                            continue
                        direct_group = direct[:remaining]
                        mappings.extend(_lineages_with_anchor_conditions(direct_group, anchor))
                        remaining -= len(direct_group)
                        if remaining <= 0:
                            sampled_mappings = sampled_mappings or anchor_total > len(direct_group)
                            continue
                        dynamic_group = dynamic[:remaining]
                        mappings.extend(_lineages_with_anchor_conditions(dynamic_group, anchor))
                        if len(direct_group) + len(dynamic_group) < anchor_total:
                            sampled_mappings = True
                        continue
                    mappings.extend(_lineages_with_anchor_conditions(direct, anchor))
                    mappings.extend(_lineages_with_anchor_conditions(dynamic, anchor))
            else:
                total = len(direct) + dynamic_total
                if total:
                    semantic_summary = semantic_summary.with_lineages(direct)
                    semantic_summary = semantic_summary.with_summary(dynamic_summary)
                mappings_total += total
                if compact and len(mappings) + total > sample_limit:
                    sampled_mappings = True
                    remaining = max(0, sample_limit - len(mappings))
                    direct_group = direct[:remaining]
                    mappings.extend(_lineages_with_anchor_conditions(direct_group, None))
                    remaining -= len(direct_group)
                    if remaining > 0:
                        mappings.extend(_lineages_with_anchor_conditions(dynamic[:remaining], None))
                    continue
                mappings.extend(_lineages_with_anchor_conditions(direct, None))
                mappings.extend(_lineages_with_anchor_conditions(dynamic, None))
        mappings = _dedupe_lineages(mappings)
        warnings = list(state.warnings)
        structured_warnings = list(state.structured_warnings)
        if not mappings and mappings_total <= 0:
            warning = (
                "No assignment to the requested field was found in the parsed subset. "
                "Try --list to inspect discovered UDM fields."
            )
            warnings = _dedupe_strings(warnings + [warning])
            structured_warnings = _dedupe_warning_reasons(
                structured_warnings
                + [
                    WarningReason(
                        code="no_assignment",
                        message="No assignment to the requested field was found in the parsed subset.",
                        warning=warning,
                    )
                ]
            )
        return QueryResult(
            udm_field=udm_field,
            normalized_candidates=candidates_for_result,
            normalized_candidates_total=candidates_total if compact else None,
            mappings=mappings,
            mappings_total=mappings_total if sampled_mappings else None,
            output_anchors=anchors,
            unsupported=state.unsupported,
            warnings=warnings,
            structured_warnings=structured_warnings,
            diagnostics=state.diagnostics
            if not query_diagnostics
            else _dedupe_diagnostics([*state.diagnostics, *query_diagnostics]),
            semantic_summary=semantic_summary,
        )

    def list_udm_fields(self) -> list[str]:
        """Return the sorted list of UDM-like fields the parser writes to.

        The list is derived from every token the analyzer recognized as a UDM
        destination (either a fully qualified ``event.idm.read_only_udm....``
        path, or any anchor-prefixed token whose anchor is referenced in an
        ``@output``). Anchor-relative names are also expanded under the
        canonical ``event`` anchor for convenience. Mirrors the CLI's
        ``--list`` output.
        """
        state = cast(_QueryContext, self).analyze()
        return self._list_udm_fields(state)

    def _list_udm_fields(
        self, state: AnalyzerState, limit: int | None = None, anchors: list[OutputAnchor] | None = None
    ) -> list[str]:
        fields = sorted(k for k in state.tokens if _looks_like_udm_field(k))
        normalized = set(fields)
        coalesced = anchors if anchors is not None else _coalesce_output_anchors(state.output_anchors)
        anchor_names = set(_dedupe_strings(anchor.anchor for anchor in coalesced))
        for field in fields:
            start = 0
            while True:
                dot = field.find(".", start)
                if dot == -1:
                    break
                prefix = field[:dot]
                if prefix in anchor_names:
                    normalized.add("event." + field[dot + 1 :])
                start = dot + 1
        out = sorted(normalized)
        return out[:limit] if limit is not None else out

    def analysis_summary(self, *, compact: bool = False) -> AnalysisSummaryDict | CompactAnalysisSummaryDict:
        """Return deterministic parser/analyzer coverage metadata for CI use."""
        state = cast(_QueryContext, self).analyze()
        if compact:
            return self._compact_analysis_summary(state)
        taints = self._summary_taints(state)
        # R1.2: per-token value_type union — only emit entries whose union is
        # a definite type ("string"/"array"/"object"/"mixed"). Tokens whose
        # lineage is all "unknown" don't contribute, keeping the summary
        # compact for fixtures that don't use type-promoting ops.
        # Computed lazily on demand. Profiling on the largest corpus fixture
        # (~67ms) and the typical call pattern (one summary per parser)
        # showed no benefit from caching — if this becomes hot in a future
        # workload, materialize on AnalyzerState and invalidate on token
        # mutation, or memoize here.
        from .model import Lineage as _Lineage

        value_type_summary: dict[str, JSONValue] = {}
        for token, lineages in state.tokens.items():
            union = _Lineage.union_value_types(lineages)
            if union != "unknown":
                value_type_summary[token] = union
        summary: AnalysisSummaryDict = {
            "udm_fields": self.list_udm_fields(),
            "output_anchors": [a.to_json() for a in state.output_anchors],
            "unsupported": _dedupe_strings(state.unsupported),
            "warnings": _dedupe_strings(state.warnings),
            "structured_warnings": [
                warning.to_json() for warning in _dedupe_warning_reasons(state.structured_warnings)
            ],
            "diagnostics": [diagnostic.to_json() for diagnostic in state.diagnostics],
            "taints": [taint.to_json() for taint in taints],
            "token_count": len(state.tokens),
            "json_extractions": [h.to_json() for h in state.json_extractions],
            "csv_extractions": [h.to_json() for h in state.csv_extractions],
            "kv_extractions": [h.to_json() for h in state.kv_extractions],
            "xml_extractions": [h.to_json() for h in state.xml_extractions],
        }
        if value_type_summary:
            summary["value_type_summary"] = value_type_summary
        return summary

    def _summary_taints(self, state: AnalyzerState) -> list[TaintReason]:
        taints = list(state.taints)
        for lineages in state.tokens.values():
            for lin in lineages:
                taints.extend(lin.taints)
        return _dedupe_taints(taints)

    def _compact_analysis_summary(self, state: AnalyzerState) -> CompactAnalysisSummaryDict:
        taint_sample, taint_total, taint_counts = self._summary_taint_sample_counts(state)
        unsupported = _dedupe_strings(state.unsupported)
        warnings = _dedupe_strings(state.warnings)
        structured_warnings = _dedupe_warning_reasons(state.structured_warnings)
        diagnostics = _dedupe_diagnostics(state.diagnostics)
        output_anchors = _coalesce_output_anchors(state.output_anchors)
        udm_fields, udm_fields_total = _compact_udm_field_sample_total(
            state, output_anchors, limit=SUMMARY_SAMPLE_LIMIT
        )
        warning_counts = Counter(w.code for w in structured_warnings)
        warning_counts.update(state._suppressed_warning_counts)
        totals: dict[str, int] = {
            "udm_fields": udm_fields_total,
            "output_anchors": len(output_anchors),
            "unsupported": len(unsupported),
            "warnings": len(warnings),
            "structured_warnings": len(structured_warnings),
            "diagnostics": len(diagnostics),
            "taints": taint_total,
            "json_extractions": len(state.json_extractions),
            "csv_extractions": len(state.csv_extractions),
            "kv_extractions": len(state.kv_extractions),
            "xml_extractions": len(state.xml_extractions),
        }
        truncated_keys = sorted(key for key, total in totals.items() if total > SUMMARY_SAMPLE_LIMIT)
        compact_summary: CompactAnalysisSummaryDict = {
            "compact_summary": {"limit": SUMMARY_SAMPLE_LIMIT, "truncated_keys": truncated_keys},
            "udm_fields": udm_fields,
            "udm_fields_total": udm_fields_total,
            "output_anchors": [a.to_json() for a in output_anchors[:SUMMARY_SAMPLE_LIMIT]],
            "unsupported": unsupported[:SUMMARY_SAMPLE_LIMIT],
            "warnings": warnings[:SUMMARY_SAMPLE_LIMIT],
            "structured_warnings": [w.to_json() for w in structured_warnings[:SUMMARY_SAMPLE_LIMIT]],
            "diagnostics": [d.to_json() for d in diagnostics[:SUMMARY_SAMPLE_LIMIT]],
            "taints": taint_sample,
            "token_count": len(state.tokens),
            "json_extractions": [h.to_json() for h in state.json_extractions[:SUMMARY_SAMPLE_LIMIT]],
            "csv_extractions": [h.to_json() for h in state.csv_extractions[:SUMMARY_SAMPLE_LIMIT]],
            "kv_extractions": [h.to_json() for h in state.kv_extractions[:SUMMARY_SAMPLE_LIMIT]],
            "xml_extractions": [h.to_json() for h in state.xml_extractions[:SUMMARY_SAMPLE_LIMIT]],
            "warning_counts": dict(warning_counts),
            "taint_counts": taint_counts,
            "diagnostic_counts": dict(Counter(d.code for d in diagnostics)),
            "unsupported_total": totals["unsupported"],
            "warnings_total": totals["warnings"],
            "structured_warnings_total": totals["structured_warnings"],
            "diagnostics_total": totals["diagnostics"],
            "taints_total": totals["taints"],
            "output_anchors_total": totals["output_anchors"],
            "json_extractions_total": totals["json_extractions"],
            "csv_extractions_total": totals["csv_extractions"],
            "kv_extractions_total": totals["kv_extractions"],
            "xml_extractions_total": totals["xml_extractions"],
        }
        return compact_summary

    def _summary_taint_sample_counts(self, state: AnalyzerState) -> tuple[list[JSONDict], int, dict[str, int]]:
        seen: set[tuple[object, ...]] = set()
        sample: list[JSONDict] = []
        counts: Counter[str] = Counter()
        total = 0

        def visit(taint: TaintReason) -> None:
            nonlocal total
            key = _taint_key(taint)
            if key in seen:
                return
            seen.add(key)
            counts[taint.code] += 1
            total += 1
            if len(sample) < SUMMARY_SAMPLE_LIMIT:
                sample.append(taint.to_json())

        for taint in state.taints:
            visit(taint)
        for lineages in state.tokens.values():
            for lin in lineages:
                for taint in lin.taints:
                    visit(taint)
        for code, count in state._suppressed_taint_counts.items():
            counts[code] += count
            total += count
        return sample, total, dict(counts)

    # ------------------------ query normalization ------------------------

    def _anchors_for_candidate(self, candidate: str, anchor_index: dict[str, list[OutputAnchor]]) -> list[OutputAnchor]:
        """Return all output anchors that emit a candidate field, if known."""
        anchors: list[OutputAnchor] = []
        exact = anchor_index.get(candidate)
        if exact:
            anchors.extend(exact)
        start = 0
        while True:
            dot = candidate.find(".", start)
            if dot == -1:
                return anchors
            prefix = candidate[:dot]
            prefixed = anchor_index.get(prefix)
            if prefixed:
                anchors.extend(prefixed)
            start = dot + 1

    def _dynamic_matches_for_candidate(
        self, candidate: str, state: AnalyzerState, *, limit: int | None = None
    ) -> tuple[list[Lineage], int, list[DiagnosticRecord], QuerySemanticSummary]:
        """Return dynamic destination lineages whose literal template can match a concrete query.

        Example: a parser writes to ``event...request_headers.%{k}``. A query for
        ``event...request_headers.User-Agent`` should still return the dynamic
        lineage with a warning/note rather than unresolved.
        """
        if not _state_has_dynamic_templates(state):
            return [], 0, [], QuerySemanticSummary()
        matches: list[Lineage] = []
        total = 0
        diagnostics: list[DiagnosticRecord] = []
        semantic_summary = QuerySemanticSummary()
        for token in state.dynamic_template_tokens(candidate):
            lineages = state.tokens.get(token, [])
            try:
                if not state.dynamic_template_matches(token, candidate):
                    continue
            except re.error:
                diagnostics.append(
                    DiagnosticRecord(
                        code="dynamic_template_regex",
                        kind="warning",
                        message=f"Dynamic destination template {token!r} could not be matched as a regex.",
                        source_token=token,
                        warning=f"Dynamic destination template could not be matched for query: {token}",
                    )
                )
                continue
            total += len(lineages)
            if lineages:
                semantic_summary = semantic_summary.with_lineages(lineages, statuses=("dynamic",))
            if limit is not None and len(matches) >= limit:
                continue
            for lin in lineages:
                if limit is not None and len(matches) >= limit:
                    break
                note = f"Concrete query matched dynamic destination template: {token}"
                matches.append(lin.with_status("dynamic").with_notes([note]))
        return _dedupe_lineages(matches), total, diagnostics, semantic_summary

    def _candidate_tokens(
        self, udm_field: str, state: AnalyzerState | None = None, anchors: list[OutputAnchor] | None = None
    ) -> list[str]:
        state = state or cast(_QueryContext, self).analyze()
        q = udm_field.strip()
        cands: list[str] = [q]

        # Use explicit output anchors. If no @output is present, assume the common
        # anchor name "event" for direct parser snippets.
        coalesced = anchors if anchors is not None else _coalesce_output_anchors(state.output_anchors)
        anchor_names = _dedupe_strings(a.anchor for a in coalesced) or ["event"]
        suffixes = _udm_suffixes(q)
        for anchor in anchor_names:
            for suffix in suffixes:
                if suffix.startswith(anchor + "."):
                    cands.append(suffix)
                else:
                    cands.append(f"{anchor}.{suffix}")
        # Also include the canonical event anchor.
        for suffix in suffixes:
            cands.append(f"event.{suffix}")
        return _dedupe_strings(cands)


def _state_has_dynamic_templates(state: AnalyzerState) -> bool:
    dynamic_index = getattr(state, "_dynamic_token_index", {})
    if any(tokens for tokens in dynamic_index.values()):
        return True
    literal_index = getattr(state, "_dynamic_token_literal_index", {})
    if any(tokens for literal_buckets in literal_index.values() for tokens in literal_buckets.values()):
        return True
    additions = getattr(state, "_dynamic_token_index_additions", {})
    return any(tokens for tokens in additions.values())


def _compact_udm_field_sample_total(
    state: AnalyzerState, anchors: list[OutputAnchor], *, limit: int
) -> tuple[list[str], int]:
    seen: set[str] = set()
    sample: list[str] = []
    anchor_names = set(_dedupe_strings(anchor.anchor for anchor in anchors))

    def add(field: str) -> None:
        if field in seen:
            return
        seen.add(field)
        if limit <= 0:
            return
        if len(sample) < limit:
            insort(sample, field)
        elif field < sample[-1]:
            sample.pop()
            insort(sample, field)

    for field in state.tokens:
        if not _looks_like_udm_field(field):
            continue
        add(field)
        start = 0
        while True:
            dot = field.find(".", start)
            if dot == -1:
                break
            prefix = field[:dot]
            if prefix in anchor_names:
                add("event." + field[dot + 1 :])
            start = dot + 1
    return sample, len(seen)


def _coalesce_output_anchors(anchors: list[OutputAnchor]) -> list[OutputAnchor]:
    grouped: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    order: list[tuple[str, tuple[str, ...]]] = []
    for anchor in anchors:
        key = (anchor.anchor, tuple(anchor.conditions))
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].extend(anchor.parser_locations)
    return [
        OutputAnchor(
            anchor=anchor, conditions=conditions, parser_locations=_dedupe_strings(grouped[(anchor, conditions)])
        )
        for anchor, conditions in order
    ]


def _anchor_prefix_index(anchors: list[OutputAnchor]) -> dict[str, list[OutputAnchor]]:
    index: dict[str, list[OutputAnchor]] = {}
    for anchor in anchors:
        index.setdefault(anchor.anchor, []).append(anchor)
    return index
