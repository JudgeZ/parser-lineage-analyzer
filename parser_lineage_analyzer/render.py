"""Human-readable rendering for reverse-lineage query results."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from heapq import nsmallest
from typing import TypeVar, cast

from ._types import JSONDict, JSONValue
from .model import Lineage, QueryResult, TaintReason

COMPACT_JSON_SAMPLE_LIMIT = 50
_T = TypeVar("_T")

# C0 control characters (0x00-0x1F) and DEL (0x7F) in echoed parser content
# can spoof terminal output (\r line-clobbering, ANSI escapes recoloring or
# embedding hyperlinks). Tab and newline are preserved; everything else in
# the C0 range and DEL collapse to a single space so log/CI consumers see a
# benign placeholder rather than the original byte. JSON output is unaffected
# because ``json.dumps`` already escapes control characters.
_CONTROL_CHAR_TRANSLATE: dict[int, str] = {i: " " for i in range(0, 32) if i not in (0x09, 0x0A)}
_CONTROL_CHAR_TRANSLATE[0x7F] = " "


def sanitize_for_terminal(text: str) -> str:
    """Replace C0 control characters (except tab/newline) and DEL with a space."""
    return text.translate(_CONTROL_CHAR_TRANSLATE)


def _format_detail_value(value: object) -> str:
    """Render a SourceRef detail value without leaking Python repr punctuation."""
    if isinstance(value, str):
        return sanitize_for_terminal(value)
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return json.dumps(value)
    return sanitize_for_terminal(json.dumps(value, sort_keys=True))


def _clamp_limit(limit: int | None, *, max_limit: int | None = None) -> int | None:
    if limit is None:
        return None
    clamped = max(0, limit)
    if max_limit is not None:
        clamped = min(clamped, max_limit)
    return clamped


def _limited(items: Sequence[_T], limit: int | None) -> Sequence[_T]:
    return items if limit is None else items[:limit]


def _taint_sort_key(taint: TaintReason) -> tuple[str, str, str, str]:
    return (taint.code, taint.parser_location or "", taint.source_token or "", taint.message)


def _ordered_taints_for_limit(taints: Sequence[TaintReason], limit: int | None) -> Sequence[TaintReason]:
    if limit is None:
        return sorted(taints, key=_taint_sort_key)
    return nsmallest(limit, taints, key=_taint_sort_key)


def _add_limited_json_sequence(
    out: JSONDict,
    key: str,
    items: Sequence[_T],
    limit: int,
    *,
    encode: Callable[[_T], JSONValue] | None = None,
) -> None:
    limited = items[:limit]
    if encode is None:
        out[key] = cast(JSONValue, list(limited))
    else:
        out[key] = cast(JSONValue, [encode(item) for item in limited])
    out[f"{key}_total"] = len(items)
    out[f"{key}_omitted"] = len(items) - len(limited)


def _append_omitted(
    lines: list[str],
    indent: str,
    omitted: int,
    singular: str,
    plural: str | None = None,
    *,
    limit: int | None,
    sampled: bool = False,
) -> None:
    if limit is None and not sampled:
        return
    if omitted <= 0:
        return
    label = singular if omitted == 1 else (plural or f"{singular}s")
    lines.append(f"{indent}... {omitted} more {label} omitted")


def render_text(result: QueryResult, *, verbose: bool = False, limit: int | None = None) -> str:
    render_limit = _clamp_limit(limit)
    lines: list[str] = []
    lines.append(f"UDM field: {result.udm_field}")
    lines.append(f"Status: {result.status}")
    lines.append("")
    if result.output_anchors:
        anchors_to_render = _limited(result.output_anchors, render_limit)
        anchors = ", ".join(a.anchor for a in anchors_to_render)
        lines.append(f"Output anchors: {anchors}")
        _append_omitted(
            lines, "  ", len(result.output_anchors) - len(anchors_to_render), "output anchor", limit=render_limit
        )
    lines.append("Candidate parser fields checked:")
    candidates = _limited(result.normalized_candidates, render_limit)
    for cand in candidates:
        lines.append(f"  - {cand}")
    _append_omitted(
        lines,
        "  ",
        result.total_normalized_candidates - len(candidates),
        "candidate parser field",
        limit=render_limit,
        sampled=result.normalized_candidates_total is not None,
    )
    lines.append("")

    if not result.mappings and result.total_mappings <= 0:
        lines.append("No mappings found.")
    else:
        lines.append("Mappings:")
        mappings = _limited(result.mappings, render_limit)
        for idx, mapping in enumerate(mappings, 1):
            if idx == 1:
                lines.append(f"  [{idx}] status={mapping.status}")
            else:
                lines.append("")
                lines.append(f"  [{idx}] status={mapping.status}")
            if mapping.expression is not None:
                lines.append(f"      expression: {mapping.expression}")
            if mapping.sources:
                lines.append("      sources:")
                sources = _limited(mapping.sources, render_limit)
                for src in sources:
                    lines.append(f"        - {src.short()}")
                    details = src.to_json()
                    detail_keys: tuple[str, ...] = ("source_token", "path", "capture_name", "column", "pattern")
                    if verbose:
                        detail_keys = tuple(k for k in details if k != "kind")
                    for key in detail_keys:
                        if key not in details:
                            continue
                        value = details[key]
                        if value is None or value == "" or value == [] or value == {}:
                            continue
                        lines.append(f"          {key}: {_format_detail_value(value)}")
                _append_omitted(lines, "        ", len(mapping.sources) - len(sources), "source", limit=render_limit)
            if mapping.conditions:
                lines.append("      conditions:")
                conditions = _limited(mapping.conditions, render_limit)
                for cond in conditions:
                    lines.append(f"        - {cond}")
                _append_omitted(
                    lines, "        ", len(mapping.conditions) - len(conditions), "condition", limit=render_limit
                )
            if mapping.transformations:
                lines.append("      transformations:")
                transformations = _limited(mapping.transformations, render_limit)
                for t in transformations:
                    lines.append(f"        - {t}")
                _append_omitted(
                    lines,
                    "        ",
                    len(mapping.transformations) - len(transformations),
                    "transformation",
                    limit=render_limit,
                )
            if mapping.parser_locations and verbose:
                lines.append("      parser locations:")
                parser_locations = _limited(mapping.parser_locations, render_limit)
                for loc in parser_locations:
                    lines.append(f"        - {loc}")
                _append_omitted(
                    lines,
                    "        ",
                    len(mapping.parser_locations) - len(parser_locations),
                    "parser location",
                    limit=render_limit,
                )
            if mapping.notes and verbose:
                lines.append("      notes:")
                notes = _limited(mapping.notes, render_limit)
                for note in notes:
                    lines.append(f"        - {note}")
                _append_omitted(lines, "        ", len(mapping.notes) - len(notes), "note", limit=render_limit)
            if mapping.taints:
                lines.append("      taints:")
                taints_to_render = _ordered_taints_for_limit(mapping.taints, render_limit)
                for taint in taints_to_render:
                    detail = f"{taint.code}: {taint.message}"
                    if verbose and taint.parser_location:
                        detail += f" ({taint.parser_location})"
                    if verbose and taint.source_token:
                        detail += f" source={taint.source_token}"
                    lines.append(f"        - {detail}")
                _append_omitted(
                    lines, "        ", len(mapping.taints) - len(taints_to_render), "taint", limit=render_limit
                )
        _append_omitted(
            lines,
            "  ",
            result.total_mappings - len(mappings),
            "mapping",
            limit=render_limit,
            sampled=result.mappings_total is not None,
        )

    if result.unsupported:
        lines.append("\nUnsupported or partially parsed constructs:")
        unsupported = _limited(result.unsupported, render_limit)
        for item in unsupported:
            lines.append(f"  - {item}")
        _append_omitted(lines, "  ", len(result.unsupported) - len(unsupported), "unsupported item", limit=render_limit)
    if result.warnings:
        lines.append("\nWarnings:")
        warnings = _limited(result.warnings, render_limit)
        for item in warnings:
            lines.append(f"  - {item}")
        _append_omitted(lines, "  ", len(result.warnings) - len(warnings), "warning", limit=render_limit)
    if result.structured_warnings and verbose:
        lines.append("\nStructured warnings:")
        structured_warnings = _limited(result.structured_warnings, render_limit)
        for warning in structured_warnings:
            detail = f"{warning.code}: {warning.message}"
            if warning.parser_location:
                detail += f" ({warning.parser_location})"
            if warning.source_token:
                detail += f" source={warning.source_token}"
            lines.append(f"  - {detail}")
        _append_omitted(
            lines,
            "  ",
            len(result.structured_warnings) - len(structured_warnings),
            "structured warning",
            limit=render_limit,
        )
    diagnostics = result.effective_diagnostics
    if diagnostics and verbose:
        lines.append("\nDiagnostics:")
        diagnostics_to_render = _limited(diagnostics, render_limit)
        for diagnostic in diagnostics_to_render:
            detail = f"{diagnostic.code}: {diagnostic.message}"
            if diagnostic.kind:
                detail += f" [{diagnostic.kind}]"
            if diagnostic.parser_location:
                detail += f" ({diagnostic.parser_location})"
            if diagnostic.source_token:
                detail += f" source={diagnostic.source_token}"
            lines.append(f"  - {detail}")
        _append_omitted(lines, "  ", len(diagnostics) - len(diagnostics_to_render), "diagnostic", limit=render_limit)
    return sanitize_for_terminal("\n".join(lines))


def render_json(result: QueryResult) -> str:
    return json.dumps(result.to_json(), indent=2, sort_keys=False)


def _compact_mapping_json(mapping: Lineage, limit: int) -> JSONDict:
    out: JSONDict = {
        "status": mapping.status,
    }
    _add_limited_json_sequence(out, "sources", mapping.sources, limit, encode=lambda source: source.to_json())
    if mapping.expression is not None:
        out["expression"] = mapping.expression
    if mapping.transformations:
        _add_limited_json_sequence(out, "transformations", mapping.transformations, limit)
    if mapping.conditions:
        _add_limited_json_sequence(out, "conditions", mapping.conditions, limit)
    if mapping.parser_locations:
        _add_limited_json_sequence(out, "parser_locations", mapping.parser_locations, limit)
    if mapping.notes:
        _add_limited_json_sequence(out, "notes", mapping.notes, limit)
    if mapping.taints:
        taints = _ordered_taints_for_limit(mapping.taints, limit)
        out["taints"] = [taint.to_json() for taint in taints]
        out["taints_total"] = len(mapping.taints)
        omitted = len(mapping.taints) - len(taints)
        out["taints_omitted"] = omitted
    return out


def render_compact_json(result: QueryResult, *, limit: int = COMPACT_JSON_SAMPLE_LIMIT) -> str:
    compact_limit = _clamp_limit(limit, max_limit=COMPACT_JSON_SAMPLE_LIMIT)
    if compact_limit is None:
        compact_limit = COMPACT_JSON_SAMPLE_LIMIT
    # Compute the aggregate once and reuse it for status/is_conditional/has_*
    # plus the diagnostics derivation. Going through the public properties
    # (result.status, result.is_conditional, ...) would re-derive the same
    # aggregate six times per render — measurable on high-cardinality output.
    # ``_aggregate`` and ``_effective_diagnostics`` are intentionally kept
    # package-internal: callers outside this package should use the public
    # properties (``status``, ``is_conditional``, ``effective_diagnostics``).
    aggregate = result._aggregate()
    diagnostics = result._effective_diagnostics(aggregate)
    data = {
        "udm_field": result.udm_field,
        "status": aggregate.status,
        "is_conditional": aggregate.is_conditional,
        "has_dynamic": aggregate.has_dynamic,
        "has_unresolved": aggregate.has_unresolved,
        "has_taints": aggregate.has_taints,
        "normalized_candidates": result.normalized_candidates[:compact_limit],
        "normalized_candidates_total": result.total_normalized_candidates,
        "mappings": [_compact_mapping_json(mapping, compact_limit) for mapping in result.mappings[:compact_limit]],
        "mappings_total": result.total_mappings,
        "output_anchors": [anchor.to_json() for anchor in result.output_anchors[:compact_limit]],
        "output_anchors_total": len(result.output_anchors),
        "unsupported": result.unsupported[:compact_limit],
        "unsupported_total": len(result.unsupported),
        "warnings": result.warnings[:compact_limit],
        "warnings_total": len(result.warnings),
        "structured_warnings": [warning.to_json() for warning in result.structured_warnings[:compact_limit]],
        "structured_warnings_total": len(result.structured_warnings),
        "diagnostics": [diagnostic.to_json() for diagnostic in diagnostics[:compact_limit]],
        "diagnostics_total": len(diagnostics),
    }
    return json.dumps(data, indent=2, sort_keys=False)
