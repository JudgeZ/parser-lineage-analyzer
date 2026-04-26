"""Source path and member-derivation helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from ._analysis_dedupe import _dedupe_sources
from ._analysis_details import loop_member_details, map_member_details
from ._types import JSONDict
from .model import LineageStatus, SourceRef


def _status_for_sources(sources: list[SourceRef]) -> LineageStatus:
    if not sources:
        return "unresolved"
    kinds = {src.kind for src in sources}
    if kinds == {"constant"}:
        return "constant"
    if kinds <= {"grok_capture", "regex_capture", "dissect_field"}:
        return "exact_capture"
    if kinds <= {
        "json_path",
        "xml_xpath",
        "kv_key",
        "csv_column",
        "raw_message",
        "raw_token",
        "loop_item",
        "map_key",
        "map_value",
    }:
        return "exact"
    if kinds == {"unknown"}:
        return "unresolved"
    if len(sources) > 1:
        return "derived"
    kind = next(iter(kinds))
    if kind == "constant":
        return "constant"
    if kind in {"grok_capture", "regex_capture", "dissect_field"}:
        return "exact_capture"
    if kind in {
        "json_path",
        "xml_xpath",
        "kv_key",
        "csv_column",
        "raw_message",
        "raw_token",
        "loop_item",
        "map_key",
        "map_value",
    }:
        return "exact"
    if kind == "unknown":
        return "unresolved"
    return "derived"


def _path_from_iterable(iterable: str, sources: list[SourceRef], array: bool = False, map_entry: bool = False) -> str:
    base: str | None = None
    for src in sources:
        if src.path:
            base = src.path
            break
    if not base:
        base = iterable
    if array:
        return base if base.endswith("[*]") else f"{base}[*]"
    if map_entry:
        return base if base.endswith(".*") else f"{base}.*"
    return base


def _append_member_path(base_path: str | None, suffix: str, array: bool = False, map_entry: bool = False) -> str | None:
    if not base_path:
        return None
    base = base_path
    if array and not base.endswith("[*]"):
        base = f"{base}[*]"
    if map_entry and not base.endswith(".*"):
        base = f"{base}.*"
    return f"{base}.{suffix}" if suffix else base


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _source_ref_from_dict(data: Mapping[str, object]) -> SourceRef:
    raw_details = data.get("details")
    return SourceRef(
        kind=str(data.get("kind", "")),
        source_token=_optional_str(data.get("source_token")),
        path=_optional_str(data.get("path")),
        capture_name=_optional_str(data.get("capture_name")),
        column=_optional_int(data.get("column")),
        pattern=_optional_str(data.get("pattern")),
        expression=_optional_str(data.get("expression")),
        details=cast(JSONDict, raw_details) if isinstance(raw_details, Mapping) else {},
    )


def _member_sources_from_ref(src: SourceRef, suffix: str) -> list[SourceRef]:
    out: list[SourceRef] = []

    raw_upstream = src.details.get("iterable_sources", []) if src.details else []
    upstream_dicts = raw_upstream if isinstance(raw_upstream, Sequence) and not isinstance(raw_upstream, str) else []
    upstream_sources: list[SourceRef] = []
    for raw in upstream_dicts:
        if isinstance(raw, Mapping) and raw.get("kind"):
            upstream_sources.append(_source_ref_from_dict(raw))

    if src.kind == "loop_item":
        if upstream_sources:
            for up in upstream_sources:
                member_path = _append_member_path(up.path or src.path, suffix, array=True)
                if not member_path:
                    continue
                out.append(
                    SourceRef(
                        kind="json_path" if up.kind == "json_path" else src.kind,
                        source_token=up.source_token or src.source_token,
                        path=member_path,
                        details=loop_member_details(src, up),
                    )
                )
        else:
            member_path = _append_member_path(src.path or src.source_token, suffix)
            if member_path:
                out.append(
                    SourceRef(kind="loop_item", source_token=src.source_token, path=member_path, details=src.details)
                )

    elif src.kind in {"map_value", "map_key"}:
        if upstream_sources:
            for up in upstream_sources:
                member_path = _append_member_path(up.path or src.path, suffix, map_entry=True)
                if not member_path:
                    continue
                out.append(
                    SourceRef(
                        kind="json_path" if up.kind in {"json_path", "loop_item", "map_value"} else src.kind,
                        source_token=up.source_token or src.source_token,
                        path=member_path,
                        details=map_member_details(src, up),
                    )
                )
        else:
            member_path = _append_member_path(src.path or src.source_token, suffix)
            if member_path:
                out.append(
                    SourceRef(kind=src.kind, source_token=src.source_token, path=member_path, details=src.details)
                )

    elif src.kind == "json_path":
        member_path = _append_member_path(src.path, suffix)
        if member_path:
            out.append(
                SourceRef(kind="json_path", source_token=src.source_token, path=member_path, details=src.details)
            )

    return _dedupe_sources(out)
