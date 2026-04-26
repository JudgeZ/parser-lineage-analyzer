"""Internal factories for SourceRef.details payloads and common notes."""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from ._types import ConfigPair, ConfigValue, JSONDict, JSONValue
from .model import SourceRef


def source_refs_json(sources: Iterable[SourceRef]) -> list[JSONDict]:
    return [src.to_json() for src in sources]


def iterable_sources_details(sources: Iterable[SourceRef]) -> JSONDict:
    return {"iterable_sources": source_refs_json(sources)}


def loop_tuple_details(sources: Iterable[SourceRef], position: int) -> JSONDict:
    details = iterable_sources_details(sources)
    details["tuple_position"] = position
    return details


def capture_upstream_details(sources: Iterable[SourceRef]) -> JSONDict:
    return {"upstream_sources": source_refs_json(sources)}


def json_extraction_details(array_function: ConfigValue | None, target: ConfigValue | None, line: int) -> JSONDict:
    return {"array_function": array_function, "target": target, "line": line}


def kv_extraction_details(config: list[ConfigPair], line: int) -> JSONDict:
    captured_keys = {
        "field_split",
        "value_split",
        "whitespace",
        "trim_value",
        "trim_key",
        "target",
        "prefix",
        "include_keys",
        "exclude_keys",
        "allow_duplicate_values",
    }
    details: JSONDict = {k: cast(JSONValue, v) for k, v in config if k in captured_keys}
    details["line"] = line
    return details


def csv_extraction_details(separator: ConfigValue | None, columns: ConfigValue | None, line: int) -> JSONDict:
    return {"separator": separator, "columns": columns, "line": line}


def csv_column_details(separator: ConfigValue | None, column_name: str) -> JSONDict:
    return {"separator": separator, "column_name": column_name}


def xml_line_details(line: int) -> JSONDict:
    return {"line": line}


def xml_template_details(raw_path: str, normalized_path: str) -> JSONDict:
    return {"template": raw_path} if normalized_path != raw_path else {}


def loop_member_details(src: SourceRef, upstream: SourceRef) -> JSONDict:
    return {"from_loop_item": src.to_json(), "upstream_source": upstream.to_json()}


def map_member_details(src: SourceRef, upstream: SourceRef) -> JSONDict:
    return {"from_map_member": src.to_json(), "upstream_source": upstream.to_json()}


OBJECT_LITERAL_NOTE = "Object literal/config map value."
OBJECT_LITERAL_MERGED_NOTE = "Object literal/config map value merged."
ERROR_FLAG_NOTE = "Boolean runtime flag set by parser error handling."


def removed_field_note(token: str) -> str:
    return f"Removed by remove_field {token}"
