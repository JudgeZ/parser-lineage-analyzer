"""Pydantic models for plugin configuration validation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class _PluginConfig(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(extra="forbid", strict=True)


class JsonPluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    source: str = "message"
    target: str | None = None
    array_function: str | None = None


class XmlPluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    source: str = "message"
    xpath: list[object] = Field(default_factory=list)
    namespaces: list[object] = Field(default_factory=list)


class KvPluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    source: str = "message"
    target: str | None = None
    field_split: str | None = None
    value_split: str | None = None
    trim_value: str | None = None
    trim_key: str | None = None
    whitespace: str | None = None
    prefix: str | None = None
    include_keys: list[str] | None = None
    exclude_keys: list[str] | None = None
    allow_duplicate_values: bool | None = None


class CsvPluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    source: str = "message"
    separator: str = ","
    columns: list[str] | None = None


class GrokPluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    match: list[object] = Field(default_factory=list)
    pattern_definitions: list[object] = Field(default_factory=list)


class DissectPluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    mapping: list[object] = Field(default_factory=list)
    match: list[object] = Field(default_factory=list)


class DatePluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    match: list[object] | None = None
    target: str = "event.idm.read_only_udm.metadata.event_timestamp"
    timezone: str | None = None


class Base64PluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    source: str | None = None
    field: str | None = None
    fields: list[object] | str | None = None
    target: str | None = None
    encoding: str = "Standard"


class UrlDecodePluginConfig(_PluginConfig):  # type: ignore[explicit-any]
    source: str | None = None
    field: str | None = None
    fields: list[object] | str | None = None
    target: str | None = None


# F3 (PR-D): plugin signature registry — see parser_lineage_analyzer/
# _plugin_signatures.py for the loader and dispatch wiring. Without a
# matching signature, an unknown plugin invocation falls through to the
# ``unsupported_plugin`` taint path. With one, the dispatcher routes to a
# generic handler that reads ``source_keys`` / ``dest_keys`` from the
# plugin's config and produces signature-dispatched lineage tagged with
# the declared ``lineage_status`` and ``taint_hint``.
#
# Inherits ``_PluginConfig`` for parity with sibling models — that
# combines ``extra="forbid"`` (typos in semantic_class /
# lineage_status / taint_hint surface as loud ``ValidationError`` at
# TOML load time rather than silently degrading to UNKNOWN) with
# ``strict=True`` (no implicit type coercion on ``in_place: bool``,
# etc.).
class PluginSignature(_PluginConfig):  # type: ignore[explicit-any]
    name: str
    semantic_class: Literal["extractor", "enricher", "transform", "mutate_like", "passthrough"]
    source_keys: list[str] = Field(default_factory=list)
    dest_keys: list[str] = Field(default_factory=list)
    dest_value_kind: Literal["scalar", "map", "list"] = "scalar"
    in_place: bool = False
    lineage_status: Literal["exact", "derived", "dynamic", "conditional"] = "derived"
    taint_hint: Literal["none", "derived", "dynamic"] = "derived"


def compact_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ())) or "config"
        parts.append(f"{loc}: {err.get('msg', 'invalid value')}")
    return "; ".join(parts) if parts else str(exc).splitlines()[0]
