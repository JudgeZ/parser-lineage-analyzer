"""Pydantic models for plugin configuration validation."""
# mypy: disable-error-code="explicit-any"

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class _PluginConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class JsonPluginConfig(_PluginConfig):
    source: str = "message"
    target: str | None = None
    array_function: str | None = None


class XmlPluginConfig(_PluginConfig):
    source: str = "message"
    xpath: list[object] = Field(default_factory=list)
    namespaces: list[object] = Field(default_factory=list)


class KvPluginConfig(_PluginConfig):
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


class CsvPluginConfig(_PluginConfig):
    source: str = "message"
    separator: str = ","
    columns: list[str] | None = None


class GrokPluginConfig(_PluginConfig):
    match: list[object] = Field(default_factory=list)
    pattern_definitions: list[object] = Field(default_factory=list)


class DissectPluginConfig(_PluginConfig):
    mapping: list[object] = Field(default_factory=list)
    match: list[object] = Field(default_factory=list)


class DatePluginConfig(_PluginConfig):
    match: list[object] | None = None
    target: str = "event.idm.read_only_udm.metadata.event_timestamp"
    timezone: str | None = None


class Base64PluginConfig(_PluginConfig):
    source: str | None = None
    field: str | None = None
    fields: list[object] | str | None = None
    target: str | None = None
    encoding: str = "Standard"


class UrlDecodePluginConfig(_PluginConfig):
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
# ``extra="forbid"`` keeps typos in semantic_class / lineage_status /
# taint_hint loud — they surface at TOML load time as
# ``ValidationError`` rather than silently degrading to UNKNOWN.
class PluginSignature(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
