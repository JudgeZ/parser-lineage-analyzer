"""Pydantic models for plugin configuration validation."""
# mypy: disable-error-code="explicit-any"

from __future__ import annotations

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


def compact_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ())) or "config"
        parts.append(f"{loc}: {err.get('msg', 'invalid value')}")
    return "; ".join(parts) if parts else str(exc).splitlines()[0]
