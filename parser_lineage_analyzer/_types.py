"""Shared recursive type aliases for parser/config payloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

JSONValue = None | bool | int | float | str | Sequence["JSONValue"] | Mapping[str, "JSONValue"]
JSONDict = dict[str, JSONValue]
FrozenJSONValue = JSONValue
FrozenJSONDict = Mapping[str, FrozenJSONValue]

ConfigValue = str | bool | list["ConfigValue"] | list[tuple[str, "ConfigValue"]]
ConfigPair = tuple[str, ConfigValue]
