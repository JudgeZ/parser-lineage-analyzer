"""Internal compatibility shim for shared reverse-lineage analysis helpers.

The underscore modules remain private implementation modules. This shim keeps
older internal imports stable while the helpers are split across smaller files.
"""

from __future__ import annotations

import json
import re
from typing import cast

from ._analysis_conditions import (
    MAX_EXACT_PRIOR_NEGATIONS,
    _add_conditions,
    _clean_condition,
    _lineages_with_anchor_conditions,
    _prior_negation_conditions,
)
from ._analysis_dedupe import (
    _anchor_key,
    _dedupe_anchors,
    _dedupe_diagnostics,
    _dedupe_hints,
    _dedupe_lineages,
    _dedupe_sources,
    _dedupe_strings,
    _dedupe_taints,
    _dedupe_warning_reasons,
    _diagnostic_key,
    _freeze_value,
    _hint_key,
    _lineage_key,
    _source_key,
    _taint_key,
    _warning_key,
)
from ._analysis_members import (
    _append_member_path,
    _member_sources_from_ref,
    _path_from_iterable,
    _source_ref_from_dict,
    _status_for_sources,
)
from ._analysis_paths import (
    _has_nested_token_reference,
    _is_path_char,
    _is_plausible_data_path,
    _is_plausible_kv_key,
    _looks_like_enum_constant,
    _looks_like_udm_field,
    _normalize_field_ref,
    _starts_identifier,
    _strip_ref,
    _udm_suffixes,
)
from ._types import ConfigValue
from .config_parser import as_pairs
from .model import Lineage

_TOKEN_REF_RE = re.compile(r"%\{([^}]+)\}")
_GROK_NAMED_RE = re.compile(
    r"%\{(?P<pattern>[A-Za-z0-9_]+)(?::(?P<token>[A-Za-z_@][A-Za-z0-9_@.-]*))?(?::(?P<type>[^}]*))?\}"
)
_REGEX_NAMED_RE = re.compile(r"\(\?(?:P)?<(?P<token>[A-Za-z_@][A-Za-z0-9_@.:-]*)>")
_DISSECT_FIELD_RE = re.compile(r"%\{(?P<raw>[^}]*)\}")
_COLUMN_RE = re.compile(r"^column(?P<num>\d+)$")
MAX_TEMPLATE_COMBINATIONS = 1024


def _location(line: int, op: str, detail: str = "") -> str:
    return f"line {line}: {op}{(' ' + detail) if detail else ''}"


def _flatten_scalars(value: object) -> list[object]:
    """Flatten nested arrays while preserving map/pair objects as scalars."""
    if isinstance(value, list) and not as_pairs(cast(ConfigValue, value)):
        out: list[object] = []
        for item in value:
            out.extend(_flatten_scalars(item))
        return out
    return [value]


def _stable_value_repr(value: object) -> str:
    """Deterministic compact representation for config containers."""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _static_lineage_value(lineage: Lineage) -> str | None:
    """Return a concrete template value when lineage is a literal on all paths."""
    if getattr(lineage, "status", None) not in {"constant", "conditional"}:
        return None
    sources = tuple(getattr(lineage, "sources", ()) or ())
    if sources and not all(
        getattr(src, "kind", None) == "constant" and getattr(src, "expression", None) is not None for src in sources
    ):
        return None
    value = getattr(lineage, "expression", None)
    if value is None and sources:
        value = getattr(sources[0], "expression", None)
    if value is None:
        return None
    value_s = str(value)
    if _TOKEN_REF_RE.search(value_s):
        return None
    return value_s


__all__ = [
    "MAX_EXACT_PRIOR_NEGATIONS",
    "MAX_TEMPLATE_COMBINATIONS",
    "_COLUMN_RE",
    "_DISSECT_FIELD_RE",
    "_GROK_NAMED_RE",
    "_REGEX_NAMED_RE",
    "_TOKEN_REF_RE",
    "_add_conditions",
    "_anchor_key",
    "_append_member_path",
    "_clean_condition",
    "_dedupe_anchors",
    "_dedupe_diagnostics",
    "_dedupe_hints",
    "_dedupe_lineages",
    "_dedupe_sources",
    "_dedupe_strings",
    "_dedupe_taints",
    "_dedupe_warning_reasons",
    "_flatten_scalars",
    "_freeze_value",
    "_has_nested_token_reference",
    "_hint_key",
    "_diagnostic_key",
    "_is_path_char",
    "_is_plausible_data_path",
    "_is_plausible_kv_key",
    "_lineage_key",
    "_lineages_with_anchor_conditions",
    "_location",
    "_looks_like_enum_constant",
    "_looks_like_udm_field",
    "_member_sources_from_ref",
    "_normalize_field_ref",
    "_path_from_iterable",
    "_prior_negation_conditions",
    "_source_key",
    "_taint_key",
    "_warning_key",
    "_source_ref_from_dict",
    "_stable_value_repr",
    "_static_lineage_value",
    "_starts_identifier",
    "_status_for_sources",
    "_strip_ref",
    "_udm_suffixes",
]
