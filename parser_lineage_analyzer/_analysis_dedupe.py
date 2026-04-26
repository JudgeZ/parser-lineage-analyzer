"""Tuple-key dedupe helpers for analysis objects."""

from __future__ import annotations

import contextlib
import importlib
import os
from collections.abc import Callable, Iterable
from typing import Protocol, TypeVar, cast

from .model import (
    DiagnosticRecord,
    Lineage,
    OutputAnchor,
    SourceRef,
    TaintReason,
    WarningReason,
    _freeze_for_key as _freeze_value_python,
)

Key = tuple[object, ...]


class _HintLike(Protocol):
    @property
    def kind(self) -> str: ...

    @property
    def source_token(self) -> str: ...

    @property
    def details(self) -> object: ...

    @property
    def conditions(self) -> Iterable[str]: ...

    @property
    def parser_locations(self) -> Iterable[str]: ...

    @property
    def source_resolved(self) -> bool: ...


Hint = TypeVar("Hint", bound=_HintLike)


def _source_key_python(src: SourceRef) -> Key:
    cached = getattr(src, "_analysis_key", None)
    if cached is not None:
        return cast(Key, cached)
    key = (
        src.kind,
        src.source_token,
        src.path,
        src.capture_name,
        src.column,
        src.pattern,
        src.expression,
        _freeze_value_python(src.details),
    )
    object.__setattr__(src, "_analysis_key", key)
    return key


def _taint_key_python(taint: TaintReason) -> Key:
    cached = getattr(taint, "_analysis_key", None)
    if cached is not None:
        return cast(Key, cached)
    key = (taint.code, taint.parser_location, taint.source_token, taint.message)
    object.__setattr__(taint, "_analysis_key", key)
    return key


def _warning_key_python(warning: WarningReason) -> Key:
    cached = getattr(warning, "_analysis_key", None)
    if cached is not None:
        return cast(Key, cached)
    key = (warning.code, warning.parser_location, warning.source_token, warning.message, warning.warning)
    object.__setattr__(warning, "_analysis_key", key)
    return key


def _diagnostic_key_python(diagnostic: DiagnosticRecord) -> Key:
    cached = getattr(diagnostic, "_analysis_key", None)
    if cached is not None:
        return cast(Key, cached)
    taint_key = _taint_key_python(diagnostic.taint) if diagnostic.taint else None
    key = (
        diagnostic.code,
        diagnostic.kind,
        diagnostic.parser_location,
        diagnostic.source_token,
        diagnostic.message,
        diagnostic.warning,
        diagnostic.unsupported,
        taint_key,
        diagnostic.strict,
    )
    object.__setattr__(diagnostic, "_analysis_key", key)
    return key


def _lineage_key_python(lin: Lineage) -> Key:
    cached = getattr(lin, "_analysis_key", None)
    if cached is not None:
        return cast(Key, cached)
    key = (
        lin.status,
        tuple(_source_key_python(src) for src in lin.sources),
        lin.expression,
        tuple(lin.transformations),
        tuple(lin.conditions),
        tuple(lin.parser_locations),
        tuple(lin.notes),
        tuple(_taint_key_python(taint) for taint in lin.taints),
    )
    object.__setattr__(lin, "_analysis_key", key)
    return key


def _anchor_key_python(anchor: OutputAnchor) -> Key:
    return (anchor.anchor, tuple(anchor.conditions), tuple(anchor.parser_locations))


def _hint_key_python(hint: _HintLike) -> Key:
    cached = getattr(hint, "_analysis_key", None)
    if cached is not None:
        return cast(Key, cached)
    key = (
        hint.kind,
        hint.source_token,
        _freeze_value_python(hint.details),
        tuple(hint.conditions),
        tuple(hint.parser_locations),
        hint.source_resolved,
    )
    with contextlib.suppress(AttributeError, TypeError):
        object.__setattr__(hint, "_analysis_key", key)
    return key


def _dedupe_lineages_python(lineages: Iterable[Lineage]) -> list[Lineage]:
    seen: set[Key] = set()
    out: list[Lineage] = []
    for lin in lineages:
        key = _lineage_key_python(lin)
        if key not in seen:
            seen.add(key)
            out.append(lin)
    return out


def _dedupe_sources_python(sources: Iterable[SourceRef]) -> list[SourceRef]:
    seen: set[Key] = set()
    out: list[SourceRef] = []
    for src in sources:
        key = _source_key_python(src)
        if key not in seen:
            seen.add(key)
            out.append(src)
    return out


def _dedupe_taints_python(taints: Iterable[TaintReason]) -> list[TaintReason]:
    seen: set[Key] = set()
    out: list[TaintReason] = []
    for taint in taints:
        key = _taint_key_python(taint)
        if key not in seen:
            seen.add(key)
            out.append(taint)
    return out


def _dedupe_warning_reasons_python(warnings: Iterable[WarningReason]) -> list[WarningReason]:
    seen: set[Key] = set()
    out: list[WarningReason] = []
    for warning in warnings:
        key = _warning_key_python(warning)
        if key not in seen:
            seen.add(key)
            out.append(warning)
    return out


def _dedupe_diagnostics_python(diagnostics: Iterable[DiagnosticRecord]) -> list[DiagnosticRecord]:
    seen: set[Key] = set()
    out: list[DiagnosticRecord] = []
    for diagnostic in diagnostics:
        key = _diagnostic_key_python(diagnostic)
        if key not in seen:
            seen.add(key)
            out.append(diagnostic)
    return out


def _dedupe_hints_python(hints: Iterable[Hint]) -> list[Hint]:
    seen: set[Key] = set()
    out: list[Hint] = []
    for h in hints:
        key = _hint_key_python(h)
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def _dedupe_anchors_python(anchors: Iterable[OutputAnchor]) -> list[OutputAnchor]:
    seen: set[Key] = set()
    out: list[OutputAnchor] = []
    for a in anchors:
        key = _anchor_key_python(a)
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out


def _dedupe_strings_python(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


_freeze_value: Callable[[object], object] = _freeze_value_python
_source_key: Callable[[SourceRef], Key] = _source_key_python
_taint_key: Callable[[TaintReason], Key] = _taint_key_python
_warning_key: Callable[[WarningReason], Key] = _warning_key_python
_diagnostic_key: Callable[[DiagnosticRecord], Key] = _diagnostic_key_python
_lineage_key: Callable[[Lineage], Key] = _lineage_key_python
_anchor_key: Callable[[OutputAnchor], Key] = _anchor_key_python
_hint_key: Callable[[_HintLike], Key] = _hint_key_python
_dedupe_lineages: Callable[[Iterable[Lineage]], list[Lineage]] = _dedupe_lineages_python
_dedupe_sources: Callable[[Iterable[SourceRef]], list[SourceRef]] = _dedupe_sources_python
_dedupe_taints: Callable[[Iterable[TaintReason]], list[TaintReason]] = _dedupe_taints_python
_dedupe_warning_reasons: Callable[[Iterable[WarningReason]], list[WarningReason]] = _dedupe_warning_reasons_python
_dedupe_diagnostics: Callable[[Iterable[DiagnosticRecord]], list[DiagnosticRecord]] = _dedupe_diagnostics_python
_dedupe_hints: Callable[[Iterable[Hint]], list[Hint]] = _dedupe_hints_python
_dedupe_anchors: Callable[[Iterable[OutputAnchor]], list[OutputAnchor]] = _dedupe_anchors_python
_dedupe_strings: Callable[[Iterable[str]], list[str]] = _dedupe_strings_python

_NATIVE_DEDUPE = None
if os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() not in {"1", "true", "yes", "on"}:
    try:
        _NATIVE_DEDUPE = importlib.import_module("parser_lineage_analyzer._native._dedupe_ext")
    except ImportError:
        _NATIVE_DEDUPE = None

_USE_NATIVE_DEDUPE = os.environ.get("PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE", "").lower() not in {
    "0",
    "false",
    "no",
    "off",
}

if _NATIVE_DEDUPE is not None and _USE_NATIVE_DEDUPE:
    _freeze_value = cast(Callable[[object], object], _NATIVE_DEDUPE._freeze_value)
    _source_key = cast(Callable[[SourceRef], Key], _NATIVE_DEDUPE._source_key)
    _taint_key = cast(Callable[[TaintReason], Key], _NATIVE_DEDUPE._taint_key)
    _warning_key = cast(Callable[[WarningReason], Key], _NATIVE_DEDUPE._warning_key)
    _diagnostic_key = cast(Callable[[DiagnosticRecord], Key], _NATIVE_DEDUPE._diagnostic_key)
    _lineage_key = cast(Callable[[Lineage], Key], _NATIVE_DEDUPE._lineage_key)
    _anchor_key = cast(Callable[[OutputAnchor], Key], _NATIVE_DEDUPE._anchor_key)
    _hint_key = cast(Callable[[_HintLike], Key], _NATIVE_DEDUPE._hint_key)
    _dedupe_lineages = cast(Callable[[Iterable[Lineage]], list[Lineage]], _NATIVE_DEDUPE._dedupe_lineages)
    _dedupe_sources = cast(Callable[[Iterable[SourceRef]], list[SourceRef]], _NATIVE_DEDUPE._dedupe_sources)
    _dedupe_taints = cast(Callable[[Iterable[TaintReason]], list[TaintReason]], _NATIVE_DEDUPE._dedupe_taints)
    _dedupe_warning_reasons = cast(
        Callable[[Iterable[WarningReason]], list[WarningReason]], _NATIVE_DEDUPE._dedupe_warning_reasons
    )
    _dedupe_diagnostics = cast(
        Callable[[Iterable[DiagnosticRecord]], list[DiagnosticRecord]], _NATIVE_DEDUPE._dedupe_diagnostics
    )
    _dedupe_hints = cast(Callable[[Iterable[Hint]], list[Hint]], _NATIVE_DEDUPE._dedupe_hints)
    _dedupe_anchors = cast(Callable[[Iterable[OutputAnchor]], list[OutputAnchor]], _NATIVE_DEDUPE._dedupe_anchors)
    _dedupe_strings = cast(Callable[[Iterable[str]], list[str]], _NATIVE_DEDUPE._dedupe_strings)
