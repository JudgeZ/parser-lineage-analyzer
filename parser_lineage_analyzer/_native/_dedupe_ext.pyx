"""Cython tuple-key dedupe helpers."""

from collections.abc import Mapping

from parser_lineage_analyzer.model import _FrozenDetails


def _freeze_value(object value):
    if isinstance(value, _FrozenDetails):
        return value.key_tuple
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _freeze_value(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(v) for v in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze_value(v) for v in value), key=repr))
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def _source_key(object src):
    cdef object cached = getattr(src, "_analysis_key", None)
    cdef tuple key
    if cached is not None:
        return cached
    key = (
        src.kind,
        src.source_token,
        src.path,
        src.capture_name,
        src.column,
        src.pattern,
        src.expression,
        _freeze_value(src.details),
    )
    object.__setattr__(src, "_analysis_key", key)
    return key


def _taint_key(object taint):
    cdef object cached = getattr(taint, "_analysis_key", None)
    cdef tuple key
    if cached is not None:
        return cached
    key = (taint.code, taint.parser_location, taint.source_token, taint.message)
    object.__setattr__(taint, "_analysis_key", key)
    return key


def _warning_key(object warning):
    cdef object cached = getattr(warning, "_analysis_key", None)
    cdef tuple key
    if cached is not None:
        return cached
    key = (warning.code, warning.parser_location, warning.source_token, warning.message, warning.warning)
    object.__setattr__(warning, "_analysis_key", key)
    return key


def _diagnostic_key(object diagnostic):
    cdef object cached = getattr(diagnostic, "_analysis_key", None)
    cdef object taint_key
    cdef tuple key
    if cached is not None:
        return cached
    taint_key = _taint_key(diagnostic.taint) if diagnostic.taint else None
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


def _lineage_key(object lin):
    cdef object cached = getattr(lin, "_analysis_key", None)
    cdef tuple key
    if cached is not None:
        return cached
    key = (
        lin.status,
        tuple(_source_key(src) for src in lin.sources),
        lin.expression,
        tuple(lin.transformations),
        tuple(lin.conditions),
        tuple(lin.parser_locations),
        tuple(lin.notes),
        tuple(_taint_key(taint) for taint in lin.taints),
    )
    object.__setattr__(lin, "_analysis_key", key)
    return key


def _anchor_key(object anchor):
    return (anchor.anchor, tuple(anchor.conditions), tuple(anchor.parser_locations))


def _hint_key(object hint):
    cdef object cached = getattr(hint, "_analysis_key", None)
    cdef tuple key
    if cached is not None:
        return cached
    key = (
        hint.kind,
        hint.source_token,
        _freeze_value(hint.details),
        tuple(hint.conditions),
        tuple(hint.parser_locations),
        hint.source_resolved,
    )
    try:
        object.__setattr__(hint, "_analysis_key", key)
    except (AttributeError, TypeError):
        pass
    return key


def _dedupe_lineages(object lineages):
    cdef set seen = set()
    cdef list out = []
    cdef object lin
    cdef tuple key
    for lin in lineages:
        key = _lineage_key(lin)
        if key not in seen:
            seen.add(key)
            out.append(lin)
    return out


def _dedupe_sources(object sources):
    cdef set seen = set()
    cdef list out = []
    cdef object src
    cdef tuple key
    for src in sources:
        key = _source_key(src)
        if key not in seen:
            seen.add(key)
            out.append(src)
    return out


def _dedupe_taints(object taints):
    cdef set seen = set()
    cdef list out = []
    cdef object taint
    cdef tuple key
    for taint in taints:
        key = _taint_key(taint)
        if key not in seen:
            seen.add(key)
            out.append(taint)
    return out


def _dedupe_warning_reasons(object warnings):
    cdef set seen = set()
    cdef list out = []
    cdef object warning
    cdef tuple key
    for warning in warnings:
        key = _warning_key(warning)
        if key not in seen:
            seen.add(key)
            out.append(warning)
    return out


def _dedupe_diagnostics(object diagnostics):
    cdef set seen = set()
    cdef list out = []
    cdef object diagnostic
    cdef tuple key
    for diagnostic in diagnostics:
        key = _diagnostic_key(diagnostic)
        if key not in seen:
            seen.add(key)
            out.append(diagnostic)
    return out


def _dedupe_hints(object hints):
    cdef set seen = set()
    cdef list out = []
    cdef object hint
    cdef tuple key
    for hint in hints:
        key = _hint_key(hint)
        if key not in seen:
            seen.add(key)
            out.append(hint)
    return out


def _dedupe_anchors(object anchors):
    cdef set seen = set()
    cdef list out = []
    cdef object anchor
    cdef tuple key
    for anchor in anchors:
        key = _anchor_key(anchor)
        if key not in seen:
            seen.add(key)
            out.append(anchor)
    return out


def _dedupe_strings(object values):
    cdef dict seen = {}
    cdef object value
    for value in values:
        if value:
            seen[value] = None
    return list(seen.keys())
