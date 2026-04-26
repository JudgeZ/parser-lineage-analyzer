"""Template-string helper kernels with optional native acceleration."""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Callable
from typing import Protocol, cast


class _TemplateExt(Protocol):
    def template_refs(self, text: str) -> list[str]: ...

    def dynamic_template_literals(self, text: str) -> tuple[str, ...]: ...

    def dynamic_template_bucket_literal(self, text: str) -> str: ...

    def dynamic_template_pattern_text(self, text: str) -> str: ...

    def dynamic_template_matches(self, template: str, candidate: str) -> bool: ...


_NATIVE_TEMPLATE: _TemplateExt | None = None
if os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() not in {"1", "true", "yes", "on"}:
    try:
        _NATIVE_TEMPLATE = cast(_TemplateExt, importlib.import_module("parser_lineage_analyzer._native._template_ext"))
    except ImportError:
        _NATIVE_TEMPLATE = None


def _template_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    start = 0
    while True:
        marker = text.find("%{", start)
        if marker == -1:
            return spans
        close = text.find("}", marker + 2)
        if close == -1:
            start = marker + 2
            continue
        if close > marker + 2:
            spans.append((marker, close + 1, text[marker + 2 : close]))
        start = close + 1


def template_refs_python(text: str) -> list[str]:
    return [ref for _start, _end, ref in _template_spans(text)]


def dynamic_template_literals_python(text: str) -> tuple[str, ...]:
    literals: list[str] = []
    last = 0
    for start, end, _ref in _template_spans(text):
        literal = text[last:start]
        if literal:
            literals.append(literal)
        last = end
    if text[last:]:
        literals.append(text[last:])
    return tuple(literals)


def dynamic_template_bucket_literal_python(text: str) -> str:
    literals = dynamic_template_literals_python(text)
    return max(literals, key=len) if literals else ""


def dynamic_template_pattern_text_python(text: str) -> str:
    parts: list[str] = ["^"]
    last = 0
    for start, end, _ref in _template_spans(text):
        parts.append(re.escape(text[last:start]))
        parts.append(r".*?")
        last = end
    parts.append(re.escape(text[last:]))
    parts.append("$")
    return "".join(parts)


def dynamic_template_matches_python(template: str, candidate: str) -> bool:
    spans = _template_spans(template)
    if not spans:
        return template == candidate
    first_start = spans[0][0]
    pos = 0
    if first_start:
        leading = template[:first_start]
        if not candidate.startswith(leading):
            return False
        pos = len(leading)
    last = spans[0][1]
    for start, end, _ref in spans[1:]:
        literal = template[last:start]
        if literal:
            found = candidate.find(literal, pos)
            if found == -1:
                return False
            pos = found + len(literal)
        last = end
    trailing = template[last:]
    if trailing:
        found = candidate.find(trailing, pos)
        return found != -1 and candidate.endswith(trailing)
    return True


template_refs: Callable[[str], list[str]] = template_refs_python
dynamic_template_literals: Callable[[str], tuple[str, ...]] = dynamic_template_literals_python
dynamic_template_bucket_literal: Callable[[str], str] = dynamic_template_bucket_literal_python
dynamic_template_pattern_text: Callable[[str], str] = dynamic_template_pattern_text_python
dynamic_template_matches: Callable[[str, str], bool] = dynamic_template_matches_python

if _NATIVE_TEMPLATE is not None:
    template_refs = cast(Callable[[str], list[str]], _NATIVE_TEMPLATE.template_refs)
    dynamic_template_literals = cast(Callable[[str], tuple[str, ...]], _NATIVE_TEMPLATE.dynamic_template_literals)
    dynamic_template_bucket_literal = cast(Callable[[str], str], _NATIVE_TEMPLATE.dynamic_template_bucket_literal)
    dynamic_template_pattern_text = cast(Callable[[str], str], _NATIVE_TEMPLATE.dynamic_template_pattern_text)
    dynamic_template_matches = cast(Callable[[str, str], bool], _NATIVE_TEMPLATE.dynamic_template_matches)
