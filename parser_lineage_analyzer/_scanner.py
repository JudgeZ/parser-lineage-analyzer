"""Shared scanner helpers for parser text.

The parser frontend needs comment stripping and delimiter search that understand
quoted strings, regex literals, and Logstash-ish paths. Keep that policy in one
module so statement parsing and config handling do not drift.
"""

from __future__ import annotations

import importlib
import os
from bisect import bisect_left
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Protocol, cast


class _ScannerExt(Protocol):
    def strip_comments_keep_offsets(self, text: str) -> str: ...

    def build_scanner_index_parts(
        self, text: str
    ) -> tuple[tuple[int, ...], tuple[int, ...], dict[tuple[str, int], tuple[int, ...]], dict[int, int], int]: ...

    def target_positions_for(self, text: str, target: str, square_depth: int) -> tuple[int, ...]: ...


_NATIVE_SCANNER: _ScannerExt | None = None
if os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() not in {"1", "true", "yes", "on"}:
    try:  # pragma: no cover - exercised only when the optional extension is built.
        _NATIVE_SCANNER = cast(_ScannerExt, importlib.import_module("parser_lineage_analyzer._native._scanner_ext"))
    except ImportError:
        _NATIVE_SCANNER = None


@dataclass(frozen=True, slots=True)
class ScanEvent:
    kind: str
    start: int
    end: int
    char: str = ""
    square_depth: int = 0


@dataclass(slots=True)
class ScannerIndex:
    text: str
    square_positions: tuple[int, ...]
    square_depths: tuple[int, ...]
    target_positions: dict[tuple[str, int], tuple[int, ...]]
    matching_close: dict[int, int]
    fallback_close: int
    _lazy_target_positions: dict[tuple[str, int], tuple[int, ...]] = field(default_factory=dict, repr=False)

    def square_depth_before(self, pos: int) -> int:
        idx = bisect_left(self.square_positions, pos)
        return self.square_depths[idx - 1] if idx > 0 else 0

    def find_next_unquoted(
        self, target: str, pos: int, limit: int | None = None, *, relative_depth: bool = True
    ) -> int:
        if len(target) != 1:
            raise ValueError("find_next_unquoted target must be exactly one character")
        square_depth = self.square_depth_before(pos) if relative_depth else 0
        key = (target, square_depth)
        candidates = self.target_positions.get(key)
        if candidates is None:
            candidates = self._lazy_target_positions.get(key)
        if candidates is None:
            candidates = _target_positions_for(self.text, target, square_depth)
            self._lazy_target_positions[key] = candidates
        idx = bisect_left(candidates, pos)
        if idx >= len(candidates):
            return -1
        found = candidates[idx]
        if limit is not None and found >= limit:
            return -1
        return found


def _is_line_comment_start(text: str, pos: int) -> bool:
    """Return True for ``//`` comments outside protected scanner states."""
    if pos + 1 >= len(text) or text[pos + 1] != "/":
        return False
    if _is_unquoted_slash_mapping_key(text, pos):
        return False
    j = pos - 1
    while j >= 0 and text[j] not in "\r\n":
        if not text[j].isspace():
            break
        j -= 1
    if j < 0 or text[j] in "\r\n":
        return True
    if pos > 0 and not text[pos - 1].isspace() and text[pos - 1] != "}":
        return False
    return text[j] not in {",", "(", "[", "=", "~", "!"}


def _is_unquoted_slash_mapping_key(text: str, pos: int) -> bool:
    """Return True for unquoted config keys like ``//node =>`` or ``//node =``."""
    i = pos + 2
    if i >= len(text) or text[i].isspace():
        return False
    key_start = i
    while i < len(text) and text[i] not in "\r\n{}[]," and not text[i].isspace() and text[i] != "=":
        i += 1
    while i < len(text) and text[i] not in "\r\n" and text[i].isspace():
        i += 1
    if i == key_start:
        return False
    if text.startswith("=>", i):
        i += 2
    elif i < len(text) and text[i] == "=":
        i += 1
    else:
        return False
    while i < len(text) and text[i] not in "\r\n" and text[i].isspace():
        i += 1
    return i < len(text) and text[i] in {'"', "'"}


def _is_regex_literal_start(text: str, pos: int) -> bool:
    """Heuristic for condition/config regex literals."""
    if pos + 1 < len(text) and text[pos + 1] == "*":
        return False
    j = pos - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    if j >= 1 and text[j - 1 : j + 1] in {"=~", "!~"}:
        return True
    if pos + 1 < len(text) and text[pos + 1] == "/":
        return False
    if j >= 0 and text[j] == ">":
        # `=> /pattern/` form. Walk forward looking for the closing `/`. An
        # unescaped `{` outside a character class is almost never a real
        # regex — `\{n,m\}` quantifiers escape them — so treat its presence
        # as evidence the `/...` was actually a bareword path. This rejects
        # things like `=> /var_{/logs/}` (path that looks like regex).
        k = pos + 1
        in_class = False
        escape = False
        while k < len(text) and text[k] not in "\r\n":
            ch = text[k]
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif in_class:
                if ch == "]":
                    in_class = False
            elif ch == "[":
                in_class = True
            elif ch == "{":
                # Unescaped `{` outside a char class — bareword, not regex.
                return False
            elif ch == "/":
                return True
            elif ch.isspace() or ch in {",", "}", "]"}:
                return False
            k += 1
        return False
    return j >= 0 and text[j] in {"[", "{", ",", "="}


def _is_path_bareword_start(text: str, pos: int) -> bool:
    """Heuristic: `/` after `=>` that is NOT a regex (per `_is_regex_literal_start`)
    and contains an unescaped `{` before end-of-line.

    Path-style barewords like `/var_{/logs/}` have unbalanced braces inside
    them. Without special-casing, the scanner would count those braces and
    desync the surrounding brace-depth tracker.
    """
    j = pos - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    if j < 0 or text[j] != ">":
        return False
    if _is_regex_literal_start(text, pos):
        return False
    k = pos + 1
    saw_brace = False
    while k < len(text) and text[k] not in "\r\n":
        if text[k] == "\\" and k + 1 < len(text):
            k += 2
            continue
        if text[k] == "{" or text[k] == "}":
            saw_brace = True
            break
        if text[k] in " \t,":
            return False  # delimiter ended the would-be bareword without a brace
        k += 1
    return saw_brace


def scan_parser_text(text: str, pos: int = 0, *, track_square: bool = False) -> Iterator[ScanEvent]:
    """Yield unprotected characters and comment ranges in parser text."""
    quote: str | None = None
    regex = False
    escape = False
    depth_square = 0
    i = pos
    while i < len(text):
        c = text[i]
        if regex:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "/":
                regex = False
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = None
            i += 1
            continue
        if c in {'"', "'"}:
            quote = c
            i += 1
            continue
        if c == "/" and _is_regex_literal_start(text, i):
            regex = True
            i += 1
            continue
        if c == "/" and i + 1 < len(text) and text[i + 1] == "/" and _is_line_comment_start(text, i):
            start = i
            while i < len(text) and text[i] != "\n":
                i += 1
            yield ScanEvent("line_comment", start, i)
            continue
        if c == "/" and _is_path_bareword_start(text, i):
            # Path-style bareword (e.g. `=> /var_{/logs/}`). The Phase D3
            # disambiguation already prevents these from being mis-detected
            # as regexes, but the inner `{`/`}` must also not count toward
            # the surrounding brace depth — otherwise the outer block's
            # closing brace gets mismatched. Treat the bareword as opaque
            # until end-of-line or whitespace.
            start = i
            i += 1
            while i < len(text) and text[i] not in " \t\r\n,":
                i += 1
            yield ScanEvent("bareword", start, i)
            continue
        if c == "/" and i + 1 < len(text) and text[i + 1] == "*":
            start = i
            i += 2
            while i < len(text):
                if i + 1 < len(text) and text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            else:
                i = len(text)
            yield ScanEvent("block_comment", start, i)
            continue
        if c == "#":
            start = i
            while i < len(text) and text[i] != "\n":
                i += 1
            yield ScanEvent("line_comment", start, i)
            continue
        if track_square:
            if c == "[":
                depth_square += 1
            elif c == "]" and depth_square:
                depth_square -= 1
        yield ScanEvent("char", i, i + 1, c, depth_square)
        i += 1


def _strip_comments_keep_offsets_python(text: str) -> str:
    out = list(text)
    for event in scan_parser_text(text):
        if event.kind not in {"line_comment", "block_comment"}:
            continue
        for i in range(event.start, min(event.end, len(out))):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


_strip_comments_keep_offsets_impl: Callable[[str], str] = _strip_comments_keep_offsets_python
if _NATIVE_SCANNER is not None:
    _strip_comments_keep_offsets_impl = cast(Callable[[str], str], _NATIVE_SCANNER.strip_comments_keep_offsets)


def strip_comments_keep_offsets(text: str) -> str:
    """Remove comments while preserving offsets and protected literals."""
    if "#" not in text and "/" not in text:
        return text
    return _strip_comments_keep_offsets_impl(text)


def _build_scanner_index_python(text: str) -> ScannerIndex:
    """Build primitive lookup tables for unprotected text positions."""
    quote: str | None = None
    regex = False
    escape = False
    depth_square = 0
    square_positions: list[int] = []
    square_depths: list[int] = []
    mutable_targets: dict[tuple[str, int], list[int]] = {}
    matching_close: dict[int, int] = {}
    stack: list[int] = []
    ref_depth = 0
    skip_ref_open_at = -1
    fallback_close = -1
    i = 0
    while i < len(text):
        c = text[i]
        if regex:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "/":
                regex = False
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = None
            i += 1
            continue
        if c in {'"', "'"}:
            quote = c
            i += 1
            continue
        if c == "/" and _is_regex_literal_start(text, i):
            regex = True
            i += 1
            continue
        if c == "/" and i + 1 < len(text) and text[i + 1] == "/" and _is_line_comment_start(text, i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if c == "/" and _is_path_bareword_start(text, i):
            # Path-style bareword (e.g. `=> /var_{/logs/}`); the inner braces
            # must not count toward the surrounding brace depth tracker.
            i += 1
            while i < len(text) and text[i] not in " \t\r\n,":
                i += 1
            continue
        if c == "/" and i + 1 < len(text) and text[i + 1] == "*":
            i += 2
            while i < len(text):
                if i + 1 < len(text) and text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            else:
                i = len(text)
            continue
        if c == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if c == "[":
            depth_square += 1
            square_positions.append(i)
            square_depths.append(depth_square)
        elif c == "]" and depth_square:
            depth_square -= 1
            square_positions.append(i)
            square_depths.append(depth_square)
        if c == "%" and i + 1 < len(text) and text[i + 1] == "{":
            ref_depth += 1
            skip_ref_open_at = i + 1
            i += 1
            continue
        if ref_depth:
            if i == skip_ref_open_at:
                skip_ref_open_at = -1
            elif c == "{":
                ref_depth += 1
            elif c == "}":
                ref_depth -= 1
            i += 1
            continue
        if c in "{}":
            mutable_targets.setdefault((c, depth_square), []).append(i)
        if c == "{":
            stack.append(i)
        elif c == "}":
            fallback_close = i
            if stack:
                matching_close[stack.pop()] = i
        i += 1
    target_positions = {key: tuple(value) for key, value in mutable_targets.items()}
    return ScannerIndex(
        text=text,
        square_positions=tuple(square_positions),
        square_depths=tuple(square_depths),
        target_positions=target_positions,
        matching_close=matching_close,
        fallback_close=fallback_close,
    )


def _build_scanner_index_native(text: str) -> ScannerIndex:
    native = _NATIVE_SCANNER
    if native is None:
        raise RuntimeError("native scanner extension is not available")
    square_positions, square_depths, target_positions, matching_close, fallback_close = (
        native.build_scanner_index_parts(text)
    )
    return ScannerIndex(
        text=text,
        square_positions=square_positions,
        square_depths=square_depths,
        target_positions=target_positions,
        matching_close=matching_close,
        fallback_close=fallback_close,
    )


def _target_positions_for_python(text: str, target: str, square_depth: int) -> tuple[int, ...]:
    positions: list[int] = []
    ref_depth = 0
    skip_ref_open_at = -1
    for event in scan_parser_text(text, track_square=True):
        if event.kind != "char":
            continue
        if event.char == "%" and event.start + 1 < len(text) and text[event.start + 1] == "{":
            ref_depth += 1
            skip_ref_open_at = event.start + 1
            continue
        if ref_depth:
            if event.start == skip_ref_open_at:
                skip_ref_open_at = -1
            elif event.char == "{":
                ref_depth += 1
            elif event.char == "}":
                ref_depth -= 1
            continue
        if event.char == target and event.square_depth == square_depth:
            positions.append(event.start)
    return tuple(positions)


_target_positions_for: Callable[[str, str, int], tuple[int, ...]] = _target_positions_for_python

_native_build_scanner_index: Callable[[str], ScannerIndex] | None = None
if _NATIVE_SCANNER is not None:
    _native_build_scanner_index = _build_scanner_index_native
    _target_positions_for = cast(Callable[[str, str, int], tuple[int, ...]], _NATIVE_SCANNER.target_positions_for)
else:
    _native_build_scanner_index = None


def build_scanner_index(text: str) -> ScannerIndex:
    """Dispatch to the native scanner when available, else the Python fallback.

    T5: the native scanner now mirrors the Python ``_is_path_bareword_start``
    heuristic, so the prior ``_has_path_bareword_with_brace`` short-circuit
    is unnecessary. Output equivalence is verified across the entire corpus
    by ``tests/test_scanner_native_parity.py`` — if the native scanner ever
    drifts from the Python implementation again, that test fails before
    misclassification reaches downstream lineage.
    """
    if _native_build_scanner_index is not None:
        return _native_build_scanner_index(text)
    return _build_scanner_index_python(text)


def find_next_unquoted(text: str, pos: int, target: str) -> int:
    """Find one target character outside protected scanner states."""
    if len(target) != 1:
        raise ValueError("find_next_unquoted target must be exactly one character")
    return build_scanner_index(text).find_next_unquoted(target, pos, relative_depth=False)


def find_matching(text: str, open_pos: int, open_ch: str = "{", close_ch: str = "}") -> int:
    """Find a matching delimiter outside quotes, regex literals, and ``%{...}`` refs."""
    depth = 0
    ref_depth = 0
    skip_ref_open_at = -1
    for event in scan_parser_text(text, open_pos):
        if event.kind != "char":
            continue
        if event.char == "%" and event.start + 1 < len(text) and text[event.start + 1] == "{":
            ref_depth += 1
            skip_ref_open_at = event.start + 1
            continue
        if ref_depth:
            if event.start == skip_ref_open_at:
                skip_ref_open_at = -1
            elif event.char == "{":
                ref_depth += 1
            elif event.char == "}":
                ref_depth -= 1
            continue
        if event.char == open_ch:
            depth += 1
        elif event.char == close_ch:
            depth -= 1
            if depth == 0:
                return event.start
    return -1
