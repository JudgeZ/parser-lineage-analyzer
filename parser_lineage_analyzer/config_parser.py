"""Lark parser for Logstash-like plugin configuration bodies.

The SecOps statement parser treats plugin bodies as opaque CONFIG tokens. This
module parses those bodies with a dedicated Lark LALR grammar into duplicate-key
preserving ``[(key, value), ...]`` pairs.
"""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import NamedTuple, Protocol, TypeVar, cast

from lark import Lark, Token, Transformer, UnexpectedInput

from ._grammar import load_grammar
from ._scanner import scan_parser_text
from ._types import ConfigPair, ConfigValue
from .model import SyntaxDiagnostic


class _ConfigFastExt(Protocol):
    def decode_string(self, token_text: str) -> str: ...

    def parse_simple_config_fast(self, text: str, max_depth: int) -> list[ConfigPair] | None: ...


_NATIVE_CONFIG_FAST: _ConfigFastExt | None = None
if os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() not in {"1", "true", "yes", "on"}:
    try:  # pragma: no cover - exercised only when the optional extension is built.
        _NATIVE_CONFIG_FAST = cast(
            _ConfigFastExt, importlib.import_module("parser_lineage_analyzer._native._config_fast_ext")
        )
    except ImportError:
        _NATIVE_CONFIG_FAST = None

_CONFIG_GRAMMAR = load_grammar("config.lark")
MAX_CONFIG_NESTING_DEPTH = 64
MAX_CACHED_CONFIG_BODY_BYTES = 8192
MAX_CONFIG_ERROR_EXCERPT = 512


ConfigDiagnostic = SyntaxDiagnostic
DefaultValue = TypeVar("DefaultValue")


@dataclass(frozen=True, slots=True)
class FrozenConfigArray:
    values: tuple[FrozenConfigValue, ...]


@dataclass(frozen=True, slots=True)
class FrozenConfigMap:
    pairs: tuple[tuple[str, FrozenConfigValue], ...]


FrozenConfigValue = str | bool | FrozenConfigArray | FrozenConfigMap
FrozenConfigPair = tuple[str, FrozenConfigValue]
FrozenConfigResult = tuple[FrozenConfigPair, ...]


class ConfigParseCacheInfo(NamedTuple):
    hits: int
    misses: int
    maxsize: int | None
    currsize: int


def _is_config_pair(value: object) -> bool:
    return isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str)


def _config_pairs(values: list[object]) -> list[ConfigPair]:
    return [cast(ConfigPair, value) for value in values if _is_config_pair(value)]


def _freeze_config_value(value: ConfigValue) -> FrozenConfigValue:
    if isinstance(value, list):
        pairs = as_pairs(value)
        if pairs:
            return FrozenConfigMap(tuple((key, _freeze_config_value(item)) for key, item in pairs))
        return FrozenConfigArray(tuple(_freeze_config_value(item) for item in cast(list[ConfigValue], value)))
    return value


def _freeze_config_pairs(values: list[ConfigPair]) -> FrozenConfigResult:
    return tuple((key, _freeze_config_value(value)) for key, value in values)


def _thaw_config_value(value: FrozenConfigValue) -> ConfigValue:
    if isinstance(value, FrozenConfigMap):
        return [(key, _thaw_config_value(item_value)) for key, item_value in value.pairs]
    if isinstance(value, FrozenConfigArray):
        return [_thaw_config_value(item) for item in value.values]
    return value


def _thaw_config_pairs(values: FrozenConfigResult) -> list[ConfigPair]:
    return [(key, _thaw_config_value(value)) for key, value in values]


def _config_error_value(text: str) -> str:
    stripped = text.strip()
    if len(stripped) <= MAX_CONFIG_ERROR_EXCERPT:
        return stripped
    return stripped[:MAX_CONFIG_ERROR_EXCERPT] + "...<truncated>"


def _line_column(text: str, pos: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, pos) + 1
    return text.count("\n", 0, pos) + 1, pos - line_start + 1


def _line_offset(text: str, line_one_indexed: int) -> int:
    """Return character offset of the start of the given 1-indexed line."""
    pos = 0
    for _ in range(line_one_indexed - 1):
        nl = text.find("\n", pos)
        if nl == -1:
            return len(text)
        pos = nl + 1
    return pos


def _recover_unbalanced_bareword(text: str, exc: UnexpectedInput) -> str | None:
    """Phase 3C recovery: rewrite an unbalanced bareword as a quoted string.

    Only fires for the specific failure shape ``=> <bareword-with-{>``,
    where the bareword starts with `/` (path-style) and contains an
    unescaped brace. The recovery picks the bareword span by scanning
    forward from the most recent ``=>`` to the next newline or whitespace
    delimiter that is balanced w.r.t. the inner braces, and wraps the span
    in double quotes (escaping any embedded ``"``).

    Returns the rewritten text, or ``None`` if the heuristic doesn't apply.
    """
    line = getattr(exc, "line", None)
    column = getattr(exc, "column", None)
    if not line or not column:
        return None
    line_start = _line_offset(text, line)
    fail_pos = line_start + (column - 1)
    if fail_pos >= len(text) or text[fail_pos] not in "{}":
        return None
    # Look back for the most recent `=>` on this line; the bareword starts
    # after it (skipping whitespace).
    arrow = text.rfind("=>", line_start, fail_pos)
    if arrow == -1:
        return None
    bw_start = arrow + 2
    while bw_start < fail_pos and text[bw_start].isspace():
        bw_start += 1
    if bw_start >= fail_pos:
        return None
    if text[bw_start] != "/":
        # Phase 3C is targeted: only path-style barewords. Plain identifiers
        # don't typically contain braces; treating them this way risks more
        # damage than benefit.
        return None
    # The bareword runs until end-of-line or the trailing space before the
    # next pair / closing brace. Take everything to end-of-line, then trim
    # trailing whitespace.
    nl = text.find("\n", bw_start)
    if nl == -1:
        nl = len(text)
    raw_span = text[bw_start:nl].rstrip()
    if not raw_span or '"' in raw_span:
        return None
    # Wrap the bareword span in double quotes.
    span_end = bw_start + len(raw_span)
    quoted = f'"{raw_span}"'
    return text[:bw_start] + quoted + text[span_end:]


def _multiline_regex_literal_diagnostic(text: str) -> ConfigDiagnostic | None:
    quote: str | None = None
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in {'"', "'"}:
            quote = ch
            i += 1
            continue
        if ch != "/" or (i + 1 < len(text) and text[i + 1] in {"/", "*"}):
            i += 1
            continue
        j = i - 1
        while j >= 0 and text[j].isspace():
            j -= 1
        if j >= 0 and text[j] not in {"{", "[", ",", "=", ">"}:
            i += 1
            continue
        k = i + 1
        regex_escape = False
        while k < len(text):
            cur = text[k]
            if regex_escape:
                regex_escape = False
            elif cur == "\\":
                regex_escape = True
            elif cur == "/":
                break
            elif cur == "\n":
                line, column = _line_column(text, i)
                return ConfigDiagnostic(line, column, "Multiline regex literals are not supported by the config parser")
            k += 1
        i += 1
    return None


def _config_nesting_diagnostic(text: str) -> ConfigDiagnostic | None:
    depth = 0
    for event in scan_parser_text(text):
        if event.kind != "char":
            continue
        if event.char in {"{", "["}:
            depth += 1
            if depth > MAX_CONFIG_NESTING_DEPTH:
                line, column = _line_column(text, event.start)
                return ConfigDiagnostic(
                    line, column, f"Config nesting depth exceeds limit of {MAX_CONFIG_NESTING_DEPTH}"
                )
        elif event.char in {"}", "]"} and depth:
            depth -= 1
    return None


def decode_string_body(body: str, quote: str) -> str:
    """Decode a Logstash-style string body (no surrounding quotes) using
    the same escape rules as ``_decode_string_python``. ``quote`` selects
    which inner quote character is recognized as an escapable delimiter.
    """
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "t":
                out.append("\t")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "f":
                out.append("\f")
            elif nxt == "b":
                out.append("\b")
            elif nxt == "v":
                out.append("\v")
            elif nxt == quote:
                out.append(quote)
            elif nxt == "x" and i + 3 < len(body):
                raw = body[i + 2 : i + 4]
                try:
                    out.append(chr(int(raw, 16)))
                    i += 4
                    continue
                except ValueError:
                    # Keep invalid hex escapes lossless: consume only "\x"
                    # here, then let the following loop iterations append the
                    # raw characters that failed to decode.
                    out.append("\\x")
            elif nxt == "u" and i + 5 < len(body):
                raw = body[i + 2 : i + 6]
                try:
                    out.append(chr(int(raw, 16)))
                    i += 6
                    continue
                except ValueError:
                    # Same recovery as invalid "\x": preserve the prefix now
                    # and let the original raw suffix flow through unchanged.
                    out.append("\\u")
            elif nxt == "\\":
                out.append("\\")
            else:
                # Preserve unknown escapes; they are often meaningful in regexes.
                out.append("\\" + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _decode_string_python(token_text: str) -> str:
    if len(token_text) < 2:
        return token_text
    quote = token_text[0]
    body = token_text[1:-1] if token_text[-1] == quote else token_text[1:]
    return decode_string_body(body, quote)


_decode_string: Callable[[str], str] = _decode_string_python
if _NATIVE_CONFIG_FAST is not None:
    _decode_string = cast(Callable[[str], str], _NATIVE_CONFIG_FAST.decode_string)


_FAST_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_@.-]*")


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _read_fast_quoted(text: str, pos: int) -> tuple[str | None, int]:
    if pos >= len(text) or text[pos] not in {'"', "'"}:
        return None, pos
    quote = text[pos]
    i = pos + 1
    escape = False
    while i < len(text):
        ch = text[i]
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == quote:
            raw = text[pos : i + 1]
            return _decode_string(raw), i + 1
        i += 1
    return None, pos


def _read_fast_atom(text: str, pos: int) -> tuple[str | None, int]:
    quoted, after_quoted = _read_fast_quoted(text, pos)
    if quoted is not None:
        return quoted, after_quoted
    end = pos
    while end < len(text) and not text[end].isspace() and text[end] not in "{}[],=>":
        if text[end] == "#":
            return None, pos
        if text[end] == "/":
            if end == pos:
                return None, pos
            if end + 1 < len(text) and text[end + 1] == "*":
                break
            if end + 1 < len(text) and text[end + 1] == "/" and text[end - 1] != ":":
                break
        end += 1
    if end == pos:
        return None, pos
    return text[pos:end], end


def _read_fast_array(text: str, pos: int, depth: int) -> tuple[list[ConfigValue] | None, int]:
    if depth > MAX_CONFIG_NESTING_DEPTH:
        return None, pos
    if pos >= len(text) or text[pos] != "[":
        return None, pos
    pos += 1
    values: list[ConfigValue] = []
    while True:
        pos = _skip_ws(text, pos)
        if pos >= len(text):
            return None, pos
        if text[pos] == "]":
            return values, pos + 1
        value, pos = _read_fast_value(text, pos, depth)
        if value is None:
            return None, pos
        values.append(value)
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == ",":
            pos += 1


def _read_fast_value(text: str, pos: int, nesting_depth: int = 0) -> tuple[ConfigValue | None, int]:
    array, after_array = _read_fast_array(text, pos, nesting_depth + 1)
    if array is not None:
        return array, after_array
    return _read_fast_atom(text, pos)


def _parse_simple_config_fast_python(text: str) -> list[ConfigPair] | None:
    """Parse common one-level mutate maps without invoking Lark.

    This intentionally accepts only the high-volume simple shape:
    ``op => { "key" => "value" ... }``. Complex bodies fall back to Lark.
    """
    pairs: list[ConfigPair] = []
    pos = 0
    end = len(text)
    while True:
        pos = _skip_ws(text, pos)
        if pos >= end:
            return pairs if pairs else None
        op_match = _FAST_IDENT_RE.match(text, pos)
        if not op_match:
            return None
        op = op_match.group(0)
        pos = _skip_ws(text, op_match.end())
        if not text.startswith("=>", pos):
            return None
        pos = _skip_ws(text, pos + 2)
        if pos >= end:
            return None
        if text[pos] == "[":
            values, pos = _read_fast_array(text, pos, 1)
            if values is None:
                return None
            pairs.append((op, values))
            continue
        if text[pos] == "{":
            pos += 1
            map_values: list[ConfigPair] = []
            while True:
                pos = _skip_ws(text, pos)
                if pos >= end:
                    return None
                if text[pos] == "}":
                    pos += 1
                    break
                key, pos = _read_fast_atom(text, pos)
                if key is None:
                    return None
                pos = _skip_ws(text, pos)
                if not text.startswith("=>", pos):
                    return None
                pos = _skip_ws(text, pos + 2)
                value, pos = _read_fast_value(text, pos, 1)
                if value is None:
                    return None
                map_values.append((key, value))
            pairs.append((op, map_values))
            continue
        value, pos = _read_fast_atom(text, pos)
        if value is None:
            return None
        pairs.append((op, value))


def _parse_simple_config_fast_native(text: str) -> list[ConfigPair] | None:
    native = _NATIVE_CONFIG_FAST
    if native is None:
        raise RuntimeError("native config-fast extension is not available")
    return native.parse_simple_config_fast(text, MAX_CONFIG_NESTING_DEPTH)


_parse_simple_config_fast: Callable[[str], list[ConfigPair] | None] = _parse_simple_config_fast_python
if _NATIVE_CONFIG_FAST is not None:
    _parse_simple_config_fast = _parse_simple_config_fast_native


def parse_config_with_diagnostics(text: str) -> tuple[list[ConfigPair], list[ConfigDiagnostic]]:
    """Parse a plugin config body and return diagnostics for malformed input."""
    fast = _parse_simple_config_fast(text)
    if fast is not None:
        return fast, []
    text_len = len(text)
    cacheable = text_len <= MAX_CACHED_CONFIG_BODY_BYTES
    if not cacheable and text_len <= MAX_CACHED_CONFIG_BODY_BYTES * 2 and not text.isascii():
        cacheable = len(text.encode("utf-8")) <= MAX_CACHED_CONFIG_BODY_BYTES
    if cacheable:
        frozen_config, diagnostics = _parse_config_with_diagnostics_cached(text)
        return _thaw_config_pairs(frozen_config), list(diagnostics)
    return _parse_config_with_diagnostics_uncached(text)


@lru_cache(maxsize=4096)
def _parse_config_with_diagnostics_cached(text: str) -> tuple[FrozenConfigResult, tuple[ConfigDiagnostic, ...]]:
    config, diagnostics = _parse_config_with_diagnostics_uncached(text)
    return _freeze_config_pairs(config), tuple(diagnostics)


def clear_config_parse_cache() -> None:
    """Clear the process-wide config parse cache used for repeated bodies."""
    _parse_config_with_diagnostics_cached.cache_clear()


def config_parse_cache_info() -> ConfigParseCacheInfo:
    """Return hit/miss statistics for the process-wide config parse cache."""
    return ConfigParseCacheInfo(*_parse_config_with_diagnostics_cached.cache_info())


def _parse_config_with_diagnostics_uncached(text: str) -> tuple[list[ConfigPair], list[ConfigDiagnostic]]:
    multiline_regex = _multiline_regex_literal_diagnostic(text)
    if multiline_regex is not None:
        return [("__config_parse_error__", _config_error_value(text))], [multiline_regex]
    nesting = _config_nesting_diagnostic(text)
    if nesting is not None:
        return [("__config_parse_error__", _config_error_value(text))], [nesting]
    try:
        tree = _CONFIG_PARSER.parse(text)
    except UnexpectedInput as exc:
        # Phase 3C recovery: when the failing token is a brace mid-bareword
        # (e.g. `=> /var_{/logs/}` — a path-style bareword that contains an
        # unbalanced brace), retry with the bareword wrapped in quotes. This
        # is bounded — one recovery attempt per call — and conservative: the
        # rewritten text is only used if the second parse succeeds.
        recovered = _recover_unbalanced_bareword(text, exc)
        if recovered is not None and recovered != text:
            try:
                tree = _CONFIG_PARSER.parse(recovered)
            except UnexpectedInput:
                tree = None
            if tree is not None:
                try:
                    result = _ConfigTransformer().transform(tree)
                except RecursionError:
                    result = None
                if isinstance(result, list):
                    return _config_pairs(result), []
        line = getattr(exc, "line", 1) or 1
        column = getattr(exc, "column", 1) or 1
        message = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return [("__config_parse_error__", _config_error_value(text))], [ConfigDiagnostic(line, column, message)]
    if tree is None:
        return [("__config_parse_error__", _config_error_value(text))], [
            ConfigDiagnostic(1, 1, "Config parser returned no tree")
        ]
    try:
        result = _ConfigTransformer().transform(tree)
    except RecursionError:
        return [("__config_parse_error__", _config_error_value(text))], [
            ConfigDiagnostic(1, 1, f"Config nesting depth exceeds limit of {MAX_CONFIG_NESTING_DEPTH}")
        ]
    if not isinstance(result, list):
        return [("__config_parse_error__", _config_error_value(text))], [
            ConfigDiagnostic(1, 1, "Config parser produced a non-list root")
        ]
    return _config_pairs(result), []


class _ConfigTransformer(Transformer):
    def start(self, children: list[object]) -> list[ConfigPair]:
        if len(children) == 1 and isinstance(children[0], list):
            return _config_pairs(children[0])
        return _config_pairs(children)

    def map(self, children: list[object]) -> list[ConfigPair]:
        return _config_pairs(children)

    def pair(self, children: list[object]) -> ConfigPair:
        vals = [c for c in children if not (isinstance(c, Token) and c.type in {"ARROW", "EQ"})]
        key = vals[0] if vals else ""
        value = vals[1] if len(vals) > 1 else True
        return str(key), cast(ConfigValue, value)

    def flag(self, children: list[object]) -> tuple[str, bool]:
        return str(children[0]) if children else "", True

    def array(self, children: list[object]) -> list[ConfigValue]:
        return [
            cast(ConfigValue, c)
            for c in children
            if not (isinstance(c, Token) and c.type in {"LBRACKET", "RBRACKET", "COMMA"})
        ]

    def string(self, children: list[object]) -> str:
        return _decode_string(str(children[0]))

    def regex(self, children: list[object]) -> str:
        return str(children[0])

    def bracket_ref(self, children: list[object]) -> str:
        return str(children[0])

    def ident(self, children: list[object]) -> str:
        return str(children[0])

    def bare(self, children: list[object]) -> str:
        return str(children[0])


_CONFIG_PARSER = Lark(
    _CONFIG_GRAMMAR,
    parser="lalr",
    lexer="contextual",
    maybe_placeholders=False,
    propagate_positions=True,
)


def parse_config(text: str) -> list[ConfigPair]:
    """Parse a plugin config body into duplicate-preserving key/value pairs."""
    return parse_config_with_diagnostics(text)[0]


def first_value(
    config: list[ConfigPair], key: str, default: DefaultValue | None = None
) -> ConfigValue | DefaultValue | None:
    for k, v in config:
        if k == key:
            return v
    return default


def all_values(config: list[ConfigPair], key: str) -> list[ConfigValue]:
    return [v for k, v in config if k == key]


def as_pairs(value: ConfigValue) -> list[ConfigPair]:
    if isinstance(value, list) and all(isinstance(x, tuple) and len(x) == 2 for x in value):
        return cast(list[ConfigPair], value)
    return []
