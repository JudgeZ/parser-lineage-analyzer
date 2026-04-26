"""Lark/LALR AST parser for Google SecOps / Chronicle parser code.

The frontend is intentionally split into two production phases:

1. A stateful Lex-style scanner (`_SecOpsLexer`) that understands comments,
   quotes, regex literals, nested braces, and opaque plugin config bodies.
2. A Lark LALR grammar (`_LALR_GRAMMAR`) that parses statements, conditionals,
   loops, plugin blocks, and filter wrappers into the AST consumed by the
   static analyzer.

Plugin config bodies are parsed by ``config_parser.py`` using a separate Lark
LALR grammar. This keeps statement parsing and config parsing deterministic
while still allowing analyzer-level graceful handling of unknown plugins.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass, field

from lark import Lark, Token, Transformer
from lark.exceptions import LarkError
from lark.lexer import Lexer

from ._grammar import load_grammar
from ._scanner import (
    ScannerIndex,
    build_scanner_index,
    find_matching as _public_find_matching,
    find_next_unquoted as _public_find_next_unquoted,
    strip_comments_keep_offsets as _public_strip_comments_keep_offsets,
)
from ._types import ConfigPair
from .ast_nodes import ElifBlock, ForBlock, IfBlock, IOBlock, Plugin, Statement, Unknown
from .config_parser import parse_config_with_diagnostics
from .model import SyntaxDiagnostic

_IDENT_RE = re.compile(r"[A-Za-z_@][A-Za-z0-9_@.-]*")
find_matching = _public_find_matching
find_next_unquoted = _public_find_next_unquoted
strip_comments_keep_offsets = _public_strip_comments_keep_offsets


@dataclass
class SourceText:
    original: str
    text: str
    line_starts: tuple[int, ...] = ()
    scanner_index: ScannerIndex = field(init=False, repr=False)

    @classmethod
    def from_code(cls, code: str) -> SourceText:
        return cls(original=code, text=strip_comments_keep_offsets(code))

    def __post_init__(self) -> None:
        if not self.line_starts:
            self.line_starts = tuple([0] + [idx + 1 for idx, ch in enumerate(self.original) if ch == "\n"])
        self.scanner_index = build_scanner_index(self.text)

    def line_at(self, pos: int) -> int:
        return bisect_right(self.line_starts, max(0, pos))

    def column_at(self, pos: int) -> int:
        line = self.line_at(pos)
        return max(1, pos - self.line_starts[line - 1] + 1)

    def line_col_at(self, pos: int) -> tuple[int, int]:
        line = bisect_right(self.line_starts, max(0, pos))
        return line, max(1, pos - self.line_starts[line - 1] + 1)

    def find_next_unquoted(self, pos: int, target: str, limit: int | None = None) -> int:
        return self.scanner_index.find_next_unquoted(target, pos, limit)

    def find_matching(self, open_pos: int) -> int:
        return self.scanner_index.matching_close.get(open_pos, -1)


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _read_ident(text: str, pos: int) -> tuple[str | None, int]:
    m = _IDENT_RE.match(text, pos)
    if not m:
        return None, pos
    return m.group(0), m.end()


def parse_for_header(header: str) -> tuple[list[str], str, bool]:
    is_map = False
    m = re.search(r"\s+in\s+", header)
    if not m:
        return [v.strip() for v in header.split(",") if v.strip()], "", False
    left = header[: m.start()].strip()
    right = header[m.end() :].strip()
    if re.search(r"\s+map\s*$", right):
        is_map = True
        right = re.sub(r"\s+map\s*$", "", right).strip()
    vars_ = [v.strip() for v in left.split(",") if v.strip()]
    return vars_, right, is_map


_LALR_GRAMMAR = load_grammar("statement.lark")


def _make_token(src: SourceText, typ: str, val: str, pos: int) -> Token:
    tok = Token(typ, val)
    tok.line, tok.column = src.line_col_at(pos)
    tok.start_pos = pos
    tok.end_pos = pos + len(val)
    tok.end_line, tok.end_column = src.line_col_at(tok.end_pos)
    return tok


class _SecOpsLexer(Lexer):
    """Lex-style stateful scanner used by the Lark LALR statement grammar."""

    def __init__(self, lexer_conf: object) -> None:  # pragma: no cover - Lark construction hook
        self.lexer_conf = lexer_conf

    def lex(self, data: str) -> Iterator[Token]:  # type: ignore[override]  # Lark's hook omits useful typing.
        src = SourceText.from_code(data)
        text = src.text
        end = len(text)
        pos = 0
        while pos < end:
            pos = _skip_ws(text, pos)
            if pos >= end:
                break
            if text[pos] == "}":
                yield _make_token(src, "RBRACE", "}", pos)
                pos += 1
                continue
            if text[pos] == "{":
                yield _make_token(src, "LBRACE", "{", pos)
                pos += 1
                continue

            ident, after_ident = _read_ident(text, pos)
            if ident is not None:
                # Logstash-style top-level pipeline blocks share the same
                # ``KEYWORD { ... }`` shape: a bare keyword followed by a brace
                # whose body is a list of nested plugin invocations. Treat
                # ``input``/``output`` as ``filter`` aliases at the lexer level
                # so the LALR grammar parses all three identically; the
                # analyzer then sees the inner plugins as ordinary statements
                # (and falls back to the unsupported-plugin path for
                # input/output-only plugins like ``beats`` or ``elasticsearch``)
                # rather than treating the entire pipeline body as one opaque
                # config map.
                if ident in ("filter", "input", "output"):
                    brace = _skip_ws(text, after_ident)
                    if brace < end and text[brace] == "{":
                        yield _make_token(src, "FILTER", ident, pos)
                        yield _make_token(src, "LBRACE", "{", brace)
                        pos = brace + 1
                        continue

                if ident == "if":
                    brace = src.find_next_unquoted(after_ident, "{")
                    if brace != -1:
                        yield _make_token(src, "IF", ident, pos)
                        yield _make_token(src, "HEADER", text[after_ident:brace].strip(), after_ident)
                        yield _make_token(src, "LBRACE", "{", brace)
                        pos = brace + 1
                        continue

                if ident == "else":
                    yield _make_token(src, "ELSE", ident, pos)
                    pos = after_ident
                    continue

                if ident == "elsif":
                    # Logstash accepts both `else if` and the Ruby-style `elsif`.
                    # Synthesize ELSE + IF + HEADER + LBRACE so the existing
                    # grammar parses both forms identically.
                    brace = src.find_next_unquoted(after_ident, "{")
                    if brace != -1:
                        yield _make_token(src, "ELSE", ident, pos)
                        yield _make_token(src, "IF", ident, pos)
                        yield _make_token(src, "HEADER", text[after_ident:brace].strip(), after_ident)
                        yield _make_token(src, "LBRACE", "{", brace)
                        pos = brace + 1
                        continue

                if ident == "for":
                    brace = src.find_next_unquoted(after_ident, "{")
                    if brace != -1:
                        yield _make_token(src, "FOR", ident, pos)
                        yield _make_token(src, "HEADER", text[after_ident:brace].strip(), after_ident)
                        yield _make_token(src, "LBRACE", "{", brace)
                        pos = brace + 1
                        continue

                brace = _skip_ws(text, after_ident)
                if brace < end and text[brace] == "{":
                    close = src.find_matching(brace)
                    if close != -1:
                        body = text[brace + 1 : close]
                        yield _make_token(src, "IDENT", ident, pos)
                        yield _make_token(src, "CONFIG", body, brace + 1)
                        pos = close + 1
                        continue

            # Unknown statement. Keep a token so the grammar and analyzer can
            # report it deterministically instead of crashing.
            next_nl = text.find("\n", pos, end)
            next_rb = text.find("}", pos, end)
            candidates = [x for x in (next_nl, next_rb) if x != -1]
            stop = min(candidates) if candidates else end
            snippet = text[pos:stop].strip()
            if snippet:
                yield _make_token(src, "UNKNOWN", snippet, pos)
            if stop <= pos:
                raise RuntimeError("SecOps lexer failed to make progress while recovering an unknown statement")
            pos = max(stop, pos + 1)


_LALR = Lark(_LALR_GRAMMAR, parser="lalr", lexer=_SecOpsLexer, maybe_placeholders=False, cache=False)


def _candidate_statement_end(src: SourceText, pos: int, ident: str, after_ident: int, limit: int) -> int:
    text = src.text
    if ident in ("filter", "input", "output"):
        brace = _skip_ws(text, after_ident)
        if brace >= limit or text[brace] != "{":
            return -1
        return src.find_matching(brace)
    if ident in {"if", "for"}:
        brace = src.find_next_unquoted(after_ident, "{", limit)
        if brace == -1 or brace >= limit:
            return -1
        close = src.find_matching(brace)
        if close == -1:
            return -1
        if ident == "if":
            return _extend_if_chain_end(src, close, limit)
        return close
    if ident == "else":
        return -1
    brace = _skip_ws(text, after_ident)
    if brace >= limit or text[brace] != "{":
        return -1
    return src.find_matching(brace)


def _extend_if_chain_end(src: SourceText, close: int, limit: int) -> int:
    text = src.text
    out = close
    pos = close + 1
    while True:
        pos = _skip_ws(text, pos)
        if pos >= limit:
            return out
        ident, after_ident = _read_ident(text, pos)
        if ident == "elsif":
            # `elsif` is a single token equivalent to `else if`; treat as such.
            brace = src.find_next_unquoted(after_ident, "{", limit)
        elif ident != "else":
            return out
        else:
            after_ident = _skip_ws(text, after_ident)
            if text.startswith("if", after_ident):
                if_ident, after_if = _read_ident(text, after_ident)
                if if_ident != "if":
                    return out
                brace = src.find_next_unquoted(after_if, "{", limit)
            else:
                brace = _skip_ws(text, after_ident)
        if ident is None:
            return out
        if brace == -1 or brace >= limit or text[brace] != "{":
            return out
        branch_close = src.find_matching(brace)
        if branch_close == -1:
            return out
        out = branch_close
        pos = branch_close + 1


def _filter_body_bounds(src: SourceText) -> tuple[int, int]:
    text = src.text
    pos = _skip_ws(text, 0)
    ident, after_ident = _read_ident(text, pos)
    if ident == "filter":
        brace = _skip_ws(text, after_ident)
        if brace < len(text) and text[brace] == "{":
            close = src.find_matching(brace)
            if close == -1:
                close = src.scanner_index.fallback_close
                if close <= brace:
                    close = len(text)
            return brace + 1, close
    return 0, len(text)


def _parse_recovery_fragment(src: SourceText, start: int, end: int, *, base_line: int = 1) -> list[Statement]:
    line = src.line_at(start)
    fragment = src.original[start:end]
    return LalrSecOpsAstParser(fragment, base_line=base_line + line - 1).parse()


def _collect_recoverable_spans(src: SourceText, start: int, limit: int) -> list[tuple[int, int]]:
    text = src.text
    spans: list[tuple[int, int]] = []
    pos = start
    while pos < limit:
        pos = _skip_ws(text, pos)
        if pos >= limit or text[pos] == "}":
            break
        ident, after_ident = _read_ident(text, pos)
        if ident is None or ident == "else":
            break
        end = _candidate_statement_end(src, pos, ident, after_ident, limit)
        if end == -1 or end >= limit:
            break
        spans.append((pos, end))
        pos = end + 1
    return spans


def _parse_recovery_spans(src: SourceText, spans: list[tuple[int, int]], *, base_line: int = 1) -> list[Statement]:
    if not spans:
        return []
    start = spans[0][0]
    end = spans[-1][1] + 1
    try:
        return _parse_recovery_fragment(src, start, end, base_line=base_line)
    except LarkError:
        statements: list[Statement] = []
        for span_start, span_end in spans:
            try:
                statements.extend(_parse_recovery_fragment(src, span_start, span_end + 1, base_line=base_line))
            except LarkError:
                statements.append(
                    Unknown(
                        line=base_line + src.line_at(span_start) - 1,
                        text="parse recovery skipped malformed statement",
                    )
                )
        return statements


def _find_next_recoverable_statement(src: SourceText, start: int, limit: int) -> int:
    text = src.text
    pos = start
    while pos < limit:
        ident, after_ident = _read_ident(text, pos)
        if ident is not None and ident != "else":
            end = _candidate_statement_end(src, pos, ident, after_ident, limit)
            if end != -1 and end < limit:
                return pos
        next_nl = text.find("\n", pos, limit)
        pos = next_nl + 1 if next_nl != -1 else limit
        pos = _skip_ws(text, pos)
    return -1


def _recover_parse_after_lark_error(
    code: str, original: ParseDiagnostic, *, base_line: int = 1
) -> tuple[list[Statement], list[ParseDiagnostic]]:
    src = SourceText.from_code(code)
    text = src.text
    start, limit = _filter_body_bounds(src)
    pos = start
    statements: list[Statement] = []
    diagnostics = [
        original,
        ParseDiagnostic(
            original.line, original.column, "Recovered parser after Lark failure; malformed spans emitted as Unknown"
        ),
    ]
    while pos < limit:
        pos = _skip_ws(text, pos)
        if pos >= limit:
            break
        if text[pos] == "}":
            pos += 1
            continue
        ident, after_ident = _read_ident(text, pos)
        if ident is None:
            next_pos = text.find("\n", pos, limit)
            if next_pos == -1:
                break
            pos = next_pos + 1
            continue
        spans = _collect_recoverable_spans(src, pos, limit)
        if spans:
            statements.extend(_parse_recovery_spans(src, spans, base_line=base_line))
            pos = spans[-1][1] + 1
            continue
        resync = _find_next_recoverable_statement(src, pos + 1, limit)
        line = base_line + src.line_at(pos) - 1
        if resync == -1:
            statements.append(Unknown(line=line, text="parse recovery skipped malformed statement until end of file"))
            break
        statements.append(
            Unknown(
                line=line,
                text=(f"parse recovery skipped malformed statement before line {base_line + src.line_at(resync) - 1}"),
            )
        )
        pos = resync
    if not statements:
        statements = [
            Unknown(line=original.line, text=f"Lark parse failure at column {original.column}: {original.message}")
        ]
    return statements, diagnostics


class _TreeToAst(Transformer):
    def __init__(self, code: str, *, base_line: int = 1):
        super().__init__()
        self.code = code
        self.base_line = base_line
        self._src: SourceText | None = None

    @property
    def src(self) -> SourceText:
        if self._src is None:
            self._src = SourceText.from_code(self.code)
        return self._src

    def _line(self, token: Token, default_pos: int = 0) -> int:
        local_line = token.line if token.line is not None else self.src.line_at(token.start_pos or default_pos)
        return self.base_line + local_line - 1

    def _statement_list(self, children: list[object]) -> list[Statement]:
        out: list[Statement] = []
        for child in children:
            if isinstance(child, Token):
                continue
            if isinstance(child, list):
                out.extend(item for item in child if isinstance(item, Statement))
            elif isinstance(child, Statement):
                out.append(child)
        return out

    def start(self, children: list[object]) -> list[Statement]:
        return self._statement_list(children)

    def block(self, children: list[object]) -> list[Statement]:
        return self._statement_list(children)

    def filter_block(self, children: list[object]) -> list[Statement] | IOBlock:
        # The keyword (filter/input/output) is the FILTER token's value.
        kind_tok = next(
            (ch for ch in children if isinstance(ch, Token) and ch.type == "FILTER"),
            None,
        )
        kind = str(kind_tok.value) if kind_tok is not None else "filter"
        body: list[Statement] = []
        for child in children:
            if isinstance(child, list):
                body = [stmt for stmt in child if isinstance(stmt, Statement)]
                break
        if kind == "filter":
            # Existing behavior: filter blocks flatten into the top-level
            # statement list so the analyzer walks them directly.
            return body
        # input/output blocks get a dedicated AST wrapper so the analyzer can
        # treat their inner plugins as anchors instead of normal filter ops.
        line = self._line(kind_tok) if kind_tok is not None else 1
        return IOBlock(line=line, kind=kind, body=body)

    def plugin(self, children: list[object]) -> Plugin:
        ident = next(ch for ch in children if isinstance(ch, Token) and ch.type == "IDENT")
        config = next(ch for ch in children if isinstance(ch, Token) and ch.type == "CONFIG")
        body = str(config.value)
        if str(ident.value) == "on_error":
            parsed_config: list[ConfigPair] = []
            diagnostics: list[SyntaxDiagnostic] = []
        else:
            parsed_config, diagnostics = parse_config_with_diagnostics(body)
        return Plugin(
            line=self._line(ident),
            name=str(ident.value),
            body=body,
            config=parsed_config,
            config_diagnostics=diagnostics,
            body_line=self._line(config) if config.line is not None else self._line(ident),
        )

    def unknown(self, children: list[object]) -> Unknown:
        tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "UNKNOWN")
        return Unknown(line=self._line(tok), text=str(tok.value))

    def for_block(self, children: list[object]) -> ForBlock:
        for_tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "FOR")
        header_tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "HEADER")
        body = next((ch for ch in children if isinstance(ch, list)), [])
        variables, iterable, is_map = parse_for_header(str(header_tok.value))
        return ForBlock(
            line=self._line(for_tok),
            variables=variables,
            iterable=iterable,
            is_map=is_map,
            body=[stmt for stmt in body if isinstance(stmt, Statement)],
            header=str(header_tok.value),
        )

    def elif_clause(self, children: list[object]) -> ElifBlock:
        else_tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "ELSE")
        header_tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "HEADER")
        body = next((ch for ch in children if isinstance(ch, list)), [])
        return ElifBlock(
            line=self._line(else_tok),
            condition=str(header_tok.value),
            body=[stmt for stmt in body if isinstance(stmt, Statement)],
        )

    def else_clause(self, children: list[object]) -> tuple[list[Statement]]:
        body = next((ch for ch in children if isinstance(ch, list)), [])
        return ([stmt for stmt in body if isinstance(stmt, Statement)],)

    def if_block(self, children: list[object]) -> IfBlock:
        if_tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "IF")
        header_tok = next(ch for ch in children if isinstance(ch, Token) and ch.type == "HEADER")
        blocks = [ch for ch in children if isinstance(ch, list)]
        then_body = [stmt for stmt in blocks[0] if isinstance(stmt, Statement)] if blocks else []
        stmt = IfBlock(line=self._line(if_tok), condition=str(header_tok.value), then_body=then_body)
        for child in children:
            if isinstance(child, ElifBlock):
                stmt.elifs.append(child)
            elif isinstance(child, tuple):
                (body,) = child
                stmt.else_body = body
        return stmt


class LalrSecOpsAstParser:
    """Lex/Yacc-style parser frontend using a stateful lexer and Lark LALR parser."""

    def __init__(self, code: str, *, base_line: int = 1):
        self.code = code
        self.base_line = base_line

    def parse(self) -> list[Statement]:
        tree = _LALR.parse(self.code)
        converted = _TreeToAst(self.code, base_line=self.base_line).transform(tree)
        if not isinstance(converted, list):
            raise TypeError("Statement parser produced a non-list AST root")
        return [stmt for stmt in converted if isinstance(stmt, Statement)]


ParseDiagnostic = SyntaxDiagnostic


def parse_code_with_diagnostics(code: str, *, start_line: int = 1) -> tuple[list[Statement], list[ParseDiagnostic]]:
    try:
        return LalrSecOpsAstParser(code, base_line=start_line).parse(), []
    except RecursionError:
        diagnostic = ParseDiagnostic(start_line, 1, "Parser nesting depth exceeded while building AST")
        return [Unknown(line=start_line, text="parser nesting depth exceeded while building AST")], [
            diagnostic,
            ParseDiagnostic(
                start_line, 1, "Recovered parser after nesting-depth failure; malformed span emitted as Unknown"
            ),
        ]
    except LarkError as exc:
        line = start_line + (getattr(exc, "line", None) or 1) - 1
        column = getattr(exc, "column", None) or 1
        message = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        message = _specialize_lark_error_message(code, exc, message, start_line)
        diagnostic = ParseDiagnostic(line, column, message)
        return _recover_parse_after_lark_error(code, diagnostic, base_line=start_line)


_ELSE_IF_AT_LINE_START_RE = re.compile(r"\s*\}?\s*else\s+if\b")


def _specialize_lark_error_message(code: str, exc: object, message: str, start_line: int) -> str:
    """Replace generic Lark messages with actionable ones for known shapes (W4).

    Lark only knows it received an unexpected ELSE token. When that token is the
    start of an `else if` clause that the grammar refused (because a prior
    `else` already closed the chain, or because the file opens with a stray
    `else if`), translate the message into something a human can act on without
    needing to consult the grammar file.
    """
    token = getattr(exc, "token", None)
    token_type = getattr(token, "type", None) if token is not None else None
    if token_type != "ELSE" and "Token('ELSE'" not in message:
        return message
    raw_line = getattr(exc, "line", None) or 1
    pos = _line_offset(code, raw_line - 1)
    if pos is None:
        return message
    snippet = code[pos : pos + 32]
    if not _ELSE_IF_AT_LINE_START_RE.match(snippet):
        return message
    actual_line = start_line + raw_line - 1
    return (
        f"line {actual_line}: 'else if' cannot follow a bare 'else' clause (or appear without a "
        f"preceding 'if' at this level); convert the trailing 'else if' branches to standalone 'if' statements"
    )


def _line_offset(text: str, line_zero_indexed: int) -> int | None:
    if line_zero_indexed < 0:
        return None
    pos = 0
    for _ in range(line_zero_indexed):
        nl = text.find("\n", pos)
        if nl == -1:
            return None
        pos = nl + 1
    return pos


def parse_code(code: str) -> list[Statement]:
    return parse_code_with_diagnostics(code)[0]
