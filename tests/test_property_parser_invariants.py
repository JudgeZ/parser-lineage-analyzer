"""Property-based tests for parser entry-point invariants.

The two ``*_with_diagnostics`` entry points are designed to capture every
parse failure as a diagnostic and return — they must never propagate an
exception to the caller, regardless of input. This is the security-relevant
invariant: a parser exposed to untrusted operator input cannot turn a
malformed file into an unhandled crash.

Hypothesis explores arbitrary unicode and a grammar-biased alphabet; the
deadline doubles as a ReDoS / pathological-backtracking guard.
"""

from __future__ import annotations

from collections.abc import Callable

from hypothesis import given, strategies as st

from parser_lineage_analyzer.config_parser import parse_config_with_diagnostics
from parser_lineage_analyzer.model import SyntaxDiagnostic
from parser_lineage_analyzer.parser import parse_code_with_diagnostics

# Grammar-biased alphabet: characters that frequently appear in SecOps
# parser source (braces, quotes, arrows, comments) maximise the chance of
# hitting interesting parser branches versus uniform-random unicode.
_GRAMMAR_ALPHABET = st.characters(
    categories=("L", "N", "P", "Z"),
    include_characters="\n\t \"'\\{}[]()=>,;:%/.|#",
)
GRAMMAR_BIASED_TEXT = st.text(alphabet=_GRAMMAR_ALPHABET, max_size=512)
ARBITRARY_TEXT = st.text(max_size=512)
INPUTS = st.one_of(GRAMMAR_BIASED_TEXT, ARBITRARY_TEXT)


def _assert_diagnostics_well_formed(diagnostics: list[SyntaxDiagnostic]) -> None:
    for diag in diagnostics:
        assert isinstance(diag, SyntaxDiagnostic)
        assert diag.line >= 1
        assert diag.column >= 1
        assert isinstance(diag.message, str)
        assert diag.message  # non-empty


@given(INPUTS)
def test_parse_code_with_diagnostics_never_raises(text: str) -> None:
    statements, diagnostics = parse_code_with_diagnostics(text)
    assert isinstance(statements, list)
    assert isinstance(diagnostics, list)
    _assert_diagnostics_well_formed(diagnostics)


@given(INPUTS)
def test_parse_config_with_diagnostics_never_raises(text: str) -> None:
    pairs, diagnostics = parse_config_with_diagnostics(text)
    assert isinstance(pairs, list)
    assert isinstance(diagnostics, list)
    _assert_diagnostics_well_formed(diagnostics)


# --- Structured-input strategies ---------------------------------------------
#
# Random-unicode fuzzing mostly bounces off the lexer. Building near-valid
# fragments — plugin blocks, conditionals, nested braces — pushes inputs
# into the AST builder and the recovery-after-LarkError path, which is
# where the harder bugs live.

_SAFE_IDENT = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=8)
_SAFE_STRING_BODY = st.text(
    alphabet=st.characters(exclude_characters='"\\\n', categories=("L", "N", "P", "Z")),
    max_size=20,
)
_PLUGIN_NAMES = st.sampled_from(["json", "grok", "mutate", "kv", "csv", "xml", "date", "drop", "ruby"])
_CORRUPTION_FUNCS: list[Callable[[str], str]] = [
    lambda s: s,
    lambda s: s[:-1] if s else s,  # truncate
    lambda s: s.replace("}", "", 1),  # drop one closing brace
    lambda s: s.replace('"', "", 1),  # unbalance a quote
    lambda s: s + " { dangling",  # append unclosed block
    lambda s: s.replace("=>", "==", 1),  # corrupt the arrow
    lambda s: s + "\n" + s,  # duplicate (stress recovery)
]
_CORRUPTIONS = st.sampled_from(_CORRUPTION_FUNCS)


@st.composite
def _config_value(draw: st.DrawFn, depth: int = 0) -> str:
    if depth >= 2:
        kind = draw(st.sampled_from(["string", "ident"]))
    else:
        kind = draw(st.sampled_from(["string", "ident", "map", "array", "bracket"]))
    if kind == "string":
        return '"' + draw(_SAFE_STRING_BODY) + '"'
    if kind == "ident":
        return draw(_SAFE_IDENT)
    if kind == "bracket":
        return "[" + draw(_SAFE_IDENT) + "]"
    if kind == "map":
        n = draw(st.integers(min_value=0, max_value=3))
        items = [f'"{draw(_SAFE_IDENT)}" => {draw(_config_value(depth + 1))}' for _ in range(n)]
        return "{ " + " ".join(items) + " }"
    # array
    n = draw(st.integers(min_value=0, max_value=3))
    items = [draw(_config_value(depth + 1)) for _ in range(n)]
    return "[" + ", ".join(items) + "]"


@st.composite
def _config_body(draw: st.DrawFn) -> str:
    n = draw(st.integers(min_value=0, max_value=6))
    pairs = [f'"{draw(_SAFE_IDENT)}" => {draw(_config_value())}' for _ in range(n)]
    body = " ".join(pairs)
    return draw(_CORRUPTIONS)(body)


@st.composite
def _plugin_block(draw: st.DrawFn) -> str:
    name = draw(_PLUGIN_NAMES)
    body = draw(_config_body())
    return f"{name} {{ {body} }}"


@st.composite
def _statement(draw: st.DrawFn, depth: int = 0) -> str:
    if depth >= 3:
        return draw(_plugin_block())
    kind = draw(st.sampled_from(["plugin", "filter", "if"]))
    if kind == "plugin":
        return draw(_plugin_block())
    if kind == "filter":
        n = draw(st.integers(min_value=0, max_value=3))
        inner = " ".join(draw(_statement(depth + 1)) for _ in range(n))
        return f"filter {{ {inner} }}"
    # if-block
    field = draw(_SAFE_IDENT)
    op = draw(st.sampled_from(["==", "!=", "=~", "!~"]))
    val = '"' + draw(_SAFE_STRING_BODY) + '"'
    body = draw(_plugin_block())
    fragment = f"if [{field}] {op} {val} {{ {body} }}"
    if draw(st.booleans()):
        fragment += f" else {{ {draw(_plugin_block())} }}"
    return fragment


@st.composite
def secops_code(draw: st.DrawFn) -> str:
    n = draw(st.integers(min_value=1, max_value=4))
    fragment = " ".join(draw(_statement()) for _ in range(n))
    return draw(_CORRUPTIONS)(fragment)


@given(secops_code())
def test_parse_code_structured_never_raises(text: str) -> None:
    statements, diagnostics = parse_code_with_diagnostics(text)
    assert isinstance(statements, list)
    assert isinstance(diagnostics, list)
    _assert_diagnostics_well_formed(diagnostics)


@given(_config_body())
def test_parse_config_structured_never_raises(text: str) -> None:
    pairs, diagnostics = parse_config_with_diagnostics(text)
    assert isinstance(pairs, list)
    assert isinstance(diagnostics, list)
    _assert_diagnostics_well_formed(diagnostics)
