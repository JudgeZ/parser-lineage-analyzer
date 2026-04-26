"""Behavioral tests for ``_normalize_condition`` fast path.

Guard against regressions in the already-normalized fast path: the function
must return identical output to the slow ``" ".join(str(x).strip().split())``
implementation for every input.
"""

from __future__ import annotations

import pytest

from parser_lineage_analyzer._analysis_condition_facts import _normalize_condition


def _slow_normalize(condition: object) -> str:
    return " ".join(str(condition).strip().split())


@pytest.mark.parametrize(
    "value",
    [
        '[event][type] == "login"',
        '[a] != "b"',
        'NOT([x] == "y")',
        "a",
        "",
        "single-token",
        '[a] == "x" and [b] == "y"',
        '[a] == "x" or [b] == "y"',
        '[a] == "with space inside quotes"',
    ],
)
def test_already_normalized_fast_path_matches_slow_path(value: str) -> None:
    assert _normalize_condition(value) == _slow_normalize(value)


@pytest.mark.parametrize(
    "messy,expected",
    [
        ("  leading", "leading"),
        ("trailing  ", "trailing"),
        ("  both  ", "both"),
        ("a  b", "a b"),
        ("a   b   c", "a b c"),
        ("a\tb", "a b"),
        ("a\nb", "a b"),
        ("a \t b", "a b"),
        ("\t\nleading-ws", "leading-ws"),
        ("trailing-ws\t\n", "trailing-ws"),
        ("  multi   spaces  and\ttabs\n", "multi spaces and tabs"),
    ],
)
def test_messy_strings_normalize_correctly(messy: str, expected: str) -> None:
    assert _normalize_condition(messy) == expected
    # And the slow path agrees, sanity-checking the test fixtures themselves.
    assert _slow_normalize(messy) == expected


def test_non_string_input_uses_str() -> None:
    # Both paths coerce via str(); confirm parity for a few non-string inputs.
    for value in (None, 42, ("a", "b")):
        assert _normalize_condition(value) == _slow_normalize(value)


def test_empty_string_returns_empty_string() -> None:
    assert _normalize_condition("") == ""
