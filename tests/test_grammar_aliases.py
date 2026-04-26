"""Grammar-alias equivalence tests.

Logstash and the analyzer accept both ``else if`` and the Ruby-style
``elsif`` keyword. The lexer treats ``elsif`` as ``ELSE`` + ``IF`` so the
LALR grammar parses both forms via the same rule. These tests assert the
ALIAS doesn't drift from the canonical form's behavior — same UDM fields,
same per-field lineage, same warning codes for equivalent inputs.
"""

from __future__ import annotations

import pytest

from parser_lineage_analyzer import ReverseParser
from tests._typing_helpers import expect_mapping, expect_mapping_list, expect_str

# Each pair is (description, else_if_form, elsif_form). They must produce
# byte-identical analyzer output.
EQUIVALENT_PAIRS = [
    (
        "simple else-if chain",
        """
        filter {
          if [a] == "1" {
            mutate { replace => { "out" => "one" } }
          } else if [a] == "2" {
            mutate { replace => { "out" => "two" } }
          } else {
            mutate { replace => { "out" => "other" } }
          }
        }
        """,
        """
        filter {
          if [a] == "1" {
            mutate { replace => { "out" => "one" } }
          } elsif [a] == "2" {
            mutate { replace => { "out" => "two" } }
          } else {
            mutate { replace => { "out" => "other" } }
          }
        }
        """,
    ),
    (
        "elsif as final clause (no else)",
        """
        filter {
          if [t] == "x" {
            mutate { replace => { "f" => "v1" } }
          } else if [t] == "y" {
            mutate { replace => { "f" => "v2" } }
          }
        }
        """,
        """
        filter {
          if [t] == "x" {
            mutate { replace => { "f" => "v1" } }
          } elsif [t] == "y" {
            mutate { replace => { "f" => "v2" } }
          }
        }
        """,
    ),
    (
        "nested if/elsif inside if",
        """
        filter {
          if [outer] == "yes" {
            if [inner] == "a" {
              mutate { replace => { "x" => "1" } }
            } else if [inner] == "b" {
              mutate { replace => { "x" => "2" } }
            }
          }
        }
        """,
        """
        filter {
          if [outer] == "yes" {
            if [inner] == "a" {
              mutate { replace => { "x" => "1" } }
            } elsif [inner] == "b" {
              mutate { replace => { "x" => "2" } }
            }
          }
        }
        """,
    ),
    (
        "elsif followed by bare else",
        """
        filter {
          if [k] == "p" {
            mutate { replace => { "r" => "p_val" } }
          } else if [k] == "q" {
            mutate { replace => { "r" => "q_val" } }
          } else {
            mutate { replace => { "r" => "default" } }
          }
        }
        """,
        """
        filter {
          if [k] == "p" {
            mutate { replace => { "r" => "p_val" } }
          } elsif [k] == "q" {
            mutate { replace => { "r" => "q_val" } }
          } else {
            mutate { replace => { "r" => "default" } }
          }
        }
        """,
    ),
    (
        "two consecutive elsif clauses",
        """
        filter {
          if [s] == "a" {
            mutate { replace => { "z" => "A" } }
          } else if [s] == "b" {
            mutate { replace => { "z" => "B" } }
          } else if [s] == "c" {
            mutate { replace => { "z" => "C" } }
          }
        }
        """,
        """
        filter {
          if [s] == "a" {
            mutate { replace => { "z" => "A" } }
          } elsif [s] == "b" {
            mutate { replace => { "z" => "B" } }
          } elsif [s] == "c" {
            mutate { replace => { "z" => "C" } }
          }
        }
        """,
    ),
]


@pytest.mark.parametrize(
    "description,else_if_form,elsif_form",
    EQUIVALENT_PAIRS,
    ids=[p[0] for p in EQUIVALENT_PAIRS],
)
def test_elsif_lineage_matches_else_if(description: str, else_if_form: str, elsif_form: str) -> None:
    canon = ReverseParser(else_if_form)
    alias = ReverseParser(elsif_form)

    canon_state = canon.analyze()
    alias_state = alias.analyze()

    # Same UDM fields surfaced (order doesn't matter, set comparison).
    assert set(canon.list_udm_fields()) == set(alias.list_udm_fields()), (
        f"{description}: UDM field set diverged between forms"
    )

    # Same warning codes.
    canon_codes = sorted(
        {
            expect_str(expect_mapping(w)["code"])
            for w in expect_mapping_list(canon.analysis_summary()["structured_warnings"])
        }
    )
    alias_codes = sorted(
        {
            expect_str(expect_mapping(w)["code"])
            for w in expect_mapping_list(alias.analysis_summary()["structured_warnings"])
        }
    )
    assert canon_codes == alias_codes, (
        f"{description}: warning codes diverged: canonical={canon_codes!r} vs alias={alias_codes!r}"
    )

    # Same set of tokens with lineage.
    assert set(canon_state.tokens) == set(alias_state.tokens), f"{description}: token set diverged between forms"

    # Per-token: same lineage source expressions and conditions.
    for token in canon_state.tokens:
        canon_lins = canon_state.tokens[token]
        alias_lins = alias_state.tokens[token]
        canon_summary = sorted(
            (
                lin.expression,
                tuple(lin.conditions),
                tuple(s.kind for s in lin.sources),
            )
            for lin in canon_lins
        )
        alias_summary = sorted(
            (
                lin.expression,
                tuple(lin.conditions),
                tuple(s.kind for s in lin.sources),
            )
            for lin in alias_lins
        )
        assert canon_summary == alias_summary, (
            f"{description}: token {token!r} lineage differs:\n  else_if: {canon_summary}\n  elsif:   {alias_summary}"
        )
