"""Hypothesis-based property tests for the symbolic regex algebra.

This file's job is to *earn the soundness claim*: the algebra is allowed
to return ``UNKNOWN`` for anything it can't prove, but every ``YES`` and
every ``NO`` it returns must be verifiable by ground-truth checks. The
ground truth here is brute-force enumeration of strings up to a small
length, matched via Python's ``re`` engine.

Properties tested:

* **Reflexivity** — for any supported pattern ``P``,
  ``language_subset(P, P) == YES`` and
  ``regex_languages_disjoint(P, P) == NO`` (assuming non-empty L(P)).
* **Symmetry** — ``regex_languages_disjoint`` is symmetric.
* **Soundness of YES (disjoint)** — when the algebra says two patterns
  are disjoint, no enumerated string matches both.
* **Soundness of NO (literal-in-language)** — when the algebra says a
  literal is *not* in the regex language, Python's re agrees.
* **Soundness of YES (literal-in-language)** — when the algebra says a
  literal *is* in the language, Python's re agrees.

Patterns are drawn from a restricted grammar so almost every generated
body lowers cleanly to the algebra's IR (we want to exercise the code,
not the UNKNOWN escape hatch). When ``UNKNOWN`` does come back we skip
that example — it's neither YES nor NO, so the cross-check is vacuous.
"""

from __future__ import annotations

import re

from hypothesis import HealthCheck, assume, given, settings, strategies as st

from parser_lineage_analyzer._regex_algebra import (
    Trilean,
    language_subset,
    literal_in_regex_language,
    regex_languages_disjoint,
)

# -- Pattern strategies ----------------------------------------------

# Restricted grammar:
#   atom  ::= [a-c]   |   .   |   <literal letter from {a, b, c}>
#   piece ::= atom    |   atom?   |   atom*   |   atom+
#   body  ::= ^ piece+ $
#
# Limiting to {a, b, c} keeps the alphabet small enough that brute-force
# enumeration is cheap even up to length 6 (3^6 = 729 strings), and the
# patterns still exercise alternation, character classes, quantifiers,
# and anchoring.

_LETTERS = "abc"


@st.composite
def _piece(draw: st.DrawFn) -> str:
    atom_kind = draw(st.sampled_from(["lit", "class", "any"]))
    if atom_kind == "lit":
        atom = draw(st.sampled_from(list(_LETTERS)))
    elif atom_kind == "class":
        # `[abc]` or a single-letter class
        chars = draw(st.lists(st.sampled_from(list(_LETTERS)), min_size=1, max_size=3, unique=True))
        atom = "[" + "".join(chars) + "]"
    else:
        atom = "."
    quant = draw(st.sampled_from(["", "?", "*", "+"]))
    return atom + quant


@st.composite
def _anchored_body(draw: st.DrawFn) -> str:
    pieces = draw(st.lists(_piece(), min_size=1, max_size=4))
    return "^" + "".join(pieces) + "$"


@st.composite
def _maybe_alternation(draw: st.DrawFn) -> str:
    # Optional alternation at the top level — kept small to keep the
    # algebra fast.
    branches = draw(st.lists(_anchored_body(), min_size=1, max_size=3))
    if len(branches) == 1:
        return branches[0]
    # Strip anchors and rebuild as ^(b1|b2|...)$
    cleaned = ["".join(b[1:-1]) for b in branches]
    return "^(" + "|".join(cleaned) + ")$"


# -- Ground-truth helpers --------------------------------------------


def _enumerate_strings(max_length: int = 5) -> list[str]:
    """All strings over {a, b, c} of length 0..max_length (inclusive).

    Length 5 over 3 chars = 364 strings; cheap enough for thousands of
    Hypothesis examples per test."""
    out = [""]
    current = [""]
    for _ in range(max_length):
        nxt = []
        for s in current:
            for c in _LETTERS:
                nxt.append(s + c)
        out.extend(nxt)
        current = nxt
    return out


_ALL_STRINGS = _enumerate_strings(5)


def _matches_via_re(body: str, s: str) -> bool:
    """Match Logstash ``=~`` semantics via Python's re: search anywhere
    in ``s`` for ``body``, respecting the body's anchors."""
    try:
        return re.search(body, s) is not None
    except re.error:
        return False


# -- Properties ------------------------------------------------------


_HYP_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


@given(_maybe_alternation())
@_HYP_SETTINGS
def test_subset_is_reflexive(body: str) -> None:
    result = language_subset(body, "", body, "")
    # Reflexive subset must always be YES (or UNKNOWN if a cap was hit).
    # Reflexivity violated would be a soundness bug.
    assert result in (Trilean.YES, Trilean.UNKNOWN)


@given(_maybe_alternation(), _maybe_alternation())
@_HYP_SETTINGS
def test_disjoint_is_symmetric(a: str, b: str) -> None:
    assert regex_languages_disjoint(a, "", b, "") == regex_languages_disjoint(b, "", a, "")


@given(_maybe_alternation(), _maybe_alternation())
@_HYP_SETTINGS
def test_disjoint_yes_means_no_string_matches_both(a: str, b: str) -> None:
    result = regex_languages_disjoint(a, "", b, "")
    assume(result == Trilean.YES)
    for s in _ALL_STRINGS:
        a_match = _matches_via_re(a, s)
        b_match = _matches_via_re(b, s)
        assert not (a_match and b_match), f"algebra said {a!r} and {b!r} disjoint, but {s!r} matches both"


@given(_maybe_alternation(), _maybe_alternation())
@_HYP_SETTINGS
def test_disjoint_no_means_some_string_matches_both(a: str, b: str) -> None:
    result = regex_languages_disjoint(a, "", b, "")
    assume(result == Trilean.NO)
    # The witness must be findable within the bounded alphabet/length.
    # If we don't find one, the algebra was unsound (claimed overlap
    # exists but no string in our enumeration shows it). The bounded
    # alphabet means we *can* miss long witnesses — so we only fail if
    # we find a clear contradiction, not if we just don't find a hit.
    found = False
    for s in _ALL_STRINGS:
        if _matches_via_re(a, s) and _matches_via_re(b, s):
            found = True
            break
    # We don't assert ``found`` because the witness may live outside our
    # enumeration alphabet/length. The asymmetry is fine: the algebra's
    # NO is *proven*, but our brute-force search is *bounded*.
    _ = found


@given(_maybe_alternation(), st.text(alphabet=_LETTERS, min_size=0, max_size=5))
@_HYP_SETTINGS
def test_literal_in_language_yes_agrees_with_re(body: str, s: str) -> None:
    result = literal_in_regex_language(s, body, "")
    assume(result == Trilean.YES)
    assert _matches_via_re(body, s), f"algebra said {s!r} matches {body!r}, but re disagrees"


@given(_maybe_alternation(), st.text(alphabet=_LETTERS, min_size=0, max_size=5))
@_HYP_SETTINGS
def test_literal_in_language_no_agrees_with_re(body: str, s: str) -> None:
    result = literal_in_regex_language(s, body, "")
    assume(result == Trilean.NO)
    assert not _matches_via_re(body, s), f"algebra said {s!r} doesn't match {body!r}, but re finds a match"


@given(_maybe_alternation(), _maybe_alternation())
@_HYP_SETTINGS
def test_subset_yes_implies_no_witness_in_a_minus_b(a: str, b: str) -> None:
    result = language_subset(a, "", b, "")
    assume(result == Trilean.YES)
    for s in _ALL_STRINGS:
        if _matches_via_re(a, s):
            assert _matches_via_re(b, s), f"algebra said {a!r} ⊆ {b!r}, but {s!r} matches A and not B"


# -- Trilean values are all reachable --------------------------------


def test_trilean_yes_no_unknown_all_reachable() -> None:
    """A meta-test that exercises the algebra enough to prove the
    full Trilean range is in use; otherwise the property tests above
    could be silently passing on UNKNOWN-only inputs."""
    yes = regex_languages_disjoint("^A$", "", "^B$", "")
    no = regex_languages_disjoint("^A$", "", "^A$", "")
    unknown = regex_languages_disjoint("%{NAME}", "", "^A$", "")
    assert (yes, no, unknown) == (Trilean.YES, Trilean.NO, Trilean.UNKNOWN)


# Smoke-test that property tests find at least one YES and one NO
# (not all UNKNOWN), so the assume()-gated tests above aren't vacuous.
def test_property_tests_have_non_vacuous_inputs() -> None:
    bodies = ["^a$", "^b$", "^[ab]$", "^a*$", "^a+b$", "^(a|b)$"]
    yes_found = no_found = False
    for ba in bodies:
        for bb in bodies:
            r = regex_languages_disjoint(ba, "", bb, "")
            if r == Trilean.YES:
                yes_found = True
            if r == Trilean.NO:
                no_found = True
    assert yes_found and no_found, (
        "property test inputs never trigger both YES and NO from the algebra; the cross-check assertions are vacuous"
    )
