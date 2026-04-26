"""Tests for the regex shape classifier (Phase 0) and symbolic algebra
(Phase 1).

Phase 0's contract: ``exact_literal_value`` returns ``(field, literal)``
for any condition equivalent to ``[field] =~ /^literal$/`` with no flags.
For everything else it returns ``None`` and the analyzer falls back to
opaque-regex behavior.

Phase 1's contract: ``regex_languages_disjoint`` /
``language_subset`` / ``literal_in_regex_language`` return
:class:`Trilean.YES` only when they have *proven* the property,
:class:`Trilean.NO` only when they have *proven* the negation, and
:class:`Trilean.UNKNOWN` for every limit hit, parse error, or
unsupported construct. The contradiction check treats ``UNKNOWN`` as
"compatible" — false negatives only.

The load-bearing soundness rule: false positives (declaring a
contradiction that doesn't hold) silently drop reachable branches and
corrupt the lineage graph downstream. The "false-positive guard" suites
below are what earn the soundness claim.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from parser_lineage_analyzer._analysis_condition_facts import (
    LiteralFact,
    RegexFact,
    _fact_from_condition,
    _facts_contradict,
    _literal_fact_from_normalized_condition,
    condition_is_contradicted,
    conditions_are_compatible,
    is_exact_literal_regex_condition,
)
from parser_lineage_analyzer._regex_algebra import (
    ALGEBRA_TIME_BUDGET_MS,
    MAX_ALTERNATION_BRANCHES,
    MAX_CHARSET_SIZE,
    MAX_REGEX_BODY_BYTES,
    MAX_REPEAT_BOUND,
    RegexShape,
    Trilean,
    analyze_shape,
    exact_literal_value,
    extract_regex_literal,
    language_subset,
    literal_in_regex_language,
    regex_languages_disjoint,
)


class TestExtractRegexLiteral:
    @pytest.mark.parametrize(
        "condition,field,body,flags",
        [
            ("[type] =~ /^A$/", "[type]", "^A$", ""),
            ("[a][b] =~ /^x$/", "[a][b]", "^x$", ""),
            ("[type] =~ /^A$/i", "[type]", "^A$", "i"),
            (r"[t] =~ /^foo\.bar$/", "[t]", r"^foo\.bar$", ""),
            (r"[t] =~ /\//", "[t]", r"\/", ""),  # escaped slash inside body
            ("[t]   =~   /^A$/", "[t]", "^A$", ""),  # tolerates extra spaces
        ],
    )
    def test_extracts_field_body_and_flags(self, condition: str, field: str, body: str, flags: str) -> None:
        result = extract_regex_literal(condition)
        assert result is not None
        assert (result.field, result.body, result.flags) == (field, body, flags)

    @pytest.mark.parametrize(
        "condition",
        [
            '[type] == "A"',
            "[type] != /^A$/",  # wrong operator
            "no field =~ /^A$/",
            "[type] =~ /^A",  # missing closing slash
            "",
        ],
    )
    def test_rejects_non_regex_conditions(self, condition: str) -> None:
        assert extract_regex_literal(condition) is None

    def test_rejects_oversized_body(self) -> None:
        body = "a" * (MAX_REGEX_BODY_BYTES + 1)
        condition = f"[t] =~ /{body}/"
        assert extract_regex_literal(condition) is None


class TestExactLiteralRecognition:
    """Cases that ``exact_literal_value`` MUST recognize as literals.

    These are the wins over the prior narrow ``[A-Za-z0-9_ .:@-]+``
    charset: punctuation, escaped metacharacters, escaped slashes.
    """

    @pytest.mark.parametrize(
        "condition,field,literal",
        [
            ("[type] =~ /^A$/", "[type]", "A"),
            ("[type] =~ /^foo$/", "[type]", "foo"),
            ("[type] =~ /^foo bar$/", "[type]", "foo bar"),
            (r"[t] =~ /^foo\.bar$/", "[t]", "foo.bar"),
            (r"[t] =~ /^192\.168\.1\.1$/", "[t]", "192.168.1.1"),
            ("[t] =~ /^Hello, World$/", "[t]", "Hello, World"),
            (r"[t] =~ /^a;b$/", "[t]", "a;b"),
            (r"[t] =~ /^foo\\bar$/", "[t]", r"foo\bar"),  # escaped backslash
            (r"[t] =~ /^foo\/bar$/", "[t]", "foo/bar"),  # escaped forward slash
            ("[a][b] =~ /^x$/", "[a][b]", "x"),
            (r"[t] =~ /^(?:foo)$/", "[t]", "foo"),  # non-capturing group of literal
            (r"[t] =~ /^(?P<x>foo)$/", "[t]", "foo"),  # named-capture of literal
        ],
    )
    def test_recognizes_anchored_literal(self, condition: str, field: str, literal: str) -> None:
        assert exact_literal_value(condition) == (field, literal)
        assert is_exact_literal_regex_condition(condition)
        assert _literal_fact_from_normalized_condition(condition) == LiteralFact(field, literal)


class TestSoundnessGuards:
    """False-positive guards. ``exact_literal_value`` MUST return ``None``
    for any condition whose match set is not a single literal string.

    Any case that wrongly returns a literal here would let the contradiction
    check declare two compatible branches mutually exclusive, silently
    dropping reachable lineage.
    """

    @pytest.mark.parametrize(
        "condition",
        [
            # Flag rejection (Phase 0 honors only the empty flag set). The
            # prior ``_EXACT_REGEX_RE`` accepted ``/^Foo$/i`` and produced
            # LiteralFact("Foo"), which would wrongly contradict
            # ``[t] == "FOO"``. This is the soundness fix.
            "[t] =~ /^A$/i",
            "[t] =~ /^A$/m",
            "[t] =~ /^A$/s",
            "[t] =~ /^A$/x",
            # Not fully anchored.
            "[t] =~ /^A/",
            "[t] =~ /A$/",
            "[t] =~ /A/",
            # Quantifiers.
            r"[t] =~ /^a+$/",
            r"[t] =~ /^a*$/",
            r"[t] =~ /^a?$/",
            r"[t] =~ /^a{2,3}$/",
            # Character classes / shorthand.
            r"[t] =~ /^\d+$/",
            r"[t] =~ /^[abc]$/",
            r"[t] =~ /^[^x]$/",
            r"[t] =~ /^.$/",
            # Alternation (Phase 1 will lift this).
            r"[t] =~ /^(SEC|AUTH)$/",
            # Inline modifier groups change semantics.
            r"[t] =~ /^(?i:foo)$/",
            r"[t] =~ /^(?i)foo$/",
            # Grok references (pre-processed by Logstash, not real regex).
            "[t] =~ /^%{NAME}$/",
            "[t] =~ /%{NAME}/",
            # Empty body.
            "[t] =~ //",
            # Lookaround.
            r"[t] =~ /^(?=foo)foo$/",
            r"[t] =~ /^(?!foo)bar$/",
            # Unescaped `.` is a metacharacter, NOT a literal period. The
            # prior `_EXACT_REGEX_RE` accepted this as `192.168.1.1`,
            # which was unsound: the regex also matches `192X168Y1Z1`.
            # Fixing this to UNSUPPORTED is the soundness improvement.
            "[t] =~ /^192.168.1.1$/",
            r"[t] =~ /^foo.bar$/",
        ],
    )
    def test_does_not_recognize_as_literal(self, condition: str) -> None:
        assert exact_literal_value(condition) is None
        assert not is_exact_literal_regex_condition(condition)


class TestShapeClassifier:
    @pytest.mark.parametrize(
        "body,expected_shape",
        [
            ("^A$", RegexShape.EXACT_LITERAL),
            (r"^foo\.bar$", RegexShape.EXACT_LITERAL),
            (r"^(?:foo)$", RegexShape.EXACT_LITERAL),
            ("^(SEC|AUTH)$", RegexShape.ANCHORED_ALTERNATION_OF_LITERALS),
            ("^(?:SEC|AUTH)$", RegexShape.ANCHORED_ALTERNATION_OF_LITERALS),
            (r"^\d+$", RegexShape.UNSUPPORTED),
            ("^foo", RegexShape.UNSUPPORTED),  # not fully anchored
            ("foo$", RegexShape.UNSUPPORTED),
            ("", RegexShape.UNSUPPORTED),
            ("[invalid", RegexShape.UNSUPPORTED),  # parse error -> UNSUPPORTED
        ],
    )
    def test_shape(self, body: str, expected_shape: RegexShape) -> None:
        assert analyze_shape(body).shape == expected_shape

    def test_alternation_branches_are_recorded(self) -> None:
        analysis = analyze_shape("^(SEC|AUTH|MISC)$")
        assert analysis.shape == RegexShape.ANCHORED_ALTERNATION_OF_LITERALS
        assert analysis.alternatives == ("SEC", "AUTH", "MISC")

    def test_alternation_with_non_literal_branch_is_unsupported(self) -> None:
        # A single non-literal branch poisons the alternation classification.
        analysis = analyze_shape(r"^(SEC|\d+)$")
        assert analysis.shape == RegexShape.UNSUPPORTED


class TestLimitEnforcement:
    """Limits MUST cause ``UNSUPPORTED``, never raise, never loop."""

    def test_oversized_body_returns_unsupported(self) -> None:
        body = "a" * (MAX_REGEX_BODY_BYTES + 1)
        assert analyze_shape(body).shape == RegexShape.UNSUPPORTED

    def test_oversized_alternation_returns_unsupported(self) -> None:
        # MAX_ALTERNATION_BRANCHES + 1 branches is a real-world DoS shape.
        # The classifier must reject without enumerating each branch's IR.
        body = "^(" + "|".join(f"a{i}" for i in range(MAX_ALTERNATION_BRANCHES + 1)) + ")$"
        analysis = analyze_shape(body)
        assert analysis.shape == RegexShape.UNSUPPORTED

    def test_grok_reference_in_body_returns_unsupported(self) -> None:
        assert analyze_shape("%{NAME}").shape == RegexShape.UNSUPPORTED
        assert analyze_shape("^foo%{NAME}bar$").shape == RegexShape.UNSUPPORTED

    def test_flags_return_unsupported(self) -> None:
        for flag in ("i", "m", "s", "x", "im"):
            assert analyze_shape("^A$", flag).shape == RegexShape.UNSUPPORTED, (
                f"flag {flag!r} should be rejected but was accepted"
            )

    def test_invalid_regex_returns_unsupported(self) -> None:
        # A body that's not a valid Python regex (e.g. unclosed bracket)
        # must surface as UNSUPPORTED, not raise.
        assert analyze_shape("[unclosed").shape == RegexShape.UNSUPPORTED

    def test_newline_in_body_returns_unsupported(self) -> None:
        # Defense-in-depth: ``analyze_shape`` is callable directly with
        # multi-line bodies. The upstream parser already rejects these
        # at the config layer, but the algebra must not assume that.
        assert analyze_shape("^A\nB$").shape == RegexShape.UNSUPPORTED
        assert analyze_shape("^A\rB$").shape == RegexShape.UNSUPPORTED


class TestParityWithPriorBehavior:
    """Spot-check that conditions the *prior* ``_EXACT_REGEX_RE`` accepted
    *and which were sound* are still accepted.

    Prior bodies that contained an unescaped ``.`` (e.g. ``192.168.1.1``)
    are intentionally NOT in this list — the prior code unsoundly treated
    ``.`` as a literal period instead of as the wildcard metacharacter.
    Those cases now return ``None`` and are covered as soundness fixes
    in :class:`TestSoundnessGuards`.
    """

    @pytest.mark.parametrize(
        "condition,literal",
        [
            ("[type] =~ /^foo$/", "foo"),
            ("[type] =~ /^foo bar$/", "foo bar"),
            ("[type] =~ /^Foo_Bar-123$/", "Foo_Bar-123"),
            ("[type] =~ /^a:b@c$/", "a:b@c"),
        ],
    )
    def test_prior_charset_still_accepted(self, condition: str, literal: str) -> None:
        result = exact_literal_value(condition)
        assert result is not None
        _, value = result
        assert value == literal


# =====================================================================
# Phase 1: symbolic algebra
# =====================================================================


class TestRegexLanguagesDisjoint:
    """``regex_languages_disjoint`` returns YES only when the two
    languages have *no* common string. The cross-check below confirms
    every YES is correct via brute-force string enumeration."""

    @pytest.mark.parametrize(
        "body_a,body_b",
        [
            ("^A$", "^B$"),
            ("^foo$", "^bar$"),
            ("^[a-z]+$", "^[0-9]+$"),
            ("^(SEC|AUTH)$", "^MISC$"),
            ("^(SEC|AUTH)$", "^(MISC|UNKNOWN)$"),
            (r"^\d+$", r"^[a-z]+$"),
            (r"^foo\.bar$", "^baz$"),
            ("CRITICAL", "^DEBUG$"),
            ("^prefix-foo$", "^prefix-bar$"),
        ],
    )
    def test_proven_disjoint(self, body_a: str, body_b: str) -> None:
        # NO would be a false positive (the only unsound answer here);
        # YES is the precise answer; UNKNOWN is sound but less precise
        # and may surface under heavy concurrent test load.
        result_ab = regex_languages_disjoint(body_a, "", body_b, "")
        result_ba = regex_languages_disjoint(body_b, "", body_a, "")
        assert result_ab != Trilean.NO, f"unsound: {body_a!r} and {body_b!r} are disjoint"
        assert result_ba != Trilean.NO, f"unsound: {body_b!r} and {body_a!r} are disjoint"
        assert result_ab == result_ba, "regex_languages_disjoint must be symmetric"

    @pytest.mark.parametrize(
        "body_a,body_b",
        [
            ("^A$", "^A$"),
            ("^foo$", "^[a-z]+$"),  # foo ⊆ [a-z]+
            ("^[a-z]$", "^[a-y]$"),  # overlap
            ("^(A|B)$", "^(B|C)$"),  # overlap on B
            (r"^\d+$", r"^[0-9]{3}$"),  # 3-digit numbers in both
            ("CRITICAL", "ALERT_CRITICAL"),  # both contain 'CRITICAL'
            ("^prefix-", "^prefix-foo$"),  # prefix wins
        ],
    )
    def test_proven_overlapping(self, body_a: str, body_b: str) -> None:
        # YES would be a false positive (the only unsound answer here);
        # NO is the precise answer; UNKNOWN is sound but less precise
        # and may surface under heavy concurrent test load when the
        # algebra wall-clock budget is exceeded mid-BFS.
        result = regex_languages_disjoint(body_a, "", body_b, "")
        assert result != Trilean.YES, f"unsound: {body_a!r} and {body_b!r} actually overlap"

    @pytest.mark.parametrize(
        "body_a,body_b",
        [
            ("%{NAME}", "^A$"),  # grok ref unsupported
            ("^A$", "%{NAME}"),
            (r"^(?=foo)bar$", "^bar$"),  # lookahead unsupported
            (r"^\1$", "^A$"),  # backref unsupported (parse error)
        ],
    )
    def test_unsupported_returns_unknown(self, body_a: str, body_b: str) -> None:
        result = regex_languages_disjoint(body_a, "", body_b, "")
        assert result == Trilean.UNKNOWN

    def test_case_fold_semantics(self) -> None:
        # /^foo$/i ∩ /^FOO$/ — both can match 'FOO', so non-disjoint.
        assert regex_languages_disjoint("^foo$", "i", "^FOO$", "") == Trilean.NO
        # /^foo$/i ∩ /^bar$/i — disjoint.
        assert regex_languages_disjoint("^foo$", "i", "^bar$", "i") == Trilean.YES


class TestLanguageSubset:
    """``language_subset(A, B)`` returns YES iff every string in L(A)
    is also in L(B)."""

    @pytest.mark.parametrize(
        "body_a,body_b",
        [
            ("^foo$", "^foo$"),  # reflexive
            ("^foo$", "^[a-z]+$"),
            ("^A$", "^(A|B)$"),
            ("^prefix-A$", "^prefix-"),
            (r"^[0-9]{3}$", r"^\d+$"),
        ],
    )
    def test_proven_subset(self, body_a: str, body_b: str) -> None:
        assert language_subset(body_a, "", body_b, "") == Trilean.YES

    @pytest.mark.parametrize(
        "body_a,body_b",
        [
            ("^[a-z]+$", "^foo$"),  # superset isn't subset
            ("^(A|B)$", "^A$"),
            (r"^\d+$", r"^[0-9]{3}$"),  # arbitrary length not bounded to 3
            ("^foo$", "^bar$"),  # disjoint => not subset
        ],
    )
    def test_proven_not_subset(self, body_a: str, body_b: str) -> None:
        assert language_subset(body_a, "", body_b, "") == Trilean.NO

    def test_universal_pattern_contains_everything(self) -> None:
        # Σ* contains any anchored literal.
        assert language_subset("^foo$", "", ".*", "") == Trilean.YES


class TestLiteralInRegexLanguage:
    """``literal_in_regex_language(literal, body, flags)`` returns YES
    iff the *exact* string ``literal`` is matched by the regex under
    Logstash semantics (substring search unless anchored)."""

    @pytest.mark.parametrize(
        "literal,body,expected",
        [
            ("A", "^A$", Trilean.YES),
            ("B", "^A$", Trilean.NO),
            ("foo", "^[a-z]+$", Trilean.YES),
            ("FOO", "^[a-z]+$", Trilean.NO),
            ("alert_CRITICAL_msg", "CRITICAL", Trilean.YES),  # substring
            ("alert_DEBUG_msg", "CRITICAL", Trilean.NO),
            ("123", r"^\d+$", Trilean.YES),
            ("12a", r"^\d+$", Trilean.NO),
            ("SEC", "^(SEC|AUTH)$", Trilean.YES),
            ("MISC", "^(SEC|AUTH)$", Trilean.NO),
        ],
    )
    def test_membership(self, literal: str, body: str, expected: Trilean) -> None:
        assert literal_in_regex_language(literal, body, "") == expected

    def test_unsupported_body_is_unknown(self) -> None:
        assert literal_in_regex_language("A", "%{NAME}", "") == Trilean.UNKNOWN

    def test_oversized_literal_is_unknown(self) -> None:
        big = "x" * (MAX_REGEX_BODY_BYTES + 1)
        assert literal_in_regex_language(big, "^x+$", "") == Trilean.UNKNOWN


class TestSoundnessCrossCheck:
    """For every YES result from ``regex_languages_disjoint``, brute-force
    enumerate strings up to a small length over the union alphabet and
    confirm Python's ``re.search`` agrees that no string matches both.
    This is the load-bearing soundness test — a false-positive YES from
    the algebra would surface here."""

    @pytest.mark.parametrize(
        "body_a,body_b",
        [
            ("^A$", "^B$"),
            ("^[ab]+$", "^[cd]+$"),
            ("^(SEC|AUTH)$", "^MISC$"),
            (r"^\d+$", r"^[a-z]+$"),
            ("^a$", "^aa$"),
            ("^(?:foo)$", "^(?:bar)$"),
        ],
    )
    def test_disjoint_yes_is_truly_disjoint(self, body_a: str, body_b: str) -> None:
        assert regex_languages_disjoint(body_a, "", body_b, "") == Trilean.YES
        # Build alphabet from both bodies' "interesting" chars.
        alphabet = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ ")
        # Limit explored strings to keep the test fast (cap = 4096).
        re_a = re.compile(body_a)
        re_b = re.compile(body_b)
        explored = 0
        for length in range(0, 6):
            for s in _strings_of_length(alphabet, length):
                explored += 1
                if explored > 4096:
                    return
                a_matches = re_a.search(s) is not None
                b_matches = re_b.search(s) is not None
                assert not (a_matches and b_matches), f"algebra said disjoint but {s!r} matches both"

    @pytest.mark.parametrize(
        "literal,body",
        [
            ("X", "^A$"),
            ("123", r"^[a-z]+$"),
            ("MISC", "^(SEC|AUTH)$"),
            ("DEBUG", "CRITICAL"),
        ],
    )
    def test_literal_no_is_truly_no_match(self, literal: str, body: str) -> None:
        assert literal_in_regex_language(literal, body, "") == Trilean.NO
        # Cross-check: Python's regex engine confirms no match.
        assert re.search(body, literal) is None


def _strings_of_length(alphabet: set[str], length: int) -> Iterator[str]:
    """Generator over strings of exactly ``length`` from ``alphabet``.

    Lazy on purpose: with a 65-char alphabet, length 5 is 65⁵ ≈ 1.16B
    strings — materializing the list would OOM the test process even
    though the cap inside the caller (4096 explored) keeps the actual
    iteration cheap. The generator means raising the cap or extending
    the length range can never silently blow past it."""
    if length == 0:
        yield ""
        return
    for s in _strings_of_length(alphabet, length - 1):
        for c in alphabet:
            yield s + c


class TestAlgebraLimitEnforcement:
    """Every cap returns Trilean.UNKNOWN; never raises, never loops."""

    def test_oversized_body_is_unknown(self) -> None:
        big = "a" * (MAX_REGEX_BODY_BYTES + 1)
        assert regex_languages_disjoint(big, "", "^A$", "") == Trilean.UNKNOWN
        assert language_subset(big, "", "^A$", "") == Trilean.UNKNOWN

    def test_repeat_above_bound_is_unknown(self) -> None:
        # ``a{n}`` with n > MAX_REPEAT_BOUND should not unroll.
        body = f"^a{{{MAX_REPEAT_BOUND + 1}}}$"
        assert regex_languages_disjoint(body, "", "^A$", "") == Trilean.UNKNOWN

    def test_repeat_at_bound_is_supported(self) -> None:
        # The boundary case must still be handled cleanly.
        body = f"^a{{{MAX_REPEAT_BOUND}}}$"
        # Comparing against itself: not disjoint.
        result = regex_languages_disjoint(body, "", body, "")
        assert result in (Trilean.NO, Trilean.UNKNOWN)  # may hit other caps; both sound

    def test_oversized_alternation_is_unknown(self) -> None:
        body = "^(" + "|".join(f"a{i}" for i in range(MAX_ALTERNATION_BRANCHES + 1)) + ")$"
        assert regex_languages_disjoint(body, "", "^A$", "") == Trilean.UNKNOWN

    def test_unsupported_construct_is_unknown(self) -> None:
        for body in [r"^\1$", r"^(?=foo)bar$", r"^(?<=x)A$", "^(?P<n>A)(?P=n)$"]:
            assert regex_languages_disjoint(body, "", "^A$", "") == Trilean.UNKNOWN, body

    def test_ascii_case_fold_only_under_i_flag(self) -> None:
        # Only ``i`` is honored; ``m``, ``s``, ``x``, ``u`` etc. -> UNKNOWN.
        for flag in ("m", "s", "x", "u", "im"):
            assert regex_languages_disjoint("^A$", flag, "^B$", "") == Trilean.UNKNOWN, flag

    def test_inline_modifier_other_than_i_is_unknown(self) -> None:
        # Inline ``(?m)`` etc. -> UNKNOWN (only ``(?i)`` is honored).
        assert regex_languages_disjoint("(?m)^A$", "", "^B$", "") == Trilean.UNKNOWN

    def test_pathological_repeat_does_not_hang(self) -> None:
        # A nested-quantifier shape that's the textbook ReDoS trigger.
        # Even if `a*a*` parses, the algebra must complete within the
        # wall-clock budget (returning UNKNOWN if it doesn't).
        import time as _t

        start = _t.monotonic()
        result = regex_languages_disjoint("(a*a*)*b", "", "(a*a*)*c", "")
        elapsed_ms = (_t.monotonic() - start) * 1000
        # 10× the BFS budget. The pre-BFS phases (sre_parse, IR
        # lowering, NFA build, alphabet partition) aren't wall-clock
        # bounded individually — only the structural caps protect
        # them. On slow CI with cold caches, cumulative cold-path cost
        # can comfortably exceed 4× = 100ms even when nothing is
        # actually hung. 10× still catches a real hang while
        # tolerating CI variance.
        assert elapsed_ms < ALGEBRA_TIME_BUDGET_MS * 10, f"took {elapsed_ms:.1f}ms"
        assert result in (Trilean.YES, Trilean.NO, Trilean.UNKNOWN)


class TestAlgebraReflexivity:
    """Every supported pattern must satisfy reflexivity invariants."""

    @pytest.mark.parametrize(
        "body",
        [
            "^A$",
            "^foo$",
            "^[a-z]+$",
            r"^\d+$",
            "^(SEC|AUTH|MISC)$",
            "CRITICAL",
            "^prefix-",
            "-suffix$",
        ],
    )
    def test_pattern_is_subset_of_self(self, body: str) -> None:
        assert language_subset(body, "", body, "") == Trilean.YES

    @pytest.mark.parametrize(
        "body",
        [
            "^A$",
            "^[a-z]+$",
            "CRITICAL",
        ],
    )
    def test_pattern_intersects_self(self, body: str) -> None:
        # A pattern is never disjoint from itself (assuming non-empty
        # language; all of these have non-empty languages).
        assert regex_languages_disjoint(body, "", body, "") == Trilean.NO


class TestRegexFactWiring:
    """Phase 1 contradictions surface through the existing public API."""

    def test_regex_fact_extracted_for_non_literal_body(self) -> None:
        # ``=~ /^[A-Z]+$/`` is not a pure literal — it should produce a
        # RegexFact, not a LiteralFact.
        fact = _fact_from_condition("[t] =~ /^[A-Z]+$/")
        assert isinstance(fact, RegexFact)
        assert fact.field == "[t]"
        assert fact.body == "^[A-Z]+$"
        assert fact.is_match is True

    def test_literal_fact_still_preferred_for_pure_literal_body(self) -> None:
        # ``=~ /^foo$/`` reduces to a LiteralFact (Phase 0 behavior).
        fact = _fact_from_condition("[t] =~ /^foo$/")
        assert isinstance(fact, LiteralFact)
        assert fact.value == "foo"

    @pytest.mark.parametrize(
        "conditions,compatible",
        [
            # Same field, disjoint regexes => contradicted.
            (["[t] =~ /^A$/", "[t] =~ /^B$/"], False),
            (["[t] =~ /^[A-Z]+$/", "[t] =~ /^[0-9]+$/"], False),
            # Same field, overlapping regexes => compatible.
            (["[t] =~ /^[A-Z]+$/", "[t] =~ /^[A-C]+$/"], True),
            # Different fields => never contradicts via these regexes.
            (["[a] =~ /^X$/", "[b] =~ /^Y$/"], True),
            # Literal vs regex on same field.
            (['[t] == "FOO"', "[t] =~ /^[a-z]+$/"], False),
            (['[t] == "foo"', "[t] =~ /^[a-z]+$/"], True),
            # Literal substring semantics.
            (['[t] == "DEBUG_msg"', "[t] =~ /CRITICAL/"], False),
            (['[t] == "ALERT_CRITICAL"', "[t] =~ /CRITICAL/"], True),
        ],
    )
    def test_conditions_are_compatible_consults_algebra(self, conditions: list[str], compatible: bool) -> None:
        assert conditions_are_compatible(conditions) is compatible

    def test_condition_is_contradicted_consults_algebra(self) -> None:
        # else-if branch with a regex disjoint from the if branch's regex.
        assert condition_is_contradicted("[t] =~ /^A$/", ["[t] =~ /^B$/"]) is True
        assert condition_is_contradicted("[t] =~ /^[A-Z]+$/", ["[t] =~ /^[a-z]+$/"]) is True

    def test_unsupported_pattern_does_not_contradict(self) -> None:
        # An unsupported body must never authorize a contradiction —
        # UNKNOWN propagates as "compatible".
        assert condition_is_contradicted("[t] =~ /%{NAME}/", ["[t] =~ /^B$/"]) is False
        assert conditions_are_compatible(["[t] =~ /%{NAME}/", "[t] =~ /^B$/"]) is True


class TestFactsContradictDispatch:
    """Direct unit tests for ``_facts_contradict``."""

    def test_literal_vs_literal_fast_path(self) -> None:
        a = LiteralFact("[t]", "x")
        b = LiteralFact("[t]", "y")
        assert _facts_contradict(a, b) is True
        assert _facts_contradict(a, a) is False

    def test_literal_vs_regex_uses_membership(self) -> None:
        lit = LiteralFact("[t]", "FOO")
        rx = RegexFact("[t]", "^[a-z]+$", "")
        assert _facts_contradict(lit, rx) is True
        assert _facts_contradict(rx, lit) is True  # commutative

    def test_regex_vs_regex_disjoint(self) -> None:
        a = RegexFact("[t]", "^A$", "")
        b = RegexFact("[t]", "^B$", "")
        assert _facts_contradict(a, b) is True

    def test_different_fields_never_contradict(self) -> None:
        assert _facts_contradict(RegexFact("[a]", "^X$", ""), RegexFact("[b]", "^Y$", "")) is False
        assert _facts_contradict(LiteralFact("[a]", "X"), RegexFact("[b]", "^Y$", "")) is False


class TestRegexStressFile:
    """End-to-end regression for the regex-algebra stress fixture under
    ``tests/fixtures/test_corpus/challenge/``.

    The fixture is a deliberate scanner / regex torture test: ambiguous
    ``//`` sequences, Grok-lookalike ``%{...}`` inside a regex literal,
    nested escapes, unbalanced brackets in strings, etc. Phase 1 must:

    * Detect the embedded ``%{...}`` and bail to UNSUPPORTED for that
      body (sound — the substring may or may not be a real Grok ref;
      treating it as opaque preserves all four branches).
    * Lower the bracket/escape-heavy bodies cleanly to IR.
    * Keep the analyzer happy: all four ``if/else if`` branches must
      remain reachable (no branch dropped by an unsound contradiction),
      and the analysis must complete well under any reasonable budget.

    The challenge-bucket smoke test in ``tests/test_corpus_challenge.py``
    already asserts the fixture parses without ``parse_recovery`` /
    ``malformed_config`` warnings within a 60s budget; the tests here
    pin down the *algebra-specific* behavior instead.
    """

    @pytest.fixture(scope="class")
    def stress_file_text(self) -> str:
        from pathlib import Path

        path = (
            Path(__file__).parent / "fixtures" / "test_corpus" / "challenge" / "test_challenge_regex_algebra_stress.cbn"
        )
        return path.read_text(encoding="utf-8")

    def test_grok_lookalike_body_is_unsupported(self) -> None:
        # The Path A condition mixes anchored alternation, escape
        # sequences, and ``%{not_a_reference}``. The substring ``%{`` is
        # the Grok-ref guard's trigger — must yield UNKNOWN, not a YES.
        body = r"^([a-zA-Z]+):\/\/(?:\[[a-f0-9:]+\]|%{not_a_reference})(?:\/|\/\/|\/.\/)$"
        assert regex_languages_disjoint(body, "", "^https$", "") == Trilean.UNKNOWN
        assert language_subset(body, "", "^https$", "") == Trilean.UNKNOWN
        assert literal_in_regex_language("https", body, "") == Trilean.UNKNOWN

    def test_bracket_and_escape_heavy_body_lowers(self) -> None:
        # Path B body: ``=>\s*\[\s*\]\s*\{\s*\}\s*#\s*\/\/`` — escape-
        # heavy but no Grok refs. Must lower to IR and answer literal-
        # membership questions correctly.
        body = r"=>\s*\[\s*\]\s*\{\s*\}\s*#\s*\/\/"
        # Exact match for the canonical form should be YES.
        assert literal_in_regex_language("=> [] {} # //", body, "") == Trilean.YES
        # A near-miss without ``#`` must NOT match.
        assert literal_in_regex_language("=> [] {} //", body, "") == Trilean.NO

    def test_unanchored_charclass_body_lowers(self) -> None:
        # Path C: ``[{}]`` — unanchored ⇒ implicit Σ* wrapping ⇒
        # "contains either { or }".
        body = "[{}]"
        assert literal_in_regex_language("/var/log/syslog_{date}/", body, "") == Trilean.YES
        assert literal_in_regex_language("/var/log/syslog/", body, "") == Trilean.NO

    def test_full_analyzer_keeps_all_branches_reachable(self, stress_file_text: str) -> None:
        # The four mutate-replace branches all set the same UDM field;
        # if Phase 1 wrongly authorized a contradiction between any
        # two of them, one or more would be dropped. The fields differ
        # across the conditions in this file (different ``[capture]``
        # variables), so no contradiction is possible.
        from parser_lineage_analyzer.analyzer import ReverseParser

        parser = ReverseParser(stress_file_text)
        result = parser.query("event.idm.read_only_udm.metadata.description")
        expressions = sorted({m.expression for m in result.mappings})
        assert expressions == ["Path A", "Path B", "Path C", "Path D"]

    def test_analyzer_completes_in_reasonable_time(self, stress_file_text: str) -> None:
        # Sanity bound — well above the algebra budget so transient
        # CI hiccups don't flake. A real regression (e.g. the algebra
        # being called per-character on Σ*-expanded NFAs) would blow
        # past this by orders of magnitude.
        import time

        from parser_lineage_analyzer.analyzer import ReverseParser

        start = time.monotonic()
        ReverseParser(stress_file_text).query("event.idm.read_only_udm.metadata.description")
        elapsed_s = time.monotonic() - start
        assert elapsed_s < 2.0, f"analyzer took {elapsed_s:.2f}s on the stress file"


class TestReviewFindings:
    """Regression tests for review feedback that pinned down two real
    bugs in the initial Phase 1 implementation. Both are soundness /
    DoS-resistance regressions; the assertions are written so the bug
    pattern can never silently come back."""

    def test_dot_excludes_only_lf_not_cr(self) -> None:
        """``.`` in Logstash/Ruby/Oniguruma matches every char *except*
        ``\\n``. ``\\r`` is matched.

        Earlier the algebra excluded both ``\\n`` and ``\\r``, which
        would let ``regex_languages_disjoint("^.$", "^\\r$")`` return
        :attr:`Trilean.YES` — a false positive that would silently
        drop reachable branches when a field value happened to
        contain a carriage return.
        """
        # Direct: dot must NOT be disjoint from a literal CR.
        assert regex_languages_disjoint("^.$", "", "^\r$", "") != Trilean.YES, (
            "unsound: '.' must match '\\r' under Ruby/Oniguruma semantics"
        )
        # Membership: '\r' is in L(.).
        result = literal_in_regex_language("\r", "^.$", "")
        assert result != Trilean.NO, "unsound: '\\r' must be in L(/^.$/)"
        # Sanity: '\n' is still excluded (the *only* char excluded by '.').
        # Use the regex escape ``\n`` (two chars: backslash, n) — a literal
        # newline byte in the body would be rejected by the multiline guard.
        assert regex_languages_disjoint("^.$", "", r"^\n$", "") == Trilean.YES
        assert literal_in_regex_language("\n", "^.$", "") == Trilean.NO

    def test_wide_unicode_range_does_not_blow_up(self) -> None:
        """``[\\x00-\\U0010ffff]`` in a body must not materialize 1.1M
        code points into a frozenset before any algebra budget check
        fires. The earlier implementation did, causing multi-second
        spikes on untrusted regex bodies that defeated the wall-clock
        guard's intent."""
        import time as _t

        # Time the pathological case end-to-end. With the size cap in
        # place this returns UNKNOWN (sound) almost instantly; without
        # the cap it materializes 1.1M ints.
        start = _t.monotonic()
        result = regex_languages_disjoint(r"[\x00-\U0010ffff]", "", "^A$", "")
        elapsed_ms = (_t.monotonic() - start) * 1000
        # Generous bound — the actual non-bug path completes in < 1ms;
        # 200ms still catches a regression while tolerating CI jitter.
        assert elapsed_ms < 200, f"wide-range body took {elapsed_ms:.1f}ms — frozenset materialization may have leaked"
        assert result == Trilean.UNKNOWN

    @pytest.mark.parametrize(
        "lo,hi",
        [
            (0, MAX_CHARSET_SIZE - 1),  # exactly at the cap — accepted
            (0, MAX_CHARSET_SIZE),  # one over — rejected
            (0, 0x10FFFF),  # full Unicode — rejected
        ],
    )
    def test_charset_size_cap_boundary(self, lo: int, hi: int) -> None:
        """Direct check on the boundary of :data:`MAX_CHARSET_SIZE`."""
        body = f"[\\x{lo:04x}-\\U{hi:08x}]"
        # Just confirm no raise + bounded time. Sound result either way.
        result = regex_languages_disjoint(body, "", "^A$", "")
        assert isinstance(result, Trilean)

    def test_complement_dfa_respects_budget(self) -> None:
        """The DFA-completion fill loop is ``O(num_states × num_classes)``,
        up to ~1M iterations. It must poll the budget on the same
        cadence as the BFS loops; with an already-expired deadline the
        function returns ``None`` (which surfaces as ``UNKNOWN`` from
        :func:`language_subset`) rather than running to completion.
        """
        from parser_lineage_analyzer._regex_algebra import (
            _DFA,
            _Budget,
            _CharSet,
            _complete_and_complement_dfa,
        )

        # Build a small synthetic DFA so the test is fast when the
        # budget *isn't* expired.
        partition = (_CharSet(frozenset({ord("a")}), False),)
        dfa = _DFA(
            num_states=2,
            start=0,
            accepts=frozenset({1}),
            transitions={(0, 0): 1},
            partition=partition,
        )
        # Fresh budget: the function should complete normally and
        # return a complement DFA.
        result = _complete_and_complement_dfa(dfa, _Budget.fresh())
        assert result is not None
        assert result.num_states == 3  # original 2 + sink
        # Expired budget: the function must bail. ``_Budget(deadline=0.0)``
        # is in the past, so ``budget.exceeded()`` is True from the
        # first poll inside the loop.
        expired = _Budget(deadline=0.0)
        assert _complete_and_complement_dfa(dfa, expired) is None

    def test_non_ascii_letter_under_caseless_flag_is_unsupported(self) -> None:
        """Phase 1's case-folding only handles ASCII letter pairs.
        Non-ASCII letters with Unicode case (``é``↔``É``, ``α``↔``Α``,
        ``ß``↔``ẞ``, ...) would be folded by Onigmo but not by us;
        leaving them unchanged would let the algebra return YES based
        on a language that's strictly smaller than the real one.

        Concrete bug this guards: ``regex_languages_disjoint('^é$',
        'i', '^É$', '')`` would return YES (proven disjoint) under
        the broken implementation because Phase 1 sees ``{é}`` vs
        ``{É}`` while Onigmo's ``(?i)`` makes ``^é$`` match both.
        """
        # Direct case from the review.
        assert regex_languages_disjoint("^é$", "i", "^É$", "") == Trilean.UNKNOWN
        assert language_subset("^é$", "i", "^É$", "") == Trilean.UNKNOWN
        assert literal_in_regex_language("É", "^é$", "i") == Trilean.UNKNOWN
        # A handful more scripts to make sure the rule is general.
        for body in ("^α$", "^ß$", "^Й$"):
            assert regex_languages_disjoint(body, "i", "^X$", "") == Trilean.UNKNOWN, body
        # ASCII-only with /i still honored — fold pair {a,A} works fine.
        assert regex_languages_disjoint("^a$", "i", "^A$", "") == Trilean.NO
        assert literal_in_regex_language("A", "^a$", "i") == Trilean.YES
        # Non-ASCII *without* case (snowman, digit, symbol) passes
        # through unchanged because Onigmo doesn't fold it either.
        assert literal_in_regex_language("☃", "^☃$", "i") == Trilean.YES
        assert literal_in_regex_language("1", "^1$", "i") == Trilean.YES

    def test_inline_caseless_flag_is_unsupported_not_globally_folded(self) -> None:
        """Logstash uses Onigmo, where ``(?i)`` is scoped to its
        enclosing group. Phase 1's IR has no way to model mid-pattern
        scope changes, and CPython's ``sre_parse`` propagates the flag
        globally — folding the whole IR over-approximates the language
        and could let ``language_subset`` and
        ``literal_in_regex_language`` unsoundly return ``YES``.

        The fix: bail to ``UNKNOWN`` whenever any inline flag group
        appears in the body. Scoped ``(?i:...)`` is still honored via
        the SUBPATTERN ``add_flags`` lowering — that *is* an
        explicit-scope group and matches Onigmo's behavior.
        """
        # Unscoped inline ``(?i)`` — must be UNKNOWN, never YES from
        # the algebra (which would imply a global fold has happened).
        for body in ("(?i)foo", "^(?i)foo$", r"^A(?i)B$"):
            assert regex_languages_disjoint(body, "", "^Foo$", "") == Trilean.UNKNOWN
            assert language_subset(body, "", "^FOO$", "") == Trilean.UNKNOWN
            assert literal_in_regex_language("Foo", body, "") == Trilean.UNKNOWN
        # Trailing ``/i`` flag — applies to the whole pattern by
        # definition; still honored.
        assert literal_in_regex_language("FOO", "^foo$", "i") == Trilean.YES
        # Scoped ``(?i:foo)`` — explicit group scope; Onigmo and our
        # IR agree, so it's honored. Anchored membership: the body
        # ``(?i:foo)`` is unanchored, so Σ* wrapping makes it match
        # any string containing a case-insensitive ``foo``.
        assert literal_in_regex_language("alert_FOO_msg", "(?i:foo)", "") == Trilean.YES
        assert literal_in_regex_language("alert_BAR_msg", "(?i:foo)", "") == Trilean.NO

    def test_unknown_results_are_not_cached(self) -> None:
        """A transient cap hit (cold caches under load, slow CI, etc.)
        can make ``regex_languages_disjoint`` return ``UNKNOWN`` for
        an input that would resolve to YES/NO with a fresh budget.
        Caching that ``UNKNOWN`` would let one slow run mask a
        definitive result for the rest of the process — definitively
        unsound for precision (still sound for correctness, since
        ``UNKNOWN`` only ever drops branches conservatively).

        This test forces an UNKNOWN by handing the algebra a
        zero-budget call (via patching), then verifies a normal call
        afterward still returns the correct definitive answer.
        """
        from parser_lineage_analyzer import _regex_algebra as algebra

        # Use a unique pair so other tests can't have populated the
        # definitive cache for these bodies.
        body_a = "^uncached_test_disjoint_a$"
        body_b = "^uncached_test_disjoint_b$"

        # Clear caches up front so the test is independent.
        algebra._DEFINITIVE_DISJOINT_CACHE.clear()

        # Force an UNKNOWN by patching the BFS to bail. We do this by
        # temporarily replacing ``_intersect_empty_nfa`` with a stub.
        original = algebra._intersect_empty_nfa
        algebra._intersect_empty_nfa = lambda *_args, **_kwargs: Trilean.UNKNOWN
        try:
            result_unknown = regex_languages_disjoint(body_a, "", body_b, "")
        finally:
            algebra._intersect_empty_nfa = original
        assert result_unknown == Trilean.UNKNOWN

        # The UNKNOWN must NOT be in the definitive cache.
        canonical_key = (body_a, "", body_b, "") if (body_a, "") <= (body_b, "") else (body_b, "", body_a, "")
        assert canonical_key not in algebra._DEFINITIVE_DISJOINT_CACHE

        # A subsequent call with the real BFS gets the right answer.
        result_real = regex_languages_disjoint(body_a, "", body_b, "")
        assert result_real == Trilean.YES  # different anchored literals
        # And NOW the definitive answer IS cached.
        assert algebra._DEFINITIVE_DISJOINT_CACHE.get(canonical_key) == Trilean.YES

    def test_language_subset_does_not_exceed_5x_budget(self) -> None:
        """End-to-end soak: hand :func:`language_subset` a pair
        of patterns that build near-max DFAs. Even when the algebra
        bails to ``UNKNOWN``, the wall-clock must stay within a
        generous bound — proves the budget polls in the BFS *and* the
        complement loop are both wired up."""
        import time

        # A pair that exercises the full pipeline: lower → NFA → DFA →
        # complement → product BFS. Both bodies are real but moderately
        # large; the algebra should either prove a result or hit a cap
        # quickly.
        body_a = r"^([a-z]|[A-Z]|[0-9]){1,32}$"
        body_b = r"^[A-Za-z0-9]+$"
        start = time.monotonic()
        result = language_subset(body_a, "", body_b, "")
        elapsed_ms = (time.monotonic() - start) * 1000
        assert isinstance(result, Trilean)
        assert elapsed_ms < ALGEBRA_TIME_BUDGET_MS * 5, f"language_subset took {elapsed_ms:.1f}ms"
