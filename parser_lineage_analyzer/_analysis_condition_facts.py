"""Conservative fact extraction for branch conditions.

Two fact flavors:

* :class:`LiteralFact` — ``[field] == "x"``, ``[field] != "x"``, and the
  Phase 0 reduction of ``[field] =~ /^literal$/`` to a value-equality
  fact. Comparisons among LiteralFacts are pure string ops; this is the
  fast path the analyzer hits the most.
* :class:`RegexFact` — ``[field] =~ /body/flags`` for any regex body
  *not* already reducible to a LiteralFact. Comparisons consult the
  Phase 1 algebra in :mod:`_regex_algebra`, which returns
  :class:`Trilean` and only ever drops branches when the answer is
  provably ``YES`` (sound under the false-positives-are-not-OK rule).

The public surface (``condition_is_contradicted``,
``conditions_are_compatible``, ``is_exact_literal_regex_condition``)
is unchanged; the new fact type is internal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from itertools import product

from ._regex_algebra import (
    Trilean,
    exact_literal_value as _regex_exact_literal_value,
    extract_regex_literal,
    is_exact_literal_regex as _regex_is_exact_literal,
    language_subset,
    literal_in_regex_language,
    regex_languages_disjoint,
)


@dataclass(frozen=True)
class LiteralFact:
    field: str
    value: str
    is_equal: bool = True

    def negated(self) -> LiteralFact:
        return LiteralFact(self.field, self.value, not self.is_equal)


@dataclass(frozen=True)
class RegexFact:
    """A ``[field] =~ /body/flags`` or ``[field] !~ /body/flags`` constraint
    that is not (or not yet) reducible to a LiteralFact. Contradiction
    checks consult the symbolic regex algebra."""

    field: str
    body: str
    flags: str
    # ``True`` for ``=~`` (positive match); ``False`` for ``!~`` (negative).
    is_match: bool = True


Fact = LiteralFact | RegexFact


_EQ_RE = re.compile(r'^(?P<field>(?:\[[^\]]+\])+)\s*==\s*"(?P<value>(?:\\.|[^"\\])*)"$')
_NE_RE = re.compile(r'^(?P<field>(?:\[[^\]]+\])+)\s*!=\s*"(?P<value>(?:\\.|[^"\\])*)"$')
_NEGATED_RE = re.compile(r"^NOT\((?P<inner>.*)\)$")
# Used by _normalize_condition's fast path to detect non-space whitespace
# (\t, \n, \r, etc.) that would be collapsed to a single space by the
# str.split()/" ".join() slow path.
_HAS_NON_SPACE_WS_RE = re.compile(r"[^\S ]")


def _normalize_condition(condition: object) -> str:
    text = str(condition)
    # Fast path: already-normalized strings (no double spaces, no
    # leading/trailing whitespace, no non-space whitespace such as tabs or
    # newlines) round-trip through the slow path unchanged. Skip the
    # strip+split+join allocation when we can detect this in O(n).
    if text and "  " not in text and text == text.strip() and not _HAS_NON_SPACE_WS_RE.search(text):
        return text
    return " ".join(text.strip().split())


def _decode_condition_string(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            escaped = value[i + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(escaped, escaped))
            i += 2
            continue
        out.append(value[i])
        i += 1
    return "".join(out)


def literal_fact_from_condition(condition: str) -> LiteralFact | None:
    condition = _normalize_condition(condition)
    return _literal_fact_from_normalized_condition(condition)


def _literal_fact_from_normalized_condition(condition: str) -> LiteralFact | None:
    m = _EQ_RE.match(condition)
    if m:
        return LiteralFact(m.group("field"), _decode_condition_string(m.group("value")))
    m = _NE_RE.match(condition)
    if m:
        return LiteralFact(m.group("field"), _decode_condition_string(m.group("value")), False)
    regex_literal = _safe_regex_literal_fact_from_normalized_condition(condition)
    if regex_literal is not None:
        return regex_literal
    # Intentional gap: ``[t] =~ /^literal$/`` and ``[t] !~ /^literal$/`` are
    # not reduced to value-equality facts when the regex language also admits
    # ``"literal\n"`` via Python/Ruby ``$`` semantics. The literal classifier
    # still recognizes these bodies for diagnostics, but contradiction facts
    # keep them as RegexFacts so Phase 1 can reason about the wider language.
    return None


def _safe_regex_literal_fact_from_normalized_condition(condition: str) -> LiteralFact | None:
    regex_literal = _regex_exact_literal_value(condition)
    extracted = extract_regex_literal(condition)
    if regex_literal is None or extracted is None:
        return None
    field, value = regex_literal
    if literal_in_regex_language(f"{value}\n", extracted.body, extracted.flags) != Trilean.NO:
        return None
    return LiteralFact(field, value)


def _regex_fact_from_normalized_condition(condition: str) -> RegexFact | None:
    """Produce a :class:`RegexFact` for ``[t] =~ /body/flags`` or
    ``[t] !~ /body/flags`` when the body does *not* reduce to a literal
    (Phase 0 already handled those). Returns ``None`` for non-match
    conditions or oversized bodies; the Phase 1 algebra returns
    :attr:`Trilean.UNKNOWN` for unsupported bodies (which propagates as
    "compatible" — sound)."""
    extracted = extract_regex_literal(condition)
    if extracted is None:
        return None
    return RegexFact(extracted.field, extracted.body, extracted.flags, is_match=extracted.is_match)


def _negated_regex_fact_from_normalized_condition(condition: str) -> RegexFact | None:
    m = _NEGATED_RE.match(condition)
    if not m:
        return None
    fact = _regex_fact_from_normalized_condition(_normalize_condition(m.group("inner")))
    if fact is None:
        return None
    return RegexFact(fact.field, fact.body, fact.flags, is_match=not fact.is_match)


@lru_cache(maxsize=8192)
def _fact_from_condition(condition: str) -> Fact | None:
    condition = _normalize_condition(condition)
    literal = _literal_fact_from_normalized_condition(condition) or _negated_literal_fact_from_normalized_condition(
        condition
    )
    if literal is not None:
        return literal
    negated_regex = _negated_regex_fact_from_normalized_condition(condition)
    if negated_regex is not None:
        return negated_regex
    # Phase 1: a ``=~``/``!~`` whose body wasn't reducible to a LiteralFact
    # becomes a RegexFact for the symbolic algebra to reason about.
    return _regex_fact_from_normalized_condition(condition)


def _split_top_level(condition: str, separator: str) -> list[str]:
    """Split ``condition`` by ``separator`` (e.g. " and " / " or ") at top level.

    Top-level means: not inside a quoted string, regex literal, or parenthesis.
    Returns the original condition as a single-element list if no split is
    possible.
    """
    # Common-case fast path: most SecOps conditions never contain a top-level
    # ``and`` / ``or`` separator. A full char-by-char scan with paren/quote/
    # regex bookkeeping is wasted on those — just return the stripped
    # condition. Behavior matches the slow path's final return for inputs
    # without the separator: empty/whitespace-only inputs yield ``[]`` (the
    # ``if p`` filter), and a non-empty input is stripped and wrapped in a
    # single-element list.
    if separator not in condition:
        stripped = condition.strip()
        return [stripped] if stripped else []
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(condition)
    paren = 0
    quote: str | None = None
    in_regex = False
    sep_len = len(separator)
    while i < n:
        ch = condition[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(condition[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if in_regex:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(condition[i + 1])
                i += 2
                continue
            if ch == "/":
                in_regex = False
            i += 1
            continue
        if ch in {'"', "'"}:
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "/" and (i == 0 or condition[i - 1] in " \t(=~"):
            in_regex = True
            buf.append(ch)
            i += 1
            continue
        if ch == "(":
            paren += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            paren = max(0, paren - 1)
            buf.append(ch)
            i += 1
            continue
        if paren == 0 and ch == " " and condition.startswith(separator, i):
            # The separator's leading and trailing spaces (e.g. " and ") are
            # the word boundaries: " and " cannot match inside ``branding``
            # because there is no preceding space, and cannot match before
            # ``andx`` because the trailing-space char would not align.
            parts.append("".join(buf).strip())
            buf = []
            i += sep_len
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _split_top_level_and(condition: str) -> list[str]:
    """Split a condition by top-level ``and`` operators."""
    return _split_top_level(condition, " and ")


def _split_top_level_or(condition: str) -> list[str]:
    """Split a condition by top-level ``or`` operators."""
    return _split_top_level(condition, " or ")


@lru_cache(maxsize=8192)
def _facts_for_condition(condition: str) -> tuple[Fact, ...]:
    """Extract one fact per top-level ``and``-conjunct.

    Returns ``()`` if no conjunct yields a fact. Conjuncts that can't be parsed
    into a fact are silently dropped — the analyzer is conservative, and a
    partial fact set is still useful for contradiction detection.
    """
    facts: list[Fact] = []
    for conjunct in _split_top_level_and(_normalize_condition(condition)):
        fact = _fact_from_condition(conjunct)
        if fact is not None:
            facts.append(fact)
    return tuple(facts)


@lru_cache(maxsize=8192)
def _disjunctive_facts_for_condition(condition: str) -> tuple[tuple[Fact, ...], ...]:
    """Return condition's facts in DNF form: outer tuple = OR alternatives,
    inner tuple = AND-conjuncts within that alternative.

    A condition with no top-level ``or`` returns a single inner tuple (the
    existing _facts_for_condition behavior wrapped in a singleton). A
    condition like ``[a] == "x" or [a] == "y"`` returns
    ``((Fact("[a]", "x"),), (Fact("[a]", "y"),))``.

    Disjuncts that yield no facts at all (no parseable conjunct) are dropped,
    which is conservative — fewer alternatives means we're less likely to
    declare a contradiction.
    """
    normalized = _normalize_condition(condition)
    disjuncts = _split_top_level_or(normalized)
    out: list[tuple[Fact, ...]] = []
    for disjunct in disjuncts:
        facts = _facts_for_condition(disjunct)
        if facts:
            out.append(facts)
    return tuple(out)


def _negated_literal_fact_from_normalized_condition(condition: str) -> LiteralFact | None:
    m = _NEGATED_RE.match(condition)
    if not m:
        return None
    fact = _literal_fact_from_normalized_condition(_normalize_condition(m.group("inner")))
    if fact is None:
        return None
    return fact.negated()


def _facts_contradict(left: Fact, right: Fact) -> bool:
    if left.field != right.field:
        return False

    # Fast path: both literal facts. This is the hottest comparison —
    # pure string equality, no algebra invocation.
    if isinstance(left, LiteralFact) and isinstance(right, LiteralFact):
        if left.is_equal and right.is_equal:
            return left.value != right.value
        if left.is_equal != right.is_equal:
            return left.value == right.value
        return False

    # Mixed literal + regex: the literal's singleton language is checked
    # for membership in the regex's language. ``Trilean.NO`` (proven not
    # in language) is the only return that justifies declaring a
    # contradiction.
    if isinstance(left, LiteralFact) and isinstance(right, RegexFact):
        return _literal_vs_regex_contradicts(left, right)
    if isinstance(left, RegexFact) and isinstance(right, LiteralFact):
        return _literal_vs_regex_contradicts(right, left)

    # Both regex: defer to the symbolic algebra. The earlier branches
    # exhaust every other Fact-type pairing, so by elimination both
    # operands are RegexFact here. The explicit guard documents the
    # invariant and survives ``python -O`` (which strips ``assert``).
    if not (isinstance(left, RegexFact) and isinstance(right, RegexFact)):
        raise TypeError(
            "_facts_contradict reached the regex-vs-regex arm with non-RegexFact operands: "
            f"left={type(left).__name__}, right={type(right).__name__}"
        )
    if left.is_match and right.is_match:
        return regex_languages_disjoint(left.body, left.flags, right.body, right.flags) == Trilean.YES
    if left.is_match != right.is_match:
        # Positive vs negative: contradicted iff L(positive) ⊆ L(negative).
        # Every value satisfying ``=~ /A/`` is in L(A); the ``!~ /B/`` peer
        # excludes everything in L(B); the conjunction is unsatisfiable
        # exactly when L(A) ⊆ L(B).
        positive, negative = (left, right) if left.is_match else (right, left)
        return language_subset(positive.body, positive.flags, negative.body, negative.flags) == Trilean.YES
    # Both negative: never provably contradicts. A value can lie outside
    # both languages, satisfying ``!~ /A/`` and ``!~ /B/`` simultaneously.
    return False


def _literal_vs_regex_contradicts(literal: LiteralFact, regex: RegexFact) -> bool:
    if not regex.is_match:
        # ``[t] == "x"`` and ``[t] !~ /A/`` contradict iff ``"x"`` *is*
        # in L(A) (which would force a !~ violation). Symmetrically for
        # ``!=``.
        if literal.is_equal:
            return literal_in_regex_language(literal.value, regex.body, regex.flags) == Trilean.YES
        return False  # `[t] != "x"` and `[t] !~ /A/`: no general contradiction
    # Positive regex match.
    if literal.is_equal:
        # ``[t] == "x"`` and ``[t] =~ /A/`` contradict iff "x" not in L(A).
        return literal_in_regex_language(literal.value, regex.body, regex.flags) == Trilean.NO
    # ``[t] != "x"`` and ``[t] =~ /A/``: contradict iff L(A) = {"x"}.
    # Hard to prove in general (would need language equality); skip.
    return False


def condition_is_contradicted(
    condition: str,
    prior_conditions: list[str],
    implicit_conditions: tuple[str, ...] = (),
) -> bool:
    """Check whether ``condition`` is unsatisfiable given prior conditions.

    ``implicit_conditions`` (PR-C / F2 algebra wiring): synthetic
    constraints injected by the analyzer that augment the user-visible
    ``prior_conditions``. Currently populated by the grok extractor for
    captured fields whose pattern name resolves to a known regex body
    (e.g. ``[src_ip] =~ /<IP_BODY>/``); the contradiction engine treats
    them as additional priors so a downstream ``[src_ip] =~ /^[A-Z]+$/``
    can be proven unreachable. Empty tuple by default — pre-PR-C
    behavior preserved byte-for-byte.
    """
    # Implicit conditions are folded into the prior list before hashing
    # so the cache partitions correctly: distinct implicit sets produce
    # distinct cache keys.
    combined_priors = tuple(prior_conditions) + implicit_conditions if implicit_conditions else tuple(prior_conditions)
    return _condition_is_contradicted_cached(_normalize_condition(condition), combined_priors)


# R4.1: bound the cross-product enumeration in the contradiction check.
# Raised from 64 → 256 after profiling showed real corpora rarely hit even
# 16 combinations; the prior cap was overly conservative. Soundness is
# preserved: when the cap is hit, the check returns "not contradicted"
# (false negatives are OK, false positives would silently drop reachable
# branches).
_MAX_DISJUNCTIVE_COMBINATIONS = 256


def _conjunction_is_self_consistent(facts: list[Fact]) -> bool:
    """True iff a single AND-conjunction of facts is internally satisfiable."""
    for i, left in enumerate(facts):
        for right in facts[i + 1 :]:
            if _facts_contradict(left, right):
                return False
    return True


@lru_cache(maxsize=8192)
def _condition_is_contradicted_cached(condition: str, prior_conditions: tuple[str, ...]) -> bool:
    """Check whether `condition` is unsatisfiable given prior_conditions.

    Both `condition` and each prior may be a disjunction of conjunctions
    (DNF). The combined formula is satisfiable iff some choice of one
    disjunct from `condition` and one disjunct from each prior produces an
    internally-consistent conjunction. We try every combination and return
    True only if ALL combinations are inconsistent. To keep this cheap, the
    cross-product is bounded by `_MAX_DISJUNCTIVE_COMBINATIONS`; over the
    bound we conservatively report "not contradicted" (sound: false negatives
    are OK, false positives would silently kill reachable branches).

    R4.1 note: an inner cache keyed on canonicalized fact tuples was tried
    and reverted. The accumulating ``prior_conditions`` tuple grows by one
    distinct fact per elif branch, so canonical-form keys are still
    unique-per-branch (0% hit rate measured on the worst fixture). If a
    future workload exposes condition-reordering across branches, revisit.
    """
    current_alternatives = _disjunctive_facts_for_condition(condition)
    if not current_alternatives:
        return False  # nothing parseable; can't conclude anything

    prior_alternatives_per_condition: list[tuple[tuple[Fact, ...], ...]] = []
    total = len(current_alternatives)
    for prior in prior_conditions:
        prior_alts = _disjunctive_facts_for_condition(prior)
        if not prior_alts:
            continue  # no facts from this prior; ignore it
        prior_alternatives_per_condition.append(prior_alts)
        total *= len(prior_alts)
        if total > _MAX_DISJUNCTIVE_COMBINATIONS:
            return False  # bail out conservatively

    # Try every combination of (one current disjunct + one disjunct per prior).
    # If any combination is self-consistent, the condition is satisfiable.
    for combo in product(current_alternatives, *prior_alternatives_per_condition):
        merged: list[Fact] = []
        for facts in combo:
            merged.extend(facts)
        if _conjunction_is_self_consistent(merged):
            return False  # satisfiable combination found
    return True


def conditions_are_compatible(
    conditions: list[str],
    implicit_conditions: tuple[str, ...] = (),
) -> bool:
    """Returns False iff the conjunction of ``conditions`` plus
    ``implicit_conditions`` is provably unsatisfiable.

    ``implicit_conditions`` (PR-C / F2 algebra wiring): same role as in
    :func:`condition_is_contradicted` — synthetic grok-derived
    constraints that augment the user-visible ``conditions`` list so
    downstream contradiction reasoning can leverage what the analyzer
    knows about captured fields' value shapes. Empty tuple by default.
    """
    combined = tuple(conditions) + implicit_conditions if implicit_conditions else tuple(conditions)
    return _conditions_are_compatible_cached(combined)


@lru_cache(maxsize=65536)
def _conditions_are_compatible_cached(conditions: tuple[str, ...]) -> bool:
    """Returns False iff the conjunction of all ``conditions`` is provably
    unsatisfiable.

    The literal-only path uses per-field equal/not-equal dicts for O(n)
    detection of pure-literal contradictions; this is the hot path and
    handles the vast majority of conditions in real corpora. RegexFacts
    are collected and resolved in a second pairwise pass via the
    symbolic algebra — only when one or more is present, so literal-only
    workloads pay zero algebra cost.
    """
    equal_by_field: dict[str, str] = {}
    not_equal_by_field: dict[str, set[str]] = {}
    regex_facts: list[RegexFact] = []
    literal_facts_by_field: dict[str, list[LiteralFact]] = {}
    for condition in conditions:
        if not condition:
            continue
        # Each condition may be a single fact or a top-level `and`-conjunction
        # of multiple facts; ingest every conjunct.
        for fact in _facts_for_condition(condition):
            if isinstance(fact, RegexFact):
                regex_facts.append(fact)
                continue
            literal_facts_by_field.setdefault(fact.field, []).append(fact)
            if fact.is_equal:
                prior_equal = equal_by_field.get(fact.field)
                if prior_equal is not None and prior_equal != fact.value:
                    return False
                if fact.value in not_equal_by_field.get(fact.field, set()):
                    return False
                equal_by_field[fact.field] = fact.value
                continue
            prior_equal = equal_by_field.get(fact.field)
            if prior_equal == fact.value:
                return False
            not_equal_by_field.setdefault(fact.field, set()).add(fact.value)

    if not regex_facts:
        return True

    # Phase 1: regex-fact pairwise check. Only same-field pairs can
    # contradict, so partition first.
    by_field: dict[str, list[RegexFact]] = {}
    for rf in regex_facts:
        by_field.setdefault(rf.field, []).append(rf)
    for field, rfs in by_field.items():
        for i, left in enumerate(rfs):
            for right in rfs[i + 1 :]:
                # Identical-regex fast path: ``A`` is never disjoint
                # from itself (the algebra would always return NO),
                # but going through ``_facts_contradict`` is wasted
                # work even on a cache hit. Skip directly.
                if left.body == right.body and left.flags == right.flags and left.is_match == right.is_match:
                    continue
                if _facts_contradict(left, right):
                    return False
            for lf in literal_facts_by_field.get(field, ()):
                if _facts_contradict(left, lf):
                    return False
    return True


def is_exact_literal_regex_condition(condition: str) -> bool:
    return _regex_is_exact_literal(_normalize_condition(condition))
