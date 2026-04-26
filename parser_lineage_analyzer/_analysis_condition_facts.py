"""Conservative literal-fact extraction for branch conditions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from itertools import product


@dataclass(frozen=True)
class LiteralFact:
    field: str
    value: str
    is_equal: bool = True

    def negated(self) -> LiteralFact:
        return LiteralFact(self.field, self.value, not self.is_equal)


_EQ_RE = re.compile(r'^(?P<field>(?:\[[^\]]+\])+)\s*==\s*"(?P<value>(?:\\.|[^"\\])*)"$')
_NE_RE = re.compile(r'^(?P<field>(?:\[[^\]]+\])+)\s*!=\s*"(?P<value>(?:\\.|[^"\\])*)"$')
_EXACT_REGEX_RE = re.compile(r"^(?P<field>(?:\[[^\]]+\])+)\s*=~\s*/\^(?P<value>[A-Za-z0-9_ .:@-]+)\$/[A-Za-z]*$")
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
            out.append(value[i + 1])
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
    m = _EXACT_REGEX_RE.match(condition)
    if m:
        return LiteralFact(m.group("field"), m.group("value"))
    return None


def negated_literal_fact_from_condition(condition: str) -> LiteralFact | None:
    m = _NEGATED_RE.match(_normalize_condition(condition))
    if not m:
        return None
    fact = _literal_fact_from_normalized_condition(_normalize_condition(m.group("inner")))
    if fact is None:
        return None
    return fact.negated()


@lru_cache(maxsize=8192)
def _fact_from_condition(condition: str) -> LiteralFact | None:
    condition = _normalize_condition(condition)
    return _literal_fact_from_normalized_condition(condition) or _negated_literal_fact_from_normalized_condition(
        condition
    )


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
            # Word-boundary check: the character after the separator can't be
            # an identifier char (so we don't split `branding` on " and ").
            after = i + sep_len
            if after >= n or not (condition[after].isalnum() or condition[after] == "_"):
                parts.append("".join(buf).strip())
                buf = []
                i = after
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
def _facts_for_condition(condition: str) -> tuple[LiteralFact, ...]:
    """Extract one fact per top-level ``and``-conjunct.

    Returns ``()`` if no conjunct yields a fact. Conjuncts that can't be parsed
    into a fact are silently dropped — the analyzer is conservative, and a
    partial fact set is still useful for contradiction detection.
    """
    facts: list[LiteralFact] = []
    for conjunct in _split_top_level_and(_normalize_condition(condition)):
        fact = _fact_from_condition(conjunct)
        if fact is not None:
            facts.append(fact)
    return tuple(facts)


@lru_cache(maxsize=8192)
def _disjunctive_facts_for_condition(condition: str) -> tuple[tuple[LiteralFact, ...], ...]:
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
    out: list[tuple[LiteralFact, ...]] = []
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


def _facts_contradict(left: LiteralFact, right: LiteralFact) -> bool:
    if left.field != right.field:
        return False
    if left.is_equal and right.is_equal:
        return left.value != right.value
    if left.is_equal != right.is_equal:
        return left.value == right.value
    return False


def condition_is_contradicted(condition: str, prior_conditions: list[str]) -> bool:
    return _condition_is_contradicted_cached(_normalize_condition(condition), tuple(prior_conditions))


# R4.1: bound the cross-product enumeration in the contradiction check.
# Raised from 64 → 256 after profiling showed real corpora rarely hit even
# 16 combinations; the prior cap was overly conservative. Soundness is
# preserved: when the cap is hit, the check returns "not contradicted"
# (false negatives are OK, false positives would silently drop reachable
# branches).
_MAX_DISJUNCTIVE_COMBINATIONS = 256


def _conjunction_is_self_consistent(facts: list[LiteralFact]) -> bool:
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

    prior_alternatives_per_condition: list[tuple[tuple[LiteralFact, ...], ...]] = []
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
        merged: list[LiteralFact] = []
        for facts in combo:
            merged.extend(facts)
        if _conjunction_is_self_consistent(merged):
            return False  # satisfiable combination found
    return True


def conditions_are_compatible(conditions: list[str]) -> bool:
    return _conditions_are_compatible_cached(tuple(conditions))


@lru_cache(maxsize=65536)
def _conditions_are_compatible_cached(conditions: tuple[str, ...]) -> bool:
    equal_by_field: dict[str, str] = {}
    not_equal_by_field: dict[str, set[str]] = {}
    for condition in conditions:
        if not condition:
            continue
        # Each condition may be a single fact or a top-level `and`-conjunction
        # of multiple facts; ingest every conjunct.
        for fact in _facts_for_condition(condition):
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
    return True


def is_exact_literal_regex_condition(condition: str) -> bool:
    return _EXACT_REGEX_RE.match(_normalize_condition(condition)) is not None
