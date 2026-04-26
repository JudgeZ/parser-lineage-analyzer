"""Symbolic regex algebra for Logstash-style ``=~`` condition regexes.

Two layers:

* **Phase 0 (shape classification)** — extract ``=~ /body/flags`` from a
  normalized condition, classify the body's structural shape via stdlib
  ``sre_parse``, and surface the *literal value* for ``EXACT_LITERAL``
  patterns so callers can build a literal fact for the existing
  contradiction logic.
* **Phase 1 (algebra)** — for bodies the supported subset can lower to
  an internal IR, decide intersection-emptiness and language subset by
  building NFAs (Thompson construction), determinizing on-the-fly via
  product subset construction over a disjoint alphabet partition, and
  reasoning over the resulting reachability.

The two layers share the same untrusted-input surface and the same
soundness model (below).

Soundness rule (load-bearing): every limit, parse error, or
unrecognized construct returns ``UNSUPPORTED`` (Phase 0) or
:attr:`Trilean.UNKNOWN` (Phase 1). False negatives in the analyzer's
contradiction check are acceptable; false positives silently drop
reachable branches and corrupt the lineage graph downstream. Every
limit constant in this module is named so the budget is greppable, and
every limit-hit path is exercised by a test in
``tests/test_regex_algebra.py``.
"""

from __future__ import annotations

import re
import threading
import time
import warnings
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache

# Python 3.12 moved ``sre_parse`` and ``sre_constants`` under the ``re``
# package as private modules. Both names still exist as deprecated shims,
# but importing the new location avoids ``DeprecationWarning`` and the
# eventual removal. Both modules are private (no typeshed stubs), hence
# the ``type: ignore`` comments.
try:
    from re import (  # type: ignore[attr-defined]
        _constants as _sre_constants,
        _parser as _sre_parse,
    )
except ImportError:  # Python 3.10, 3.11
    import sre_constants as _sre_constants
    import sre_parse as _sre_parse


# -- Public limits ----------------------------------------------------
# Module-level so they're grep-able and can be tightened in one place.
# Each limit's behavior at the cap is *always* the same: return
# UNSUPPORTED (Phase 0) or Trilean.UNKNOWN (Phase 1). Never raise,
# never loop. The contradiction check treats UNKNOWN as "compatible" —
# false negatives only.

# Pre-flight rejections (apply to both phases).
MAX_REGEX_BODY_BYTES = 512
MAX_SRE_PARSE_DEPTH = 32
MAX_ALTERNATION_BRANCHES = 64

# Phase 1 algebra budget. NFA states are bounded per pattern; DFA
# states are bounded per side; product states bound the joint search.
# Wall-clock budget is checked inside the BFS loop every
# ``_TIME_CHECK_INTERVAL`` iterations to avoid the per-step syscall cost.
MAX_NFA_STATES = 1024
MAX_DFA_STATES = 4096
MAX_PRODUCT_STATES = 16384
MAX_ALPHABET_PARTITIONS = 256
MAX_REPEAT_BOUND = 64  # `{n,m}` with m above this => UNKNOWN
# Cap on the number of code points materialized into a single
# ``_CharSet`` from a literal range like ``[lo-hi]``. Without it,
# ``[\x00-\U0010ffff]`` would allocate ~1.1M ints in
# ``_charset_from_range`` *before* any algebra budget check fires.
# 1024 is generous enough for typical real-world classes (ASCII,
# Latin-1, single Unicode block) but rejects pathological wide ranges.
MAX_CHARSET_SIZE = 1024
ALGEBRA_TIME_BUDGET_MS = 25
# Iterations between ``time.monotonic`` polls inside the BFS / fill
# loops. Must be a power of 2 (the bounded loops use bitwise ``&`` to
# mask the iteration counter). Lowered from 256 → 32 after review:
# each BFS step iterates the alphabet partition (up to 256 classes)
# and an epsilon-closure pass per class, so 256 outer iterations could
# do millions of inner ops between clock polls — enough to blow past
# the 25ms budget by an order of magnitude before the first check
# fired. 32 keeps the polling overhead negligible (one clock call per
# ~32 popleft, ~200ns per call) while tightening the worst-case
# overshoot to ~12% of the prior bound.
_TIME_CHECK_INTERVAL = 32


# -- Shape classification --------------------------------------------


class RegexShape(Enum):
    """Structural classification of a parsed regex body."""

    EXACT_LITERAL = "exact_literal"
    ANCHORED_ALTERNATION_OF_LITERALS = "anchored_alternation_of_literals"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ShapeAnalysis:
    """Result of classifying a regex body.

    ``literal_value`` is set only when ``shape == EXACT_LITERAL``; it is
    the concrete matched string (escapes resolved), comparable directly
    to a ``==`` literal.

    ``alternatives`` is set only when
    ``shape == ANCHORED_ALTERNATION_OF_LITERALS``; each element is the
    literal of one branch. Phase 0 records this for diagnostics but does
    not yet plumb it through to the contradiction logic.
    """

    shape: RegexShape
    literal_value: str | None = None
    alternatives: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RegexLiteral:
    """An extracted ``=~ /body/flags`` regex literal."""

    field: str
    body: str
    flags: str


# -- Extractor -------------------------------------------------------

# Captures `<field>+ =~ /body/flags` from a normalized condition. The
# body permits any character except an unescaped delimiter `/`; `\\.`
# escapes any single character (including `/`). We do NOT validate the
# body as a real regex here — that is `analyze_shape`'s job.
_EXTRACT_REGEX_LITERAL_RE = re.compile(
    r"^(?P<field>(?:\[[^\]]+\])+)"
    r"\s*=~\s*"
    r"/(?P<body>(?:\\.|[^/\\])*)/"
    r"(?P<flags>[A-Za-z]*)$"
)


def extract_regex_literal(condition: str) -> RegexLiteral | None:
    """Pull ``=~ /body/flags`` out of a normalized condition string.

    Returns ``None`` if the condition is not a single ``=~`` comparison
    or if the body exceeds ``MAX_REGEX_BODY_BYTES``.
    """
    match = _EXTRACT_REGEX_LITERAL_RE.match(condition)
    if match is None:
        return None
    body = match.group("body")
    if len(body.encode("utf-8")) > MAX_REGEX_BODY_BYTES:
        return None
    return RegexLiteral(
        field=match.group("field"),
        body=body,
        flags=match.group("flags"),
    )


# -- Shape classifier ------------------------------------------------

# Logstash pre-processes Grok refs (`%{NAME}` / `%{NAME:capture}`)
# *before* the regex engine ever sees the body. If we encounter `%{` in
# the body we are not looking at a real regex; bail.
_GROK_REF_SUBSTRING = "%{"

# Opcodes we know how to interpret. Anything else => UNSUPPORTED.
_LITERAL = _sre_constants.LITERAL
_AT = _sre_constants.AT
_AT_BEGINNING = _sre_constants.AT_BEGINNING
_AT_END = _sre_constants.AT_END
_SUBPATTERN = _sre_constants.SUBPATTERN
_BRANCH = _sre_constants.BRANCH

# Baseline flag bits ``sre_parse`` always sets on a freshly-parsed pattern.
# Any flag bit *outside* this mask was introduced by an inline modifier
# in the body (e.g. ``(?i)``); those change match semantics in ways the
# Phase 0 classifier does not yet model, so we treat the body as opaque.
# ``sre_parse`` swallows top-level ``(?i)`` etc. silently — the AST shows
# only the literal nodes — so without this check we would unsoundly
# extract ``foo`` from ``(?i)foo`` and let it contradict ``== "FOO"``.
_PERMITTED_INLINE_FLAGS = _sre_constants.SRE_FLAG_UNICODE


def analyze_shape(body: str, flags: str = "") -> ShapeAnalysis:
    """Classify a Logstash regex body's structural shape.

    Returns ``RegexShape.UNSUPPORTED`` for any body that is too large,
    contains Grok references, has flags (Phase 0 honors only the empty
    flag set), or whose ``sre_parse`` tree contains constructs the
    classifier hasn't proven sound.
    """
    return _analyze_shape_cached(body, flags)


@lru_cache(maxsize=8192)
def _analyze_shape_cached(body: str, flags: str) -> ShapeAnalysis:
    # Pre-flight cheap rejects.
    if len(body.encode("utf-8")) > MAX_REGEX_BODY_BYTES:
        return ShapeAnalysis(RegexShape.UNSUPPORTED)
    if _GROK_REF_SUBSTRING in body:
        return ShapeAnalysis(RegexShape.UNSUPPORTED)
    if "\n" in body or "\r" in body:
        return ShapeAnalysis(RegexShape.UNSUPPORTED)

    # Phase 0 honors only the empty flag set. `(?i)` and friends change
    # match semantics in ways the classifier does not yet model; rather
    # than partially honor some, we punt. The prior `_EXACT_REGEX_RE`
    # silently accepted trailing flags, which was unsound under `i` —
    # rejecting them here is a deliberate soundness fix.
    if flags:
        return ShapeAnalysis(RegexShape.UNSUPPORTED)

    try:
        # `sre_parse` emits DeprecationWarning for things like inline flags
        # not at the start of the pattern. We classify those bodies as
        # UNSUPPORTED anyway; suppress the warning so the analyzer doesn't
        # leak parser noise into callers' stderr.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = _sre_parse.parse(body)
    except (re.error, RecursionError, MemoryError):
        return ShapeAnalysis(RegexShape.UNSUPPORTED)

    if tree.state.flags & ~_PERMITTED_INLINE_FLAGS:
        return ShapeAnalysis(RegexShape.UNSUPPORTED)

    return _classify(list(tree))


def _classify(items: list) -> ShapeAnalysis:
    if not items:
        return ShapeAnalysis(RegexShape.UNSUPPORTED)

    starts_anchored = items[0] == (_AT, _AT_BEGINNING)
    ends_anchored = items[-1] == (_AT, _AT_END)
    if not (starts_anchored and ends_anchored):
        # Phase 0: only fully-anchored bodies produce a usable fact. The
        # plan reserves PREFIX_LITERAL / SUFFIX_LITERAL / SUBSTRING_LITERAL
        # shapes for Phase 1, where the algebra can reason about them.
        return ShapeAnalysis(RegexShape.UNSUPPORTED)

    inner = items[1:-1]

    # Pure-literal sequence => EXACT_LITERAL.
    flat = _flatten_pure_literals(inner)
    if flat is not None:
        return ShapeAnalysis(
            shape=RegexShape.EXACT_LITERAL,
            literal_value=flat,
        )

    # Anchored alternation of pure literals => record branches. (Phase 0
    # classifier-only; downstream code does not yet consume these.)
    alts = _try_anchored_alternation_of_literals(inner)
    if alts is not None:
        return ShapeAnalysis(
            shape=RegexShape.ANCHORED_ALTERNATION_OF_LITERALS,
            alternatives=alts,
        )

    return ShapeAnalysis(RegexShape.UNSUPPORTED)


def _flatten_pure_literals(items: list) -> str | None:
    """Return the literal string if ``items`` is a pure sequence of
    ``LITERAL`` nodes, optionally wrapped in single-child SUBPATTERNs.

    Returns ``None`` for any node that isn't a literal or a transparent
    group around literals. Capture-group naming is immaterial here — we
    only care about the matched language.
    """
    out: list[str] = []
    for node in items:
        op = node[0]
        if op == _LITERAL:
            out.append(chr(node[1]))
            continue
        if op == _SUBPATTERN:
            # SUBPATTERN args: (group_id, add_flags, del_flags, subpattern).
            # Honor only groups that don't change flags; any inline
            # `(?i:...)` / `(?-i:...)` etc. has nonzero add/del flags
            # and we treat it as opaque.
            _group_id, add_flags, del_flags, subpattern = node[1]
            if add_flags or del_flags:
                return None
            inner = _flatten_pure_literals(list(subpattern))
            if inner is None:
                return None
            out.append(inner)
            continue
        return None
    return "".join(out)


def _try_anchored_alternation_of_literals(inner: list) -> tuple[str, ...] | None:
    """Return tuple of literal alternatives if ``inner`` is exactly one
    BRANCH node (optionally wrapped in a single SUBPATTERN) whose every
    branch is a pure literal sequence. Otherwise ``None``.
    """
    if len(inner) != 1:
        return None
    node = inner[0]
    op = node[0]
    if op == _SUBPATTERN:
        _group_id, add_flags, del_flags, subpattern = node[1]
        if add_flags or del_flags:
            return None
        sub_items = list(subpattern)
        if len(sub_items) != 1:
            return None
        node = sub_items[0]
        op = node[0]
    if op != _BRANCH:
        return None
    # BRANCH args: (None, [branch1, branch2, ...]) — branches are SubPatterns.
    branches = node[1][1]
    if len(branches) > MAX_ALTERNATION_BRANCHES:
        return None
    out: list[str] = []
    for branch in branches:
        flat = _flatten_pure_literals(list(branch))
        if flat is None:
            return None
        out.append(flat)
    return tuple(out)


# -- Phase 0 entry points used by `_analysis_condition_facts` ---------


def exact_literal_value(condition: str) -> tuple[str, str] | None:
    """Return ``(field, literal)`` if ``condition`` is ``=~ /^literal$/``
    with all-pure-literal characters and no flags. Otherwise ``None``.

    This is a strict superset of the prior ``_EXACT_REGEX_RE`` charset
    (``[A-Za-z0-9_ .:@-]+``): the new extractor accepts any pure-literal
    body, including escaped metacharacters that resolve to a single
    literal char (``\\.`` => ``.``, ``\\\\`` => ``\\``). It also rejects
    trailing flags, which the prior extractor silently accepted —
    fixing an unsoundness under ``/^Foo$/i``.
    """
    extracted = extract_regex_literal(condition)
    if extracted is None:
        return None
    analysis = analyze_shape(extracted.body, extracted.flags)
    if analysis.shape != RegexShape.EXACT_LITERAL or analysis.literal_value is None:
        return None
    return extracted.field, analysis.literal_value


def is_exact_literal_regex(condition: str) -> bool:
    """``True`` iff ``condition`` is ``=~ /^literal$/`` with no flags."""
    return exact_literal_value(condition) is not None


# =====================================================================
# Phase 1: symbolic algebra (intersection emptiness, language subset)
# =====================================================================
#
# The algebra is sandwiched between two narrow boundaries:
#
# 1. ``_lower_pattern_to_ir`` — the *only* place that walks the
#    ``sre_parse`` AST for Phase 1. Every unsupported construct, every
#    over-bound quantifier, every over-large alternation returns
#    ``None`` here, and ``None`` propagates as ``Trilean.UNKNOWN`` from
#    the public API.
# 2. The IR is finite-state-language-only (no backrefs, no lookaround).
#    Every IR node maps to a sound NFA via Thompson construction. NFA →
#    DFA is the textbook subset construction over a precomputed
#    disjoint alphabet partition. Intersection-emptiness is on-the-fly
#    product BFS; language subset is ``A ∩ ¬B = ∅``.
#
# All algebra functions thread a :class:`_Budget` and return ``None``
# (or :attr:`Trilean.UNKNOWN`) the moment any cap is hit.


# -- Public algebra types --------------------------------------------


class Trilean(Enum):
    """Three-valued logic: ``YES`` / ``NO`` / ``UNKNOWN``.

    ``UNKNOWN`` is the soundness-preserving default for any limit hit,
    parse error, or unsupported construct. Callers must treat
    ``UNKNOWN`` exactly like the property they were asking about being
    false (i.e. "we couldn't prove the contradiction, so assume the
    branches are compatible").
    """

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


# -- CharSet ----------------------------------------------------------


@dataclass(frozen=True)
class _CharSet:
    """A set of Unicode code points represented as a finite frozenset
    of "interesting" code points plus a ``negated`` bit.

    ``negated=False``: the set is exactly ``chars``.
    ``negated=True``: the set is *every* code point *except* ``chars``
    (i.e. complement of ``chars``).

    This representation keeps ``[a-z]`` compact (26 ints) and ``[^abc]``
    compact (3 ints + a bit), and avoids enumerating Unicode for
    operations like ``\\d`` or wildcard ``.``.
    """

    chars: frozenset[int]
    negated: bool = False

    def contains(self, c: int) -> bool:
        return (c in self.chars) ^ self.negated

    def is_empty(self) -> bool:
        return not self.negated and not self.chars

    def is_universal(self) -> bool:
        return self.negated and not self.chars

    def union(self, other: _CharSet) -> _CharSet:
        # Set algebra over (chars, negated) representation:
        #   pos(A) ∪ pos(B) = pos(A ∪ B)
        #   pos(A) ∪ neg(B) = neg(B \ A)        [complement of "in B but not in A"]
        #   neg(A) ∪ pos(B) = neg(A \ B)
        #   neg(A) ∪ neg(B) = neg(A ∩ B)
        if self.negated and other.negated:
            return _CharSet(self.chars & other.chars, True)
        if self.negated:
            return _CharSet(self.chars - other.chars, True)
        if other.negated:
            return _CharSet(other.chars - self.chars, True)
        return _CharSet(self.chars | other.chars, False)

    def intersection(self, other: _CharSet) -> _CharSet:
        # Dual of union.
        if self.negated and other.negated:
            return _CharSet(self.chars | other.chars, True)
        if self.negated:
            return _CharSet(other.chars - self.chars, False)
        if other.negated:
            return _CharSet(self.chars - other.chars, False)
        return _CharSet(self.chars & other.chars, False)

    def difference(self, other: _CharSet) -> _CharSet:
        return self.intersection(other.complement())

    def complement(self) -> _CharSet:
        return _CharSet(self.chars, not self.negated)

    def representative(self) -> int | None:
        """Pick any code point in this set, or ``None`` if empty.

        Used during DFA transitions: since every alphabet class is
        either fully contained in or fully disjoint from each transition
        CharSet, *any* representative gives the right answer.
        """
        if self.chars and not self.negated:
            return next(iter(self.chars))
        if self.negated:
            # Find smallest non-negative int not in chars. ASCII range is
            # always enough for our purposes; if every ASCII char is
            # excluded we fall back to scanning higher.
            c = 0
            while c in self.chars:
                c += 1
            return c
        return None


_EMPTY_CHARSET = _CharSet(frozenset(), False)
_UNIVERSAL_CHARSET = _CharSet(frozenset(), True)


def _charset_from_chars(chars: tuple[int, ...]) -> _CharSet:
    return _CharSet(frozenset(chars), False)


def _charset_from_range(lo: int, hi: int) -> _CharSet | None:
    """Inclusive ``[lo, hi]`` range to a CharSet, or ``None`` if the
    range exceeds :data:`MAX_CHARSET_SIZE`.

    The size check happens *before* materializing the frozenset so
    pathological inputs like ``[\\x00-\\U0010ffff]`` can't burn time
    or memory enumerating 1.1M code points before any algebra budget
    check fires. The caller treats ``None`` as "unsupported", which
    propagates as :attr:`Trilean.UNKNOWN` from the public API.
    """
    if hi < lo:
        return _EMPTY_CHARSET
    if hi - lo + 1 > MAX_CHARSET_SIZE:
        return None
    return _CharSet(frozenset(range(lo, hi + 1)), False)


# Common shorthand classes (ASCII semantics — Phase 1 does not honor
# Unicode-aware ``\d``/``\w``/``\s`` to keep the alphabet finite and the
# soundness model simple).
_DIGIT_CHARSET = _CharSet(frozenset(range(ord("0"), ord("9") + 1)), False)
_WORD_CHARSET = _CharSet(
    frozenset(
        list(range(ord("0"), ord("9") + 1))
        + list(range(ord("A"), ord("Z") + 1))
        + list(range(ord("a"), ord("z") + 1))
        + [ord("_")]
    ),
    False,
)
_SPACE_CHARSET = _charset_from_chars((ord(" "), ord("\t"), ord("\n"), ord("\r"), ord("\v"), ord("\f")))


# -- IR ---------------------------------------------------------------
#
# Node types are deliberately minimal. All quantifiers reduce to
# combinations of (Concat, Union, Star, Empty). Smart constructors
# enforce canonical forms so equal patterns hash equally and the
# IR-keyed caches hit reliably.


class _IR:
    """Marker base class for IR nodes."""

    __slots__ = ()


@dataclass(frozen=True)
class _IREmpty(_IR):
    """Matches the empty string (only)."""


@dataclass(frozen=True)
class _IREmptySet(_IR):
    """Matches no string."""


@dataclass(frozen=True)
class _IRChar(_IR):
    """Matches one code point from ``chars``."""

    chars: _CharSet


@dataclass(frozen=True)
class _IRConcat(_IR):
    a: _IR
    b: _IR


@dataclass(frozen=True)
class _IRUnion(_IR):
    a: _IR
    b: _IR


@dataclass(frozen=True)
class _IRStar(_IR):
    a: _IR


_IR_EMPTY = _IREmpty()
_IR_EMPTYSET = _IREmptySet()


def _ir_concat(a: _IR, b: _IR) -> _IR:
    if isinstance(a, _IREmptySet) or isinstance(b, _IREmptySet):
        return _IR_EMPTYSET
    if isinstance(a, _IREmpty):
        return b
    if isinstance(b, _IREmpty):
        return a
    return _IRConcat(a, b)


def _ir_union(a: _IR, b: _IR) -> _IR:
    if isinstance(a, _IREmptySet):
        return b
    if isinstance(b, _IREmptySet):
        return a
    if a == b:
        return a
    return _IRUnion(a, b)


def _ir_star(a: _IR) -> _IR:
    if isinstance(a, (_IREmpty, _IREmptySet)):
        return _IR_EMPTY
    if isinstance(a, _IRStar):
        return a  # (a*)* = a*
    return _IRStar(a)


def _ir_optional(a: _IR) -> _IR:
    """``a?`` = ``a | ε``."""
    return _ir_union(a, _IR_EMPTY)


def _ir_concat_many(parts: list[_IR]) -> _IR:
    if not parts:
        return _IR_EMPTY
    result = parts[0]
    for p in parts[1:]:
        result = _ir_concat(result, p)
    return result


# -- Pattern → IR lowering -------------------------------------------


# Logstash uses Oniguruma named-capture syntax `(?<name>...)`; Python's
# stdlib regex uses `(?P<name>...)`. They're semantically identical for
# matching (capture names are immaterial here), so we rewrite before
# handing the body to ``sre_parse``. Two negative cases the rewrite
# must avoid:
#   * Lookbehind ``(?<=`` / ``(?<!`` — handled by the lookahead
#     ``(?=[A-Za-z_])`` requiring an identifier char after ``<``.
#   * Escaped left-paren ``\(?<...>`` — a literal ``(`` followed by
#     unrelated ``?<...``. We rewrite only when an *even* number of
#     backslashes precedes the ``(`` (zero counts as even); odd means
#     the ``(`` itself is escaped. Python regex lookbehind is
#     fixed-length, so the parity check happens in a callback that
#     scans the preceding chars. Naive ``(?<!\\)`` would mis-handle
#     ``\\(?<x>...`` (two backslashes = literal ``\`` then real named
#     capture), leaving it unconverted.
_NAMED_CAPTURE_HEAD_RE = re.compile(r"\(\?<(?=[A-Za-z_])")


def _normalize_oniguruma(body: str) -> str:
    def _rewrite(match: re.Match[str]) -> str:
        # Count backslashes immediately preceding the match. Odd ⇒
        # ``(`` is escaped (literal paren), don't rewrite.
        backslashes = 0
        i = match.start() - 1
        while i >= 0 and body[i] == "\\":
            backslashes += 1
            i -= 1
        if backslashes % 2 == 1:
            return match.group(0)
        return "(?P<"

    return _NAMED_CAPTURE_HEAD_RE.sub(_rewrite, body)


# Additional ``sre_parse`` opcodes used by Phase 1 lowering. Phase 0
# already imported the small subset it needs; the rest live here so
# Phase 0 stays minimal.
_NOT_LITERAL = _sre_constants.NOT_LITERAL
_ANY = _sre_constants.ANY
_IN = _sre_constants.IN
_MAX_REPEAT = _sre_constants.MAX_REPEAT
_MIN_REPEAT = _sre_constants.MIN_REPEAT
_RANGE = _sre_constants.RANGE
_CATEGORY = _sre_constants.CATEGORY
_NEGATE = _sre_constants.NEGATE
_CATEGORY_DIGIT = _sre_constants.CATEGORY_DIGIT
_CATEGORY_NOT_DIGIT = _sre_constants.CATEGORY_NOT_DIGIT
_CATEGORY_WORD = _sre_constants.CATEGORY_WORD
_CATEGORY_NOT_WORD = _sre_constants.CATEGORY_NOT_WORD
_CATEGORY_SPACE = _sre_constants.CATEGORY_SPACE
_CATEGORY_NOT_SPACE = _sre_constants.CATEGORY_NOT_SPACE
_MAXREPEAT = _sre_constants.MAXREPEAT


@dataclass
class _LoweringContext:
    """Per-call lowering state. ``case_fold`` toggles ASCII case-folding
    for ``LITERAL`` / ``IN`` nodes (set when the pattern carries
    ``re.IGNORECASE``)."""

    case_fold: bool


def _case_fold_chars(chars: frozenset[int]) -> frozenset[int] | None:
    """ASCII case-fold: each ASCII letter becomes the pair {upper, lower}.

    Returns ``None`` if any code point in ``chars`` is a *non-ASCII*
    letter with Unicode case (e.g. ``é``↔``É``, ``α``↔``Α``,
    ``ß``↔``ẞ``). Phase 1 does not model Unicode case folding —
    leaving such characters unchanged would let the algebra return
    definitive ``YES``/``NO`` answers based on a language Onigmo
    actually folds (``regex_languages_disjoint("^é$", "i", "^É$", "")``
    would unsoundly come back ``YES``). Callers propagate the ``None``
    as ``Trilean.UNKNOWN``.

    ASCII non-letters and non-ASCII characters *without* case (digits,
    punctuation, symbols, emoji, ``☃``) are passed through unchanged —
    Onigmo doesn't fold them either.

    Case folding can be requested via the trailing ``/i`` flag (always
    applies to the whole pattern) or — for scoped subexpressions only —
    via ``(?i:...)`` SUBPATTERN ``add_flags``. Unscoped inline ``(?i)``
    in the body is rejected upstream in :func:`_lower_pattern_to_ir`.
    """
    out: set[int] = set()
    for c in chars:
        if 0x41 <= c <= 0x5A:  # A-Z
            out.add(c)
            out.add(c + 0x20)
            continue
        if 0x61 <= c <= 0x7A:  # a-z
            out.add(c)
            out.add(c - 0x20)
            continue
        if c <= 0x7F:
            # ASCII non-letter — no case mapping to track.
            out.add(c)
            continue
        # Non-ASCII: pass through only if Unicode considers it
        # uncased. Anything with a different upper/lower mapping
        # would be folded by Onigmo but not by us, so we bail.
        ch = chr(c)
        if ch.lower() != ch.upper():
            return None
        out.add(c)
    return frozenset(out)


def _lower_pattern_to_ir(body: str, flags: str) -> _IR | None:
    """Lower a Logstash regex body to IR.

    Wraps the IR with implicit ``Σ*`` on either side that lacks an
    explicit anchor at the *top level* of the body, matching Logstash's
    "search" semantics for ``=~``. Returns ``None`` for unsupported
    bodies or when any structural cap is hit.
    """
    if len(body.encode("utf-8")) > MAX_REGEX_BODY_BYTES:
        return None
    if _GROK_REF_SUBSTRING in body:
        return None
    if "\n" in body or "\r" in body:
        return None

    # Trailing flag bytes from the regex literal: only ``i`` is honored.
    # Anything else (m, s, x, u, ...) returns UNSUPPORTED to keep the
    # semantics-modeling burden small.
    case_fold = False
    for ch in flags:
        if ch == "i":
            case_fold = True
        else:
            return None

    rewritten = _normalize_oniguruma(body)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = _sre_parse.parse(rewritten)
    except (re.error, RecursionError, MemoryError):
        return None

    extra_flags = tree.state.flags & ~_PERMITTED_INLINE_FLAGS
    if extra_flags:
        # Any inline flag group inside the body — including the
        # unscoped ``(?i)`` — is unsupported. Logstash's Onigmo engine
        # scopes ``(?i)`` to the *remainder of its enclosing group*,
        # but CPython's ``sre_parse`` propagates it globally via
        # ``tree.state.flags`` with no positional information we could
        # use to recover the scoping. Folding the whole IR would
        # over-approximate the language: for ``^A(?i)B$``, Onigmo
        # accepts ``{A}{b,B}`` while a global fold accepts
        # ``{a,A}{b,B}``. The over-approximation is sound for
        # ``regex_languages_disjoint`` but unsound for
        # ``language_subset`` and ``literal_in_regex_language`` — both
        # could return YES based on strings that aren't actually in
        # L(P) under Onigmo. Bailing here preserves soundness across
        # all three primitives. Scoped ``(?i:...)`` is still honored
        # via the SUBPATTERN ``add_flags`` path in ``_lower_node``,
        # since that *is* an enclosing group whose scope is explicit.
        return None

    items = list(tree)
    if not items:
        return None  # empty body — no useful constraint

    # Detect top-level ``^`` and ``$``. They're "real" anchors only when
    # they sit at the very start/end of the top-level item sequence.
    starts_anchored = items[0] == (_AT, _AT_BEGINNING)
    ends_anchored = items[-1] == (_AT, _AT_END)
    inner = items[(1 if starts_anchored else 0) : (-1 if ends_anchored else None)]

    ctx = _LoweringContext(case_fold=case_fold)
    inner_ir = _lower_items(inner, ctx, depth=0)
    if inner_ir is None:
        return None

    sigma_star = _ir_star(_IRChar(_UNIVERSAL_CHARSET))
    parts: list[_IR] = []
    if not starts_anchored:
        parts.append(sigma_star)
    parts.append(inner_ir)
    if ends_anchored:
        # Ruby/Oniguruma (and Python ``re`` in default mode) let ``$``
        # match *either* end-of-string *or* just before a final ``\n``.
        # Without the optional newline below, the algebra would
        # unsoundly answer YES for pairs like ``^a?$`` ∩ ``.[^a\r]$``
        # where both actually match ``"a\n"`` (``^a?$`` accepts ``a``
        # followed by trailing newline; the second pattern accepts
        # ``a`` then ``\n`` since ``\n`` is neither ``a`` nor ``\r``).
        parts.append(_ir_optional(_IRChar(_CharSet(frozenset({0x0A}), False))))
    else:
        parts.append(sigma_star)
    return _ir_concat_many(parts)


def _lower_items(items: list, ctx: _LoweringContext, depth: int) -> _IR | None:
    if depth > MAX_SRE_PARSE_DEPTH:
        return None
    parts: list[_IR] = []
    for node in items:
        ir = _lower_node(node, ctx, depth + 1)
        if ir is None:
            return None
        parts.append(ir)
    return _ir_concat_many(parts)


def _lower_node(node: tuple, ctx: _LoweringContext, depth: int) -> _IR | None:
    op, arg = node
    if op == _LITERAL:
        chars = frozenset({arg})
        if ctx.case_fold:
            folded = _case_fold_chars(chars)
            if folded is None:
                return None  # non-ASCII letter under (?i) — unsupported
            chars = folded
        return _IRChar(_CharSet(chars, False))
    if op == _NOT_LITERAL:
        chars = frozenset({arg})
        if ctx.case_fold:
            folded = _case_fold_chars(chars)
            if folded is None:
                return None
            chars = folded
        return _IRChar(_CharSet(chars, True))
    if op == _ANY:
        # Logstash uses Ruby/Oniguruma, where ``.`` matches any char
        # *except* line feed (``\n`` / 0x0A). Carriage return (``\r``)
        # *is* matched. Excluding ``\r`` here would be unsound: it
        # would let the algebra declare ``^.$`` and ``^\r$`` disjoint,
        # which they aren't, and would silently drop reachable
        # branches when a field value happens to contain ``\r``.
        return _IRChar(_CharSet(frozenset({0x0A}), True))
    if op == _IN:
        return _lower_in(arg, ctx)
    if op in (_MAX_REPEAT, _MIN_REPEAT):
        return _lower_repeat(arg, ctx, depth)
    if op == _SUBPATTERN:
        _group_id, add_flags, del_flags, sub = arg
        if del_flags:
            return None  # ``(?-i:...)`` etc.
        sub_ctx = ctx
        if add_flags:
            if add_flags == _sre_constants.SRE_FLAG_IGNORECASE:
                sub_ctx = _LoweringContext(case_fold=True)
            else:
                return None
        return _lower_items(list(sub), sub_ctx, depth + 1)
    if op == _BRANCH:
        _, branches = arg
        if len(branches) > MAX_ALTERNATION_BRANCHES:
            return None
        result: _IR = _IR_EMPTYSET
        for branch in branches:
            sub_ir = _lower_items(list(branch), ctx, depth + 1)
            if sub_ir is None:
                return None
            result = _ir_union(result, sub_ir)
        return result
    if op == _AT:
        # Anchor *not* at top level. ``^`` / ``$`` mid-pattern (e.g.
        # ``(^A|B$)``) interact with the implicit ``Σ*`` wrapping in
        # ways the algebra doesn't model precisely; bail.
        return None
    return None


def _lower_in(items: list, ctx: _LoweringContext) -> _IR | None:
    """Lower an ``IN`` node (character class like ``[a-z]``, ``[^abc]``,
    ``\\d``, etc.) to an ``_IRChar``."""
    negated = False
    chars = _EMPTY_CHARSET
    for child in items:
        op, arg = child
        if op == _NEGATE:
            negated = True
            continue
        if op == _LITERAL:
            cs = _CharSet(frozenset({arg}), False)
        elif op == _RANGE:
            lo, hi = arg
            range_cs = _charset_from_range(lo, hi)
            if range_cs is None:
                return None
            cs = range_cs
        elif op == _CATEGORY:
            maybe_cs = _category_charset(arg)
            if maybe_cs is None:
                return None
            cs = maybe_cs
        else:
            return None
        chars = chars.union(cs)
    if ctx.case_fold:
        # Case-fold a character class by folding its positive char set;
        # for negated classes we fold first then complement to preserve
        # ``[^A]`` ≡ ``[^aA]`` under ``(?i)``. ``_case_fold_chars``
        # returns None when any non-ASCII letter would require Unicode
        # folding we don't model — propagate as unsupported.
        folded = _case_fold_chars(chars.chars)
        if folded is None:
            return None
        chars = _CharSet(folded, chars.negated)
    if negated:
        chars = chars.complement()
    return _IRChar(chars)


def _category_charset(category: object) -> _CharSet | None:
    if category == _CATEGORY_DIGIT:
        return _DIGIT_CHARSET
    if category == _CATEGORY_NOT_DIGIT:
        return _DIGIT_CHARSET.complement()
    if category == _CATEGORY_WORD:
        return _WORD_CHARSET
    if category == _CATEGORY_NOT_WORD:
        return _WORD_CHARSET.complement()
    if category == _CATEGORY_SPACE:
        return _SPACE_CHARSET
    if category == _CATEGORY_NOT_SPACE:
        return _SPACE_CHARSET.complement()
    return None


def _lower_repeat(arg: tuple, ctx: _LoweringContext, depth: int) -> _IR | None:
    """Lower ``MAX_REPEAT(min, max, [body])`` / ``MIN_REPEAT(...)``.

    Greedy vs lazy doesn't affect language membership for our purposes,
    so both are lowered identically. Bounded ``{n,m}`` is unrolled to
    ``a^n · (a?)^(m-n)``; unbounded uses ``Star``.
    """
    lo, hi, sub = arg
    body_ir = _lower_items(list(sub), ctx, depth + 1)
    if body_ir is None:
        return None
    if hi is _MAXREPEAT or hi == _MAXREPEAT:
        if lo > MAX_REPEAT_BOUND:
            return None
        # ``a{n,}`` = ``a · a · ... · a`` (n times) · ``a*``
        return _ir_concat(_ir_concat_many([body_ir] * lo), _ir_star(body_ir))
    if hi > MAX_REPEAT_BOUND:
        return None
    if lo > hi:
        return None  # invalid range; degenerate but soundly empty
    # ``a{n,m}`` = ``a · ... · a`` (n times) · ``a?`` (m-n times)
    required = [body_ir] * lo
    optional = [_ir_optional(body_ir)] * (hi - lo)
    return _ir_concat_many(required + optional)


# -- NFA construction (Thompson) -------------------------------------


@dataclass
class _NFA:
    num_states: int
    start: int
    accept: int
    # ``edges[s]`` is a list of ``(label, target)`` where ``label`` is
    # ``None`` for an ε-edge or a ``_CharSet`` for a labeled edge.
    edges: list[list[tuple[_CharSet | None, int]]]


class _NFABuildBudget:
    """Tracks NFA construction cost; ``new_state`` returns ``-1`` once
    the cap is hit, and the builder propagates that as ``None``."""

    def __init__(self) -> None:
        self.next_state = 0
        self.edges: list[list[tuple[_CharSet | None, int]]] = []

    def new_state(self) -> int:
        if self.next_state >= MAX_NFA_STATES:
            return -1
        s = self.next_state
        self.next_state += 1
        self.edges.append([])
        return s

    def add_edge(self, src: int, label: _CharSet | None, dst: int) -> None:
        self.edges[src].append((label, dst))


def _build_nfa(ir: _IR) -> _NFA | None:
    builder = _NFABuildBudget()
    result = _build_fragment(ir, builder)
    if result is None:
        return None
    start, accept = result
    return _NFA(num_states=builder.next_state, start=start, accept=accept, edges=builder.edges)


def _build_fragment(ir: _IR, b: _NFABuildBudget) -> tuple[int, int] | None:
    """Returns ``(start, accept)`` for the sub-NFA, or ``None`` if the
    state cap was hit."""
    if isinstance(ir, _IREmpty):
        s = b.new_state()
        a = b.new_state()
        if s < 0 or a < 0:
            return None
        b.add_edge(s, None, a)
        return s, a
    if isinstance(ir, _IREmptySet):
        s = b.new_state()
        a = b.new_state()
        if s < 0 or a < 0:
            return None
        # No edge from s to a — accept is unreachable. Still need both
        # states so callers can wire ε-edges to/from this fragment.
        return s, a
    if isinstance(ir, _IRChar):
        s = b.new_state()
        a = b.new_state()
        if s < 0 or a < 0:
            return None
        if not ir.chars.is_empty():
            b.add_edge(s, ir.chars, a)
        return s, a
    if isinstance(ir, _IRConcat):
        f1 = _build_fragment(ir.a, b)
        if f1 is None:
            return None
        f2 = _build_fragment(ir.b, b)
        if f2 is None:
            return None
        b.add_edge(f1[1], None, f2[0])
        return f1[0], f2[1]
    if isinstance(ir, _IRUnion):
        f1 = _build_fragment(ir.a, b)
        if f1 is None:
            return None
        f2 = _build_fragment(ir.b, b)
        if f2 is None:
            return None
        s = b.new_state()
        a = b.new_state()
        if s < 0 or a < 0:
            return None
        b.add_edge(s, None, f1[0])
        b.add_edge(s, None, f2[0])
        b.add_edge(f1[1], None, a)
        b.add_edge(f2[1], None, a)
        return s, a
    if isinstance(ir, _IRStar):
        f = _build_fragment(ir.a, b)
        if f is None:
            return None
        s = b.new_state()
        a = b.new_state()
        if s < 0 or a < 0:
            return None
        b.add_edge(s, None, f[0])
        b.add_edge(s, None, a)
        b.add_edge(f[1], None, f[0])
        b.add_edge(f[1], None, a)
        return s, a
    return None


# -- NFA helpers (epsilon closure, step) -----------------------------


def _eps_closure(nfa: _NFA, states: frozenset[int]) -> frozenset[int]:
    result = set(states)
    stack = list(states)
    while stack:
        s = stack.pop()
        for label, target in nfa.edges[s]:
            if label is None and target not in result:
                result.add(target)
                stack.append(target)
    return frozenset(result)


def _step(nfa: _NFA, states: frozenset[int], rep: int) -> frozenset[int]:
    """States reachable from ``states`` by consuming the representative
    code point ``rep``. Caller is responsible for picking ``rep`` from
    an alphabet class (so the answer is the same for any rep in that
    class)."""
    out: set[int] = set()
    for s in states:
        for label, target in nfa.edges[s]:
            if label is not None and label.contains(rep):
                out.add(target)
    return frozenset(out)


# -- Alphabet partition ---------------------------------------------


def _alphabet_partition(*nfas: _NFA) -> tuple[_CharSet, ...] | None:
    """Compute a list of disjoint :class:`_CharSet`\\ s covering every
    char that any transition in any of ``nfas`` cares about, plus an
    "everything else" class iff at least one transition is negated.

    The partition has the property: for every transition CharSet ``T``
    and every class ``C`` in the partition, either ``C ⊆ T`` or
    ``C ∩ T = ∅``. So during DFA / product construction we can pick
    *any* representative from a class and the transition outcome is
    determined.

    Returns ``None`` if the partition exceeds
    :data:`MAX_ALPHABET_PARTITIONS`.
    """
    transition_sets: list[_CharSet] = []
    for nfa in nfas:
        for src_edges in nfa.edges:
            for label, _ in src_edges:
                if label is not None and not label.is_empty():
                    transition_sets.append(label)

    partition: list[_CharSet] = [_UNIVERSAL_CHARSET]
    for cs in transition_sets:
        new_partition: list[_CharSet] = []
        for p in partition:
            inter = p.intersection(cs)
            diff = p.difference(cs)
            if not inter.is_empty():
                new_partition.append(inter)
            if not diff.is_empty():
                new_partition.append(diff)
        partition = new_partition
        if len(partition) > MAX_ALPHABET_PARTITIONS:
            return None
    return tuple(partition)


# -- Time + product budget -------------------------------------------


@dataclass
class _Budget:
    """Per-algebra-call budget. ``deadline`` is monotonic seconds; the
    BFS loops poll every ``_TIME_CHECK_INTERVAL`` iterations."""

    deadline: float

    @classmethod
    def fresh(cls) -> _Budget:
        return cls(deadline=time.monotonic() + ALGEBRA_TIME_BUDGET_MS / 1000.0)

    def exceeded(self) -> bool:
        return time.monotonic() > self.deadline


# -- Intersection emptiness (on-the-fly product BFS) ----------------


def _intersect_empty_nfa(nfa_a: _NFA, nfa_b: _NFA, budget: _Budget) -> Trilean:
    partition = _alphabet_partition(nfa_a, nfa_b)
    if partition is None:
        return Trilean.UNKNOWN
    # Pick representatives once, up front — same reps used for every
    # state-pair's transition lookup.
    reps: list[int] = []
    for cls in partition:
        rep = cls.representative()
        if rep is None:
            continue
        reps.append(rep)

    start = (
        _eps_closure(nfa_a, frozenset({nfa_a.start})),
        _eps_closure(nfa_b, frozenset({nfa_b.start})),
    )
    seen: set[tuple[frozenset[int], frozenset[int]]] = {start}
    queue: deque[tuple[frozenset[int], frozenset[int]]] = deque([start])
    iterations = 0

    while queue:
        if iterations & (_TIME_CHECK_INTERVAL - 1) == 0 and budget.exceeded():
            return Trilean.UNKNOWN
        iterations += 1
        sa, sb = queue.popleft()
        if nfa_a.accept in sa and nfa_b.accept in sb:
            return Trilean.NO  # found a witness string accepted by both
        for rep in reps:
            next_sa = _eps_closure(nfa_a, _step(nfa_a, sa, rep))
            if not next_sa:
                continue
            next_sb = _eps_closure(nfa_b, _step(nfa_b, sb, rep))
            if not next_sb:
                continue
            np = (next_sa, next_sb)
            if np in seen:
                continue
            if len(seen) >= MAX_PRODUCT_STATES:
                return Trilean.UNKNOWN
            seen.add(np)
            queue.append(np)
    return Trilean.YES


# -- NFA → DFA (subset construction over a fixed partition) ---------


@dataclass
class _DFA:
    num_states: int
    start: int
    accepts: frozenset[int]
    # ``transitions[(state, alphabet_class_index)] = next_state``; missing
    # keys mean "no transition" (for incomplete DFAs).
    transitions: dict[tuple[int, int], int]
    partition: tuple[_CharSet, ...]


def _nfa_to_dfa(nfa: _NFA, partition: tuple[_CharSet, ...], budget: _Budget) -> _DFA | None:
    reps: list[tuple[int, int]] = []
    for i, cls in enumerate(partition):
        rep = cls.representative()
        if rep is None:
            continue
        reps.append((i, rep))

    start_subset = _eps_closure(nfa, frozenset({nfa.start}))
    states: dict[frozenset[int], int] = {start_subset: 0}
    accepts: set[int] = set()
    transitions: dict[tuple[int, int], int] = {}
    queue: deque[frozenset[int]] = deque([start_subset])
    iterations = 0

    while queue:
        if iterations & (_TIME_CHECK_INTERVAL - 1) == 0 and budget.exceeded():
            return None
        iterations += 1
        subset = queue.popleft()
        sid = states[subset]
        if nfa.accept in subset:
            accepts.add(sid)
        for class_idx, rep in reps:
            target = _eps_closure(nfa, _step(nfa, subset, rep))
            if not target:
                continue
            tid = states.get(target)
            if tid is None:
                if len(states) >= MAX_DFA_STATES:
                    return None
                tid = len(states)
                states[target] = tid
                queue.append(target)
            transitions[(sid, class_idx)] = tid

    return _DFA(
        num_states=len(states),
        start=0,
        accepts=frozenset(accepts),
        transitions=transitions,
        partition=partition,
    )


def _complete_and_complement_dfa(dfa: _DFA, budget: _Budget) -> _DFA | None:
    """Return a complete DFA whose accepting states are the original's
    *non*-accepting states. Adds a single sink state for missing
    transitions; the sink is always non-accepting in the original (so
    accepting in the complement).

    The transition-fill loop is ``O(num_states × num_classes)`` —
    up to ``MAX_DFA_STATES × MAX_ALPHABET_PARTITIONS`` ≈ 1M iterations
    in the worst case. Polls the wall-clock budget on the same
    ``_TIME_CHECK_INTERVAL`` cadence as the BFS loops; returns ``None``
    when the budget is exceeded so callers propagate ``UNKNOWN``.
    """
    if dfa.num_states + 1 > MAX_DFA_STATES:
        return None
    sink = dfa.num_states
    new_num_states = dfa.num_states + 1
    new_transitions = dict(dfa.transitions)
    num_classes = len(dfa.partition)
    iterations = 0
    for s in range(new_num_states):
        for i in range(num_classes):
            if iterations & (_TIME_CHECK_INTERVAL - 1) == 0 and budget.exceeded():
                return None
            iterations += 1
            new_transitions.setdefault((s, i), sink)
    new_accepts = frozenset(s for s in range(new_num_states) if s not in dfa.accepts)
    return _DFA(
        num_states=new_num_states,
        start=dfa.start,
        accepts=new_accepts,
        transitions=new_transitions,
        partition=dfa.partition,
    )


def _intersect_empty_dfa(dfa_a: _DFA, dfa_b: _DFA, budget: _Budget) -> Trilean:
    """Intersection emptiness over two DFAs that share an alphabet
    partition. Used by language-subset (where one side is the complement
    DFA, which only makes sense when fully constructed)."""
    assert dfa_a.partition == dfa_b.partition
    num_classes = len(dfa_a.partition)
    start = (dfa_a.start, dfa_b.start)
    seen: set[tuple[int, int]] = {start}
    queue: deque[tuple[int, int]] = deque([start])
    iterations = 0

    while queue:
        if iterations & (_TIME_CHECK_INTERVAL - 1) == 0 and budget.exceeded():
            return Trilean.UNKNOWN
        iterations += 1
        sa, sb = queue.popleft()
        if sa in dfa_a.accepts and sb in dfa_b.accepts:
            return Trilean.NO
        for i in range(num_classes):
            ta = dfa_a.transitions.get((sa, i))
            if ta is None:
                continue
            tb = dfa_b.transitions.get((sb, i))
            if tb is None:
                continue
            np = (ta, tb)
            if np in seen:
                continue
            if len(seen) >= MAX_PRODUCT_STATES:
                return Trilean.UNKNOWN
            seen.add(np)
            queue.append(np)
    return Trilean.YES


# -- Public algebra entry points ------------------------------------


def _ir_for(body: str, flags: str) -> _IR | None:
    return _ir_for_cached(body, flags)


@lru_cache(maxsize=4096)
def _ir_for_cached(body: str, flags: str) -> _IR | None:
    # IR lowering is purely structural — bounded by ``MAX_*`` caps but
    # has no wall-clock budget, so its result is path-independent and
    # always safe to cache (including ``None`` for unsupported bodies).
    return _lower_pattern_to_ir(body, flags)


# Definitive-only caches for the time-bounded algebra primitives below.
# ``_intersect_empty_nfa`` / ``_intersect_empty_dfa`` /
# ``_complete_and_complement_dfa`` may return ``Trilean.UNKNOWN`` due
# to a transient cap hit (cold caches under CI load, GC pauses,
# etc.) — caching that ``UNKNOWN`` would let a one-off slow run mask a
# definitive YES/NO for the rest of the process. We therefore cache
# only ``YES`` / ``NO`` results and recompute on ``UNKNOWN`` so a
# subsequent call gets a fresh budget and a fresh chance.
#
# Hand-rolled because ``functools.lru_cache`` has no "skip storing
# this result" hook. ``OrderedDict`` + ``move_to_end`` gives true LRU
# (cheaper than rebuilding the whole cache when a long-running process
# rotates through more than ``_DEFINITIVE_CACHE_MAX`` distinct keys);
# the lock makes get/put atomic so concurrent callers can't corrupt
# the eviction queue. CPython's ``lru_cache`` already gets thread
# safety from the GIL, but our hand-rolled `if-len; pop; assign`
# sequence has check-then-act races without an explicit lock.

_DEFINITIVE_DISJOINT_CACHE: OrderedDict[tuple[str, str, str, str], Trilean] = OrderedDict()
_DEFINITIVE_SUBSET_CACHE: OrderedDict[tuple[str, str, str, str], Trilean] = OrderedDict()
_DEFINITIVE_CACHE_LOCK = threading.Lock()
_DEFINITIVE_CACHE_MAX = 4096


def _definitive_get(
    cache: OrderedDict[tuple[str, str, str, str], Trilean],
    key: tuple[str, str, str, str],
) -> Trilean | None:
    with _DEFINITIVE_CACHE_LOCK:
        cached = cache.get(key)
        if cached is not None:
            # Mark as recently used. Cheap (O(1)) and pays off for the
            # workload where the same condition pair is checked across
            # many priors / disjuncts.
            cache.move_to_end(key)
        return cached


def _definitive_put(
    cache: OrderedDict[tuple[str, str, str, str], Trilean],
    key: tuple[str, str, str, str],
    value: Trilean,
) -> None:
    if value == Trilean.UNKNOWN:
        return
    with _DEFINITIVE_CACHE_LOCK:
        if key in cache:
            cache.move_to_end(key)
            return
        if len(cache) >= _DEFINITIVE_CACHE_MAX:
            # LRU eviction: drop the least-recently-used entry, which
            # ``OrderedDict`` keeps at the front.
            cache.popitem(last=False)
        cache[key] = value


def regex_languages_disjoint(body_a: str, flags_a: str, body_b: str, flags_b: str) -> Trilean:
    """Return :attr:`Trilean.YES` iff the languages of two Logstash
    ``=~`` patterns are *provably* disjoint (cannot match the same
    string), :attr:`Trilean.NO` if they're *provably* overlapping, or
    :attr:`Trilean.UNKNOWN` if any cap is hit or either body is outside
    the supported subset.

    This is the load-bearing primitive for regex-vs-regex contradiction
    detection. ``YES`` here authorizes the analyzer to declare two
    branches mutually exclusive; everything else preserves the existing
    "compatible" assumption.
    """
    # Canonicalize argument order so swapped calls (``A,B`` and ``B,A``)
    # share the same cache slot. The relation is symmetric, so the
    # answer is invariant under swap; halving cache pressure shows up
    # in workloads that pair regexes both ways (the literal-vs-regex
    # dispatch in ``_facts_contradict`` currently does this).
    if (body_a, flags_a) > (body_b, flags_b):
        body_a, flags_a, body_b, flags_b = body_b, flags_b, body_a, flags_a
    key = (body_a, flags_a, body_b, flags_b)
    cached = _definitive_get(_DEFINITIVE_DISJOINT_CACHE, key)
    if cached is not None:
        return cached
    result = _disjoint_compute(body_a, flags_a, body_b, flags_b)
    _definitive_put(_DEFINITIVE_DISJOINT_CACHE, key, result)
    return result


def _disjoint_compute(body_a: str, flags_a: str, body_b: str, flags_b: str) -> Trilean:
    ir_a = _ir_for(body_a, flags_a)
    if ir_a is None:
        return Trilean.UNKNOWN
    ir_b = _ir_for(body_b, flags_b)
    if ir_b is None:
        return Trilean.UNKNOWN
    nfa_a = _build_nfa(ir_a)
    if nfa_a is None:
        return Trilean.UNKNOWN
    nfa_b = _build_nfa(ir_b)
    if nfa_b is None:
        return Trilean.UNKNOWN
    return _intersect_empty_nfa(nfa_a, nfa_b, _Budget.fresh())


def language_subset(body_a: str, flags_a: str, body_b: str, flags_b: str) -> Trilean:
    """Return :attr:`Trilean.YES` iff every string accepted by ``A`` is
    also accepted by ``B``; :attr:`Trilean.NO` if there's a string in
    ``A \\ B``; :attr:`Trilean.UNKNOWN` otherwise.

    Used for ``[t] !~ /B/`` vs ``[t] =~ /A/`` contradiction
    detection: if ``L(A) ⊆ L(B)`` and ``B`` is forbidden, then ``A``
    cannot hold either.
    """
    key = (body_a, flags_a, body_b, flags_b)
    cached = _definitive_get(_DEFINITIVE_SUBSET_CACHE, key)
    if cached is not None:
        return cached
    result = _subset_compute(body_a, flags_a, body_b, flags_b)
    _definitive_put(_DEFINITIVE_SUBSET_CACHE, key, result)
    return result


def _subset_compute(body_a: str, flags_a: str, body_b: str, flags_b: str) -> Trilean:
    ir_a = _ir_for(body_a, flags_a)
    if ir_a is None:
        return Trilean.UNKNOWN
    ir_b = _ir_for(body_b, flags_b)
    if ir_b is None:
        return Trilean.UNKNOWN
    nfa_a = _build_nfa(ir_a)
    nfa_b = _build_nfa(ir_b)
    if nfa_a is None or nfa_b is None:
        return Trilean.UNKNOWN
    partition = _alphabet_partition(nfa_a, nfa_b)
    if partition is None:
        return Trilean.UNKNOWN
    budget = _Budget.fresh()
    dfa_a = _nfa_to_dfa(nfa_a, partition, budget)
    if dfa_a is None:
        return Trilean.UNKNOWN
    dfa_b = _nfa_to_dfa(nfa_b, partition, budget)
    if dfa_b is None:
        return Trilean.UNKNOWN
    complement_b = _complete_and_complement_dfa(dfa_b, budget)
    if complement_b is None:
        return Trilean.UNKNOWN
    return _intersect_empty_dfa(dfa_a, complement_b, budget)


def literal_in_regex_language(literal: str, body: str, flags: str) -> Trilean:
    """Return :attr:`Trilean.YES` iff ``literal`` is in the language of
    the regex; :attr:`Trilean.NO` if not; :attr:`Trilean.UNKNOWN` if the
    body is unsupported.

    Used for ``[t] == "x"`` vs ``[t] =~ /A/`` contradiction detection:
    if ``"x"`` is *not* in ``L(A)``, the conditions contradict.
    Implemented via algebra (singleton-language vs body) so it shares
    the same soundness model rather than going through Python's ``re``.
    """
    if len(literal.encode("utf-8")) > MAX_REGEX_BODY_BYTES:
        return Trilean.UNKNOWN
    # Build the singleton IR ``literal`` (anchored at both ends; no
    # implicit Σ* wrapping) and intersect against the regex body's IR.
    singleton_ir = _ir_for_literal_singleton(literal)
    body_ir = _ir_for(body, flags)
    if body_ir is None:
        return Trilean.UNKNOWN
    nfa_lit = _build_nfa(singleton_ir)
    nfa_body = _build_nfa(body_ir)
    if nfa_lit is None or nfa_body is None:
        return Trilean.UNKNOWN
    disjoint = _intersect_empty_nfa(nfa_lit, nfa_body, _Budget.fresh())
    if disjoint == Trilean.YES:
        return Trilean.NO
    if disjoint == Trilean.NO:
        return Trilean.YES
    return Trilean.UNKNOWN


def _ir_for_literal_singleton(literal: str) -> _IR:
    """IR for the language ``{literal}`` exactly — no anchoring magic."""
    parts: list[_IR] = [_IRChar(_CharSet(frozenset({ord(ch)}), False)) for ch in literal]
    return _ir_concat_many(parts) if parts else _IR_EMPTY
