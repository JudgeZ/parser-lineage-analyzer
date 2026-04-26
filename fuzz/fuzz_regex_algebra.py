"""Atheris coverage-guided fuzz harness for the symbolic regex algebra.

The algebra ingests untrusted SecOps customer regex bodies. Its
documented contract is:

* ``regex_languages_disjoint`` and ``language_subset`` *never* raise
  and *always* return a :class:`Trilean`.
* The same applies to ``literal_in_regex_language``.
* All three respect ``ALGEBRA_TIME_BUDGET_MS`` modulo a small constant
  for cold-cache misses; this harness asserts a generous 5x bound, so
  a true hang surfaces but a slow-CI hiccup does not.

Run locally::

    mkdir -p fuzz/corpus_regex_algebra
    PARSER_LINEAGE_ANALYZER_NO_EXT=1 python fuzz/fuzz_regex_algebra.py \\
        -max_total_time=120 fuzz/corpus_regex_algebra

The corpus directory must be writable — libFuzzer mutates it.
``fuzz/corpus_*/`` is gitignored.
"""

from __future__ import annotations

import sys
import time

import atheris

with atheris.instrument_imports():
    from parser_lineage_analyzer._regex_algebra import (
        ALGEBRA_TIME_BUDGET_MS,
        MAX_REGEX_BODY_BYTES,
        Trilean,
        language_subset,
        literal_in_regex_language,
        regex_languages_disjoint,
    )


# A 5x multiplier on the wall-clock budget gives enough headroom for
# cold-cache lookups, GC pauses, and slow CI runners while still
# catching genuine hangs. Each algebra call is bounded by
# ALGEBRA_TIME_BUDGET_MS internally; this is the outer "did the bound
# actually hold?" check.
_HANG_THRESHOLD_S = (ALGEBRA_TIME_BUDGET_MS * 5) / 1000.0


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    fdp = atheris.FuzzDataProvider(data)
    # Split the input into two regex bodies and a literal; cap each at
    # the body-size limit so we don't waste cycles on inputs the
    # extractor would reject up front.
    body_a = fdp.ConsumeUnicodeNoSurrogates(MAX_REGEX_BODY_BYTES)
    body_b = fdp.ConsumeUnicodeNoSurrogates(MAX_REGEX_BODY_BYTES)
    literal = fdp.ConsumeUnicodeNoSurrogates(MAX_REGEX_BODY_BYTES)
    # Flags drawn from the small set the algebra knows about plus
    # garbage; the algebra must reject the garbage by returning UNKNOWN.
    flags_a = fdp.ConsumeUnicodeNoSurrogates(4)
    flags_b = fdp.ConsumeUnicodeNoSurrogates(4)

    # 1. Disjoint must terminate, return a Trilean, and respect the
    #    wall-clock budget.
    start = time.monotonic()
    result = regex_languages_disjoint(body_a, flags_a, body_b, flags_b)
    elapsed = time.monotonic() - start
    assert isinstance(result, Trilean)
    assert elapsed < _HANG_THRESHOLD_S, (
        f"regex_languages_disjoint took {elapsed * 1000:.1f}ms (budget*5 is "
        f"{_HANG_THRESHOLD_S * 1000:.1f}ms) for bodies {body_a!r} / {body_b!r}"
    )

    # 2. Symmetry: result must be the same when arguments are swapped.
    swapped = regex_languages_disjoint(body_b, flags_b, body_a, flags_a)
    assert swapped == result, f"asymmetric disjoint result: {result} vs {swapped} for {body_a!r} / {body_b!r}"

    # 3. language_subset must also terminate and return a Trilean.
    start = time.monotonic()
    sub = language_subset(body_a, flags_a, body_b, flags_b)
    elapsed = time.monotonic() - start
    assert isinstance(sub, Trilean)
    assert elapsed < _HANG_THRESHOLD_S, f"language_subset took {elapsed * 1000:.1f}ms for {body_a!r} / {body_b!r}"

    # 4. literal_in_regex_language must terminate and return a Trilean.
    start = time.monotonic()
    lit_result = literal_in_regex_language(literal, body_a, flags_a)
    elapsed = time.monotonic() - start
    assert isinstance(lit_result, Trilean)
    assert elapsed < _HANG_THRESHOLD_S, (
        f"literal_in_regex_language took {elapsed * 1000:.1f}ms for literal={literal!r} body={body_a!r}"
    )

    # 5. Self-reflexivity for the subset relation. ``A ⊆ A`` is always
    #    true (or UNKNOWN if we hit a cap building the DFA). Any NO
    #    here would be a soundness violation.
    self_sub = language_subset(body_a, flags_a, body_a, flags_a)
    assert self_sub != Trilean.NO, f"language_subset({body_a!r}, {body_a!r}) returned NO — soundness violation"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
