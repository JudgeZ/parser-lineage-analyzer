"""Atheris coverage-guided fuzz harness for ReverseParser.analyze().

The parser front-end is documented to never raise — it captures all parse
errors as diagnostics. The analyzer pipeline that runs over the resulting
AST has no explicit "never-raises" contract in its docstring, but in
practice anything escaping ``analyze()`` other than the documented
size-limit ``ValueError`` from ``__init__`` indicates a bug: an unchecked
indexing, a missing dict key, a busted invariant, an attribute on a
``None`` somewhere in the symbolic execution.

We deliberately do *not* swallow exception types that would mask real
bugs (IndexError, KeyError, AttributeError, AssertionError, RecursionError,
TypeError, etc.) — those propagate and atheris records the input.

Run locally:

    mkdir -p fuzz/corpus_analyzer
    cp tests/fixtures/test_corpus/baseline/*.cbn fuzz/corpus_analyzer/
    PARSER_LINEAGE_ANALYZER_NO_EXT=1 python fuzz/fuzz_analyzer.py \
        -max_total_time=120 fuzz/corpus_analyzer

The corpus directory must be writable — libFuzzer mutates it. ``fuzz/corpus_*/``
is gitignored.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from parser_lineage_analyzer.analyzer import MAX_PARSER_BYTES, ReverseParser


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    # Pre-check the documented size limit instead of catching ValueError —
    # narrowing the swallow keeps any *other* ValueError raised by the
    # constructor visible as a finding.
    if len(text.encode("utf-8")) > MAX_PARSER_BYTES:
        return
    state = ReverseParser(text).analyze()
    assert state is not None


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
