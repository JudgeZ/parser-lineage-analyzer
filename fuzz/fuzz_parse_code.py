"""Atheris coverage-guided fuzz harness for parse_code_with_diagnostics.

The function is documented to capture every parse failure as a diagnostic
and return — it must never propagate an exception. Atheris mutates byte
inputs to maximise edge coverage, complementing Hypothesis (which samples).

Run locally (Linux, or macOS with `brew install llvm`):

    mkdir -p fuzz/corpus_parse_code
    cp tests/fixtures/test_corpus/baseline/*.cbn fuzz/corpus_parse_code/
    python fuzz/fuzz_parse_code.py -max_total_time=120 fuzz/corpus_parse_code

The corpus directory must be writable — libFuzzer adds new interesting
inputs to it as it runs. Pointing it at checked-in fixtures will mutate
them in place. ``fuzz/corpus_*/`` is gitignored.

Run in CI: see .github/workflows/fuzz.yml.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from parser_lineage_analyzer.model import SyntaxDiagnostic
    from parser_lineage_analyzer.parser import parse_code_with_diagnostics


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    statements, diagnostics = parse_code_with_diagnostics(text)
    assert isinstance(statements, list)
    assert isinstance(diagnostics, list)
    for diag in diagnostics:
        assert isinstance(diag, SyntaxDiagnostic)
        assert diag.line >= 1
        assert diag.column >= 1
        assert isinstance(diag.message, str) and diag.message


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
