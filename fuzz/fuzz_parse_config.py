"""Atheris coverage-guided fuzz harness for parse_config_with_diagnostics.

The plugin-config parser (key => value pairs, hashes, arrays) is documented
to capture every parse failure as a diagnostic — it must never propagate
an exception. Run locally:

    python fuzz/fuzz_parse_config.py -max_total_time=120

Or with a seed corpus directory as a positional argument.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from parser_lineage_analyzer.config_parser import parse_config_with_diagnostics
    from parser_lineage_analyzer.model import SyntaxDiagnostic


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    pairs, diagnostics = parse_config_with_diagnostics(text)
    assert isinstance(pairs, list)
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
