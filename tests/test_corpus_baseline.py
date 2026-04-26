"""Parametrized smoke + sidecar coverage for the test_corpus buckets.

The 324 fixtures under ``tests/fixtures/test_corpus/{baseline,expected,misc}/``
each describe a parser construct the analyzer is expected to handle.

Two contracts are enforced per fixture:

1. **Smoke contract (always)** — the analyzer must not crash and must not emit
   unexpected parse-recovery diagnostics. Per-fixture wall-clock budget keeps
   pathological regressions in other tests from silently turning a baseline
   fixture into a 60s hang.
2. **Sidecar contract (optional)** — if a sibling ``<name>.expected.json``
   file exists next to the fixture, its declared assertions are also checked.
   This lets us scale per-fixture assertions without writing a Python function
   per fixture; sidecars are easy to diff and easy to author.

Sidecar schema (all keys optional; missing keys mean "don't check"):

```json
{
  "must_have_warning_codes": ["dynamic_destination", "drop"],
  "must_resolve_fields":     ["target.ip", "principal.hostname"],
  "must_have_unsupported":   ["ruby"],
  "must_not_have_warning_codes": ["malformed_config"]
}
```

Bug-reproduction fixtures live under ``tests/fixtures/test_corpus/bugs/`` and
are exercised by ``tests/test_corpus_bugs.py``.

Stress fixtures live under ``tests/fixtures/test_corpus/challenge/`` and are
exercised by ``tests/test_corpus_challenge.py`` with a looser budget.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from parser_lineage_analyzer import ReverseParser
from tests._typing_helpers import expect_mapping, expect_mapping_list, expect_str, expect_str_list

CORPUS_ROOT = Path(__file__).parent / "fixtures" / "test_corpus"
SMOKE_BUCKETS = ("baseline", "expected", "misc")
PER_FIXTURE_BUDGET_SECONDS = 5.0
# Header phrases that legitimately advertise a malformed-input demo. Fixtures
# whose header includes one of these are exempt from the no-parse-recovery
# guard below, since the recovery diagnostic is exactly what they're showing.
RECOVERY_AWARE_PHRASES = (
    "parse recovery",
    "parse error",
    "parse_recovery",
    "malformed",
    "unparseable",
    "syntax error",
    "recovered parser",
)


def _smoke_fixture_paths() -> list[Path]:
    paths: list[Path] = []
    for bucket in SMOKE_BUCKETS:
        bdir = CORPUS_ROOT / bucket
        if not bdir.is_dir():
            continue
        paths.extend(sorted(bdir.iterdir()))
    return [p for p in paths if p.suffix == ".cbn"]


def _fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


_FIXTURES = _smoke_fixture_paths()


SIDECAR_KEYS = (
    "must_have_warning_codes",
    "must_not_have_warning_codes",
    "must_resolve_fields",
    "must_have_unsupported",
)


def _sidecar_for(fixture_path: Path) -> dict[str, list[str]] | None:
    sidecar = fixture_path.with_suffix(".expected.json")
    if not sidecar.exists():
        return None
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{sidecar} must be a JSON object")
    unknown = set(data) - set(SIDECAR_KEYS)
    if unknown:
        raise ValueError(f"{sidecar} has unknown keys: {sorted(unknown)}; valid keys: {SIDECAR_KEYS}")
    return data


def _check_sidecar(parser: ReverseParser, fixture_id: str, sidecar: dict[str, list[str]]) -> None:
    summary = parser.analysis_summary()
    warning_codes = {expect_str(expect_mapping(w)["code"]) for w in expect_mapping_list(summary["structured_warnings"])}
    unsupported_blobs = " | ".join(expect_str_list(summary["unsupported"]))

    for code in sidecar.get("must_have_warning_codes", []):
        assert code in warning_codes, (
            f"{fixture_id}: expected warning code {code!r} not emitted; got {sorted(warning_codes)}"
        )
    for code in sidecar.get("must_not_have_warning_codes", []):
        assert code not in warning_codes, f"{fixture_id}: warning code {code!r} should NOT be emitted but was"
    for field in sidecar.get("must_resolve_fields", []):
        result = parser.query(field)
        assert result.mappings, f"{fixture_id}: query({field!r}) returned no mappings"
    for plugin in sidecar.get("must_have_unsupported", []):
        assert plugin in unsupported_blobs, (
            f"{fixture_id}: expected {plugin!r} in unsupported list; got {summary['unsupported']!r}"
        )


@pytest.mark.parametrize("fixture_path", _FIXTURES, ids=[_fixture_id(p) for p in _FIXTURES])
def test_corpus_fixture_analyzes_cleanly(fixture_path: Path) -> None:
    src = fixture_path.read_text(encoding="utf-8")
    start = time.perf_counter()
    parser = ReverseParser(src)
    parser.analyze()
    elapsed = time.perf_counter() - start
    assert elapsed < PER_FIXTURE_BUDGET_SECONDS, (
        f"{_fixture_id(fixture_path)} took {elapsed:.2f}s, exceeds "
        f"{PER_FIXTURE_BUDGET_SECONDS}s per-fixture budget — investigate before relaxing."
    )
    header_blob = src[:512].lower()
    if not any(phrase in header_blob for phrase in RECOVERY_AWARE_PHRASES):
        recovery_diags = [
            d
            for d in parser.parse_diagnostics
            if any(token in d.message for token in ("Recovered", "Unexpected token", "'else if' cannot"))
        ]
        assert not recovery_diags, (
            f"{_fixture_id(fixture_path)} emitted unexpected parse-recovery diagnostics:\n"
            + "\n".join(f"  L{d.line}: {d.message[:160]}" for d in recovery_diags[:5])
            + "\nIf this is intentional, add a malformed-input phrase to the fixture header."
        )

    sidecar = _sidecar_for(fixture_path)
    if sidecar is not None:
        _check_sidecar(parser, _fixture_id(fixture_path), sidecar)


def test_sidecar_loader_rejects_unknown_keys(tmp_path: Path) -> None:
    """Sidecar files must use only the documented schema keys."""
    fixture = tmp_path / "demo.cbn"
    fixture.write_text('filter { mutate { replace => { "x" => "y" } } }', encoding="utf-8")
    sidecar = fixture.with_suffix(".expected.json")
    sidecar.write_text(json.dumps({"made_up_key": ["foo"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown keys"):
        _sidecar_for(fixture)


def test_sidecar_loader_returns_none_for_missing_sidecar(tmp_path: Path) -> None:
    fixture = tmp_path / "demo.cbn"
    fixture.write_text("filter {}", encoding="utf-8")
    assert _sidecar_for(fixture) is None


def test_corpus_buckets_have_expected_size() -> None:
    """Sanity check: a major drift in the corpus size should be a deliberate edit, not silent.

    Counts only `.cbn` fixture files — sibling sidecar `<name>.expected.json`
    files (Phase C) shouldn't inflate the count.
    """
    counts = {
        bucket: len([p for p in (CORPUS_ROOT / bucket).iterdir() if p.suffix == ".cbn"]) for bucket in SMOKE_BUCKETS
    }
    # Expected approximate sizes after the initial corpus adoption (2026-04-25).
    # If any bucket deviates by more than 10% the change should be reflected here
    # alongside the underlying diff.
    expected = {"baseline": 132, "expected": 201, "misc": 3}
    for bucket, want in expected.items():
        got = counts[bucket]
        assert abs(got - want) <= max(2, want // 10), (
            f"corpus bucket {bucket!r} drifted: expected ~{want}, got {got}. "
            f"Update tests/test_corpus_baseline.py:expected to reflect the intended size."
        )
