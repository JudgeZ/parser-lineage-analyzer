"""Parametrized stress coverage for the test_corpus challenge bucket.

Each fixture under ``tests/fixtures/test_corpus/challenge/`` is intentionally
pathological: deeply nested conditionals, very long if/else-if chains, large
inline arrays, dynamic interpolation that produces dense fan-out. The goal
here is *not* to lock down specific lineage — those would be too fragile
across legitimate analyzer improvements. The contracts this file enforces:

1. The analyzer terminates within a per-fixture wall-clock budget (60s, more
   forgiving than the 5s baseline budget because these inputs are designed to
   blow up).
2. The analyzer does not crash with an unhandled exception — it must reach
   ``analyze()`` completion and produce *some* result, even if the result is
   heavily summarized / dynamic.
3. **Sidecar contract** (L3): if a sibling ``<name>.expected.json`` file
   exists, its declared assertions are checked too. Most challenge sidecars
   carry only the smoke-level "must_not_have_warning_codes: [malformed_config,
   parse_recovery]" contract; richer claims (must_have_unsupported,
   must_resolve_fields) appear on fixtures whose ``EXPECTED BEHAVIOR:`` block
   names specific plugins or fields.

Bug-reproduction fixtures live under ``tests/fixtures/test_corpus/bugs/`` and
are exercised by ``tests/test_corpus_bugs.py``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from parser_lineage_analyzer import ReverseParser
from tests._typing_helpers import expect_mapping, expect_mapping_list, expect_str, expect_str_list

CORPUS_ROOT = Path(__file__).parent / "fixtures" / "test_corpus"
CHALLENGE_DIR = CORPUS_ROOT / "challenge"
PER_FIXTURE_BUDGET_SECONDS = 60.0
SIDECAR_KEYS = (
    "must_have_warning_codes",
    "must_not_have_warning_codes",
    "must_resolve_fields",
    "must_have_unsupported",
)


def _challenge_fixture_paths() -> list[Path]:
    if not CHALLENGE_DIR.is_dir():
        return []
    return sorted(p for p in CHALLENGE_DIR.iterdir() if p.suffix == ".cbn")


_FIXTURES = _challenge_fixture_paths()


def _check_sidecar(parser: ReverseParser, fixture_id: str, sidecar: dict[str, object]) -> None:
    summary = parser.analysis_summary()
    warning_codes = {expect_str(expect_mapping(w)["code"]) for w in expect_mapping_list(summary["structured_warnings"])}
    unsupported_blob = " | ".join(expect_str_list(summary["unsupported"]))

    for code in expect_str_list(sidecar.get("must_have_warning_codes", [])):
        assert code in warning_codes, f"{fixture_id}: expected warning code {code!r}; got {sorted(warning_codes)}"
    for code in expect_str_list(sidecar.get("must_not_have_warning_codes", [])):
        assert code not in warning_codes, f"{fixture_id}: warning code {code!r} should NOT be emitted but was"
    for field in expect_str_list(sidecar.get("must_resolve_fields", [])):
        result = parser.query(field)
        assert any(mapping.status not in {"removed", "unresolved"} for mapping in result.mappings), (
            f"{fixture_id}: query({field!r}) returned no live mappings"
        )
    for plugin in expect_str_list(sidecar.get("must_have_unsupported", [])):
        assert plugin in unsupported_blob, (
            f"{fixture_id}: expected {plugin!r} in unsupported list; got {summary['unsupported']!r}"
        )


@pytest.mark.parametrize("fixture_path", _FIXTURES, ids=[p.name for p in _FIXTURES])
def test_challenge_fixture_completes_within_budget(fixture_path: Path) -> None:
    src = fixture_path.read_text(encoding="utf-8")
    start = time.perf_counter()
    parser = ReverseParser(src)
    parser.analyze()
    elapsed = time.perf_counter() - start
    assert elapsed < PER_FIXTURE_BUDGET_SECONDS, (
        f"{fixture_path.name} took {elapsed:.2f}s, exceeds {PER_FIXTURE_BUDGET_SECONDS}s budget"
    )

    sidecar_path = fixture_path.with_suffix(".expected.json")
    if sidecar_path.exists():
        sidecar_data = json.loads(sidecar_path.read_text(encoding="utf-8"))
        if not isinstance(sidecar_data, dict):
            raise ValueError(f"{sidecar_path.name}: sidecar must be a JSON object")
        sidecar: dict[str, object] = dict(sidecar_data)
        unknown = set(sidecar) - set(SIDECAR_KEYS)
        assert not unknown, f"{sidecar_path.name}: unknown sidecar keys {sorted(unknown)}"
        _check_sidecar(parser, fixture_path.name, sidecar)


def test_challenge_sidecar_rejects_string_values_for_string_list_fields() -> None:
    parser = ReverseParser("filter {}")

    with pytest.raises(AssertionError, match="expected list"):
        _check_sidecar(parser, "demo.cbn", {"must_not_have_warning_codes": "parse_recovery"})


def test_challenge_sidecar_removed_field_is_not_live_resolution() -> None:
    parser = ReverseParser(
        """
        filter {
          mutate {
            replace => { "gone" => "yes" }
            remove_field => ["gone"]
          }
        }
        """
    )

    with pytest.raises(AssertionError, match="no live mappings"):
        _check_sidecar(parser, "demo.cbn", {"must_resolve_fields": ["gone"]})


def test_challenge_bucket_size() -> None:
    expected = 225
    got = len(_FIXTURES)
    assert abs(got - expected) <= max(2, expected // 10), f"challenge bucket drifted: expected ~{expected}, got {got}"
