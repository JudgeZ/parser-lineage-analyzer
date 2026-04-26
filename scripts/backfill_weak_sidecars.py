#!/usr/bin/env python3
"""Backfill ``<fixture>.expected.json`` sidecars with the weakest useful contract.

Walks every ``tests/fixtures/test_corpus/<bucket>/*.cbn`` fixture that does
NOT already have a sibling sidecar, runs the analyzer, and writes a uniform
``{"must_not_have_warning_codes": ["malformed_config", "parse_recovery"]}``
sidecar for any fixture that the analyzer parses cleanly (no
``malformed_config`` / ``parse_recovery`` warning codes and no parse
diagnostics).

Fixtures that DO produce one of those codes are intentionally broken — those
codes are dropped from the sidecar's negative-list so the contract remains
satisfiable. (For baseline/expected/misc, the recovery-aware-phrase guard
in ``tests/test_corpus_baseline.py`` was the original hand-made check; this
script complements it with a programmatic, per-fixture sidecar.)

Default scope: baseline + expected + misc. Pass ``--bucket=challenge`` (or
``--bucket=all``) to expand to the challenge bucket too. Bug fixtures are
handled by ``scripts/parse_bug_fixture_headers.py`` — don't double-backfill.

Usage:
    python scripts/backfill_weak_sidecars.py [--dry-run]
    python scripts/backfill_weak_sidecars.py --bucket=challenge
    python scripts/backfill_weak_sidecars.py --bucket=all
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from parser_lineage_analyzer import ReverseParser  # noqa: E402

CORPUS_ROOT = REPO_ROOT / "tests" / "fixtures" / "test_corpus"
SMOKE_BUCKETS = ("baseline", "expected", "misc")
ALL_NON_BUG_BUCKETS = ("baseline", "expected", "misc", "challenge")
SKIP_CODES = frozenset({"malformed_config", "parse_recovery"})


def _analyzer_signal(fixture_path: Path) -> tuple[bool, set[str], int, str]:
    """Return (loaded_ok, emitted_warning_codes, parse_diag_count, error_repr)."""
    src = fixture_path.read_text(encoding="utf-8")
    try:
        parser = ReverseParser(src)
        parser.analyze()
    except Exception as exc:  # noqa: BLE001
        return False, set(), 0, repr(exc)
    summary = parser.analysis_summary()
    emitted = {w.get("code") for w in summary.get("structured_warnings", [])}
    return True, emitted, len(parser.parse_diagnostics), ""


def _build_payload(emitted: set[str]) -> dict[str, list[str]] | None:
    """Build the smoke-contract payload, filtered by what the analyzer emits.

    If both ``malformed_config`` and ``parse_recovery`` are emitted, returns
    ``None`` — the fixture is so noisy that the smoke contract has nothing
    useful to add.
    """
    negatives = [c for c in ("malformed_config", "parse_recovery") if c not in emitted]
    if not negatives:
        return None
    return {"must_not_have_warning_codes": negatives}


def _write_sidecar(fixture_path: Path, payload: dict[str, list[str]], dry_run: bool) -> None:
    sidecar = fixture_path.with_suffix(".expected.json")
    rendered = json.dumps(payload, indent=2) + "\n"
    if dry_run:
        print(f"[dry-run] would write {sidecar.relative_to(REPO_ROOT)}")
        return
    sidecar.write_text(rendered, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="preview without writing")
    parser.add_argument(
        "--bucket",
        choices=("smoke", "challenge", "all"),
        default="smoke",
        help=(
            "Which buckets to scan. 'smoke' = baseline+expected+misc (default); "
            "'challenge' = challenge only; 'all' = both. Bug fixtures use a "
            "different script (parse_bug_fixture_headers.py)."
        ),
    )
    args = parser.parse_args(argv)
    if args.bucket == "smoke":
        buckets = SMOKE_BUCKETS
    elif args.bucket == "challenge":
        buckets = ("challenge",)
    else:
        buckets = ALL_NON_BUG_BUCKETS

    written = 0
    skipped: list[tuple[Path, str]] = []
    already: list[Path] = []
    for bucket in buckets:
        bdir = CORPUS_ROOT / bucket
        if not bdir.is_dir():
            continue
        for fixture in sorted(bdir.iterdir()):
            if fixture.suffix != ".cbn":
                continue
            sidecar = fixture.with_suffix(".expected.json")
            if sidecar.exists():
                already.append(fixture)
                continue
            loaded, emitted, parse_diags, err = _analyzer_signal(fixture)
            if not loaded:
                skipped.append((fixture, f"crash: {err}"))
                continue
            payload = _build_payload(emitted)
            if payload is None:
                skipped.append((fixture, f"emits both {sorted(SKIP_CODES)}"))
                continue
            _write_sidecar(fixture, payload, args.dry_run)
            written += 1

    print(f"Already had sidecars: {len(already)}")
    print(f"Wrote sidecars:       {written}")
    print(f"Skipped:              {len(skipped)}")
    for path, reason in skipped[:10]:
        print(f"  - {path.relative_to(REPO_ROOT)}: {reason}")
    if len(skipped) > 10:
        print(f"  ... and {len(skipped) - 10} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
