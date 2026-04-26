#!/usr/bin/env python3
"""Auto-generate candidate sidecars for bug fixtures by parsing their headers.

Walks every ``tests/fixtures/test_corpus/bugs/*.cbn`` fixture, reads its
header comment, and tries to extract:

* **Warning codes mentioned in the header** — cross-referenced against the
  canonical list (the 35 codes the analyzer can actually emit).
* **UDM field paths mentioned in the header** — anything matching
  ``[\\w]+(?:\\.[\\w]+)+`` that doesn't look like a code identifier.
* **Plugin names mentioned in the header** — drawn from a fixed list of
  unsupported plugins commonly cited.

For each fixture, the script writes a ``<stem>.expected.json.candidate`` file
(NOT ``<stem>.expected.json``) so a human reviewer can accept / reject /
refine before promotion. To accept a candidate:

    mv <stem>.expected.json.candidate <stem>.expected.json

The candidate file also carries claims that the analyzer ACTUALLY emits — a
header may mention "drop" for a drop-related fixture, but the analyzer's
``drop`` warning may not actually fire on this fixture. The script intersects
header claims with observed analyzer signal so the candidate doesn't suggest
contracts the analyzer can't satisfy today.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from parser_lineage_analyzer import ReverseParser  # noqa: E402

BUGS_DIR = REPO_ROOT / "tests" / "fixtures" / "test_corpus" / "bugs"

# Cross-reference: every code the analyzer can actually emit. Sourced from a
# corpus-wide enumeration on 2026-04-25; bump when new codes are added.
CANONICAL_WARNING_CODES = frozenset(
    {
        "branch_lineage_fanout",
        "complex_xpath",
        "conditional_tag_check",
        "config_validation",
        "dissect_indirect",
        "drop",
        "drop_probabilistic",
        "duplicate_config_key",
        "dynamic_date_timezone",
        "dynamic_destination",
        "dynamic_loop_iterable",
        "dynamic_output_anchor",
        "grok_pattern_definitions",
        "gsub_backreference",
        "json_array_function",
        "json_target",
        "loop_variables",
        "malformed_config",
        "malformed_gsub",
        "missing_xpath_mappings",
        "mutate_ordering_drift",
        "parse_recovery",
        "regex_over_escape",
        "runtime_condition",
        "self_referential_merge",
        "statedump",
        "string_in_check",
        "syslog_pri_label_count_mismatch",
        "unknown_config_key",
        "unreachable_branch",
        "unresolved_bare_token",
        "unresolved_extractor_source",
        "unsupported_mutate_operation",
        "unsupported_plugin",
        "xml_namespaces",
    }
)

# Common unsupported-plugin names that show up in fixture headers.
COMMON_UNSUPPORTED_PLUGINS = (
    "ruby",
    "translate",
    "aggregate",
    "clone",
    "fingerprint",
    "geoip",
    "metricize",
    "elasticsearch",
    "useragent",
)

UDM_FIELD_RE = re.compile(r"\b((?:event\.idm\.read_only_udm\.)?[a-z][a-z_]*(?:\.[a-z][a-z_0-9]+)+)\b")

# Codes that are noisy when auto-suggested — leave them off the candidate
# unless the header explicitly cites them. e.g. ``drop`` fires anytime a
# drop{} appears, but most bug fixtures aren't about drop semantics.
NOISY_CODES = frozenset({"drop", "runtime_condition"})

# Skip the cheap smoke contract (already covered by test_corpus_baseline.py
# for non-bugs fixtures; for bugs/ it's the right minimum if no other claim
# survives).
SMOKE_CONTRACT = {
    "must_not_have_warning_codes": ["malformed_config", "parse_recovery"],
}


def _read_header(text: str) -> str:
    """Return the leading comment block (consecutive `# ...` lines)."""
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            out.append(stripped[1:].strip())
        elif stripped == "":
            continue
        else:
            break
    return "\n".join(out)


def _extract_warning_codes(header: str) -> list[str]:
    """Find canonical warning codes mentioned in the header."""
    found: list[str] = []
    seen: set[str] = set()
    for token in re.findall(r"[a-z][a-z_0-9]+", header.lower()):
        if token in CANONICAL_WARNING_CODES and token not in seen:
            seen.add(token)
            found.append(token)
    return found


def _extract_unsupported_plugins(header: str) -> list[str]:
    """Find unsupported plugin names mentioned in the header."""
    lower = header.lower()
    return [p for p in COMMON_UNSUPPORTED_PLUGINS if re.search(rf"\b{p}\b", lower)]


def _extract_udm_fields(header: str) -> list[str]:
    """Find dotted UDM-like field paths mentioned in the header."""
    found = []
    seen: set[str] = set()
    for m in UDM_FIELD_RE.finditer(header):
        path = m.group(1)
        # Drop matches whose first component looks like a warning code (e.g.
        # ``mutate_ordering_drift.foo``) — those are codes accidentally
        # joined to a word, not real UDM paths.
        if path.split(".")[0] in CANONICAL_WARNING_CODES:
            continue
        # Drop obvious code-like dotted strings
        if any(p in NOISY_CODES for p in path.split(".")):
            continue
        if path not in seen:
            seen.add(path)
            found.append(path)
    return found[:5]  # cap; long lists usually catch noise


def _intersect_with_analyzer(fixture_path: Path, claims: dict[str, list[str]]) -> dict[str, list[str]]:
    """Drop claims the analyzer doesn't actually satisfy on this fixture.

    Returns the refined claim dict. The caller is responsible for adding the
    smoke contract; if the analyzer emits ``malformed_config`` or
    ``parse_recovery`` on this fixture, we DON'T add them to
    ``must_not_have_warning_codes`` (the contract would be false on day one).
    """
    parser = ReverseParser(fixture_path.read_text(encoding="utf-8"))
    summary = parser.analysis_summary()
    actual_codes = {w.get("code") for w in summary.get("structured_warnings", [])}
    actual_unsupported_text = " | ".join(summary.get("unsupported", []))
    actual_udm_fields = set(parser.list_udm_fields())

    refined: dict[str, list[str]] = {}
    have_codes = [c for c in claims.get("must_have_warning_codes", []) if c in actual_codes]
    if have_codes:
        refined["must_have_warning_codes"] = have_codes
    have_unsupported = [p for p in claims.get("must_have_unsupported", []) if p in actual_unsupported_text]
    if have_unsupported:
        refined["must_have_unsupported"] = have_unsupported
    resolve_fields = []
    for f in claims.get("must_resolve_fields", []):
        # Field must resolve via parser.query() OR be in udm_fields.
        if any(actual.endswith(f) or f.endswith(actual) for actual in actual_udm_fields):
            resolve_fields.append(f)
        else:
            try:
                if parser.query(f).mappings:
                    resolve_fields.append(f)
            except Exception:
                pass
    if resolve_fields:
        refined["must_resolve_fields"] = resolve_fields[:3]
    return refined


def _build_candidate(fixture_path: Path) -> dict[str, list[str]]:
    text = fixture_path.read_text(encoding="utf-8")
    header = _read_header(text)
    raw = {
        "must_have_warning_codes": [c for c in _extract_warning_codes(header) if c not in NOISY_CODES],
        "must_have_unsupported": _extract_unsupported_plugins(header),
        "must_resolve_fields": _extract_udm_fields(header),
    }
    # Filter the smoke contract by what the fixture actually emits — a fixture
    # that intentionally exercises ``parse_recovery`` shouldn't have it in the
    # negative-list.
    parser = ReverseParser(text)
    parser.analyze()
    emitted = {w.get("code") for w in parser.analysis_summary().get("structured_warnings", [])}
    smoke_negatives = [c for c in ("malformed_config", "parse_recovery") if c not in emitted]

    refined = _intersect_with_analyzer(fixture_path, raw)
    if smoke_negatives:
        refined["must_not_have_warning_codes"] = smoke_negatives
    return refined or {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write directly to <stem>.expected.json instead of <stem>.expected.json.candidate",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="skip fixtures that already have a real <stem>.expected.json",
    )
    args = parser.parse_args(argv)

    written = 0
    skipped = 0
    for fixture in sorted(BUGS_DIR.glob("*.cbn")):
        sidecar = fixture.with_suffix(".expected.json")
        if args.skip_existing and sidecar.exists():
            skipped += 1
            continue
        candidate = _build_candidate(fixture)
        suffix = ".expected.json" if args.apply else ".expected.json.candidate"
        target = fixture.with_suffix(suffix)
        target.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        rel = target.relative_to(REPO_ROOT)
        print(f"wrote {rel}")
        written += 1
    mode = "applied" if args.apply else "candidates"
    print(f"\n{written} {mode} written; {skipped} skipped (already had sidecars).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
