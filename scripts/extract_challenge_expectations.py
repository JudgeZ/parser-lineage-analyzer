#!/usr/bin/env python3
"""Extract specific assertion candidates from challenge fixture
``# EXPECTED BEHAVIOR:`` blocks and merge them into the existing universal
smoke sidecar.

Most challenge fixtures already carry a smoke sidecar from
``backfill_weak_sidecars.py --bucket=challenge`` (just
``must_not_have_warning_codes``). When the fixture's header contains an
``EXPECTED BEHAVIOR:`` block naming specific plugins or warning-code-like
phrases, this script intersects those mentions with what the analyzer
actually emits and writes the merged sidecar back.

Default mode: dry run (prints candidates only). Use ``--apply`` to write the
merged sidecars in place.
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

CHALLENGE_DIR = REPO_ROOT / "tests" / "fixtures" / "test_corpus" / "challenge"

# Same canonical list used by parse_bug_fixture_headers.py.
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

COMMON_UNSUPPORTED_PLUGINS = (
    "ruby",
    "translate",
    "aggregate",
    "clone",
    "fingerprint",
    "geoip",
    "metricize",
    "useragent",
    "kafka",
    "elasticsearch",
)

# Header phrase → warning-code mappings. Drawn from corpus exploration. Each
# pair is checked case-insensitively against the EXPECTED BEHAVIOR block.
PHRASE_TO_CODE = (
    ("dynamic destination", "dynamic_destination"),
    ("dynamic field", "dynamic_destination"),
    ("dynamic output anchor", "dynamic_output_anchor"),
    ("dynamic loop iterable", "dynamic_loop_iterable"),
    ("dynamic date timezone", "dynamic_date_timezone"),
    ("statedump", "statedump"),
    ("dissect indirect", "dissect_indirect"),
    ("complex xpath", "complex_xpath"),
    ("xml namespace", "xml_namespaces"),
    ("malformed gsub", "malformed_gsub"),
    ("gsub backreference", "gsub_backreference"),
    ("loop variables", "loop_variables"),
    ("json target", "json_target"),
    ("array_function", "json_array_function"),
    ("drop probabilistic", "drop_probabilistic"),
    ("unsupported mutate", "unsupported_mutate_operation"),
    ("unsupported plugin", "unsupported_plugin"),
    ("ordering drift", "mutate_ordering_drift"),
    ("regex over-escape", "regex_over_escape"),
    ("self-referential merge", "self_referential_merge"),
    ("self referential merge", "self_referential_merge"),
    ("string in check", "string_in_check"),
    ("conditional tag", "conditional_tag_check"),
    ("syslog pri label", "syslog_pri_label_count_mismatch"),
    ("branch fanout", "branch_lineage_fanout"),
    ("unresolved extractor", "unresolved_extractor_source"),
    ("unreachable branch", "unreachable_branch"),
)

EXPECTED_BLOCK_RE = re.compile(
    r"^\s*#\s*EXPECTED BEHAVIOR:?\s*\n((?:\s*#.*\n)+)",
    re.MULTILINE | re.IGNORECASE,
)


def _expected_block(text: str) -> str:
    m = EXPECTED_BLOCK_RE.search(text)
    if not m:
        # Fallback: take leading comment block.
        lines = []
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                lines.append(line)
            elif line.strip() == "":
                continue
            else:
                break
        return "\n".join(lines)
    return m.group(1)


def _candidate_codes_from_block(block: str) -> set[str]:
    out: set[str] = set()
    lower = block.lower()
    # Direct mention of canonical code identifiers.
    for token in re.findall(r"[a-z][a-z_0-9]+", lower):
        if token in CANONICAL_WARNING_CODES:
            out.add(token)
    # Phrase mappings.
    for phrase, code in PHRASE_TO_CODE:
        if phrase in lower:
            out.add(code)
    return out


def _candidate_unsupported_from_block(block: str) -> set[str]:
    lower = block.lower()
    return {p for p in COMMON_UNSUPPORTED_PLUGINS if re.search(rf"\b{p}\b", lower)}


def _refine_via_analyzer(
    fixture_path: Path,
    code_candidates: set[str],
    unsupported_candidates: set[str],
) -> dict[str, list[str]]:
    parser = ReverseParser(fixture_path.read_text(encoding="utf-8"))
    summary = parser.analysis_summary()
    actual_codes = {w.get("code") for w in summary.get("structured_warnings", [])}
    actual_unsupported_text = " | ".join(summary.get("unsupported", []))
    refined: dict[str, list[str]] = {}
    have_codes = sorted(c for c in code_candidates if c in actual_codes)
    if have_codes:
        refined["must_have_warning_codes"] = have_codes
    have_unsupported = sorted(p for p in unsupported_candidates if p in actual_unsupported_text)
    if have_unsupported:
        refined["must_have_unsupported"] = have_unsupported
    return refined


def _merge_with_existing(existing: dict[str, list[str]], extras: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = dict(existing)
    for key, values in extras.items():
        prior = list(merged.get(key, []))
        for v in values:
            if v not in prior:
                prior.append(v)
        merged[key] = prior
    return merged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write merged sidecars in place")
    args = parser.parse_args(argv)

    enriched = 0
    untouched = 0
    for fixture in sorted(CHALLENGE_DIR.glob("*.cbn")):
        text = fixture.read_text(encoding="utf-8")
        block = _expected_block(text)
        code_candidates = _candidate_codes_from_block(block)
        unsupported_candidates = _candidate_unsupported_from_block(block)
        if not code_candidates and not unsupported_candidates:
            untouched += 1
            continue
        extras = _refine_via_analyzer(fixture, code_candidates, unsupported_candidates)
        if not extras:
            untouched += 1
            continue
        sidecar = fixture.with_suffix(".expected.json")
        existing = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else {}
        merged = _merge_with_existing(existing, extras)
        if merged == existing:
            untouched += 1
            continue
        rel = fixture.relative_to(REPO_ROOT)
        if args.apply:
            sidecar.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
            print(f"enriched {rel} -> {extras}")
        else:
            print(f"[dry-run] {rel}: would add {extras}")
        enriched += 1
    print(f"\n{enriched} fixtures enriched; {untouched} unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
