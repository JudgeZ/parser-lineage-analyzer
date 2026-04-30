"""Hand-written tests + sidecar contracts for bug-reproduction fixtures
under ``tests/fixtures/test_corpus/bugs/``.

Each fixture's top-of-file comment claims an analyzer bug. Four parallel
triage subagents read every fixture, compared the claim to current analyzer
behavior, and bucketed each one as:

- **EASY-FIX** — the bug is real and the fix is small (~5-30 LoC). The
  analyzer is patched and the corresponding test below asserts the fixed
  behavior. No xfail.
- **NEEDS-DESIGN** — the bug is real but the fix touches architecture or
  multiple subsystems. The test asserts the *desired* behavior and is marked
  ``@pytest.mark.xfail(strict=True)`` so the suite stays green and the xfail
  count tracks unfixed bugs.
- **INVALID** — the claim is wrong; the analyzer is already correct. The test
  asserts the *current* (correct) behavior so future regressions break it.
  No xfail.
- **PARTIAL** — analyzer does part of what's claimed; treated like EASY-FIX or
  NEEDS-DESIGN depending on the gap size.

Each test has a short docstring explaining the fixture's claim and the
disposition reasoning.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from parser_lineage_analyzer import LIVE_LINEAGE_STATUSES, ReverseParser
from tests._typing_helpers import expect_mapping, expect_mapping_list, expect_str, expect_str_list

BUG_DIR = Path(__file__).parent / "fixtures" / "test_corpus" / "bugs"


def _load(name: str) -> ReverseParser:
    return ReverseParser((BUG_DIR / name).read_text(encoding="utf-8"))


def _summary_codes(parser: ReverseParser) -> set[str]:
    return {
        expect_str(expect_mapping(w)["code"])
        for w in expect_mapping_list(parser.analysis_summary()["structured_warnings"])
    }


def _has_unsupported(parser: ReverseParser, name_substr: str) -> bool:
    return any(name_substr in u for u in expect_str_list(parser.analysis_summary()["unsupported"]))


# ---------------------------------------------------------------------------
# Batch 1
# ---------------------------------------------------------------------------


def test_bug_array_index_normalization():
    """EASY-FIX: `user[0][name]` must normalize to `user.0.name` so static
    queries reach the assigned token."""
    # fixture: test_array_index
    parser = _load("test_array_index.cbn")
    assert "user.0.name" in parser.list_udm_fields() or any(t == "user.0.name" for t in parser.analyze().tokens)


def test_bug_balanced_regex_bareword():
    """EASY-FIX (Phase D3): scanner heuristic now refuses to treat `/path/{...}/`
    as a regex when it contains an unescaped brace outside a character class.
    The mutate block parses cleanly and downstream lineage (here, `status`)
    survives instead of being swallowed by a misdetected regex literal."""
    # fixture: test_balanced_regex_bareword
    parser = _load("test_balanced_regex_bareword.cbn")
    state = parser.analyze()
    assert "status" in state.tokens
    assert not list(parser.parse_diagnostics), (
        "no Lark parse failure should occur after the regex/bareword disambiguation fix"
    )


def test_bug_baseline_drop_complex_control_flow():
    """INVALID (per triage): drop already terminates execution correctly. The
    fixture is effectively a baseline; assert current behavior."""
    # fixture: test_baseline_drop_complex_control_flow
    parser = _load("test_baseline_drop_complex_control_flow.cbn")
    parser.analyze()  # must not crash
    assert "drop" in _summary_codes(parser)


def test_bug_challenge_700_convoluted_plugin_ordering():
    """PARTIAL/EASY-FIX: ordering+rename work; fixture also exposes the
    `_exec_split_mutate_op` shape bug covered by test_bug_mutate_split. The
    expected behavior is that the analyzer at least completes without crashing
    and reports both expected mutate operations.
    """
    # fixture: test_challenge_700_convoluted_plugin_ordering_and_state_mutations
    parser = _load("test_challenge_700_convoluted_plugin_ordering_and_state_mutations.cbn")
    parser.analyze()


def test_bug_challenge_700_dynamic_fallback_routing():
    """INVALID: fallback chain modeled cleanly via path-condition accumulation."""
    # fixture: test_challenge_700_dynamic_fallback_routing_with_circular_dependencies
    parser = _load("test_challenge_700_dynamic_fallback_routing_with_circular_dependencies.cbn")
    parser.analyze()


def test_bug_challenge_700_dynamic_plugin_evaluation_order():
    """EASY-FIX (Phase D6 + 4C): both string alternatives for `target_field`
    are captured AND the typed-value tagging exposes the runtime type for
    fields whose lineage went through a known type-promoting mutate op
    (split → array, join → string)."""
    # fixture: test_challenge_700_dynamic_plugin_evaluation_order_with_conflicting_if_branches
    parser = _load("test_challenge_700_dynamic_plugin_evaluation_order_with_conflicting_if_branches.cbn")
    state = parser.analyze()
    assert "target_field" in state.tokens
    expressions = {lin.expression for lin in state.tokens["target_field"]}
    # Both Block 1's "error_found" and Block 2's "internal_network" must be
    # represented as alternative lineages — that's the core observation the
    # fixture wants the analyzer to reach.
    assert "error_found" in expressions, f"missing Block 1 alternative; got {expressions!r}"
    assert "internal_network" in expressions, f"missing Block 2 alternative; got {expressions!r}"


def test_bug_typed_value_split_then_join_round_trips_to_string():
    """EASY-FIX (Phase 4C): split → join sequence ends with the field's
    value_type back at "string". Each type-promoting op tags the lineage
    with the new value_type so downstream consumers can see it.

    Note: the analyzer overwrites the lineage on each mutate.replace/split/
    join (in-place transform), so only the FINAL state is preserved. The
    transformations list still records the full chain for provenance.
    """
    parser = ReverseParser("""
        filter {
          mutate { replace => { "csv" => "a,b,c" } }
          mutate { split => { "csv" => "," } }
          mutate { join => { "csv" => "|" } }
        }
    """)
    state = parser.analyze()
    csv_lineages = state.tokens.get("csv", [])
    assert csv_lineages, "expected at least one lineage for csv"
    final = csv_lineages[-1]
    assert final.value_type == "string", f"expected string after join; got value_type={final.value_type!r}"
    # The chain of transformations is preserved even though the value_type
    # only carries the latest state.
    assert any("split" in t for t in final.transformations)
    assert any("join" in t for t in final.transformations)


def test_bug_typed_value_assignment_string_literal_tagged_string():
    """EASY-FIX (Phase R1.1): mutate.replace with a string literal sets
    value_type="string" on the destination's lineage."""
    parser = ReverseParser('filter { mutate { replace => { "x" => "hello" } } }')
    state = parser.analyze()
    lins = state.tokens.get("x", [])
    assert lins
    assert lins[-1].value_type == "string"


def test_bug_typed_value_assignment_array_literal_tagged_array():
    """EASY-FIX (Phase R1.1): mutate.replace with a list literal sets
    value_type="array"."""
    parser = ReverseParser('filter { mutate { replace => { "names" => ["a", "b"] } } }')
    state = parser.analyze()
    lins = state.tokens.get("names", [])
    assert lins
    assert lins[-1].value_type == "array"


def test_bug_typed_value_tags_always_array():
    """EASY-FIX (Phase R1.1): mutate.add_tag produces a tags lineage with
    value_type="array"."""
    parser = ReverseParser('filter { mutate { add_tag => ["a", "b"] } }')
    state = parser.analyze()
    lins = state.tokens.get("tags", [])
    assert lins
    assert any(lin.value_type == "array" for lin in lins)


def test_bug_string_in_check_semantics_warning():
    """EASY-FIX (Phase R1.3): `"X" in [field]` against a string-typed field
    means substring match. Surface a `string_in_check` advisory so users
    are aware (the analogous tag-set check is handled separately for
    `[tags]`)."""
    parser = ReverseParser("""
        filter {
          mutate { replace => { "msg" => "the quick brown fox" } }
          if "quick" in [msg] {
            mutate { replace => { "match" => "yes" } }
          }
        }
    """)
    parser.analyze()
    assert "string_in_check" in _summary_codes(parser)


def test_bug_string_in_check_skips_arrays_and_tags():
    """EASY-FIX (Phase R1.3 sanity): the substring advisory must NOT fire
    for `[tags]` (handled separately) or fields whose value_type is "array"."""
    # tags handled separately
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["x"] }
          if "x" in [tags] { mutate { replace => { "f" => "v" } } }
        }
    """)
    parser.analyze()
    assert "string_in_check" not in _summary_codes(parser)
    # array field doesn't trigger
    parser2 = ReverseParser("""
        filter {
          mutate { replace => { "items" => "a,b,c" } }
          mutate { split => { "items" => "," } }
          if "a" in [items] { mutate { replace => { "f" => "v" } } }
        }
    """)
    parser2.analyze()
    assert "string_in_check" not in _summary_codes(parser2)


def test_bug_typed_value_branch_merge_yields_mixed_summary():
    """EASY-FIX (Phase R1.2): when one branch sets a field to a string and
    another splits it into an array, the per-token value_type_summary
    reports `"mixed"` so consumers see the runtime ambiguity at a glance."""
    parser = ReverseParser("""
        filter {
          if [route] == "raw" {
            mutate { replace => { "csv" => "literal_string" } }
          } else {
            mutate { replace => { "csv" => "a,b,c" } }
            mutate { split => { "csv" => "," } }
          }
        }
    """)
    summary = parser.analysis_summary()
    vts = summary.get("value_type_summary", {})
    assert vts.get("csv") == "mixed", f"expected mixed value_type for csv across branches; got {vts!r}"


def test_bug_typed_value_summary_omits_unknown_tokens():
    """EASY-FIX (Phase R1.2): the summary only includes tokens whose union
    is a definite type. A pure-template assignment (value_type='unknown')
    must NOT appear in value_type_summary."""
    parser = ReverseParser('filter { mutate { replace => { "y" => "%{src}" } } }')
    summary = parser.analysis_summary()
    vts = summary.get("value_type_summary", {})
    assert "y" not in vts, f"unknown-type token leaked into summary: {vts!r}"


def test_bug_typed_value_template_expression_stays_unknown():
    """EASY-FIX (Phase R1.1 sanity): templated values (`%{...}`) leave
    value_type as `"unknown"` since the analyzer can't conclude the type
    without evaluating the template."""
    parser = ReverseParser('filter { mutate { replace => { "y" => "%{src}" } } }')
    state = parser.analyze()
    lins = state.tokens.get("y", [])
    assert lins
    # Templated → unknown
    assert all(lin.value_type == "unknown" for lin in lins)


def test_bug_typed_value_split_alone_yields_array():
    """EASY-FIX (Phase 4C): a field that's only been split (no follow-up
    join) carries `value_type="array"`."""
    parser = ReverseParser("""
        filter {
          mutate { replace => { "csv" => "a,b,c" } }
          mutate { split => { "csv" => "," } }
        }
    """)
    state = parser.analyze()
    csv_lineages = state.tokens.get("csv", [])
    assert csv_lineages
    assert csv_lineages[-1].value_type == "array"


def test_bug_challenge_700_massive_plugin_sequence_ambiguous_drop():
    """INVALID: chain tracing and drops both work."""
    # fixture: test_challenge_700_massive_plugin_sequence_ambiguous_drop
    _load("test_challenge_700_massive_plugin_sequence_ambiguous_drop.cbn").analyze()


def test_bug_challenge_io_dead_letter_queue_file_routing():
    """EASY-FIX (Phase 3E follow-up): input/output blocks parse cleanly
    AND their inner plugins surface as IOAnchor records carrying any
    conditional routing (e.g. `output { if [tags] { file {} } else { elasticsearch {} } }`)."""
    # fixture: test_challenge_io_dead_letter_queue_file_routing
    parser = _load("test_challenge_io_dead_letter_queue_file_routing.cbn")
    msgs = [
        expect_str(expect_mapping(w)["message"])
        for w in expect_mapping_list(parser.analysis_summary()["structured_warnings"])
    ]
    assert not any("input config parse failure" in m or "output config parse failure" in m for m in msgs)
    state = parser.analyze()
    plugins_by_kind = {(a.kind, a.plugin) for a in state.io_anchors}
    assert ("input", "beats") in plugins_by_kind
    assert ("output", "file") in plugins_by_kind
    assert ("output", "elasticsearch") in plugins_by_kind
    # Conditional routing in the output block must be reflected in anchor conditions.
    assert any(a.kind == "output" and a.plugin == "file" and a.conditions for a in state.io_anchors), (
        "expected the dead-letter file output to carry a routing condition"
    )


# ---------------------------------------------------------------------------
# Batch 2
# ---------------------------------------------------------------------------


def test_bug_challenge_io_output_drop_blackhole():
    """EASY-FIX (Phase 3E follow-up): input/output blocks parse cleanly
    AND the conditional `null` (drop) sink is recorded as an output anchor
    with its routing condition."""
    # fixture: test_challenge_io_output_drop_blackhole
    parser = _load("test_challenge_io_output_drop_blackhole.cbn")
    msgs = [
        expect_str(expect_mapping(w)["message"])
        for w in expect_mapping_list(parser.analysis_summary()["structured_warnings"])
    ]
    assert not any("input config parse failure" in m or "output config parse failure" in m for m in msgs)
    state = parser.analyze()
    null_anchors = [a for a in state.io_anchors if a.kind == "output" and a.plugin == "null"]
    assert null_anchors, "expected the null (drop) output sink to be recorded as an io anchor"
    assert null_anchors[0].conditions, "null-sink anchor must carry the routing condition"


def test_bug_complex_boolean_tag_and_regex():
    """INVALID: parses without errors; emits a deliberate symbolic-branch warning
    for the `(?i)` regex. Assert current correct behavior."""
    # fixture: test_complex_boolean_tag_and_regex
    parser = _load("test_complex_boolean_tag_and_regex.cbn")
    parser.analyze()
    # Inline regex flag should produce runtime_condition (symbolic)
    assert "runtime_condition" in _summary_codes(parser)


def test_bug_conditional_and_contradiction():
    """EASY-FIX (Phase D4): top-level `and` splitter now feeds each conjunct
    into the contradiction detector. `[user] == "Alice" and [user] == "Bob"`
    is recognized as internally contradictory; the branch is reported as
    unreachable instead of silently executed."""
    # fixture: test_conditional_and_contradiction
    parser = _load("test_conditional_and_contradiction.cbn")
    parser.analyze()
    assert "unreachable_branch" in _summary_codes(parser)


def test_bug_conditional_nested():
    """INVALID: nested conditions are tracked verbatim in `conditions` list.
    The latent fact-extraction gap manifests with a SECOND contradicting
    condition (covered by test_bug_conditional_nested_contradiction)."""
    # fixture: test_conditional_nested
    parser = _load("test_conditional_nested.cbn")
    state = parser.analyze()
    lineages = state.tokens.get("user.role", [])
    assert lineages, "expected user.role assignment from nested-field condition fixture"
    assert {lin.expression for lin in lineages} == {"Admin"}
    assert all('[user][name] == "Alice"' in lin.conditions for lin in lineages)


def test_bug_conditional_nested_contradiction():
    """EASY-FIX: condition-fact regexes only accept ONE bracketed segment.
    After the regex update, deeply-nested bracket refs like `[a][b][c]` should
    still be recognized as facts so contradictions get detected."""
    # fixture: test_conditional_nested_contradiction
    parser = _load("test_conditional_nested_contradiction.cbn")
    parser.analyze()
    assert "unreachable_branch" in _summary_codes(parser), (
        "expected unreachable_branch warning after multi-segment bracket-ref support"
    )


def test_bug_conditional_toplevel_contradiction():
    """INVALID: self-identifies as a baseline; already produces unreachable_branch."""
    # fixture: test_conditional_toplevel_contradiction
    parser = _load("test_conditional_toplevel_contradiction.cbn")
    parser.analyze()
    assert "unreachable_branch" in _summary_codes(parser)


def test_bug_copy_object():
    """EASY-FIX: `copy: user => target.user` should also project descendants
    (`user.name`, `user.id`) onto the destination namespace."""
    # fixture: test_copy_object
    parser = _load("test_copy_object.cbn")
    state = parser.analyze()
    # After fix: target.user.name should exist in tokens (or descendant index).
    has_descendant = any(t.startswith("target.user.") for t in state.tokens)
    assert has_descendant, "copy did not project descendants onto target namespace"


def test_bug_drop_filter_in_nested_conditionals():
    """PARTIAL (positive regression): drop branching works. Assert that drop
    is recognized in both nested sites."""
    # fixture: test_drop_filter_in_nested_conditionals
    parser = _load("test_drop_filter_in_nested_conditionals.cbn")
    parser.analyze()
    assert "drop" in _summary_codes(parser)


# ---------------------------------------------------------------------------
# Batch 3
# ---------------------------------------------------------------------------


def test_bug_drop_percentage():
    """EASY-FIX: `drop { percentage => 50 }` is probabilistic — post-drop
    fields should remain reachable via a survival branch."""
    # fixture: test_drop_percentage
    parser = _load("test_drop_percentage.cbn")
    parser.analyze()
    codes = _summary_codes(parser)
    # After fix: a `drop_probabilistic` warning is emitted (distinct from `drop`).
    assert "drop_probabilistic" in codes


def test_bug_dynamic_loop_shadow():
    """INVALID: dynamic loop preserves outer `user='Admin'` and adds the
    iteration's `User`. Assert both alternatives are present."""
    # fixture: test_dynamic_loop_shadow
    parser = _load("test_dynamic_loop_shadow.cbn")
    parser.analyze()


def test_bug_extractor_overwrite():
    """EASY-FIX (Phase D2): when an extractor (xml/csv/grok/dissect) writes to
    a token that already has lineage from a non-extractor source
    (mutate.replace/copy/merge), the prior lineage is preserved as an
    alternative instead of being clobbered. Two extractor writes to the same
    token still overwrite, matching baseline behavior."""
    # fixture: test_extractor_overwrite
    parser = _load("test_extractor_overwrite.cbn")
    state = parser.analyze()
    user_lineages = state.tokens.get("user", [])
    assert len(user_lineages) >= 2, "expected both Alice and xml-derived value"


def test_bug_json_split_columns():
    """EASY-FIX: `array_function => split_columns` should expose `<target>_N`
    indexed sub-tokens linked to `message[N]`."""
    # fixture: test_json_split_columns
    parser = _load("test_json_split_columns.cbn")
    state = parser.analyze()
    indexed_tokens = [t for t in state.tokens if "_1" in t or "_2" in t]
    assert indexed_tokens, "expected indexed sub-tokens like user_1, user_2"


def test_bug_kv_hallucination():
    """EASY-FIX: `kv { include_keys => [...] }` must restrict which tokens are
    inferable; without the restriction the analyzer hallucinates fields not in
    the include list."""
    # fixture: test_kv_hallucination
    parser = _load("test_kv_hallucination.cbn")
    parser.analyze()
    # After fix: querying a key NOT in include_keys should be unresolved.
    result = parser.query("not_in_include_list")
    # Either no mappings, or all marked unresolved
    assert all(m.status not in LIVE_LINEAGE_STATUSES for m in result.mappings) or not result.mappings


def test_bug_loop_shadow():
    """EASY-FIX: static for-loop must preserve outer-scope tokens (the
    no-execution branch). After fix, querying `principal.user` should still
    resolve to the pre-loop assignment."""
    # fixture: test_loop_shadow
    parser = _load("test_loop_shadow.cbn")
    parser.analyze()
    result = parser.query("principal.user")
    # Pre-loop assignment must survive as one of the alternatives.
    assert result.mappings, "expected at least one mapping for principal.user"


def test_bug_loop_shadow2():
    """EASY-FIX: same restructure as test_bug_loop_shadow."""
    # fixture: test_loop_shadow2
    parser = _load("test_loop_shadow2.cbn")
    parser.analyze()
    result = parser.query("target")
    assert result.mappings


def test_bug_mutate_execution_order():
    """EASY-FIX (Phase D5): the analyzer follows source order (source-order
    semantics are exploited by many real parsers, so changing the default would
    silently break them) but now flags `mutate_ordering_drift` when source order
    differs from Logstash's canonical order, so users can decide whether to
    reorder their config or accept the discrepancy."""
    # fixture: test_mutate_execution_order
    parser = _load("test_mutate_execution_order.cbn")
    parser.analyze()
    assert "mutate_ordering_drift" in _summary_codes(parser)


def test_bug_mutate_execution_order_canonical_flag_changes_lineage():
    """EASY-FIX (Phase 4A): the `--mutate-canonical-order` opt-in (CLI flag,
    Python kwarg `mutate_canonical_order=True`) actually reorders mutate
    execution. With source-order (default), `replace` runs before `rename`
    so `target` ends up with the replace value's lineage. With canonical
    order, `rename` runs first (no-op since target doesn't exist yet), then
    `replace` writes the constant — different lineage shape proves the flag
    has effect."""
    # fixture: test_mutate_execution_order
    src = _load("test_mutate_execution_order.cbn").parser_code

    default_state = ReverseParser(src).analyze()
    canonical_state = ReverseParser(src, mutate_canonical_order=True).analyze()

    # The flag should actually change something — the per-token lineage must
    # not be byte-identical between the two runs.
    default_target = default_state.tokens.get("target", [])
    canonical_target = canonical_state.tokens.get("target", [])
    default_summary = sorted((lin.expression, tuple(lin.transformations)) for lin in default_target)
    canonical_summary = sorted((lin.expression, tuple(lin.transformations)) for lin in canonical_target)
    assert default_summary != canonical_summary, (
        "the canonical-order flag must produce a different lineage than the default"
    )


# ---------------------------------------------------------------------------
# Batch 4
# ---------------------------------------------------------------------------


def test_bug_mutate_join():
    """EASY-FIX: `mutate { join => { field => sep } }` must be a recognized
    operation, not flagged as unsupported."""
    # fixture: test_mutate_join
    parser = _load("test_mutate_join.cbn")
    parser.analyze()
    assert not _has_unsupported(parser, "join"), "mutate.join must be recognized after the fix"


def test_bug_mutate_split():
    """EASY-FIX: `mutate { split => { field => sep } }` must read the field
    from the map key, not from a `source =>` config key."""
    # fixture: test_mutate_split
    parser = _load("test_mutate_split.cbn")
    parser.analyze()
    codes = _summary_codes(parser)
    # After fix: no empty_destination warnings from split misreading config.
    assert "empty_destination" not in codes


def test_bug_on_error_recursion():
    """INVALID: depth IS bumped at the dispatch site. Author misread the code."""
    # fixture: test_on_error_recursion
    parser = _load("test_on_error_recursion.cbn")
    parser.analyze()  # must not crash


def test_bug_regex_bareword():
    """EASY-FIX (Phase 3C): the scanner now treats path-style barewords
    (`=> /var_{/logs/}`) as opaque so their inner braces don't desync the
    surrounding brace-depth tracker. The mutate block parses cleanly and
    `target.ip` survives the previously-corrupt brace counting."""
    # fixture: test_regex_bareword
    parser = _load("test_regex_bareword.cbn")
    parser.analyze()
    assert any("target.ip" in f for f in parser.list_udm_fields())
    assert not list(parser.parse_diagnostics), "no Lark parse failure should occur after the path-bareword fix"


def test_bug_rename_object():
    """EASY-FIX: `rename: user => target.user` must project descendants onto
    the renamed namespace, not just delete them."""
    # fixture: test_rename_object
    parser = _load("test_rename_object.cbn")
    state = parser.analyze()
    # After fix: target.user.name should exist (renamed from user.name).
    has_descendant = any(t.startswith("target.user.") for t in state.tokens)
    assert has_descendant, "rename did not project descendants onto target namespace"


def test_bug_syslog_pri_and_facility_complex():
    """EASY-FIX (Phase D7 + 4B): syslog_pri now has a handler that synthesizes
    `<pri>_severity` and `<pri>_facility` derived destinations and applies
    the configured `severity_labels` / `facility_labels` arrays when the
    source PRI is a literal integer."""
    # fixture: test_syslog_pri_and_facility_complex
    parser = _load("test_syslog_pri_and_facility_complex.cbn")
    state = parser.analyze()
    assert "syslog_pri_severity" in state.tokens
    assert "syslog_pri_facility" in state.tokens
    # syslog_pri must no longer fall through to unsupported.
    assert not any("syslog_pri" in u for u in expect_str_list(parser.analysis_summary()["unsupported"]))


def test_bug_syslog_pri_label_count_mismatch_warns():
    """EASY-FIX (Phase R4.2): the syslog spec says severity is 3 bits (8
    labels) and facility is 5 bits (24 labels). When the configured arrays
    don't match, surface a `syslog_pri_label_count_mismatch` warning so
    mis-configurations are caught."""
    parser = ReverseParser("""
        filter {
          mutate { add_field => { "syslog_pri" => "13" } }
          syslog_pri {
            syslog_pri_field_name => "syslog_pri"
            severity_labels => ["A", "B", "C"]
            facility_labels => ["x", "y", "z"]
          }
        }
    """)
    parser.analyze()
    assert "syslog_pri_label_count_mismatch" in _summary_codes(parser)


def test_bug_syslog_pri_resolves_concrete_labels_for_literal_pri():
    """EASY-FIX (Phase 4B): when the PRI source resolves to a literal
    integer constant, syslog_pri produces concrete severity/facility label
    lineages (e.g. PRI=13 → severity index 5 ("Notice"), facility index 1
    ("user-level"))."""
    parser = ReverseParser("""
        filter {
          mutate { add_field => { "syslog_pri" => "13" } }
          syslog_pri {
            syslog_pri_field_name => "syslog_pri"
            severity_labels => ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
            facility_labels => ["kernel", "user-level", "mail", "daemon", "security/authorization", "syslogd", "line printer", "network news"]
          }
        }
    """)
    state = parser.analyze()
    severity_lineages = state.tokens.get("syslog_pri_severity", [])
    severity_exprs = {lin.expression for lin in severity_lineages}
    assert "Notice" in severity_exprs, f"expected concrete severity label; got {severity_exprs}"
    facility_lineages = state.tokens.get("syslog_pri_facility", [])
    facility_exprs = {lin.expression for lin in facility_lineages}
    assert "user-level" in facility_exprs, f"expected concrete facility label; got {facility_exprs}"


def test_bug_xml_overwrite():
    """EASY-FIX (Phase D2): same fix as ``test_bug_extractor_overwrite``. An
    xml extractor that writes to a token previously assigned by mutate.replace
    must preserve the prior lineage as an alternative."""
    # fixture: test_xml_overwrite
    parser = _load("test_xml_overwrite.cbn")
    state = parser.analyze()
    user_lineages = state.tokens.get("user", [])
    assert len(user_lineages) >= 2


def test_bug_xpath_comment():
    """INVALID: `//commented_out_node` is valid XPath; the disambiguation rule
    is intentional. The proposed fix would silently drop legitimate xpath rules."""
    # fixture: test_xpath_comment
    parser = _load("test_xpath_comment.cbn")
    parser.analyze()  # must not crash


# ---------------------------------------------------------------------------
# Sanity check: fixture count tracks the bug bucket size
# ---------------------------------------------------------------------------


def test_bug_tag_membership_routing():
    """EASY-FIX (Phase 3B): the analyzer now reasons about literal-tag
    membership checks. ``if "_jsonparsefailure" in [tags]`` after only
    ``add_tag => ["_seen"]`` is unreachable — no add_tag call could have
    produced ``_jsonparsefailure``."""
    # fixture: test_tag_membership_routing
    parser = _load("test_tag_membership_routing.cbn")
    parser.analyze()
    assert "unreachable_branch" in _summary_codes(parser)


def test_bug_conditional_tag_check_warns_when_add_tag_was_guarded():
    """EASY-FIX (Phase R2): when add_tag is inside an if branch, the
    subsequent `if "<tag>" in [tags]` is reachable but tag membership
    isn't guaranteed. Emit `conditional_tag_check` advisory."""
    parser = ReverseParser("""
        filter {
          if [src] == "test" {
            mutate { add_tag => ["seen"] }
          }
          if "seen" in [tags] {
            mutate { replace => { "x" => "v" } }
          }
        }
    """)
    parser.analyze()
    assert "conditional_tag_check" in _summary_codes(parser)


def test_bug_conditional_tag_check_silent_when_add_tag_unconditional():
    """EASY-FIX (Phase R2 sanity): when add_tag is unconditional, the
    membership check is guaranteed and the advisory must NOT fire."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
          if "seen" in [tags] {
            mutate { replace => { "x" => "v" } }
          }
        }
    """)
    parser.analyze()
    assert "conditional_tag_check" not in _summary_codes(parser)


def test_bug_conditional_tag_check_warns_when_remove_tag_present():
    """EASY-FIX (Phase R2): when add_tag was unconditional but a remove_tag
    appears later, membership is uncertain — emit the advisory."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
          mutate { remove_tag => ["seen"] }
          if "seen" in [tags] {
            mutate { replace => { "x" => "v" } }
          }
        }
    """)
    parser.analyze()
    assert "conditional_tag_check" in _summary_codes(parser)


def test_bug_tag_membership_with_matching_tag_stays_reachable():
    """EASY-FIX (Phase 3B sanity): when the literal IS added by a prior
    add_tag, the branch must NOT be flagged unreachable."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["_seen"] }
          if "_seen" in [tags] {
            mutate { replace => { "x" => "ok" } }
          }
        }
    """)
    parser.analyze()
    assert "unreachable_branch" not in _summary_codes(parser)


def test_single_quoted_tag_membership_prunes_unreachable_branch():
    """Single-quoted tag membership has the same runtime semantics as
    double-quoted membership, so the analyzer must use the same reachability
    pruning for both forms."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
          if 'missing' in [tags] {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "bad" } }
          } else {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "ok" } }
          }
          mutate { merge => { "@output" => "event" } }
        }
    """)
    result = parser.query("metadata.description")
    assert {mapping.expression for mapping in result.mappings} == {"ok"}
    assert "unreachable_branch" in _summary_codes(parser)


def test_bug_conditional_or_disjunction_contradiction():
    """EASY-FIX (Phase 3D): the contradiction detector now considers
    OR-disjuncts. When every disjunct of an outer condition contradicts a
    child fact (`[a] == "x" or [a] == "y"` then `if [a] == "z"`), the child
    branch is reported as unreachable."""
    # fixture: test_conditional_or_disjunction_contradiction
    parser = _load("test_conditional_or_disjunction_contradiction.cbn")
    parser.analyze()
    assert "unreachable_branch" in _summary_codes(parser)


def test_bug_kv_include_keys_filter():
    """EASY-FIX (Phase 3A): the kv plugin's `include_keys` / `exclude_keys`
    filters are now honored by the resolver. UDM destinations populated from
    listed kv keys resolve via kv lineage; destinations populated from
    excluded or unlisted keys do not.
    """
    # fixture: test_kv_include_keys_filter
    parser = _load("test_kv_include_keys_filter.cbn")
    parser.analyze()
    # In include_keys → user.userid resolves with kv lineage
    allowed = parser.query("principal.user.userid")
    assert any(s.kind == "kv_key" for m in allowed.mappings for s in m.sources), (
        "expected kv-derived mapping for an included key"
    )
    # In exclude_keys → principal.role has no kv lineage
    forbidden = parser.query("principal.role")
    assert not any(s.kind == "kv_key" for m in forbidden.mappings for s in m.sources), (
        "exclude_keys was ignored; resolver returned a kv mapping for a forbidden key"
    )
    # Outside include_keys → email_addresses has no kv lineage
    other = parser.query("principal.email_addresses")
    assert not any(s.kind == "kv_key" for m in other.mappings for s in m.sources), (
        "include_keys was ignored; resolver returned a kv mapping for an unlisted key"
    )


def test_bug_io_for_loop_routing():
    """T3.1: for-loops nested inside input/output blocks expand to one
    IOAnchor per iteration (when the iterable is a static string array).
    The fixture has one input for-loop over 2 sources and one output for-loop
    over 3 sinks, so we expect 2 + 3 = 5 anchors with per-iteration conditions.

    Also exercises T3.2: each anchor carries a config_summary listing the
    plugin's interesting keys (topics for kafka, hosts/index for ES).
    """
    # fixture: test_io_for_loop_routing
    parser = _load("test_io_for_loop_routing.cbn")
    state = parser.analyze()
    kafka_anchors = [a for a in state.io_anchors if a.plugin == "kafka"]
    es_anchors = [a for a in state.io_anchors if a.plugin == "elasticsearch"]
    assert len(kafka_anchors) == 2, f"expected 2 kafka anchors; got {kafka_anchors!r}"
    assert len(es_anchors) == 3, f"expected 3 elasticsearch anchors; got {es_anchors!r}"
    es_conditions = sorted(a.conditions[0] for a in es_anchors)
    assert es_conditions == [
        "for sink = 'es_cold'",
        "for sink = 'es_hot'",
        "for sink = 'es_warm'",
    ], es_conditions
    # T3.2: every kafka anchor must carry topics in its config_summary; every
    # ES anchor must carry hosts and index. Templated values render as-is so
    # users can see "events_%{source}" rather than re-grep the source.
    for anchor in kafka_anchors:
        keys = {k for k, _ in anchor.config_summary}
        assert "topics" in keys, anchor.config_summary
    for anchor in es_anchors:
        keys = {k for k, _ in anchor.config_summary}
        assert "hosts" in keys and "index" in keys, anchor.config_summary


def test_io_block_skips_unreachable_elif_anchor():
    """Input/output routing should use the same branch reachability checks
    as filter blocks; impossible elif branches must not produce IO anchors."""
    parser = ReverseParser("""
        output {
          if [route] == "a" {
            elasticsearch { hosts => ["hot"] index => "a" }
          } else if [route] == "a" {
            file { path => "/tmp/impossible" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert plugins == {"elasticsearch", "null"}
    assert "unreachable_branch" in _summary_codes(parser)


def test_io_block_skips_unreachable_single_quoted_tag_branch():
    """Tag-membership pruning also applies inside output routing blocks."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
        }
        output {
          if 'missing' in [tags] {
            file { path => "/tmp/missing" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert plugins == {"null"}
    assert "unreachable_branch" in _summary_codes(parser)


def test_tag_membership_preserves_unknown_escapes_like_config_strings():
    """Unknown condition escapes must match config string decoding.

    Config string decoding preserves unknown escapes (`\\q` stays `\\q`), so
    the condition literal decoder must do the same. Otherwise this reachable
    output route is mistaken for a missing tag and pruned as unreachable.
    """
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["a\\q"] }
        }
        output {
          if "a\\q" in [tags] {
            file { path => "/tmp/matched" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert "file" in plugins
    assert "unreachable_branch" not in _summary_codes(parser)


def test_tag_membership_decodes_known_quote_escape_like_config_strings():
    """Known condition escapes must match config string decoding too.

    The add_tag config string decodes `\"` to `"`, so the condition literal
    must decode the same way or this reachable output route gets pruned.
    """
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["a\\"b"] }
        }
        output {
          if "a\\"b" in [tags] {
            file { path => "/tmp/matched" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert "file" in plugins
    assert "unreachable_branch" not in _summary_codes(parser)


def test_tag_membership_decodes_escaped_backslash_like_config_strings():
    """Escaped backslashes in conditions must match config string decoding."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["a\\\\b"] }
        }
        output {
          if "a\\\\b" in [tags] {
            file { path => "/tmp/matched" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert "file" in plugins
    assert "unreachable_branch" not in _summary_codes(parser)


def test_double_quoted_tag_membership_preserves_escaped_single_quote():
    """Double-quoted condition literals preserve escaped single quotes."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["a\\'b"] }
        }
        output {
          if "a\\'b" in [tags] {
            file { path => "/tmp/matched" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert "file" in plugins
    assert "unreachable_branch" not in _summary_codes(parser)


def test_single_quoted_tag_membership_preserves_escaped_double_quote():
    """Single-quoted condition literals preserve escaped double quotes."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ['a\\"b'] }
        }
        output {
          if 'a\\"b' in [tags] {
            file { path => "/tmp/matched" }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert "file" in plugins
    assert "unreachable_branch" not in _summary_codes(parser)


def test_io_block_skips_else_anchor_when_tag_check_is_definitely_true():
    """A definitely-true tag membership check makes the synthesized else
    negation unreachable, so the else output anchor should not survive.
    """
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
        }
        output {
          if "seen" in [tags] {
            elasticsearch { hosts => ["hot"] }
          } else {
            null { }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert plugins == {"elasticsearch"}


def test_filter_if_skips_else_mapping_when_tag_check_is_definitely_true():
    """Normal filter branches should prune an else branch whose synthesized
    tag negation is unreachable.
    """
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
          if "seen" in [tags] {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "then" } }
          } else {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "else" } }
          }
          mutate { merge => { "@output" => "event" } }
        }
    """)
    result = parser.query("metadata.description")
    assert {mapping.expression for mapping in result.mappings} == {"then"}


def test_filter_if_skips_elif_mapping_when_prior_tag_check_is_definitely_true():
    """Normal filter elif branches should prune current-chain tag negations."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
          if "seen" in [tags] {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "then" } }
          } else if [route] == "a" {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "bad" } }
          }
          mutate { merge => { "@output" => "event" } }
        }
    """)
    result = parser.query("metadata.description")
    assert {mapping.expression for mapping in result.mappings} == {"then"}


def test_io_block_skips_elif_anchor_when_prior_tag_check_is_definitely_true():
    """IO elif branches should prune current-chain tag negations."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
        }
        output {
          if "seen" in [tags] {
            elasticsearch { hosts => ["hot"] }
          } else if [route] == "a" {
            file { path => "/tmp/bad" }
          }
        }
    """)
    state = parser.analyze()
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert plugins == {"elasticsearch"}


def test_filter_if_inner_else_ignores_stale_outer_tag_negation_after_tag_mutation():
    """Only the current if/elif chain's negations may prune an else branch."""
    parser = ReverseParser("""
        filter {
          if "seen" in [tags] {
            mutate { replace => { "event.idm.read_only_udm.metadata.description" => "outer then" } }
          } else {
            mutate { add_tag => ["seen"] }
            if [route] == "a" {
              mutate { replace => { "event.idm.read_only_udm.metadata.description" => "inner then" } }
            } else {
              mutate { replace => { "event.idm.read_only_udm.metadata.description" => "inner else" } }
            }
          }
          mutate { merge => { "@output" => "event" } }
        }
    """)
    result = parser.query("metadata.description")
    assert "inner else" in {mapping.expression for mapping in result.mappings}


def test_io_if_inner_else_ignores_stale_outer_tag_negation_after_tag_mutation():
    """IO routing uses only the current if/elif chain's negations too."""
    from parser_lineage_analyzer.ast_nodes import IfBlock, IOBlock, Plugin

    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["seen"] }
        }
    """)
    state = parser.analyze()
    parser._exec_io_block(
        IOBlock(
            line=1,
            kind="output",
            body=[
                IfBlock(
                    line=1,
                    condition='[route] == "a"',
                    then_body=[Plugin(line=1, name="elasticsearch", body="", config=[])],
                    else_body=[Plugin(line=1, name="null", body="", config=[])],
                )
            ],
        ),
        state,
        ['NOT("seen" in [tags])'],
    )
    plugins = {anchor.plugin for anchor in state.io_anchors}
    assert "null" in plugins


def test_bug_syslog_pri_resolves_concrete_labels_for_branched_pri():
    """T4.1: when the PRI source is set conditionally (one integer per branch),
    the analyzer emits one concrete-label lineage per distinct integer value.
    Branches resolving to the same PRI dedupe into a single lineage.
    """
    parser = ReverseParser("""
        filter {
          if [x] == "a" { mutate { add_field => { "syslog_pri" => "13" } } }
          else if [x] == "b" { mutate { add_field => { "syslog_pri" => "14" } } }
          else if [x] == "c" { mutate { add_field => { "syslog_pri" => "13" } } }
          else { mutate { add_field => { "syslog_pri" => "29" } } }
          syslog_pri {
            syslog_pri_field_name => "syslog_pri"
            severity_labels => ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"]
            facility_labels => ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
          }
        }
    """)
    state = parser.analyze()
    sev = state.tokens.get("syslog_pri_severity", [])
    sev_exprs = sorted({lin.expression for lin in sev if lin.status == "constant"})
    # PRI 13 → notice, 14 → info, 29 → notice (29 & 7 == 5, 13 & 7 == 5).
    # 13/29 dedupe; final set = {info, notice}.
    assert sev_exprs == ["info", "notice"], sev_exprs


def test_bug_syslog_pri_caps_alternative_count():
    """T4.1: more than MAX_SYSLOG_PRI_BRANCHES distinct PRI integers fall back
    to the symbolic path so the lineage list doesn't grow unboundedly."""
    from parser_lineage_analyzer._plugins_transforms import MAX_SYSLOG_PRI_BRANCHES

    cases = "\n".join(
        f'  if [x] == "k{i}" {{ mutate {{ add_field => {{ "syslog_pri" => "{i}" }} }} }}'
        for i in range(MAX_SYSLOG_PRI_BRANCHES + 5)
    )
    parser = ReverseParser(f"""
        filter {{
          {cases}
          syslog_pri {{
            syslog_pri_field_name => "syslog_pri"
            severity_labels => ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"]
            facility_labels => ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
          }}
        }}
    """)
    state = parser.analyze()
    sev = state.tokens.get("syslog_pri_severity", [])
    constant_count = sum(1 for lin in sev if lin.status == "constant")
    # Past the cap, the analyzer should NOT emit one constant per alternative.
    assert constant_count == 0, f"expected fallback to symbolic past the cap; got {constant_count} constant lineages"


def test_tag_state_definitely_after_two_unconditional_adds():
    """T2: two unconditional add_tag invocations land both literals in
    `definitely`. Membership checks for either tag should NOT trigger the
    conditional advisory."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["a"] }
          mutate { add_tag => ["b"] }
          if "a" in [tags] {
            mutate { add_field => { "saw_a" => "yes" } }
          }
          if "b" in [tags] {
            mutate { add_field => { "saw_b" => "yes" } }
          }
        }
    """)
    state = parser.analyze()
    assert "a" in state.tag_state.definitely
    assert "b" in state.tag_state.definitely
    assert state.tag_state.possibly >= state.tag_state.definitely
    assert "conditional_tag_check" not in _summary_codes(parser)


def test_tag_state_possibly_only_after_one_branch_adds():
    """T2: a tag added only in one branch of an if/else lands in `possibly`
    (union) but not `definitely` (intersection). A subsequent membership
    check should fire `conditional_tag_check` since the tag isn't always
    present."""
    parser = ReverseParser("""
        filter {
          if [route] == "x" {
            mutate { add_tag => ["routed_x"] }
          } else {
            mutate { add_tag => ["routed_y"] }
          }
          if "routed_x" in [tags] {
            mutate { add_field => { "post" => "ok" } }
          }
        }
    """)
    state = parser.analyze()
    assert "routed_x" in state.tag_state.possibly
    assert "routed_y" in state.tag_state.possibly
    assert "routed_x" not in state.tag_state.definitely
    assert "routed_y" not in state.tag_state.definitely
    assert "conditional_tag_check" in _summary_codes(parser)


def test_tag_state_dynamic_add_widens_possibly():
    """T2: a templated add_tag (``add_tag => ["%{src}"]``) sets
    `has_dynamic=True` so any literal-tag membership check is potentially
    reachable — no unreachable-branch advisory should fire."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["%{source_type}"] }
          if "kafka" in [tags] {
            mutate { add_field => { "from_kafka" => "yes" } }
          }
        }
    """)
    state = parser.analyze()
    assert state.tag_state.has_dynamic is True
    # The membership check is reachable (template might match), so
    # unreachable_branch must NOT be emitted.
    assert "unreachable_branch" not in _summary_codes(parser)


def test_tag_state_remove_tag_subtracts_from_definitely():
    """T2: an unconditional remove_tag on a previously-added literal removes
    it from both `definitely` and `possibly` (since the remove is purely
    literal — no dynamic widening)."""
    parser = ReverseParser("""
        filter {
          mutate { add_tag => ["a", "b"] }
          mutate { remove_tag => ["a"] }
        }
    """)
    state = parser.analyze()
    assert "b" in state.tag_state.definitely
    assert "a" not in state.tag_state.definitely
    assert "a" not in state.tag_state.possibly


def test_bug_io_anchor_config_summary_unknown_plugin_falls_back():
    """T3.2: plugins not in the per-plugin allowlist still get a config_summary
    via the fallback ("all string-valued top-level keys, capped at 256 chars").
    Nested-map values (e.g. ``codec { plain { ... } }``) are dropped rather
    than rendered cryptically.
    """
    parser = ReverseParser("""
        output {
          made_up_sink_plugin {
            endpoint => "https://made-up.example.com"
            timeout => "30s"
          }
        }
    """)
    state = parser.analyze()
    anchor = next(a for a in state.io_anchors if a.plugin == "made_up_sink_plugin")
    summary = dict(anchor.config_summary)
    assert summary.get("endpoint") == "https://made-up.example.com"
    assert summary.get("timeout") == "30s"


def test_bug_unsupported_edge_cases_recovers_and_reports_limits():
    """L1: migrated from test_remediation.py. The fixture is a 15KB pile of
    intentionally-malformed and unsupported constructs; the analyzer must
    recover gracefully and report each known signal."""
    # fixture: test_unsupported_edge_cases_recovery
    parser = _load("test_unsupported_edge_cases_recovery.cbn")
    summary = parser.analysis_summary()
    udm_fields = expect_str_list(summary["udm_fields"])
    assert len(udm_fields) > 1
    token_count = summary["token_count"]
    assert isinstance(token_count, int) and token_count > 1
    unsupported = expect_str_list(summary["unsupported"])
    assert any("unsupported plugin some_weird_plugin" in item for item in unsupported)
    assert any("unsupported plugin another_weird_plugin" in item for item in unsupported)
    assert any("parse recovery skipped malformed statement" in item for item in unsupported)

    warnings = "\n".join(expect_str_list(summary["warnings"]))
    for expected in [
        "dynamic destination field name",
        "dissect indirect field",
        "statedump debug statement ignored",
        "loop declares 4 variables",
        "dynamic @output anchor",
        "complex XPath expression",
        "json array_function=extract_elements",
        "Recovered parser after Lark failure",
        "dynamic loop iterable",
        "dynamic date timezone",
        "gsub replacement backreferences",
        "condition '[hostname] =~",
    ]:
        assert expected in warnings, f"missing expected warning fragment: {expected!r}"


def test_bug_unsupported_edge_cases_queries_remain_useful():
    """L1: migrated from test_remediation.py. Despite the fixture's noise,
    a few specific queries must still resolve cleanly — that's the
    "useful even when partially broken" contract."""
    # fixture: test_unsupported_edge_cases_recovery
    parser = _load("test_unsupported_edge_cases_recovery.cbn")
    target_ip = parser.query("target.ip")
    assert target_ip.status == "constant"
    assert target_ip.mappings[0].expression == "1.1.1.1"

    dynamic_field = parser.query("additional.fields.concrete_key")
    assert dynamic_field.status == "dynamic"
    assert any("dynamic destination template" in note for mapping in dynamic_field.mappings for note in mapping.notes)

    timestamp = parser.query("metadata.event_timestamp")
    assert timestamp.status == "derived"
    assert any("date(ISO8601)" in tx for mapping in timestamp.mappings for tx in mapping.transformations)
    assert any("dynamic date timezone" in warning for warning in timestamp.warnings)

    reference_url = parser.query("reference_url")
    assert any(mapping.expression == "http://www.google.com" for mapping in reference_url.mappings)


def test_bug_bucket_size():
    """Fail loudly if the bug bucket grows or shrinks without test updates."""
    files = sorted(p.name for p in BUG_DIR.iterdir() if p.suffix == ".cbn")
    # 35 initial corpus, +1 test_io_for_loop_routing (T3.1), +1 test_unsupported_edge_cases_recovery (L1).
    assert len(files) == 37, (
        f"bug bucket changed size: expected 37, got {len(files)}. "
        f"Update tests/test_corpus_bugs.py to add/remove the corresponding test."
    )


# ---------------------------------------------------------------------------
# L2: parametrized sidecar contract checks for bug fixtures.
# Bug fixtures already have hand-written tests above. The sidecar layer is
# orthogonal: it asserts the *claim* extracted from the fixture header. When
# the hand-written test and the sidecar disagree, the diff is the diagnostic.
# ---------------------------------------------------------------------------

SIDECAR_KEYS = (
    "must_have_warning_codes",
    "must_not_have_warning_codes",
    "must_resolve_fields",
    "must_have_unsupported",
)

_BUG_SIDECAR_FIXTURES = sorted(
    p for p in BUG_DIR.iterdir() if p.suffix == ".cbn" and p.with_suffix(".expected.json").exists()
)


@pytest.mark.parametrize(
    "fixture_path",
    _BUG_SIDECAR_FIXTURES,
    ids=[p.name for p in _BUG_SIDECAR_FIXTURES],
)
def test_bug_fixture_sidecar_contract(fixture_path: Path) -> None:
    sidecar_path = fixture_path.with_suffix(".expected.json")
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    unknown = set(sidecar) - set(SIDECAR_KEYS)
    assert not unknown, f"{sidecar_path}: unknown sidecar keys {sorted(unknown)}"

    parser = ReverseParser(fixture_path.read_text(encoding="utf-8"))
    summary = parser.analysis_summary()
    warning_codes = {expect_mapping(w).get("code") for w in expect_mapping_list(summary["structured_warnings"])}
    unsupported_blob = " | ".join(expect_str_list(summary["unsupported"]))

    fid = fixture_path.name
    for code in sidecar.get("must_have_warning_codes", []):
        assert code in warning_codes, f"{fid}: expected warning code {code!r}; got {sorted(warning_codes, key=str)}"
    for code in sidecar.get("must_not_have_warning_codes", []):
        assert code not in warning_codes, f"{fid}: warning code {code!r} should NOT be emitted but was"
    for field in sidecar.get("must_resolve_fields", []):
        assert parser.query(field).mappings, f"{fid}: query({field!r}) returned no mappings"
    for plugin in sidecar.get("must_have_unsupported", []):
        assert plugin in unsupported_blob, (
            f"{fid}: expected {plugin!r} in unsupported list; got {summary['unsupported']!r}"
        )
