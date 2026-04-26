from parser_lineage_analyzer import OutputAnchor, ReverseParser
from parser_lineage_analyzer._analysis_resolution import ResolutionMixin
from parser_lineage_analyzer._analysis_state import AnalyzerState, BranchRecord, ExtractionHint
from parser_lineage_analyzer.cli import main
from parser_lineage_analyzer.model import Lineage, SourceRef
from tests._typing_helpers import expect_mapping_list, expect_str


class _Resolver(ResolutionMixin):
    pass


def _anchor_dynamic_parser(anchor_count: int, dynamic_count: int) -> str:
    lines = ["filter {"]
    for i in range(anchor_count):
        lines.append(f'  if [out{i}] == "1" {{ mutate {{ merge => {{ "@output" => "event" }} }} }}')
    for i in range(dynamic_count):
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.%{{k{i}}}" => "%{{v{i}}}" }} }}'
        )
    lines.append("}")
    return "\n".join(lines)


def test_sampled_zero_mapping_query_keeps_hidden_taint_semantics():
    result = ReverseParser(_anchor_dynamic_parser(300, 200)).query("additional.fields.anything", sample_limit=-1)

    assert result.mappings == []
    assert result.total_mappings == 60_000
    assert result.status == "dynamic"
    assert result.has_dynamic
    assert result.has_taints
    assert not result.has_unresolved


def test_compact_summary_text_uses_total_counts_for_sampled_sections(tmp_path, capsys):
    code = "\n".join(
        ["filter {"]
        + [f'  unsupported_custom_plugin_{i} {{ knob => "v" }}' for i in range(60)]
        + [
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.%{{k{i}}}" => "v" }} }}'
            for i in range(60)
        ]
        + ["}"]
    )
    parser_file = tmp_path / "sampled.cbn"
    parser_file.write_text(code, encoding="utf-8")

    assert main([str(parser_file), "--compact-summary"]) == 0

    out = capsys.readouterr().out
    assert "UDM fields: 60" in out
    assert "Unsupported: 60" in out
    assert "Warnings: 60" in out


def test_inferred_token_overwrite_survives_extractor_generation_change():
    resolver = _Resolver()
    state = AnalyzerState()
    state.add_extraction_hint(
        "json",
        ExtractionHint("json", "message", {"target": "payload"}, parser_locations=["line 1: json source=message"]),
    )

    inferred = resolver._lookup_token("payload.user", state, "line 2: first lookup")
    assert [source.source_token for lineage in inferred for source in lineage.sources] == ["message"]

    state.tokens["payload.user"] = [
        Lineage(
            status="constant",
            expression="manual",
            sources=[SourceRef(kind="constant", expression="manual")],
        )
    ]
    state.add_extraction_hint(
        "json",
        ExtractionHint("json", "body", {"target": "payload"}, parser_locations=["line 3: json source=body"]),
    )

    refreshed = resolver._lookup_token("payload.user", state, "line 4: second lookup")

    assert len(refreshed) == 1
    assert refreshed[0].status == "constant"
    assert refreshed[0].expression == "manual"


def test_clone_metadata_dedupe_indexes_are_copy_on_write():
    state = AnalyzerState()
    original_hint = ExtractionHint(
        "json",
        "message",
        {"target": "payload"},
        parser_locations=["line 1: json source=message"],
    )
    state.add_extraction_hint("json", original_hint)
    state.add_output_anchor(OutputAnchor("event"))

    left = state.clone()
    right = state.clone()
    branch_hint = ExtractionHint(
        "json",
        "body",
        {"target": "payload"},
        parser_locations=["line 2: json source=body"],
    )

    left.add_extraction_hint("json", branch_hint)
    left.add_output_anchor(OutputAnchor("alt"))
    right.add_extraction_hint("json", branch_hint)
    right.add_output_anchor(OutputAnchor("alt"))

    assert [hint.source_token for hint in state.json_extractions] == ["message"]
    assert [hint.source_token for hint in left.json_extractions] == ["message", "body"]
    assert [hint.source_token for hint in right.json_extractions] == ["message", "body"]
    assert [anchor.anchor for anchor in state.output_anchors] == ["event"]
    assert [anchor.anchor for anchor in left.output_anchors] == ["event", "alt"]
    assert [anchor.anchor for anchor in right.output_anchors] == ["event", "alt"]


def test_clone_diagnostic_dedupe_indexes_are_hydrated_on_first_owned_write():
    # Regression for the latent bug where ``AnalyzerState.clone()`` aliases the
    # diagnostic lists to the parent but resets the seen-set indexes to empty
    # (via ``default_factory=set``). If the first writer on the clone went
    # through ``_ensure_diagnostics_owned`` directly (rather than first being
    # synced via ``_sync_branch_seed_diagnostics``), the seen-sets would remain
    # empty and a duplicate of any pre-existing parent diagnostic would slip
    # past the dedup check, producing a duplicate entry on the clone's lists
    # that ``merge_branch_records`` could only collapse if the merge path
    # happened to dedupe against the parent. The defensive contract: emitting
    # the same diagnostic on a clone leaves the clone's lists with the entry
    # exactly once, and merging the clone back into the parent leaves the
    # parent's lists with the entry exactly once.
    state = AnalyzerState()
    state.add_warning(
        "duplicate-warning",
        code="dup_warn",
        message="duplicate-warning",
        parser_location="line 1: filter",
    )
    state.add_taint("dup_taint", "duplicate-taint", "line 1: filter")
    state.add_unsupported(
        "duplicate-unsupported",
        code="dup_unsupp",
        message="duplicate-unsupported",
        parser_location="line 1: filter",
    )

    parent_warning_count = len(state.warnings)
    parent_taint_count = len(state.taints)
    parent_unsupported_count = len(state.unsupported)
    parent_diagnostic_count = len(state.diagnostics)
    parent_structured_count = len(state.structured_warnings)

    clone = state.clone()
    # Re-emit the same warning, taint, and unsupported on the clone without
    # going through ``_sync_branch_seed_diagnostics``. The first emission is
    # what triggers ``_ensure_diagnostics_owned``; without seen-set hydration
    # the duplicate would slip through.
    clone.add_warning(
        "duplicate-warning",
        code="dup_warn",
        message="duplicate-warning",
        parser_location="line 1: filter",
    )
    clone.add_taint("dup_taint", "duplicate-taint", "line 1: filter")
    clone.add_unsupported(
        "duplicate-unsupported",
        code="dup_unsupp",
        message="duplicate-unsupported",
        parser_location="line 1: filter",
    )

    # The clone's lists should still contain each diagnostic exactly once.
    assert clone.warnings.count("duplicate-warning") == 1
    assert len(clone.warnings) == parent_warning_count
    assert sum(1 for taint in clone.taints if taint.code == "dup_taint") == 1
    assert len(clone.taints) == parent_taint_count
    assert clone.unsupported.count("duplicate-unsupported") == 1
    assert len(clone.unsupported) == parent_unsupported_count
    assert sum(1 for diag in clone.diagnostics if diag.code == "dup_warn") == 1
    assert sum(1 for diag in clone.diagnostics if diag.code == "dup_taint") == 1
    assert sum(1 for diag in clone.diagnostics if diag.code == "dup_unsupp") == 1
    assert len(clone.diagnostics) == parent_diagnostic_count
    assert len(clone.structured_warnings) == parent_structured_count

    # Merging the clone back into the parent must leave the parent unchanged
    # (the duplicates are no-ops).
    state.merge_branch_records(state, [BranchRecord(clone, [], False)])
    assert state.warnings.count("duplicate-warning") == 1
    assert len(state.warnings) == parent_warning_count
    assert sum(1 for taint in state.taints if taint.code == "dup_taint") == 1
    assert state.unsupported.count("duplicate-unsupported") == 1
    assert sum(1 for diag in state.diagnostics if diag.code == "dup_warn") == 1
    assert len(state.diagnostics) == parent_diagnostic_count


# ---------------------------------------------------------------------------
# Regression coverage for the eight weaknesses surfaced by examples/*.cbn.
# Each example file is a sentinel: a future change that silently regresses one
# of these analyzer behaviors will fail one of these tests.
# ---------------------------------------------------------------------------


def _structured_codes(parser: ReverseParser) -> dict[str, int]:
    counts: dict[str, int] = {}
    for warning in expect_mapping_list(parser.analysis_summary()["structured_warnings"]):
        code = expect_str(warning["code"])
        counts[code] = counts.get(code, 0) + 1
    return counts


def test_w1_mutate_merge_duplicate_keys_emit_warning():
    """W1: duplicate destination keys in mutate.merge must surface a
    ``duplicate_mutate_map_key`` warning. The mutate code is distinct from
    the extractor/transform ``duplicate_config_key`` code because mutate map
    ops do NOT keep the first value — ``merge`` appends every duplicate."""
    parser = ReverseParser(
        """
        filter {
          mutate {
            merge => {
              "event.idm.read_only_udm.observer.ip" => "device.ips.0"
              "event.idm.read_only_udm.observer.ip" => "device.ips.1"
            }
          }
        }
        """
    )
    dups = [w for w in parser.analysis_summary()["structured_warnings"] if w["code"] == "duplicate_mutate_map_key"]
    assert len(dups) == 1
    assert "event.idm.read_only_udm.observer.ip" in dups[0]["message"]
    assert "mutate.merge" in dups[0]["message"]


def test_w2_unsupported_plugin_taint_does_not_broadcast_to_independent_fields():
    """W2: an unsupported plugin should taint only fields it would have written.
    Fields whose lineage was resolved before the unsupported plugin must stay clean."""
    parser = ReverseParser(
        """
        filter {
          json { source => "message" array_function => "return_last" }
          unsupported_custom_plugin { action => "do_magic" }
          if [log_type] == "type_0" {
            mutate {
              replace => {
                "event.idm.read_only_udm.principal.ip" => "%{source_ip_0}"
              }
            }
          }
        }
        """
    )
    result = parser.query("principal.ip")
    # principal.ip is sourced from the json extraction at line 3 (which precedes the
    # unsupported plugin) — none of its mappings should carry an unsupported_plugin taint.
    assert all(taint.code != "unsupported_plugin" for mapping in result.mappings for taint in mapping.taints)
    state = parser.analyze()
    assert "unsupported_plugin" not in {t.code for t in state.taints}
    # The pipeline-wide signal is preserved as a warning + unsupported entry.
    assert any(warning.code == "unsupported_plugin" for warning in state.structured_warnings)


def test_w2_unsupported_plugin_taint_attaches_to_destinations_it_writes():
    """W2: when the unsupported plugin's config exposes destination fields,
    the taint should attach to those specific fields so a query reflects the
    real uncertainty."""
    parser = ReverseParser(
        """
        filter {
          unsupported_translate_plugin {
            source => "input"
            destination => "event.idm.read_only_udm.security_result.action"
          }
        }
        """
    )
    result = parser.query("security_result.action")
    assert any(taint.code == "unsupported_plugin" for mapping in result.mappings for taint in mapping.taints)


def test_w3_over_escaped_regex_in_condition_emits_warning():
    """W3: `\\\\d` inside a regex literal matches a literal backslash, not a digit.
    The analyzer should warn so users notice the dead branch."""
    parser = ReverseParser(
        r"""
        filter {
          if [src] =~ /\\d+\\.\\d+\\.\\d+\\.\\d+/ {
            mutate { replace => { "x" => "1" } }
          }
        }
        """
    )
    over_escapes = [w for w in parser.analysis_summary()["structured_warnings"] if w["code"] == "regex_over_escape"]
    assert over_escapes, "expected regex_over_escape warning"
    # Both \\d and \\. forms should be reported (deduped by message text).
    msgs = "\n".join(w["message"] for w in over_escapes)
    assert r"\\d" in msgs
    assert r"\\." in msgs


def test_w3_normal_regex_does_not_trigger_over_escape_warning():
    """W3: properly escaped regexes (\\d, \\., \\s) must not be flagged."""
    parser = ReverseParser(
        r"""
        filter {
          if [src] =~ /^\d+\.\d+\.\d+\.\d+$/ {
            mutate { replace => { "x" => "1" } }
          }
        }
        """
    )
    assert "regex_over_escape" not in _structured_codes(parser)


def test_w4_else_if_after_else_yields_specific_diagnostic():
    """W4: `else if` after a bare `else` produces a specific actionable diagnostic
    instead of the generic Lark `Unexpected token Token('ELSE', 'else')` message."""
    src = """
    filter {
      if [t] == "a" {
        mutate { replace => { "x" => "1" } }
      } else {
        mutate { replace => { "x" => "2" } }
      } else if [t] == "b" {
        mutate { replace => { "x" => "3" } }
      }
    }
    """
    parser = ReverseParser(src)
    messages = [d.message for d in parser.parse_diagnostics]
    assert any("'else if' cannot follow a bare 'else'" in m for m in messages), messages
    # The generic Lark message should no longer dominate.
    assert not any(m.startswith("Unexpected token Token('ELSE'") for m in messages)


def test_w5_on_error_inside_plugin_config_warns_non_canonical():
    """W5: `on_error { ... }` placed inside a plugin's config map (rather than
    after it as a sibling statement) is a common authoring mistake; emit a
    specific advisory in addition to whatever parse-recovery noise fires."""
    src = """
    filter {
      json {
        source => "message"
        on_error {
          json { source => "message" target => "fallback" }
        }
      }
    }
    """
    parser = ReverseParser(src)
    codes = _structured_codes(parser)
    assert codes.get("non_canonical_on_error_placement", 0) >= 1


def test_w5_canonical_on_error_block_does_not_warn():
    """W5: the canonical statement-level `} on_error { ... }` form must NOT
    trigger the non-canonical advisory. The trip_up_2 fixture (now under
    expected/test_trip_up_2_mutate_ordering.cbn) is the canonical example."""
    fixture = "tests/fixtures/test_corpus/expected/test_trip_up_2_mutate_ordering.cbn"
    with open(fixture, encoding="utf-8") as fh:
        parser = ReverseParser(fh.read())
    assert "non_canonical_on_error_placement" not in _structured_codes(parser)


def test_w5_canonical_on_error_string_tag_does_not_warn():
    """W5: `on_error => "tag"` (string-valued, used for failure tagging) is
    canonical and must not be flagged as non-canonical placement."""
    parser = ReverseParser(
        """
        filter {
          json {
            source => "message"
            on_error => "json_failure"
          }
        }
        """
    )
    assert "non_canonical_on_error_placement" not in _structured_codes(parser)


def test_w6_static_loop_fanout_message_includes_multiplication():
    """W6: the cumulative-loop-fanout warning must show the running multiplication
    (current × items at this level) so users can identify which loop level
    pushed them over the cap, not just a single opaque number."""
    src = """
    filter {
      for x1 in ["a", "b", "c"] {
        for x2 in ["d", "e", "f"] {
          for x3 in ["g", "h", "i"] {
            for x4 in ["j", "k", "l"] {
              for x5 in ["m", "n", "o"] {
                for x6 in ["p", "q", "r"] {
                  for x7 in ["s", "t", "u"] {
                    for x8 in ["v", "w", "x"] {
                      mutate { replace => { "out" => "%{x1}-%{x8}" } }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    parser = ReverseParser(src)
    fanout = [w for w in parser.analysis_summary()["structured_warnings"] if w["code"] == "loop_fanout"]
    assert fanout, "expected at least one loop_fanout warning"
    # The enriched message must include the multiplication shape, e.g. "3×3=9".
    assert any("×" in w["message"] and "=" in w["message"] for w in fanout)


def test_w7_large_array_literal_warning_fires_above_threshold():
    """W7: a config array with > MAX_ARRAY_LITERAL_BEFORE_WARNING elements should
    surface a soft warning so users notice they are stressing the analyzer."""
    from parser_lineage_analyzer._analysis_flow import MAX_ARRAY_LITERAL_BEFORE_WARNING

    huge = ", ".join(f'"ip_{i}"' for i in range(MAX_ARRAY_LITERAL_BEFORE_WARNING + 5))
    src = f"""
    filter {{
      mutate {{
        merge => {{
          "global_threat_feed" => [{huge}]
        }}
      }}
    }}
    """
    parser = ReverseParser(src)
    warnings = [w for w in parser.analysis_summary()["structured_warnings"] if w["code"] == "large_array_literal"]
    assert len(warnings) == 1
    assert "elements" in warnings[0]["message"]


def test_w7_small_array_literal_does_not_warn():
    """W7: small arrays under the threshold must not trigger the soft warning."""
    parser = ReverseParser(
        """
        filter {
          mutate {
            merge => { "small_feed" => ["a", "b", "c"] }
          }
        }
        """
    )
    assert "large_array_literal" not in _structured_codes(parser)


def test_w8_long_elif_chain_emits_soft_warning():
    """W8: an if/else-if chain longer than MAX_ELIF_CHAIN_BEFORE_WARNING surfaces
    a long_elif_chain warning so reviewers notice the maintenance smell."""
    from parser_lineage_analyzer._analysis_flow import MAX_ELIF_CHAIN_BEFORE_WARNING

    branches = MAX_ELIF_CHAIN_BEFORE_WARNING + 5
    lines = ["filter {"]
    for i in range(branches):
        prefix = "if" if i == 0 else "} else if"
        lines.append(f'  {prefix} [vendor] == "V_{i}" {{')
        lines.append('    mutate { replace => { "x" => "v" } }')
    lines.append("  }")
    lines.append("}")
    parser = ReverseParser("\n".join(lines))
    warnings = [w for w in parser.analysis_summary()["structured_warnings"] if w["code"] == "long_elif_chain"]
    assert len(warnings) == 1
    assert f"{branches - 1} elif clauses" in warnings[0]["message"]


def test_w8_short_elif_chain_does_not_warn():
    """W8: chains under the threshold (the common case) must not trigger."""
    lines = ["filter {", '  if [v] == "0" { mutate { replace => { "x" => "v" } } }']
    for i in range(1, 50):
        lines.append(f'  else if [v] == "{i}" {{ mutate {{ replace => {{ "x" => "v" }} }} }}')
    lines.append("}")
    parser = ReverseParser("\n".join(lines))
    assert "long_elif_chain" not in _structured_codes(parser)
