from importlib import resources

import pytest

from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._analysis_assignment import AssignmentMixin
from parser_lineage_analyzer._analysis_dedupe import _dedupe_lineages, _dedupe_sources, _dedupe_strings, _freeze_value
from parser_lineage_analyzer._analysis_details import (
    capture_upstream_details,
    csv_column_details,
    csv_extraction_details,
    iterable_sources_details,
    json_extraction_details,
    kv_extraction_details,
    loop_member_details,
    loop_tuple_details,
    map_member_details,
    xml_line_details,
    xml_template_details,
)
from parser_lineage_analyzer._analysis_diagnostics import (
    drop_warning,
    dynamic_destination_warning,
    dynamic_field_removal_warning,
    json_source_unresolved_warning,
    malformed_gsub_warning,
    no_dissect_mapping_warning,
    no_grok_match_warning,
    no_match_array_warning,
    no_source_field_warning,
    no_xpath_mappings_warning,
    on_error_parse_warning,
    unparsed_statement,
    unsupported_mutate_operation,
    unsupported_plugin,
)
from parser_lineage_analyzer._analysis_executor import AnalysisExecutor
from parser_lineage_analyzer._analysis_flow import FlowExecutorMixin
from parser_lineage_analyzer._analysis_paths import _is_plausible_data_path
from parser_lineage_analyzer._analysis_resolution import ResolutionMixin
from parser_lineage_analyzer._plugins_mutate import MutatePluginMixin
from parser_lineage_analyzer.config_parser import _CONFIG_GRAMMAR
from parser_lineage_analyzer.model import Lineage, SourceRef, _freeze_details
from parser_lineage_analyzer.parser import _LALR_GRAMMAR, LalrSecOpsAstParser, parse_code_with_diagnostics


@pytest.mark.timeout(0.5)
def test_plausible_data_path_rejects_redos_shape_quickly():
    assert _is_plausible_data_path("a" + ".a" * 30 + "!") is False


def test_large_else_if_chain_uses_bounded_prior_negation_summary():
    branch_count = 1000
    lines = ["filter {"]
    lines.append(
        'if [event_type] == "0" { mutate { replace => { "event.idm.read_only_udm.metadata.event_type" => "EVENT_0" } } }'
    )
    for i in range(1, branch_count):
        lines.append(
            f'else if [event_type] == "{i}" {{ mutate {{ replace => {{ "event.idm.read_only_udm.metadata.event_type" => "EVENT_{i}" }} }} }}'
        )
    lines.append("}")
    state = ReverseParser("\n".join(lines)).analyze()
    total_conditions = sum(len(lin.conditions) for vals in state.tokens.values() for lin in vals)
    assert total_conditions < branch_count * 5
    event_type = state.tokens["event.idm.read_only_udm.metadata.event_type"]
    assert any("NOT(any of 33 prior if/else-if conditions matched)" in lin.conditions for lin in event_type)


def test_small_else_if_chain_keeps_exact_prior_negations():
    code = r"""
    filter {
      if [severity] == "high" {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "HIGH" } }
      } else if [severity] == "medium" {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "MEDIUM" } }
      } else if [severity] == "low" {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "LOW" } }
      } else {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "OTHER" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    by_value = {m.sources[0].expression: set(m.conditions) for m in result.mappings}
    assert by_value["LOW"] == {'NOT([severity] == "high")', 'NOT([severity] == "medium")', '[severity] == "low"'}
    assert by_value["OTHER"] == {'NOT([severity] == "high")', 'NOT([severity] == "medium")', 'NOT([severity] == "low")'}


def test_tuple_dedupe_preserves_nested_lineage_equivalence():
    source_a = SourceRef(kind="json_path", source_token="message", path="a.b", details={"nested": ["x", {"n": 1}]})
    source_b = SourceRef(kind="json_path", source_token="message", path="a.b", details={"nested": ["x", {"n": 1}]})
    source_c = SourceRef(kind="json_path", source_token="message", path="a.c", details={"nested": ["x", {"n": 1}]})
    assert _dedupe_sources([source_a, source_b, source_c]) == [source_a, source_c]

    lineage_a = Lineage(
        status="exact",
        sources=[source_a],
        expression="expr",
        transformations=["copy"],
        conditions=["cond"],
        parser_locations=["line 1"],
        notes=["note"],
    )
    lineage_b = Lineage(
        status="exact",
        sources=[source_b],
        expression="expr",
        transformations=["copy"],
        conditions=["cond"],
        parser_locations=["line 1"],
        notes=["note"],
    )
    assert _dedupe_lineages([lineage_a, lineage_b]) == [lineage_a]


def test_frozen_details_hash_and_key_are_stable_without_changing_dedupe_equivalence():
    details_a = _freeze_details({"z": ["x", {"n": 1}], "a": "first"})
    details_b = _freeze_details({"a": "first", "z": ["x", {"n": 1}]})

    assert hash(details_a) != 0
    assert _freeze_value(details_a) == _freeze_value(details_b)

    source_a = SourceRef(kind="json_path", source_token="message", path="a.b", details=details_a)
    source_b = SourceRef(kind="json_path", source_token="message", path="a.b", details=details_b)
    assert _dedupe_sources([source_a, source_b]) == [source_a]


def test_dedupe_strings_preserves_order_and_drops_empty_values():
    assert _dedupe_strings(["", "a", "b", "a", "", "c", "b"]) == ["a", "b", "c"]


def test_lineage_with_conditions_preserves_order_and_identity_on_duplicates():
    lineage = Lineage(status="exact", expression="x", conditions=tuple(f"c{i}" for i in range(64)))
    duplicate = lineage.with_conditions(["c1", "c2"])
    extended = lineage.with_conditions(["c2", "new", "c3", "newer", "new"])

    assert duplicate is lineage
    assert list(extended.conditions[-2:]) == ["new", "newer"]
    assert extended.conditions[:64] == lineage.conditions


def test_parse_code_with_diagnostics_only_catches_lark_errors(monkeypatch):
    def raise_type_error(self):
        raise TypeError("programmer bug")

    monkeypatch.setattr(LalrSecOpsAstParser, "parse", raise_type_error)
    with pytest.raises(TypeError):
        parse_code_with_diagnostics("filter {}")


def test_reverse_parser_facade_imports_are_compatible():
    from parser_lineage_analyzer import ReverseParser as PackageReverseParser
    from parser_lineage_analyzer.analyzer import ReverseParser as ModuleReverseParser

    assert PackageReverseParser is ModuleReverseParser


def test_plugin_dispatch_registry_contains_supported_plugins():
    assert {
        "mutate",
        "json",
        "xml",
        "kv",
        "csv",
        "grok",
        "date",
        "base64",
        "url_decode",
        "dissect",
        "on_error",
    } <= set(AnalysisExecutor._PLUGIN_HANDLERS)


def test_io_anchor_config_summary_omits_secret_like_unknown_plugin_values():
    code = r"""
    output {
      custom_sink {
        endpoint => "https://collector.example.test"
        api_key => "sk_live_should_not_leak"
        auth_token => "token-should-not-leak"
        password => "password-should-not-leak"
        client_secret => "secret-should-not-leak"
      }
    }
    """

    state = ReverseParser(code).analyze()
    anchor = next(anchor for anchor in state.io_anchors if anchor.plugin == "custom_sink")
    summary = dict(anchor.config_summary)

    assert summary == {"endpoint": "https://collector.example.test"}
    rendered = repr(anchor.to_json())
    assert "should_not_leak" not in rendered
    assert "should-not-leak" not in rendered


def test_statement_grammar_matches_packaged_resource():
    packaged = (
        resources.files("parser_lineage_analyzer").joinpath("grammar", "statement.lark").read_text(encoding="utf-8")
    )
    assert packaged == _LALR_GRAMMAR


def test_config_grammar_matches_packaged_resource():
    packaged = resources.files("parser_lineage_analyzer").joinpath("grammar", "config.lark").read_text(encoding="utf-8")
    assert packaged == _CONFIG_GRAMMAR


def test_analysis_executor_composes_flow_assignment_and_resolution_mixins():
    assert issubclass(AnalysisExecutor, FlowExecutorMixin)
    assert issubclass(AnalysisExecutor, AssignmentMixin)
    assert issubclass(AnalysisExecutor, ResolutionMixin)
    assert hasattr(AnalysisExecutor, "_exec_statements")
    assert hasattr(AnalysisExecutor, "_assign")
    assert hasattr(AnalysisExecutor, "_lineage_from_expression")


def test_source_ref_to_json_preserves_shape_without_empty_fields():
    src = SourceRef(
        kind="json_path",
        source_token="message",
        path="network.dst",
        details={"nested": [{"k": "v"}], "empty": []},
    )
    assert src.to_json() == {
        "kind": "json_path",
        "source_token": "message",
        "path": "network.dst",
        "details": {"nested": [{"k": "v"}], "empty": []},
    }
    assert SourceRef(kind="constant", expression="ALLOW").to_json() == {
        "kind": "constant",
        "expression": "ALLOW",
    }


def test_mutate_registry_contains_supported_operations():
    assert MutatePluginMixin._MUTATE_OP_HANDLERS == {
        "replace": "_exec_assignment_mutate_op",
        "add_field": "_exec_assignment_mutate_op",
        "update": "_exec_assignment_mutate_op",
        "rename": "_exec_rename_mutate_op",
        "copy": "_exec_copy_mutate_op",
        "merge": "_exec_merge_mutate_op",
        "convert": "_exec_convert_mutate_op",
        "lowercase": "_exec_case_mutate_op",
        "uppercase": "_exec_case_mutate_op",
        "strip": "_exec_case_mutate_op",
        "gsub": "_exec_gsub_mutate_op",
        "split": "_exec_split_mutate_op",
        "join": "_exec_join_mutate_op",
        "remove_field": "_exec_remove_field_mutate_op",
        "add_tag": "_exec_tag_mutate_op",
        "remove_tag": "_exec_tag_mutate_op",
        "on_error": "_exec_on_error_mutate_op",
    }


def test_mutate_registry_preserves_config_order():
    code = r"""
    filter {
      mutate {
        replace => { "tmp" => "abc" }
        gsub => ["tmp", "a", "z"]
        replace => { "event.idm.read_only_udm.metadata.description" => "%{tmp}" }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    assert result.status == "derived"
    assert any(
        "gsub(pattern=a, replacement=z)" in transform for m in result.mappings for transform in m.transformations
    )


def test_diagnostic_helpers_preserve_exact_strings():
    class Diag:
        line = 3
        column = 4
        message = "bad parser"

    assert unparsed_statement(7, "x" * 90) == f"line 7: unparsed statement: {'x' * 80}"
    assert unsupported_plugin(8, "weird") == "line 8: unsupported plugin weird"
    assert unsupported_mutate_operation(9, "odd") == "line 9: unsupported mutate operation odd"
    assert drop_warning(10) == "line 10: drop parser may drop events on this path"
    assert (
        on_error_parse_warning("line 11: on_error block", Diag())
        == "line 11: on_error block: could not parse fallback body at line 3, column 4: bad parser"
    )
    assert (
        dynamic_destination_warning("line 12: mutate.replace x <= y", "event.%{k}")
        == "line 12: mutate.replace x <= y: dynamic destination field name 'event.%{k}' cannot be resolved to concrete UDM paths without a raw event"
    )
    assert (
        dynamic_field_removal_warning("line 13: mutate.remove_field %{k}")
        == "line 13: mutate.remove_field %{k}: dynamic field removal not resolved statically"
    )
    assert (
        malformed_gsub_warning(14, 2) == "line 14: mutate.gsub malformed gsub array has 2 element(s); expected triples"
    )
    assert (
        json_source_unresolved_warning("line 15: json source=payload")
        == "line 15: json source=payload: source token was not resolved; fields from this json block are not inferred as exact raw paths"
    )
    assert (
        no_xpath_mappings_warning("line 16: xml source=message")
        == "line 16: xml source=message: no xpath mappings discovered"
    )
    assert no_grok_match_warning("line 17: grok.match") == "line 17: grok.match: no match mappings discovered"
    assert no_dissect_mapping_warning("line 18: dissect") == "line 18: dissect: no mapping/match pairs discovered"
    assert no_match_array_warning("line 19: date target=t") == "line 19: date target=t: no match array discovered"
    assert no_source_field_warning("line 20: base64") == "line 20: base64: no source/field discovered"


def test_details_factories_preserve_payload_shapes():
    upstream = SourceRef(kind="json_path", source_token="message", path="alerts")
    loop = SourceRef(
        kind="loop_item", source_token="alerts", path="alerts[*]", details=iterable_sources_details([upstream])
    )
    map_value = SourceRef(
        kind="map_value", source_token="labels", path="labels.*", details=iterable_sources_details([upstream])
    )

    assert iterable_sources_details([upstream]) == {"iterable_sources": [upstream.to_json()]}
    assert loop_tuple_details([upstream], 2) == {"iterable_sources": [upstream.to_json()], "tuple_position": 2}
    assert capture_upstream_details([upstream]) == {"upstream_sources": [upstream.to_json()]}
    assert json_extraction_details("split_columns", "payload", 21) == {
        "array_function": "split_columns",
        "target": "payload",
        "line": 21,
    }
    assert kv_extraction_details([("source", "message"), ("field_split", " "), ("trim_value", '"')], 22) == {
        "field_split": " ",
        "trim_value": '"',
        "line": 22,
    }
    assert csv_extraction_details(",", ["a", "b"], 23) == {"separator": ",", "columns": ["a", "b"], "line": 23}
    assert csv_column_details(",", "dst") == {"separator": ",", "column_name": "dst"}
    assert xml_line_details(24) == {"line": 24}
    assert xml_template_details("//HOST[%{i}]", "//HOST[*]") == {"template": "//HOST[%{i}]"}
    assert xml_template_details("//HOST", "//HOST") == {}
    assert loop_member_details(loop, upstream) == {
        "from_loop_item": loop.to_json(),
        "upstream_source": upstream.to_json(),
    }
    assert map_member_details(map_value, upstream) == {
        "from_map_member": map_value.to_json(),
        "upstream_source": upstream.to_json(),
    }
