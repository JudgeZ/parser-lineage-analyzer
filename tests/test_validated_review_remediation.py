from typing import get_args

import pytest

import parser_lineage_analyzer.cli as cli_module
from parser_lineage_analyzer import (
    DiagnosticRecord,
    Lineage,
    LineageStatus,
    OutputAnchor,
    QueryResult,
    QueryStatus,
    ReverseParser,
    SourceRef,
    SyntaxDiagnostic,
)
from parser_lineage_analyzer._analysis_members import _status_for_sources
from parser_lineage_analyzer._scanner import find_next_unquoted, strip_comments_keep_offsets
from parser_lineage_analyzer.cli import main
from parser_lineage_analyzer.config_parser import parse_config, parse_config_with_diagnostics
from parser_lineage_analyzer.model import QuerySemanticSummary
from parser_lineage_analyzer.parser import parse_code_with_diagnostics


def test_empty_regex_and_adjacent_brace_comment_are_scanned_correctly():
    code = r"""
    filter {
      if [message] =~ // {
        mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }//comment
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "conditional"
    assert list(result.mappings[0].conditions) == ["[message] =~ //"]
    assert not result.unsupported

    stripped = strip_comments_keep_offsets('filter { mutate { replace => {"a"=>"b"} }//comment\n }')
    assert "}//comment" not in stripped
    assert "}         \n" in stripped


def test_config_slash_comments_preserve_urls_and_xpath_but_allow_adjacent_comments():
    assert parse_config('replace => { "url" => http://example.com/path }') == [
        ("replace", [("url", "http://example.com/path")])
    ]
    assert parse_config('xpath => { //node => "node_token" }//comment') == [("xpath", [("//node", "node_token")])]


@pytest.mark.timeout(0.5)
def test_scanner_slash_candidates_are_linear_enough():
    text = (
        "filter {\n"
        + "\n".join(f'  mutate {{ replace => {{ "x{i}" => /no_close_{i} }} }}' for i in range(2000))
        + "\n}"
    )
    strip_comments_keep_offsets(text)


def test_reachable_else_if_runtime_condition_warning_survives_merge():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "x" => "a" } }
      } else if [dyn] =~ /foo.*/ {
        mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    summary = ReverseParser(code).analysis_summary()
    assert any(warning["code"] == "runtime_condition" for warning in summary["structured_warnings"])


def test_summary_strict_fails_on_unresolved_taints(tmp_path):
    parser_file = tmp_path / "unresolved.cbn"
    parser_file.write_text(
        'filter { mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{missing}" } } }',
        encoding="utf-8",
    )
    assert main([str(parser_file), "--summary", "--strict"]) == 3


def test_conditional_constant_destination_template_expands_to_concrete_fields():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "field" => "foo" } }
      } else {
        mutate { replace => { "field" => "bar" } }
      }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{field}" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    foo = ReverseParser(code).query("additional.fields.foo")
    bar = ReverseParser(code).query("additional.fields.bar")
    assert foo.status == "conditional"
    assert bar.status == "conditional"
    assert not any(warning["code"] == "dynamic_destination" for warning in foo.to_json().get("structured_warnings", []))
    assert list(foo.mappings[0].conditions) == ['[a] == "1"']
    assert list(bar.mappings[0].conditions) == ['NOT([a] == "1")']


def test_conditional_composed_template_value_resolves_to_concrete_branches():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "prefix" => "foo" } }
      } else {
        mutate { replace => { "prefix" => "bar" } }
      }
      mutate { replace => { "field" => "pre_%{prefix}" } }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{field}" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.pre_foo")
    assert result.status == "conditional"
    assert list(result.mappings[0].conditions) == ['[a] == "1"']
    assert not any(
        warning["code"] == "dynamic_destination" for warning in result.to_json().get("structured_warnings", [])
    )


def test_repeated_destination_placeholder_uses_one_branch_binding():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "field" => "foo" } }
      } else {
        mutate { replace => { "field" => "bar" } }
      }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{field}.%{field}" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    foo = rp.query("additional.fields.foo.foo")
    bar = rp.query("additional.fields.bar.bar")
    impossible = rp.query("additional.fields.foo.bar")
    assert foo.status == "conditional"
    assert bar.status == "conditional"
    assert list(foo.mappings[0].conditions) == ['[a] == "1"']
    assert list(bar.mappings[0].conditions) == ['NOT([a] == "1")']
    assert impossible.status == "unresolved"


def test_destination_template_skips_contradictory_branch_products():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "p" => "foo" "s" => "x" } }
      } else {
        mutate { replace => { "p" => "bar" "s" => "y" } }
      }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{p}.%{s}" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    assert rp.query("additional.fields.foo.x").status == "conditional"
    assert rp.query("additional.fields.bar.y").status == "conditional"
    assert rp.query("additional.fields.foo.y").status == "unresolved"
    assert rp.query("additional.fields.bar.x").status == "unresolved"


def test_destination_template_skips_products_contradicting_current_branch():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "p" => "foo" } }
      } else {
        mutate { replace => { "p" => "bar" } }
      }
      if [a] == "1" {
        mutate { replace => { "event.idm.read_only_udm.additional.fields.%{p}" => "then" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    assert rp.query("additional.fields.foo").status == "conditional"
    assert rp.query("additional.fields.bar").status == "unresolved"


def test_destination_template_skips_products_contradicting_inequality_fact():
    code = r"""
    filter {
      if [a] != "1" {
        mutate { replace => { "p" => "foo" } }
      } else {
        mutate { replace => { "p" => "bar" } }
      }
      if [a] == "2" {
        mutate { replace => { "event.idm.read_only_udm.additional.fields.%{p}" => "then" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    assert rp.query("additional.fields.foo").status == "conditional"
    assert rp.query("additional.fields.bar").status == "unresolved"


def test_dynamic_destination_branch_preserves_static_concrete_branch():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "field" => "foo" } }
      } else {
        mutate { replace => { "field" => "%{runtime_key}" } }
      }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{field}" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.foo")
    assert result.status == "dynamic"
    assert any(
        mapping.status == "conditional" and list(mapping.conditions) == ['[a] == "1"'] for mapping in result.mappings
    )
    assert any(
        mapping.status == "dynamic" and list(mapping.conditions) == ['NOT([a] == "1")'] for mapping in result.mappings
    )


def test_unchanged_real_branch_preserves_else_condition_after_token_change():
    code = r"""
    filter {
      mutate { replace => { "x" => "orig" } }
      if [a] == "1" {
        mutate { replace => { "x" => "then" } }
      } else {
        mutate { replace => { "z" => "other" } }
      }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.value" => "%{x}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.value")
    by_expr = {mapping.expression: list(mapping.conditions) for mapping in result.mappings}
    assert by_expr["then"] == ['[a] == "1"']
    assert by_expr["orig"] == ['NOT([a] == "1")']


def test_token_created_on_one_branch_is_unresolved_on_missing_branch_when_read_later():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "x" => "then" } }
      } else {
        mutate { replace => { "z" => "other" } }
      }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.value" => "%{x}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.value")

    assert result.status == "partial"
    assert any(mapping.status == "conditional" and mapping.expression == "then" for mapping in result.mappings)
    unresolved = [mapping for mapping in result.mappings if mapping.status == "unresolved"]
    assert len(unresolved) == 1
    assert list(unresolved[0].conditions) == ['NOT([a] == "1")']


def test_self_referential_template_summary_preserves_upstream_metadata():
    assignments = "\n".join(
        f'        mutate {{ add_field => {{ "ctx" => "%{{missing_{idx}}}" }} }}' for idx in range(16)
    )
    code = f"""
    filter {{
      if [outer] == "1" {{
{assignments}
        mutate {{ gsub => ["ctx", "x", "y"] }}
        mutate {{ replace => {{ "ctx" => "%{{ctx}}:tail" }} }}
      }}
    }}
    """
    lineage = ReverseParser(code).analyze().tokens["ctx"][0]

    assert lineage.status == "dynamic"
    assert list(lineage.conditions) == ['[outer] == "1"']
    assert "gsub(pattern=x, replacement=y)" in lineage.transformations
    assert "template_interpolation" in lineage.transformations
    assert any("mutate.gsub ctx /x/ -> y" in loc for loc in lineage.parser_locations)
    assert any("mutate.replace ctx <= %{ctx}:tail" in loc for loc in lineage.parser_locations)
    assert "Token was referenced before this analyzer could infer its extractor." in lineage.notes
    assert any("summarized after fanout threshold" in note for note in lineage.notes)
    assert {"unresolved_token", "template_fanout"} <= {taint.code for taint in lineage.taints}


def test_static_composed_destination_template_resolves_to_concrete_field():
    code = r"""
    filter {
      mutate { replace => { "prefix" => "foo" } }
      mutate { replace => { "field" => "pre_%{prefix}" } }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{field}" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.pre_foo")
    assert result.status == "constant"
    assert result.mappings[0].expression == "v"
    assert not any(
        warning["code"] == "dynamic_destination" for warning in result.to_json().get("structured_warnings", [])
    )


def test_date_bracket_target_resolves_through_normal_udm_query():
    code = r"""
    filter {
      mutate { replace => { "[event][time]" => "2024-01-02T03:04:05Z" } }
      date {
        match => ["[event][time]", "ISO8601"]
        target => "[event][idm][read_only_udm][metadata][event_timestamp]"
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.event_timestamp")
    assert result.status == "derived"
    assert any(transform.startswith("date(") for mapping in result.mappings for transform in mapping.transformations)


def test_transform_bracket_and_template_targets_use_destination_storage():
    base64_code = r"""
    filter {
      json { source => "message" }
      base64 { source => "ip_address" target => "[event][idm][read_only_udm][target][ip]" }
      mutate { merge => { "@output" => "event" } }
    }
    """
    base64_result = ReverseParser(base64_code).query("target.ip")
    assert base64_result.status == "derived"
    assert any(
        "base64_decode" in transform for mapping in base64_result.mappings for transform in mapping.transformations
    )

    url_code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "url_field" => "url" } }
      url_decode {
        source => "raw_url"
        target => "[event][idm][read_only_udm][target][%{url_field}]"
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    url_result = ReverseParser(url_code).query("target.url")
    assert url_result.status == "derived"
    assert any("url_decode" in mapping.transformations for mapping in url_result.mappings)
    assert not any(
        warning["code"] == "dynamic_destination" for warning in url_result.to_json().get("structured_warnings", [])
    )


@pytest.mark.parametrize(
    ("operation", "expected_transform"),
    [
        ('convert => { "[foo][bar]" => "integer" }', "convert(integer)"),
        ('lowercase => ["[foo][bar]"]', "lowercase"),
        ('uppercase => ["[foo][bar]"]', "uppercase"),
        ('gsub => ["[foo][bar]", "raw", "clean"]', "gsub(pattern=raw, replacement=clean)"),
        ('split => { "[foo][bar]" => "," }', "split(separator=',')"),
    ],
)
def test_mutate_in_place_transforms_store_normalized_bracket_refs(operation, expected_transform):
    code = f"""
    filter {{
      mutate {{ replace => {{ "[foo][bar]" => "raw" }} }}
      mutate {{ {operation} }}
      mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.value" => "%{{[foo][bar]}}" }} }}
      mutate {{ merge => {{ "@output" => "event" }} }}
    }}
    """
    result = ReverseParser(code).query("additional.fields.value")
    assert result.status == "derived"
    assert any(expected_transform in mapping.transformations for mapping in result.mappings)


def test_static_string_loop_replays_sequentially_for_scalar_replace():
    code = r"""
    filter {
      for x in ["a", "b"] {
        mutate { replace => { "event.idm.read_only_udm.additional.fields.value" => "%{x}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.value")
    assert result.status == "constant"
    assert [mapping.expression for mapping in result.mappings] == ["b"]


def test_static_string_loop_accumulates_append_style_assignments():
    code = r"""
    filter {
      for x in ["a", "b"] {
        mutate { add_field => { "event.idm.read_only_udm.additional.fields.value" => "%{x}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("additional.fields.value")
    assert result.status == "repeated"
    assert sorted(mapping.expression for mapping in result.mappings) == ["a", "b"]


def test_remove_field_tombstone_preserves_original_branch_conditions():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "x" => "foo" } }
      }
      mutate { remove_field => ["x"] }
    }
    """
    state = ReverseParser(code).analyze()
    assert state.tokens["x"][0].status == "removed"
    assert list(state.tokens["x"][0].conditions) == ['[a] == "1"']


def test_query_strict_fails_on_taints(tmp_path):
    parser_file = tmp_path / "dynamic.cbn"
    parser_file.write_text(
        'filter { mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "x" } } }',
        encoding="utf-8",
    )
    assert main([str(parser_file), "additional.fields.foo", "--strict"]) == 3


def test_multiline_regex_config_emits_malformed_config_diagnostic():
    code = """filter { grok { match => { "message" => /foo
bar/ } } }"""
    summary = ReverseParser(code).analysis_summary()
    assert any(warning["code"] == "malformed_config" for warning in summary["structured_warnings"])


def test_oniguruma_named_capture_and_unquoted_url_stay_supported():
    code = r"""
    filter {
      grok { match => { "message" => "(?<dst>[0-9.]+)" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact_capture"
    assert result.mappings[0].sources[0].capture_name == "dst"
    assert parse_config('replace => { "url" => http://example.com/path }') == [
        ("replace", [("url", "http://example.com/path")])
    ]


def test_conditional_constant_extractor_source_is_not_marked_dynamic():
    code = r"""
    filter {
      mutate { replace => { "payload" => "%{message}" } }
      if [a] == "1" {
        mutate { replace => { "src" => "message" } }
      } else {
        mutate { replace => { "src" => "payload" } }
      }
      grok { match => { "%{src}" => "%{IP:dst}" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "conditional"
    assert len(result.mappings) == 2
    assert not any(
        warning["code"] == "dynamic_extractor_source" for warning in result.to_json().get("structured_warnings", [])
    )


def test_statedump_is_visible_in_summary_warnings():
    summary = ReverseParser('filter { statedump { label => "debug" } }').analysis_summary()
    assert any(warning["code"] == "statedump" for warning in summary["structured_warnings"])


def test_drop_with_malformed_config_still_marks_path_dropped():
    state = ReverseParser('filter { drop { foo => { "a" => [ } } }').analyze()
    assert state.dropped
    assert any(warning.code == "malformed_config" for warning in state.structured_warnings)


def test_grok_type_suffix_is_not_part_of_capture_name():
    code = r"""
    filter {
      grok { match => { "message" => "%{IP:dst:int}" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact_capture"
    assert result.mappings[0].sources[0].capture_name == "dst"


def test_grok_alternative_captures_accumulate_for_same_token():
    code = r"""
    filter {
      grok { match => { "message" => ["%{IP:dst}", "%{HOSTNAME:dst}"] } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    patterns = sorted(src.pattern for mapping in result.mappings for src in mapping.sources)
    assert patterns == ["%{HOSTNAME:dst}", "%{IP:dst}"]


def test_sequential_grok_plugins_overwrite_same_capture_token():
    code = r"""
    filter {
      grok { match => { "message" => "%{IP:dst}" } }
      grok { match => { "message" => "%{HOSTNAME:dst}" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    patterns = [src.pattern for mapping in result.mappings for src in mapping.sources]
    assert patterns == ["%{HOSTNAME:dst}"]


def test_xml_xpath_alternatives_accumulate_for_same_token():
    code = r"""
    filter {
      xml { xpath => { "/a/ip" => "dst" "/a/host" => "dst" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    paths = sorted(src.path for mapping in result.mappings for src in mapping.sources)
    assert paths == ["/a/host", "/a/ip"]


def test_sequential_xml_plugins_overwrite_same_xpath_token():
    code = r"""
    filter {
      xml { xpath => { "/a/ip" => "dst" } }
      xml { xpath => { "/a/host" => "dst" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    paths = [src.path for mapping in result.mappings for src in mapping.sources]
    assert paths == ["/a/host"]


def test_uppercase_bare_merge_prefers_existing_token_before_enum_constant():
    code = r"""
    filter {
      grok { match => { "message" => "%{IP:IPADDR}" } }
      mutate { merge => { "event.idm.read_only_udm.target.ip" => "IPADDR" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact_capture"
    assert result.mappings[0].sources[0].capture_name == "IPADDR"


def test_bare_merge_typo_is_unresolved_not_constant():
    code = r"""
    filter {
      mutate { merge => { "event.idm.read_only_udm.target.ip" => "misstyped_token" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "unresolved"
    assert result.mappings[0].sources[0].kind == "unknown"
    assert any(warning["code"] == "unresolved_bare_token" for warning in result.to_json()["structured_warnings"])


def test_strict_enum_constant_detection_keeps_only_upper_snake_as_constant():
    enum_result = ReverseParser(
        'filter { mutate { merge => { "event.idm.read_only_udm.metadata.event_type" => "NETWORK_CONNECTION" } } }'
    ).query("metadata.event_type")
    assert enum_result.status == "constant"

    not_enum = ReverseParser(
        'filter { mutate { merge => { "event.idm.read_only_udm.metadata.event_type" => "A:1" } } }'
    ).query("metadata.event_type")
    assert not_enum.status == "unresolved"


def test_empty_destination_is_skipped_with_diagnostic():
    state = ReverseParser('filter { mutate { replace => { "" => "foo" } } }').analyze()
    assert "" not in state.tokens
    assert any(warning.code == "empty_destination" for warning in state.structured_warnings)


def test_array_self_merge_is_warned():
    state = ReverseParser(
        'filter { mutate { replace => { "x" => "a" "y" => "b" } } mutate { merge => { "x" => ["x", "y"] } } }'
    ).analyze()
    assert any(warning.code == "self_referential_merge" for warning in state.structured_warnings)


def test_query_status_types_are_exhaustive_and_partial_for_removed_live_mix():
    assert "partial" in get_args(QueryStatus)
    assert "partial" not in get_args(LineageStatus)
    result = QueryResult(
        "f",
        ["f"],
        [
            Lineage(status="removed", expression="f"),
            Lineage(status="exact", sources=[SourceRef(kind="raw_token", expression="x")], expression="x"),
        ],
    )
    assert result.status == "partial"

    # Deliberately pass an invalid ``LineageStatus`` literal to verify the
    # runtime fallback path (status reset to ``"unresolved"`` plus an
    # ``invalid_lineage_status`` diagnostic). ``# type: ignore[arg-type]`` is
    # the cleanest way to violate the ``Literal[...]`` constraint at one
    # call site without ``cast`` lying about the value.
    bad = QueryResult("f", ["f"], [Lineage(status="bogus")])  # type: ignore[arg-type]
    assert bad.status == "unresolved"
    assert bad.to_json()["diagnostics"][0]["code"] == "invalid_lineage_status"


def test_query_status_uses_deterministic_order_for_sampled_semantics():
    result = QueryResult(
        "f",
        ["f"],
        [],
        mappings_total=1,
        semantic_summary=QuerySemanticSummary(statuses=("constant", "exact_capture")),
    )

    assert result.status == "exact_capture"


def test_status_for_sources_preserves_homogeneous_source_statuses():
    assert (
        _status_for_sources([SourceRef(kind="constant", expression="a"), SourceRef(kind="constant", expression="b")])
        == "constant"
    )
    assert (
        _status_for_sources([SourceRef(kind="json_path", path="a"), SourceRef(kind="csv_column", column=1)]) == "exact"
    )
    assert (
        _status_for_sources([SourceRef(kind="constant", expression="a"), SourceRef(kind="json_path", path="a")])
        == "derived"
    )


def test_case_sensitive_plugins_keywords_and_mutate_operations():
    assert (
        ReverseParser('filter { Mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } } }')
        .query("target.ip")
        .status
        == "unresolved"
    )
    assert (
        ReverseParser('filter { mutate { REPLACE => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } } }')
        .query("target.ip")
        .status
        == "unresolved"
    )
    ast, _diagnostics = parse_code_with_diagnostics('filter { IF [x] == "y" { mutate { replace => { "a" => "b" } } } }')
    assert ast and ast[0].__class__.__name__ == "Unknown"


def test_config_decodes_common_escapes_and_preserves_invalid_escapes():
    parsed = parse_config(r'replace => { "x" => "a\fb\bc\vd\x0Ae\u000Af\xZZg\q" }')
    value = parsed[0][1][0][1]
    assert value == "a\fb\bc\vd\ne\nf\\xZZg\\q"


def test_unknown_config_key_comes_from_forbid_validation_but_known_config_continues():
    summary = ReverseParser('filter { json { sourc => "payload" } }').analysis_summary()
    assert any(warning["code"] == "unknown_config_key" for warning in summary["structured_warnings"])
    assert not any(warning["code"] == "config_validation" for warning in summary["structured_warnings"])


def test_analysis_summary_does_not_leak_mutable_extraction_details():
    rp = ReverseParser('filter { json { source => "message" } }')
    summary = rp.analysis_summary()
    summary["json_extractions"][0]["details"]["target"] = "MUTATED"
    assert rp.analyze().json_extractions[0].details["target"] is None


def test_public_types_are_exported():
    assert DiagnosticRecord.__name__ == "DiagnosticRecord"
    assert SyntaxDiagnostic(1, 2, "x").to_json() == {"line": 1, "column": 2, "message": "x"}
    assert OutputAnchor("event").to_json() == {"anchor": "event"}


def test_on_error_not_created_for_unsupported_or_drop_plugins():
    assert (
        "bad_unsupported"
        not in ReverseParser('filter { unsupported_custom_plugin { on_error => "bad_unsupported" } }').analyze().tokens
    )
    assert "bad_drop" not in ReverseParser('filter { drop { on_error => "bad_drop" } }').analyze().tokens


@pytest.mark.timeout(1.0)
def test_malformed_parser_frontend_is_bounded():
    parse_code_with_diagnostics("if\n" * 2000)
    parse_code_with_diagnostics("filter {\n" + ("mutate {\n" * 1200))


@pytest.mark.timeout(1.0)
def test_missing_brace_header_scans_are_indexed():
    code = "\n".join(f'if [field{i}] == "value"' for i in range(6000))
    ast, diagnostics = parse_code_with_diagnostics(code)
    assert len(ast) == 6000
    assert not diagnostics


@pytest.mark.timeout(1.5)
def test_recovery_batches_large_valid_tail():
    valid_tail = "\n".join(
        f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.x{i}" => "y" }} }}' for i in range(1000)
    )
    code = f"""
    filter {{
      mutate {{ replace => {{ "event.idm.read_only_udm.metadata.description" => "before" }} }}
      if [broken_syntax] == "true" {{
        mutate {{
          replace => {{
            "event.idm.read_only_udm.udm.field" => "lost"
          # missing closing braces for replace/mutate/if
    {valid_tail}
    }}
    """
    ast, diagnostics = parse_code_with_diagnostics(code)
    assert diagnostics
    assert len(ast) >= 1000


def test_public_unquoted_lookup_still_ignores_refs_comments_regex_and_brackets():
    text = 'if [a] in ["{"] and [b] =~ /{/ and [c] == "%{not_a_block}" { mutate {} } # {'
    assert find_next_unquoted(text, len("if"), "{") == text.index("{ mutate")


def test_nested_config_maps_return_diagnostic_instead_of_recursion_error():
    config = "a => " + "{ a => " * 500 + "1" + " }" * 500
    parsed, diagnostics = parse_config_with_diagnostics(config)
    assert parsed[0][0] == "__config_parse_error__"
    assert diagnostics
    assert "nesting depth" in diagnostics[0].message


def test_nested_on_error_blocks_emit_depth_warning():
    code = "filter { " + ("on_error { " * 70) + 'mutate { replace => { "x" => "y" } }' + (" }" * 70) + " }"
    summary = ReverseParser(code).analysis_summary()
    assert any(warning["code"] == "analysis_nesting_depth" for warning in summary["structured_warnings"])


def test_deep_valid_if_nesting_returns_diagnostic_instead_of_crashing():
    code = "filter { " + ('if [a] == "1" { ' * 300) + 'mutate { replace => { "x" => "y" } }' + (" }" * 300) + " }"
    summary = ReverseParser(code).analysis_summary()
    assert any(
        warning["code"] in {"parse_recovery", "analysis_nesting_depth"} for warning in summary["structured_warnings"]
    )


def test_on_error_body_parse_diagnostics_preserve_original_line_numbers():
    code = """filter {
  mutate { replace => { "a" => "b" } }


  on_error {
    if [x] == "y" {
      mutate { replace => { "z" => [ } }
    }
  }
}"""
    summary = ReverseParser(code).analysis_summary()
    assert any(
        warning["code"] == "malformed_config" and warning["parser_location"] == "line 7: mutate"
        for warning in summary["structured_warnings"]
    )


def test_dynamic_template_query_matches_dotted_placeholder_values():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.network.%{subnet}.ip" => "v" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("network.10.0.0.1.ip")
    assert result.status == "dynamic"
    assert result.mappings[0].expression == "v"


def test_reverse_parser_and_cli_reject_oversized_input(tmp_path, monkeypatch, capsys):
    with pytest.raises(ValueError):
        ReverseParser("abcd", max_parser_bytes=3)

    parser_file = tmp_path / "too_large.cbn"
    parser_file.write_text("abcd", encoding="utf-8")
    monkeypatch.setattr(cli_module, "MAX_PARSER_BYTES", 3)
    assert main([str(parser_file), "--summary"]) == 1
    assert "exceeds maximum parser size" in capsys.readouterr().err


def _lineage_for_branch_fanout_test(token: str, suffix: str) -> Lineage:
    return Lineage(
        status="exact",
        sources=[SourceRef(kind="constant", expression=f"{token}-{suffix}")],
        expression=f"{token}-{suffix}",
        parser_locations=[f"line 1: {token}.{suffix}"],
    )


def test_branch_lineage_fanout_warnings_are_emitted_in_sorted_token_order(monkeypatch):
    """Token-name iteration in branch merging must be sorted to keep diagnostic
    output byte-deterministic across Python processes / PYTHONHASHSEED values.

    Set iteration over strings is randomized per process, so when more than one
    token simultaneously triggers branch_lineage_fanout, the order of warnings,
    taints, and structured diagnostics would otherwise vary.
    """
    from parser_lineage_analyzer import _analysis_state
    from parser_lineage_analyzer._analysis_state import AnalyzerState, BranchRecord

    # Lower the fanout threshold so we can trigger the summarize-and-warn path
    # cheaply for multiple tokens at once.
    monkeypatch.setattr(_analysis_state, "MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES", 2)

    # Use enough tokens that an accidental match with set-iteration order is
    # statistically negligible across PYTHONHASHSEED values.
    token_names = [f"token_{name}" for name in ("zeta", "alpha", "mid", "epsilon", "kappa", "omicron", "tau", "delta")]

    state = AnalyzerState()
    original = AnalyzerState()
    branch_one = AnalyzerState()
    branch_two = AnalyzerState()

    for token in token_names:
        branch_one.tokens[token] = [_lineage_for_branch_fanout_test(token, f"a{i}") for i in range(3)]
        branch_one._dirty_tokens.add(token)
        branch_two.tokens[token] = [_lineage_for_branch_fanout_test(token, f"b{i}") for i in range(3)]
        branch_two._dirty_tokens.add(token)

    state.merge_branch_records(
        original,
        [
            BranchRecord(branch_one, ['[c] == "1"'], False),
            BranchRecord(branch_two, ['[c] == "2"'], False),
        ],
    )

    fanout_warnings = [w for w in state.warnings if "exceeded" in w]
    assert len(fanout_warnings) == len(token_names), fanout_warnings

    fanout_taints = [t for t in state.taints if t.code == "branch_lineage_fanout"]
    assert len(fanout_taints) == len(token_names)

    # Pull the token name out of each warning/taint and confirm they appear in
    # sorted order. Before the fix, this order followed a randomized set
    # iteration over `changed_tokens`.
    warning_tokens = [w.split("'")[1] for w in fanout_warnings]
    taint_tokens = [t.source_token for t in fanout_taints]

    assert warning_tokens == sorted(token_names)
    assert taint_tokens == sorted(token_names)

    fanout_diagnostics = [
        diagnostic.source_token for diagnostic in state.diagnostics if diagnostic.code == "branch_lineage_fanout"
    ]
    # Each token should produce one warning diagnostic and one taint
    # diagnostic, both interleaved in token-sort order.
    assert fanout_diagnostics == [token for token in sorted(token_names) for _ in range(2)]


def test_branch_no_op_lineage_fanout_warnings_are_emitted_in_sorted_token_order(monkeypatch):
    """The no-op conditioning path in `_condition_no_op_record` also iterates
    `changed_tokens`; its warning order must likewise be deterministic."""
    from parser_lineage_analyzer import _analysis_state
    from parser_lineage_analyzer._analysis_state import AnalyzerState, BranchRecord

    monkeypatch.setattr(_analysis_state, "MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES", 1)

    token_names = [f"token_{name}" for name in ("zeta", "alpha", "mid", "epsilon", "kappa", "omicron", "tau", "delta")]

    # Original state has each token with several pre-existing lineages; the
    # no-op branch will inherit them. The mutating branch changes all three
    # tokens, so each appears in `changed_tokens`. Then the no-op branch's
    # existing values exceed the conditioning threshold and trigger the
    # `branch_lineage_fanout` warning per token.
    original = AnalyzerState()
    for token in token_names:
        original.tokens[token] = [_lineage_for_branch_fanout_test(token, f"orig{i}") for i in range(5)]

    no_op_branch = AnalyzerState()
    for token in token_names:
        no_op_branch.tokens[token] = [_lineage_for_branch_fanout_test(token, f"orig{i}") for i in range(5)]

    mutating_branch = AnalyzerState()
    for token in token_names:
        mutating_branch.tokens[token] = [_lineage_for_branch_fanout_test(token, "new")]
        mutating_branch._dirty_tokens.add(token)

    state = AnalyzerState()
    state.merge_branch_records(
        original,
        [
            BranchRecord(no_op_branch, ['[c] == "no_op"'], True),
            BranchRecord(mutating_branch, ['[c] == "mutate"'], False),
        ],
    )

    no_op_warnings = [w for w in state.warnings if "branch no-op path" in w]
    assert len(no_op_warnings) == len(token_names), no_op_warnings

    no_op_taints = [t for t in state.taints if t.code == "branch_lineage_fanout" and "no-op path" in t.message]
    assert len(no_op_taints) == len(token_names)

    warning_tokens = [t.source_token for t in state.structured_warnings if "no-op path" in (t.message or "")]
    assert warning_tokens == sorted(token_names)

    taint_tokens = [t.source_token for t in no_op_taints]
    assert taint_tokens == sorted(token_names)
