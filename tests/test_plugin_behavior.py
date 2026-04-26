from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._scanner import strip_comments_keep_offsets
from parser_lineage_analyzer.config_parser import parse_config


def test_csv_column():
    code = r"""
    filter {
      csv { source => "message" separator => "," }
      mutate { replace => { "event.idm.read_only_udm.target.user.userid" => "%{column24}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.user.userid")
    assert result.mappings[0].sources[0].kind == "csv_column"
    assert result.mappings[0].sources[0].column == 24


def test_xml_xpath():
    code = r"""
    filter {
      xml {
        source => "message"
        xpath => {
          "/Event/System/Computer" => "hostname"
        }
      }
      mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{hostname}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("principal.hostname")
    assert result.mappings[0].sources[0].kind == "xml_xpath"
    assert result.mappings[0].sources[0].path == "/Event/System/Computer"


def test_base64_plugin_propagates_lineage_and_transform():
    code = r"""
    filter {
      json { source => "message" }
      base64 { source => "ip_address" target => "decoded_ip" encoding => "RawStandard" }
      mutate { merge => { "event.idm.read_only_udm.target.ip" => "%{decoded_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.mappings
    assert any(src.kind == "json_path" and src.path == "ip_address" for m in result.mappings for src in m.sources)
    assert any("base64_decode" in transform for m in result.mappings for transform in m.transformations)


def test_base64_scalar_fields_propagates_in_place_transform():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "raw_payload" => "%{payload}" } }
      base64 { fields => "raw_payload" }
      mutate { replace => { "event.idm.read_only_udm.network.application_protocol" => "%{raw_payload}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("network.application_protocol")
    warnings = result.to_json().get("structured_warnings", [])

    assert result.status == "derived"
    assert any(src.kind == "json_path" and src.path == "payload" for m in result.mappings for src in m.sources)
    assert any("base64_decode" in transform for m in result.mappings for transform in m.transformations)
    assert not any(warning["code"] == "config_validation" for warning in warnings)
    assert not any(warning["code"] == "missing_source_field" for warning in warnings)


def test_base64_duplicate_singleton_keys_warn_and_use_first_value():
    code = r"""
    filter {
      json { source => "message" }
      base64 {
        source => "ip_address"
        source => "other_ip"
        target => "decoded_ip"
      }
      mutate { merge => { "event.idm.read_only_udm.target.ip" => "%{decoded_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    warnings = result.to_json().get("structured_warnings", [])

    assert any(src.kind == "json_path" and src.path == "ip_address" for m in result.mappings for src in m.sources)
    assert not any(src.kind == "json_path" and src.path == "other_ip" for m in result.mappings for src in m.sources)
    assert any(
        warning["code"] == "duplicate_config_key" and warning["source_token"] == "source" for warning in warnings
    )


def test_base64_unknown_key_warns_and_invalid_shape_warns():
    typo_summary = ReverseParser('filter { base64 { source => "raw" targt => "decoded" } }').analysis_summary()
    assert any(
        warning["code"] == "unknown_config_key" and warning["source_token"] == "targt"
        for warning in typo_summary["structured_warnings"]
    )

    invalid_summary = ReverseParser('filter { base64 { source => ["raw"] target => "decoded" } }').analysis_summary()
    assert any(warning["code"] == "config_validation" for warning in invalid_summary["structured_warnings"])


def test_gsub_preserves_unknown_regex_escapes():
    code = r"""
    filter {
      json { source => "message" }
      mutate { gsub => ["version", "v\d+", "vX"] }
      mutate { replace => { "event.idm.read_only_udm.metadata.product_version" => "%{version}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.product_version")
    assert any("v\\d+" in transform for m in result.mappings for transform in m.transformations)
    assert not any("vd+" in transform for m in result.mappings for transform in m.transformations)


def test_mutate_copy_uses_source_key_destination_value_and_projects_descendants():
    code = r"""
    filter {
      mutate { replace => { "user.name" => "Alice" } }
      mutate { copy => { "user" => "event.idm.read_only_udm.target.user" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.user.name")

    assert result.status == "derived"
    assert any(src.kind == "constant" and src.expression == "Alice" for m in result.mappings for src in m.sources)
    assert any("copy" in transform for m in result.mappings for transform in m.transformations)
    assert any(
        "user.name -> event.idm.read_only_udm.target.user.name" in loc
        for m in result.mappings
        for loc in m.parser_locations
    )


def test_mutate_update_missing_destination_is_noop():
    code = r"""
    filter {
      mutate { update => { "event.idm.read_only_udm.metadata.description" => "NEW" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")

    assert result.status == "unresolved"
    assert not result.mappings


def test_mutate_update_replaces_existing_destination_and_existing_descendants():
    scalar_code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "OLD" } }
      mutate { update => { "event.idm.read_only_udm.metadata.description" => "NEW" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    scalar_result = ReverseParser(scalar_code).query("metadata.description")

    assert scalar_result.status == "constant"
    assert any(src.kind == "constant" and src.expression == "NEW" for m in scalar_result.mappings for src in m.sources)
    assert not any(
        src.kind == "constant" and src.expression == "OLD" for m in scalar_result.mappings for src in m.sources
    )

    descendant_code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.target.user.name" => "Alice" } }
      mutate { update => { "event.idm.read_only_udm.target.user" => { "name" => "Bob" } } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    descendant_result = ReverseParser(descendant_code).query("target.user.name")

    assert descendant_result.status == "constant"
    assert any(
        src.kind == "constant" and src.expression == "Bob" for m in descendant_result.mappings for src in m.sources
    )
    assert not any(
        src.kind == "constant" and src.expression == "Alice" for m in descendant_result.mappings for src in m.sources
    )


def test_ruby_plugin_add_field_decorator_populates_udm_field():
    code = r"""
    filter {
      ruby {
        code => "event.set(\"scratch\", \"ok\")"
        add_field => { "event.idm.read_only_udm.metadata.description" => "ruby decorated" }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")

    assert result.status == "constant"
    assert any(
        src.kind == "constant" and src.expression == "ruby decorated"
        for mapping in result.mappings
        for src in mapping.sources
    )


def test_translate_plugin_decorators_populate_fields_and_tags():
    code = r"""
    filter {
      translate {
        field => "event_code"
        destination => "translated_event"
        dictionary => { "100" => "login" }
        add_tag => ["translated"]
        add_field => { "event.idm.read_only_udm.metadata.description" => "translated event" }
      }
      if "translated" in [tags] {
        mutate { add_field => { "event.idm.read_only_udm.target.ip" => "10.0.0.1" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    parser = ReverseParser(code)
    description = parser.query("metadata.description")
    target_ip = parser.query("target.ip")

    assert description.status == "constant"
    assert any(
        src.kind == "constant" and src.expression == "translated event"
        for mapping in description.mappings
        for src in mapping.sources
    )
    assert target_ip.status == "conditional"
    assert any(src.kind == "constant" and src.expression == "10.0.0.1" for m in target_ip.mappings for src in m.sources)
    assert not any(warning.code == "unreachable_branch" for warning in target_ip.structured_warnings)


def test_aggregate_plugin_add_field_decorator_uses_ruby_path():
    code = r"""
    filter {
      aggregate {
        task_id => "%{id}"
        code => "map['seen'] = true"
        add_field => { "event.idm.read_only_udm.metadata.product_name" => "aggregated" }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.product_name")

    assert result.status == "constant"
    assert any(src.kind == "constant" and src.expression == "aggregated" for m in result.mappings for src in m.sources)


def test_clone_plugin_add_tag_decorator_enables_tag_condition_only_on_clone_branch():
    code = r"""
    filter {
      clone {
        clones => ["cloned_event"]
        add_tag => ["is_clone"]
      }
      if "is_clone" in [tags] {
        mutate { add_field => { "event.idm.read_only_udm.metadata.description" => "clone branch" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    parser = ReverseParser(code)
    result = parser.query("metadata.description")

    assert result.status == "conditional"
    assert any(
        src.kind == "constant" and src.expression == "clone branch" for m in result.mappings for src in m.sources
    )
    assert "is_clone" in parser.analyze().tag_state.possibly
    assert "is_clone" not in parser.analyze().tag_state.definitely
    assert not any(warning.code == "unreachable_branch" for warning in result.structured_warnings)


def test_url_decode_plugin_propagates_lineage():
    code = r"""
    filter {
      json { source => "message" }
      url_decode { source => "raw_url" target => "decoded_url" }
      mutate { replace => { "event.idm.read_only_udm.target.url" => "%{decoded_url}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.url")
    assert any(src.kind == "json_path" and src.path == "raw_url" for m in result.mappings for src in m.sources)
    assert any("url_decode" in transform for m in result.mappings for transform in m.transformations)
    assert not result.unsupported


def test_url_decode_scalar_fields_propagates_in_place_transform():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "raw_url" => "%{url}" } }
      url_decode { fields => "raw_url" }
      mutate { replace => { "event.idm.read_only_udm.target.url" => "%{raw_url}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.url")
    warnings = result.to_json().get("structured_warnings", [])

    assert result.status == "derived"
    assert any(src.kind == "json_path" and src.path == "url" for m in result.mappings for src in m.sources)
    assert any("url_decode" in transform for m in result.mappings for transform in m.transformations)
    assert not any(warning["code"] == "config_validation" for warning in warnings)
    assert not any(warning["code"] == "missing_source_field" for warning in warnings)


def test_url_decode_duplicate_singleton_keys_warn_and_use_first_value():
    code = r"""
    filter {
      json { source => "message" }
      url_decode {
        source => "raw_url"
        target => "decoded_url"
        target => "ignored_url"
      }
      mutate { replace => { "event.idm.read_only_udm.target.url" => "%{decoded_url}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.url")
    warnings = result.to_json().get("structured_warnings", [])

    assert result.status == "derived"
    assert any(
        warning["code"] == "duplicate_config_key" and warning["source_token"] == "target" for warning in warnings
    )


def test_url_decode_unknown_key_warns_and_invalid_shape_warns():
    typo_summary = ReverseParser('filter { url_decode { source => "raw" targt => "decoded" } }').analysis_summary()
    assert any(
        warning["code"] == "unknown_config_key" and warning["source_token"] == "targt"
        for warning in typo_summary["structured_warnings"]
    )

    invalid_summary = ReverseParser(
        'filter { url_decode { source => ["raw"] target => "decoded" } }'
    ).analysis_summary()
    assert any(warning["code"] == "config_validation" for warning in invalid_summary["structured_warnings"])


def test_date_match_map_is_rejected_as_missing_match_array():
    code = r"""
    filter {
      mutate { replace => { "event_time" => "2024-01-02T03:04:05Z" } }
      date {
        match => { "event_time" => "ISO8601" }
        target => "event.idm.read_only_udm.metadata.event_timestamp"
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    summary = ReverseParser(code).analysis_summary()

    assert any(warning["code"] == "missing_match_array" for warning in summary["structured_warnings"])


def test_dissect_plugin_extracts_fields():
    code = r"""
    filter {
      dissect { mapping => { "message" => "%{src_ip} %{dst_ip}" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact_capture"
    assert any(
        src.kind == "dissect_field" and src.capture_name == "dst_ip" for m in result.mappings for src in m.sources
    )
    assert not result.unsupported


def test_dissect_match_alias_extracts_without_unknown_key_warning():
    code = r"""
    filter {
      dissect { match => { "message" => "%{src_ip} %{dst_ip}" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    warnings = result.to_json().get("structured_warnings", [])

    assert result.status == "exact_capture"
    assert any(
        src.kind == "dissect_field" and src.capture_name == "dst_ip" for m in result.mappings for src in m.sources
    )
    assert not any(
        warning["code"] == "unknown_config_key" and warning["source_token"] == "match" for warning in warnings
    )


def test_json_target_scopes_inferred_paths():
    code = r"""
    filter {
      json { source => "message" target => "payload" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{payload.network.dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact"
    assert any(
        src.kind == "json_path" and src.source_token == "message" and src.path == "network.dst"
        for m in result.mappings
        for src in m.sources
    )


def test_json_target_does_not_expose_top_level_token():
    code = r"""
    filter {
      json { source => "message" target => "payload" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{network.dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "unresolved"


def test_csv_named_columns_are_sources():
    code = r"""
    filter {
      csv { source => "message" separator => "," columns => ["src", "dst", "action"] }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact"
    assert any(src.kind == "csv_column" and src.column == 2 for m in result.mappings for src in m.sources)


def test_config_regex_literal_hash_is_preserved_in_gsub():
    code = r"""
    filter {
      json { source => "message" }
      mutate { gsub => ["version", /v#\d+/, "vX"] }
      mutate { replace => { "event.idm.read_only_udm.metadata.product_version" => "%{version}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.product_version")
    assert any("/v#\\d+/" in transform for m in result.mappings for transform in m.transformations)


def test_parse_config_accepts_top_level_map_with_multiline_string():
    assert parse_config('{"key" => "multi\nline"}') == [("key", "multi\nline")]


def test_bare_xpath_key_is_not_stripped_as_comment():
    code = r"""
    filter {
      xml {
        xpath => {
          //node => "node_token"
        }
      }
      mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{node_token}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("principal.hostname")
    assert result.status == "exact"
    assert any(src.kind == "xml_xpath" and src.path == "//node" for m in result.mappings for src in m.sources)
    assert not result.unsupported


def test_trailing_slash_comment_with_equals_is_stripped():
    stripped = strip_comments_keep_offsets('filter { mutate { replace => {"a" => "b"} } //todo = fix\n }')

    assert "//todo = fix" not in stripped
    assert "             \n" in stripped


def test_bare_xpath_key_with_equal_is_not_stripped_as_comment():
    code = r"""
    filter {
      xml { xpath => { //node = "node_token" } }
      mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{node_token}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("principal.hostname")
    assert result.status == "exact"
    assert any(src.kind == "xml_xpath" and src.path == "//node" for m in result.mappings for src in m.sources)
    assert not result.unsupported


def test_config_regex_with_quantifier_parses_as_single_value():
    result = parse_config(r"match => /\d{1,3}\.\d{1,3}/")
    # Expect a single ('match', regex_value) tuple, not a parse error or split into atoms.
    assert len(result) == 1, f"expected single entry, got {result}"
    assert result[0][0] == "match"
    # The regex should be preserved as a single string value (not a bool flag).
    assert isinstance(result[0][1], str)
    assert result[0][1] == r"/\d{1,3}\.\d{1,3}/"


def test_config_regex_with_character_class_parses_as_single_value():
    result = parse_config("pattern => /[a-zA-Z0-9]+/")
    assert len(result) == 1
    assert result[0][0] == "pattern"
    assert isinstance(result[0][1], str)
    assert result[0][1] == "/[a-zA-Z0-9]+/"


def test_gsub_with_regex_quantifier_records_transform_without_malformed_warning():
    parser_text = r"""filter {
      mutate {
        gsub => [ "host", /\d{1,3}\.\d{1,3}/, "X.X" ]
      }
    }"""
    summary = ReverseParser(parser_text).analysis_summary()
    # Should NOT produce a "malformed" warning of any kind.
    structured = summary.get("structured_warnings", [])
    assert not any(w.get("code") == "malformed_config" for w in structured), (
        f"unexpected malformed_config warning: {structured}"
    )
    assert not any("malformed" in str(w).lower() for w in summary.get("warnings", [])), (
        f"unexpected malformed warning: {summary.get('warnings')}"
    )
