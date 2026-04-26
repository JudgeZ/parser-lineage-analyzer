"""Hand-written rich-lineage assertions for migrated legacy fixtures.

These tests cover lineage shape invariants (specific source kinds, expressions,
condition strings, transformation chains) that the sidecar contract can't
express. The fixtures themselves live under
``tests/fixtures/test_corpus/{baseline,expected}/`` alongside the rest of the
corpus; this file replaces the old ``tests/test_fixtures.py`` which loaded
from the now-removed ``tests/fixtures/*.cbn`` flat directory.

Sidecars next to each fixture handle the cheap invariants
(``must_have_warning_codes``, ``must_resolve_fields``, ``must_have_unsupported``);
the assertions here are the expensive ones that are easier to read as Python.
"""

from __future__ import annotations

from pathlib import Path

from parser_lineage_analyzer import ReverseParser

CORPUS = Path(__file__).parent / "fixtures" / "test_corpus"


def _load(bucket: str, stem: str) -> ReverseParser:
    return ReverseParser((CORPUS / bucket / f"{stem}.cbn").read_text(encoding="utf-8"))


def test_breaker_slash_comment_drop_and_nested_interpolation():
    rp = _load("baseline", "test_breaker_slash_comment_drop")
    summary = rp.analysis_summary()
    assert not any("unparsed statement" in item for item in summary["unsupported"])

    hostname = rp.query("target.hostname")
    assert hostname.status == "conditional"
    assert hostname.mappings[0].sources[0].expression == "host1"

    dropped_ip = rp.query("target.ip")
    assert dropped_ip.status == "unresolved"

    mac = rp.query("target.mac")
    assert mac.status == "dynamic"
    assert any(src.kind == "dynamic_reference" for m in mac.mappings for src in m.sources)


def test_breaker_escaped_quotes_in_condition_and_config_string():
    rp = _load("baseline", "test_breaker_escaped_quotes")
    ip = rp.query("target.ip")
    assert ip.status == "conditional"
    assert ip.mappings[0].sources[0].expression == "4.4.4.4"
    assert any('escaped \\" quote' in cond for m in ip.mappings for cond in m.conditions)

    host = rp.query("target.hostname")
    assert host.status == "constant"
    assert host.mappings[0].sources[0].expression == 'host with " quote'


def test_breaker_escaped_terminal_backslash_does_not_eat_following_block():
    rp = _load("baseline", "test_breaker_terminal_backslash")
    ip = rp.query("target.ip")
    mac = rp.query("target.mac")
    assert ip.status == "constant"
    assert ip.mappings[0].sources[0].expression.endswith("\\")
    assert mac.status == "constant"
    assert mac.mappings[0].sources[0].expression == "00:00:00:00:00:00"


def test_corner_cases_expected_unsupported_only():
    rp = _load("expected", "test_corner_cases_unsupported")
    summary = rp.analysis_summary()
    assert len(summary["unsupported"]) == 2
    assert any("some_weird_plugin" in item for item in summary["unsupported"])
    assert any("weird_mutate" in item for item in summary["unsupported"])
    assert not any("unparsed statement" in item for item in summary["unsupported"])

    mac = rp.query("target.mac")
    assert mac.status == "conditional"
    assert {'[a] == "1"', '[b] == "2"', '[c] == "3"'} <= set(mac.mappings[0].conditions)


def test_dissect_base64_field_mode_and_url_decode_chain():
    rp = _load("baseline", "test_dissect_base64_chain")
    protocol = rp.query("network.application_protocol")
    assert protocol.status == "conditional"
    assert any(
        src.kind == "dissect_field" and src.capture_name == "enc_payload"
        for m in protocol.mappings
        for src in m.sources
    )
    transforms = [t for m in protocol.mappings for t in m.transformations]
    assert any("base64_decode" in t for t in transforms)
    assert "url_decode" in transforms
    assert not protocol.warnings


def test_json_array_loop_fixture_outputs_loop_item_category():
    rp = _load("baseline", "test_json_array_loop_outputs_loop_item_category")
    result = rp.query("security_result.category")
    assert result.status == "conditional"
    assert any(src.kind == "loop_item" and src.path == "tags[*]" for m in result.mappings for src in m.sources)
    assert any("for item in tags" in cond for m in result.mappings for cond in m.conditions)


def test_high_complexity_fixture_core_lineage():
    rp = _load("expected", "test_high_complexity_core_lineage")
    target_url = rp.query("event2.idm.read_only_udm.target.url")
    assert target_url.status == "conditional"
    assert any(
        src.kind == "json_path" and src.path == "data.encoded_url" for m in target_url.mappings for src in m.sources
    )
    assert any("base64_decode" in t for m in target_url.mappings for t in m.transformations)
    assert any("url_decode" in t for m in target_url.mappings for t in m.transformations)

    category = rp.query("security_result.category")
    constants = {src.expression for m in category.mappings for src in m.sources if src.kind == "constant"}
    assert {"SOFTWARE_MALICIOUS", "NETWORK_SUSPICIOUS"} <= constants


def test_trip_up_multiline_regex_inline_comments_bare_path_and_indirect_dissect():
    rp = _load("expected", "test_trip_up_multiline_regex")
    summary = rp.analysis_summary()
    assert not summary["unsupported"]
    assert any("dissect indirect field" in warning for warning in summary["warnings"])

    ip = rp.query("target.ip")
    assert ip.status == "conditional"
    assert ip.mappings[0].sources[0].expression == "1.1.1.1"
    assert any("multi line regex" in cond for m in ip.mappings for cond in m.conditions)

    action = rp.query("security_result.action")
    assert action.status == "conditional"
    assert action.mappings[0].sources[0].expression == "ALLOW"
    assert not any("unparsed statement" in item for item in action.unsupported)

    path = rp.query("target.file.full_path")
    assert path.status == "constant"
    assert path.mappings[0].sources[0].expression == "/var/log/syslog"

    dynamic = rp.query("event.idm.read_only_udm.%{parent_%{child_token}}")
    assert dynamic.status == "dynamic"

    # The indirect dissect placeholder &{dynamic_key} should not create a fake literal token.
    assert "dynamic_key" not in rp.state.tokens


def test_trip_up_2_mutate_add_update_on_error_and_bracket_refs():
    rp = _load("expected", "test_trip_up_2_mutate_ordering")
    summary = rp.analysis_summary()
    assert not summary["unsupported"]

    ip = rp.query("target.ip")
    assert ip.mappings
    assert ip.mappings[0].sources[0].kind == "unknown"
    assert ip.mappings[0].sources[0].source_token == "src_ip"

    port = rp.query("target.port")
    assert port.status == "constant"
    assert port.mappings[0].sources[0].expression == "443"

    timestamp = rp.query("metadata.event_timestamp")
    assert len(timestamp.mappings) == 2
    assert any("NOT(on_error)" in cond for m in timestamp.mappings for cond in m.conditions)
    assert any("on_error" in cond for m in timestamp.mappings for cond in m.conditions)
    assert any(m.sources and m.sources[0].expression == "1970-01-01T00:00:00Z" for m in timestamp.mappings)

    action = rp.query("security_result.action")
    assert action.status == "constant"
    assert action.mappings[0].sources[0].expression == "BLOCK"

    renamed = rp.query("new.field")
    assert renamed.mappings
    assert renamed.mappings[0].sources[0].source_token == "old_field"


def test_trip_up_3_array_output_array_merge_and_object_replace():
    rp = _load("baseline", "test_trip_up_3_array_output_array_merge")
    summary = rp.analysis_summary()
    anchors = {a["anchor"] for a in summary["output_anchors"]}
    assert anchors == {"event1", "event2"}
    assert not summary["unsupported"]

    ip = rp.query("target.ip")
    assert len(ip.mappings) == 2
    assert {m.sources[0].source_token for m in ip.mappings} == {"ip1", "ip2"}

    obj = rp.query("my_udm_object")
    assert obj.status == "derived"
    assert any(src.kind == "object_literal" for m in obj.mappings for src in m.sources)

    child = rp.query("my_udm_object.child_key")
    assert child.status == "constant"
    assert child.mappings[0].sources[0].expression == "nested_value"


def test_trip_up_4_json_array_target_warns_and_does_not_self_infer():
    rp = _load("expected", "test_trip_up_4_json_array_target")
    summary = rp.analysis_summary()
    assert any("json target must be a scalar" in warning for warning in summary["warnings"])
    assert rp.query("target1.ip").status == "unresolved"
    assert rp.query("target2.ip").status == "unresolved"


def test_trip_up_5_nested_date_base64_map_extra_loop_vars_and_malformed_gsub():
    rp = _load("expected", "test_trip_up_5_loop_vars_malformed_gsub")
    summary = rp.analysis_summary()
    assert any("loop declares 3 variables" in warning for warning in summary["warnings"])
    assert any("malformed gsub array" in warning for warning in summary["warnings"])

    ts = rp.query("metadata.event_timestamp")
    assert any("date(ISO8601, UNIX)" in transform for m in ts.mappings for transform in m.transformations)

    encoded = rp.query("encoded_payload")
    assert encoded.mappings
    assert any("base64_decode" in transform for m in encoded.mappings for transform in m.transformations)

    ip = rp.query("target.ip")
    assert ip.mappings
    assert any(src.kind == "loop_item" and src.path == "target_array[*]" for m in ip.mappings for src in m.sources)

    dns = rp.query("network.dns.answers.data")
    assert dns.status == "unresolved"


def test_mega_fixture_lalr_and_analyzer_complete_without_unparsed_statements():
    rp = _load("challenge", "test_mega_parser_perf_budget")
    summary = rp.analysis_summary()
    assert not summary["unsupported"]
    assert "event.idm.read_only_udm.security_result.action" in summary["udm_fields"]
    action = rp.query("security_result.action")
    assert action.mappings
    assert len(action.mappings) >= 100
