from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._scanner import find_next_unquoted, strip_comments_keep_offsets
from parser_lineage_analyzer.cli import main
from parser_lineage_analyzer.config_parser import parse_config
from parser_lineage_analyzer.parser import parse_code_with_diagnostics
from parser_lineage_analyzer.render import render_text


def test_malformed_config_warns_and_strict_fails(tmp_path):
    code = r"""
    filter {
      json { source => "message" target => ["payload" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "unresolved"
    assert any("config parse failure" in warning for warning in result.warnings)
    assert not any(src.kind == "json_path" for m in result.mappings for src in m.sources)

    parser_file = tmp_path / "bad.cbn"
    parser_file.write_text(code, encoding="utf-8")
    assert main([str(parser_file), "target.ip", "--strict"]) == 3


def test_no_else_retained_value_gets_false_branch_condition():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.security_result.action" => "UNKNOWN" } }
      if [a] == "1" {
        mutate { replace => { "event.idm.read_only_udm.security_result.action" => "ALLOW" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("security_result.action")
    by_value = {m.sources[0].expression: set(m.conditions) for m in result.mappings}
    assert by_value["ALLOW"] == {'[a] == "1"'}
    assert by_value["UNKNOWN"] == {'NOT([a] == "1")'}


def test_conditional_drop_warning_survives_and_gates_following_assignments():
    code = r"""
    filter {
      if [drop_me] == "1" { drop { } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    summary = rp.analysis_summary()
    assert any("drop parser may drop events" in warning for warning in summary["warnings"])
    result = rp.query("target.ip")
    assert any("drop parser may drop events" in warning for warning in result.warnings)
    assert list(result.mappings[0].conditions) == ['NOT([drop_me] == "1")']


def test_missing_extractor_sources_are_unresolved_not_exact():
    cases = [
        (
            r"""filter {
              grok { match => { "payload" => "%{IP:dst}" } }
              mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
              mutate { merge => { "@output" => "event" } }
            }""",
            "target.ip",
        ),
        (
            r"""filter {
              dissect { mapping => { "payload" => "%{dst}" } }
              mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
              mutate { merge => { "@output" => "event" } }
            }""",
            "target.ip",
        ),
        (
            r"""filter {
              xml { source => "payload" xpath => { "/host" => "host" } }
              mutate { replace => { "event.idm.read_only_udm.target.hostname" => "%{host}" } }
              mutate { merge => { "@output" => "event" } }
            }""",
            "target.hostname",
        ),
        (
            r"""filter {
              csv { source => "payload" columns => ["dst"] }
              mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
              mutate { merge => { "@output" => "event" } }
            }""",
            "target.ip",
        ),
    ]
    for code, query in cases:
        result = ReverseParser(code).query(query)
        assert result.status == "unresolved"
        assert any("source token was not resolved" in warning for warning in result.warnings)


def test_rename_normalizes_and_removes_source_descendants():
    code = r"""
    filter {
      mutate { replace => { "old.field" => "x" "old.other" => "y" } }
      mutate { rename => { "[old][field]" => "event.idm.read_only_udm.target.hostname" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code, dialect="logstash")
    state = rp.analyze()
    assert "old.field" not in state.tokens
    assert "old.other" in state.tokens
    assert rp.query("target.hostname").status == "derived"

    parent_code = r"""
    filter {
      mutate { replace => { "old.field" => "x" "old.other" => "y" } }
      mutate { rename => { "old" => "event.idm.read_only_udm.target" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    parent_state = ReverseParser(parent_code).analyze()
    assert not any(token == "old" or token.startswith("old.") for token in parent_state.tokens)


def test_duplicate_match_entries_and_logstash_named_captures_are_processed():
    code = r"""
    filter {
      grok {
        match => { "message" => "%{IP:dst1}" }
        match => { "message" => "(?<dst2>\d+\.\d+\.\d+\.\d+)" }
      }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst2}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact_capture"
    assert result.mappings[0].sources[0].kind == "regex_capture"
    assert result.mappings[0].sources[0].capture_name == "dst2"


def test_duplicate_xml_and_dissect_mappings_are_processed_in_order():
    xml_code = r"""
    filter {
      xml {
        xpath => { "/first" => "first_host" }
        xpath => { "/second" => "second_host" }
      }
      mutate { replace => { "event.idm.read_only_udm.target.hostname" => "%{second_host}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    xml_result = ReverseParser(xml_code).query("target.hostname")
    assert xml_result.status == "exact"
    assert xml_result.mappings[0].sources[0].path == "/second"

    dissect_code = r"""
    filter {
      dissect {
        mapping => { "message" => "%{first}" }
        mapping => { "message" => "%{second}" }
      }
      mutate { replace => { "event.idm.read_only_udm.target.hostname" => "%{second}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    dissect_result = ReverseParser(dissect_code).query("target.hostname")
    assert dissect_result.status == "exact_capture"
    assert dissect_result.mappings[0].sources[0].capture_name == "second"


def test_duplicate_singleton_extractor_options_warn():
    code = r"""
    filter {
      json {
        source => "message"
        source => "payload"
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    summary = ReverseParser(code).analysis_summary()
    assert any("duplicate singleton config key 'source'" in warning for warning in summary["warnings"])


def test_template_fanout_is_capped_and_reported_dynamic():
    add_fields = "\n".join(f'add_field => {{ "k{i}" => "A{i}" "k{i}" => "B{i}" }}' for i in range(11))
    refs = "".join(f"%{{k{i}}}" for i in range(11))
    code = f'''
    filter {{
      mutate {{
        {add_fields}
      }}
      mutate {{ replace => {{ "event.idm.read_only_udm.metadata.description" => "{refs}" }} }}
      mutate {{ merge => {{ "@output" => "event" }} }}
    }}
    '''
    result = ReverseParser(code).query("metadata.description")
    assert result.status == "dynamic"
    assert any("template interpolation has" in warning for warning in result.warnings)


def test_static_string_loop_expands_destination_template():
    code = r"""
    filter {
      for key in ["src", "dst"] {
        mutate { replace => { "event.idm.read_only_udm.network.%{key}" => "x" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    assert rp.query("network.src").status == "constant"
    assert rp.query("network.dst").status == "constant"
    assert rp.query("network.%{key}").status == "unresolved"


def test_dissect_append_records_derived_append_lineage():
    code = r"""
    filter {
      dissect { mapping => { "message" => "%{+ts} %{+ts} %{host}" } }
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "%{ts}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    assert result.status == "derived"
    assert len(result.mappings[0].sources) == 2
    assert "dissect_append" in result.mappings[0].transformations


def test_config_urls_multiline_regex_and_python_scanner():
    assert parse_config('replace => { "url" => http://example.com/path }') == [
        ("replace", [("url", "http://example.com/path")])
    ]
    code = r"""
    filter {
      if [message] =~ /multi
    line regex/ {
        mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    assert ReverseParser(code).query("target.ip").status == "conditional"
    assert "http://example.com/path" in strip_comments_keep_offsets(
        'mutate { replace => { "url" => http://example.com/path } }'
    )


def test_interpolation_braces_do_not_confuse_loop_header_scanner():
    text = "for dyn_key, dyn_val in %{unknown_json_payload} {"
    assert find_next_unquoted(text, len("for"), "{") == text.rfind("{")


def test_parse_recovery_preserves_later_balanced_statements():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "before" } }
      if [broken_syntax] == "true" {
        mutate {
          replace => {
            "event.idm.read_only_udm.udm.field" => "lost"
          # missing closing braces for replace/mutate/if
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
    }
    """
    ast, diagnostics = parse_code_with_diagnostics(code)
    assert diagnostics
    assert len(ast) >= 2
    rp = ReverseParser(code)
    assert rp.query("target.ip").mappings[0].expression == "1.1.1.1"
    assert any("parse recovery skipped malformed statement" in item for item in rp.analysis_summary()["unsupported"])


def test_compact_unsupported_warning_catalog_covers_representative_codes():
    code = r"""
    filter {
      unsupported_custom_plugin { url => "https://example.invalid" }
      mutate { weird_mutate => ["message"] }
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{runtime_key}" => "v" } }
      mutate { gsub => [ "message", "(foo)", "\1" ] }
      for a, b, c in ["x"] {
        mutate { replace => { "too_many_loop_vars" => "x" } }
      }
      json { source => "missing_json_source" unknown_json_key => "x" }
      json { source => ["not", "scalar"] }
      mutate { replace => { "broken" => } }
      mutate {
        replace => {
          "event.idm.read_only_udm.udm.field" => "lost"
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
    }
    """
    summary = ReverseParser(code).analysis_summary()
    codes = {warning["code"] for warning in summary["structured_warnings"]}

    assert {
        "unsupported_plugin",
        "unknown_config_key",
        "unsupported_mutate_operation",
        "dynamic_destination",
        "loop_variables",
        "gsub_backreference",
        "parse_recovery",
        "malformed_config",
        "unresolved_extractor_source",
    } <= codes


def test_coalesced_unresolved_extractor_sources_still_fail_strict(tmp_path):
    lines = ["filter {"]
    for i in range(150):
        lines.append(f'  json {{ source => "missing_json_source_{i}" }}')
    lines.append("}")
    parser_file = tmp_path / "coalesced_unresolved_sources.cbn"
    parser_file.write_text("\n".join(lines), encoding="utf-8")

    assert main([str(parser_file), "target.ip", "--strict"]) == 3


def test_taints_are_exposed_in_summary_json_and_text():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "%{missing_value}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    summary = rp.analysis_summary()
    assert any(taint["code"] == "dynamic_destination" for taint in summary["taints"])
    assert any(taint["code"] == "unresolved_token" for taint in summary["taints"])

    result = rp.query("additional.fields.foo")
    payload = result.to_json()
    assert any("taints" in mapping for mapping in payload["mappings"])
    rendered = render_text(result)
    assert "taints:" in rendered
    assert "dynamic_destination" in rendered


def test_pydantic_invalid_extractor_config_downgrades_inference():
    code = r"""
    filter {
      csv {
        source => "message"
        columns => "not-an-array"
      }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{column1}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    summary = rp.analysis_summary()
    assert any("csv config validation failure" in warning for warning in summary["warnings"])
    assert any(taint["code"] == "invalid_config" for taint in summary["taints"])

    result = rp.query("target.ip")
    assert result.status == "unresolved"
    assert not any(src.kind == "csv_column" for mapping in result.mappings for src in mapping.sources)


def test_repeatable_configs_still_preserve_order_with_pydantic_validation():
    code = r"""
    filter {
      grok {
        match => { "message" => "%{IP:first_ip}" }
        match => { "message" => "%{IP:second_ip}" }
      }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{second_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact_capture"
    assert result.mappings[0].sources[0].capture_name == "second_ip"


def test_limited_literal_regex_reasoning_skips_contradictory_branch():
    code = r"""
    filter {
      if [kind] == "foo" {
        if [kind] =~ /^bar$/ {
          mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
        }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    summary = rp.analysis_summary()
    assert any("contradicts prior literal branch facts" in warning for warning in summary["warnings"])
    assert any(taint["code"] == "unreachable_branch" for taint in summary["taints"])
    assert rp.query("target.ip").status == "unresolved"


def test_literal_regex_without_contradiction_remains_conditional():
    code = r"""
    filter {
      if [kind] =~ /^foo$/ {
        mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "conditional"
    assert list(result.mappings[0].conditions) == ["[kind] =~ /^foo$/"]
    assert not any("dynamic regex" in warning for warning in result.warnings)


def test_complex_regex_is_symbolic_not_pruned():
    code = r"""
    filter {
      if [kind] =~ /foo.*/ {
        mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    result = rp.query("target.ip")
    assert result.status == "conditional"
    assert any("dynamic regex" in warning for warning in result.warnings)
    assert any(taint["code"] == "runtime_condition" for taint in rp.analysis_summary()["taints"])


def test_io_block_elif_else_carry_prior_negations_in_conditions():
    """IO routing under `if/else if/else` must accumulate prior NOT() clauses
    on each subsequent branch — mirrors `_exec_if`'s prior_negations tracking
    so a query like "which sink fires when [a]==\"2\"?" disambiguates the
    elif sink from the else sink instead of returning both."""
    code = r"""
    output {
      if [a] == "1" {
        file { path => "/a" }
      } else if [a] == "2" {
        file { path => "/b" }
      } else {
        file { path => "/c" }
      }
    }
    """
    state = ReverseParser(code).analyze()
    by_path = {
        dict(a.config_summary).get("path"): a.conditions
        for a in state.io_anchors
        if a.kind == "output" and a.plugin == "file"
    }
    # then-branch: just the if condition
    assert by_path["/a"] == ('[a] == "1"',)
    # elif-branch: prior NOT(if) + the elif condition
    assert by_path["/b"] == ('NOT([a] == "1")', '[a] == "2"')
    # else-branch: ALL prior NOT() clauses
    assert by_path["/c"] == ('NOT([a] == "1")', 'NOT([a] == "2")')


def test_remove_field_of_unwritten_field_does_not_inject_phantom_token():
    """C2: ``mutate { remove_field => [...] }`` must NOT manufacture a UDM
    field for a name the pipeline never wrote. Previously the analyzer
    inserted a ``removed`` tombstone at ``state.tokens[name]`` even when the
    name had no prior lineage and no descendants, surfacing the phantom in
    ``list_udm_fields()`` / ``analysis_summary()['udm_fields']``. The fix
    routes the no-op into a structured ``noop_remove_field`` warning instead
    so consumers see the diagnostic without polluting the UDM-field set."""
    code = r"""
    filter {
      mutate { remove_field => ["event.idm.read_only_udm.metadata.fictional_field"] }
    }
    """
    rp = ReverseParser(code)
    summary = rp.analysis_summary()

    # No phantom field surfaced.
    assert summary["udm_fields"] == []
    assert rp.list_udm_fields() == []

    # The no-op is still surfaced as a structured warning so it isn't lost.
    codes = [warning["code"] for warning in summary["structured_warnings"]]
    assert "noop_remove_field" in codes
    assert any("fictional_field" in warning and "nothing to remove" in warning for warning in summary["warnings"])

    # query() of the unwritten name returns unresolved (no removed tombstone).
    assert rp.query("metadata.fictional_field").status == "unresolved"


def test_remove_field_of_written_field_still_emits_removed_lineage():
    """C2 sanity: a real removal — the field WAS written earlier — must
    still produce a ``removed`` tombstone so ``query()`` can report the
    lifecycle. Only the no-prior, no-descendants path was changed."""
    code = r"""
    filter {
      mutate { replace => { "foo" => "bar" } }
      mutate { remove_field => ["foo"] }
    }
    """
    state = ReverseParser(code).analyze()
    assert state.tokens["foo"][0].status == "removed"


def test_remove_field_with_descendants_still_cascades():
    """C2 sanity: removing a parent token must still cascade ``removed`` to
    every descendant. The bug fix only suppressed the phantom-tombstone
    insertion when both the field AND its descendants were absent."""
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }
      mutate { remove_field => ["event.idm.read_only_udm.target"] }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "removed"


def test_on_error_appends_lineage_instead_of_clobbering_prior_token():
    """C4: ``on_error => "my_flag"`` must preserve any lineage previously
    written to ``my_flag`` instead of overwriting it. Before the fix, a
    prior ``mutate { replace => { my_flag => "important_data" } }`` was
    silently dropped, leaving only the synthetic ``error_flag`` source."""
    code = r"""
    filter {
      mutate { replace => { "my_flag" => "important_data" } }
      json { source => "message" on_error => "my_flag" }
    }
    """
    result = ReverseParser(code).query("my_flag")

    source_kinds = {src.kind for m in result.mappings for src in m.sources}
    expressions = {src.expression for m in result.mappings for src in m.sources}
    # Both the success-path constant AND the on_error sentinel survive.
    assert "constant" in source_kinds
    assert "error_flag" in source_kinds
    assert "important_data" in expressions


def test_mutate_duplicate_keys_warning_uses_last_write_wording():
    """C3: mutate map ops are last-write-wins (replace/update/add_field/copy/
    rename/convert) or append-all (merge), NOT first-wins. The warning text
    must reflect that — the previous "using the first value" message was
    inherited from the extractor singleton helper and was wrong for mutate."""
    code = r"""
    filter {
      mutate {
        replace => {
          "foo" => "first"
          "foo" => "second"
        }
      }
    }
    """
    summary = ReverseParser(code).analysis_summary()
    mutate_warnings = [w for w in summary["warnings"] if "mutate.replace" in w]
    assert mutate_warnings, "expected a mutate.replace duplicate-key warning"
    text = mutate_warnings[0]
    assert "duplicate map key 'foo'" in text
    assert "keeping the last value" in text
    assert "appending all values (merge)" in text
    # Make sure the misleading old wording is gone for mutate.
    assert "using the first value" not in text
    # The extractor "singleton" qualifier is also wrong for mutate map ops
    # (e.g. ``merge`` legitimately appends every duplicate value).
    assert "singleton" not in text
    # And the structured code must distinguish mutate from extractor singletons
    # so consumers grouping diagnostics by ``code`` see the right semantics.
    structured = ReverseParser(code).analysis_summary()["structured_warnings"]
    mutate_codes = {w["code"] for w in structured if "mutate.replace" in w["message"]}
    assert mutate_codes == {"duplicate_mutate_map_key"}, mutate_codes


def test_extractor_duplicate_keys_keep_first_value_wording():
    """C3 sanity: the original ``duplicate_config_key_warning`` callers
    (extractors / transforms like ``json``, ``base64``, ``url_decode``)
    legitimately keep the first value, so their warning text must keep the
    "using the first value" phrasing — only the mutate caller switched."""
    code = r"""
    filter {
      json {
        source => "message"
        source => "payload"
      }
    }
    """
    summary = ReverseParser(code).analysis_summary()
    json_warnings = [w for w in summary["warnings"] if "json " in w and "duplicate singleton config key 'source'" in w]
    assert json_warnings, "expected a json duplicate-key warning"
    assert "using the first value" in json_warnings[0]
    # Mutate's last-value text must not leak into the extractor message.
    assert "keeping the last value" not in json_warnings[0]


def test_syslog_pri_negative_literal_falls_through_to_symbolic():
    """C5: PRI is unsigned 0-191 per RFC 3164 / 5424. The previous literal
    detection (``lstrip("-").isdigit()``) accepted ``-13`` and then Python's
    signed bitwise ops produced wrong concrete labels (``(-13) & 7 == 3``
    => "err"). After the fix, negative literals fall through to the symbolic
    path so no fake severity label is emitted."""
    sev = ",".join(
        f'"{label}"'
        for label in (
            "emerg",
            "alert",
            "crit",
            "err",
            "warn",
            "notice",
            "info",
            "debug",
        )
    )
    fac = ",".join(f'"f{i}"' for i in range(24))
    code = f"""
    filter {{
      mutate {{ replace => {{ "raw_pri" => "-13" }} }}
      syslog_pri {{
        syslog_pri_field_name => "raw_pri"
        severity_labels => [{sev}]
        facility_labels => [{fac}]
      }}
    }}
    """
    result = ReverseParser(code).query("raw_pri_severity")
    # No concrete-label lineage — all sources are the original constant
    # propagated symbolically, never the bogus "err" label.
    expressions = {src.expression for m in result.mappings for src in m.sources}
    assert "err" not in expressions
    statuses = {m.status for m in result.mappings}
    assert "constant" not in statuses or expressions == {"-13"}


def test_syslog_pri_positive_literal_in_range_still_resolves_concrete_labels():
    """C5 sanity: in-range positive PRI literals must still resolve to
    concrete severity/facility labels — the fix only narrowed the predicate
    to non-negative integers in [0, 191]."""
    sev = ",".join(
        f'"{label}"'
        for label in (
            "emerg",
            "alert",
            "crit",
            "err",
            "warn",
            "notice",
            "info",
            "debug",
        )
    )
    fac = ",".join(f'"f{i}"' for i in range(24))
    code = f"""
    filter {{
      mutate {{ replace => {{ "raw_pri" => "13" }} }}
      syslog_pri {{
        syslog_pri_field_name => "raw_pri"
        severity_labels => [{sev}]
        facility_labels => [{fac}]
      }}
    }}
    """
    result = ReverseParser(code).query("raw_pri_severity")
    # 13 & 7 == 5 -> "notice"
    assert any(src.expression == "notice" for m in result.mappings for src in m.sources)


def test_syslog_pri_out_of_range_literal_falls_through_to_symbolic():
    """C5 sanity: PRI literals above 191 are out of the unsigned 0-191 range
    too and should also fall through to symbolic, not produce a wrap-around
    label."""
    sev = ",".join(
        f'"{label}"'
        for label in (
            "emerg",
            "alert",
            "crit",
            "err",
            "warn",
            "notice",
            "info",
            "debug",
        )
    )
    fac = ",".join(f'"f{i}"' for i in range(24))
    code = f"""
    filter {{
      mutate {{ replace => {{ "raw_pri" => "999" }} }}
      syslog_pri {{
        syslog_pri_field_name => "raw_pri"
        severity_labels => [{sev}]
        facility_labels => [{fac}]
      }}
    }}
    """
    result = ReverseParser(code).query("raw_pri_severity")
    # Nothing from the 8-element severity_labels list should appear as a
    # concrete-label source; the symbolic path passes the original "999"
    # constant through transformations only.
    sev_label_set = {"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}
    label_sources = [src.expression for m in result.mappings for src in m.sources if src.expression in sev_label_set]
    assert not label_sources


def test_ruby_global_variable_emits_concurrency_risk():
    """R3: a ruby block that reads or writes a Ruby global (``@@var``) or
    ``$var``) must surface a structured ``ruby_concurrency_risk`` warning.
    Ruby globals are shared across all events processed by a worker, so
    parser authors should know when a block depends on cross-event state.
    """
    at_globals = ReverseParser('filter { ruby { code => "@@last_session = event.get(\\"id\\")" } }').analysis_summary()
    codes = {warning["code"] for warning in at_globals["structured_warnings"]}
    assert "ruby_concurrency_risk" in codes
    assert any("@@last_session" in warning for warning in at_globals["warnings"])

    dollar_globals = ReverseParser('filter { ruby { code => "$tally += 1" } }').analysis_summary()
    dollar_codes = {warning["code"] for warning in dollar_globals["structured_warnings"]}
    assert "ruby_concurrency_risk" in dollar_codes
    assert any("$tally" in warning for warning in dollar_globals["warnings"])

    # Plain ruby (no globals) must NOT trip the warning.
    benign = ReverseParser('filter { ruby { code => "event.set(\\"x\\", event.get(\\"y\\"))" } }').analysis_summary()
    assert "ruby_concurrency_risk" not in {w["code"] for w in benign["structured_warnings"]}


def test_ruby_yield_or_event_clone_emits_event_split():
    """R3: a ruby block that calls ``yield`` (multi-event yield) or
    ``event.clone`` (event multiplication) must surface a structured
    ``ruby_event_split`` warning so downstream consumers know the parser
    can fan one input event out to multiple output events.
    """
    yielded = ReverseParser('filter { ruby { code => "yield event.clone" } }').analysis_summary()
    codes = {warning["code"] for warning in yielded["structured_warnings"]}
    assert "ruby_event_split" in codes

    cloned = ReverseParser('filter { ruby { code => "new_event = event.clone" } }').analysis_summary()
    clone_codes = {warning["code"] for warning in cloned["structured_warnings"]}
    assert "ruby_event_split" in clone_codes

    # Plain event.set without yield/clone must NOT trip the warning.
    benign = ReverseParser('filter { ruby { code => "event.set(\\"x\\", \\"y\\")" } }').analysis_summary()
    assert "ruby_event_split" not in {w["code"] for w in benign["structured_warnings"]}


def test_clone_fanout_above_cap_emits_clone_fanout_warning():
    """R2: ``clone { clones => [...too many entries...] }`` must emit a
    structured ``clone_fanout`` warning with a matching ``clone_fanout``
    taint, and the analyzer must not synthesize one branch per entry —
    only the first ``MAX_CLONE_FANOUT`` types are modeled.
    """
    from parser_lineage_analyzer._analysis_flow import MAX_CLONE_FANOUT

    over = MAX_CLONE_FANOUT + 5
    clone_list = ", ".join(f'"k{i}"' for i in range(over))
    code = f"filter {{ clone {{ clones => [{clone_list}] }} }}"

    summary = ReverseParser(code).analysis_summary()
    codes = {warning["code"] for warning in summary["structured_warnings"]}
    assert "clone_fanout" in codes

    fanout_warnings = [w for w in summary["warnings"] if "clone fanout" in w]
    assert any(str(over) in w and str(MAX_CLONE_FANOUT) in w for w in fanout_warnings), fanout_warnings

    # A list within the cap must NOT trip the warning.
    under_clones = ", ".join(f'"k{i}"' for i in range(min(8, MAX_CLONE_FANOUT - 1)))
    under_code = f"filter {{ clone {{ clones => [{under_clones}] }} }}"
    under_summary = ReverseParser(under_code).analysis_summary()
    assert "clone_fanout" not in {w["code"] for w in under_summary["structured_warnings"]}


def test_ruby_event_set_with_templated_destination_emits_dynamic_destination():
    """R1: ``event.set("event.idm.read_only_udm.additional.fields.%{key}", ...)``
    in a ruby block writes through ``_store_destination``, which detects the
    templated destination and emits a structured ``dynamic_destination``
    warning. The previous direct-write path bypassed this check entirely so
    the dynamic-name risk was invisible.
    """
    code = r"""
    filter {
      ruby { code => "event.set(\"event.idm.read_only_udm.additional.fields.%{k}\", \"v\")" }
    }
    """
    summary = ReverseParser(code).analysis_summary()
    codes = {warning["code"] for warning in summary["structured_warnings"]}
    assert "dynamic_destination" in codes


def test_geoip_target_normalization_via_store_destination():
    """R1: bracketed Logstash field syntax (``[src][geo]``) on a geoip
    ``target`` must reach the canonical ``src.geo`` token via
    ``_normalize_field_ref`` — the previous inline ``.strip("[]")
    .replace("][", ".")`` would have flattened ``"[src][geo]"`` to
    ``"src.geo"`` correctly, but only by coincidence. Routing through the
    canonical helper guarantees consistency with the rest of the analyzer.
    """
    code = r"""
    filter {
      geoip { source => "src_ip" target => "[src][geo]" }
    }
    """
    state = ReverseParser(code).analyze()
    assert "src.geo" in state.tokens


def test_external_lookup_target_and_get_collision_keeps_both_lineages():
    """R5: when ``elasticsearch { target => "es.id" get => { "x" => "es.id" } }``
    writes the same destination from both ``target`` and a ``get`` mapping,
    each is a real assignment with a distinct source path. They must both
    survive deduplication so ``query()`` reports both lineages.
    """
    code = r"""
    filter {
      elasticsearch {
        target => "es.id"
        get => { "elastic_query_id" => "es.id" }
      }
    }
    """
    rp = ReverseParser(code, dialect="logstash")
    lineages = rp.analyze().tokens.get("es.id", [])
    assert len(lineages) >= 2, lineages
    paths = sorted({src.path or "" for lin in lineages for src in lin.sources})
    assert "external_query" in paths
    assert "elastic_query_id" in paths


def test_ruby_event_split_warning_no_longer_forces_branch_merge():
    """R4: emitting a ``ruby_event_split`` warning must not trigger the
    no-op two-clone merge. The previous implementation did
    ``state.merge_branch_records(original, [original.clone(), yielded])``
    where both branches were unmutated ``state.clone()`` copies — that
    produced no observable lineage difference. Verify the warning still
    fires, downstream lineage is unchanged, and no clone-induced branch
    multiplication shows up in the analyzer state.
    """
    code = r"""
    filter {
      mutate { replace => { "before" => "x" } }
      ruby { code => "yield event.clone" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
    }
    """
    rp = ReverseParser(code)
    summary = rp.analysis_summary()

    # Warning fires.
    assert "ruby_event_split" in {w["code"] for w in summary["structured_warnings"]}

    # Lineage on either side of the ruby block stays linear: ``before`` keeps
    # its single ``x`` lineage; ``target.ip`` keeps its single ``1.1.1.1``.
    state = rp.analyze()
    assert len(state.tokens["before"]) == 1
    target_lineages = state.tokens["event.idm.read_only_udm.target.ip"]
    assert len(target_lineages) == 1
    assert target_lineages[0].expression == "1.1.1.1"
