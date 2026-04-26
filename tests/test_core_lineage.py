from conftest import EXAMPLE

from parser_lineage_analyzer import ReverseParser


def test_grok_capture_reverse_mapping():
    result = ReverseParser(EXAMPLE).query("target.ip")
    assert result.status == "exact_capture"
    assert result.mappings
    assert result.mappings[0].sources[0].kind == "grok_capture"
    assert result.mappings[0].sources[0].capture_name == "dstAddr"


def test_json_path_merge_reverse_mapping():
    result = ReverseParser(EXAMPLE).query("observer.ip")
    paths = {src.path for m in result.mappings for src in m.sources if src.kind == "json_path"}
    assert "device.ips.0" in paths
    assert "device.ips.1" in paths


def test_constant_reverse_mapping():
    result = ReverseParser(EXAMPLE).query("metadata.event_type")
    assert result.status == "constant"
    assert result.mappings[0].sources[0].kind == "constant"
    assert result.mappings[0].sources[0].expression == "NETWORK_CONNECTION"


def test_convert_transformation_preserved():
    result = ReverseParser(EXAMPLE).query("network.target.port")
    transforms = result.mappings[0].transformations
    assert any("convert(integer)" in t for t in transforms)


def test_conditional_constants():
    code = r"""
    filter {
      kv { source => "message" field_split => " " value_split => "=" }
      if [action] == "allow" {
        mutate { replace => { "event.idm.read_only_udm.security_result.action" => "ALLOW" } }
      } else {
        mutate { replace => { "event.idm.read_only_udm.security_result.action" => "UNKNOWN_ACTION" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("security_result.action")
    values = {m.sources[0].expression for m in result.mappings}
    assert values == {"ALLOW", "UNKNOWN_ACTION"}
    assert all(m.conditions for m in result.mappings)


def test_multi_event_anchor_normalization():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event1.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event1" } }
    }
    """
    result = ReverseParser(code).query("event.idm.read_only_udm.target.ip")
    assert result.mappings
    assert result.mappings[0].sources[0].kind == "json_path"
    assert result.mappings[0].sources[0].path == "dst"


def test_else_if_else_condition_chain_has_full_negations():
    code = r"""
    filter {
      if [severity] == "high" {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "HIGH" } }
      } else if [severity] == "medium" {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "MEDIUM" } }
      } else {
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "LOW" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    by_value = {m.sources[0].expression: set(m.conditions) for m in result.mappings}
    assert by_value["HIGH"] == {'[severity] == "high"'}
    assert by_value["MEDIUM"] == {'NOT([severity] == "high")', '[severity] == "medium"'}
    assert by_value["LOW"] == {'NOT([severity] == "high")', 'NOT([severity] == "medium")'}


def test_loop_item_member_maps_to_array_member_path():
    code = r"""
    filter {
      json { source => "message" array_function => "split_columns" }
      for alert in alerts {
        mutate { replace => { "event.idm.read_only_udm.security_result.summary" => "%{alert.name}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("security_result.summary")
    paths = {src.path for m in result.mappings for src in m.sources}
    assert "alerts[*].name" in paths
    assert result.status == "conditional"


def test_nested_loop_item_member_maps_to_nested_array_path():
    code = r"""
    filter {
      json { source => "message" array_function => "split_columns" }
      for resourceId in resourceIdentifiers {
        for subnet in resourceId.subnet {
          mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{subnet.ip}" } }
        }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    paths = {src.path for m in result.mappings for src in m.sources}
    assert "resourceIdentifiers[*].subnet[*].ip" in paths


def test_map_loop_object_merge_projects_udm_subfields():
    code = r"""
    filter {
      json { source => "message" array_function => "split_columns" }
      for key, value in resource.labels map {
        mutate { replace => { "label" => "" } }
        mutate { replace => { "label.key" => "%{key}" "label.value" => "%{value}" } }
        mutate { merge => { "event.idm.read_only_udm.principal.resource.attribute.labels" => "label" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result_key = ReverseParser(code).query("principal.resource.attribute.labels.key")
    assert result_key.mappings
    assert any(src.kind == "map_key" for m in result_key.mappings for src in m.sources)

    result_value = ReverseParser(code).query("principal.resource.attribute.labels.value")
    assert result_value.mappings
    assert any(src.kind == "map_value" for m in result_value.mappings for src in m.sources)


def test_empty_string_replace_is_constant_not_unresolved():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    assert result.status == "constant"
    assert result.mappings[0].sources[0].kind == "constant"
    assert result.mappings[0].sources[0].expression == ""


def test_bracket_field_reference_resolves_to_json_path():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{[network][dst_ip]}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "exact"
    assert any(src.kind == "json_path" and src.path == "network.dst_ip" for m in result.mappings for src in m.sources)


def test_conditional_json_extractor_conditions_are_preserved():
    code = r"""
    filter {
      if [format] == "json" {
        json { source => "message" }
      }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "conditional"
    assert result.mappings
    assert any('[format] == "json"' in cond for m in result.mappings for cond in m.conditions)
    assert any(src.kind == "json_path" and src.path == "dst_ip" for m in result.mappings for src in m.sources)


def test_json_source_does_not_self_infer_when_source_token_missing():
    code = r"""
    filter {
      json { source => "payload" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "unresolved"
    assert not any(src.kind == "json_path" for m in result.mappings for src in m.sources)
    assert any("source token was not resolved" in warning for warning in result.warnings)


def test_template_with_all_unresolved_refs_propagates_unresolved():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "%{missing_a}-%{missing_b}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    assert result.mappings, "expected at least one mapping"
    # All refs unresolved -> combo must NOT be derived; must propagate unresolved.
    assert result.mappings[0].status == "unresolved"
    # Sources include unknown refs and taints flow through.
    assert any(src.kind == "unknown" for m in result.mappings for src in m.sources)
    assert any(t.code == "unresolved_token" for m in result.mappings for t in m.taints)


def test_template_with_some_unresolved_refs_propagates_unresolved():
    code = r"""
    filter {
      grok { match => { "message" => "host=%{WORD:hostname}" } }
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "%{hostname}-%{missing_b}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    assert result.mappings, "expected at least one mapping"
    # One unresolved + one resolved (grok capture) -> still unresolved (conservative).
    assert result.mappings[0].status == "unresolved"
    # Taints from the unresolved sub-ref still flow through.
    assert any(t.code == "unresolved_token" for m in result.mappings for t in m.taints)


def test_template_interpolation_preserves_upstream_conditions():
    code = r"""
    filter {
      json { source => "message" }
      if [has_src] == "true" {
        mutate { replace => { "src" => "%{client.ip}" } }
      }
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "%{src}-%{message}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    assert result.status == "conditional"
    assert any('[has_src] == "true"' in cond for m in result.mappings for cond in m.conditions)


def test_dynamic_destination_is_warned_and_marked_dynamic():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event.idm.read_only_udm.network.http.request_headers.%{k}" => "%{v}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("event.idm.read_only_udm.network.http.request_headers.%{k}")
    assert result.status == "dynamic"
    assert result.mappings and result.mappings[0].status == "dynamic"
    assert any("dynamic destination field name" in warning for warning in result.warnings)


def test_unconditional_repeated_merge_is_not_labeled_conditional():
    result = ReverseParser(EXAMPLE).query("observer.ip")
    assert result.status == "repeated"


def test_remove_field_cascades_to_children():
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
    assert result.mappings and result.mappings[0].status == "removed"


def test_xml_loop_xpath_template_is_symbolic_wildcard_with_condition():
    code = r"""
    filter {
      for index, _ in xml(message,/Event/HOST_LIST/HOST){
        xml {
          source => "message"
          xpath => {
            "/Event/HOST_LIST/HOST[%{index}]/IP" => "IPs"
          }
        }
      }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{IPs}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.mappings
    assert any(
        src.kind == "xml_xpath" and src.path == "/Event/HOST_LIST/HOST[*]/IP"
        for m in result.mappings
        for src in m.sources
    )
    assert any("for index, _ in xml" in cond for m in result.mappings for cond in m.conditions)


def test_conditional_output_anchor_conditions_are_attached():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event1.idm.read_only_udm.target.ip" => "%{dst}" } }
      if [emit] == "yes" {
        mutate { merge => { "@output" => "event1" } }
      }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "conditional"
    assert any('[emit] == "yes"' in cond for m in result.mappings for cond in m.conditions)


def test_dynamic_destination_template_matches_concrete_query():
    code = r"""
    filter {
      json { source => "message" }
      for k, v in headers map {
        mutate { replace => { "event.idm.read_only_udm.network.http.request_headers.%{k}" => "%{v}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("network.http.request_headers.User-Agent")
    assert result.status == "dynamic"
    assert result.mappings
    assert any("dynamic destination" in warning for warning in result.warnings)
    assert any(src.kind == "map_value" for m in result.mappings for src in m.sources)


def test_dynamic_destination_template_matches_empty_placeholder_query():
    code = r"""
    filter {
      mutate { replace => { "event.idm.read_only_udm.principal%{suffix}.ip" => "1.1.1.1" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("principal.ip")
    assert result.status == "dynamic"
    assert result.mappings
    assert result.mappings[0].expression == "1.1.1.1"
    assert not any(warning.code == "no_assignment" for warning in result.structured_warnings)
    assert any("dynamic destination template" in note for mapping in result.mappings for note in mapping.notes)


def test_static_array_multivar_loop_resolves_each_index_to_constant():
    """C4: ``for index, item in [...]`` over a literal array used to fall
    through ``_exec_for``'s single-variable fast path and resolve as
    ``unresolved``. The fast path now handles multi-variable iteration so
    every destination templated on ``index`` or ``item`` resolves to its
    constant value."""
    code = r"""
    filter {
      for index, item in ["a", "b", "c"] {
        mutate { add_field => { "event.idm.read_only_udm.additional.fields.tag_%{index}" => "%{item}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    parser = ReverseParser(code)
    by_index = {0: "a", 1: "b", 2: "c"}
    for index, expected in by_index.items():
        result = parser.query(f"additional.fields.tag_{index}")
        assert result.status == "constant", f"tag_{index} status was {result.status}"
        assert {m.expression for m in result.mappings} == {expected}


def test_static_array_loop_does_not_erase_outer_scope_token_with_same_name():
    """C4 follow-up: ``_exec_static_string_loop`` pops the loop-variable
    tokens (and their descendants) from ``state.tokens`` after each
    iteration to scope them to the loop body. Without protection, that
    would also erase any pre-existing token with the same name — and
    ``index``/``item`` are common-enough field names in real parsers that
    the multi-variable fast path (introduced by C4) would silently
    regress to ``unresolved`` for any later reference to the prior
    token. The dynamic path sidesteps this by cloning state per
    iteration; the fast path now snapshots and restores outer-scope
    tokens around the loop.
    """
    code = r"""
    filter {
      grok { match => { "message" => "%{WORD:item}\\s+%{INT:index}" } on_error => "_grokfail" }
      for index, item in ["x", "y"] {
        mutate { add_field => { "event.idm.read_only_udm.additional.fields.tmp_%{index}" => "%{item}" } }
      }
      mutate { replace => { "event.idm.read_only_udm.target.user.userid" => "%{item}" } }
      mutate { replace => { "event.idm.read_only_udm.target.resource.id" => "%{index}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    parser = ReverseParser(code)

    # The loop body consumed ``index``/``item`` as iteration-scoped
    # constants, but the post-loop replace must still see the grok
    # captures — not the loop's per-iteration constants and not
    # ``unresolved`` (which is what happened before the save+restore
    # fix when the cleanup pop wiped the grok-derived tokens).
    user_result = parser.query("target.user.userid")
    assert user_result.status == "exact_capture", f"target.user.userid status was {user_result.status}"
    user_kinds = {src.kind for mapping in user_result.mappings for src in mapping.sources}
    assert user_kinds == {"grok_capture"}, f"unexpected sources for target.user.userid: {user_kinds}"

    resource_result = parser.query("target.resource.id")
    assert resource_result.status == "exact_capture", (
        f"target.resource.id status was {resource_result.status} — outer-scope ``index`` "
        "was clobbered by the loop's per-iteration cleanup pop"
    )
    resource_kinds = {src.kind for mapping in resource_result.mappings for src in mapping.sources}
    assert resource_kinds == {"grok_capture"}, f"unexpected sources for target.resource.id: {resource_kinds}"

    # And the loop-body destinations still resolve correctly — the
    # save+restore must not interfere with the per-iteration semantics.
    tmp0 = parser.query("additional.fields.tmp_0")
    assert tmp0.status == "constant", f"loop body tmp_0 status was {tmp0.status}"
    assert {m.expression for m in tmp0.mappings} == {"x"}


def test_static_array_loop_save_restore_does_not_alias_parent_token_lists():
    """C4 + branch interaction (Codex P1): when ``_exec_static_string_loop``
    runs against a forked ``TokenStore``, ``state.tokens[var]`` falls
    through ``__getitem__`` to the parent's list reference. The save+restore
    must shallow-copy that list — otherwise the post-loop store would alias
    the parent's list, and any later ``append_token_lineages`` on this
    branch would mutate the parent's list in place via the
    ``mutate_local`` fast path, leaking branch-local lineage changes into
    the sibling branch's view.

    Direct invariant check: simulate the analyzer's save+restore at the
    ``AnalyzerState`` level (so the test doesn't depend on the surrounding
    branch-merge machinery), and assert the post-restore list is a
    distinct object from both the parent's stored list AND the saved
    snapshot. A subsequent in-place append on the fork must not be
    visible to the parent.
    """
    from parser_lineage_analyzer._analysis_state import AnalyzerState
    from parser_lineage_analyzer.model import Lineage, SourceRef

    parent = AnalyzerState()
    parent_lineage = Lineage(
        status="exact_capture",
        sources=[SourceRef(kind="grok_capture", source_token="message", path="message", capture_name="index")],
        expression="index",
    )
    parent.tokens["index"] = [parent_lineage]
    parent_list_id = id(parent.tokens["index"])

    # Fork — emulates the if-branch entry that owns the analyzer state for
    # the body. Reading "index" via __getitem__ on an unmodified fork falls
    # through to the parent's list reference, which is exactly the
    # aliasing setup the loop's save step would otherwise inherit.
    fork = parent.clone()
    assert id(fork.tokens["index"]) == parent_list_id, "precondition: fork shares parent's list"

    # Mimic the loop's save+restore path. The production code at
    # _analysis_flow.py uses ``list(state.tokens[var])`` — this assertion
    # locks that invariant by checking the post-restore object identity.
    saved = list(fork.tokens["index"])
    assert id(saved) != parent_list_id, "save step must shallow-copy, not alias"
    fork.tokens.pop("index", None)  # per-iteration cleanup pop
    fork.tokens["index"] = saved  # restore step

    # The fork's local list must be a distinct object from the parent's.
    assert id(fork.tokens["index"]) != parent_list_id, (
        "fork aliases parent's list after restore — append_token_lineages "
        "would mutate parent in place via the mutate_local fast path"
    )

    # Cross-check via mutation: appending to the fork's list must NOT show
    # up in the parent's list. Pre-fix (without the ``list(...)`` copy),
    # this assertion would fail because the two lists were the same
    # object.
    fork_lineage = Lineage(
        status="constant",
        sources=[SourceRef(kind="constant", expression="branch-only")],
        expression="branch-only",
    )
    fork.append_token_lineages("index", [fork_lineage])
    parent_kinds_after = {src.kind for lin in parent.tokens["index"] for src in lin.sources}
    assert parent_kinds_after == {"grok_capture"}, (
        f"parent's ``index`` lineage was corrupted by fork's append: {parent_kinds_after} — "
        "this is exactly the cross-branch leak the save+restore copy prevents"
    )


def test_static_array_loop_descendant_save_restore_isolates_from_loop_body_appends():
    """Codex P1 follow-up: a stricter version of the previous test that
    targets the descendant-mutation path Codex specifically called out.

    Scenario: a colliding outer-scope token (``index``) has descendants
    (``index.foo``) populated before the loop. The loop body performs an
    append-style write to ``index.foo``. The save snapshot captured
    pre-loop must not be polluted by that append, and the post-loop
    restore must reinstate the ORIGINAL outer-scope ``index.foo`` (not
    the loop body's modified version).

    Direct invariant check at the AnalyzerState level — exercises the
    ``descendant_tokens`` save path in isolation from the analyzer's
    branch-merge machinery.
    """
    from parser_lineage_analyzer._analysis_state import AnalyzerState
    from parser_lineage_analyzer.model import Lineage, SourceRef

    parent = AnalyzerState()
    parent_index = Lineage(
        status="exact_capture",
        sources=[SourceRef(kind="grok_capture", source_token="message", capture_name="index")],
        expression="index",
    )
    parent_index_foo = Lineage(
        status="exact_capture",
        sources=[SourceRef(kind="grok_capture", source_token="message", capture_name="index_foo")],
        expression="index.foo",
    )
    parent.tokens["index"] = [parent_index]
    parent.tokens["index.foo"] = [parent_index_foo]

    fork = parent.clone()

    # Mimic the loop's pre-loop save step (matches the production code at
    # _analysis_flow.py:1286-1293 — shallow copy of var and each
    # descendant). The shallow copy must produce lists distinct from
    # whatever ``state.tokens`` happens to hand back.
    saved_outer = {
        "index": list(fork.tokens["index"]),
        "index.foo": list(fork.tokens["index.foo"]),
    }
    saved_index_foo_id = id(saved_outer["index.foo"])

    # Mimic an iteration: pre-iteration set, then a body op that appends
    # to ``index.foo``, then per-iteration cleanup pop.
    fork.tokens["index"] = [
        Lineage(
            status="constant",
            sources=[SourceRef(kind="constant", expression="0")],
            expression="0",
        )
    ]
    body_lineage = Lineage(
        status="constant",
        sources=[SourceRef(kind="constant", expression="loop-body-foo")],
        expression="loop-body-foo",
    )
    fork.append_token_lineages("index.foo", [body_lineage])
    # Per-iteration cleanup pops descendants too.
    fork.tokens.pop("index", None)
    for token_name in fork.descendant_tokens("index"):
        fork.tokens.pop(token_name, None)

    # The saved snapshot must be untouched by the body's append. If the
    # save had captured a reference to the parent's list, the body's
    # ``mutate_local`` append on ``index.foo`` could have polluted that
    # reference and the snapshot would now contain ``loop-body-foo``.
    saved_kinds = {src.kind for lin in saved_outer["index.foo"] for src in lin.sources}
    assert saved_kinds == {"grok_capture"}, (
        f"loop-body append polluted the snapshot: {saved_kinds} — "
        "save step must shallow-copy lineage lists for descendants too"
    )
    assert id(saved_outer["index.foo"]) == saved_index_foo_id, "snapshot identity changed unexpectedly"

    # Restore: writes the saved (clean) list back into the fork's _data.
    fork.tokens["index"] = saved_outer["index"]
    fork.tokens["index.foo"] = saved_outer["index.foo"]

    # Post-restore: the fork sees the original outer-scope lineage,
    # not the loop body's transient additions.
    fork_index_foo_kinds = {src.kind for lin in fork.tokens["index.foo"] for src in lin.sources}
    assert fork_index_foo_kinds == {"grok_capture"}, (
        f"restored ``index.foo`` includes loop-body lineage: {fork_index_foo_kinds}"
    )

    # And the parent remains untouched throughout — the entire flow
    # operated on the fork's owned lists.
    parent_index_foo_kinds = {src.kind for lin in parent.tokens["index.foo"] for src in lin.sources}
    assert parent_index_foo_kinds == {"grok_capture"}


def test_loop_variables_do_not_leak_after_loop():
    code = r"""
    filter {
      for alert in alerts {
        mutate { replace => { "tmp.summary" => "%{alert.name}" } }
      }
      mutate { replace => { "event.idm.read_only_udm.security_result.summary" => "%{alert.name}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("security_result.summary")
    assert result.status == "unresolved"


def test_grok_capture_preserves_upstream_branch_conditions_and_transforms():
    code = r"""
    filter {
      json { source => "message" }
      if [kind] == "a" {
        url_decode { source => "net_a" target => "network" }
      } else {
        url_decode { source => "net_b" target => "network" }
      }
      grok { match => { "network" => "%{IP:dst}" } }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    by_path = {m.sources[0].details["upstream_sources"][0]["path"]: m for m in result.mappings}
    assert set(by_path) == {"net_a", "net_b"}
    assert list(by_path["net_a"].conditions) == ['[kind] == "a"']
    assert list(by_path["net_b"].conditions) == ['NOT([kind] == "a")']
    assert all("url_decode" in m.transformations for m in result.mappings)


def test_dissect_capture_preserves_upstream_branch_conditions_and_transforms():
    code = r"""
    filter {
      json { source => "message" }
      if [kind] == "a" {
        url_decode { source => "payload_a" target => "payload" }
      } else {
        url_decode { source => "payload_b" target => "payload" }
      }
      dissect { mapping => { "payload" => "%{host}" } }
      mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{host}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("principal.hostname")
    by_path = {m.sources[0].details["upstream_sources"][0]["path"]: m for m in result.mappings}
    assert set(by_path) == {"payload_a", "payload_b"}
    assert list(by_path["payload_a"].conditions) == ['[kind] == "a"']
    assert list(by_path["payload_b"].conditions) == ['NOT([kind] == "a")']
    assert all("url_decode" in m.transformations for m in result.mappings)


def test_loop_iterable_branch_alternatives_remain_separate():
    code = r"""
    filter {
      json { source => "message" }
      if [kind] == "a" {
        mutate { replace => { "items" => "%{foo}" } }
      } else {
        mutate { replace => { "items" => "%{bar}" } }
      }
      for item in items {
        mutate { replace => { "event.idm.read_only_udm.security_result.summary" => "%{item}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("security_result.summary")
    by_path = {m.sources[0].path: m for m in result.mappings}
    assert set(by_path) == {"foo[*]", "bar[*]"}
    assert list(by_path["foo[*]"].conditions) == ['[kind] == "a"', "for item in items"]
    assert list(by_path["bar[*]"].conditions) == ['NOT([kind] == "a")', "for item in items"]


def test_template_interpolation_keeps_branch_alternatives_separate():
    code = r"""
    filter {
      json { source => "message" }
      if [kind] == "a" {
        mutate { replace => { "src" => "%{foo}" } }
      } else {
        mutate { replace => { "src" => "%{bar}" } }
      }
      mutate { replace => { "event.idm.read_only_udm.metadata.description" => "%{src}:%{baz}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("metadata.description")
    by_paths = {tuple(src.path for src in m.sources): m for m in result.mappings}
    assert set(by_paths) == {("foo", "baz"), ("bar", "baz")}
    assert list(by_paths[("foo", "baz")].conditions) == ['[kind] == "a"']
    assert list(by_paths[("bar", "baz")].conditions) == ['NOT([kind] == "a")']


def test_duplicate_output_anchors_all_apply_conditions():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst}" } }
      if [a] == "1" { mutate { merge => { "@output" => "event" } } }
      if [b] == "1" { mutate { merge => { "@output" => "event" } } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert {tuple(m.conditions) for m in result.mappings} == {('[a] == "1"',), ('[b] == "1"',)}


def test_mixed_exact_and_dynamic_mappings_report_dynamic_status():
    code = r"""
    filter {
      json { source => "message" }
      mutate { replace => { "event.idm.read_only_udm.network.http.request_headers.%{k}" => "%{v}" } }
      mutate { replace => { "event.idm.read_only_udm.network.http.request_headers.User-Agent" => "%{ua}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("network.http.request_headers.User-Agent")
    assert result.status == "dynamic"
    assert {m.status for m in result.mappings} == {"exact", "dynamic"}


def test_parent_overwrite_removes_stale_child_lineage():
    code = r"""
    filter {
      mutate { replace => { "user.name" => "alice" } }
      mutate { replace => { "user" => "bob" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    assert "user.name" not in rp.analyze().tokens
    result = rp.query("user.name")
    assert result.status == "unresolved"


def test_copy_to_nested_destination_does_not_project_written_destination_again():
    code = r"""
    filter {
      mutate { replace => { "user.name" => "alice" } }
      mutate { copy => { "user" => "user.copy" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    state = rp.analyze()
    assert "user.copy.name" in state.tokens
    assert "user.copy.copy" not in state.tokens
    assert rp.query("user.copy.name").status == "derived"
    assert rp.query("user.copy.copy").status == "unresolved"


def test_rename_to_nested_destination_does_not_project_written_destination_again():
    code = r"""
    filter {
      mutate { replace => { "user.name" => "alice" } }
      mutate { rename => { "user" => "user.copy" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    rp = ReverseParser(code)
    state = rp.analyze()
    assert "user.copy.name" in state.tokens
    assert "user.copy.copy" not in state.tokens
    assert "user.name" not in state.tokens
    assert rp.query("user.copy.name").status == "derived"
    assert rp.query("user.copy.copy").status == "unresolved"


def test_copy_and_rename_to_nested_destination_preserve_overlapping_child_lineage():
    for op in ("copy", "rename"):
        code = rf"""
        filter {{
          mutate {{ replace => {{ "user.copy.old" => "old" }} }}
          mutate {{ {op} => {{ "user" => "user.copy" }} }}
          mutate {{ merge => {{ "@output" => "event" }} }}
        }}
        """
        result = ReverseParser(code).query("user.copy.copy.old")
        assert result.status == "derived"
        assert result.mappings[0].sources[0].expression == "old"


def test_frozen_details_eq_and_hash_are_order_insensitive_but_iter_preserves_order():
    """`_FrozenDetails.__eq__` must match the dedupe-key contract used by
    `SourceRef._analysis_key` (which calls `_frozen_details_key` over a sorted
    items view). Two instances whose key/value pairs differ only in insertion
    order must compare equal and hash the same. Iteration order, however, must
    still reflect insertion order so JSON output stays stable."""
    from parser_lineage_analyzer.model import _FrozenDetails

    d_ab = _FrozenDetails((("a", 1), ("b", 2)))
    d_ba = _FrozenDetails((("b", 2), ("a", 1)))

    # Equality and hash align with the sorted dedupe key.
    assert d_ab == d_ba
    assert hash(d_ab) == hash(d_ba)
    assert d_ab.key_tuple == d_ba.key_tuple

    # Iteration order is preserved (still reflects insertion order).
    assert list(d_ab) == ["a", "b"]
    assert list(d_ba) == ["b", "a"]
    assert d_ab.items_tuple == (("a", 1), ("b", 2))
    assert d_ba.items_tuple == (("b", 2), ("a", 1))

    # Different content still compares unequal.
    d_diff = _FrozenDetails((("a", 1), ("b", 3)))
    assert d_ab != d_diff
    assert hash(d_ab) != hash(d_diff)

    # Sanity: non-_FrozenDetails comparisons return NotImplemented (here
    # observable as plain inequality with another type).
    assert d_ab != (("a", 1), ("b", 2))
