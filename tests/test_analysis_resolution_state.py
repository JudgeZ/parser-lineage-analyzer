from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._analysis_resolution import ResolutionMixin
from parser_lineage_analyzer._analysis_state import AnalyzerState, BranchRecord, ExtractionHint
from parser_lineage_analyzer.model import Lineage, SourceRef


class _Resolver(ResolutionMixin):
    pass


def _constant_lineage(expression: str) -> Lineage:
    return Lineage(
        status="constant", sources=[SourceRef(kind="constant", expression=expression)], expression=expression
    )


def test_inferred_token_cache_refreshes_after_extractor_hint_is_added():
    resolver = _Resolver()
    state = AnalyzerState()
    state.add_extraction_hint(
        "json",
        ExtractionHint(
            "json",
            "message",
            {"target": "payload"},
            parser_locations=["line 1: json source=message"],
        ),
    )

    first = resolver._lookup_token("payload.user", state, "line 2: first lookup")
    assert [source.source_token for lineage in first for source in lineage.sources] == ["message"]

    state.add_extraction_hint(
        "json",
        ExtractionHint(
            "json",
            "body",
            {"target": "payload"},
            parser_locations=["line 3: json source=body"],
        ),
    )

    refreshed = resolver._lookup_token("payload.user", state, "line 4: second lookup")
    assert sorted(source.source_token for lineage in refreshed for source in lineage.sources) == [
        "body",
        "message",
    ]


def test_stale_inferred_token_refresh_preserves_explicit_appended_lineages():
    resolver = _Resolver()
    state = AnalyzerState()
    state.add_extraction_hint(
        "json",
        ExtractionHint(
            "json",
            "message",
            {"target": "payload"},
            parser_locations=["line 1: json source=message"],
        ),
    )

    resolver._lookup_token("payload.user", state, "line 2: first lookup")
    state.append_token_lineages(
        "payload.user",
        [
            Lineage(
                status="exact",
                sources=[SourceRef(kind="constant", expression="explicit")],
                expression="payload.user",
                parser_locations=["line 3: explicit append"],
            )
        ],
    )
    state.add_extraction_hint(
        "json",
        ExtractionHint(
            "json",
            "body",
            {"target": "payload"},
            parser_locations=["line 4: json source=body"],
        ),
    )

    refreshed = resolver._lookup_token("payload.user", state, "line 5: second lookup")

    assert [
        (source.kind, source.source_token, source.expression) for lineage in refreshed for source in lineage.sources
    ] == [
        ("json_path", "message", None),
        ("json_path", "body", None),
        ("constant", None, "explicit"),
    ]


def test_untargeted_json_hint_fanout_summarizes_but_keeps_targeted_hints():
    resolver = _Resolver()
    state = AnalyzerState()
    for i in range(130):
        state.add_extraction_hint(
            "json",
            ExtractionHint(
                "json",
                f"message{i}",
                {},
                conditions=[f'[source] == "{i}"'],
                parser_locations=[f"line {i}: json source=message{i}"],
            ),
        )
    state.add_extraction_hint(
        "json",
        ExtractionHint(
            "json",
            "targeted",
            {"target": "payload"},
            parser_locations=["line 200: json source=targeted"],
        ),
    )

    inferred = resolver._lookup_token("payload.user", state, "line 201: lookup")

    assert len(inferred) == 2
    targeted = [lineage for lineage in inferred if any(source.source_token == "targeted" for source in lineage.sources)]
    summarized = [lineage for lineage in inferred if lineage.status == "dynamic"]
    assert len(targeted) == 1
    assert targeted[0].sources[0].path == "user"
    assert len(summarized) == 1
    assert summarized[0].sources[0].path == "payload.user"
    assert any(diagnostic.code == "extractor_hint_fanout" for diagnostic in state.diagnostics)


def test_clone_preserves_pending_descendant_token_index_overlays():
    state = AnalyzerState({"root.old": [_constant_lineage("old")]})
    branch = state.clone()
    branch.tokens["root.new"] = [_constant_lineage("new")]
    branch.tokens.pop("root.old")

    cloned_branch = branch.clone()

    assert cloned_branch.descendant_tokens("root") == ["root.new"]
    assert cloned_branch._token_parent_index_additions["root"] is not branch._token_parent_index_additions["root"]
    assert cloned_branch._token_parent_index_removals["root"] is not branch._token_parent_index_removals["root"]


def test_clone_preserves_pending_dynamic_template_token_index_overlays():
    state = AnalyzerState({"event.%{old}": [_constant_lineage("old")]})
    branch = state.clone()
    branch.tokens["event.%{name}"] = [_constant_lineage("new")]
    branch.tokens.pop("event.%{old}")

    cloned_branch = branch.clone()

    assert cloned_branch.dynamic_template_tokens("event.alice") == ["event.%{name}"]
    assert cloned_branch._dynamic_token_index_additions["event."] is not branch._dynamic_token_index_additions["event."]
    assert cloned_branch._dynamic_token_index_removals["event."] is not branch._dynamic_token_index_removals["event."]


def test_nested_branch_parent_assignment_clears_outer_branch_descendant():
    code = r"""
    filter {
      if [a] == "1" {
        mutate { replace => { "root.child" => "seed" } }
        if [b] == "1" {
          mutate { replace => { "root" => "parent" } }
        }
        mutate { replace => { "event.idm.read_only_udm.metadata.description" => "%{root.child}" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """

    result = ReverseParser(code).query("metadata.description")

    seed_mappings = [mapping for mapping in result.mappings if mapping.expression == "seed"]
    assert seed_mappings
    assert all('NOT([b] == "1")' in mapping.conditions for mapping in seed_mappings)


def test_dropped_branch_metadata_is_not_merged_but_diagnostics_are_preserved():
    state = AnalyzerState()
    original = state.clone()
    survivor = original.clone()
    dropped = original.clone()
    dropped.dropped = True
    dropped.add_extraction_hint(
        "json",
        ExtractionHint(
            "json",
            "message",
            {"target": "dropped_payload"},
            parser_locations=["line 2: json source=message"],
        ),
    )
    dropped.add_warning(
        "line 3: dropped branch warning",
        code="dropped_branch_warning",
        message="dropped branch warning",
        parser_location="line 3: warning",
    )

    state.merge_branch_records(
        original,
        [
            BranchRecord(survivor, ['[keep] == "1"'], False),
            BranchRecord(dropped, ['[drop] == "1"'], False),
        ],
    )

    assert state.json_extractions == []
    assert any(diagnostic.code == "dropped_branch_warning" for diagnostic in state.diagnostics)
