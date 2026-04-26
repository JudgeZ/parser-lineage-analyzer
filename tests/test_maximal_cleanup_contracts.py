import json
from dataclasses import FrozenInstanceError
from typing import get_args

import pytest

import parser_lineage_analyzer.render as render_module
from parser_lineage_analyzer import (
    DiagnosticRecord,
    Lineage,
    LineageStatus,
    OutputAnchor,
    QueryResult,
    ReverseParser,
    SourceRef,
    TaintReason,
    WarningReason,
)
from parser_lineage_analyzer._analysis_executor import _EXECUTOR_COMPONENTS, AnalysisExecutor
from parser_lineage_analyzer._analysis_query import re as query_re
from parser_lineage_analyzer._analysis_state import AnalyzerState
from parser_lineage_analyzer._scanner import find_matching, find_next_unquoted, strip_comments_keep_offsets
from parser_lineage_analyzer.model import LINEAGE_STATUS_VALUES
from parser_lineage_analyzer.parser import LalrSecOpsAstParser, SourceText, _SecOpsLexer
from parser_lineage_analyzer.render import COMPACT_JSON_SAMPLE_LIMIT, render_compact_json, render_json, render_text


def test_lineage_is_frozen_tuple_backed_and_serializes_lists():
    lineage = Lineage(
        status="exact",
        sources=[SourceRef(kind="constant", expression="x")],
        conditions=["a"],
        parser_locations=["line 1"],
        notes=["note"],
    )

    assert isinstance(lineage.conditions, tuple)
    assert lineage.to_json()["conditions"] == ["a"]
    with pytest.raises(FrozenInstanceError):
        lineage.status = "dynamic"
    with pytest.raises(AttributeError):
        lineage.conditions.append("b")


def test_status_validation_uses_public_get_args_and_json_does_not_raise():
    assert set(get_args(LineageStatus)) == LINEAGE_STATUS_VALUES
    result = QueryResult("f", ["f"], [Lineage(status="bogus")])

    payload = result.to_json()
    assert payload["status"] == "unresolved"
    assert payload["has_unresolved"] is True
    assert payload["diagnostics"][0]["code"] == "invalid_lineage_status"


def test_source_text_line_lookup_and_token_end_metadata():
    text = 'filter {\n  mutate { replace => { "a" => "b" } }\n}\n'
    src = SourceText.from_code(text)
    assert src.line_at(text.index("mutate")) == 2
    assert src.column_at(text.index("mutate")) == 3

    token = next(_SecOpsLexer(None).lex(text))
    assert token.line == 1
    assert token.column == 1
    assert token.end_line == 1
    assert token.end_column > token.column


def test_transformer_ast_has_typed_elif_block():
    ast = LalrSecOpsAstParser(
        'filter { if [a] == "1" { mutate { replace => { "x" => "1" } } } else if [a] == "2" { mutate { replace => { "x" => "2" } } } }'
    ).parse()
    if_block = ast[0]
    assert if_block.__class__.__name__ == "IfBlock"
    assert if_block.elifs[0].__class__.__name__ == "ElifBlock"
    assert if_block.elifs[0].condition == '[a] == "2"'


def test_scanner_eof_nested_refs_and_target_validation():
    stripped = strip_comments_keep_offsets("filter { /* unterminatedX")
    assert stripped.endswith(" " * len("/* unterminatedX"))
    with pytest.raises(ValueError, match="one character"):
        find_next_unquoted("a => b", 0, "=>")
    assert find_next_unquoted("for x in %{foo{bar}baz} {", 0, "{") == len("for x in %{foo{bar}baz} ")
    assert find_matching("{ %{foo{bar}baz} }", 0) == len("{ %{foo{bar}baz} ")


def test_dynamic_query_regex_error_is_reported(monkeypatch):
    code = 'filter { mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "x" } } }'
    rp = ReverseParser(code)

    class BrokenPattern:
        def match(self, candidate: str) -> object:
            raise query_re.error("bad pattern")

    monkeypatch.setattr(AnalyzerState, "dynamic_template_pattern", lambda _state, _token: BrokenPattern())
    result = rp.query("additional.fields.foo")
    assert any(diagnostic.code == "dynamic_template_regex" for diagnostic in result.diagnostics)


def test_query_skips_dynamic_template_lookup_when_state_has_no_dynamic_templates(monkeypatch):
    code = 'filter { mutate { replace => { "event.idm.read_only_udm.principal.ip" => "%{ip}" } } }'
    rp = ReverseParser(code)
    rp.analyze()

    def fail_dynamic_lookup(_state: AnalyzerState, _candidate: str) -> list[str]:
        pytest.fail("dynamic template lookup should be skipped")

    monkeypatch.setattr(AnalyzerState, "dynamic_template_tokens", fail_dynamic_lookup)

    result = rp.query("principal.ip")

    assert result.mappings


def test_render_helpers_do_not_own_final_newline_and_verbose_shows_all_source_fields():
    result = QueryResult(
        "f",
        ["f"],
        [
            Lineage(
                status="constant",
                sources=[SourceRef(kind="constant", expression="x", details={"k": "v"})],
                expression="x",
                parser_locations=["line 1"],
            )
        ],
    )
    text = render_text(result, verbose=True)
    assert not text.endswith("\n")
    assert "expression: x" in text
    # Detail dict values render as JSON (double-quoted) rather than Python
    # repr to keep the text output free of single-quote/None punctuation
    # that would otherwise leak into log/CI surfaces.
    assert 'details: {"k": "v"}' in text
    assert "{'k': 'v'}" not in text
    assert not render_json(result).endswith("\n")


def test_render_text_limit_is_optional_and_bounds_repeated_sections():
    result = QueryResult(
        "f",
        ["candidate.one", "candidate.two"],
        [
            Lineage(
                status="derived",
                sources=[
                    SourceRef(kind="constant", expression="first_source"),
                    SourceRef(kind="constant", expression="second_source"),
                ],
                expression="first_mapping",
                transformations=["first_transform", "second_transform"],
                conditions=["first_condition", "second_condition"],
                parser_locations=["line 1", "line 2"],
                notes=["first_note", "second_note"],
                taints=[
                    TaintReason(code="first_taint", message="first"),
                    TaintReason(code="second_taint", message="second"),
                ],
            ),
            Lineage(
                status="constant",
                sources=[SourceRef(kind="constant", expression="third_source")],
                expression="second_mapping",
            ),
        ],
        output_anchors=[OutputAnchor("anchor.one"), OutputAnchor("anchor.two")],
        unsupported=["unsupported one", "unsupported two"],
        warnings=["warning one", "warning two"],
        structured_warnings=[
            WarningReason(code="first_structured", message="first"),
            WarningReason(code="second_structured", message="second"),
        ],
        diagnostics=[
            DiagnosticRecord(code="first_diagnostic", message="first"),
            DiagnosticRecord(code="second_diagnostic", message="second"),
        ],
    )

    full_text = render_text(result, verbose=True)
    limited_text = render_text(result, verbose=True, limit=1)

    assert "candidate.two" in full_text
    assert "second_mapping" in full_text
    assert "candidate.two" not in limited_text
    assert "second_mapping" not in limited_text
    assert "second_source" not in limited_text
    assert "... 1 more candidate parser field omitted" in limited_text
    assert "... 1 more mapping omitted" in limited_text
    assert "... 1 more source omitted" in limited_text
    assert "... 1 more output anchor omitted" in limited_text
    assert "... 1 more diagnostic omitted" in limited_text


def test_render_text_limit_uses_bounded_taint_selection(monkeypatch):
    calls: list[int] = []
    original_nsmallest = render_module.nsmallest

    def spy_nsmallest(n, iterable, *, key=None):
        calls.append(n)
        return original_nsmallest(n, iterable, key=key)

    monkeypatch.setattr(render_module, "nsmallest", spy_nsmallest)
    result = QueryResult(
        "f",
        ["f"],
        [
            Lineage(
                status="dynamic",
                taints=[
                    TaintReason(code="z", message="last"),
                    TaintReason(code="a", message="first"),
                    TaintReason(code="m", message="middle"),
                ],
            )
        ],
    )

    text = render_text(result, limit=2)

    assert calls == [2]
    assert "a: first" in text
    assert "m: middle" in text
    assert "z: last" not in text
    assert "... 1 more taint omitted" in text


def test_render_text_reports_presampled_query_result_totals_without_limit():
    result = QueryResult(
        "f",
        ["candidate.one", "candidate.two"],
        [Lineage(status="constant", expression="first_mapping")],
        normalized_candidates_total=5,
        mappings_total=3,
    )

    text = render_text(result)

    assert "candidate.two" in text
    assert "first_mapping" in text
    assert "... 3 more candidate parser fields omitted" in text
    assert "... 2 more mappings omitted" in text


def test_render_text_reports_empty_presampled_mappings_as_omitted():
    result = QueryResult(
        "f",
        ["candidate.one"],
        [],
        mappings_total=3,
    )

    text = render_text(result)

    assert "No mappings found." not in text
    assert "Mappings:" in text
    assert "... 3 more mappings omitted" in text


def test_compact_json_clamps_limit_without_truncating_full_json():
    result = QueryResult(
        "f",
        [f"candidate.{idx}" for idx in range(COMPACT_JSON_SAMPLE_LIMIT + 10)],
        [
            Lineage(
                status="constant",
                sources=[SourceRef(kind="constant", expression=f"value-{idx}")],
                expression=f"value-{idx}",
            )
            for idx in range(COMPACT_JSON_SAMPLE_LIMIT + 10)
        ],
    )

    compact_payload = json.loads(render_compact_json(result, limit=COMPACT_JSON_SAMPLE_LIMIT + 10))
    full_payload = json.loads(render_json(result))
    empty_payload = json.loads(render_compact_json(result, limit=-1))

    assert len(compact_payload["normalized_candidates"]) == COMPACT_JSON_SAMPLE_LIMIT
    assert len(compact_payload["mappings"]) == COMPACT_JSON_SAMPLE_LIMIT
    assert compact_payload["normalized_candidates_total"] == COMPACT_JSON_SAMPLE_LIMIT + 10
    assert compact_payload["mappings_total"] == COMPACT_JSON_SAMPLE_LIMIT + 10
    assert len(full_payload["normalized_candidates"]) == COMPACT_JSON_SAMPLE_LIMIT + 10
    assert len(full_payload["mappings"]) == COMPACT_JSON_SAMPLE_LIMIT + 10
    assert empty_payload["normalized_candidates"] == []
    assert empty_payload["mappings"] == []
    assert empty_payload["mappings_total"] == COMPACT_JSON_SAMPLE_LIMIT + 10


def test_compact_json_bounds_nested_mapping_taints_but_full_json_preserves_them():
    result = QueryResult(
        "f",
        ["f"],
        [
            Lineage(
                status="dynamic",
                taints=[
                    TaintReason(code="z", message="last", parser_location="line 3"),
                    TaintReason(code="a", message="first", parser_location="line 1"),
                    TaintReason(code="m", message="middle", parser_location="line 2"),
                ],
            )
        ],
    )

    compact_mapping = json.loads(render_compact_json(result, limit=2))["mappings"][0]
    full_mapping = json.loads(render_json(result))["mappings"][0]

    assert [taint["code"] for taint in compact_mapping["taints"]] == ["a", "m"]
    assert compact_mapping["taints_total"] == 3
    assert compact_mapping["taints_omitted"] == 1
    assert [taint["code"] for taint in full_mapping["taints"]] == ["a", "m", "z"]
    assert "taints_total" not in full_mapping
    assert "taints_omitted" not in full_mapping


def test_compact_json_bounds_nested_mapping_metadata_but_full_json_preserves_it():
    result = QueryResult(
        "f",
        ["f"],
        [
            Lineage(
                status="derived",
                sources=[SourceRef(kind="json_path", path=f"path.{idx}") for idx in range(3)],
                transformations=[f"transform_{idx}" for idx in range(3)],
                conditions=[f"condition_{idx}" for idx in range(3)],
                parser_locations=[f"line {idx}: mutate" for idx in range(3)],
                notes=[f"note_{idx}" for idx in range(3)],
            )
        ],
    )

    compact_mapping = json.loads(render_compact_json(result, limit=2))["mappings"][0]
    full_mapping = json.loads(render_json(result))["mappings"][0]

    assert [source["path"] for source in compact_mapping["sources"]] == ["path.0", "path.1"]
    assert compact_mapping["sources_total"] == 3
    assert compact_mapping["sources_omitted"] == 1
    assert compact_mapping["transformations"] == ["transform_0", "transform_1"]
    assert compact_mapping["transformations_total"] == 3
    assert compact_mapping["transformations_omitted"] == 1
    assert compact_mapping["conditions"] == ["condition_0", "condition_1"]
    assert compact_mapping["conditions_total"] == 3
    assert compact_mapping["conditions_omitted"] == 1
    assert compact_mapping["parser_locations"] == ["line 0: mutate", "line 1: mutate"]
    assert compact_mapping["parser_locations_total"] == 3
    assert compact_mapping["parser_locations_omitted"] == 1
    assert compact_mapping["notes"] == ["note_0", "note_1"]
    assert compact_mapping["notes_total"] == 3
    assert compact_mapping["notes_omitted"] == 1

    assert [source["path"] for source in full_mapping["sources"]] == ["path.0", "path.1", "path.2"]
    assert full_mapping["transformations"] == ["transform_0", "transform_1", "transform_2"]
    assert full_mapping["conditions"] == ["condition_0", "condition_1", "condition_2"]
    assert full_mapping["parser_locations"] == ["line 0: mutate", "line 1: mutate", "line 2: mutate"]
    assert full_mapping["notes"] == ["note_0", "note_1", "note_2"]
    assert "sources_total" not in full_mapping
    assert "transformations_total" not in full_mapping
    assert "conditions_total" not in full_mapping
    assert "parser_locations_total" not in full_mapping
    assert "notes_total" not in full_mapping


def test_compact_json_uses_single_query_result_aggregate(monkeypatch):
    calls = 0
    original_aggregate = QueryResult.aggregate
    result = QueryResult(
        "f",
        ["f"],
        [
            Lineage(status="dynamic", conditions=["cond"]),
            Lineage(status="exact"),
        ],
    )

    def counting_aggregate(self):
        nonlocal calls
        calls += 1
        return original_aggregate(self)

    monkeypatch.setattr(QueryResult, "aggregate", counting_aggregate)

    payload = json.loads(render_compact_json(result))

    assert calls == 1
    assert payload["status"] == "dynamic"
    assert payload["is_conditional"] is True
    assert payload["has_dynamic"] is True


def test_executor_components_have_no_method_collisions():
    seen: dict[str, str] = {}
    for component in _EXECUTOR_COMPONENTS:
        for name in component.__dict__:
            if name.startswith("__"):
                continue
            assert name not in seen, f"{name} collides between {seen[name]} and {component.__name__}"
            seen[name] = component.__name__
    assert issubclass(AnalysisExecutor, _EXECUTOR_COMPONENTS)
