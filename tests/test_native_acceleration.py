import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from parser_lineage_analyzer import _analysis_dedupe, _analysis_state, _analysis_templates, _scanner, config_parser
from parser_lineage_analyzer._analysis_dedupe import _lineage_key
from parser_lineage_analyzer._analysis_state import (
    MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES,
    AnalyzerState,
    BranchRecord,
    ExtractionHint,
    _merge_appended_only_python,
    _merge_with_unchanged_fallback_python,
)
from parser_lineage_analyzer.config_parser import parse_config, parse_config_with_diagnostics
from parser_lineage_analyzer.model import DiagnosticRecord, Lineage, OutputAnchor, SourceRef, TaintReason, WarningReason


class _UnhashableValue:
    # Setting ``__hash__ = None`` is the documented Python pattern for
    # "intentionally unhashable" (it overrides the inherited ``object.__hash__``
    # so ``hash(obj)`` raises ``TypeError``). Mypy can't model this because the
    # parent slot is typed as a callable; the suppression is the standard
    # workaround. See https://docs.python.org/3/reference/datamodel.html#object.__hash__
    __hash__ = None  # type: ignore[assignment]

    def __repr__(self):
        return "UnhashableValue()"


def _scanner_index_snapshot(index: _scanner.ScannerIndex):
    return (
        index.square_positions,
        index.square_depths,
        index.target_positions,
        index.matching_close,
        index.fallback_close,
    )


def test_no_ext_runtime_env_uses_python_fallbacks():
    env = dict(os.environ)
    env["PARSER_LINEAGE_ANALYZER_NO_EXT"] = "1"
    code = (
        "from parser_lineage_analyzer import _analysis_templates, _scanner, config_parser; "
        "print(_scanner._NATIVE_SCANNER is None); "
        "print(config_parser._NATIVE_CONFIG_FAST is None); "
        "print(_analysis_templates._NATIVE_TEMPLATE is None); "
        "print(repr(_scanner.strip_comments_keep_offsets('a // b\\n'))); "
        'print(config_parser.parse_config(\'replace => { "a" => "b" }\'))'
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    lines = result.stdout.splitlines()
    assert lines[:3] == ["True", "True", "True"]
    assert lines[3] == "'a     \\n'"
    assert lines[4] == "[('replace', [('a', 'b')])]"


def test_python_fallback_scanner_and_config_paths_still_match_expected_behavior():
    code = 'filter { mutate { replace => {"url" => "http://example.com/a//b"} } // trailing\n }'
    stripped = _scanner._strip_comments_keep_offsets_python(code)
    assert len(stripped) == len(code)
    assert "http://example.com/a//b" in stripped
    assert "// trailing" not in stripped

    assert config_parser._parse_simple_config_fast_python('replace => { "a" => ["b", ["c"]] }') == [
        ("replace", [("a", ["b", ["c"]])])
    ]
    assert config_parser._parse_simple_config_fast_python("match => /a\\/b/") is None


@pytest.mark.skipif(_scanner._NATIVE_SCANNER is None, reason="optional scanner extension is not built")
def test_native_scanner_matches_python_scanner_on_protected_regions():
    code = "\n".join(
        [
            'filter { mutate { replace => { "url" => "http://example.com/a//b" } } // trailing',
            '  if [field] =~ /^literal$/ { mutate { replace => { "x" => "%{{not_a_block}}" } } }',
            '  xpath { //node => "node_token" } /* block */',
            "}",
        ]
    )

    assert _scanner.strip_comments_keep_offsets(code) == _scanner._strip_comments_keep_offsets_python(code)
    assert _scanner_index_snapshot(_scanner.build_scanner_index(code)) == _scanner_index_snapshot(
        _scanner._build_scanner_index_python(code)
    )
    native_index = _scanner.build_scanner_index(code)
    python_index = _scanner._build_scanner_index_python(code)
    for target in ("{", "}", "[", "]"):
        assert native_index.find_next_unquoted(target, 0, relative_depth=False) == python_index.find_next_unquoted(
            target, 0, relative_depth=False
        )


@pytest.mark.skipif(_scanner._NATIVE_SCANNER is None, reason="optional scanner extension is not built")
def test_native_scanner_handles_path_bareword_with_brace():
    """T5: the native scanner now mirrors the Python ``_is_path_bareword_start``
    heuristic, so the historical ``=> /var_{/logs/}`` short-circuit fallback
    is gone. Output equivalence is asserted on the canonical bareword fixture
    AND a hand-crafted snippet so failures point to the right rule.
    """
    snippet = """\
filter {
  mutate {
    replace => {
      "log_dir" => /var_{/logs/}
      "status"  => "ok"
    }
  }
}
"""
    assert _scanner.strip_comments_keep_offsets(snippet) == _scanner._strip_comments_keep_offsets_python(snippet)
    assert _scanner_index_snapshot(_scanner.build_scanner_index(snippet)) == _scanner_index_snapshot(
        _scanner._build_scanner_index_python(snippet)
    )

    fixture = Path(__file__).parent / "fixtures" / "test_corpus" / "bugs" / "test_balanced_regex_bareword.cbn"
    if fixture.exists():
        text = fixture.read_text(encoding="utf-8")
        assert _scanner.strip_comments_keep_offsets(text) == _scanner._strip_comments_keep_offsets_python(text)
        assert _scanner_index_snapshot(_scanner.build_scanner_index(text)) == _scanner_index_snapshot(
            _scanner._build_scanner_index_python(text)
        )


@pytest.mark.skipif(config_parser._NATIVE_CONFIG_FAST is None, reason="optional config extension is not built")
def test_native_config_fast_path_matches_python_fast_path():
    cases = [
        'replace => { "a" => "b" "c" => "%{d}" }',
        'replace => { "a" => ["b", ["c", "d"]] }',
        'source => "message" target => "payload"',
        'replace => { "url" => http://example.com/path }',
        "match => /a\\/b/",
        "x => " + ("[" * 65) + '"a"' + ("]" * 65),
        'μ_op => "v"',
        'op_with_µ => "v"',
    ]

    for text in cases:
        assert config_parser._parse_simple_config_fast(text) == config_parser._parse_simple_config_fast_python(text)


def test_config_fallback_diagnostics_still_cover_malformed_and_deep_inputs():
    config, diagnostics = parse_config_with_diagnostics("source => a=b")
    assert config[0][0] == "__config_parse_error__"
    assert diagnostics

    deep = "x => " + ("[" * 65) + '"a"' + ("]" * 65)
    config, diagnostics = parse_config_with_diagnostics(deep)
    assert config[0][0] == "__config_parse_error__"
    assert "Config nesting depth exceeds limit" in diagnostics[0].message

    assert parse_config('replace => { "url" => http://example.com/path }') == [
        ("replace", [("url", "http://example.com/path")])
    ]


def _complex_lineage(expression: str = "expr") -> Lineage:
    taint = TaintReason(
        code="dynamic_template",
        message="dynamic",
        parser_location="line 9: mutate.replace",
        source_token="src",
    )
    return Lineage(
        status="derived",
        sources=[
            SourceRef(
                kind="json_path",
                source_token="message",
                path="payload.user",
                expression="json(message)",
                details={
                    "nested": [{"2": "two", "items": [1, "x"]}],
                    "3": {"int-key": True},
                },
            ),
            SourceRef(kind="constant", expression="fallback"),
        ],
        expression=expression,
        transformations=["json", "lowercase"],
        conditions=["[ok] == true", "[kind] == user"],
        parser_locations=["line 1: json", "line 2: mutate.replace"],
        notes=["first", "second"],
        taints=[taint],
    )


@pytest.mark.skipif(_analysis_dedupe._NATIVE_DEDUPE is None, reason="optional dedupe extension is not built")
def test_native_dedupe_is_default_on_when_extension_is_built():
    env = dict(os.environ)
    for key in ("PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE", "PARSER_LINEAGE_ANALYZER_NO_EXT"):
        env.pop(key, None)
    code = (
        "from parser_lineage_analyzer import _analysis_dedupe; "
        "print(_analysis_dedupe._USE_NATIVE_DEDUPE); "
        "print(_analysis_dedupe._NATIVE_DEDUPE is not None and "
        "_analysis_dedupe._dedupe_lineages is _analysis_dedupe._NATIVE_DEDUPE._dedupe_lineages)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == ["True", "True"]


def test_use_native_dedupe_can_be_disabled_via_env_var_opt_out():
    env = dict(os.environ)
    env["PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE"] = "0"
    env.pop("PARSER_LINEAGE_ANALYZER_NO_EXT", None)
    code = (
        "from parser_lineage_analyzer import _analysis_dedupe; "
        "print(_analysis_dedupe._USE_NATIVE_DEDUPE); "
        "print(_analysis_dedupe._dedupe_lineages is _analysis_dedupe._dedupe_lineages_python)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    lines = result.stdout.splitlines()
    assert lines == ["False", "True"]


@pytest.mark.skipif(_analysis_dedupe._NATIVE_DEDUPE is None, reason="optional dedupe extension is not built")
def test_native_dedupe_keys_match_python_reference_on_complex_values():
    native = _analysis_dedupe._NATIVE_DEDUPE

    values = [
        {"b": [1, {"nested": {"y", "x"}}], 2: {"z": _UnhashableValue()}},
        [{3: "three"}, {"set": {"b", "a"}}],
        [_UnhashableValue(), {"literal", 3}],
    ]
    for value in values:
        assert native._freeze_value(value) == _analysis_dedupe._freeze_value_python(value)

    assert native._source_key(_complex_lineage().sources[0]) == _analysis_dedupe._source_key_python(
        _complex_lineage().sources[0]
    )
    assert native._taint_key(_complex_lineage().taints[0]) == _analysis_dedupe._taint_key_python(
        _complex_lineage().taints[0]
    )
    warning = WarningReason(
        code="w",
        message="warn",
        parser_location="line 3",
        source_token="src",
        warning="warning text",
    )
    diagnostic = DiagnosticRecord(
        code="d",
        kind="taint",
        message="diag",
        parser_location="line 4",
        source_token="src",
        taint=_complex_lineage().taints[0],
        strict=False,
    )
    hint = ExtractionHint(
        "json",
        "message",
        {"target": "field", "nested": {"items": [1, 2]}},
        conditions=["if"],
        parser_locations=["line 5"],
        source_resolved=False,
    )
    anchor = OutputAnchor("principal.ip", conditions=["if"], parser_locations=["line 6"])

    assert native._warning_key(warning) == _analysis_dedupe._warning_key_python(warning)
    assert native._diagnostic_key(diagnostic) == _analysis_dedupe._diagnostic_key_python(diagnostic)
    assert native._lineage_key(_complex_lineage()) == _analysis_dedupe._lineage_key_python(_complex_lineage())
    assert native._hint_key(hint) == _analysis_dedupe._hint_key_python(hint)
    assert native._anchor_key(anchor) == _analysis_dedupe._anchor_key_python(anchor)


@pytest.mark.skipif(_analysis_dedupe._NATIVE_DEDUPE is None, reason="optional dedupe extension is not built")
def test_native_dedupe_outputs_match_python_reference_ordering():
    native = _analysis_dedupe._NATIVE_DEDUPE
    lineages = [_complex_lineage("a"), _complex_lineage("a"), _complex_lineage("b")]
    sources = [lineages[0].sources[0], lineages[1].sources[0], lineages[2].sources[1]]
    taints = [lineages[0].taints[0], lineages[1].taints[0]]
    warnings = [
        WarningReason(code="w", message="one", warning="one"),
        WarningReason(code="w", message="one", warning="one"),
        WarningReason(code="w", message="two", warning="two"),
    ]
    diagnostics = [
        DiagnosticRecord(code="d", message="one"),
        DiagnosticRecord(code="d", message="one"),
        DiagnosticRecord(code="d", message="two"),
    ]
    hints = [
        ExtractionHint("json", "message", {"target": "a"}),
        ExtractionHint("json", "message", {"target": "a"}),
        ExtractionHint("json", "message", {"target": "b"}),
    ]
    anchors = [OutputAnchor("a"), OutputAnchor("a"), OutputAnchor("b")]

    assert native._dedupe_lineages(lineages) == _analysis_dedupe._dedupe_lineages_python(lineages)
    assert native._dedupe_sources(sources) == _analysis_dedupe._dedupe_sources_python(sources)
    assert native._dedupe_taints(taints) == _analysis_dedupe._dedupe_taints_python(taints)
    assert native._dedupe_warning_reasons(warnings) == _analysis_dedupe._dedupe_warning_reasons_python(warnings)
    assert native._dedupe_diagnostics(diagnostics) == _analysis_dedupe._dedupe_diagnostics_python(diagnostics)
    assert native._dedupe_hints(hints) == _analysis_dedupe._dedupe_hints_python(hints)
    assert native._dedupe_anchors(anchors) == _analysis_dedupe._dedupe_anchors_python(anchors)
    assert native._dedupe_strings(["a", "", "a", "b"]) == _analysis_dedupe._dedupe_strings_python(["a", "", "a", "b"])


@pytest.mark.parametrize(
    ("template", "candidate", "expected"),
    [
        ("abc%{x}", "abc123", True),
        ("abc%{x}", "xabc123", False),
        ("%{x}abc", "123abc", True),
        ("%{x}abc", "abc123", False),
        ("a%{x}b%{y}c", "aXXbYYc", True),
        ("a%{x}b%{y}c", "aXXcYYb", False),
        ("a%{x}b%{y}c", "zaXXbYYc", False),
        ("a%{x}b%{y}c", "aXXbYYcz", False),
        ("%{x}", "", True),
        ("%{x}", "anything", True),
        ("literal", "literal", True),
        ("literal", "literalx", False),
        ("a%{}b", "a%{}b", True),
    ],
)
def test_dynamic_template_python_matcher_keeps_regex_compatible_anchoring(template, candidate, expected):
    regex_match = bool(re.compile(_analysis_templates.dynamic_template_pattern_text_python(template)).match(candidate))

    assert regex_match is expected
    assert _analysis_templates.dynamic_template_matches_python(template, candidate) is expected


@pytest.mark.skipif(_analysis_templates._NATIVE_TEMPLATE is None, reason="optional template extension is not built")
def test_native_template_helpers_match_python_reference():
    native = _analysis_templates._NATIVE_TEMPLATE
    templates = [
        "event.%{field}",
        "prefix.%{one}.middle.%{two}.suffix",
        "%{root}.tail",
        "head.%{leaf}",
        "%{only}",
        "literal",
        "a%{}b",
        "unterminated.%{field",
    ]
    candidates = ["event.name", "x.tail", "head.value", "prefix.a.middle.b.suffix", "literal", "a%{}b"]

    for template in templates:
        assert native.template_refs(template) == _analysis_templates.template_refs_python(template)
        assert native.dynamic_template_literals(template) == _analysis_templates.dynamic_template_literals_python(
            template
        )
        assert native.dynamic_template_bucket_literal(
            template
        ) == _analysis_templates.dynamic_template_bucket_literal_python(template)
        assert native.dynamic_template_pattern_text(
            template
        ) == _analysis_templates.dynamic_template_pattern_text_python(template)
        for candidate in candidates:
            assert native.dynamic_template_matches(
                template, candidate
            ) == _analysis_templates.dynamic_template_matches_python(template, candidate)


def test_branch_lineage_key_cache_is_clone_safe_for_append_replace_and_delete():
    base_lineages = [_complex_lineage(f"base-{idx}") for idx in range(8)]
    appended = _complex_lineage("appended")
    replacement = _complex_lineage("replacement")
    state = AnalyzerState(tokens={"x": base_lineages})
    base_keys = state._cached_token_lineage_keys("x", state.tokens["x"])

    clone = state.clone()
    assert clone._token_lineage_key_cache is state._token_lineage_key_cache
    assert clone._token_lineage_key_cache["x"] is base_keys

    clone.append_token_lineages("x", [appended])
    assert clone._token_lineage_key_cache is not state._token_lineage_key_cache
    assert state.tokens["x"] == base_lineages
    assert clone.tokens["x"] == [*base_lineages, appended]
    assert state._token_lineage_key_cache["x"] == frozenset(_analysis_dedupe._lineage_key(lin) for lin in base_lineages)
    assert clone._token_lineage_key_cache["x"] == frozenset(
        {_analysis_dedupe._lineage_key(lin) for lin in [*base_lineages, appended]}
    )

    replacement_clone = state.clone()
    replacement_clone.tokens["x"] = [replacement]
    assert replacement_clone._peek_token_lineage_key_cache("x") is None
    assert state._token_lineage_key_cache["x"] == base_keys

    delete_clone = state.clone()
    del delete_clone.tokens["x"]
    assert delete_clone._peek_token_lineage_key_cache("x") is None
    assert state._token_lineage_key_cache["x"] == base_keys


def test_unchanged_non_no_op_lineage_keys_does_not_poison_original_cache():
    """Branch merging must not mutate the original state's mutable cache set."""
    base_lineages = [_complex_lineage(f"base-{idx}") for idx in range(10)]
    base = AnalyzerState(tokens={"x": list(base_lineages)})
    base.append_token_lineages("x", list(base_lineages))
    cached_before = base._token_lineage_key_cache["x"]
    assert isinstance(cached_before, set)
    snapshot_before = frozenset(cached_before)

    unchanged_branch = base.clone()
    unchanged_branch._dirty_tokens.add("x")

    replacement_branch = base.clone()
    replacement_lineage = _complex_lineage("replacement-only")
    replacement_branch.tokens["x"] = [replacement_lineage]
    replacement_branch._dirty_tokens.add("x")

    base._unchanged_non_no_op_lineage_keys(
        base,
        [
            BranchRecord(unchanged_branch, ["[a]"], False),
            BranchRecord(replacement_branch, ["[b]"], False),
        ],
        {"x"},
    )

    assert base._token_lineage_key_cache["x"] is cached_before
    assert frozenset(cached_before) == snapshot_before


def test_repeated_append_updates_token_lineage_key_cache_in_place_without_duplicates():
    base_lineages = [_complex_lineage(f"base-{idx}") for idx in range(8)]
    base_snapshot = list(base_lineages)
    first = _complex_lineage("first")
    second = _complex_lineage("second")
    state = AnalyzerState(tokens={"x": base_lineages})
    state._cached_token_lineage_keys("x", state.tokens["x"])

    state.append_token_lineages("x", [first])
    cache_after_first = state._token_lineage_key_cache["x"]
    assert isinstance(cache_after_first, set)

    state.append_token_lineages("x", [first, second])
    assert state._token_lineage_key_cache["x"] is cache_after_first
    assert state.tokens["x"] == [*base_snapshot, first, second]

    state.append_token_lineages("x", [second])
    assert state._token_lineage_key_cache["x"] is cache_after_first
    assert state.tokens["x"] == [*base_snapshot, first, second]


def test_batch_extraction_hints_preserve_order_duplicates_generation_and_resolved_cache():
    state = AnalyzerState()
    state._has_resolved_extractor["json"] = False
    first = ExtractionHint("json", "message", {"target": "a"}, parser_locations=["line 1"])
    duplicate = ExtractionHint("json", "message", {"target": "a"}, parser_locations=["line 1"])
    resolved = ExtractionHint("json", "body", {"target": "b"}, parser_locations=["line 2"], source_resolved=True)
    json_generation = state._extractor_hint_generation_by_kind.get("json", 0)

    state.add_extraction_hints("json", [first, duplicate, resolved])

    assert state.json_extractions == [first, resolved]
    assert state._extractor_hint_generation_by_kind["json"] == json_generation + 2
    assert state.has_resolved_extractor("json") is True

    generation = state._extractor_hint_generation
    state.add_extraction_hints("json", [duplicate])
    assert state.json_extractions == [first, resolved]
    assert state._extractor_hint_generation == generation


def test_branch_metadata_delta_batches_hint_merges_with_first_seen_ordering():
    base = AnalyzerState()
    branch_one = base.clone()
    branch_two = base.clone()
    first = ExtractionHint("json", "message", {"target": "a"}, parser_locations=["line 1"])
    duplicate = ExtractionHint("json", "message", {"target": "a"}, parser_locations=["line 1"])
    second = ExtractionHint("json", "body", {"target": "b"}, parser_locations=["line 2"])
    third = ExtractionHint("kv", "kv_source", {"target": "c"}, parser_locations=["line 3"])

    branch_one.add_extraction_hints("json", [first, second])
    branch_two.add_extraction_hints("json", [duplicate])
    branch_two.add_extraction_hints("kv", [third])
    json_generation = base._extractor_hint_generation_by_kind.get("json", 0)
    kv_generation = base._extractor_hint_generation_by_kind.get("kv", 0)

    base._merge_branch_metadata_delta(
        [
            BranchRecord(branch_one, ["[a]"], False),
            BranchRecord(branch_two, ["[b]"], False),
        ]
    )

    assert base.json_extractions == [first, second]
    assert base.kv_extractions == [third]
    assert base._extractor_hint_generation_by_kind["json"] == json_generation + 2
    assert base._extractor_hint_generation_by_kind["kv"] == kv_generation + 1


def test_batch_extraction_hints_refresh_lazy_index_after_it_was_built():
    state = AnalyzerState()
    initial = ExtractionHint("json", "message", {"target": "payload.first"}, parser_locations=["line 1"])
    later = ExtractionHint("json", "message", {"target": "payload.second"}, parser_locations=["line 2"])
    untargeted = ExtractionHint(
        "json",
        "message",
        {},
        parser_locations=[f"line {idx}" for idx in range(200)],
    )

    state.add_extraction_hint("json", initial)
    assert state.extractor_hints_for_token("json", "payload.first") == [initial]

    state.add_extraction_hints("json", [later, untargeted])
    second_hints = state.extractor_hints_for_token("json", "payload.second")

    assert later in second_hints
    untargeted_hints = [hint for hint in second_hints if not hint.details.get("target")]
    assert len(untargeted_hints) == 1
    assert len(tuple(untargeted_hints[0].parser_locations)) == 128


def _branch_heavy_parser_driver() -> str:
    return textwrap.dedent(
        """
        from parser_lineage_analyzer import ReverseParser
        import json

        parser_text = '''
        filter {
          mutate { replace => { "repeat" => "base" } }
          if [a] == "1" {
            mutate { replace => { "repeat" => "%{repeat}a" } }
          } else if [b] == "1" {
            mutate { replace => { "repeat" => "%{repeat}b" } }
          } else {
            mutate { replace => { "other" => "z" } }
          }
          mutate { replace => { "event.idm.read_only_udm.additional.fields.repeat" => "%{repeat}" } }
        }
        '''
        parser = ReverseParser(parser_text)
        parser.analyze()
        payload = {
            "summary": parser.analysis_summary(compact=True),
            "query": parser.query("additional.fields.repeat").to_json(),
        }
        print(json.dumps(payload, sort_keys=True))
        """
    )


@pytest.mark.parametrize(
    "env_overrides",
    [
        pytest.param({"PARSER_LINEAGE_ANALYZER_NO_EXT": "1"}, id="no-ext"),
        pytest.param({"PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE": "0"}, id="no-native-dedupe"),
        pytest.param({"PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE": "0"}, id="no-native-branch-merge"),
    ],
)
def test_native_and_no_ext_analysis_outputs_match_for_branch_heavy_shape(env_overrides):
    code = _branch_heavy_parser_driver()
    base_env = dict(os.environ)
    for key in (
        "PARSER_LINEAGE_ANALYZER_NO_EXT",
        "PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE",
        "PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE",
    ):
        base_env.pop(key, None)
    native = subprocess.run([sys.executable, "-c", code], check=True, env=base_env, capture_output=True, text=True)
    other_env = dict(base_env)
    other_env.update(env_overrides)
    other = subprocess.run([sys.executable, "-c", code], check=True, env=other_env, capture_output=True, text=True)
    assert native.stdout == other.stdout


def _branch_lineage(text: str) -> Lineage:
    return Lineage(
        status="exact",
        sources=[SourceRef(kind="literal", expression=text)],
        expression=text,
        conditions=(),
        parser_locations=("line 1: mutate.replace",),
        notes=(),
    )


@pytest.mark.parametrize(
    "factory",
    [
        pytest.param(
            lambda: SourceRef(kind="json_path", source_token="m", path="a.b", details={"k": [1, "x"]}),
            id="SourceRef",
        ),
        pytest.param(
            lambda: TaintReason(code="c", message="m", parser_location="loc", source_token="t"),
            id="TaintReason",
        ),
        pytest.param(
            lambda: WarningReason(code="c", message="m", parser_location="loc", warning="w"),
            id="WarningReason",
        ),
        pytest.param(
            lambda: DiagnosticRecord(
                code="c",
                message="m",
                kind="taint",
                taint=TaintReason(code="c2", message="m2"),
                strict=False,
            ),
            id="DiagnosticRecord",
        ),
        pytest.param(
            lambda: Lineage(
                status="exact",
                sources=[SourceRef(kind="constant", expression="hi")],
                expression="hi",
                conditions=("c1",),
                parser_locations=("p1",),
            ),
            id="Lineage",
        ),
        pytest.param(
            lambda: ExtractionHint("json", "msg", {"target": "field"}, conditions=("c1",), parser_locations=("p1",)),
            id="ExtractionHint",
        ),
    ],
)
def test_model_objects_with_same_fields_are_hash_eq_consistent(factory):
    a = factory()
    b = factory()
    assert a is not b
    assert a == b
    assert hash(a) == hash(b)
    items = [a, b]
    assert len(set(items)) == 1
    assert len(list(dict.fromkeys(items))) == 1


def test_lineage_distinct_hashes_when_sources_differ():
    base_src = SourceRef(kind="constant", expression="hi")
    other_src = SourceRef(kind="constant", expression="hello")
    a = Lineage(status="exact", sources=[base_src], expression="hi")
    b = Lineage(status="exact", sources=[other_src], expression="hi")
    assert a != b
    assert hash(a) != hash(b)


def test_python_branch_merge_appended_only_matches_kernel_contract():
    initial = [_branch_lineage("a"), _branch_lineage("b")]
    initial_keys = {_lineage_key(lin) for lin in initial}
    appended = [
        [_branch_lineage("c"), _branch_lineage("a")],
        [_branch_lineage("d"), _branch_lineage("c")],
    ]
    merged, keys, hit_limit = _merge_appended_only_python(
        _lineage_key, list(initial), set(initial_keys), appended, MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES
    )
    assert hit_limit is False
    assert [lin.expression for lin in merged] == ["a", "b", "c", "d"]
    assert keys == {_lineage_key(_branch_lineage(t)) for t in ("a", "b", "c", "d")}


def test_python_branch_merge_appended_only_hits_fanout_cap():
    fanout = 3
    appended = [
        [_branch_lineage(f"v{i}") for i in range(fanout + 5)],
    ]
    merged, _keys, hit_limit = _merge_appended_only_python(_lineage_key, [], set(), appended, fanout)
    assert hit_limit is True
    assert len(merged) == fanout + 1


def test_python_branch_merge_with_unchanged_fallback_dedupes_and_caps():
    unchanged = [_branch_lineage("u1"), _branch_lineage("u2")]
    effective = [
        [_branch_lineage("u1"), _branch_lineage("e1")],
        [_branch_lineage("e2")],
    ]
    missing = [_branch_lineage("m1"), _branch_lineage("e1")]
    merged, _keys, hit_limit, total_seen = _merge_with_unchanged_fallback_python(
        _lineage_key, unchanged, effective, missing, MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES
    )
    assert hit_limit is False
    assert [lin.expression for lin in merged] == ["u1", "u2", "e1", "e2", "m1"]
    assert total_seen == len(unchanged) + sum(len(v) for v in effective) + len(missing)


@pytest.mark.skipif(
    _analysis_state._NATIVE_BRANCH_MERGE is None,
    reason="optional branch-merge extension is not built",
)
def test_native_branch_merge_appended_only_matches_python():
    native = _analysis_state._NATIVE_BRANCH_MERGE
    initial = [_branch_lineage("a"), _branch_lineage("b")]
    initial_keys = {_lineage_key(lin) for lin in initial}
    appended = [
        [_branch_lineage("c"), _branch_lineage("a")],
        [_branch_lineage("d"), _branch_lineage("c")],
    ]
    n_merged, n_keys, n_hit = native.merge_appended_only(
        _lineage_key, list(initial), set(initial_keys), appended, MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES
    )
    p_merged, p_keys, p_hit = _merge_appended_only_python(
        _lineage_key, list(initial), set(initial_keys), appended, MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES
    )
    assert [lin.expression for lin in n_merged] == [lin.expression for lin in p_merged]
    assert n_keys == p_keys
    assert n_hit == p_hit


@pytest.mark.skipif(
    _analysis_state._NATIVE_BRANCH_MERGE is None,
    reason="optional branch-merge extension is not built",
)
def test_native_branch_merge_appended_only_fanout_summary_path_matches_python():
    native = _analysis_state._NATIVE_BRANCH_MERGE
    fanout = 4
    appended = [[_branch_lineage(f"x{i}") for i in range(fanout + 3)]]
    n_merged, n_keys, n_hit = native.merge_appended_only(_lineage_key, [], set(), appended, fanout)
    p_merged, p_keys, p_hit = _merge_appended_only_python(_lineage_key, [], set(), appended, fanout)
    assert n_hit is True and p_hit is True
    assert [lin.expression for lin in n_merged] == [lin.expression for lin in p_merged]
    assert n_keys == p_keys


@pytest.mark.skipif(
    _analysis_state._NATIVE_BRANCH_MERGE is None,
    reason="optional branch-merge extension is not built",
)
def test_native_branch_merge_with_unchanged_fallback_matches_python():
    native = _analysis_state._NATIVE_BRANCH_MERGE
    unchanged = [_branch_lineage("u1"), _branch_lineage("u2"), _branch_lineage("u1")]
    effective = [
        [_branch_lineage("u2"), _branch_lineage("e1")],
        [],
        [_branch_lineage("e2"), _branch_lineage("e1")],
    ]
    missing = [_branch_lineage("m1")]
    n_merged, n_keys, n_hit, n_seen = native.merge_with_unchanged_fallback(
        _lineage_key, unchanged, effective, missing, MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES
    )
    p_merged, p_keys, p_hit, p_seen = _merge_with_unchanged_fallback_python(
        _lineage_key, unchanged, effective, missing, MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES
    )
    assert [lin.expression for lin in n_merged] == [lin.expression for lin in p_merged]
    assert n_keys == p_keys
    assert n_hit == p_hit
    assert n_seen == p_seen


@pytest.mark.skipif(
    _analysis_state._NATIVE_BRANCH_MERGE is None,
    reason="optional branch-merge extension is not built",
)
def test_native_branch_merge_fallback_fanout_summary_path_matches_python():
    native = _analysis_state._NATIVE_BRANCH_MERGE
    fanout = 5
    effective = [[_branch_lineage(f"v{i}") for i in range(fanout + 4)]]
    n_merged, n_keys, n_hit, n_seen = native.merge_with_unchanged_fallback(_lineage_key, [], effective, [], fanout)
    p_merged, p_keys, p_hit, p_seen = _merge_with_unchanged_fallback_python(_lineage_key, [], effective, [], fanout)
    assert n_hit is True and p_hit is True
    assert [lin.expression for lin in n_merged] == [lin.expression for lin in p_merged]
    assert n_keys == p_keys
    assert n_seen == p_seen
