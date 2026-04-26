import importlib
import io
import json
import sys
from pathlib import Path

import pytest

import parser_lineage_analyzer
import parser_lineage_analyzer._scanner as scanner
from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer.cli import main

SIMPLE_CODE = r"""
filter {
  json { source => "message" }
  mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{network.dst_ip}" } }
  mutate { merge => { "@output" => "event" } }
}
"""


def _write_parser(tmp_path, code=SIMPLE_CODE):
    path = tmp_path / "parser.cbn"
    path.write_text(code, encoding="utf-8")
    return path


def test_cli_file_query_json_success(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "exact"
    assert payload["is_conditional"] is False
    assert payload["has_dynamic"] is False
    assert payload["has_unresolved"] is False
    assert payload["has_taints"] is False


def test_cli_accepts_flags_between_parser_file_and_udm_field(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "--json", "target.ip"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "exact"


def test_cli_stdin_query_json_success(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(SIMPLE_CODE))
    assert main(["-", "target.ip", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "exact"


def test_cli_stdin_limit_uses_bounded_reads(monkeypatch, capsys):
    class BoundedOnlyStdin:
        def __init__(self, text: str):
            self.text = text
            self.read_sizes: list[int] = []

        def read(self, size: int = -1) -> str:
            self.read_sizes.append(size)
            if size < 0:
                raise AssertionError("stdin read must be bounded")
            chunk, self.text = self.text[:size], self.text[size:]
            return chunk

    stream = BoundedOnlyStdin("abcd")
    monkeypatch.setattr(sys, "stdin", stream)

    assert main(["-", "--summary", "--max-parser-bytes", "3"]) == 1
    assert stream.read_sizes == [4]
    assert "exceeds maximum parser size" in capsys.readouterr().err


def test_cli_text_stdin_limit_counts_multibyte_bytes(monkeypatch, capsys):
    class TextOnlyStdin:
        def __init__(self, text: str):
            self.text = text

        def read(self, size: int = -1) -> str:
            if size < 0:
                raise AssertionError("stdin read must be bounded")
            chunk, self.text = self.text[:size], self.text[size:]
            return chunk

    monkeypatch.setattr(sys, "stdin", TextOnlyStdin("éé"))

    assert main(["-", "--summary", "--max-parser-bytes", "3"]) == 1
    assert "exceeds maximum parser size" in capsys.readouterr().err


def test_cli_missing_file_and_missing_query_exit_codes(tmp_path, capsys):
    assert main([str(tmp_path / "missing.cbn"), "target.ip"]) == 1
    assert "parser file not found" in capsys.readouterr().err

    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file)]) == 2
    err = capsys.readouterr().err
    assert "udm_field is required" in err
    assert "--list" in err
    assert "--summary" in err
    assert "--compact-summary" in err


def test_cli_invalid_utf8_is_read_error(tmp_path, capsys):
    parser_file = tmp_path / "bad.cbn"
    parser_file.write_bytes(b"\xff\xfe\xfa")

    assert main([str(parser_file), "target.ip"]) == 1
    assert "could not read parser file" in capsys.readouterr().err


def test_cli_max_parser_bytes_flag_controls_input_limit(tmp_path, capsys):
    parser_file = _write_parser(tmp_path, SIMPLE_CODE)
    assert main([str(parser_file), "target.ip", "--max-parser-bytes", "3"]) == 1
    assert "exceeds maximum parser size" in capsys.readouterr().err

    assert main([str(parser_file), "target.ip", "--max-parser-bytes", "25000000", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "exact"


def test_cli_file_limit_uses_bounded_read(monkeypatch, capsys):
    class BoundedBinaryFile:
        def __init__(self, data: bytes):
            self.data = data
            self.read_sizes: list[int] = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size: int = -1) -> bytes:
            self.read_sizes.append(size)
            if size < 0:
                raise AssertionError("file read must be bounded")
            return self.data[:size]

    stream = BoundedBinaryFile(b"abcd")

    monkeypatch.setattr(Path, "is_dir", lambda _self: False)
    monkeypatch.setattr(Path, "open", lambda _self, mode="r", *args, **kwargs: stream)

    assert main(["fake.cbn", "--summary", "--max-parser-bytes", "3"]) == 1
    # The file path uses the same bounded-read pattern as stdin, with room for
    # a leading UTF-8 BOM before deciding whether the payload exceeds the cap.
    assert stream.read_sizes == [7]
    assert "exceeds maximum parser size" in capsys.readouterr().err


def test_cli_negative_max_parser_bytes_matches_unlimited_analyzer_sentinel(tmp_path, monkeypatch, capsys):
    parser_file = _write_parser(tmp_path, SIMPLE_CODE)
    assert main([str(parser_file), "target.ip", "--max-parser-bytes", "-1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "exact"

    monkeypatch.setattr(sys, "stdin", io.StringIO(SIMPLE_CODE))
    assert main(["-", "target.ip", "--max-parser-bytes", "-1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "exact"


def test_cli_rejects_udm_field_with_non_query_modes(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)

    for mode in ("--list", "--summary", "--compact-summary"):
        assert main([str(parser_file), "target.ip", mode]) == 2
        assert "udm_field cannot be used" in capsys.readouterr().err


def test_cli_strict_exit_three_with_structured_warning_json(tmp_path, capsys):
    code = r"""
filter {
  mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "%{missing_value}" } }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)
    assert main([str(parser_file), "additional.fields.foo", "--json", "--strict"]) == 3

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "dynamic"
    assert payload["has_dynamic"] is True
    assert payload["has_taints"] is True
    assert any("dynamic destination field name" in warning for warning in payload["warnings"])
    assert any(warning["code"] == "dynamic_destination" for warning in payload["structured_warnings"])


def test_cli_summary_list_and_version(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)

    assert main([str(parser_file), "--summary", "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["token_count"] >= 1
    assert "structured_warnings" in summary
    assert "taints" in summary

    assert main([str(parser_file), "--list", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert "event.idm.read_only_udm.target.ip" in listed["udm_fields"]
    assert listed["udm_fields_total"] == len(listed["udm_fields"])

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "parser-lineage-analyzer 0.1.0" in capsys.readouterr().out


def test_cli_list_text_reports_empty_state(tmp_path, capsys):
    parser_file = _write_parser(tmp_path, "filter {}")

    assert main([str(parser_file), "--list"]) == 0
    assert capsys.readouterr().out == "No UDM fields found.\n"

    assert main([str(parser_file), "--list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"udm_fields": [], "udm_fields_total": 0}


def test_cli_rejects_json_with_compact_json(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip", "--json", "--compact-json"]) == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err
    assert "--json" in err
    assert "--compact-json" in err


def test_cli_rejects_compact_json_with_list(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "--list", "--compact-json"]) == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err
    assert "--compact-json" in err
    assert "--list" in err


def test_cli_rejects_compact_json_with_summary(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "--summary", "--compact-json"]) == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err
    assert "--compact-json" in err
    assert "--summary" in err


def test_cli_rejects_compact_json_with_compact_summary(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "--compact-summary", "--compact-json"]) == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err
    assert "--compact-json" in err
    assert "--compact-summary" in err


def test_cli_strict_failure_emits_stderr_summary(tmp_path, capsys):
    code = r"""
filter {
  mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "%{missing_value}" } }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)
    assert main([str(parser_file), "additional.fields.foo", "--json", "--strict"]) == 3
    captured = capsys.readouterr()
    # Stdout JSON shape unchanged.
    payload = json.loads(captured.out)
    assert payload["status"] == "dynamic"
    # Stderr now carries a one-line strict summary naming the gates.
    assert "strict:" in captured.err
    assert "status=dynamic" in captured.err
    assert "warning" in captured.err
    assert "taint" in captured.err


def test_cli_strict_summary_emits_stderr_summary(tmp_path, capsys):
    code = r"""
filter {
  unsupported_custom_plugin { knob => "value" }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)
    assert main([str(parser_file), "--summary", "--strict", "--json"]) == 3
    captured = capsys.readouterr()
    assert "strict:" in captured.err
    assert "unsupported" in captured.err


def test_cli_max_parser_bytes_help_documents_unlimited():
    from parser_lineage_analyzer.cli import build_arg_parser

    help_text = build_arg_parser().format_help()
    # The --max-parser-bytes help text should mention the negative-sentinel.
    assert "--max-parser-bytes" in help_text
    assert "negative" in help_text.lower() or "unlimited" in help_text.lower()


def test_cli_empty_stdin_is_read_error(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert main(["-", "target.ip"]) == 1
    err = capsys.readouterr().err
    assert "empty" in err

    monkeypatch.setattr(sys, "stdin", io.StringIO("   \n\t  \n"))
    assert main(["-", "target.ip"]) == 1
    err = capsys.readouterr().err
    assert "empty" in err


def test_cli_empty_file_is_read_error(tmp_path, capsys):
    parser_file = tmp_path / "empty.cbn"
    parser_file.write_text("", encoding="utf-8")
    assert main([str(parser_file), "target.ip"]) == 1
    err = capsys.readouterr().err
    assert "empty" in err

    whitespace_file = tmp_path / "whitespace.cbn"
    whitespace_file.write_text("   \n\t  \n", encoding="utf-8")
    assert main([str(whitespace_file), "target.ip"]) == 1
    err = capsys.readouterr().err
    assert "empty" in err


def test_cli_rejects_list_combined_with_summary(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "--list", "--summary"]) == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err

    assert main([str(parser_file), "--list", "--compact-summary"]) == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err


def test_cli_rejects_empty_or_whitespace_udm_field(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)

    assert main([str(parser_file), ""]) == 2
    err = capsys.readouterr().err
    assert "udm_field cannot be empty" in err

    assert main([str(parser_file), "   "]) == 2
    err = capsys.readouterr().err
    assert "udm_field cannot be empty" in err

    assert main([str(parser_file), "  target.ip  "]) == 0
    out = capsys.readouterr().out
    assert "UDM field: target.ip\n" in out


def test_cli_missing_file_error_is_actionable(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.cbn"
    assert main([str(missing), "target.ip"]) == 1
    err = capsys.readouterr().err
    assert "parser file not found" in err
    assert "use '-' to read from stdin" in err
    assert "[Errno" not in err

    assert main([str(tmp_path), "target.ip"]) == 1
    err = capsys.readouterr().err
    assert "parser file is a directory" in err


def test_cli_size_cap_error_hints_at_flag(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip", "--max-parser-bytes", "10"]) == 1
    err = capsys.readouterr().err
    assert "raise with --max-parser-bytes" in err


def test_cli_compact_summary_text_uses_total_counts(tmp_path, capsys):
    code = "\n".join(
        ["filter {"]
        + [
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.field{i}" => "value" }} }}'
            for i in range(60)
        ]
        + ['  mutate { merge => { "@output" => "event" } }', "}"]
    )
    parser_file = _write_parser(tmp_path, code)

    assert main([str(parser_file), "--compact-summary"]) == 0

    out = capsys.readouterr().out
    assert "UDM fields: 60" in out


def test_cli_compact_summary_text_includes_count_maps(tmp_path, capsys):
    code = r"""
filter {
  unsupported_custom_plugin { knob => "value" }
  mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "%{missing_value}" } }
  mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{missing_value}" } }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)

    assert main([str(parser_file), "--compact-summary"]) == 0

    out = capsys.readouterr().out
    assert "Warning counts by code:" in out
    assert "  - dynamic_destination: 1" in out
    assert "Taint counts by code:" in out
    assert "  - unresolved_token: 3" in out
    assert "Diagnostic counts by code:" in out
    assert "  - dynamic_destination: 2" in out
    assert "  - unresolved_token: 3" in out


def test_cli_compact_json_bounds_query_output_and_reports_totals(tmp_path, capsys):
    code = "\n".join(
        ["filter {"]
        + [
            f'  mutate {{ add_field => {{ "event.idm.read_only_udm.additional.fields.repeat" => "value{i}" }} }}'
            for i in range(60)
        ]
        + ['  mutate { merge => { "@output" => "event" } }', "}"]
    )
    parser_file = _write_parser(tmp_path, code)

    assert main([str(parser_file), "additional.fields.repeat", "--compact-json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "repeated"
    assert len(payload["mappings"]) == 50
    assert payload["mappings_total"] == 60
    assert payload["normalized_candidates_total"] == len(payload["normalized_candidates"])


def test_lazy_public_exports_are_visible_and_cached():
    package = importlib.reload(parser_lineage_analyzer)

    for export in package.__all__:
        assert export in dir(package)

    assert "QueryResult" not in package.__dict__
    assert package.QueryResult.__name__ == "QueryResult"
    assert package.__dict__["QueryResult"] is package.QueryResult


def test_structured_warning_codes_cover_reviewed_categories():
    malformed = r"""
filter {
  json { source => "message" target => ["payload" }
  mutate { merge => { "@output" => "event" } }
}
"""
    assert any(
        w["code"] == "malformed_config" for w in ReverseParser(malformed).analysis_summary()["structured_warnings"]
    )

    unsupported = 'filter { unsupported_custom_plugin { knob => "value" } }'
    assert any(
        w["code"] == "unsupported_plugin" for w in ReverseParser(unsupported).analysis_summary()["structured_warnings"]
    )

    unknown_key = 'filter { json { sourc => "payload" } }'
    assert any(
        w["code"] == "unknown_config_key" for w in ReverseParser(unknown_key).analysis_summary()["structured_warnings"]
    )

    dynamic_condition = r"""
filter {
  if "%{kind}" == "foo" {
    mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
  }
}
"""
    assert any(
        w["code"] == "runtime_condition"
        for w in ReverseParser(dynamic_condition).analysis_summary()["structured_warnings"]
    )

    parse_recovery = r"""
filter {
  mutate {
    replace => {
      "event.idm.read_only_udm.udm.field" => "lost"
  mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
}
"""
    assert any(
        w["code"] == "parse_recovery" for w in ReverseParser(parse_recovery).analysis_summary()["structured_warnings"]
    )


def test_warning_order_preserves_first_seen_line_order():
    code = "\n".join(
        [
            "filter {",
            '  if [a] =~ /a.*/ { mutate { replace => { "event.idm.read_only_udm.metadata.description" => "a" } } }',
            '  mutate { replace => { "tmp3" => "x" } }',
            '  mutate { replace => { "tmp4" => "x" } }',
            '  mutate { replace => { "tmp5" => "x" } }',
            '  mutate { replace => { "tmp6" => "x" } }',
            '  mutate { replace => { "tmp7" => "x" } }',
            '  mutate { replace => { "tmp8" => "x" } }',
            '  mutate { replace => { "tmp9" => "x" } }',
            '  if [b] =~ /b.*/ { mutate { replace => { "event.idm.read_only_udm.metadata.product_name" => "b" } } }',
            "}",
        ]
    )
    warnings = [warning for warning in ReverseParser(code).analysis_summary()["warnings"] if "condition" in warning]
    assert "line 2:" in warnings[0]
    assert "line 10:" in warnings[1]


def test_dynamic_conditional_result_keeps_status_and_exposes_flags():
    code = r"""
filter {
  if [kind] =~ /foo.*/ {
    mutate { replace => { "event.idm.read_only_udm.additional.fields.%{k}" => "x" } }
  }
  mutate { merge => { "@output" => "event" } }
}
"""
    result = ReverseParser(code).query("additional.fields.any")
    assert result.status == "dynamic"
    assert result.is_conditional is True
    assert result.has_dynamic is True
    assert result.has_unresolved is False


def test_scanner_has_no_backend_env_contract():
    assert not hasattr(scanner, "scanner_backend")
    assert scanner.strip_comments_keep_offsets("x // comment\n") == "x           \n"
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    legacy_scanner_env = "_".join(["SECOPS", "REVERSE", "PARSER", "SCANNER"])
    assert legacy_scanner_env not in readme
    assert "_scanner_rust" not in readme


@pytest.mark.parametrize("bad_value", [123, None, b"filter {}", 1.5, ["filter {}"], object()])
def test_reverse_parser_init_rejects_non_str_with_typeerror(bad_value):
    with pytest.raises(TypeError, match="parser_code must be str"):
        ReverseParser(bad_value)


@pytest.mark.parametrize("bad_value", [None, 123, b"target.ip", 1.5, ["target.ip"], object()])
def test_reverse_parser_query_rejects_non_str_with_typeerror(bad_value):
    rp = ReverseParser("")
    with pytest.raises(TypeError, match="udm_field must be str"):
        rp.query(bad_value)


def test_reverse_parser_public_methods_have_docstrings():
    # Library consumers rely on help(ReverseParser.query) / IDE tooltips for
    # the documented contract. Guard against accidental docstring removal.
    assert ReverseParser.__init__.__doc__
    assert ReverseParser.query.__doc__
    assert ReverseParser.list_udm_fields.__doc__
    assert ReverseParser.analyze.__doc__


def test_cli_list_strict_exits_three_on_warnings(tmp_path, capsys):
    code = r"""
filter {
  ruby { code => "event.cancel" }
  mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{network.dst_ip}" } }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)
    assert main([str(parser_file), "--list", "--strict"]) == 3
    captured = capsys.readouterr()
    # The UDM field listing still runs to stdout.
    assert "event.idm.read_only_udm.target.ip" in captured.out
    # Strict gate fires on stderr with the same shape as --summary --strict.
    assert "strict:" in captured.err
    assert "unsupported" in captured.err


def test_cli_list_strict_clean_parser_exits_zero(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "--list", "--strict"]) == 0
    captured = capsys.readouterr()
    assert "event.idm.read_only_udm.target.ip" in captured.out
    assert "strict:" not in captured.err


def test_cli_list_strict_json_exits_three_on_warnings(tmp_path, capsys):
    code = r"""
filter {
  unsupported_custom_plugin { knob => "value" }
  mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)
    assert main([str(parser_file), "--list", "--strict", "--json"]) == 3
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "event.idm.read_only_udm.target.ip" in payload["udm_fields"]
    assert "strict:" in captured.err


def test_cli_verbose_with_noop_modes_emits_stderr_warning(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)

    # --list + --verbose: clean parser → exit 0, but stderr must announce the no-op.
    assert main([str(parser_file), "--list", "--verbose"]) == 0
    err = capsys.readouterr().err
    assert "verbose is ignored" in err

    # --summary + --verbose
    assert main([str(parser_file), "--summary", "--verbose"]) == 0
    assert "verbose is ignored" in capsys.readouterr().err

    # --compact-summary + --verbose
    assert main([str(parser_file), "--compact-summary", "--verbose"]) == 0
    assert "verbose is ignored" in capsys.readouterr().err


def test_cli_verbose_with_json_modes_does_not_warn(tmp_path, capsys):
    """--verbose + --json/--compact-json is a no-op rather than misleading.
    JSON output already includes the parser_locations / notes / structured
    warning detail that ``--verbose`` would surface in text mode, so
    combining them is supported (no stderr warning)."""
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip", "--json", "--verbose"]) == 0
    assert "verbose is ignored" not in capsys.readouterr().err
    assert main([str(parser_file), "target.ip", "--compact-json", "--verbose"]) == 0
    assert "verbose is ignored" not in capsys.readouterr().err


def test_cli_verbose_with_text_query_does_not_warn(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip", "--verbose"]) == 0
    err = capsys.readouterr().err
    assert "verbose is ignored" not in err


def test_cli_list_strict_verbose_with_warnings_exits_three(tmp_path, capsys):
    # Combines Fix 3 (--list --strict → exit 3) with Fix 4 (--verbose stderr warning).
    code = r"""
filter {
  unsupported_custom_plugin { knob => "value" }
  mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } }
  mutate { merge => { "@output" => "event" } }
}
"""
    parser_file = _write_parser(tmp_path, code)
    assert main([str(parser_file), "--list", "--strict", "--verbose"]) == 3
    err = capsys.readouterr().err
    assert "verbose is ignored" in err
    assert "strict:" in err


def test_cli_strict_help_mentions_exit_three():
    from parser_lineage_analyzer.cli import build_arg_parser

    help_text = build_arg_parser().format_help()
    assert "--strict" in help_text
    assert "Exit 3" in help_text or "exit 3" in help_text
    # Also assert it covers --list (Fix 3 surface change).
    assert "--list" in help_text


def test_readme_documents_exit_codes():
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "## Exit codes" in readme
    # Each documented exit code should appear under that section.
    exit_section = readme.split("## Exit codes", 1)[1].split("##", 1)[0]
    assert "`0`" in exit_section
    assert "`1`" in exit_section
    assert "`2`" in exit_section
    assert "`3`" in exit_section


def test_cli_consumes_utf8_bom_from_parser_file(tmp_path, capsys):
    # Windows-authored parser files commonly carry a leading UTF-8 BOM. Decoding
    # with plain ``utf-8`` would push U+FEFF into the first identifier, which
    # used to make Lark recover with "no mappings" + exit 0. With BOM stripping
    # the CLI must succeed end-to-end and discover the same mapping as the
    # BOM-free parser.
    parser_file = tmp_path / "with_bom.cbn"
    parser_file.write_bytes(b"\xef\xbb\xbf" + SIMPLE_CODE.encode("utf-8"))

    assert main([str(parser_file), "target.ip", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "exact"
    # The 'no_assignment' suggestion should not appear in any warning channel
    # — the BOM was consumed so the parse succeeded.
    assert "warnings" not in payload or not any("No assignment" in warning for warning in payload.get("warnings", []))
    assert "hint" not in payload


def test_cli_consumes_utf8_bom_from_stdin(monkeypatch, capsys):
    # Mirror the file-path BOM test for stdin: we feed a BOM-prefixed string
    # and expect the analyzer to discover the same mapping.
    monkeypatch.setattr(sys, "stdin", io.StringIO("﻿" + SIMPLE_CODE))
    assert main(["-", "target.ip", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "exact"


def test_cli_query_no_match_renders_hint_separately_in_text(tmp_path, capsys):
    # When the query has no mappings, the analyzer's "Try --list" suggestion
    # is a UX nudge, not a parser warning. The text renderer must split it
    # into its own ``Hint:`` section so users can distinguish parser
    # diagnostics (line N: ...) from CLI suggestions.
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "nonexistent.field"]) == 0
    out = capsys.readouterr().out
    assert "Hint:\n  - No assignment to the requested field" in out
    assert "Try --list" in out
    # The hint must NOT be inside any "Warnings:" section.
    if "Warnings:" in out:
        warnings_block = out.split("Warnings:\n", 1)[1].split("\n\n", 1)[0]
        assert "No assignment" not in warnings_block


def test_cli_query_no_match_emits_top_level_hint_in_json(tmp_path, capsys):
    # JSON output must surface the suggestion as a distinct top-level ``hint``
    # key (with code ``query_no_match``) so machine consumers can filter it
    # out of warning aggregation pipelines.
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "nonexistent.field", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    hint = payload.get("hint")
    assert hint is not None
    assert hint["code"] == "query_no_match"
    assert "Try --list" in hint["warning"]
    # The hint must NOT also appear in the warnings / structured_warnings arrays.
    assert not any("No assignment" in warning for warning in payload.get("warnings", []))
    assert not any(warning.get("code") == "no_assignment" for warning in payload.get("structured_warnings", []))


def test_cli_query_no_match_emits_top_level_hint_in_compact_json(tmp_path, capsys):
    # ``--compact-json`` shares the no-match-hint contract with ``--json``.
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "nonexistent.field", "--compact-json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    hint = payload.get("hint")
    assert hint is not None
    assert hint["code"] == "query_no_match"
    # Compact JSON keeps the warning arrays as empty lists rather than
    # omitting them, so check explicitly.
    assert all("No assignment" not in warning for warning in payload.get("warnings", []))
    assert all(warning.get("code") != "no_assignment" for warning in payload.get("structured_warnings", []))


def test_cli_query_with_mapping_does_not_emit_hint(tmp_path, capsys):
    # Sanity check: when the requested field IS resolved, no hint section
    # should appear in either text or JSON output.
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip"]) == 0
    out = capsys.readouterr().out
    assert "Hint:" not in out
    assert "No assignment" not in out

    assert main([str(parser_file), "target.ip", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "hint" not in payload


def test_cli_mutate_canonical_order_help_omits_internal_ticket(tmp_path):
    # External CLI users should never see internal ticket IDs ("T4.2") in
    # ``--help`` output.
    from parser_lineage_analyzer.cli import build_arg_parser

    help_text = build_arg_parser().format_help()
    assert "--mutate-canonical-order" in help_text
    assert "T4.2" not in help_text
    # The behavior summary should still mention canonical order semantics.
    assert "canonical" in help_text.lower()


def test_max_parser_bytes_constant_is_shared_with_analyzer():
    # ``cli.MAX_PARSER_BYTES`` and ``analyzer.MAX_PARSER_BYTES`` must refer to
    # the same value so the help text never drifts from the library default.
    from parser_lineage_analyzer import analyzer as analyzer_module, cli as cli_module

    assert cli_module.MAX_PARSER_BYTES == analyzer_module.MAX_PARSER_BYTES


def test_cli_emits_parse_recovery_warning_to_stderr_on_garbage_input(monkeypatch, capsys):
    """A parser that fails to parse cleanly recovers via per-statement
    fallback. Without a stderr signal the only indication is buried in the
    body output, and downstream pipelines mistake "garbage in" for "valid
    parser, no match" — both exit 0. Surface a stderr line so the failure
    is at least visible; ``--strict`` is still required to convert it to a
    non-zero exit."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("invalid syntax garbage\n"))
    assert main(["-", "target.ip"]) == 0
    err = capsys.readouterr().err
    assert "parser recovered from" in err
    assert "unparsed statement" in err


def test_cli_does_not_warn_about_parse_recovery_for_clean_parser(tmp_path, capsys):
    parser_file = _write_parser(tmp_path)
    assert main([str(parser_file), "target.ip"]) == 0
    err = capsys.readouterr().err
    assert "parser recovered from" not in err


def test_cli_summary_emits_parse_recovery_warning_to_stderr(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("invalid syntax garbage\n"))
    assert main(["-", "--summary"]) == 0
    err = capsys.readouterr().err
    assert "parser recovered from" in err


def test_cli_text_output_scrubs_terminal_control_chars_in_warnings(tmp_path, capsys):
    """Hostile parser content must not be able to spoof adjacent log lines
    via \\r line-clobbering or recolor terminals via ANSI escapes when its
    text is echoed back through warnings/unsupported messages. JSON output
    is already safe because ``json.dumps`` escapes control characters."""
    code = 'filter {\n  unknown_plugin_\x1b[31m_evil { setting => "\\rEVIL" }\n}\n'
    parser_file = tmp_path / "evil.cbn"
    parser_file.write_text(code, encoding="utf-8")
    assert main([str(parser_file), "--summary"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\r" not in out


def test_io_anchor_is_publicly_exported():
    """``IOAnchor`` is part of the documented public surface — analyzer
    state exposes ``io_anchors`` on real parsers and SDK consumers need to
    pattern-match the type without reaching into ``parser_lineage_analyzer.model``."""
    from parser_lineage_analyzer import IOAnchor

    assert "IOAnchor" in parser_lineage_analyzer.__all__
    assert IOAnchor.__name__ == "IOAnchor"


def test_legacy_status_alias_is_not_exported():
    """``Status`` was a backward-compatible alias for ``LineageStatus`` from
    a pre-public release. Initial v0.1.0 should not lock that alias into the
    public surface."""
    assert "Status" not in parser_lineage_analyzer.__all__
    with pytest.raises(AttributeError):
        parser_lineage_analyzer.Status  # noqa: B018  # attribute access asserts removal
