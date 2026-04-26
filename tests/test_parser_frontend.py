from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer.config_parser import (
    _parse_config_with_diagnostics_uncached,
    clear_config_parse_cache,
    config_parse_cache_info,
    parse_config,
)
from parser_lineage_analyzer.parser import find_matching, find_next_unquoted, strip_comments_keep_offsets


def test_regex_literal_hash_is_not_stripped_as_comment():
    code = r"""
    filter {
      if [field] =~ /abc#def/ {
        mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.2.3.4" } }
      }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "conditional"
    assert result.mappings[0].sources[0].expression == "1.2.3.4"
    assert any("/abc#def/" in cond for m in result.mappings for cond in m.conditions)
    assert not any("unparsed statement" in item for item in result.unsupported)


def test_scanner_comment_stripping_preserves_offsets_and_newlines():
    text = (
        'filter {\n  mutate { replace => { "x" => "y" } } // fake { }\n  # fake }\n  /* block {\n     still } */\n}\n'
    )
    stripped = strip_comments_keep_offsets(text)
    assert len(stripped) == len(text)
    assert [i for i, ch in enumerate(stripped) if ch == "\n"] == [i for i, ch in enumerate(text) if ch == "\n"]

    slash_start = text.index("//")
    slash_end = text.index("\n", slash_start)
    assert stripped[slash_start:slash_end].strip() == ""

    hash_start = text.index("#")
    hash_end = text.index("\n", hash_start)
    assert stripped[hash_start:hash_end].strip() == ""

    block_start = text.index("/*")
    block_end = text.index("*/") + 2
    assert stripped[block_start:block_end].count("\n") == text[block_start:block_end].count("\n")
    assert stripped[block_start:block_end].replace("\n", "").strip() == ""


def test_scanner_comment_stripping_returns_comment_free_input_unchanged():
    text = 'filter {\n  mutate { replace => { "x" => "y" } }\n}\n'
    assert strip_comments_keep_offsets(text) is text


def test_scanner_preserves_regex_xpath_and_path_like_literals():
    text = r"""
    filter {
      if [field] =~ /abc#\{def\}/ {
        mutate { replace => { "path" => "/var/log/syslog" } }
        xml { xpath => { //node => "token" } }
      }
    }
    """
    stripped = strip_comments_keep_offsets(text)
    assert "/abc#\\{def\\}/" in stripped
    assert "/var/log/syslog" in stripped
    assert "//node" in stripped


def test_scanner_delimiter_search_ignores_protected_regions():
    text = r'if [field{ignored}] =~ /abc\/{ignored}/ and [x] == "{ignored}" /* { */ { body { nested => "}" } }'
    expected_open = text.index("{ body")
    assert find_next_unquoted(text, len("if"), "{") == expected_open
    assert find_matching(text, expected_open) == text.rfind("}")


def test_formal_lalr_frontend_is_used():
    from parser_lineage_analyzer.parser import LalrSecOpsAstParser, parse_code

    ast = parse_code('filter { mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } } }')
    assert ast
    assert LalrSecOpsAstParser.__name__ == "LalrSecOpsAstParser"


def test_xpath_double_slash_is_not_treated_as_line_comment():
    code = r"""
    filter {
      for index, _ in xml(message,//Event/HOST_LIST/HOST) {
        xml {
          source => "message"
          xpath => { "//Event/HOST_LIST/HOST[%{index}]/IP" => "IPs" }
        }
      }
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{IPs}" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.mappings
    assert any(
        src.kind == "xml_xpath" and src.path == "//Event/HOST_LIST/HOST[*]/IP"
        for m in result.mappings
        for src in m.sources
    )
    assert not any("parse diagnostic" in w.lower() for w in result.warnings)


def test_config_fast_path_handles_bare_url_values_without_consuming_comments_or_regexes():
    clear_config_parse_cache()
    assert parse_config('replace => { "url" => http://example.com/path }') == [
        ("replace", [("url", "http://example.com/path")])
    ]
    assert config_parse_cache_info().currsize == 0

    assert parse_config('replace => { "a" => "b" // comment\n "d" => "e" }') == [("replace", [("a", "b"), ("d", "e")])]
    assert parse_config("match => /a\\/b/") == [("match", "/a\\/b/")]


def test_config_fast_path_falls_back_for_hash_comments_in_arrays():
    text = "x => [a # comment\n b]"
    expected, diagnostics = _parse_config_with_diagnostics_uncached(text)

    clear_config_parse_cache()

    assert diagnostics == []
    assert expected == [("x", ["a", "b"])]
    assert parse_config(text) == expected
    assert config_parse_cache_info().currsize == 1


def test_config_parser_ignores_c_style_block_comments():
    assert parse_config('replace => { "a" => "b" /* comment */ "d" => "e" }') == [("replace", [("a", "b"), ("d", "e")])]

    expected, diagnostics = _parse_config_with_diagnostics_uncached('replace => { "a" => "b" /* } */ "d" => "e" }')
    assert diagnostics == []
    assert expected == [("replace", [("a", "b"), ("d", "e")])]


def test_c_block_comment_with_unmatched_brace_is_ignored():
    code = r"""
    filter {
      /* a block comment with fake syntax { if [x] == "y" { */
      mutate { replace => { "event.idm.read_only_udm.target.ip" => "9.9.9.9" } }
      mutate { merge => { "@output" => "event" } }
    }
    """
    result = ReverseParser(code).query("target.ip")
    assert result.status == "constant"
    assert result.mappings[0].sources[0].expression == "9.9.9.9"


def test_malformed_parser_fails_deterministically_not_with_traceback():
    code = 'filter { mutate { replace => { "event.idm.read_only_udm.target.ip" => "1.1.1.1" } '
    rp = ReverseParser(code)
    result = rp.query("target.ip")
    assert result.status == "unresolved"
    assert any("unparsed statement" in item for item in result.unsupported)
