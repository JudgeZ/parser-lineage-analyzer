"""Tests for the grok pattern resolver (`_grok_patterns`).

Coverage targets:
* Bundled library loads and resolves common upstream patterns.
* `expand_pattern` recursively inlines `%{NAME}` references.
* Cycle detection (mutual recursion) returns ``None`` rather than recursing.
* Recursion depth bound (`MAX_GROK_RECURSION_DEPTH`) returns ``None``.
* Byte expansion bound (`MAX_EXPANDED_BODY_BYTES`) returns ``None``.
* Missing pattern names return ``None``.
* User-supplied libraries override bundled patterns by last-write-wins.
* Identity / hashing semantics share LRU cache slots across logically-equal libraries.
* Loading from filesystem paths (single file + directory).
* Soundness contract: every failure mode returns ``None``, never partial output.
"""

from __future__ import annotations

from pathlib import Path

from parser_lineage_analyzer._grok_patterns import (
    MAX_EXPANDED_BODY_BYTES,
    MAX_GROK_RECURSION_DEPTH,
    GrokLibrary,
    bundled_library,
    expand_pattern,
    load_library_from_paths,
)


class TestBundledLibrary:
    def test_loads_with_expected_patterns(self) -> None:
        lib = bundled_library()
        # Spot-check a handful of patterns the upstream legacy bundle ships.
        for name in ("IP", "IPV4", "IPV6", "WORD", "NUMBER", "TIMESTAMP_ISO8601", "COMMONAPACHELOG"):
            assert name in lib, f"expected bundled pattern {name!r} to be present"

    def test_singleton_returns_same_instance(self) -> None:
        # Bundled library is process-singleton — repeated calls return the
        # cached instance rather than reparsing data files.
        first = bundled_library()
        second = bundled_library()
        assert first is second

    def test_resolves_simple_patterns(self) -> None:
        body = expand_pattern("WORD")
        assert body == r"\b\w+\b"

    def test_resolves_recursive_patterns(self) -> None:
        # IP wraps `(?:%{IPV6}|%{IPV4})` — expanded body must contain both
        # the IPV6 and IPV4 character classes.
        body = expand_pattern("IP")
        assert body is not None
        assert "0-9A-Fa-f" in body  # IPV6 hex
        assert "25[0-5]" in body  # IPV4 octet upper bound

    def test_resolved_bodies_have_no_grok_refs(self) -> None:
        # Post-expansion, no `%{...}` should remain — every reference must
        # have been inlined (or expansion would have returned None).
        for name in ("IP", "TIMESTAMP_ISO8601", "COMMONAPACHELOG", "URI"):
            body = expand_pattern(name)
            if body is None:
                continue  # pattern hit a budget bound; that's also sound
            assert "%{" not in body, f"{name} expansion still contains %{{...}}: {body[:60]}..."


class TestExpansionFailureModes:
    def test_unknown_name_returns_none(self) -> None:
        assert expand_pattern("DOES_NOT_EXIST") is None

    def test_empty_library_returns_none(self) -> None:
        empty = GrokLibrary({})
        assert expand_pattern("ANYTHING", empty) is None

    def test_cycle_detection_returns_none(self) -> None:
        # Direct self-reference: expanding A would need to inline A.
        cyclic = GrokLibrary({"A": "%{A}"})
        assert expand_pattern("A", cyclic) is None

        # Mutual recursion: A -> B -> A.
        mutual = GrokLibrary({"A": "%{B}", "B": "%{A}"})
        assert expand_pattern("A", mutual) is None
        assert expand_pattern("B", mutual) is None

    def test_depth_bound_returns_none(self) -> None:
        # Build a chain longer than the recursion depth bound.
        chain: dict[str, str] = {}
        for i in range(MAX_GROK_RECURSION_DEPTH + 5):
            chain[f"L{i}"] = f"%{{L{i + 1}}}" if i < MAX_GROK_RECURSION_DEPTH + 4 else "leaf"
        lib = GrokLibrary(chain)
        # Deep chain — somewhere along the way the depth bound trips and we
        # return ``None`` rather than expanding past the cap.
        assert expand_pattern("L0", lib) is None

    def test_byte_bound_returns_none(self) -> None:
        # Build a body that, after one expansion, blows past the byte bound.
        # ``BIG`` references ``CHUNK`` 100 times — each ``CHUNK`` is ~1KB, so
        # the total expansion is ~100KB which exceeds 8KB.
        chunk = "X" * 1024
        big_body = " ".join("%{CHUNK}" for _ in range(100))
        lib = GrokLibrary({"BIG": big_body, "CHUNK": chunk})
        result = expand_pattern("BIG", lib)
        assert result is None
        # Confirm the bound's location: at least the chunk size is expandable.
        assert expand_pattern("CHUNK", lib) == chunk
        assert len(chunk) < MAX_EXPANDED_BODY_BYTES

    def test_partial_failure_propagates(self) -> None:
        # If a sub-reference fails, the whole expansion fails (no partial output).
        lib = GrokLibrary({"OUTER": "before %{MISSING} after"})
        assert expand_pattern("OUTER", lib) is None


class TestUserLibraryMerge:
    def test_user_overrides_bundled(self) -> None:
        bundled = bundled_library()
        user = GrokLibrary({"WORD": "OVERRIDDEN"})
        merged = bundled.merge(user)
        # In the merged library, user's WORD wins.
        assert expand_pattern("WORD", merged) == "OVERRIDDEN"
        # The bundled library is unchanged (immutability check).
        assert expand_pattern("WORD", bundled) == r"\b\w+\b"

    def test_merge_preserves_unrelated_patterns(self) -> None:
        bundled = bundled_library()
        user = GrokLibrary({"MY_NEW_PATTERN": r"\d{4}"})
        merged = bundled.merge(user)
        assert expand_pattern("MY_NEW_PATTERN", merged) == r"\d{4}"
        assert expand_pattern("IP", merged) is not None  # bundled still resolves


class TestLibraryIdentity:
    def test_equal_content_equal_identity(self) -> None:
        a = GrokLibrary({"X": "1", "Y": "2"})
        b = GrokLibrary({"Y": "2", "X": "1"})  # different insertion order
        assert a == b
        assert hash(a) == hash(b)

    def test_different_content_different_identity(self) -> None:
        a = GrokLibrary({"X": "1"})
        b = GrokLibrary({"X": "2"})
        assert a != b
        # Hashes MAY collide but content compare differs; equality enforces.

    def test_cache_is_shared_across_logically_equal_libraries(self) -> None:
        # Two distinct GrokLibrary instances built from identical patterns
        # should share LRU cache slots in `_expand_pattern_cached`. We can
        # observe this indirectly: both must return identical results
        # (which is trivially true), and both must be hash-equal.
        a = GrokLibrary({"X": "%{Y}", "Y": "leaf"})
        b = GrokLibrary({"X": "%{Y}", "Y": "leaf"})
        assert hash(a) == hash(b)
        assert expand_pattern("X", a) == expand_pattern("X", b) == "leaf"


class TestLoadLibraryFromPaths:
    def test_load_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "user_patterns"
        f.write_text("FOO foo\nBAR bar\n", encoding="utf-8")
        lib = load_library_from_paths([f])
        assert "FOO" in lib
        assert "BAR" in lib
        assert expand_pattern("FOO", lib) == "foo"

    def test_load_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a").write_text("FROM_A from_a\n", encoding="utf-8")
        (tmp_path / "b").write_text("FROM_B from_b\n", encoding="utf-8")
        lib = load_library_from_paths([tmp_path])
        assert expand_pattern("FROM_A", lib) == "from_a"
        assert expand_pattern("FROM_B", lib) == "from_b"

    def test_argument_order_is_last_write_wins(self, tmp_path: Path) -> None:
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.write_text("OVERLAP first\n", encoding="utf-8")
        second.write_text("OVERLAP second\n", encoding="utf-8")
        lib = load_library_from_paths([first, second])
        assert expand_pattern("OVERLAP", lib) == "second"

    def test_directory_files_merge_in_sorted_order(self, tmp_path: Path) -> None:
        # Inside a directory, files merge sorted by name. Last-name wins on conflict.
        (tmp_path / "a").write_text("CONFLICT a\n", encoding="utf-8")
        (tmp_path / "z").write_text("CONFLICT z\n", encoding="utf-8")
        lib = load_library_from_paths([tmp_path])
        assert expand_pattern("CONFLICT", lib) == "z"

    def test_skips_hidden_files(self, tmp_path: Path) -> None:
        (tmp_path / ".hidden").write_text("HIDDEN hidden\n", encoding="utf-8")
        (tmp_path / "visible").write_text("VISIBLE visible\n", encoding="utf-8")
        lib = load_library_from_paths([tmp_path])
        assert "HIDDEN" not in lib
        assert "VISIBLE" in lib

    def test_skips_comment_and_blank_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "patterns"
        f.write_text(
            "# comment\n\n  # indented comment\nREAL real_body\n\n",
            encoding="utf-8",
        )
        lib = load_library_from_paths([f])
        assert "REAL" in lib
        assert expand_pattern("REAL", lib) == "real_body"

    def test_nonexistent_path_silently_skipped(self, tmp_path: Path) -> None:
        # Caller is responsible for validating paths exist; the loader
        # tolerates missing paths by returning an empty library.
        lib = load_library_from_paths([tmp_path / "does_not_exist"])
        assert len(lib) == 0


class TestParserIntegration:
    """End-to-end: ``ReverseParser`` exposes the resolved grok body through
    ``Lineage.sources[*].details`` for a captured field."""

    def test_resolved_body_attached_to_grok_capture_details(self) -> None:
        from parser_lineage_analyzer.analyzer import ReverseParser

        src = """\
filter {
  grok {
    match => { "message" => "%{IP:src_ip}" }
  }
}
"""
        rp = ReverseParser(src)
        rp.analyze()
        lins = rp.state.tokens.get("src_ip")
        assert lins, "expected lineage for src_ip after grok capture"
        # First lineage's first SourceRef should carry the resolved IP body.
        details = lins[0].sources[0].details
        assert details is not None
        assert details.get("resolved_pattern_name") == "IP"
        body = details.get("resolved_pattern_body")
        assert isinstance(body, str)
        # Sanity-check: IP body contains markers for both v4 and v6 alternatives.
        assert "25[0-5]" in body
        assert "0-9A-Fa-f" in body

    def test_unresolved_pattern_omits_resolved_fields(self) -> None:
        # An unknown grok pattern name still produces a capture lineage but
        # without resolved-body details — the consumer can distinguish.
        from parser_lineage_analyzer.analyzer import ReverseParser

        src = """\
filter {
  grok {
    match => { "message" => "%{TOTALLY_UNKNOWN_PATTERN:weird_capture}" }
  }
}
"""
        rp = ReverseParser(src)
        rp.analyze()
        lins = rp.state.tokens.get("weird_capture")
        assert lins
        details = lins[0].sources[0].details
        assert details is not None
        assert "resolved_pattern_body" not in details
