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
from typing import cast

import pytest

from parser_lineage_analyzer._grok_patterns import (
    MAX_EXPANDED_BODY_BYTES,
    MAX_GROK_RECURSION_DEPTH,
    GrokLibrary,
    bundled_library,
    expand_pattern,
    load_library_from_paths,
)
from parser_lineage_analyzer._types import ConfigPair, ConfigValue


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

    def test_uri_expands_within_budget(self) -> None:
        # The module's recursion-depth comment claims the deepest chain in
        # the upstream legacy library tops out around URI's 5-layer fan-in
        # (URIPROTO/USER/URIHOST/URIPATH/...). Pin that as a positive
        # assertion: ``expand_pattern("URI")`` must return a non-``None``
        # body so the bundled library — and the comment's depth claim —
        # cannot silently regress past either the depth bound or
        # ``MAX_EXPANDED_BODY_BYTES``.
        body = expand_pattern("URI")
        assert body is not None, (
            "URI no longer expands — depth or byte budget regressed; if intentional, "
            "update _grok_patterns.py:27-30 and remove this assertion."
        )
        assert "%{" not in body


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


class TestLoadLibraryFromPathsSafety:
    """Loader robustness: byte cap and symlink containment."""

    def test_explicit_oversize_file_raises_value_error(self, tmp_path: Path) -> None:
        # An explicit file argument that exceeds the per-file byte cap
        # surfaces as a loud ``ValueError`` so a typo or wrong path
        # doesn't silently produce an empty library.
        from parser_lineage_analyzer._grok_patterns import MAX_PATTERN_FILE_BYTES

        oversize = tmp_path / "huge"
        # 2 MiB of pattern-shaped lines (well past the 1 MiB cap).
        oversize.write_bytes(b"FOO foo\n" * ((2 * MAX_PATTERN_FILE_BYTES) // 8))
        with pytest.raises(ValueError, match="exceeds .* bytes"):
            load_library_from_paths([oversize])

    def test_directory_oversize_file_silently_skipped(self, tmp_path: Path) -> None:
        # When walking a directory, oversize files are silently skipped
        # (matches the silent-drop convention for malformed lines).
        # Sibling files that are within the cap still load.
        from parser_lineage_analyzer._grok_patterns import MAX_PATTERN_FILE_BYTES

        big = tmp_path / "big"
        big.write_bytes(b"BIG big\n" * ((2 * MAX_PATTERN_FILE_BYTES) // 8))
        small = tmp_path / "small"
        small.write_text("SMALL small\n", encoding="utf-8")
        lib = load_library_from_paths([tmp_path])
        # Big was silently skipped; small still loads.
        assert "BIG" not in lib
        assert "SMALL" in lib
        assert expand_pattern("SMALL", lib) == "small"

    def test_in_directory_symlink_is_followed(self, tmp_path: Path) -> None:
        # Symlinks pointing inside the same directory must still be
        # followed — the safety bar is "no escape", not "no symlinks".
        target = tmp_path / "real"
        target.write_text("VIA_LINK via_link\n", encoding="utf-8")
        link = tmp_path / "link"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):  # pragma: no cover - filesystem-specific
            pytest.skip("symlinks unavailable on this filesystem")
        lib = load_library_from_paths([tmp_path])
        # Both the original file and the symlink resolve to the same
        # pattern definitions.
        assert "VIA_LINK" in lib
        assert expand_pattern("VIA_LINK", lib) == "via_link"

    def test_outside_directory_symlink_is_skipped(self, tmp_path: Path) -> None:
        # A symlink whose resolved target sits outside the configured
        # directory is skipped — a configured patterns dir shouldn't
        # silently pull pattern data from elsewhere on the filesystem
        # just because someone dropped a symlink in.
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "secret"
        outside_file.write_text("SECRET secret\n", encoding="utf-8")

        patterns_dir = tmp_path / "patterns"
        patterns_dir.mkdir()
        # Friendly local file that should still load.
        (patterns_dir / "ok").write_text("OK ok\n", encoding="utf-8")
        # Escaping symlink: should be skipped.
        link = patterns_dir / "escape_link"
        try:
            link.symlink_to(outside_file)
        except (OSError, NotImplementedError):  # pragma: no cover - filesystem-specific
            pytest.skip("symlinks unavailable on this filesystem")

        lib = load_library_from_paths([patterns_dir])
        assert "OK" in lib
        # The escaping symlink's target was not loaded.
        assert "SECRET" not in lib

    def test_case_insensitive_filesystem_follows_in_dir_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On macOS APFS / Windows NTFS, ``Path.is_relative_to`` does
        case-sensitive string equality even though the underlying lookup
        folds case. The shared ``path_is_within`` helper (in
        ``_path_safety``) routes both sides through ``os.path.normcase``
        so a case-mismatched directory argument doesn't false-reject an
        in-dir symlink. Mirrors the
        ``test_load_directory_case_insensitive_filesystem_follows_in_dir_symlink``
        test in the plugin-signatures suite — the two loaders share the
        same containment policy.
        """
        import os

        from parser_lineage_analyzer._path_safety import path_is_within

        monkeypatch.setattr(os.path, "normcase", lambda p: p.casefold())
        patterns_dir = tmp_path / "Patterns"
        patterns_dir.mkdir()
        target = patterns_dir / "real"
        target.write_text("VIA_LINK via_link\n", encoding="utf-8")
        link = patterns_dir / "link"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):  # pragma: no cover - filesystem-specific
            pytest.skip("symlinks unavailable on this filesystem")

        # Configured-directory argument differs only in case from the
        # resolved target's parent. Without ``path_is_within`` this
        # would mis-classify the in-dir symlink as outward.
        case_mismatched = tmp_path / "patterns"
        resolved_target = link.resolve()
        assert path_is_within(resolved_target, case_mismatched) is True
        # Sanity: a genuinely-outside path is still rejected even with
        # casefold normalization.
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        outside_file = outside / "secret"
        outside_file.write_text("SECRET secret\n", encoding="utf-8")
        assert path_is_within(outside_file, case_mismatched) is False


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


# -- Regression tests for review feedback on PR-B ---------------------


class TestPR11ReviewFixes:
    """Regression coverage for Gemini / Codex / Copilot findings on PR #11."""

    def test_leading_whitespace_in_pattern_file_is_tolerated(self) -> None:
        # Gemini finding: ``re.search(r"\s", line)`` on a leading-whitespace
        # line found the leading space as the separator, producing an empty
        # NAME and silently dropping the entry. Strip both ends first.
        from parser_lineage_analyzer._grok_patterns import _parse_pattern_file_text

        text = "  INDENTED_PAT  body_for_indented\n\tTAB_PAT\tbody_for_tab\nFLUSH_PAT flush_body\n"
        parsed = _parse_pattern_file_text(text)
        assert parsed == {
            "INDENTED_PAT": "body_for_indented",
            "TAB_PAT": "body_for_tab",
            "FLUSH_PAT": "flush_body",
        }

    def test_pre_substitution_byte_budget_short_circuits(self) -> None:
        # Codex P2: previous implementation called ``re.sub`` first and
        # then checked the byte cap, so an adversarial pattern like
        # ``BIG => "%{CHUNK} ..." * 100`` would allocate a multi-megabyte
        # intermediate string before bailing. The new ``_expand`` streams
        # segments and bails as soon as ``bytes_so_far`` exceeds the cap.
        from parser_lineage_analyzer._grok_patterns import (
            MAX_EXPANDED_BODY_BYTES,
            GrokLibrary,
            expand_pattern,
        )

        chunk_body = "X" * 1024  # 1 KB on its own — fits comfortably
        # 100 references × ~1 KB each = 100 KB, far over the 8 KB cap.
        big_body = " ".join("%{CHUNK}" for _ in range(100))
        lib = GrokLibrary({"BIG": big_body, "CHUNK": chunk_body})
        # Should return None (over budget) without exceeding it: confirm
        # the cap is enforced (we can't directly observe peak memory,
        # but the result being None proves the streaming check fired).
        assert expand_pattern("BIG", lib) is None
        # CHUNK alone fits.
        assert expand_pattern("CHUNK", lib) == chunk_body
        assert len(chunk_body) < MAX_EXPANDED_BODY_BYTES

    def test_inner_call_memoization_shares_within_one_expand(self) -> None:
        # PR-B self-review: a body referencing the same pattern N times
        # used to recompute N times. The inner cache shares within one
        # outer ``expand_pattern`` call. Observable effect: a deeply-
        # nested pattern that fans out to many sub-references resolves
        # without exploding.
        from parser_lineage_analyzer._grok_patterns import GrokLibrary, expand_pattern

        # 10 references to LEAF (single byte body) — all 10 should
        # share the same inner-cache slot for LEAF.
        body = "".join("%{LEAF}" for _ in range(10))
        lib = GrokLibrary({"OUTER": body, "LEAF": "x"})
        assert expand_pattern("OUTER", lib) == "x" * 10

    def test_is_pattern_data_file_filters_extensions(self) -> None:
        # PR-B self-review: a stray non-pattern file in grok_patterns/
        # would have been silently parsed. Filter known non-pattern
        # extensions defensively.
        from parser_lineage_analyzer._grok_patterns import _is_pattern_data_file

        # Real pattern files (extensionless).
        for name in ("aws", "grok-patterns", "linux-syslog", "haproxy"):
            assert _is_pattern_data_file(name)
        # Bundle metadata.
        for name in ("NOTICE", "LICENSE", "__init__.py", "__pycache__"):
            assert not _is_pattern_data_file(name)
        # Hidden files.
        for name in (".DS_Store", ".gitkeep", ".hidden"):
            assert not _is_pattern_data_file(name)
        # Non-pattern extensions.
        for name in ("README.md", "CHANGELOG.txt", "config.json", "data.toml", "schema.yaml"):
            assert not _is_pattern_data_file(name)

    def test_cli_validates_grok_patterns_dir_path_exists(self, tmp_path: Path) -> None:
        # Gemini finding: a typo in --grok-patterns-dir silently produces
        # an empty user library because load_library_from_paths is
        # tolerant of missing paths (intentional for programmatic use).
        # The CLI surface should fail loudly so the user notices.
        from parser_lineage_analyzer.cli import main

        parser_file = tmp_path / "parser.cbn"
        parser_file.write_text('filter { mutate { add_tag => ["x"] } }\n', encoding="utf-8")
        bogus = tmp_path / "this_does_not_exist"
        rc = main(
            [
                str(parser_file),
                "--summary",
                "--json",
                "--grok-patterns-dir",
                str(bogus),
            ]
        )
        assert rc == 1, f"CLI should exit 1 on missing --grok-patterns-dir path; got {rc}"

    def test_cli_accepts_existing_grok_patterns_dir(self, tmp_path: Path) -> None:
        # Sanity-check the validation path's positive case: an existing
        # directory passes through to ReverseParser without error.
        from parser_lineage_analyzer.cli import main

        parser_file = tmp_path / "parser.cbn"
        parser_file.write_text('filter { mutate { add_tag => ["x"] } }\n', encoding="utf-8")
        sigs_dir = tmp_path / "patterns"
        sigs_dir.mkdir()
        (sigs_dir / "user").write_text("MY_PAT my_body\n", encoding="utf-8")
        rc = main(
            [
                str(parser_file),
                "--summary",
                "--json",
                "--grok-patterns-dir",
                str(sigs_dir),
            ]
        )
        assert rc == 0

    def test_malformed_pattern_definitions_entries_taint(self) -> None:
        # Codex P2: when a pattern_definitions entry's value is not a
        # plain string (e.g. nested map, array), the previous loop
        # silently dropped it. Now we taint conservatively — silently
        # dropping would let the analyzer report exact_capture for grok
        # rules whose effective pattern set is not actually modeled.
        #
        # We can't easily construct an array-valued pattern_definitions
        # via the Logstash-style grammar, but we CAN exercise the path
        # by directly invoking ``_exec_grok`` with a synthetic Plugin.
        from parser_lineage_analyzer._analysis_state import AnalyzerState
        from parser_lineage_analyzer.analyzer import ReverseParser
        from parser_lineage_analyzer.ast_nodes import Plugin

        # Construct a Plugin AST node by hand with a malformed
        # pattern_definitions entry: ("BAD_PAT", ["nested", "list"]).
        # This bypasses the grammar and goes straight to _exec_grok.
        rp = ReverseParser('filter { mutate { add_tag => ["x"] } }')
        rp.analyze()
        state = AnalyzerState()
        # ConfigPair tuples: (key, value). pattern_definitions value is
        # a list of (name, body) pairs. One good, one bad.
        pattern_definitions: list[tuple[str, ConfigValue]] = [
            ("GOOD_PAT", "[a-z]+"),
            ("BAD_PAT", cast(ConfigValue, ["nested", "list"])),
        ]
        config: list[ConfigPair] = [
            ("pattern_definitions", cast(ConfigValue, pattern_definitions)),
            ("match", cast(ConfigValue, [("message", "%{BAD_PAT:weird} %{GOOD_PAT:good}")])),
        ]
        plugin = Plugin(
            name="grok",
            body="",
            line=1,
            config=config,
        )
        rp._exec_grok(plugin, state, [])
        codes = {w.code for w in state.structured_warnings}
        assert "grok_pattern_definitions" in codes, (
            f"malformed entry should emit grok_pattern_definitions warning; got {sorted(codes)}"
        )
        # And the taint message should mention the malformed entry by name.
        taint_messages = [t.message for t in state.taints if t.code == "grok_pattern_definitions"]
        assert any("BAD_PAT" in msg for msg in taint_messages), (
            f"taint message should reference BAD_PAT; got {taint_messages}"
        )
