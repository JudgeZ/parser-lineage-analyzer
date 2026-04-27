"""Tests for the plugin signature registry (F3, PR-D).

Coverage targets:
* Registry: register / lookup / contains / merge / from_paths.
* TOML loader: single file, directory, sorted-key determinism, default
  ``name`` from table key, validation error → ValueError mapping.
* Bundled registry returns an empty registry (no signatures shipped in v0.2).
* Pydantic ``extra="forbid"`` rejects unknown signature keys.
* End-to-end dispatch: a registered fake plugin produces signature-dispatched
  lineage with the declared semantic_class / lineage_status / sources.
* Regression guard: an unregistered unknown plugin still hits the
  ``unsupported_plugin`` taint path.
* CLI flag plumbing: ``--plugin-signatures`` and ``--plugin-signatures-dir``
  reach ``ReverseParser``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from parser_lineage_analyzer._plugin_config_models import PluginSignature
from parser_lineage_analyzer._plugin_signatures import (
    PluginSignatureRegistry,
    load_bundled_registry,
)


def _sig(name: str, **overrides: object) -> PluginSignature:
    """Concise factory for tests; defaults to a single-source/single-dest enricher."""
    payload: dict[str, object] = {
        "name": name,
        "semantic_class": "enricher",
        "source_keys": ["source"],
        "dest_keys": ["target"],
        "lineage_status": "derived",
        "taint_hint": "none",
    }
    payload.update(overrides)
    return PluginSignature.model_validate(payload)


# -- PluginSignature pydantic model -----------------------------------


class TestPluginSignatureModel:
    def test_basic_construction(self) -> None:
        sig = _sig("foo")
        assert sig.name == "foo"
        assert sig.semantic_class == "enricher"
        assert sig.source_keys == ["source"]
        assert sig.dest_keys == ["target"]
        assert sig.lineage_status == "derived"
        assert sig.taint_hint == "none"
        assert sig.in_place is False
        assert sig.dest_value_kind == "scalar"

    @pytest.mark.parametrize("cls", ["extractor", "enricher", "transform", "mutate_like", "passthrough"])
    def test_all_semantic_classes_accepted(self, cls: str) -> None:
        sig = _sig("p", semantic_class=cls)
        assert sig.semantic_class == cls

    def test_typo_in_semantic_class_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PluginSignature.model_validate(
                {"name": "p", "semantic_class": "extracter", "source_keys": [], "dest_keys": []}
            )

    def test_extra_field_rejected_loud(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PluginSignature.model_validate(
                {
                    "name": "p",
                    "semantic_class": "extractor",
                    "source_keys": [],
                    "dest_keys": [],
                    "destination_keys": ["typo"],  # extra
                }
            )


# -- PluginSignatureRegistry ------------------------------------------


class TestRegistryBasics:
    def test_register_and_lookup(self) -> None:
        reg = PluginSignatureRegistry()
        sig = _sig("foo")
        reg.register(sig)
        assert reg.lookup("foo") is sig
        assert "foo" in reg

    def test_lookup_miss_returns_none(self) -> None:
        reg = PluginSignatureRegistry()
        assert reg.lookup("nope") is None
        assert "nope" not in reg

    def test_register_overwrites(self) -> None:
        reg = PluginSignatureRegistry()
        reg.register(_sig("foo", semantic_class="extractor"))
        reg.register(_sig("foo", semantic_class="enricher"))
        looked_up = reg.lookup("foo")
        assert looked_up is not None
        assert looked_up.semantic_class == "enricher"

    def test_names_sorted(self) -> None:
        reg = PluginSignatureRegistry()
        reg.register(_sig("zebra"))
        reg.register(_sig("alpha"))
        reg.register(_sig("mango"))
        assert reg.names() == ["alpha", "mango", "zebra"]

    def test_merge_last_write_wins(self) -> None:
        a = PluginSignatureRegistry({"foo": _sig("foo", semantic_class="extractor")})
        b = PluginSignatureRegistry({"foo": _sig("foo", semantic_class="enricher")})
        merged = a.merge(b)
        assert merged.lookup("foo") is not None
        assert merged.lookup("foo").semantic_class == "enricher"  # type: ignore[union-attr]
        # Inputs unmodified.
        assert a.lookup("foo").semantic_class == "extractor"  # type: ignore[union-attr]


# -- TOML loader ------------------------------------------------------


class TestTomlLoader:
    def test_load_rejects_top_level_scalar(self, tmp_path: Path) -> None:
        # Top-level scalars are NOT supported (the file must be a table-of-tables);
        # a stray scalar makes the loader fail with a clear error.
        f = tmp_path / "sigs.toml"
        f.write_text(
            'name = "ignored_top_level"\n'
            "\n"
            "[example]\n"
            'name = "example"\n'
            'semantic_class = "extractor"\n'
            'source_keys = ["src"]\n'
            'dest_keys = ["dst"]\n',
            encoding="utf-8",
        )
        reg = PluginSignatureRegistry()
        with pytest.raises(ValueError, match="must be a TOML table"):
            reg.load_toml(f)

    def test_load_only_tables(self, tmp_path: Path) -> None:
        f = tmp_path / "sigs.toml"
        f.write_text(
            '[example]\nname = "example"\nsemantic_class = "extractor"\nsource_keys = ["src"]\ndest_keys = ["dst"]\n',
            encoding="utf-8",
        )
        reg = PluginSignatureRegistry()
        reg.load_toml(f)
        sig = reg.lookup("example")
        assert sig is not None
        assert sig.semantic_class == "extractor"

    def test_default_name_from_table_key(self, tmp_path: Path) -> None:
        f = tmp_path / "sigs.toml"
        f.write_text(
            '[my_plugin]\nsemantic_class = "passthrough"\nsource_keys = ["src"]\ndest_keys = ["dst"]\n',
            encoding="utf-8",
        )
        reg = PluginSignatureRegistry()
        reg.load_toml(f)
        assert reg.lookup("my_plugin") is not None

    def test_invalid_signature_raises_value_error(self, tmp_path: Path) -> None:
        f = tmp_path / "sigs.toml"
        f.write_text(
            '[bad]\nsemantic_class = "not_a_real_class"\nsource_keys = ["src"]\ndest_keys = ["dst"]\n',
            encoding="utf-8",
        )
        reg = PluginSignatureRegistry()
        with pytest.raises(ValueError, match="invalid plugin signature 'bad'"):
            reg.load_toml(f)

    def test_load_directory_sorts_files(self, tmp_path: Path) -> None:
        for stem, cls in [("z", "extractor"), ("a", "enricher")]:
            (tmp_path / f"{stem}.toml").write_text(
                f"[overlap]\nsemantic_class = {cls!r}\nsource_keys = []\ndest_keys = []\n",
                encoding="utf-8",
            )
        reg = PluginSignatureRegistry()
        reg.load_directory(tmp_path)
        # `z.toml` loads after `a.toml` (sorted), so `extractor` wins.
        sig = reg.lookup("overlap")
        assert sig is not None
        assert sig.semantic_class == "extractor"

    def test_load_directory_ignores_non_toml(self, tmp_path: Path) -> None:
        (tmp_path / "ignored.txt").write_text("garbage", encoding="utf-8")
        (tmp_path / "real.toml").write_text(
            '[real]\nsemantic_class = "extractor"\nsource_keys = []\ndest_keys = []\n',
            encoding="utf-8",
        )
        reg = PluginSignatureRegistry()
        reg.load_directory(tmp_path)
        assert "real" in reg
        assert "ignored" not in reg

    def test_load_directory_silent_on_missing_path(self, tmp_path: Path) -> None:
        # Non-directory paths are silently ignored — the bundled directory
        # ships empty in v0.2 so callers can opt into "load if present"
        # without guarding.
        reg = PluginSignatureRegistry()
        reg.load_directory(tmp_path / "does_not_exist")
        assert len(reg) == 0

    def test_from_paths_directories_then_files(self, tmp_path: Path) -> None:
        dir_ = tmp_path / "defaults"
        dir_.mkdir()
        (dir_ / "plug.toml").write_text(
            '[plug]\nsemantic_class = "extractor"\nsource_keys = []\ndest_keys = []\n',
            encoding="utf-8",
        )
        override = tmp_path / "override.toml"
        override.write_text(
            '[plug]\nsemantic_class = "enricher"\nsource_keys = []\ndest_keys = []\n',
            encoding="utf-8",
        )
        reg = PluginSignatureRegistry.from_paths(files=[override], directories=[dir_])
        sig = reg.lookup("plug")
        # Files (override) load after directories (defaults), so enricher wins.
        assert sig is not None
        assert sig.semantic_class == "enricher"


# -- Bundled registry --------------------------------------------------


class TestBundledRegistry:
    def test_empty_in_v0_2(self) -> None:
        reg = load_bundled_registry()
        assert len(reg) == 0


# -- Dispatch end-to-end ----------------------------------------------


class TestDispatch:
    def test_unregistered_plugin_falls_through_to_unsupported_taint(self) -> None:
        from parser_lineage_analyzer.analyzer import ReverseParser

        # No registry: the unknown plugin must still produce the
        # ``unsupported_plugin`` taint (pre-F3 behavior preserved).
        src = """\
filter {
  totally_made_up_plugin {
    target => "event.idm.read_only_udm.metadata.product"
  }
}
"""
        rp = ReverseParser(src)
        rp.analyze()
        unsupported = " | ".join(rp.state.unsupported)
        assert "totally_made_up_plugin" in unsupported

    def test_signature_dispatched_replaces_unsupported_path(self) -> None:
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(
            _sig(
                "totally_made_up_plugin",
                semantic_class="enricher",
                source_keys=["source"],
                dest_keys=["target"],
                lineage_status="derived",
                taint_hint="none",
            )
        )
        src = """\
filter {
  totally_made_up_plugin {
    source => "message"
    target => "event.idm.read_only_udm.metadata.product"
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        # No unsupported_plugin taint.
        unsupported = " | ".join(rp.state.unsupported)
        assert "totally_made_up_plugin" not in unsupported
        # Lineage exists for the destination.
        result = rp.query("event.idm.read_only_udm.metadata.product")
        assert result.mappings, "destination should resolve via signature dispatch"

    def test_signature_taint_hint_attaches_per_destination(self) -> None:
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(
            _sig(
                "tainting_plugin",
                taint_hint="dynamic",
                source_keys=["source"],
                dest_keys=["target"],
            )
        )
        src = """\
filter {
  tainting_plugin {
    source => "message"
    target => "event.idm.read_only_udm.metadata.id"
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        lineages = rp.state.tokens.get("event.idm.read_only_udm.metadata.id", [])
        assert lineages
        codes = {t.code for lin in lineages for t in lin.taints}
        assert "signature_dispatched_dynamic" in codes

    def test_signature_dispatched_with_map_destinations(self) -> None:
        # ``replace`` style: dest_keys references a map of dest=>source pairs.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(
            _sig(
                "fanout_plugin",
                semantic_class="mutate_like",
                source_keys=[],
                dest_keys=["replace"],
                dest_value_kind="map",
            )
        )
        src = """\
filter {
  fanout_plugin {
    replace => {
      "event.idm.read_only_udm.metadata.product" => "%{message}"
      "event.idm.read_only_udm.metadata.vendor"  => "%{message}"
    }
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        for dest in (
            "event.idm.read_only_udm.metadata.product",
            "event.idm.read_only_udm.metadata.vendor",
        ):
            assert rp.state.tokens.get(dest), f"expected lineage for {dest}"


# -- CLI plumbing -----------------------------------------------------


class TestCliPlumbing:
    def test_cli_loads_plugin_signatures_file(self, tmp_path: Path) -> None:
        # Build a minimal parser file that uses an unknown plugin.
        parser_file = tmp_path / "parser.cbn"
        parser_file.write_text(
            'filter { my_special_plugin { source => "message" target => "event.idm.read_only_udm.metadata.product" } }\n',
            encoding="utf-8",
        )
        sigs_file = tmp_path / "sigs.toml"
        sigs_file.write_text(
            '[my_special_plugin]\nsemantic_class = "enricher"\nsource_keys = ["source"]\ndest_keys = ["target"]\n',
            encoding="utf-8",
        )
        from parser_lineage_analyzer.cli import main

        rc = main(
            [
                str(parser_file),
                "--summary",
                "--json",
                "--plugin-signatures",
                str(sigs_file),
            ]
        )
        assert rc == 0

    def test_cli_invalid_signature_file_returns_error(self, tmp_path: Path) -> None:
        parser_file = tmp_path / "parser.cbn"
        parser_file.write_text('filter { mutate { add_tag => ["x"] } }\n', encoding="utf-8")
        sigs_file = tmp_path / "bad.toml"
        sigs_file.write_text(
            '[bad]\nsemantic_class = "not_real"\nsource_keys = []\ndest_keys = []\n',
            encoding="utf-8",
        )
        from parser_lineage_analyzer.cli import main

        rc = main([str(parser_file), "--summary", "--json", "--plugin-signatures", str(sigs_file)])
        assert rc == 1


# -- Corpus fixture (loads paired *.signatures.toml) -------------------


class TestCorpusFixture:
    """The standard ``test_corpus_baseline`` runner constructs
    ``ReverseParser(src)`` with no signatures kwarg, so signature-dispatch
    fixtures need a dedicated test that knows about the paired TOML."""

    FIXTURE_DIR = Path(__file__).parent / "fixtures" / "test_corpus" / "expected"
    FIXTURE_NAME = "test_signature_dispatched_plugin"

    def test_signature_dispatched_corpus_fixture(self) -> None:
        from parser_lineage_analyzer.analyzer import ReverseParser

        parser_path = self.FIXTURE_DIR / f"{self.FIXTURE_NAME}.cbn"
        signatures_path = self.FIXTURE_DIR / f"{self.FIXTURE_NAME}.signatures.toml"
        assert parser_path.exists(), f"missing fixture parser: {parser_path}"
        assert signatures_path.exists(), f"missing paired signatures: {signatures_path}"

        registry = PluginSignatureRegistry()
        registry.load_toml(signatures_path)
        rp = ReverseParser(parser_path.read_text(encoding="utf-8"), plugin_signatures=registry)
        rp.analyze()

        # The custom enricher's destination resolves via signature dispatch.
        result = rp.query("event.idm.read_only_udm.principal.location.country")
        assert result.mappings, "destination should resolve via signature dispatch"

        # No `unsupported_plugin` taint (the registry intercepted the unknown name).
        unsupported_blob = " | ".join(rp.state.unsupported)
        assert "acme_geo_enrich" not in unsupported_blob

        # A `signature_dispatched_derived` taint is attached per the signature.
        lineages = rp.state.tokens.get("event.idm.read_only_udm.principal.location.country", [])
        codes = {t.code for lin in lineages for t in lin.taints}
        assert "signature_dispatched_derived" in codes


# -- Regression tests for review feedback on PR-D ---------------------


class TestPR12ReviewFixes:
    """Regression coverage for Gemini / Codex / CodeRabbit / Copilot findings
    on PR #12.

    Each test is named after the specific finding it nails down so a
    future regression is easy to attribute.
    """

    def test_on_error_block_runs_after_signature_dispatch(self) -> None:
        # Gemini high (#1): the dispatch's early return used to skip
        # ``_handle_on_error``. Built-in plugins call it after dispatch;
        # signature-dispatched plugins must too, so a trailing
        # ``on_error => "tag"`` (the canonical fail-tag form) is
        # processed symbolically — landing as a token-level Lineage at
        # the named flag.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(_sig("custom_enrich", source_keys=["source"], dest_keys=["target"], taint_hint="none"))
        src = """\
filter {
  custom_enrich {
    source => "message"
    target => "event.idm.read_only_udm.metadata.product"
    on_error => "_custom_enrich_failed"
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        # `_handle_on_error` records the flag as a token-level Lineage
        # with `kind="error_flag"`; presence of that token confirms the
        # post-dispatch hook fired.
        flag_lineages = rp.state.tokens.get("_custom_enrich_failed", [])
        kinds = {src.kind for lin in flag_lineages for src in lin.sources}
        assert "error_flag" in kinds, (
            f"on_error flag should be tracked when dispatch runs _handle_on_error; "
            f"got source kinds {sorted(kinds)} for token '_custom_enrich_failed'"
        )

    def test_post_plugin_decorators_run_after_signature_dispatch(self) -> None:
        # Gemini high (#2): built-in handlers call
        # ``_apply_post_plugin_decorators`` so ``add_tag`` /
        # ``add_field`` etc. on the plugin take effect. Signature
        # dispatch must do the same. ``add_tag`` populates
        # ``state.tag_state.possibly`` (and ``definitely`` on a single
        # path); ``add_field`` writes a mutate-style destination.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(_sig("decorated_plugin", source_keys=["source"], dest_keys=["target"], taint_hint="none"))
        src = """\
filter {
  decorated_plugin {
    source => "message"
    target => "event.idm.read_only_udm.metadata.product"
    add_tag => ["_decorated"]
    add_field => { "event.idm.read_only_udm.metadata.event_type" => "DECORATED" }
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        possibly = sorted(rp.state.tag_state.possibly)
        assert "_decorated" in possibly, f"add_tag decorator should populate tag_state.possibly; got {possibly}"
        # add_field is a mutate-style decorator; the field must resolve.
        result = rp.query("event.idm.read_only_udm.metadata.event_type")
        assert result.mappings, "add_field decorator should produce lineage"

    def test_signature_destination_appends_to_existing_lineage(self) -> None:
        # Gemini high (#2): generic handler can't know whether the
        # plugin's real semantics are replace-style or merge-style, so
        # ``_store_destination(append=True)`` matches the unsupported-
        # plugin fallback behavior — prior lineage on the field is
        # preserved as an alternative path.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(_sig("appender", source_keys=["source"], dest_keys=["target"], taint_hint="none"))
        # First a mutate.replace lays down lineage; then the signature-
        # dispatched plugin writes to the same destination. With
        # append=True both paths survive.
        src = """\
filter {
  mutate {
    replace => { "event.idm.read_only_udm.metadata.product" => "ORIGINAL" }
  }
  appender {
    source => "message"
    target => "event.idm.read_only_udm.metadata.product"
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        lineages = rp.state.tokens.get("event.idm.read_only_udm.metadata.product", [])
        # Expect 2+ lineages: the original mutate plus the signature-dispatched one.
        kinds = {src.kind for lin in lineages for src in lin.sources}
        assert "constant" in kinds or "literal" in kinds or "mutate_replace" in kinds, (
            f"expected prior mutate lineage to survive; got source kinds {sorted(kinds)}"
        )
        assert "signature_dispatched" in kinds, (
            f"expected signature-dispatched lineage to be added; got source kinds {sorted(kinds)}"
        )

    def test_per_destination_source_attribution_for_map_signatures(self) -> None:
        # Codex P1 (#3): with one shared ``source_lineages`` accumulator,
        # every destination in ``replace => {a => x, b => y}`` got the
        # union of x AND y. Per-destination tracking now attributes
        # each destination to its own source.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(
            _sig(
                "fanout_distinct_sources",
                semantic_class="mutate_like",
                source_keys=[],
                dest_keys=["replace"],
                dest_value_kind="map",
            )
        )
        # Distinct sources for each destination. Confirm each destination's
        # upstream sources include its own RHS but NOT the other's.
        src = """\
filter {
  grok {
    match => { "message" => "%{WORD:left} %{WORD:right}" }
  }
  fanout_distinct_sources {
    replace => {
      "event.idm.read_only_udm.metadata.product" => "%{left}"
      "event.idm.read_only_udm.metadata.vendor"  => "%{right}"
    }
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()

        def _upstream_capture_names(lineages: list) -> set[str]:
            """Pull every ``capture_name`` from each lineage's signature-
            dispatched upstream_sources. The grok captures both write a
            SourceRef whose ``source_token`` is the parent ``message``,
            so per-destination distinctness shows up only in
            ``capture_name`` (``"left"`` vs ``"right"``)."""
            names: set[str] = set()
            for lin in lineages:
                for src in lin.sources:
                    upstream = src.details.get("upstream_sources") if src.details else None
                    if not isinstance(upstream, (list, tuple)):
                        continue
                    for upstream_ref in upstream:
                        if isinstance(upstream_ref, Mapping):
                            cap = upstream_ref.get("capture_name")
                            if isinstance(cap, str):
                                names.add(cap)
            return names

        product_lins = rp.state.tokens.get("event.idm.read_only_udm.metadata.product", [])
        vendor_lins = rp.state.tokens.get("event.idm.read_only_udm.metadata.vendor", [])
        # Filter to just the signature-dispatched lineages.
        product_sig_lins = [lin for lin in product_lins if any(s.kind == "signature_dispatched" for s in lin.sources)]
        vendor_sig_lins = [lin for lin in vendor_lins if any(s.kind == "signature_dispatched" for s in lin.sources)]
        assert product_sig_lins, "product should have signature-dispatched lineage"
        assert vendor_sig_lins, "vendor should have signature-dispatched lineage"
        product_captures = _upstream_capture_names(product_sig_lins)
        vendor_captures = _upstream_capture_names(vendor_sig_lins)
        # Product attributes back to "left" but NOT "right".
        assert "left" in product_captures, (
            f"product should attribute to grok capture 'left'; got {sorted(product_captures)}"
        )
        assert "right" not in product_captures, (
            f"product MUST NOT attribute to capture 'right' (per-destination bug); got {sorted(product_captures)}"
        )
        # Vendor attributes back to "right" but NOT "left".
        assert "right" in vendor_captures, (
            f"vendor should attribute to grok capture 'right'; got {sorted(vendor_captures)}"
        )
        assert "left" not in vendor_captures, (
            f"vendor MUST NOT attribute to capture 'left' (per-destination bug); got {sorted(vendor_captures)}"
        )

    def test_dest_value_kind_list_produces_destinations(self) -> None:
        # Codex P1 (#4): ``dest_value_kind = "list"`` was documented but
        # never implemented. A plain list of destination field names
        # (``targets => ["a", "b"]``) is now honored when the signature
        # opts into the list shape.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(
            _sig(
                "fanout_list",
                semantic_class="enricher",
                source_keys=["source"],
                dest_keys=["targets"],
                dest_value_kind="list",
            )
        )
        src = """\
filter {
  fanout_list {
    source => "message"
    targets => [
      "event.idm.read_only_udm.metadata.product",
      "event.idm.read_only_udm.metadata.vendor"
    ]
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        for dest in (
            "event.idm.read_only_udm.metadata.product",
            "event.idm.read_only_udm.metadata.vendor",
        ):
            assert rp.state.tokens.get(dest), f"dest_value_kind='list' should produce lineage for {dest}"

    def test_sprintf_source_ref_is_stripped_before_resolve(self) -> None:
        # Copilot (#5): source values commonly use ``%{message}``-style
        # sprintf refs. Without ``_strip_ref``, ``_resolve_token`` looks
        # up the literal ``%{message}`` and falls through to unresolved.
        # The fix routes source values through ``_strip_ref`` first.
        from parser_lineage_analyzer.analyzer import ReverseParser

        reg = PluginSignatureRegistry()
        reg.register(
            _sig(
                "sprintf_source_plugin",
                semantic_class="enricher",
                source_keys=["source"],
                dest_keys=["target"],
                taint_hint="none",
            )
        )
        src = """\
filter {
  sprintf_source_plugin {
    source => "%{message}"
    target => "event.idm.read_only_udm.metadata.product"
  }
}
"""
        rp = ReverseParser(src, plugin_signatures=reg)
        rp.analyze()
        lineages = rp.state.tokens.get("event.idm.read_only_udm.metadata.product", [])
        assert lineages
        # The signature-dispatched lineage should attribute back to
        # "message" (the raw token) via upstream_sources, NOT to the
        # literal "%{message}" string.
        sig_lins = [lin for lin in lineages if any(s.kind == "signature_dispatched" for s in lin.sources)]
        assert sig_lins
        upstream_token_names: set[str] = set()
        for lin in sig_lins:
            for src in lin.sources:
                upstream = src.details.get("upstream_sources") if src.details else None
                if not isinstance(upstream, (list, tuple)):
                    continue
                for ref in upstream:
                    if isinstance(ref, Mapping):
                        tok = ref.get("source_token")
                        if isinstance(tok, str):
                            upstream_token_names.add(tok)
        assert "message" in upstream_token_names, (
            f"upstream attribution should resolve %{{message}} to the 'message' token; "
            f"got {sorted(upstream_token_names)}"
        )
