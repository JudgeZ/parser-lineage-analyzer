"""Static Parser Lineage Analyzer engine for Google SecOps / Chronicle parsers."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ._analysis_executor import AnalysisExecutor
from ._analysis_query import AnalysisQueryMixin
from ._analysis_state import AnalyzerState
from ._grok_patterns import GrokLibrary, bundled_library, load_library_from_paths
from ._plugin_signatures import PluginSignatureRegistry
from .model import Lineage, SourceRef
from .parser import parse_code_with_diagnostics

MAX_PARSER_BYTES = 25_000_000


class ReverseParser(AnalysisQueryMixin, AnalysisExecutor):
    """Static lineage engine for SecOps parser code.

    The engine does not execute a raw event. Instead, it symbolically follows the
    parser and records every possible assignment into UDM fields. This makes the
    output deterministic for parser text alone.
    """

    def __init__(
        self,
        parser_code: str,
        *,
        max_parser_bytes: int = MAX_PARSER_BYTES,
        mutate_canonical_order: bool = False,
        grok_patterns_dir: Sequence[Path | str] | None = None,
        plugin_signatures: PluginSignatureRegistry | None = None,
    ):
        """Construct a static lineage engine over a SecOps/Chronicle parser.

        ``parser_code`` is the parser source as a Python string (the contents of
        a ``.cbn`` or text parser file). The engine immediately invokes the
        Lark statement frontend, captures any recovery diagnostics as
        ``parse_recovery`` warnings/taints, and seeds the symbolic ``message``
        token; analysis itself runs lazily on the first ``analyze``/``query``
        call. ``max_parser_bytes`` caps the UTF-8 size of ``parser_code`` and
        defaults to ``25_000_000``; pass a negative value (e.g. ``-1``) to
        disable the limit. ``mutate_canonical_order`` opts into Logstash's
        canonical per-block mutate execution order; the default of ``False``
        preserves source order, which matches historical analyzer behavior.

        ``grok_patterns_dir`` extends the bundled Logstash legacy grok pattern
        library with user-supplied pattern files. Each entry may be a file or
        a directory; directory entries enumerate files in sorted order;
        argument order determines merge order with last-write-wins (matches
        Logstash ``patterns_dir`` semantics). The bundled library is always
        loaded first as the base layer.

        ``plugin_signatures`` is an optional :class:`PluginSignatureRegistry`
        teaching the analyzer how to model unknown plugins. When ``None``
        (the default), unknown plugins fall through to the ``unsupported_plugin``
        taint path — preserving pre-F3 behavior byte-for-byte.

        Raises ``TypeError`` if ``parser_code`` is not a ``str`` and
        ``ValueError`` if the encoded size exceeds ``max_parser_bytes``.
        """
        if not isinstance(parser_code, str):
            raise TypeError(f"parser_code must be str, got {type(parser_code).__name__}")
        size = len(parser_code.encode("utf-8"))
        if max_parser_bytes >= 0 and size > max_parser_bytes:
            raise ValueError(f"Parser input size {size} bytes exceeds maximum parser size of {max_parser_bytes} bytes")
        self.parser_code = parser_code
        self.ast, self.parse_diagnostics = parse_code_with_diagnostics(parser_code)
        self.state = AnalyzerState()
        # Phase 4A: when set, the mutate dispatcher reorders operations to
        # match Logstash's hardcoded canonical order before iterating. This
        # is opt-in because most real parsers exploit source-order semantics
        # and changing the default would silently re-derive every existing
        # mutate test.
        self.state.mutate_canonical_order = mutate_canonical_order
        # PR-B: grok pattern library. Bundled patterns are always loaded;
        # user-supplied directories merge on top with last-write-wins.
        # Stored on ``self`` (not ``self.state``) because the library is
        # read-only and shared across all branch clones.
        self.grok_library: GrokLibrary = bundled_library()
        if grok_patterns_dir:
            user_paths = [Path(p) for p in grok_patterns_dir]
            self.grok_library = self.grok_library.merge(load_library_from_paths(user_paths))
        # F3 (PR-D): plugin signature registry. Read by ``_exec_plugin``
        # in the unknown-plugin fallback to route to a generic handler
        # instead of the ``unsupported_plugin`` taint path. ``None``
        # preserves pre-F3 behavior.
        self.plugin_signatures: PluginSignatureRegistry | None = plugin_signatures
        self._init_state()
        for diag in self.parse_diagnostics:
            warning = (
                f"Lark parse diagnostic line {getattr(diag, 'line', '?')}, "
                f"column {getattr(diag, 'column', '?')}: {getattr(diag, 'message', diag)}"
            )
            loc = f"line {getattr(diag, 'line', '?')}: parser"
            self.state.add_warning(warning, code="parse_recovery", message=warning, parser_location=loc)
            self.state.add_taint("parse_recovery", warning, loc)
        self._executed = False

    def _init_state(self) -> None:
        self.state.tokens["message"] = [
            Lineage(
                status="exact",
                # "message" is the Logstash field name; not a credential.
                sources=[SourceRef(kind="raw_message", source_token="message", path="message")],  # nosec B106
                expression="message",
                parser_locations=["initial parser input"],
            )
        ]

    def analyze(self) -> AnalyzerState:
        """Run symbolic execution over the parsed AST and return the analyzer state.

        The full ``AnalyzerState`` exposes every internal token, output anchor,
        unsupported construct, warning, taint, and diagnostic that the engine
        observed. Use this when a caller needs the raw analyzer surface — most
        consumers should prefer ``query`` (per-UDM-field result) or
        ``analysis_summary`` (CI-friendly coverage metadata) instead.

        Analysis runs at most once per instance; subsequent calls return the
        same ``AnalyzerState`` object.
        """
        if not self._executed:
            self._exec_statements(self.ast, self.state, [])
            self._executed = True
        return self.state


__all__ = [
    "ReverseParser",
]
