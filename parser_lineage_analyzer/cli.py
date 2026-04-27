"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from . import __version__

if TYPE_CHECKING:
    from .model import QueryResult

# ``MAX_PARSER_BYTES`` is mirrored as a literal constant here so that
# ``parser-lineage-analyzer --help`` / ``--version`` do not pull in
# ``analyzer`` (and its pydantic/lark/native-extension dependency tree).
# A regression test in ``tests/test_cli_and_public_model.py`` pins this
# to the analyzer-side definition so a mismatch is caught at CI time.
MAX_PARSER_BYTES = 25_000_000

_STDIN_READ_CHUNK_CHARS = 64 * 1024
_UTF8_BOM_BYTES = b"\xef\xbb\xbf"


class _BinaryReadable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="parser-lineage-analyzer",
        description="Trace a Google SecOps / Chronicle UDM parser field to likely raw-log source field(s).",
    )
    parser.add_argument("parser_file", help="Path to a SecOps/Chronicle parser file (.cbn or text). Use '-' for stdin.")
    parser.add_argument(
        "udm_field", nargs="?", help="UDM field to trace, e.g. target.ip or event.idm.read_only_udm.target.ip"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--compact-json",
        action="store_true",
        help="Emit bounded JSON for high-cardinality query output. Query semantics are unchanged.",
    )
    parser.add_argument(
        "--list", action="store_true", help="List discovered UDM-like parser fields instead of querying one field."
    )
    parser.add_argument(
        "--summary", action="store_true", help="Emit parser/analyzer coverage summary instead of querying one field."
    )
    parser.add_argument(
        "--compact-summary",
        action="store_true",
        help="Bound high-volume summary diagnostics and include counts by code. Implies --summary.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit 3 if any parser-level (warning, taint, unsupported construct) "
            "or query-level (unresolved, partial, dynamic) finding is present. "
            "Applies to --list, --summary, --compact-summary, and query modes."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include full parser locations, notes, taints, and structured warning detail in text output.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--max-parser-bytes",
        type=int,
        default=MAX_PARSER_BYTES,
        help=(
            f"Maximum parser input size in bytes. Defaults to {MAX_PARSER_BYTES}. "
            "Use a negative value (e.g., -1) for unlimited."
        ),
    )
    # Per-mutate-block canonical ordering matches Logstash's documented
    # operation order (rename → update → replace → convert → gsub →
    # uppercase → lowercase → strip → remove → split → join → merge →
    # add_field → add_tag → remove_tag). Adjacent mutate{} blocks are
    # intentionally NOT merged for ordering: Logstash applies canonical order
    # within each individual mutate{} invocation, then advances to the next
    # pipeline plugin in source order. The per-pipeline alternative was
    # investigated and rejected (no real fixture demonstrated the cross-block
    # need).
    parser.add_argument(
        "--mutate-canonical-order",
        action="store_true",
        help=(
            "Reorder operations within each mutate{} block into Logstash's "
            "canonical execution order before iterating. Default is source "
            "order; this flag opts into Logstash-fidelity semantics."
        ),
    )
    parser.add_argument(
        "--grok-patterns-dir",
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "Add a directory (or single file) of grok pattern definitions to "
            "the bundled Logstash legacy library. Repeatable; later --grok-"
            "patterns-dir entries override earlier ones (matches Logstash "
            "patterns_dir semantics). Files inside a directory are merged in "
            "sorted-name order."
        ),
    )
    parser.add_argument(
        "--plugin-signatures",
        action="append",
        default=[],
        metavar="FILE",
        help=(
            "Load plugin signatures from a TOML FILE. Each top-level table "
            "describes one plugin (semantic_class, source_keys, dest_keys, "
            "lineage_status, taint_hint). Repeatable; later --plugin-signatures "
            "files override earlier ones. Without any signatures, unknown "
            "plugins fall through to the ``unsupported_plugin`` taint path."
        ),
    )
    parser.add_argument(
        "--plugin-signatures-dir",
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "Load every *.toml file in DIR as plugin signatures (non-recursive). "
            "Repeatable; --plugin-signatures-dir directories are processed "
            "first in argv order, then individual --plugin-signatures files; "
            "later sources override earlier ones."
        ),
    )
    parser.add_argument(
        "--include-pattern-bodies",
        action="store_true",
        help=(
            "Include resolved grok pattern bodies (the regex blob) in JSON "
            "output. By default JSON omits ``resolved_pattern_body`` from "
            "``details`` to keep ``jq | head`` output readable; "
            "``resolved_pattern_name`` is always preserved so consumers can "
            "look the body up by name."
        ),
    )
    return parser


def _parse_args(parser: argparse.ArgumentParser, argv: list[str] | None) -> argparse.Namespace:
    parse_intermixed_args = getattr(parser, "parse_intermixed_args", None)
    if parse_intermixed_args is not None:
        return cast(argparse.Namespace, parse_intermixed_args(argv))
    return parser.parse_args(argv)


def _strip_utf8_bom(text: str) -> str:
    # Defense in depth: file paths use ``utf-8-sig`` to consume a BOM before
    # decode, but stdin (and pre-decoded text streams without a binary buffer)
    # may still carry the U+FEFF character at the head. Stripping it here keeps
    # the first identifier from being silently corrupted before it reaches Lark.
    if text.startswith("﻿"):
        return text[1:]
    return text


def _read_stdin_bounded(max_parser_bytes: int) -> str:
    buffer = cast(_BinaryReadable | None, getattr(sys.stdin, "buffer", None))
    if max_parser_bytes < 0:
        data_or_text = buffer.read() if buffer is not None else sys.stdin.read()
        if isinstance(data_or_text, bytes):
            return _strip_utf8_bom(data_or_text.decode("utf-8-sig"))
        return _strip_utf8_bom(data_or_text)
    if buffer is not None:
        data = buffer.read(max_parser_bytes + 1)
        if len(data) > max_parser_bytes:
            raise ValueError(f"Parser input size exceeds maximum parser size of {max_parser_bytes} bytes")
        return _strip_utf8_bom(data.decode("utf-8-sig"))

    chunks: list[str] = []
    size = 0
    while True:
        remaining = max_parser_bytes - size
        if remaining < 0:
            raise ValueError(f"Parser input size exceeds maximum parser size of {max_parser_bytes} bytes")
        chunk = sys.stdin.read(min(_STDIN_READ_CHUNK_CHARS, remaining + 1))
        if not chunk:
            break
        size += len(chunk.encode("utf-8"))
        if size > max_parser_bytes:
            raise ValueError(f"Parser input size exceeds maximum parser size of {max_parser_bytes} bytes")
        chunks.append(chunk)
    return _strip_utf8_bom("".join(chunks))


def _read_parser(path: str, max_parser_bytes: int = MAX_PARSER_BYTES) -> str:
    if path == "-":
        text = _read_stdin_bounded(max_parser_bytes)
    else:
        parser_path = Path(path)
        if parser_path.is_dir():
            raise IsADirectoryError(path)
        if max_parser_bytes < 0:
            data = parser_path.read_bytes()
        else:
            with parser_path.open("rb") as handle:
                data = handle.read(max_parser_bytes + len(_UTF8_BOM_BYTES) + 1)
            payload_size = len(data.removeprefix(_UTF8_BOM_BYTES))
            if payload_size > max_parser_bytes:
                raise ValueError(
                    f"Parser input size exceeds maximum parser size of {max_parser_bytes} bytes "
                    f"(raise with --max-parser-bytes)"
                )
        # ``utf-8-sig`` transparently consumes a leading UTF-8 BOM (common on
        # Windows-authored files); the encoded size below still measures the
        # post-BOM payload, which is what the parser actually sees.
        text = data.decode("utf-8-sig")
    size = len(text.encode("utf-8"))
    if max_parser_bytes >= 0 and size > max_parser_bytes:
        raise ValueError(
            f"Parser input size {size} bytes exceeds maximum parser size of {max_parser_bytes} bytes "
            f"(raise with --max-parser-bytes)"
        )
    return text


# Inner repetitions are bounded to defeat catastrophic backtracking on
# adversarial input that lacks a closing quote. Each warning-rendered
# quoted span is upstream-bounded by ``MAX_REGEX_BODY_BYTES`` (512), so
# ``{0,1024}`` per side covers the cap with slack while still failing
# fast (in milliseconds) on a 10K-char string with no terminator.
_QUOTED_OVER_ESCAPE = re.compile(r"'((?:[^'\\]|\\.){0,1024}\\\\(?:[^'\\]|\\.){0,1024})'")


def _clean_warning_escapes(message: str) -> str:
    """Undo a single layer of Python ``repr()`` doubling on backslashes inside
    quoted regex fragments in warning messages.

    Several upstream warning helpers (``regex_over_escape_warning``,
    ``runtime_condition_warning``) build their text with ``f"... {pattern!r}
    ..."``, which doubles every backslash a second time. The user-facing
    output should display the source bytes as the user wrote them — single
    backslashes for ``\\d`` source, not the four-backslash ``\\\\d`` form
    that ``!r`` produces. Replacing only inside the single-quoted ``'...'``
    spans avoids touching message prose ("did you mean '\\d'?"), so the
    suggestion stays accurate while the surrounding regex literal is shown
    verbatim.
    """

    def _undouble(match: re.Match[str]) -> str:
        body = match.group(1)
        return "'" + body.replace("\\\\", "\\") + "'"

    return _QUOTED_OVER_ESCAPE.sub(_undouble, message)


def _summary_sequence(summary: Mapping[str, object], key: str) -> Sequence[object]:
    value = summary.get(key, [])
    return value if isinstance(value, Sequence) and not isinstance(value, str) else []


def _summary_count(summary: Mapping[str, object], key: str) -> int:
    total = summary.get(f"{key}_total")
    if isinstance(total, int):
        return total
    return len(_summary_sequence(summary, key))


def _summary_mapping(summary: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = summary.get(key, {})
    return value if isinstance(value, Mapping) else {}


def _summary_has_strict_findings(summary: Mapping[str, object]) -> bool:
    diagnostics = summary.get("diagnostics", [])
    has_strict_diagnostic = isinstance(diagnostics, list) and any(
        isinstance(diagnostic, dict) and diagnostic.get("strict", True) for diagnostic in diagnostics
    )
    return bool(summary.get("unsupported") or summary.get("warnings") or summary.get("taints") or has_strict_diagnostic)


def _print_strict_summary_failure(summary: Mapping[str, object]) -> None:
    unsupported_count = _summary_count(summary, "unsupported")
    warnings_count = _summary_count(summary, "warnings")
    taints_count = _summary_count(summary, "taints")
    print(
        f"strict: {unsupported_count} unsupported, {warnings_count} warning(s), "
        f"{taints_count} taint(s) in parser summary",
        file=sys.stderr,
    )


def _print_summary_count_map(
    summary: Mapping[str, object],
    key: str,
    heading: str,
    *,
    always_show: bool = False,
) -> None:
    counts = _summary_mapping(summary, key)
    if not counts:
        if not always_show:
            return
        # Always-show headings render an explicit ``(none)`` placeholder so
        # users discover the field exists even on a clean parser.
        print(f"{heading}:")
        print("  (none)")
        return
    print(f"{heading}:")
    for code in sorted(counts):
        print(f"  - {code}: {counts[code]}")


def _query_has_strict_findings(result: QueryResult) -> bool:
    return bool(
        result.status in {"unresolved", "partial", "dynamic"}
        or result.unsupported
        or result.warnings
        or result.has_taints
        or any(diagnostic.strict for diagnostic in result.effective_diagnostics)
    )


def _warn_if_parse_recovery(structured_warnings: Sequence[object]) -> None:
    """Surface a stderr notice when the parser had to recover from unparsed
    statements. Without this the only signal is buried in the body output and
    a downstream pipeline can mistake "garbage in" for "successful query".
    Exit code is unchanged so existing scripts keep working; use ``--strict``
    to convert this into a non-zero exit.
    """
    count = 0
    for warning in structured_warnings:
        code = getattr(warning, "code", None)
        if code is None and isinstance(warning, dict):
            code = warning.get("code")
        if code == "parse_recovery":
            count += 1
    if count:
        plural = "" if count == 1 else "s"
        print(
            f"warning: parser recovered from {count} unparsed statement{plural}; "
            "analysis may be incomplete (use --strict to fail)",
            file=sys.stderr,
        )


# Code emitted by the analyzer for the "no mappings discovered for the queried
# field" suggestion (see ``_analysis_query.py``). The CLI lifts this entry out
# of ``warnings`` / ``structured_warnings`` and renders it under a separate
# ``Hint:`` section / top-level ``hint`` JSON key so users can tell a parser
# diagnostic from a UX nudge at a glance.
_QUERY_NO_MATCH_CODE = "no_assignment"


def _extract_query_no_match_hint(result: QueryResult) -> dict[str, str] | None:
    """Detach the analyzer's "no assignment" suggestion from the warning lists.

    Mutates ``result.warnings`` and ``result.structured_warnings`` in place to
    remove the hint and returns the lifted hint as a plain dict (with ``code``,
    ``message``, and ``warning`` fields) for the renderer to display
    separately. Returns ``None`` if the hint isn't present.
    """
    structured = next(
        (warning for warning in result.structured_warnings if warning.code == _QUERY_NO_MATCH_CODE),
        None,
    )
    if structured is None:
        return None
    result.structured_warnings = [
        warning for warning in result.structured_warnings if warning.code != _QUERY_NO_MATCH_CODE
    ]
    hint_text = structured.warning or structured.message
    if hint_text in result.warnings:
        result.warnings = [warning for warning in result.warnings if warning != hint_text]
    return {
        "code": "query_no_match",
        "message": structured.message,
        "warning": hint_text,
    }


def _augment_json_with_hint(payload: str, hint: dict[str, str] | None) -> str:
    """Insert a top-level ``hint`` key into a rendered JSON document."""
    if hint is None:
        return payload
    data = json.loads(payload)
    if isinstance(data, dict):
        data["hint"] = hint
    return json.dumps(data, indent=2, sort_keys=False)


def _augment_json_with_strict_failure(payload: str, failure: dict[str, object] | None) -> str:
    """Insert a top-level ``strict_failure`` key when ``--strict`` triggers.

    Plain ``--strict`` already prints a one-line summary to stderr; the JSON
    document mirrors the same structure under ``strict_failure`` so machine
    consumers don't have to scrape stderr to decide whether to treat the
    payload as a failure. The stderr line is preserved unchanged.
    """
    if failure is None:
        return payload
    data = json.loads(payload)
    if isinstance(data, dict):
        data["strict_failure"] = failure
    return json.dumps(data, indent=2, sort_keys=False)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(build_arg_parser(), argv)
    summary_requested = args.summary or args.compact_summary
    if args.udm_field and (summary_requested or args.list):
        print("error: udm_field cannot be used with --list, --summary, or --compact-summary", file=sys.stderr)
        return 2
    if args.list and summary_requested:
        print("error: --list and --summary/--compact-summary are mutually exclusive", file=sys.stderr)
        return 2
    if args.json and args.compact_json:
        print("error: --json and --compact-json are mutually exclusive", file=sys.stderr)
        return 2
    if args.compact_json and args.list:
        print("error: --compact-json and --list are mutually exclusive", file=sys.stderr)
        return 2
    if args.compact_json and args.summary:
        print("error: --compact-json and --summary are mutually exclusive", file=sys.stderr)
        return 2
    if args.compact_json and args.compact_summary:
        print("error: --compact-json and --compact-summary are mutually exclusive", file=sys.stderr)
        return 2
    # JSON output already includes the same fields ``--verbose`` would surface
    # in text mode (parser_locations, notes, structured_warnings,
    # diagnostics), so combining ``--verbose`` with ``--json``/``--compact-json``
    # is a no-op rather than an error. Only warn for the modes where
    # ``--verbose`` is genuinely silent (--list, --summary, --compact-summary).
    if args.verbose and (args.list or args.summary or args.compact_summary):
        print(
            "warning: --verbose is ignored with --list, --summary, or --compact-summary",
            file=sys.stderr,
        )
    if args.udm_field is not None:
        stripped_udm = args.udm_field.strip()
        if not stripped_udm:
            print("error: udm_field cannot be empty", file=sys.stderr)
            return 2
        args.udm_field = stripped_udm
    try:
        code = _read_parser(args.parser_file, args.max_parser_bytes)
    except FileNotFoundError:
        print(
            f"error: parser file not found: {args.parser_file} (use '-' to read from stdin)",
            file=sys.stderr,
        )
        return 1
    except IsADirectoryError:
        print(f"error: parser file is a directory: {args.parser_file}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"error: permission denied reading parser file {args.parser_file}: {exc.strerror}", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"error: could not read parser file {args.parser_file}: {exc}", file=sys.stderr)
        return 1
    if not code.strip():
        print("error: parser input is empty (received 0 non-whitespace bytes)", file=sys.stderr)
        return 1
    from ._plugin_signatures import PluginSignatureRegistry
    from .analyzer import ReverseParser

    # Validate any --grok-patterns-dir paths exist before constructing
    # the analyzer. ``load_library_from_paths`` silently skips missing
    # paths (so the API stays tolerant to programmatic callers that
    # genuinely want optional paths), but a CLI typo should surface
    # immediately rather than silently produce an empty user library.
    if args.grok_patterns_dir:
        missing = [p for p in args.grok_patterns_dir if not Path(p).exists()]
        if missing:
            print(
                "error: --grok-patterns-dir path does not exist: " + ", ".join(missing),
                file=sys.stderr,
            )
            return 1

    plugin_signatures: PluginSignatureRegistry | None = None
    if args.plugin_signatures or args.plugin_signatures_dir:
        try:
            plugin_signatures = PluginSignatureRegistry.from_paths(
                files=[Path(p) for p in args.plugin_signatures],
                directories=[Path(p) for p in args.plugin_signatures_dir],
            )
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    try:
        rp = ReverseParser(
            code,
            max_parser_bytes=args.max_parser_bytes,
            mutate_canonical_order=args.mutate_canonical_order,
            grok_patterns_dir=args.grok_patterns_dir or None,
            plugin_signatures=plugin_signatures,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if summary_requested:
        summary = rp.analysis_summary(compact=args.compact_summary)
        _warn_if_parse_recovery(_summary_sequence(summary, "structured_warnings"))
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            from .render import sanitize_for_terminal

            unsupported = _summary_sequence(summary, "unsupported")
            warnings = _summary_sequence(summary, "warnings")
            print(f"UDM fields: {_summary_count(summary, 'udm_fields')}")
            print(f"Tokens: {summary['token_count']}")
            print(f"Output anchors: {_summary_count(summary, 'output_anchors')}")
            print(f"Unsupported: {_summary_count(summary, 'unsupported')}")
            print(f"Warnings: {_summary_count(summary, 'warnings')}")
            if args.compact_summary:
                _print_summary_count_map(summary, "warning_counts", "Warning counts by code")
                # Always emit the taint heading in compact-summary text mode so
                # users learn the field exists; ``_print_summary_count_map``
                # still prints the ``(none)`` placeholder for empty maps.
                _print_summary_count_map(
                    summary,
                    "taint_counts",
                    "Taint counts by code",
                    always_show=True,
                )
                _print_summary_count_map(summary, "diagnostic_counts", "Diagnostic counts by code")
            if unsupported:
                print("Unsupported constructs:")
                for item in unsupported:
                    print(f"  - {sanitize_for_terminal(str(item))}")
            if warnings:
                print("Warnings:")
                for item in warnings:
                    print(f"  - {sanitize_for_terminal(_clean_warning_escapes(str(item)))}")
        if args.strict and _summary_has_strict_findings(summary):
            sys.stdout.flush()
            _print_strict_summary_failure(summary)
            return 3
        return 0
    if args.list:
        fields = rp.list_udm_fields()
        # ``analyze()`` is memoized on the parser, so reading
        # ``state.structured_warnings`` directly costs nothing here, while
        # ``analysis_summary()`` does substantial dedup/aggregation work that
        # is only needed for the strict gate. Defer the expensive build.
        state = rp.analyze()
        _warn_if_parse_recovery(state.structured_warnings)
        if args.json:
            # Cross-mode JSON consumers expect the same top-level keys
            # regardless of which mode produced the document. ``--list``
            # carries no per-query data, so ``output_anchors``/``warnings``/
            # ``unsupported``/``structured_warnings``/``diagnostics`` are
            # always empty; emitting them as ``[]`` (instead of omitting)
            # keeps the shape stable for ``jq '.warnings | length'`` and
            # similar across query/summary/list modes.
            print(
                json.dumps(
                    {
                        "udm_fields": fields,
                        "udm_fields_total": len(fields),
                        "output_anchors": [],
                        "warnings": [],
                        "unsupported": [],
                        "structured_warnings": [],
                        "diagnostics": [],
                    },
                    indent=2,
                )
            )
        elif not fields:
            print("No UDM fields found.")
        else:
            from .render import sanitize_for_terminal

            for f in fields:
                print(sanitize_for_terminal(f))
        if args.strict:
            list_summary = rp.analysis_summary()
            if _summary_has_strict_findings(list_summary):
                sys.stdout.flush()
                _print_strict_summary_failure(list_summary)
                return 3
        return 0
    if not args.udm_field:
        print(
            "error: udm_field is required unless --list, --summary, or --compact-summary is used",
            file=sys.stderr,
        )
        return 2
    result = rp.query(args.udm_field, compact=args.compact_json)
    _warn_if_parse_recovery(result.structured_warnings)
    hint = _extract_query_no_match_hint(result)
    strict_failure_payload: dict[str, object] | None = None
    if args.strict and _query_has_strict_findings(result):
        warnings_count = len(result.warnings)
        taints_total = sum(len(mapping.taints) for mapping in result.mappings)
        unsupported_count = len(result.unsupported)
        strict_failure_payload = {
            "status": result.status,
            "unsupported": unsupported_count,
            "warnings": warnings_count,
            "taints": taints_total,
            "message": (
                f"strict: query status={result.status}, {unsupported_count} unsupported, "
                f"{warnings_count} warning(s), {taints_total} taint(s)"
            ),
        }
    if args.compact_json:
        from .render import render_compact_json

        rendered = render_compact_json(result, include_pattern_bodies=args.include_pattern_bodies)
        print(
            _augment_json_with_strict_failure(
                _augment_json_with_hint(rendered, hint),
                strict_failure_payload,
            )
        )
    elif args.json:
        from .render import render_json

        rendered = render_json(result, include_pattern_bodies=args.include_pattern_bodies)
        print(
            _augment_json_with_strict_failure(
                _augment_json_with_hint(rendered, hint),
                strict_failure_payload,
            )
        )
    else:
        from .render import render_text

        rendered = render_text(result, verbose=args.verbose)
        rendered = _clean_warning_escapes(rendered)
        if hint is not None:
            rendered = f"{rendered}\n\nHint:\n  - {hint['warning']}"
        print(rendered)
    if strict_failure_payload is not None:
        sys.stdout.flush()
        # Stderr message is preserved unchanged for back-compat with non-JSON
        # consumers; the JSON document also carries ``strict_failure`` so
        # machine consumers don't have to scrape stderr.
        print(strict_failure_payload["message"], file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
