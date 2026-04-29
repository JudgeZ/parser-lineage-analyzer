"""Statement flow, branching, looping, and plugin dispatch."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from functools import lru_cache
from typing import Literal, Protocol, cast

from ._analysis_condition_facts import (
    condition_is_contradicted,
    conditions_are_compatible,
    is_exact_literal_regex_condition,
)
from ._analysis_details import iterable_sources_details, loop_tuple_details
from ._analysis_diagnostics import (
    config_parse_warning,
    drop_warning,
    large_array_literal_warning,
    long_elif_chain_warning,
    loop_variables_warning,
    non_canonical_on_error_placement_warning,
    on_error_parse_warning,
    regex_over_escape_warning,
    ruby_concurrency_risk_warning,
    ruby_event_split_warning,
    runtime_condition_warning,
    static_limit_warning,
    unknown_config_key_warning,
    unparsed_statement,
    unreachable_branch_warning,
    unsupported_plugin,
)
from ._analysis_helpers import (
    _clean_condition,
    _dedupe_sources,
    _dedupe_strings,
    _diagnostic_key,
    _location,
    _normalize_field_ref,
    _path_from_iterable,
    _prior_negation_conditions,
    _taint_key,
    _warning_key,
)
from ._analysis_state import AnalyzerState, BranchRecord, FailureTagRoute
from ._plugin_specs import PLUGIN_SPECS, PluginSpec, dialect_profile_for, plugin_spec_for
from ._types import ConfigPair, ConfigValue
from .ast_nodes import ElifBlock, ForBlock, IfBlock, IOBlock, Plugin, Statement, Unknown
from .config_parser import all_values, as_pairs, decode_string_body, first_value
from .model import IOAnchor, Lineage, LineageStatus, SourceRef, SyntaxDiagnostic, TaintReason
from .parser import parse_code_with_diagnostics

MAX_NESTING_DEPTH = 64
MAX_STATIC_LOOP_ASSIGNMENTS = 100_000
MAX_CUMULATIVE_LOOP_FANOUT = 1_000
# Cap on the number of branch records ``_exec_clone`` will synthesize for a
# single ``clone { clones => [...] }`` block. A pathological literal list
# would otherwise produce one branch per entry; the cap keeps the merge
# linear and surfaces a structured ``clone_fanout`` warning so the user
# knows their query sees a representative sample rather than every clone.
MAX_CLONE_FANOUT = 128

# Phase 3B: detect `"<lit>" in [tags]` so the analyzer can flag branches
# that check for a tag no prior add_tag could have written.
_TAGS_MEMBERSHIP_RE = re.compile(r'^(?:"(?P<dlit>(?:\\.|[^"\\])*)"|\'(?P<slit>(?:\\.|[^\'\\])*)\')\s+in\s+\[tags\]$')

# Result of classifying a `"<lit>" in [tags]` condition against the current
# tag-state; see ``_tag_membership_check_status``.
TagMembershipStatus = Literal["definitely_true", "definitely_false", "unknown"]

# R1.3: detect `"<lit>" in [<field>]` for any field (not just `tags`).
# When `<field>`'s lineage carries `value_type="string"`, this is substring
# matching, not array membership — emit an advisory so users notice.
_GENERIC_IN_CHECK_RE = re.compile(
    r'^(?:"(?P<dlit>(?:\\.|[^"\\])*)"|\'(?P<slit>(?:\\.|[^\'\\])*)\')'
    r"\s+in\s+\[(?P<field>[A-Za-z_@][A-Za-z0-9_@.:-]*)\]$"
)
MAX_ELIF_CHAIN_BEFORE_WARNING = 1_000
MAX_ARRAY_LITERAL_BEFORE_WARNING = 100_000
_PluginHandler = Callable[[Plugin, AnalyzerState, list[str]], None]
_BlockPluginHandler = Callable[[Plugin, AnalyzerState, list[str], int, int], None]

# Regex over-escapes the analyzer flags (W3): a literal backslash followed by a
# regex metacharacter almost never matches what the author intended. The
# detector deliberately ignores quadruple-backslash sequences so users who
# really do want a literal backslash followed by `\d` are not falsely warned.
_REGEX_OVER_ESCAPE_RE = re.compile(r"(?<!\\)\\\\([dDwWsSbB.])")
_REGEX_LITERAL_IN_CONDITION_RE = re.compile(r"=~\s*/((?:\\.|[^/\\])*)/[A-Za-z]*")
# `on_error {` placed inside a plugin's config body (W5) is non-canonical — the
# canonical fallback form is the statement-level `} on_error { ... }`. We
# match the bare `on_error` identifier followed by `{`, with no `=>` separator
# preceding the brace, since `on_error => "tag"` (the canonical failure-tag
# form) is fine.
_ON_ERROR_BLOCK_IN_CONFIG_RE = re.compile(r"\bon_error\s*\{")


def _membership_literal(match: re.Match[str]) -> str:
    double_value = match.group("dlit")
    if double_value is not None:
        return decode_string_body(double_value, '"')
    return decode_string_body(match.group("slit") or "", "'")


def _iter_regex_over_escapes(condition: str) -> Iterable[tuple[str, str]]:
    """Yield (pattern, escape) for over-escaped regex metacharacters in `condition`.

    Each `escape` is a 3-char string like `\\\\d`: backslash, backslash, metachar.
    """
    for match in _REGEX_LITERAL_IN_CONDITION_RE.finditer(condition):
        body = match.group(1)
        for over_escape in _REGEX_OVER_ESCAPE_RE.finditer(body):
            yield body, over_escape.group(0)


def _iter_config_values(config: list[ConfigPair], depth: int = 0) -> Iterable[tuple[str, ConfigValue, int]]:
    """Walk a Plugin.config tree yielding (key, value, depth) for every entry.

    Depth 0 is the top-level config map; nested maps increase depth. Used by
    advisory passes that need to differentiate top-level versus nested keys
    (e.g. `on_error` is canonical at statement level, not as a nested key).
    """
    for key, value in config:
        yield key, value, depth
        if isinstance(value, list):
            pairs = as_pairs(value)
            if pairs:
                yield from _iter_config_values(pairs, depth + 1)


_IO_ANCHOR_CONFIG_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "kafka": ("topics", "topic", "bootstrap_servers", "group_id", "client_id"),
    "beats": ("port", "host", "ssl"),
    "file": ("path", "start_position", "sincedb_path", "codec"),
    "elasticsearch": ("hosts", "index", "user", "document_id"),
    "http": ("url", "http_method", "format"),
    "tcp": ("port", "host", "ssl_enable"),
    "udp": ("port", "host", "queue_size"),
    "redis": ("host", "port", "key", "data_type"),
    "syslog": ("port", "host", "facility"),
    "stdout": ("codec",),
    "stdin": ("codec",),
    "null": (),
}
_IO_ANCHOR_CONFIG_VALUE_LIMIT = 256
_SENSITIVE_IO_CONFIG_KEY_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret|"
    r"credential|password|passwd|secret|token|private[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)


def _is_sensitive_io_config_key(key: str) -> bool:
    return bool(_SENSITIVE_IO_CONFIG_KEY_RE.search(key))


def _render_io_config_value(value: ConfigValue) -> str | None:
    """Render a config value as a compact string for IOAnchor.config_summary.

    Returns ``None`` if the value is too long, contains nested-pair maps, or
    is otherwise unwieldy — the caller drops the entry rather than emit a
    misleading truncation.
    """
    if isinstance(value, str):
        rendered = value
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, list):
        if value and all(isinstance(x, tuple) and len(x) == 2 for x in value):
            return None  # nested map; skip rather than render unreadably
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(repr(item))
            elif isinstance(item, bool):
                parts.append("true" if item else "false")
            else:
                return None
        rendered = "[" + ", ".join(parts) + "]"
    else:
        return None
    if len(rendered) > _IO_ANCHOR_CONFIG_VALUE_LIMIT:
        return None
    return rendered


def _io_anchor_config_summary(plugin: Plugin) -> tuple[tuple[str, str], ...]:
    """Build the IOAnchor.config_summary tuple for a plugin invocation.

    Per-plugin allowlist controls which keys are interesting; unknown plugins
    fall back to "all top-level string-valued keys whose rendered value fits
    in the size cap". Order is preserved from the source config map so users
    see keys in the order the parser author wrote them.
    """
    allowlist = _IO_ANCHOR_CONFIG_ALLOWLIST.get(plugin.name)
    summary: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, value in plugin.config:
        if allowlist is not None and key not in allowlist:
            continue
        if key in seen:
            continue
        if _is_sensitive_io_config_key(key):
            continue
        rendered = _render_io_config_value(value)
        if rendered is None:
            continue
        seen.add(key)
        summary.append((key, rendered))
    return tuple(summary)


@lru_cache(maxsize=1024)
def _parse_on_error_body_cached(body: str) -> tuple[tuple[Statement, ...], tuple[SyntaxDiagnostic, ...]]:
    statements, diagnostics = parse_code_with_diagnostics(body, start_line=1)
    return tuple(statements), tuple(diagnostics)


def _offset_diagnostic_line(diagnostic: SyntaxDiagnostic, line_offset: int) -> SyntaxDiagnostic:
    return SyntaxDiagnostic(diagnostic.line + line_offset, diagnostic.column, diagnostic.message)


def _offset_statement_lines(statement: Statement, line_offset: int) -> Statement:
    line = statement.line + line_offset
    if isinstance(statement, Plugin):
        return Plugin(
            line=line,
            name=statement.name,
            body=statement.body,
            config=list(statement.config),
            config_diagnostics=[
                _offset_diagnostic_line(diagnostic, line_offset) for diagnostic in statement.config_diagnostics
            ],
            body_line=statement.body_line + line_offset if statement.body_line is not None else None,
        )
    if isinstance(statement, IfBlock):
        return IfBlock(
            line=line,
            condition=statement.condition,
            then_body=[_offset_statement_lines(child, line_offset) for child in statement.then_body],
            elifs=[
                ElifBlock(
                    line=elif_block.line + line_offset,
                    condition=elif_block.condition,
                    body=[_offset_statement_lines(child, line_offset) for child in elif_block.body],
                )
                for elif_block in statement.elifs
            ],
            else_body=(
                [_offset_statement_lines(child, line_offset) for child in statement.else_body]
                if statement.else_body is not None
                else None
            ),
        )
    if isinstance(statement, ForBlock):
        return ForBlock(
            line=line,
            variables=list(statement.variables),
            iterable=statement.iterable,
            is_map=statement.is_map,
            body=[_offset_statement_lines(child, line_offset) for child in statement.body],
            header=statement.header,
        )
    if isinstance(statement, Unknown):
        return Unknown(line=line, text=statement.text)
    return Statement(line=line)


class _FlowContext(Protocol):
    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _handle_on_error(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None: ...

    # ``_store_destination`` lives on ``AssignmentMixin`` (and is shadowed by
    # ``MutatePluginMixin`` / ``TransformPluginMixin`` overrides) — declare it
    # here so non-mutate plugin handlers can route their destination writes
    # through the canonical helper without ``getattr`` round-trips.
    def _store_destination(
        self,
        dest: str,
        lineages: list[Lineage],
        loc: str,
        state: AnalyzerState,
        *,
        append: bool = False,
    ) -> None: ...

    def _assign_object_literal_subfields(
        self, dest: str, pairs: list[ConfigPair], state: AnalyzerState, conditions: list[str], line: int, mode: str
    ) -> None: ...


class FlowExecutorMixin:
    _PLUGIN_HANDLERS = {name: spec.handler_name for name, spec in PLUGIN_SPECS.items()}

    def _exec_statements(
        self,
        stmts: list[Statement],
        state: AnalyzerState,
        conditions: list[str],
        depth: int = 0,
        loop_fanout: int = 1,
    ) -> None:
        if depth > MAX_NESTING_DEPTH:
            self._record_nesting_depth_warning(state, conditions, depth)
            return
        # Cache ``active_conditions`` across iterations. ``state.path_conditions``
        # is only mutated when an ``IfBlock``/``ForBlock``/``on_error`` handler
        # invokes ``merge_branch_records`` (which reassigns the list) or when a
        # ``drop`` predicate appends in-place. The snapshot below captures both
        # forms — identity changes on reassignment, length changes on append —
        # so the flat plugin-only case (extremely common in real parsers and in
        # the elif perf tests) recomputes only once for the whole loop.
        active_conditions: list[str] | None = None
        path_snapshot: tuple[int, int] | None = None
        for stmt in stmts:
            if state.dropped:
                break
            current_snapshot = (id(state.path_conditions), len(state.path_conditions))
            if active_conditions is None or current_snapshot != path_snapshot:
                active_conditions = _dedupe_strings(list(conditions) + state.path_conditions)
                path_snapshot = current_snapshot
            if isinstance(stmt, Plugin):
                self._exec_plugin(stmt, state, active_conditions, depth, loop_fanout)
            elif isinstance(stmt, IfBlock):
                self._exec_if(stmt, state, active_conditions, depth + 1, loop_fanout)
            elif isinstance(stmt, ForBlock):
                self._exec_for(stmt, state, active_conditions, depth + 1, loop_fanout)
            elif isinstance(stmt, IOBlock):
                self._exec_io_block(stmt, state, active_conditions, depth + 1, loop_fanout)
            elif isinstance(stmt, Unknown):
                warning = unparsed_statement(stmt.line, stmt.text)
                state.add_unsupported(
                    warning, code="parse_recovery", parser_location=_location(stmt.line, "parse recovery")
                )
                state.add_taint("parse_recovery", warning, _location(stmt.line, "parse recovery"))

    def _exec_io_block(
        self,
        stmt: IOBlock,
        state: AnalyzerState,
        conditions: list[str],
        depth: int = 0,
        loop_fanout: int = 1,
    ) -> None:
        """Walk an input/output block and record its inner plugins as anchors.

        We don't try to extract lineage from input/output plugins — they don't
        produce or consume UDM fields the way filter-stage plugins do. We
        just record their existence so downstream tooling can answer
        "where does this pipeline read from / write to" without re-parsing.
        Nested if/for blocks inside input/output ARE walked recursively so
        conditional routing (`output { if [x] { elasticsearch {} } else { null {} } }`)
        emits the right per-branch anchors with their conditions.
        """
        for child in stmt.body:
            if isinstance(child, Plugin) and child.name not in ("on_error",):
                loc = _location(child.line, f"{stmt.kind}.{child.name}")
                state.io_anchors.append(
                    IOAnchor(
                        kind=stmt.kind,
                        plugin=child.name,
                        conditions=tuple(conditions),
                        parser_locations=(loc,),
                        config_summary=_io_anchor_config_summary(child),
                    )
                )
            elif isinstance(child, IfBlock):
                # Walk the if body but skip the normal `_exec_if` machinery —
                # we just want to observe inner plugins under the if's
                # conditions. Construct a synthetic IOBlock for each branch.
                # Track prior-negations across elif/else siblings so each branch's
                # routing condition is `[*prior_NOTs, branch_cond]` — mirrors the
                # approach in `_exec_if` (see `_prior_negation_conditions`).
                cond = _clean_condition(child.condition)
                prior_negations: list[str] = []
                then_base_conditions = conditions + _prior_negation_conditions(prior_negations)
                then_conditions = _dedupe_strings(then_base_conditions + [cond])
                if self._branch_is_reachable(cond, then_base_conditions, child.line, state):
                    self._exec_io_block(
                        IOBlock(line=child.line, kind=stmt.kind, body=child.then_body),
                        state,
                        then_conditions,
                        depth,
                        loop_fanout,
                    )
                prior_negations.append(f"NOT({cond})")
                for elif_block in child.elifs:
                    ec = _clean_condition(elif_block.condition)
                    elif_negations = _prior_negation_conditions(prior_negations)
                    elif_base_conditions = conditions + elif_negations
                    elif_conditions = _dedupe_strings(elif_base_conditions + [ec])
                    if not self._tag_negation_conditions_are_unreachable(
                        elif_negations, state
                    ) and self._branch_is_reachable(ec, elif_base_conditions, elif_block.line, state):
                        self._exec_io_block(
                            IOBlock(line=elif_block.line, kind=stmt.kind, body=elif_block.body),
                            state,
                            elif_conditions,
                            depth,
                            loop_fanout,
                        )
                    prior_negations.append(f"NOT({ec})")
                if child.else_body is not None:
                    else_negations = _prior_negation_conditions(prior_negations)
                    else_conditions = _dedupe_strings(conditions + else_negations)
                    if self._else_branch_is_reachable(else_negations, else_conditions, state):
                        self._exec_io_block(
                            IOBlock(line=child.line, kind=stmt.kind, body=child.else_body),
                            state,
                            else_conditions,
                            depth,
                            loop_fanout,
                        )
            elif isinstance(child, ForBlock):
                # T3.1: real Logstash configs occasionally enumerate sinks via
                # a for-loop (e.g. ``output { for x in [...] { http { url => "%{x}" } } }``).
                # For static iterables, emit one IOAnchor per iteration with the
                # per-iteration condition; bound expansion by the static-loop cap
                # to protect against pathological fixtures. For dynamic iterables,
                # emit a single recursive walk under a synthetic loop condition.
                self._exec_io_for_block(child, stmt.kind, state, conditions, depth, loop_fanout)

    def _exec_io_for_block(
        self,
        stmt: ForBlock,
        kind: str,
        state: AnalyzerState,
        conditions: list[str],
        depth: int,
        loop_fanout: int,
    ) -> None:
        """T3.1: handle ``for`` loops nested inside an input/output block.

        Static string iterables are expanded one anchor per iteration. Dynamic
        iterables emit a single recursive walk with a synthetic loop condition.
        Anchor expansion is capped by ``MAX_STATIC_LOOP_ASSIGNMENTS`` so a
        pathological fixture can't blow up the anchor list.
        """
        loc = _location(stmt.line, f"{kind}.for", stmt.header)
        static_values = self._static_string_array(stmt.iterable)
        if static_values is not None:
            projected = max(1, len(stmt.body)) * len(static_values)
            if projected > MAX_STATIC_LOOP_ASSIGNMENTS:
                warning = static_limit_warning(
                    loc,
                    (
                        f"static loop fanout {len(static_values)} items × {max(1, len(stmt.body))} body statements"
                        f" = {projected}>{MAX_STATIC_LOOP_ASSIGNMENTS}"
                    ),
                )
                state.add_warning(
                    warning,
                    code="static_loop_fanout",
                    message=warning,
                    parser_location=loc,
                    source_token=stmt.iterable,
                )
                # Fall back to a single synthetic anchor under a loop-condition
                # rather than dropping the I/O block entirely.
                self._exec_io_block(
                    IOBlock(line=stmt.line, kind=kind, body=stmt.body),
                    state,
                    _dedupe_strings(conditions + [f"for {stmt.header}"]),
                    depth,
                    loop_fanout,
                )
                return
            for value in static_values:
                iter_cond = f"for {stmt.variables[0] if stmt.variables else 'item'} = {value!r}"
                self._exec_io_block(
                    IOBlock(line=stmt.line, kind=kind, body=stmt.body),
                    state,
                    _dedupe_strings(conditions + [iter_cond]),
                    depth,
                    loop_fanout,
                )
            return
        # Dynamic iterable: one synthetic walk under the loop condition.
        self._exec_io_block(
            IOBlock(line=stmt.line, kind=kind, body=stmt.body),
            state,
            _dedupe_strings(conditions + [f"for {stmt.header}"]),
            depth,
            loop_fanout,
        )

    def _record_nesting_depth_warning(self, state: AnalyzerState, conditions: list[str], depth: int) -> None:
        loc = _location(0, "analysis nesting")
        warning = (
            f"{loc}: analysis nesting depth {depth} exceeds limit of {MAX_NESTING_DEPTH}; nested statements skipped"
        )
        state.add_warning(warning, code="analysis_nesting_depth", message=warning, parser_location=loc)
        state.add_taint("analysis_nesting_depth", warning, loc)

    def _exec_if(
        self, stmt: IfBlock, state: AnalyzerState, conditions: list[str], depth: int = 0, loop_fanout: int = 1
    ) -> None:
        cond = _clean_condition(stmt.condition)
        self._warn_condition_limits(cond, stmt.line, state)
        elif_count = len(stmt.elifs)

        original = state.clone()
        original.path_conditions = []
        branch_records: list[BranchRecord] = []

        prior_negations: list[str] = []
        then_base_conditions = conditions + _prior_negation_conditions(prior_negations)
        then_conditions = _dedupe_strings(then_base_conditions + [cond])
        if self._branch_is_reachable(cond, then_base_conditions, stmt.line, state):
            then_state = original.clone()
            self._exec_statements(stmt.then_body, then_state, then_conditions, depth, loop_fanout)
            branch_records.append(BranchRecord(then_state, then_conditions, False))
        else:
            self._sync_branch_seed_diagnostics(original, state)
        prior_negations.append(f"NOT({cond})")

        for elif_block in stmt.elifs:
            elif_cond, body, _line = elif_block.condition, elif_block.body, elif_block.line
            ec = _clean_condition(elif_cond)
            self._warn_condition_limits(ec, _line, state)
            self._sync_branch_seed_diagnostics(original, state)
            elif_negations = _prior_negation_conditions(prior_negations)
            elif_base_conditions = conditions + elif_negations
            elif_conditions = _dedupe_strings(elif_base_conditions + [ec])
            if not self._tag_negation_conditions_are_unreachable(elif_negations, state) and self._branch_is_reachable(
                ec, elif_base_conditions, _line, state
            ):
                elif_state = original.clone()
                self._exec_statements(body, elif_state, elif_conditions, depth, loop_fanout)
                branch_records.append(BranchRecord(elif_state, elif_conditions, False))
            else:
                self._sync_branch_seed_diagnostics(original, state)
            prior_negations.append(f"NOT({ec})")

        if stmt.else_body is not None:
            else_state = original.clone()
            else_negations = _prior_negation_conditions(prior_negations)
            else_conditions = _dedupe_strings(conditions + else_negations)
            if self._else_branch_is_reachable(else_negations, else_conditions, state):
                self._exec_statements(stmt.else_body, else_state, else_conditions, depth, loop_fanout)
                branch_records.append(BranchRecord(else_state, else_conditions, False))
        else:
            # No-op path: fields can retain their original lineage.
            #
            # Perf note: this clone is a per-``if``-without-``else`` allocation
            # that microbenchmarks attributed ~7% of analyze time to on
            # parsers dominated by single-arm ``if`` constructs. A COW
            # alternative (defer the clone to ``_condition_no_op_record``'s
            # first write) was investigated and rejected here: the no-op
            # state is also read by ``_apply_dropped_path_conditions``
            # (which writes ``path_conditions`` when a sibling drops) and
            # by ``merge_branch_records`` itself (which reads
            # ``implicit_path_conditions``, ``tag_state``, and
            # ``path_conditions`` from each survivor). Sharing
            # ``original`` directly would alias those fields between the
            # comparison baseline and the no-op survivor, producing
            # writes to ``original.path_conditions`` and corrupting later
            # branch comparisons. The minimal-clone path that would work
            # requires an "AnalyzerState lite" mode whose blast radius
            # across the existing COW machinery is larger than the perf
            # win justifies for v0.1. Revisit when we have a concrete,
            # measured workload that puts this clone on the critical
            # path beyond the current 7%.
            no_op_state = original.clone()
            no_op_conditions = _dedupe_strings(conditions + _prior_negation_conditions(prior_negations))
            branch_records.append(BranchRecord(no_op_state, no_op_conditions, True))

        state.merge_branch_records(original, branch_records)
        # Emit the long-elif soft warning *after* merging, not before cloning.
        # If we add it pre-clone, the warning lives in the seed lists that every
        # elif iteration's ``then_state`` aliases, forcing
        # ``_ensure_diagnostics_owned`` to call ``_rebuild_diagnostic_indexes``
        # once per elif and breaking the linear-time guarantee that
        # ``_sync_branch_seed_diagnostics`` is designed to preserve.
        if elif_count > MAX_ELIF_CHAIN_BEFORE_WARNING:
            warning = long_elif_chain_warning(stmt.line, elif_count, MAX_ELIF_CHAIN_BEFORE_WARNING)
            state.add_warning(
                warning,
                code="long_elif_chain",
                message=warning,
                parser_location=_location(stmt.line, "if"),
            )

    def _sync_branch_seed_diagnostics(self, seed: AnalyzerState, state: AnalyzerState) -> None:
        # Incremental sync: ``state`` only ever appends to its diagnostic lists
        # (via ``_add_diagnostic_record``), and ``seed`` is owned by the local
        # ``_exec_if`` frame so no other writer extends it. ``len(seed.X)`` is
        # therefore the watermark of how much of ``state.X`` has already been
        # mirrored. When all five lengths already match, this call is a complete
        # no-op — which is the dominant case in long elif chains where
        # ``_warn_condition_limits`` and ``_branch_is_reachable`` add nothing,
        # turning the previous quadratic rebuild loop into linear total work.
        s_u = len(state.unsupported)
        s_w = len(state.warnings)
        s_sw = len(state.structured_warnings)
        s_t = len(state.taints)
        s_d = len(state.diagnostics)

        e_u = len(seed.unsupported)
        e_w = len(seed.warnings)
        e_sw = len(seed.structured_warnings)
        e_t = len(seed.taints)
        e_d = len(seed.diagnostics)

        if e_u == s_u and e_w == s_w and e_sw == s_sw and e_t == s_t and e_d == s_d:
            return

        # Defensive fallback: if any list has shrunk (it should not during
        # analysis, since the diagnostic lists are append-only, but stay safe if
        # an unanticipated caller resets them) rebuild from scratch so the seed
        # and its seen-set indexes match ``state`` exactly. Likewise, if the
        # seen-sets have not yet been populated (this is the first sync against
        # a freshly cloned seed), do the rebuild once to establish the
        # invariant; subsequent calls then take the incremental path below.
        seen_initialized = (
            (not seed.unsupported or seed._unsupported_seen)
            and (not seed.warnings or seed._warning_seen)
            and (not seed.structured_warnings or seed._structured_warning_seen)
            and (not seed.taints or seed._taint_seen)
            and (not seed.diagnostics or seed._diagnostic_seen)
        )
        if e_u > s_u or e_w > s_w or e_sw > s_sw or e_t > s_t or e_d > s_d or not seen_initialized:
            seed.unsupported = list(state.unsupported)
            seed.warnings = list(state.warnings)
            seed.structured_warnings = list(state.structured_warnings)
            seed.diagnostics = list(state.diagnostics)
            seed.taints = list(state.taints)
            seed._rebuild_diagnostic_indexes()
            # The fresh lists above are seed-owned, and ``_rebuild_diagnostic_indexes``
            # has just rebuilt seed-owned seen-sets. Copy the suppressed-count and
            # unresolved-extractor-source dicts (which ``clone()`` aliases to the
            # parent) and flip ``_diagnostics_owned`` so a subsequent
            # ``_ensure_diagnostics_owned()`` does not rebind the lists and drop
            # the seen-sets' covariance. After this function returns, seed owns
            # independent diagnostic state.
            seed._suppressed_warning_counts = dict(seed._suppressed_warning_counts)
            seed._suppressed_taint_counts = dict(seed._suppressed_taint_counts)
            seed._unresolved_extractor_source_counts = dict(seed._unresolved_extractor_source_counts)
            seed._unresolved_extractor_source_summary_taints = dict(seed._unresolved_extractor_source_summary_taints)
            seed._diagnostics_owned = True
            return

        # Append-only growth: extend each seed list with just the new tail and
        # add the new entries' keys to the matching seen-set. Sibling branches
        # cloned from this seed may still alias these list objects, but
        # ``merge_branch_records`` deduplicates against the parent's seen-sets
        # (which already contain every item we just appended, since ``state``
        # is the parent), so any overlap is discarded during merge. The rebuild
        # branch above always runs first (the ``not seen_initialized`` guard
        # forces it on the seed's first sync), so by the time we reach here the
        # seed's lists are independent of the parent — extending them is safe.
        if e_u != s_u:
            new_unsupported = state.unsupported[e_u:]
            seed.unsupported.extend(new_unsupported)
            seed._unsupported_seen.update(new_unsupported)
        if e_w != s_w:
            new_warnings = state.warnings[e_w:]
            seed.warnings.extend(new_warnings)
            seed._warning_seen.update(new_warnings)
        if e_sw != s_sw:
            new_structured = state.structured_warnings[e_sw:]
            seed.structured_warnings.extend(new_structured)
            seed._structured_warning_seen.update(_warning_key(reason) for reason in new_structured)
        if e_t != s_t:
            new_taints = state.taints[e_t:]
            seed.taints.extend(new_taints)
            seed._taint_seen.update(_taint_key(taint) for taint in new_taints)
        if e_d != s_d:
            new_diagnostics = state.diagnostics[e_d:]
            seed.diagnostics.extend(new_diagnostics)
            seed._diagnostic_seen.update(_diagnostic_key(diagnostic) for diagnostic in new_diagnostics)

    def _warn_condition_limits(self, cond: str, line: int, state: AnalyzerState) -> None:
        if "%{" not in cond and ("=~" not in cond or is_exact_literal_regex_condition(cond)):
            self._warn_regex_over_escapes(cond, line, state)
            self._warn_string_in_check_semantics(cond, line, state)
            return
        loc = _location(line, "if")
        warning = runtime_condition_warning(loc, cond)
        state.add_warning(
            warning, code="runtime_condition", message=f"Condition {cond!r} is symbolic", parser_location=loc
        )
        state.add_taint("runtime_condition", f"Condition {cond!r} is symbolic", loc)
        self._warn_regex_over_escapes(cond, line, state)
        self._warn_string_in_check_semantics(cond, line, state)

    def _warn_string_in_check_semantics(self, cond: str, line: int, state: AnalyzerState) -> None:
        """R1.3: `"<lit>" in [field]` has different runtime semantics
        depending on whether `[field]` is a string (substring match) or
        array (membership). Tags get specialized handling elsewhere; flag
        non-tags fields whose lineage union is `"string"` so the user knows
        the check is substring matching, not array membership.
        """
        match = _GENERIC_IN_CHECK_RE.match(cond.strip())
        if not match:
            return
        field = match.group("field")
        if field == "tags":
            return  # tag-set membership is checked separately
        lineages = state.tokens.get(field, [])
        if not lineages:
            return  # no lineage means we can't conclude anything
        if Lineage.union_value_types(lineages) != "string":
            return
        loc = _location(line, "if")
        warning = (
            f"{loc}: condition {cond!r} treats [{field}] as a string (substring match), "
            f"not an array (membership). If you expected array membership, ensure [{field}] "
            "was populated by an array-producing op (split, merge, add_tag) or use a different check."
        )
        state.add_warning(
            warning,
            code="string_in_check",
            message=warning,
            parser_location=loc,
            source_token=field,
        )

    def _warn_regex_over_escapes(self, cond: str, line: int, state: AnalyzerState) -> None:
        for pattern, escape in _iter_regex_over_escapes(cond):
            loc = _location(line, "if")
            warning = regex_over_escape_warning(loc, pattern, escape)
            state.add_warning(
                warning,
                code="regex_over_escape",
                message=warning,
                parser_location=loc,
                source_token=pattern,
            )

    def _warn_config_advisories(self, stmt: Plugin, state: AnalyzerState) -> None:
        spec = plugin_spec_for(stmt.name)
        for key, value, _depth in _iter_config_values(stmt.config):
            if (
                _depth == 0
                and spec is not None
                and spec.config_model is None
                and (spec.ignored_config_keys or spec.source_keys or spec.dest_keys)
            ):
                known_keys = {*spec.source_keys, *spec.dest_keys}
                if key not in known_keys and not spec.ignores_config_key(key):
                    warning = unknown_config_key_warning(stmt.line, stmt.name, key)
                    state.add_warning(
                        warning,
                        code="unknown_config_key",
                        message=warning,
                        parser_location=_location(stmt.line, stmt.name),
                        source_token=key,
                    )
            if isinstance(value, list) and not as_pairs(value):
                count = len(value)
                if count > MAX_ARRAY_LITERAL_BEFORE_WARNING:
                    warning = large_array_literal_warning(stmt.line, count, MAX_ARRAY_LITERAL_BEFORE_WARNING)
                    state.add_warning(
                        warning,
                        code="large_array_literal",
                        message=warning,
                        parser_location=_location(stmt.line, stmt.name),
                        source_token=key,
                    )
            if key == "on_error" and isinstance(value, list) and as_pairs(value):
                # `on_error => "tag"` is canonical (string value, used for failure-tagging);
                # `on_error { plugin { ... } }` placed inside a plugin config map is not —
                # the canonical fallback form is the statement-level `} on_error { ... }`.
                self._record_non_canonical_on_error(stmt, state, key)
        # The Lark grammar rejects bare `on_error {` (no `=>`) so the misplaced
        # block usually shows up as a config parse failure rather than a parsed
        # pair. Scan the raw body so the user gets a specific, actionable message
        # in addition to (or instead of) the generic malformed_config warning.
        if stmt.body and _ON_ERROR_BLOCK_IN_CONFIG_RE.search(stmt.body):
            self._record_non_canonical_on_error(stmt, state, "on_error")

    def _record_non_canonical_on_error(self, stmt: Plugin, state: AnalyzerState, key: str) -> None:
        warning = non_canonical_on_error_placement_warning(stmt.line, stmt.name)
        state.add_warning(
            warning,
            code="non_canonical_on_error_placement",
            message=warning,
            parser_location=_location(stmt.line, stmt.name),
            source_token=key,
        )

    def _else_branch_is_reachable(
        self, else_negations: list[str], else_conditions: list[str], state: AnalyzerState
    ) -> bool:
        """Reachability gate for the else body of an if/elif chain.

        Combines the implicit-path-conditions compatibility check (PR-C) with
        the tag-negation pruning so ``_exec_if`` and ``_exec_io_block`` agree
        on when an else body is feasible.
        """
        if not conditions_are_compatible(else_conditions, tuple(state.implicit_path_conditions)):
            return False
        return not self._tag_negation_conditions_are_unreachable(else_negations, state)

    def _branch_is_reachable(self, cond: str, prior_conditions: list[str], line: int, state: AnalyzerState) -> bool:
        # PR-C: pass ``implicit_path_conditions`` so synthetic grok-derived
        # constraints (e.g. ``[src_ip] =~ /<IP_BODY>/`` from a prior
        # ``%{IP:src_ip}`` capture) participate in the contradiction check.
        # Empty tuple when no implicit constraints have been recorded —
        # pre-PR-C behavior preserved exactly.
        if condition_is_contradicted(cond, prior_conditions, tuple(state.implicit_path_conditions)):
            self._emit_unreachable_branch(cond, line, state)
            return False
        # Phase 3B: tag-set membership reasoning. If a condition checks for a
        # literal tag that no prior `mutate { add_tag => [...] }` could have
        # added, the branch is unreachable at runtime even though it doesn't
        # contradict any literal field-fact.
        if self._tag_membership_check_status(cond, state) == "definitely_false":
            self._emit_unreachable_branch(cond, line, state)
            return False
        # Phase R2: when the tag IS reachable but only via a conditionally-
        # guarded add_tag call (or potentially removed), emit a softer
        # advisory so the user knows membership isn't guaranteed.
        self._warn_conditional_tag_membership(cond, line, state)
        return True

    def _emit_unreachable_branch(self, cond: str, line: int, state: AnalyzerState) -> None:
        loc = _location(line, "if")
        warning = unreachable_branch_warning(loc, cond)
        state.add_warning(
            warning,
            code="unreachable_branch",
            message=f"Condition {cond!r} contradicts prior literal branch facts",
            parser_location=loc,
        )
        state.add_taint("unreachable_branch", f"Condition {cond!r} contradicts prior literal branch facts", loc)

    def _warn_conditional_tag_membership(self, cond: str, line: int, state: AnalyzerState) -> None:
        """R2/T2: emit `conditional_tag_check` when ``"<lit>" in [tags]``
        matches a tag that's in ``possibly`` but not ``definitely`` — i.e.
        only added on some paths, or potentially removed.

        Consults ``state.tag_state`` first (the structured representation).
        Falls back to the lineage-walking heuristic when ``tag_state`` is
        empty (e.g. when add_tag happened inside an unreachable branch and
        was scrubbed from the merge — the lineage may still survive).
        """
        match = _TAGS_MEMBERSHIP_RE.match(cond.strip())
        if not match:
            return
        literal = _membership_literal(match)
        tag_state = state.tag_state
        if tag_state.definitely or tag_state.possibly or tag_state.has_dynamic:
            if literal in tag_state.definitely:
                return  # always present
            if literal not in tag_state.possibly and not tag_state.has_dynamic:
                return  # caller already handled the unreachable case
            # In `possibly` but not `definitely` (or only widened by dynamic).
            loc = _location(line, "if")
            if tag_state.has_dynamic and literal not in tag_state.possibly:
                reason = "a prior add_tag/remove_tag carried a templated value"
            elif literal not in tag_state.definitely:
                reason = "the tag was added on some paths but not all"
            else:
                reason = "tag membership is conditional"
            warning = f"{loc}: condition {cond!r} matches but {reason}; tag membership is conditional, not guaranteed"
            state.add_warning(
                warning,
                code="conditional_tag_check",
                message=warning,
                parser_location=loc,
                source_token=literal,
            )
            return
        # Fallback: walk lineages (legacy path for when tag_state is empty).
        tag_lineages = state.tokens.get("tags", [])
        if not tag_lineages:
            return
        matching: list = []
        has_remove_anywhere = False
        for lineage in tag_lineages:
            if "remove_tag" in lineage.transformations:
                has_remove_anywhere = True
            for source in lineage.sources:
                if source.kind == "constant" and (source.expression or "") == literal:
                    matching.append(lineage)
                    break
        if not matching:
            return
        if any(not lineage.conditions for lineage in matching) and not has_remove_anywhere:
            return
        loc = _location(line, "if")
        if has_remove_anywhere:
            reason = "a prior remove_tag may have removed this tag"
        else:
            reason = "every prior add_tag for this literal was conditionally guarded"
        warning = f"{loc}: condition {cond!r} matches but {reason}; tag membership is conditional, not guaranteed"
        state.add_warning(
            warning,
            code="conditional_tag_check",
            message=warning,
            parser_location=loc,
            source_token=literal,
        )

    def _tag_negation_conditions_are_unreachable(self, conditions: list[str], state: AnalyzerState) -> bool:
        """Return True when an else condition negates a definitely-true tag check."""
        for condition in conditions:
            if not condition.startswith("NOT(") or not condition.endswith(")"):
                continue
            inner = condition[4:-1]
            if self._tag_membership_check_status(inner, state) == "definitely_true":
                return True
        return False

    def _tag_membership_check_status(self, cond: str, state: AnalyzerState) -> TagMembershipStatus:
        """Tri-state classifier for ``"<lit>" in [tags]`` conditions.

        Returns ``"definitely_true"`` when prior add_tag definitely added the
        literal and no remove_tag could have removed it; ``"definitely_false"``
        when no path could have added the literal; ``"unknown"`` otherwise
        (conditional adds, dynamic templates, or no tag info available).
        """
        match = _TAGS_MEMBERSHIP_RE.match(cond.strip())
        if not match:
            return "unknown"
        literal = _membership_literal(match)
        tag_state = state.tag_state
        if tag_state.definitely or tag_state.possibly or tag_state.has_dynamic:
            # ``definitely`` records literal adds that survived branch-merge
            # intersection. A purely templated remove_tag sets has_dynamic
            # but cannot subtract from ``definitely`` (only literal removes
            # do — see TagState.with_removed), so membership in ``definitely``
            # outranks has_dynamic.
            if literal in tag_state.definitely:
                return "definitely_true"
            if tag_state.has_dynamic:
                return "unknown"
            if literal not in tag_state.possibly:
                return "definitely_false"
            return "unknown"
        # Fallback to lineage walking when structured tag_state is empty.
        tag_lineages = state.tokens.get("tags", [])
        if not tag_lineages:
            return "unknown"
        has_remove_anywhere = False
        has_unconditional_constant_match = False
        has_any_match = False
        for lineage in tag_lineages:
            if "remove_tag" in lineage.transformations:
                has_remove_anywhere = True
            for source in lineage.sources:
                if source.kind == "template":
                    has_any_match = True
                elif source.kind == "constant" and (source.expression or "") == literal:
                    has_any_match = True
                    if not lineage.conditions:
                        has_unconditional_constant_match = True
        if has_unconditional_constant_match and not has_remove_anywhere:
            return "definitely_true"
        if not has_any_match:
            return "definitely_false"
        return "unknown"

    def _exec_for(
        self, stmt: ForBlock, state: AnalyzerState, conditions: list[str], depth: int = 0, loop_fanout: int = 1
    ) -> None:
        context = cast(_FlowContext, self)
        loc = _location(stmt.line, "for", stmt.header)
        # Emit the ``loop_variables`` advisory before any fast-path dispatch so
        # the diagnostic fires regardless of whether the iterable is a static
        # literal array (handled by ``_exec_static_string_loop``) or a
        # runtime-resolved expression.
        if not stmt.is_map and len(stmt.variables) >= 3:
            warning = loop_variables_warning(loc, len(stmt.variables))
            state.add_warning(
                warning,
                code="loop_variables",
                message=f"Loop declares {len(stmt.variables)} variables",
                parser_location=loc,
            )
        static_values = self._static_string_array(stmt.iterable)
        if static_values is not None and not stmt.is_map and len(stmt.variables) >= 1:
            # C4: multi-variable iteration over a literal array (e.g.
            # ``for index, item in [...]``) used to fall through to
            # ``_resolve_token`` and produce ``unresolved`` mappings for
            # destinations templated on ``index`` or ``item``. The static
            # fast path now handles both the single-variable and
            # ``index, item, ...`` shapes.
            self._exec_static_string_loop(stmt, static_values, state, conditions, loc, depth, loop_fanout)
            return
        iter_lineage = context._resolve_token(stmt.iterable, state, loc)
        if "%{" in stmt.iterable:
            warning = static_limit_warning(loc, "dynamic loop iterable")
            state.add_warning(
                warning,
                code="dynamic_loop_iterable",
                message=f"Loop iterable {stmt.iterable!r} is runtime-dependent",
                parser_location=loc,
                source_token=stmt.iterable,
            )
            taint = state.add_taint(
                "dynamic_loop_iterable", f"Loop iterable {stmt.iterable!r} is runtime-dependent", loc, stmt.iterable
            )
            iter_lineage = [
                (lin if lin.status == "unresolved" else lin.with_status("dynamic")).with_taints([taint])
                for lin in iter_lineage
            ]
        loop_cond = f"for {stmt.header}"
        # ``loop_variables`` advisory now fires earlier in ``_exec_for`` so it
        # also covers static-literal-array iteration handled by the fast path.

        next_loop_fanout, fanout_taint = self._next_loop_fanout(
            loop_fanout, len(iter_lineage), loc, stmt.iterable, state
        )
        if next_loop_fanout is None:
            self._exec_summarized_dynamic_loop(stmt, state, conditions, loc, depth, loop_fanout, fanout_taint)
            return

        # Merge original with each possible loop execution. The loop may not run,
        # and each iterable lineage alternative carries its own branch predicates.
        original = state.clone()
        branch_records: list[BranchRecord] = [BranchRecord(original.clone(), [], True)]
        for iter_lin in iter_lineage:
            iter_sources = _dedupe_sources(iter_lin.sources)
            loop_conditions = _dedupe_strings(conditions + list(iter_lin.conditions) + [loop_cond])
            loop_item_path = _path_from_iterable(stmt.iterable, iter_sources, array=True)
            map_entry_path = _path_from_iterable(stmt.iterable, iter_sources, map_entry=True)
            loop_item_status: LineageStatus = (
                "unresolved"
                if iter_lin.status == "unresolved"
                else ("dynamic" if iter_lin.status == "dynamic" else "exact")
            )
            loop_index_status: LineageStatus = (
                "unresolved"
                if iter_lin.status == "unresolved"
                else ("dynamic" if iter_lin.status == "dynamic" else "derived")
            )

            loop_state = original.clone()
            if stmt.is_map and len(stmt.variables) >= 2:
                key, value = stmt.variables[0], stmt.variables[1]
                loop_state.tokens[key] = [
                    Lineage(
                        status=loop_item_status,
                        sources=[
                            SourceRef(
                                kind="map_key",
                                source_token=stmt.iterable,
                                path=map_entry_path,
                                details=iterable_sources_details(iter_sources),
                            )
                        ],
                        expression=key,
                        conditions=loop_conditions,
                        parser_locations=[loc],
                    )
                ]
                loop_state.tokens[value] = [
                    Lineage(
                        status=loop_item_status,
                        sources=[
                            SourceRef(
                                kind="map_value",
                                source_token=stmt.iterable,
                                path=map_entry_path,
                                details=iterable_sources_details(iter_sources),
                            )
                        ],
                        expression=value,
                        conditions=loop_conditions,
                        parser_locations=[loc],
                    )
                ]
            else:
                if len(stmt.variables) == 1:
                    item = stmt.variables[0]
                    if item != "_":
                        loop_state.tokens[item] = [
                            Lineage(
                                status=loop_item_status,
                                sources=[
                                    SourceRef(
                                        kind="loop_item",
                                        source_token=stmt.iterable,
                                        path=loop_item_path,
                                        details=iterable_sources_details(iter_sources),
                                    )
                                ],
                                expression=item,
                                conditions=loop_conditions,
                                parser_locations=[loc],
                            )
                        ]
                elif len(stmt.variables) >= 2:
                    index = stmt.variables[0]
                    item_vars = stmt.variables[1:]
                    if index != "_":
                        loop_state.tokens[index] = [
                            Lineage(
                                status=loop_index_status,
                                sources=[
                                    SourceRef(kind="loop_index", source_token=stmt.iterable, path=f"{stmt.iterable}[*]")
                                ],
                                expression=index,
                                conditions=loop_conditions,
                                parser_locations=[loc],
                            )
                        ]
                    for position, item in enumerate(item_vars, start=1):
                        if item != "_":
                            loop_state.tokens[item] = [
                                Lineage(
                                    status=loop_item_status,
                                    sources=[
                                        SourceRef(
                                            kind="loop_item",
                                            source_token=stmt.iterable,
                                            path=loop_item_path,
                                            details=loop_tuple_details(iter_sources, position),
                                        )
                                    ],
                                    expression=item,
                                    conditions=loop_conditions,
                                    parser_locations=[loc],
                                )
                            ]

            self._exec_statements(stmt.body, loop_state, loop_conditions, depth, next_loop_fanout)
            # Loop header variables are lexical helper variables for the loop body.
            # Do not leak them into the state that follows the loop, or a later
            # reference to the same token name could incorrectly resolve to a stale
            # array/map item. Tokens assigned inside the loop body are intentionally
            # retained as possible lineage.
            for var in stmt.variables:
                if var and var != "_":
                    loop_state.tokens.pop(var, None)
                    for token_name in loop_state.descendant_tokens(var):
                        loop_state.tokens.pop(token_name, None)
            if not loop_state.dropped:
                branch_records.append(BranchRecord(loop_state, loop_conditions, False))
        state.merge_branch_records(original, branch_records)

    def _next_loop_fanout(
        self, current: int, alternatives: int, loc: str, iterable: str, state: AnalyzerState
    ) -> tuple[int | None, TaintReason | None]:
        projected = current * max(1, alternatives)
        if projected <= MAX_CUMULATIVE_LOOP_FANOUT:
            return projected, None
        return None, self._add_loop_fanout_diagnostic(projected, current, alternatives, loc, iterable, state)

    def _add_loop_fanout_diagnostic(
        self,
        projected: int,
        current: int,
        alternatives: int,
        loc: str,
        iterable: str,
        state: AnalyzerState,
    ) -> TaintReason:
        warning = static_limit_warning(
            loc,
            f"cumulative loop fanout {current}×{alternatives}={projected}>{MAX_CUMULATIVE_LOOP_FANOUT}",
        )
        state.add_warning(
            warning,
            code="loop_fanout",
            message=warning,
            parser_location=loc,
            source_token=iterable,
        )
        return state.add_taint(
            "loop_fanout",
            (
                f"Cumulative loop fanout {projected} exceeded {MAX_CUMULATIVE_LOOP_FANOUT} "
                f"(running fanout {current} × {alternatives} items at this loop level)"
            ),
            loc,
            iterable,
        )

    def _exec_summarized_dynamic_loop(
        self,
        stmt: ForBlock,
        state: AnalyzerState,
        conditions: list[str],
        loc: str,
        depth: int,
        loop_fanout: int,
        fanout_taint: TaintReason | None,
    ) -> None:
        original = state.clone()
        loop_state = original.clone()
        loop_conditions = _dedupe_strings(conditions + [f"for {stmt.header}"])
        self._seed_summarized_loop_variables(stmt, loop_state, loop_conditions, loc, fanout_taint)
        self._exec_statements(stmt.body, loop_state, loop_conditions, depth, loop_fanout)
        self._clear_loop_variables(stmt, loop_state)
        if loop_state.dropped:
            state.merge_branch_records(original, [BranchRecord(original.clone(), [], True)])
            return
        state.merge_branch_records(
            original,
            [
                BranchRecord(original.clone(), [], True),
                BranchRecord(loop_state, loop_conditions, False),
            ],
        )

    def _seed_summarized_loop_variables(
        self,
        stmt: ForBlock,
        state: AnalyzerState,
        conditions: list[str],
        loc: str,
        fanout_taint: TaintReason | None,
    ) -> None:
        taints = [fanout_taint] if fanout_taint is not None else []

        def lineage(name: str, kind: str, path: str | None = None) -> Lineage:
            return Lineage(
                status="dynamic",
                sources=[SourceRef(kind=kind, source_token=stmt.iterable, path=path)],
                expression=name,
                conditions=conditions,
                parser_locations=[loc],
                taints=taints,
            )

        if stmt.is_map and len(stmt.variables) >= 2:
            key, value = stmt.variables[0], stmt.variables[1]
            if key != "_":
                state.tokens[key] = [lineage(key, "map_key", f"{stmt.iterable}[*]")]
            if value != "_":
                state.tokens[value] = [lineage(value, "map_value", f"{stmt.iterable}[*]")]
            return

        if len(stmt.variables) == 1:
            item = stmt.variables[0]
            if item != "_":
                state.tokens[item] = [lineage(item, "loop_item", f"{stmt.iterable}[*]")]
            return

        if len(stmt.variables) >= 2:
            index = stmt.variables[0]
            if index != "_":
                state.tokens[index] = [lineage(index, "loop_index", f"{stmt.iterable}[*]")]
            for item in stmt.variables[1:]:
                if item != "_":
                    state.tokens[item] = [lineage(item, "loop_item", f"{stmt.iterable}[*]")]

    def _clear_loop_variables(self, stmt: ForBlock, state: AnalyzerState) -> None:
        for var in stmt.variables:
            if var and var != "_":
                state.tokens.pop(var, None)
                for token_name in state.descendant_tokens(var):
                    state.tokens.pop(token_name, None)

    def _static_string_array(self, iterable: str) -> list[str] | None:
        text = iterable.strip()
        if not (text.startswith("[") and text.endswith("]")):
            return None
        values: list[str] = []
        quote: str | None = None
        escape = False
        current: list[str] = []
        expecting_value = True
        i = 1
        while i < len(text) - 1:
            ch = text[i]
            if quote:
                if escape:
                    current.append("\\" + ch)
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    values.append("".join(current))
                    current = []
                    quote = None
                    expecting_value = False
                else:
                    current.append(ch)
                i += 1
                continue
            if ch.isspace():
                i += 1
                continue
            if ch == ",":
                expecting_value = True
                i += 1
                continue
            if ch in {'"', "'"} and expecting_value:
                quote = ch
                i += 1
                continue
            return None
        return values if quote is None else None

    def _exec_static_string_loop(
        self,
        stmt: ForBlock,
        values: list[str],
        state: AnalyzerState,
        conditions: list[str],
        loc: str,
        depth: int = 0,
        loop_fanout: int = 1,
    ) -> None:
        if not values:
            return
        projected_assignments = len(values) * max(1, len(stmt.body))
        if projected_assignments > MAX_STATIC_LOOP_ASSIGNMENTS:
            warning = static_limit_warning(
                loc,
                (
                    f"static loop fanout {len(values)} items × {max(1, len(stmt.body))} body statements"
                    f" = {projected_assignments}>{MAX_STATIC_LOOP_ASSIGNMENTS}"
                ),
            )
            state.add_warning(
                warning,
                code="static_loop_fanout",
                message=warning,
                parser_location=loc,
                source_token=stmt.iterable,
            )
            state.add_taint(
                "static_loop_fanout",
                (
                    f"Static loop fanout {projected_assignments} exceeded {MAX_STATIC_LOOP_ASSIGNMENTS} "
                    f"({len(values)} iterable items × {max(1, len(stmt.body))} body statements)"
                ),
                loc,
                stmt.iterable,
            )
            return
        next_loop_fanout = loop_fanout * max(1, len(values))
        if loop_fanout > 1:
            capped_fanout, fanout_taint = self._next_loop_fanout(loop_fanout, len(values), loc, stmt.iterable, state)
            if capped_fanout is None:
                self._seed_summarized_loop_variables(stmt, state, conditions, loc, fanout_taint)
                self._exec_statements(stmt.body, state, conditions, depth, loop_fanout)
                self._clear_loop_variables(stmt, state)
                return
            next_loop_fanout = capped_fanout
        # C4: when ``stmt.variables`` has length 1, the variable binds to the
        # array element directly. With 2+ variables (``for index, item in
        # [...]``), Logstash binds the first to a 0-based index and the rest
        # to the same element value (mirroring the runtime behaviour also
        # implemented in the dynamic fast path further down ``_exec_for``).
        is_indexed = len(stmt.variables) >= 2
        bound_vars = [v for v in stmt.variables if v]

        # The per-iteration cleanup at the bottom of the loop unconditionally
        # pops the loop-variable tokens (and their descendants) from
        # ``state.tokens``. Without protection, that erases any pre-existing
        # token whose name happens to collide with a loop variable — and
        # ``index``/``item`` are common-enough field names in real parsers
        # that the multi-variable shape (``for index, item in [...]``) makes
        # this a real regression after the C4 dispatch widening. The dynamic
        # path sidesteps this by cloning state per iteration; the fast path
        # mutates in place, so snapshot the prior values once before the
        # loop and restore them after. Iteration-scoped tokens that the body
        # creates (e.g. ``index.subfield``) stay correctly cleaned up
        # because the restore only writes names that existed beforehand.
        #
        # Critical: the saved values must be SHALLOW COPIES of the lineage
        # lists, not the lists themselves. ``state.tokens[var]`` on a forked
        # ``TokenStore`` falls through ``__getitem__`` to ``self._base[key]``,
        # returning the PARENT'S list reference verbatim. If we restored that
        # reference into the fork's ``_data``, any later
        # ``append_token_lineages`` on this fork would hit the
        # ``mutate_local`` fast path and append to the parent's list in
        # place, leaking branch-local writes across branches. ``list(...)``
        # gives the fork its own owned list to mutate.
        saved_outer: dict[str, list[Lineage]] = {}
        for var in bound_vars:
            if var == "_":
                continue
            if var in state.tokens:
                saved_outer[var] = list(state.tokens[var])
            for token_name in state.descendant_tokens(var):
                saved_outer[token_name] = list(state.tokens[token_name])

        for index, value in enumerate(values):
            if is_indexed:
                index_var = stmt.variables[0]
                if index_var and index_var != "_":
                    state.tokens[index_var] = [
                        Lineage(
                            status="constant",
                            sources=[SourceRef(kind="constant", expression=str(index))],
                            expression=str(index),
                            conditions=list(conditions),
                            parser_locations=[loc],
                        )
                    ]
                for item_var in stmt.variables[1:]:
                    if item_var and item_var != "_":
                        state.tokens[item_var] = [
                            Lineage(
                                status="constant",
                                sources=[SourceRef(kind="constant", expression=value)],
                                expression=value,
                                conditions=list(conditions),
                                parser_locations=[loc],
                            )
                        ]
            else:
                item = stmt.variables[0]
                if item != "_":
                    state.tokens[item] = [
                        Lineage(
                            status="constant",
                            sources=[SourceRef(kind="constant", expression=value)],
                            expression=value,
                            conditions=list(conditions),
                            parser_locations=[loc],
                        )
                    ]
            self._exec_statements(stmt.body, state, conditions, depth, next_loop_fanout)
            for var in bound_vars:
                if var != "_":
                    state.tokens.pop(var, None)
                    for token_name in state.descendant_tokens(var):
                        state.tokens.pop(token_name, None)
            if state.dropped:
                break

        # Restore pre-existing outer-scope tokens that the per-iteration pops
        # would have clobbered. Names not present in ``saved_outer`` stay
        # popped — those were the actual loop-iteration variables, which are
        # intentionally scoped to the loop body.
        for name, lineages in saved_outer.items():
            state.tokens[name] = lineages

    def _exec_plugin(
        self, stmt: Plugin, state: AnalyzerState, conditions: list[str], depth: int = 0, loop_fanout: int = 1
    ) -> None:
        name = stmt.name
        spec = plugin_spec_for(name)
        if spec is not None and state.dialect not in spec.dialects:
            loc = _location(stmt.line, stmt.name)
            dialects = ", ".join(spec.dialects)
            warning = (
                f"{loc}: plugin {stmt.name} is disabled for dialect {state.dialect}; supported dialects: {dialects}"
            )
            state.add_warning(
                warning,
                code="plugin_dialect_disabled",
                message=warning,
                parser_location=loc,
                source_token=stmt.name,
            )
            return
        handler_name = spec.handler_name if spec is not None else None
        if name != "on_error":
            self._warn_config_advisories(stmt, state)
        if stmt.config_diagnostics and name != "on_error":
            for diag in stmt.config_diagnostics:
                warning = config_parse_warning(stmt.line, stmt.name, diag)
                state.add_warning(
                    warning, code="malformed_config", message=warning, parser_location=_location(stmt.line, stmt.name)
                )
                state.add_taint("malformed_config", warning, _location(stmt.line, stmt.name))
            if name != "drop":
                return
        if handler_name is not None:
            if name == "on_error":
                block_handler = cast(_BlockPluginHandler, getattr(self, handler_name))
                block_handler(stmt, state, conditions, depth + 1, loop_fanout)
            else:
                plugin_handler = cast(_PluginHandler, getattr(self, handler_name))
                if spec is not None and spec.symbolic_failure_routing:
                    self._exec_plugin_with_symbolic_failure(stmt, state, conditions, plugin_handler, spec)
                else:
                    plugin_handler(stmt, state, conditions)
                    if spec is not None and spec.apply_decorators:
                        self._apply_post_plugin_decorators(stmt, state, conditions)
            if name != "on_error":
                cast(_FlowContext, self)._handle_on_error(stmt, state, conditions)
        elif name == "drop":
            percentage = first_value(stmt.config, "percentage")
            if percentage is not None and str(percentage).strip() not in ("", "100"):
                # Probabilistic drop: post-drop steps may execute on the
                # survival branch. Don't terminate the path; emit a distinct
                # diagnostic so users see this is non-deterministic.
                loc = _location(stmt.line, "drop")
                warning = (
                    f"{loc}: drop is probabilistic (percentage={percentage}); "
                    f"downstream steps remain reachable on the survival branch"
                )
                state.add_warning(
                    warning,
                    code="drop_probabilistic",
                    message=warning,
                    parser_location=loc,
                )
            else:
                warning = drop_warning(stmt.line)
                state.add_warning(
                    warning,
                    code="drop",
                    message="Parser may drop events on this path",
                    parser_location=_location(stmt.line, "drop"),
                )
                state.dropped = True
        elif name == "statedump":
            loc = _location(stmt.line, "statedump")
            warning = f"{loc}: statedump debug statement ignored by static analyzer"
            state.add_warning(
                warning,
                code="statedump",
                message="statedump debug statement ignored by static analyzer",
                parser_location=loc,
            )
        else:
            # F3 (PR-D): consult the plugin signature registry before falling
            # through to the unsupported-plugin taint path. ``self.plugin_signatures``
            # is set by ``ReverseParser.__init__`` (None preserves pre-F3
            # behavior). A registered signature routes to a generic handler
            # (provided by ``SignaturePluginMixin``, also mixed into
            # :class:`AnalysisExecutor`) that emits ``signature_dispatched``
            # lineage; an unregistered name still produces the
            # ``unsupported_plugin`` taint.
            sig = None
            registry = getattr(self, "plugin_signatures", None)
            if registry is not None:
                sig = registry.lookup(stmt.name)
            if sig is not None:
                # ``_exec_signature_dispatched`` is contributed by
                # ``SignaturePluginMixin`` at composition time; mypy can't
                # see across the sibling-mixin boundary in this file so
                # the call site is annotated rather than forcing a
                # circular import on a Protocol.
                self._exec_signature_dispatched(stmt, state, conditions, sig)  # type: ignore[attr-defined]
                # Built-in plugins (line 1371 above) call ``_handle_on_error``
                # after dispatch so a trailing ``on_error { ... }`` block runs
                # symbolically. Custom plugins routed via the signature
                # registry must have the same treatment — without this call,
                # the analyzer silently drops the on_error fallback.
                cast(_FlowContext, self)._handle_on_error(stmt, state, conditions)
                return

            warning = unsupported_plugin(stmt.line, stmt.name)
            state.add_unsupported(
                warning,
                code="unsupported_plugin",
                parser_location=_location(stmt.line, stmt.name),
                source_token=stmt.name,
            )
            # W2: Don't emit a global state.taint for the unsupported plugin —
            # that broadcasts uncertainty to every later field even when the
            # plugin's outputs (if any) feed nothing downstream. Instead, scope
            # per-token taints onto the specific destination fields the plugin
            # would have written, which we can usually infer from the config map.
            self._taint_unsupported_plugin_destinations(stmt, state, warning)

    def _exec_plugin_with_symbolic_failure(
        self,
        stmt: Plugin,
        state: AnalyzerState,
        conditions: list[str],
        plugin_handler: _PluginHandler,
        spec: PluginSpec,
    ) -> None:
        failure_conditions = _dedupe_strings(conditions + [f"{stmt.name} failure"])

        plugin_handler(stmt, state, conditions)
        if spec.apply_decorators:
            self._apply_post_plugin_decorators(stmt, state, conditions)
        self._apply_failure_tags(stmt, state, failure_conditions, spec)

    def _configured_string_list(self, stmt: Plugin, key: str, default: tuple[str, ...]) -> list[str]:
        raw = first_value(stmt.config, key)
        if raw is None:
            return list(default)
        if isinstance(raw, list) and not as_pairs(raw):
            return [str(item) for item in raw if str(item)]
        text = str(raw)
        return [text] if text else []

    def _failure_tags_for(self, stmt: Plugin, state: AnalyzerState, spec: PluginSpec) -> list[str]:
        profile = dialect_profile_for(state.dialect)
        default_failure = spec.default_failure_tags if profile.default_failure_tags_enabled else ()
        default_timeout = spec.default_timeout_tags if profile.default_failure_tags_enabled else ()
        tags = self._configured_string_list(stmt, "tag_on_failure", default_failure)
        timeout_tags = self._configured_string_list(stmt, "tag_on_timeout", default_timeout)
        on_error = first_value(stmt.config, "on_error")
        if isinstance(on_error, str) and on_error:
            tags.append(on_error)
        return _dedupe_strings(tags + timeout_tags)

    def _apply_failure_tags(self, stmt: Plugin, state: AnalyzerState, conditions: list[str], spec: PluginSpec) -> None:
        tags = self._failure_tags_for(stmt, state, spec)
        if not tags:
            return
        loc = _location(stmt.line, stmt.name, "failure tags")
        state.tag_state = state.tag_state.with_possible(tags, has_dynamic=False)
        for tag in tags:
            state.add_failure_tag_route(
                FailureTagRoute(
                    plugin=stmt.name,
                    tag=tag,
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
            )

    def _taint_unsupported_plugin_destinations(self, stmt: Plugin, state: AnalyzerState, warning: str) -> None:
        """Tag each destination written by an unsupported plugin with a scoped taint.

        Walks the plugin's config for values that look like UDM destinations
        (start with `event.`/`@output`, sit in known destination keys like
        `target`/`destination`/`replace`/`add_field`/etc.). For each
        destination we can identify, emit a token-level Lineage with an
        ``unsupported_plugin`` taint attached, so a query for that field shows
        the taint while unrelated fields remain clean.
        """
        loc = _location(stmt.line, stmt.name)
        destinations: list[str] = []
        scalar_destination_keys = {"target", "destination", "field"}
        map_destination_keys = {"replace", "add_field", "update", "copy", "merge", "rename"}
        for key, value, _depth in _iter_config_values(stmt.config):
            if key in scalar_destination_keys and isinstance(value, str):
                destinations.append(value)
            elif key in map_destination_keys and isinstance(value, list):
                pairs = as_pairs(value)
                if pairs:
                    destinations.extend(str(dest) for dest, _src in pairs)
        if not destinations:
            return
        taint = TaintReason(
            code="unsupported_plugin",
            message=warning,
            parser_location=loc,
            source_token=stmt.name,
        )
        for dest in destinations:
            normalized = dest.strip("[]").replace("][", ".")
            if not normalized:
                continue
            existing = state.tokens.get(normalized, [])
            tainted_lin = Lineage(
                status="unresolved",
                sources=[SourceRef(kind="unsupported_plugin", source_token=stmt.name, expression=normalized)],
                expression=normalized,
                conditions=[],
                parser_locations=[loc],
                taints=[taint],
            )
            state.tokens[normalized] = existing + [tainted_lin]

    def _exec_on_error_block(
        self, stmt: Plugin, state: AnalyzerState, conditions: list[str], depth: int = 0, loop_fanout: int = 1
    ) -> None:
        """Execute a standalone ``on_error { ... }`` fallback block symbolically.

        SecOps parser snippets commonly place ``on_error { ... }`` after a
        plugin. The statement frontend sees this as a braced identifier. Treat
        the body as nested parser statements rather than an unsupported plugin,
        and guard the fallback assignments with a symbolic on-error predicate.
        """
        loc = _location(stmt.line, "on_error block")
        if depth > MAX_NESTING_DEPTH:
            self._record_nesting_depth_warning(state, conditions, depth)
            return
        line_offset = (stmt.body_line or stmt.line) - 1
        body_tuple, diagnostics_tuple = _parse_on_error_body_cached(stmt.body)
        body = [_offset_statement_lines(statement, line_offset) for statement in body_tuple]
        diagnostics = [_offset_diagnostic_line(diagnostic, line_offset) for diagnostic in diagnostics_tuple]
        for diag in diagnostics:
            warning = on_error_parse_warning(loc, diag)
            state.add_warning(warning, code="on_error_parse", message=warning, parser_location=loc)
        original = state.clone()
        fallback = state.clone()
        self._exec_statements(body, fallback, _dedupe_strings(conditions + ["on_error"]), depth, loop_fanout)
        success = original.clone()
        state.merge_branch_records(
            original,
            [
                BranchRecord(fallback, _dedupe_strings(conditions + ["on_error"]), False),
                BranchRecord(success, _dedupe_strings(conditions + ["NOT(on_error)"]), True),
            ],
        )

    def _apply_post_plugin_decorators(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Apply ``add_tag`` / ``remove_tag`` / ``add_field`` / ``remove_field``
        decorators that accompany a non-mutate plugin (geoip, ruby, useragent,
        etc.). These decorators run after the plugin's primary work, exactly
        like ``mutate { add_field => ... }``.

        Implementation note: the ``mutate`` dispatch lives on
        ``MutatePluginMixin``. At runtime the concrete ``AnalysisExecutor``
        composes both mixins so ``self._exec_mutate`` is bound; mypy can't see
        across mixin boundaries, so the call goes through a typed
        ``getattr`` cast. The synthetic ``Plugin`` MUST pass ``config=`` as a
        keyword — the dataclass third positional is ``body: str``, and
        accidentally routing decorators there drops them on the floor (the
        analyzer reads only ``stmt.config``).
        """
        decorators: list[ConfigPair] = []
        for key in ("add_tag", "remove_tag", "add_field", "remove_field"):
            for val in all_values(stmt.config, key):
                decorators.append((key, val))
        if not decorators:
            return
        mutate_stmt = Plugin(stmt.line, "mutate", body="", config=decorators)
        cast(_PluginHandler, getattr(self, "_exec_mutate"))(mutate_stmt, state, conditions)  # noqa: B009

    def _exec_ruby(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes a ruby block, using heuristic regex to model its effects."""
        self._exec_ruby_like(stmt, state, conditions, kind="ruby", aggregate=False)

    def _exec_ruby_like(
        self, stmt: Plugin, state: AnalyzerState, conditions: list[str], *, kind: str, aggregate: bool
    ) -> None:
        loc = _location(stmt.line, kind)

        # 1. Collect ruby code
        code_snippets = []
        for key, value, _ in _iter_config_values(stmt.config):
            if key in ("init", "code", "timeout_code") and isinstance(value, str):
                code_snippets.append(value)

        full_code = "\n".join(code_snippets)
        if not full_code:
            self._apply_post_plugin_decorators(stmt, state, conditions)
            return

        # 2. Concurrency Risk Detection (@@var or $var)
        global_vars = set(re.findall(r"(@@\w+|\$\w+)", full_code))
        for gv in global_vars:
            warning = ruby_concurrency_risk_warning(loc, gv)
            state.add_warning(
                warning, code="ruby_concurrency_risk", message=warning, parser_location=loc, source_token=gv
            )
            state.add_taint("ruby_concurrency_risk", warning, loc, gv)

        assignment_op = r"(?:\|\|=|&&=|<<=|>>=|\*\*=|[+\-*/%&|^]?=)"

        # 3. Read Dependencies (`event.get(...)`)
        gets = re.findall(r"event\.get\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?", full_code)
        gets.extend(re.findall(rf"event\s*\[\s*['\"]([^'\"]+)['\"]\s*\](?!\s*{assignment_op})", full_code))
        map_reads = (
            re.findall(rf"map\s*\[\s*['\"]([^'\"]+)['\"]\s*\](?!\s*{assignment_op})", full_code) if aggregate else []
        )
        map_writes = (
            re.findall(rf"map\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*{assignment_op}", full_code) if aggregate else []
        )
        sources = [  # nosec B106
            SourceRef(kind=f"{kind}_get", source_token=kind, path=_normalize_field_ref(g)) for g in gets
        ]
        sources.extend(
            SourceRef(kind="aggregate_map", source_token=kind, path=_normalize_field_ref(m)) for m in map_reads
        )
        if "event.to_hash" in full_code:
            sources.append(SourceRef(kind=f"{kind}_event_hash", source_token=kind, path="event.to_hash"))
        if not sources:
            sources = [SourceRef(kind=f"{kind}_block", source_token=kind)]  # nosec B106

        if aggregate:
            for map_key, event_source in re.findall(
                rf"map\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*{assignment_op}\s*"
                r"event\.get\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?",
                full_code,
            ):
                map_token = f"@metadata.aggregate.{map_key}"
                map_lin = Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind="aggregate_get", source_token=kind, path=event_source)],
                    expression=map_token,
                    transformations=["aggregate_map_write"],
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
                cast(_FlowContext, self)._store_destination(map_token, [map_lin], loc, state, append=True)

        # 4. State Mutations (`event.set(...)`). Route through
        # ``_store_destination`` (append=True) so canonical normalization,
        # template-fanout caps, and dedup apply consistently with the rest
        # of the analyzer instead of the inline ``[]``→``.`` shortcut.
        sets = re.findall(r"event\.set\s*\(?\s*['\"]([^'\"]+)['\"]\s*,", full_code)
        sets.extend(re.findall(rf"event\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*{assignment_op}", full_code))
        for dest in sets:
            normalized = _normalize_field_ref(dest)
            if not normalized:
                continue
            ruby_lin = Lineage(
                status="dynamic",
                sources=sources,
                expression=normalized,
                transformations=[f"{kind}_set"],
                conditions=list(conditions),
                parser_locations=[loc],
            )
            cast(_FlowContext, self)._store_destination(normalized, [ruby_lin], loc, state, append=True)

        removes = re.findall(r"event\.remove\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?", full_code)
        if removes:
            mutate_stmt = Plugin(stmt.line, "mutate", body="", config=[("remove_field", removes)])
            cast(_PluginHandler, getattr(self, "_exec_mutate"))(mutate_stmt, state, conditions)  # noqa: B009

        if re.search(r"\bevent\.cancel\b", full_code):
            warning = f"{loc}: ruby event.cancel may drop events on this path"
            state.add_warning(warning, code=f"{kind}_event_cancel", message=warning, parser_location=loc)
            state.add_taint(f"{kind}_event_cancel", warning, loc)

        if aggregate and self._truthy_config(stmt, "push_map_as_event_on_timeout"):
            for map_key in _dedupe_strings([*map_reads, *map_writes]):
                dest = _normalize_field_ref(map_key)
                if not dest:
                    continue
                map_lin = Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind="aggregate_map", source_token=kind, path=map_key)],
                    expression=dest,
                    transformations=["aggregate_timeout_flush"],
                    conditions=_dedupe_strings(conditions + ["aggregate timeout flush"]),
                    parser_locations=[loc],
                )
                cast(_FlowContext, self)._store_destination(dest, [map_lin], loc, state, append=True)

        # 5. Event Splitting / Yielding (`yield`, `new_event_block.call`, or `event.clone`)
        if re.search(r"\byield\b", full_code) or "new_event_block.call" in full_code or ".clone" in full_code:
            warning = ruby_event_split_warning(loc)
            state.add_warning(warning, code=f"{kind}_event_split", message=warning, parser_location=loc)
            # No state fork required: the warning already conveys the
            # event-multiplication risk to consumers, and the previous code
            # merged two unmutated ``state.clone()`` copies into ``original``
            # — by definition that produces no observable lineage difference
            # (no branch ever wrote to its clone). Keeping the no-op merge
            # was hot in long ruby chains and contributed nothing. See
            # remediation plan R4.
        self._apply_post_plugin_decorators(stmt, state, conditions)

    def _exec_translate(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes a translate block."""
        field = first_value(stmt.config, "field")
        if field is None:
            field = first_value(stmt.config, "source")

        destination = first_value(stmt.config, "destination")
        if destination is None:
            destination = field if field else "translation"

        if not field:
            return

        loc = _location(stmt.line, "translate")
        sources = [SourceRef(kind="translate", source_token="translate", path=str(field))]  # nosec B106

        dest_str = _normalize_field_ref(str(destination))
        if not dest_str:
            return

        dictionary_pairs = self._translate_dictionary_pairs(stmt)
        fallback = first_value(stmt.config, "fallback")
        regex_mode = self._truthy_config(stmt, "regex") or not self._truthy_config(stmt, "exact", default=True)
        dictionary_path = first_value(stmt.config, "dictionary_path")
        transformations = ["translate"]
        notes: list[str] = []
        if dictionary_pairs:
            transformations.append("translate_dictionary")
            preview = ", ".join(f"{key!r}->{value!r}" for key, value in dictionary_pairs[:5])
            if len(dictionary_pairs) > 5:
                preview += ", ..."
            notes.append(f"inline dictionary entries: {preview}")
        if fallback is not None:
            transformations.append("translate_fallback")
            notes.append(f"fallback: {fallback!r}")
        if regex_mode:
            transformations.append("translate_regex")
            notes.append("dictionary keys may be regex patterns")
        if dictionary_path is not None:
            transformations.append("translate_dictionary_path")
            warning = f"{loc}: translate dictionary_path is runtime-loaded; dictionary values are not enumerated"
            state.add_warning(
                warning,
                code="dynamic_translate_dictionary",
                message=warning,
                parser_location=loc,
                source_token=str(dictionary_path),
            )
            state.add_taint("dynamic_translate_dictionary", warning, loc, str(dictionary_path))

        translate_lin = Lineage(
            status="dynamic" if regex_mode or dictionary_path is not None else "derived",
            sources=sources,
            expression=f"translate({field!s})",
            transformations=transformations,
            conditions=list(conditions),
            parser_locations=[loc],
            notes=notes,
        )
        cast(_FlowContext, self)._store_destination(dest_str, [translate_lin], loc, state, append=True)
        object_pairs = self._translate_object_projection_pairs(dictionary_pairs, fallback)
        if object_pairs:
            cast(_FlowContext, self)._assign_object_literal_subfields(
                dest_str,
                object_pairs,
                state,
                conditions,
                stmt.line,
                "translate",
            )
        self._apply_post_plugin_decorators(stmt, state, conditions)

    def _exec_aggregate(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes an aggregate block (uses embedded ruby code)."""
        loc = _location(stmt.line, "aggregate")
        warning = f"{loc}: aggregate uses shared state across events; modeled conservatively"
        state.add_warning(warning, code="aggregate_state", message=warning, parser_location=loc)
        state.add_taint("aggregate_state", warning, loc)
        timeout_tags = first_value(stmt.config, "timeout_tags")
        if isinstance(timeout_tags, list) and not as_pairs(timeout_tags):
            tags = [str(tag) for tag in timeout_tags if str(tag)]
            state.tag_state = state.tag_state.with_possible(tags, has_dynamic=False)
            for tag in tags:
                state.add_failure_tag_route(
                    FailureTagRoute(
                        plugin="aggregate",
                        tag=tag,
                        conditions=_dedupe_strings(conditions + ["aggregate timeout"]),
                        parser_locations=[_location(stmt.line, "aggregate", "timeout_tags")],
                    )
                )
        self._exec_ruby_like(stmt, state, conditions, kind="aggregate", aggregate=True)

    def _truthy_config(self, stmt: Plugin, key: str, *, default: bool = False) -> bool:
        value = first_value(stmt.config, key)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes"}
        return bool(value)

    def _translate_dictionary_pairs(self, stmt: Plugin) -> list[tuple[str, str]]:
        dictionary = first_value(stmt.config, "dictionary")
        pairs = as_pairs(dictionary) if isinstance(dictionary, list) else []
        return [(str(key), str(value)) for key, value in pairs]

    def _translate_object_projection_pairs(
        self, dictionary_pairs: list[tuple[str, str]], fallback: ConfigValue | None
    ) -> list[ConfigPair]:
        merged: dict[str, ConfigValue] = {}
        for _key, value in dictionary_pairs:
            for field, field_value in self._json_object_pairs(value):
                merged.setdefault(field, field_value)
        if fallback is not None:
            for field, field_value in self._json_object_pairs(str(fallback)):
                merged.setdefault(field, field_value)
        return sorted(merged.items())

    def _json_object_pairs(self, value: str) -> list[ConfigPair]:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, dict):
            return []
        pairs: list[ConfigPair] = []
        for key, item in parsed.items():
            if isinstance(item, dict):
                pairs.append((str(key), [(str(k), self._json_scalar_to_config(v)) for k, v in sorted(item.items())]))
            elif isinstance(item, list):
                list_value: list[ConfigValue] = [self._json_scalar_to_config(v) for v in item]
                pairs.append((str(key), list_value))
            elif item is None:
                pairs.append((str(key), "null"))
            elif isinstance(item, bool):
                pairs.append((str(key), item))
            else:
                pairs.append((str(key), str(item)))
        return pairs

    def _json_scalar_to_config(self, value: object) -> ConfigValue:
        if isinstance(value, bool):
            return value
        if isinstance(value, list):
            return [self._json_scalar_to_config(item) for item in value]
        if isinstance(value, dict):
            return [(str(k), self._json_scalar_to_config(v)) for k, v in sorted(value.items())]
        if value is None:
            return "null"
        return str(value)

    def _exec_clone(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes a clone block."""
        clones = first_value(stmt.config, "clones")
        if not isinstance(clones, list):
            return

        num_clones = len(clones)
        if num_clones == 0:
            return

        loc = _location(stmt.line, "clone")

        # R2: cap fanout. A pathological ``clones => [...500 entries...]``
        # would otherwise produce one branch per entry, which is linear in
        # the parser's literal list size. Above ``MAX_CLONE_FANOUT`` we
        # truncate the iterated list and emit a structured warning so
        # consumers know the analysis only saw a sample.
        clones_iter = clones
        if num_clones > MAX_CLONE_FANOUT:
            warning = (
                f"{loc}: clone fanout {num_clones} exceeds limit {MAX_CLONE_FANOUT}; "
                f"only the first {MAX_CLONE_FANOUT} clone types are modeled"
            )
            state.add_warning(
                warning,
                code="clone_fanout",
                message=warning,
                parser_location=loc,
            )
            state.add_taint(
                "clone_fanout",
                f"Clone fanout {num_clones} exceeded {MAX_CLONE_FANOUT}; "
                f"lineage reflects the first {MAX_CLONE_FANOUT} entries only",
                loc,
            )
            clones_iter = clones[:MAX_CLONE_FANOUT]

        original = state.clone()
        branches = [BranchRecord(original.clone(), conditions, False)]

        for clone_type in clones_iter:
            clone_state = state.clone()
            type_lin = Lineage(
                status="constant",
                sources=[SourceRef(kind="constant", source_token="clone", expression=str(clone_type))],  # nosec B106
                expression=str(clone_type),
                conditions=list(conditions),
                parser_locations=[loc],
            )
            clone_state.tokens["type"] = clone_state.tokens.get("type", []) + [type_lin]
            self._apply_post_plugin_decorators(stmt, clone_state, conditions)
            branches.append(BranchRecord(clone_state, conditions, False))

        state.merge_branch_records(original, branches)

    def _exec_generic_plugin(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes generic decorators for supported but opaque plugins."""
        success_state = state.clone()
        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_enrichment_plugin(self, stmt: Plugin, state: AnalyzerState, conditions: list[str], kind: str) -> None:
        """Executes an enrichment plugin (like geoip or useragent) mapping source to target."""
        source = first_value(stmt.config, "source")
        fields = first_value(stmt.config, "fields")
        loc = _location(stmt.line, kind)

        success_state = state.clone()
        if source:
            sources = [SourceRef(kind=kind, source_token=kind, path=str(source))]
            target_val = first_value(stmt.config, "target")
            prefix_val = first_value(stmt.config, "prefix")
            projection_mode = "target"
            if target_val is not None:
                dest_value = target_val
            elif prefix_val is not None:
                dest_value = prefix_val
                projection_mode = "prefix"
            else:
                dest_value = kind
            dest_str = _normalize_field_ref(str(dest_value))
            if dest_str:
                lin = Lineage(
                    status="dynamic",
                    sources=sources,
                    expression=dest_str,
                    transformations=[kind],
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
                cast(_FlowContext, self)._store_destination(dest_str, [lin], loc, success_state, append=True)
                if isinstance(fields, list) and not as_pairs(fields):
                    for field in fields:
                        if projection_mode == "prefix":
                            child = _normalize_field_ref(f"{dest_str}{field}")
                        else:
                            child = _normalize_field_ref(f"{dest_str}.{field}")
                        if not child:
                            continue
                        child_lin = Lineage(
                            status="dynamic",
                            sources=sources,
                            expression=child,
                            transformations=[kind, "field_projection"],
                            conditions=list(conditions),
                            parser_locations=[loc],
                        )
                        cast(_FlowContext, self)._store_destination(child, [child_lin], loc, success_state, append=True)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_useragent(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        self._exec_enrichment_plugin(stmt, state, conditions, "useragent")

    def _exec_geoip(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        self._exec_enrichment_plugin(stmt, state, conditions, "geoip")

    def _exec_split(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes a split block."""
        field = first_value(stmt.config, "field")
        target = first_value(stmt.config, "target")
        if not field:
            return

        field_str = _normalize_field_ref(str(field))
        target_str = _normalize_field_ref(str(target)) if target else field_str
        if not target_str:
            return

        loc = _location(stmt.line, "split")

        success_state = state.clone()
        sources = [SourceRef(kind="split", source_token="split", path=field_str)]  # nosec B106
        lin = Lineage(
            status="dynamic",
            sources=sources,
            expression=target_str,
            conditions=list(conditions),
            parser_locations=[loc],
        )
        # split replaces the destination's value (Logstash semantics: replaces
        # a field's scalar with the array of split parts), so use the default
        # ``append=False`` ``_store_destination`` path which routes to
        # ``_assign`` and clears stale descendants.
        cast(_FlowContext, self)._store_destination(target_str, [lin], loc, success_state)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_external_lookup(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes an external lookup plugin."""
        target = first_value(stmt.config, "target")
        loc = _location(stmt.line, stmt.name)
        query_source = (
            first_value(stmt.config, "query")
            or first_value(stmt.config, "statement")
            or first_value(stmt.config, "url")
            or "external_query"
        )

        success_state = state.clone()
        store = cast(_FlowContext, self)._store_destination
        if target:
            dest_str = _normalize_field_ref(str(target))
            if dest_str:
                lin = Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind=stmt.name, source_token=stmt.name, path=str(query_source))],
                    expression=dest_str,
                    transformations=[stmt.name],
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
                store(dest_str, [lin], loc, success_state, append=True)

        # R5: ``target`` and ``get`` may both write to the same destination —
        # e.g. ``elasticsearch { target => "es.id" get => { "x" => "es.id" } }``.
        # Both lineages are real assignments (the lookup writes the row, the
        # ``get`` map projects fields onto the same path) and should both
        # survive deduplication thanks to distinct ``SourceRef.path`` values.
        projections = [*all_values(stmt.config, "get"), *all_values(stmt.config, "fields")]
        for get_block in projections:
            projection_pairs = as_pairs(get_block)
            for src, tgt in projection_pairs:
                dest_str = _normalize_field_ref(str(tgt))
                if not dest_str:
                    continue
                lin = Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind=stmt.name, source_token=stmt.name, path=str(src))],
                    expression=dest_str,
                    transformations=[stmt.name, "field_projection"],
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
                store(dest_str, [lin], loc, success_state, append=True)
            if not projection_pairs and target and isinstance(get_block, list):
                target_str = _normalize_field_ref(str(target))
                if target_str:
                    for field in get_block:
                        child = _normalize_field_ref(f"{target_str}.{field}")
                        if not child:
                            continue
                        lin = Lineage(
                            status="dynamic",
                            sources=[SourceRef(kind=stmt.name, source_token=stmt.name, path=str(field))],
                            expression=child,
                            transformations=[stmt.name, "field_projection"],
                            conditions=list(conditions),
                            parser_locations=[loc],
                        )
                        store(child, [lin], loc, success_state, append=True)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_prune(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes the prune block."""
        loc = _location(stmt.line, "prune")
        warning = f"{loc}: prune filter is destructive and runtime-dependent; downstream fields may be missing"
        state.add_warning(warning, code="dynamic_prune", message=warning, parser_location=loc)

        for token, lineages in state.tokens.items():
            tainted_lineages = []
            for lin in lineages:
                taint = state.add_taint("prune_risk", "Token may be dropped by prune filter", loc, token)
                tainted_lineages.append(lin.with_taints((*lin.taints, taint)))
            state.tokens[token] = tainted_lineages

        success_state = state.clone()
        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_generic_transform(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Symbolically propagate lineage for generic transform plugins."""
        loc = _location(stmt.line, stmt.name)
        source = first_value(stmt.config, "source")
        target = first_value(stmt.config, "target")
        fields = first_value(stmt.config, "fields")
        field = first_value(stmt.config, "field")

        operations: list[tuple[str, str]] = []
        if source is not None:
            src = str(source)
            operations.append((src, str(target) if target is not None else src))
        elif fields is not None or field is not None:
            field_values: list[str] = []
            if isinstance(fields, list):
                field_values.extend([str(f) for f in fields])
            elif fields is not None:
                field_values.append(str(fields))
            if field is not None:
                field_values.append(str(field))
            operations.extend((f, f) for f in field_values)
        elif stmt.name == "math":
            calculate = first_value(stmt.config, "calculate")
            if isinstance(calculate, list) and len(calculate) >= 4:
                src = str(calculate[1])
                tgt = str(calculate[-1])
                operations.append((src, tgt))

        success_state = state.clone()
        if not operations:
            warning = f"{loc}: generic transform plugin missing source/field"
            success_state.add_warning(warning, code="missing_source_field", message=warning, parser_location=loc)
        else:
            ctx = cast(_FlowContext, self)
            for src, dst in operations:
                op_loc = _location(stmt.line, stmt.name, f"{src} -> {dst}")
                lins = [lin.with_transform(stmt.name, op_loc) for lin in ctx._resolve_token(src, success_state, op_loc)]
                if not lins:
                    lins = [
                        Lineage(
                            status="derived",
                            sources=[SourceRef(kind=stmt.name, source_token=stmt.name, expression=src)],
                            expression=dst,
                            transformations=[stmt.name],
                            conditions=list(conditions),
                            parser_locations=[op_loc],
                        )
                    ]
                ctx._store_destination(_normalize_field_ref(dst), lins, op_loc, success_state)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_dns(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes the dns block."""
        resolves = all_values(stmt.config, "resolve")
        reverses = all_values(stmt.config, "reverse")
        fields = []
        for r in resolves + reverses:
            if isinstance(r, list):
                fields.extend([str(x) for x in r])
            else:
                fields.append(str(r))

        success_state = state.clone()
        ctx = cast(_FlowContext, self)
        for f in fields:
            op_loc = _location(stmt.line, "dns", f)
            lins = [lin.with_transform("dns", op_loc) for lin in ctx._resolve_token(f, success_state, op_loc)]
            if not lins:
                lins = [
                    Lineage(
                        status="dynamic",
                        sources=[SourceRef(kind="dns", source_token="dns", expression=f)],  # nosec B106
                        expression=f,
                        transformations=["dns"],
                        conditions=list(conditions),
                        parser_locations=[op_loc],
                    )
                ]
            ctx._store_destination(_normalize_field_ref(f), lins, op_loc, success_state)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_elapsed(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes the elapsed block."""
        loc = _location(stmt.line, "elapsed")
        success_state = state.clone()
        dest_str = "elapsed.time"
        lin = Lineage(
            status="dynamic",
            sources=[SourceRef(kind="elapsed", source_token="elapsed", path="timer")],  # nosec B106
            expression=dest_str,
            conditions=list(conditions),
            parser_locations=[loc],
        )
        cast(_FlowContext, self)._store_destination(dest_str, [lin], loc, success_state, append=True)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )

    def _exec_uuid(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Executes the uuid block."""
        target = first_value(stmt.config, "target")
        loc = _location(stmt.line, "uuid")
        success_state = state.clone()
        if target:
            dest_str = _normalize_field_ref(str(target))
            if dest_str:
                lin = Lineage(
                    status="dynamic",
                    sources=[SourceRef(kind="uuid", source_token="uuid", path="generator")],  # nosec B106
                    expression=dest_str,
                    conditions=list(conditions),
                    parser_locations=[loc],
                )
                cast(_FlowContext, self)._store_destination(dest_str, [lin], loc, success_state, append=True)

        self._apply_post_plugin_decorators(stmt, success_state, conditions)
        state.merge_branch_records(
            state.clone(),
            [
                BranchRecord(success_state, conditions, False),
                BranchRecord(state.clone(), conditions, False),
            ],
        )
