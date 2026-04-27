"""Extractor plugin handlers for reverse-lineage analysis."""

from __future__ import annotations

from typing import Protocol, TypeVar, cast

from pydantic import BaseModel, ValidationError

from ._analysis_details import (
    capture_upstream_details,
    csv_column_details,
    csv_extraction_details,
    grok_capture_details,
    json_extraction_details,
    kv_extraction_details,
    xml_line_details,
    xml_template_details,
)
from ._analysis_diagnostics import (
    config_validation_warning,
    dissect_indirect_warning,
    duplicate_config_key_warning,
    extractor_source_unresolved_warning,
    json_source_unresolved_warning,
    json_target_warning,
    no_dissect_mapping_warning,
    no_grok_match_warning,
    no_xpath_mappings_warning,
    static_limit_warning,
    unknown_config_key_warning,
)
from ._analysis_helpers import (
    _DISSECT_FIELD_RE,
    _GROK_NAMED_RE,
    _REGEX_NAMED_RE,
    _TOKEN_REF_RE,
    _dedupe_lineages,
    _dedupe_strings,
    _location,
    _static_lineage_value,
    _strip_ref,
)
from ._analysis_state import AnalyzerState, ExtractionHint
from ._grok_patterns import GrokLibrary, expand_pattern
from ._plugin_config_models import (
    CsvPluginConfig,
    DissectPluginConfig,
    GrokPluginConfig,
    JsonPluginConfig,
    KvPluginConfig,
    XmlPluginConfig,
    compact_validation_error,
)
from ._regex_algebra import MAX_REGEX_BODY_BYTES
from ._types import ConfigValue
from .ast_nodes import Plugin
from .config_parser import all_values, as_pairs
from .model import Lineage, LineageStatus, SourceRef, TaintReason

MAX_EXTRACTOR_SOURCE_DEPTH = 32
MAX_UNRESOLVED_EXTRACTOR_WARNINGS = 128
DefaultValue = TypeVar("DefaultValue")
ModelT = TypeVar("ModelT", bound=BaseModel)


# PR-C (F2 algebra wiring) — synthesizing implicit grok constraints.
#
# When the grok extractor resolves a captured pattern (e.g. ``%{IP:src_ip}``)
# we synthesize a synthetic ``[<token>] =~ /<resolved_body>/`` condition
# string and inject it into ``state.implicit_path_conditions``. The
# contradiction engine consults that list alongside the user-visible
# ``path_conditions`` so a downstream ``[src_ip] =~ /^[A-Z]+$/`` can be
# proven unreachable. Soundness contract: when the synthesis can't
# produce a parseable condition (e.g. body would need impossible
# escaping, exceeds the algebra's body cap), we skip it and the algebra
# returns its UNKNOWN-as-compatible default — never less safe than the
# pre-PR-C state.

# Bodies that constrain nothing — synthesizing a condition over them
# would only bloat the cache key and the algebra would return UNKNOWN
# anyway. The set is conservative: anything not on this list goes
# through to the algebra and lets it decide.
_TRIVIAL_GROK_BODIES = frozenset({"", ".*", ".+", "(.*)", "(.+)", "(?:.*)", "(?:.+)"})

# Aligned with ``_regex_algebra.MAX_REGEX_BODY_BYTES``: synthesizing a
# longer body would parse-fail downstream in the algebra's
# ``extract_regex_literal``, so the constraint would have no effect —
# better to skip the synthesis altogether than spend cache slots on
# dead conditions. Re-exported as ``_MAX_IMPLICIT_GROK_BODY_BYTES`` for
# test access; the source of truth is the algebra constant.
#
# v0.2 limitation: this cap means large bundled patterns (``IP`` ≈ 1.3 KB,
# ``URI`` ≈ 1.5 KB, ``COMMONAPACHELOG`` ≈ 2.3 KB) don't get implicit
# constraints. 241 of 316 bundled patterns DO fit. Future PR can either
# bump ``MAX_REGEX_BODY_BYTES`` or route implicit conditions through a
# separate code path with a higher per-body budget.
_MAX_IMPLICIT_GROK_BODY_BYTES = MAX_REGEX_BODY_BYTES

# Token names containing these characters would produce malformed
# ``[<token>] =~ /<body>/`` strings that the algebra silently rejects
# (sound: returns UNKNOWN-as-compatible). Validate up front so a
# pathological pattern like ``%{IP:weird]name}`` doesn't waste a cache
# slot on a dead constraint, and so the failure mode is visible to
# tests.
_INVALID_TOKEN_CHARS = frozenset("[]/\\\n\r")


def _is_trivial_grok_body(body: str) -> bool:
    return body in _TRIVIAL_GROK_BODIES


def _synthesize_implicit_grok_condition(token: str, body: str) -> str | None:
    """Build a ``[<token>] =~ /<body>/`` condition string parseable by
    the regex algebra's ``_EXTRACT_REGEX_LITERAL_RE``.

    Returns ``None`` when the synthesized condition would be unparseable
    or unsound. Specifically rejects:

    * empty token or body,
    * tokens containing characters that would break the ``[...] =~ /.../``
      delimiters (``[``, ``]``, ``/``, ``\\``) or that span lines,
    * bodies containing newlines (algebra is line-mode),
    * bodies exceeding the algebra's body cap.

    Only the ``/`` delimiter character is escaped in the body. Backslash
    escapes (``\\d``, ``\\b``, ``\\w``, etc.) are preserved as-is —
    doubling backslashes would change regex semantics from "match a
    digit" to "match a literal backslash followed by d", silently
    making the implicit constraint stricter than the runtime grok
    capture and corrupting downstream contradiction reasoning.
    """
    if not token or not body:
        return None
    if any(c in _INVALID_TOKEN_CHARS for c in token):
        return None
    if "\n" in body or "\r" in body:
        return None
    if len(body.encode("utf-8")) > _MAX_IMPLICIT_GROK_BODY_BYTES:
        return None
    # Escape only the ``/`` delimiter so the literal form parses; leave
    # backslashes untouched so escapes like ``\d`` keep their regex
    # meaning when the algebra compiles the body.
    escaped = body.replace("/", "\\/")
    return f"[{token}] =~ /{escaped}/"


class _ExtractorContext(Protocol):
    def _lineage_from_expression(
        self, expr: str, state: AnalyzerState, loc: str, conditions: list[str], bare_is_token: bool = False
    ) -> list[Lineage]: ...

    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _infer_source_for_token(
        self, token: str, state: AnalyzerState, loc: str, include_extractor_hints: bool = True
    ) -> list[Lineage]: ...

    def _cache_inferred_token(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None: ...

    def _assign(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None: ...

    def _append(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None: ...


# Source kinds that indicate the lineage was produced by an extractor plugin.
# When an extractor writes to a token that already holds *non-extractor* lineage
# (e.g. from mutate.replace/copy/merge), the prior lineage is preserved by
# appending the extractor result instead of overwriting it. Two extractor writes
# to the same token still overwrite, matching long-standing baseline behavior.
_EXTRACTOR_SOURCE_KINDS = frozenset(
    {
        "grok_capture",
        "regex_capture",
        "dissect_field",
        "json_path",
        "xml_xpath",
        "kv_key",
        "csv_column",
    }
)


def _has_non_extractor_lineage(state: AnalyzerState, token: str) -> bool:
    """Return True iff ``token`` has at least one prior lineage whose sources
    were NOT all produced by extractor plugins.

    Used to decide whether an extractor write should append (preserving a prior
    mutate.replace/copy/merge) or overwrite (the baseline behavior between two
    extractor writes).
    """
    existing = state.tokens.get(token, [])
    if not existing:
        return False
    for lin in existing:
        if not lin.sources:
            # No sources is treated as non-extractor (e.g. unresolved/dynamic
            # placeholders introduced outside of extractor handlers).
            return True
        if any(src.kind not in _EXTRACTOR_SOURCE_KINDS for src in lin.sources):
            return True
    return False


class ExtractorPluginMixin:
    def _extractor_assign(self, token: str, lineages: list[Lineage], state: AnalyzerState) -> None:
        """Assign an extractor capture to ``token``.

        If the token already has lineage from a non-extractor source (such as
        ``mutate.replace`` or ``mutate.copy``), append the new lineage so the
        prior value survives as an alternative. Two extractor writes to the
        same token still overwrite, preserving baseline behavior.
        """
        context = cast(_ExtractorContext, self)
        if _has_non_extractor_lineage(state, token):
            context._append(token, lineages, state)
        else:
            context._assign(token, lineages, state)

    def _record_unresolved_extractor_source(
        self, plugin_name: str, source: str, state: AnalyzerState, loc: str
    ) -> TaintReason:
        state._ensure_diagnostics_owned()
        key = plugin_name
        count = state._unresolved_extractor_source_counts.get(key, 0) + 1
        state._unresolved_extractor_source_counts[key] = count
        warning = (
            json_source_unresolved_warning(loc) if plugin_name == "json" else extractor_source_unresolved_warning(loc)
        )
        if count <= MAX_UNRESOLVED_EXTRACTOR_WARNINGS:
            state.add_warning(
                warning, code="unresolved_extractor_source", message=warning, parser_location=loc, source_token=source
            )
            return state.add_taint("unresolved_extractor_source", warning, loc, source)
        summary_taint = state._unresolved_extractor_source_summary_taints.get(key)
        if summary_taint is None:
            summary_warning = (
                f"{loc}: {plugin_name} extractor source tokens were not resolved; "
                f"additional unresolved sources summarized after {MAX_UNRESOLVED_EXTRACTOR_WARNINGS} warnings"
            )
            state.add_warning(
                summary_warning,
                code="unresolved_extractor_source",
                message=summary_warning,
                parser_location=loc,
                source_token=f"{plugin_name}:unresolved_sources",
            )
            summary_taint = state.add_taint(
                "unresolved_extractor_source",
                f"{plugin_name} extractor source tokens were summarized after unresolved-source warning limit",
                loc,
                f"{plugin_name}:unresolved_sources",
            )
            state._unresolved_extractor_source_summary_taints[key] = summary_taint
        else:
            state.add_suppressed_diagnostic_counts(
                warning_code="unresolved_extractor_source", taint_code="unresolved_extractor_source"
            )
        return summary_taint

    def _validate_config_model(
        self, stmt: Plugin, state: AnalyzerState, model_cls: type[ModelT], data: dict[str, object]
    ) -> ModelT | None:
        validation_data = dict(data)
        for key, value in stmt.config:
            if str(key) == "on_error":
                continue
            if str(key) not in validation_data:
                validation_data[str(key)] = value
        try:
            return model_cls.model_validate(validation_data)
        except ValidationError as exc:
            extra_errors = [err for err in exc.errors() if err.get("type") == "extra_forbidden"]
            for err in extra_errors:
                key = ".".join(str(part) for part in err.get("loc", ())) or "config"
                warning = unknown_config_key_warning(stmt.line, stmt.name, key)
                state.add_warning(
                    warning,
                    code="unknown_config_key",
                    message=warning,
                    parser_location=_location(stmt.line, stmt.name),
                    source_token=key,
                )
            if len(extra_errors) == len(exc.errors()):
                retry_data = dict(validation_data)
                for err in extra_errors:
                    err_loc = tuple(err.get("loc", ()))
                    if len(err_loc) == 1:
                        retry_data.pop(str(err_loc[0]), None)
                return model_cls.model_validate(retry_data)
            detail = compact_validation_error(exc)
            loc = _location(stmt.line, stmt.name)
            warning = config_validation_warning(stmt.line, stmt.name, detail)
            state.add_warning(warning, code="config_validation", message=detail, parser_location=loc)
            state.add_taint("invalid_config", detail, loc)
            return None

    def _first_config_value(
        self, stmt: Plugin, state: AnalyzerState, key: str, default: DefaultValue | None = None
    ) -> ConfigValue | DefaultValue | None:
        values = all_values(stmt.config, key)
        if len(values) > 1:
            warning = duplicate_config_key_warning(stmt.line, stmt.name, key, len(values))
            state.add_warning(
                warning,
                code="duplicate_config_key",
                message=warning,
                parser_location=_location(stmt.line, stmt.name),
                source_token=key,
            )
        return values[0] if values else default

    def _resolve_extractor_source(
        self,
        plugin_name: str,
        source: str,
        state: AnalyzerState,
        loc: str,
        _visited: set[str] | None = None,
        _depth: int = 0,
    ) -> tuple[list[Lineage], bool]:
        context = cast(_ExtractorContext, self)
        source = str(source)
        if "%{" in source:
            visited = set(_visited or set())
            if source in visited or _depth >= MAX_EXTRACTOR_SOURCE_DEPTH:
                warning = static_limit_warning(loc, f"{plugin_name} cyclic extractor source {source}")
                state.add_warning(
                    warning, code="dynamic_extractor_source", message=warning, parser_location=loc, source_token=source
                )
                cyclic_taint = state.add_taint(
                    "dynamic_extractor_source",
                    f"{plugin_name} extractor source {source!r} could not be resolved without cycling",
                    loc,
                    source,
                )
                return [
                    Lineage(
                        status="dynamic",
                        sources=[SourceRef(kind="dynamic_reference", expression=source)],
                        expression=source,
                        parser_locations=[loc],
                        notes=["Extractor source token name resolution exceeded the static recursion guard."],
                        taints=[cyclic_taint],
                    )
                ], False
            visited.add(source)
            taint: TaintReason | None = None
            expanded: list[Lineage] = []
            all_resolved = True
            for source_lin in context._lineage_from_expression(source, state, loc, [], bare_is_token=True):
                concrete = _static_lineage_value(source_lin)
                if concrete is not None:
                    concrete_lineages, concrete_resolved = self._resolve_extractor_source(
                        plugin_name, concrete, state, loc, visited, _depth + 1
                    )
                    all_resolved = all_resolved and concrete_resolved
                    for concrete_lin in concrete_lineages:
                        clone = concrete_lin.with_conditions(source_lin.conditions).with_parser_locations(
                            [*source_lin.parser_locations, loc]
                        )
                        expanded.append(clone)
                    continue
                all_resolved = False
                if taint is None:
                    warning = static_limit_warning(loc, f"{plugin_name} dynamic extractor source {source}")
                    state.add_warning(
                        warning,
                        code="dynamic_extractor_source",
                        message=warning,
                        parser_location=loc,
                        source_token=source,
                    )
                    taint = state.add_taint(
                        "dynamic_extractor_source",
                        f"{plugin_name} extractor source {source!r} is runtime-dependent",
                        loc,
                        source,
                    )
                clone = source_lin if source_lin.status == "unresolved" else source_lin.with_status("dynamic")
                clone = clone.with_notes(["Extractor source token name is runtime-dependent."]).with_taints([taint])
                expanded.append(clone)
            return _dedupe_lineages(expanded), all_resolved and bool(expanded)
        if source in state.tokens:
            return context._resolve_token(source, state, loc), True
        inferred = context._infer_source_for_token(source, state, loc, include_extractor_hints=plugin_name != "json")
        if inferred:
            context._cache_inferred_token(source, inferred, state)
            return [lin.clone() for lin in inferred], True
        taint = self._record_unresolved_extractor_source(plugin_name, source, state, loc)
        return [
            Lineage(
                status="unresolved",
                sources=[SourceRef(kind="unknown", source_token=source, expression=source)],
                expression=source,
                parser_locations=[loc],
                notes=["Extractor source token was not resolved."],
                taints=[taint],
            )
        ], False

    def _invalid_config_source_lineage(self, source: str, state: AnalyzerState, loc: str) -> tuple[list[Lineage], bool]:
        taint = state.add_taint("invalid_config", f"Extractor source {source!r} failed config validation", loc, source)
        return [
            Lineage(
                status="unresolved",
                sources=[SourceRef(kind="unknown", source_token=source, expression=source)],
                expression=source,
                parser_locations=[loc],
                notes=["Extractor source config failed validation."],
                taints=[taint],
            )
        ], False

    def _exec_json(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        source_raw = self._first_config_value(stmt, state, "source", "message")
        target_raw = self._first_config_value(stmt, state, "target")
        array_function_raw = self._first_config_value(stmt, state, "array_function")
        config = self._validate_config_model(
            stmt,
            state,
            JsonPluginConfig,
            {"source": source_raw, "target": target_raw, "array_function": array_function_raw},
        )
        if target_raw is not None and not isinstance(target_raw, str):
            loc = _location(stmt.line, "json", f"source={source_raw}")
            warning = json_target_warning(loc, target_raw)
            state.add_warning(
                warning, code="json_target", message=warning, parser_location=loc, source_token=str(target_raw)
            )
        if config is None:
            loc = _location(stmt.line, "json", f"source={source_raw}")
            state.add_extraction_hint(
                "json",
                ExtractionHint(
                    "json",
                    str(source_raw),
                    json_extraction_details(array_function_raw, None, stmt.line),
                    conditions=list(conditions),
                    parser_locations=[loc],
                    source_resolved=False,
                ),
            )
            return
        source = config.source
        target = config.target
        array_function = config.array_function
        loc = _location(stmt.line, "json", f"source={source}")
        if target is not None and not isinstance(target, str):
            warning = json_target_warning(loc, target)
            state.add_warning(
                warning, code="json_target", message=warning, parser_location=loc, source_token=str(target)
            )
            target = None
        if array_function not in (None, "split_columns"):
            warning = static_limit_warning(loc, f"json array_function={array_function}")
            state.add_warning(
                warning, code="json_array_function", message=warning, parser_location=loc, source_token=source
            )
            state.add_taint("json_array_function", f"json array_function={array_function} is symbolic", loc, source)
        _source_lineages, source_resolved = self._resolve_extractor_source("json", source, state, loc)
        state.add_extraction_hint(
            "json",
            ExtractionHint(
                "json",
                source,
                json_extraction_details(array_function, target, stmt.line),
                conditions=list(conditions),
                parser_locations=[loc],
                source_resolved=source_resolved,
            ),
        )

    def _exec_xml(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        source_raw = self._first_config_value(stmt, state, "source", "message")
        xpath_values = all_values(stmt.config, "xpath")
        namespaces = all_values(stmt.config, "namespaces")
        config = self._validate_config_model(
            stmt, state, XmlPluginConfig, {"source": source_raw, "xpath": xpath_values, "namespaces": namespaces}
        )
        source = config.source if config is not None else str(source_raw)
        loc_base = _location(stmt.line, "xml", f"source={source}")
        if config is None and not isinstance(source_raw, str):
            source_lineages, source_resolved = self._invalid_config_source_lineage(source, state, loc_base)
        else:
            source_lineages, source_resolved = self._resolve_extractor_source("xml", source, state, loc_base)
        if namespaces:
            warning = static_limit_warning(loc_base, "xml namespaces")
            state.add_warning(
                warning, code="xml_namespaces", message=warning, parser_location=loc_base, source_token=source
            )
            state.add_taint("xml_namespaces", "XML namespaces are symbolic", loc_base, source)
        state.add_extraction_hint(
            "xml",
            ExtractionHint(
                "xml",
                source,
                xml_line_details(stmt.line),
                conditions=list(conditions),
                parser_locations=[loc_base],
                source_resolved=source_resolved,
            ),
        )
        captured_tokens: dict[str, list[Lineage]] = {}
        for xpath in xpath_values:
            for path, token in as_pairs(xpath):
                raw_path = str(path)
                if "(" in raw_path or ")" in raw_path:
                    path_loc = _location(stmt.line, "xml.xpath", raw_path)
                    warning = static_limit_warning(path_loc, "complex XPath expression")
                    state.add_warning(
                        warning, code="complex_xpath", message=warning, parser_location=path_loc, source_token=source
                    )
                    state.add_taint("complex_xpath", f"XPath {raw_path!r} is symbolic", path_loc, source)
                normalized_path, path_conditions, path_locations = self._normalize_xpath_template(
                    raw_path, state, conditions, stmt.line
                )
                loc = _location(stmt.line, "xml.xpath", f"{path} => {token}")
                if source_resolved:
                    lin = Lineage(
                        status="exact",
                        sources=[
                            SourceRef(
                                kind="xml_xpath",
                                source_token=source,
                                path=normalized_path,
                                details=xml_template_details(raw_path, normalized_path),
                            )
                        ],
                        expression=str(token),
                        conditions=_dedupe_strings(list(conditions) + path_conditions),
                        parser_locations=_dedupe_strings(path_locations + [loc]),
                    )
                    if lin.conditions:
                        lin = lin.with_status("conditional")
                else:
                    lin = Lineage(
                        status="unresolved",
                        sources=[
                            SourceRef(
                                kind="unknown",
                                source_token=source,
                                expression=source,
                                details=capture_upstream_details(source_lineages[0].sources if source_lineages else []),
                            )
                        ],
                        expression=str(token),
                        conditions=_dedupe_strings(list(conditions) + path_conditions),
                        parser_locations=_dedupe_strings(path_locations + [loc]),
                        notes=["XML source token was not resolved."],
                        taints=list(source_lineages[0].taints) if source_lineages else [],
                    )
                captured_tokens.setdefault(str(token), []).append(lin)
        for token, captures in captured_tokens.items():
            self._extractor_assign(token, captures, state)
        if not xpath_values:
            warning = no_xpath_mappings_warning(loc_base)
            state.add_warning(warning, code="missing_xpath_mappings", message=warning, parser_location=loc_base)

    def _normalize_xpath_template(
        self, xpath: str, state: AnalyzerState, conditions: list[str], line: int
    ) -> tuple[str, list[str], list[str]]:
        """Normalize XPath templates containing parser token refs.

        SecOps XML loop examples use paths such as
        ``/HOST[%{index}]/IP``. For reverse lineage this is more useful as a
        deterministic symbolic path ``/HOST[*]/IP`` plus the loop condition(s)
        carried by ``index``.
        """
        loc = _location(line, "xml.xpath.template", xpath)
        refs = _TOKEN_REF_RE.findall(xpath)
        if not refs:
            return xpath, [], []
        out = xpath
        all_conditions: list[str] = []
        all_locations: list[str] = []
        for ref in refs:
            ref_name = _strip_ref(ref)
            for lin in cast(_ExtractorContext, self)._resolve_token(ref_name, state, loc):
                all_conditions.extend(lin.conditions)
                all_locations.extend(lin.parser_locations)
            # Replace full bracketed index first, then any remaining placeholder.
            out = out.replace(f"[%{{{ref}}}]", "[*]")
            out = out.replace(f"%{{{ref}}}", "*")
        return out, _dedupe_strings(all_conditions), _dedupe_strings(all_locations)

    def _exec_kv(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        source_raw = self._first_config_value(stmt, state, "source", "message")
        config = self._validate_config_model(stmt, state, KvPluginConfig, {"source": source_raw})
        source = config.source if config is not None else str(source_raw)
        loc = _location(stmt.line, "kv", f"source={source}")
        if config is None:
            _source_lineages, source_resolved = self._invalid_config_source_lineage(source, state, loc)
        else:
            _source_lineages, source_resolved = self._resolve_extractor_source("kv", source, state, loc)
        state.add_extraction_hint(
            "kv",
            ExtractionHint(
                "kv",
                source,
                kv_extraction_details(stmt.config, stmt.line),
                conditions=list(conditions),
                parser_locations=[loc],
                source_resolved=source_resolved,
            ),
        )

    def _exec_csv(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        source_raw = self._first_config_value(stmt, state, "source", "message")
        separator_raw = self._first_config_value(stmt, state, "separator", ",")
        columns_raw = self._first_config_value(stmt, state, "columns")
        config = self._validate_config_model(
            stmt, state, CsvPluginConfig, {"source": source_raw, "separator": separator_raw, "columns": columns_raw}
        )
        source = config.source if config is not None else str(source_raw)
        separator = (
            config.separator if config is not None else (separator_raw if isinstance(separator_raw, str) else ",")
        )
        columns = (
            config.columns
            if config is not None
            else (
                columns_raw if isinstance(columns_raw, list) and all(isinstance(c, str) for c in columns_raw) else None
            )
        )
        columns_details = cast(ConfigValue, columns) if columns is not None else None
        loc = _location(stmt.line, "csv", f"source={source}")
        if config is None:
            source_lineages, source_resolved = self._invalid_config_source_lineage(source, state, loc)
        else:
            source_lineages, source_resolved = self._resolve_extractor_source("csv", source, state, loc)
        state.add_extraction_hint(
            "csv",
            ExtractionHint(
                "csv",
                source,
                csv_extraction_details(separator, columns_details, stmt.line),
                conditions=list(conditions),
                parser_locations=[loc],
                source_resolved=source_resolved,
            ),
        )
        if isinstance(columns, list):
            for idx, col_name in enumerate(columns, start=1):
                if not col_name or not isinstance(col_name, str):
                    continue
                status: LineageStatus = "conditional" if conditions else "exact"
                sources = [
                    SourceRef(
                        kind="csv_column",
                        source_token=source,
                        column=idx,
                        details=csv_column_details(separator, col_name),
                    )
                ]
                notes: list[str] = []
                if not source_resolved:
                    status = "unresolved"
                    sources = [
                        SourceRef(
                            kind="unknown",
                            source_token=source,
                            expression=source,
                            details=capture_upstream_details(source_lineages[0].sources if source_lineages else []),
                        )
                    ]
                    notes = ["CSV source token was not resolved."]
                    taints = list(source_lineages[0].taints) if source_lineages else []
                else:
                    taints = []
                lin = Lineage(
                    status=status,
                    sources=sources,
                    expression=col_name,
                    conditions=list(conditions),
                    parser_locations=[_location(stmt.line, "csv.column", f"{col_name}=column{idx}")],
                    notes=notes,
                    taints=taints,
                )
                self._extractor_assign(col_name, [lin], state)

    def _exec_grok(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        match_values = all_values(stmt.config, "match")
        pattern_definitions = all_values(stmt.config, "pattern_definitions")
        self._validate_config_model(
            stmt, state, GrokPluginConfig, {"match": match_values, "pattern_definitions": pattern_definitions}
        )
        loc = _location(stmt.line, "grok.match")

        # Build the effective grok library for this call: the bundled
        # Logstash legacy patterns merged with any inline ``pattern_definitions``
        # the parser supplied. ``self.grok_library`` is set by ``ReverseParser``
        # and may itself include user-supplied patterns from
        # ``--grok-patterns-dir``. Inline ``pattern_definitions`` win on
        # conflicts, matching upstream Logstash semantics.
        effective_library = getattr(self, "grok_library", None)
        user_pattern_names: list[str] = []
        # Track entries we couldn't lift into the library because they
        # weren't plain string→string pairs (e.g. a non-string body, or
        # a nested map). These are tainted alongside any expansion
        # failures — silently dropping them would let the resolver
        # report ``exact_capture`` for grok rules whose effective
        # pattern set we never actually modeled.
        malformed_pattern_entries: list[str] = []
        if pattern_definitions:
            user_patterns: dict[str, str] = {}
            for value in pattern_definitions:
                for k, v in as_pairs(value):
                    if isinstance(k, str) and isinstance(v, str):
                        user_patterns[k] = v
                    else:
                        # Use the key (or its repr) for diagnostics so
                        # the user can find the offending entry.
                        malformed_pattern_entries.append(str(k) if k is not None else "<unnamed>")
            if user_patterns:
                user_pattern_names = list(user_patterns)
                user_lib = GrokLibrary(user_patterns)
                effective_library = effective_library.merge(user_lib) if effective_library is not None else user_lib

        # PR-B taint downgrade: pre-resolver, every ``pattern_definitions``
        # block was tainted as symbolic. With the resolver in place we only
        # taint when expansion of a user-defined pattern actually fails —
        # i.e. when the analyzer truly cannot reason about the user's body
        # (cycle, depth bound, byte bound, or unresolved sub-reference) —
        # OR when an entry was malformed and couldn't be lifted into the
        # library at all. Sound on both sides: a clean expansion can only
        # improve downstream reasoning; a failed expansion or malformed
        # entry preserves prior behavior.
        unresolved_names: list[str] = list(malformed_pattern_entries)
        if user_pattern_names:
            unresolved_names.extend(n for n in user_pattern_names if expand_pattern(n, effective_library) is None)
        if unresolved_names:
            unresolved_desc = ", ".join(sorted(set(unresolved_names)))
            warning = static_limit_warning(loc, f"grok pattern_definitions: {unresolved_desc}")
            state.add_warning(warning, code="grok_pattern_definitions", message=warning, parser_location=loc)
            state.add_taint(
                "grok_pattern_definitions",
                f"grok pattern_definitions are symbolic: {unresolved_desc}",
                loc,
            )
        for match in match_values:
            captured_tokens: dict[str, list[Lineage]] = {}
            for source_token, patterns in as_pairs(match):
                pattern_list = patterns if isinstance(patterns, list) else [patterns]
                for pattern in pattern_list:
                    if not isinstance(pattern, str):
                        continue
                    self._extract_grok_captures(
                        str(source_token),
                        pattern,
                        stmt.line,
                        state,
                        conditions,
                        captured_tokens,
                        effective_library,
                    )
            for token, captures in captured_tokens.items():
                self._extractor_assign(token, captures, state)
        if not match_values:
            warning = no_grok_match_warning(loc)
            state.add_warning(warning, code="missing_grok_match", message=warning, parser_location=loc)

    def _extract_grok_captures(
        self,
        source_token: str,
        pattern: str,
        line: int,
        state: AnalyzerState,
        conditions: list[str],
        captured_tokens: dict[str, list[Lineage]],
        library: GrokLibrary | None,
    ) -> None:
        loc = _location(line, "grok.capture", f"source={source_token}")
        source_lineages, _source_resolved = self._resolve_extractor_source("grok", source_token, state, loc)
        # Track tokens already visited *in this single grok call* so a
        # later alternative for the same token doesn't paper over an
        # earlier oversize/trivial alternative. Without this, a pattern
        # like ``%{HUGE:x}|%{IP:x}`` would invalidate on iter 1 (HUGE
        # oversize, no constraint added), then iter 2 (IP) would see
        # ``had_prior=False`` and synthesize an IP-only constraint —
        # but runtime ``x`` could have come from the HUGE alternative.
        # Treating "already visited this call" as a prior preserves the
        # disjunctive-runtime drop-both rule across alternation.
        seen_tokens_this_call: set[str] = set()
        for m in _GROK_NAMED_RE.finditer(pattern):
            token = m.group("token")
            if not token:
                continue
            fragment = m.group(0)
            pattern_name = m.group("pattern")
            resolved_body = expand_pattern(pattern_name, library) if library is not None else None
            # PR-C (F2 algebra wiring): synthesize an implicit constraint
            # for the captured field so downstream contradiction reasoning
            # can leverage the resolved-body shape. Skipped for trivial
            # bodies (``.*`` family) — they constrain nothing and would
            # only bloat the cache key. Skipped for bodies that exceed
            # the algebra's body cap — the resulting condition would be
            # parsed but the algebra would return UNKNOWN, which is
            # sound but wasteful.
            #
            # Re-grok soundness: when a token already has a prior
            # implicit constraint (from an earlier grok call or another
            # capture in this same pattern), the runtime value is
            # *disjunctive* — ``tok`` got its value from whichever grok
            # actually matched, not both. Conjuncting both bodies in the
            # algebra falsely flags valid literals as unreachable.
            # Keeping only the latest is *also* unsound (the earlier
            # grok could have been the one that matched). Drop both and
            # let the algebra fall back to UNKNOWN-as-compatible.
            #
            # Invalidation MUST fire whenever a re-grok happens to
            # ``tok`` — even when synthesis is skipped (oversize body,
            # trivial body, invalid token chars, library miss). The new
            # grok call overwrites ``tok``'s value, so any prior
            # constraint describing the *previous* shape is now stale.
            # If we invalidated only on synthesis success, an
            # oversize-body re-grok would silently retain the stale
            # constraint and the algebra could falsely flag valid
            # literals as contradictory. ``had_prior`` is captured
            # *before* invalidation so the disjunctive-runtime rule
            # below ("don't replace; let UNKNOWN reign") still fires
            # correctly when the second grok's body is also synthesizable.
            had_prior = state.has_implicit_path_condition_for_token(token) or token in seen_tokens_this_call
            state.invalidate_implicit_path_conditions_for_token(token)
            seen_tokens_this_call.add(token)
            if resolved_body and not _is_trivial_grok_body(resolved_body):
                implicit = _synthesize_implicit_grok_condition(token, resolved_body)
                if implicit is not None and not had_prior:
                    state.add_implicit_path_condition(implicit)
            captured_tokens.setdefault(token, []).extend(
                self._capture_lineages(
                    "grok_capture",
                    source_token,
                    token,
                    fragment,
                    source_lineages,
                    loc,
                    conditions,
                    pattern_name=pattern_name,
                    resolved_body=resolved_body,
                )
            )
        for m in _REGEX_NAMED_RE.finditer(pattern):
            token = m.group("token")
            fragment = pattern[max(0, m.start() - 20) : min(len(pattern), m.end() + 80)]
            captured_tokens.setdefault(token, []).extend(
                self._capture_lineages("regex_capture", source_token, token, fragment, source_lineages, loc, conditions)
            )

    def _capture_lineages(
        self,
        kind: str,
        source_token: str,
        capture_name: str,
        pattern: str,
        source_lineages: list[Lineage],
        loc: str,
        conditions: list[str],
        *,
        pattern_name: str | None = None,
        resolved_body: str | None = None,
    ) -> list[Lineage]:
        out: list[Lineage] = []
        outer_conditions = _dedupe_strings(conditions) if conditions else []
        for source_lin in source_lineages:
            if not source_lin.conditions:
                capture_conditions = list(outer_conditions)
            elif not outer_conditions:
                capture_conditions = _dedupe_strings(source_lin.conditions)
            else:
                capture_conditions = _dedupe_strings(list(source_lin.conditions) + outer_conditions)
            status: LineageStatus
            if source_lin.status == "unresolved":
                status = "unresolved"
            elif source_lin.status == "dynamic":
                status = "dynamic"
            else:
                status = "conditional" if capture_conditions else "exact_capture"
            source_locations = source_lin.parser_locations
            if not source_locations:
                parser_locations = [loc]
            elif loc in source_locations:
                parser_locations = _dedupe_strings(source_locations)
            else:
                parser_locations = _dedupe_strings(list(source_locations) + [loc])
            details = (
                grok_capture_details(source_lin.sources, pattern_name, resolved_body)
                if pattern_name is not None
                else capture_upstream_details(source_lin.sources)
            )
            out.append(
                Lineage(
                    status=status,
                    sources=[
                        SourceRef(
                            kind=kind,
                            source_token=source_token,
                            capture_name=capture_name,
                            pattern=pattern,
                            details=details,
                        )
                    ],
                    expression=capture_name,
                    transformations=list(source_lin.transformations),
                    conditions=capture_conditions,
                    parser_locations=parser_locations,
                    notes=list(source_lin.notes),
                    taints=list(source_lin.taints),
                )
            )
        return _dedupe_lineages(out)

    def _extract_dissect_fields(
        self, source_token: str, pattern: str, line: int, state: AnalyzerState, conditions: list[str]
    ) -> None:
        loc = _location(line, "dissect.capture", f"source={source_token}")
        source_lineages, _source_resolved = self._resolve_extractor_source("dissect", source_token, state, loc)
        append_lineages: dict[str, list[Lineage]] = {}
        for m in _DISSECT_FIELD_RE.finditer(pattern):
            raw_name = m.group("raw").strip()
            if not raw_name:
                continue
            # Logstash dissect supports prefixes such as ? for skipped fields,
            # + for append, and & for indirect fields. Keep append/indirect names
            # but ignore skipped placeholders.
            if raw_name.startswith("?"):
                continue
            if raw_name.startswith("&"):
                key_token = raw_name[1:].split("->", 1)[0].split(":", 1)[0].strip()
                warning = dissect_indirect_warning(loc, key_token)
                state.add_warning(
                    warning, code="dissect_indirect", message=warning, parser_location=loc, source_token=key_token
                )
                state.add_taint(
                    "dissect_indirect", f"dissect indirect field &{{{key_token}}} is runtime-named", loc, key_token
                )
                continue
            is_append = raw_name.startswith("+")
            token = raw_name.lstrip("+&")
            token = token.split("->", 1)[0].strip()
            token = token.split(":", 1)[0].strip()
            if not token:
                continue
            fragment = m.group(0)
            captures = self._capture_lineages(
                "dissect_field", source_token, token, fragment, source_lineages, loc, conditions
            )
            if is_append:
                append_lineages.setdefault(token, []).extend(captures)
                continue
            self._extractor_assign(token, captures, state)
        for token, captures in append_lineages.items():
            self._extractor_assign(token, [self._dissect_append_lineage(token, captures, loc, conditions)], state)

    def _dissect_append_lineage(self, token: str, captures: list[Lineage], loc: str, conditions: list[str]) -> Lineage:
        sources: list[SourceRef] = []
        transformations: list[str] = []
        notes: list[str] = ["Dissect append field assembled from multiple placeholders."]
        taints: list[TaintReason] = []
        upstream_conditions: list[str] = list(conditions)
        upstream_locations: list[str] = [loc]
        status: LineageStatus = "derived"
        for lin in captures:
            sources.extend(lin.sources)
            transformations.extend(lin.transformations)
            notes.extend(lin.notes)
            taints.extend(lin.taints)
            upstream_conditions.extend(lin.conditions)
            upstream_locations.extend(lin.parser_locations)
            if lin.status == "unresolved":
                status = "unresolved"
            elif lin.status == "dynamic" and status != "unresolved":
                status = "dynamic"
        return Lineage(
            status=status,
            sources=sources,
            expression=token,
            transformations=_dedupe_strings(transformations + ["dissect_append"]),
            conditions=_dedupe_strings(upstream_conditions),
            parser_locations=_dedupe_strings(upstream_locations),
            notes=_dedupe_strings(notes),
            taints=taints,
        )

    def _exec_dissect(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Extract symbolic fields from simple dissect mappings.

        This is a static approximation. It recognises mapping/match bodies such
        as ``mapping => { "message" => "%{src} %{dst}" }`` and records each
        dissect field as a capture-like source from the mapped input token.
        """
        mapping_raw = all_values(stmt.config, "mapping")
        match_raw = all_values(stmt.config, "match")
        mapping_values = mapping_raw or match_raw
        self._validate_config_model(stmt, state, DissectPluginConfig, {"mapping": mapping_raw, "match": match_raw})
        loc = _location(stmt.line, "dissect")
        if not mapping_values:
            warning = no_dissect_mapping_warning(loc)
            state.add_warning(warning, code="missing_dissect_mapping", message=warning, parser_location=loc)
            return
        for mapping in mapping_values:
            for source_token, pattern in as_pairs(mapping):
                if not isinstance(pattern, str):
                    continue
                self._extract_dissect_fields(str(source_token), pattern, stmt.line, state, conditions)
