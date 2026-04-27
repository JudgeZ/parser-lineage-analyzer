"""Transform plugin handlers for reverse-lineage analysis."""

from __future__ import annotations

from typing import Protocol, TypeVar, cast

from pydantic import BaseModel, ValidationError

from ._analysis_diagnostics import (
    config_validation_warning,
    duplicate_config_key_warning,
    no_match_array_warning,
    no_source_field_warning,
    static_limit_warning,
    unknown_config_key_warning,
)
from ._analysis_helpers import _add_conditions, _flatten_scalars, _location, _normalize_field_ref
from ._analysis_state import AnalyzerState
from ._plugin_config_models import Base64PluginConfig, DatePluginConfig, UrlDecodePluginConfig, compact_validation_error
from ._plugin_specs import config_key_is_ignored
from ._types import ConfigValue
from .ast_nodes import Plugin
from .config_parser import all_values, as_pairs
from .model import Lineage, SourceRef

DefaultValue = TypeVar("DefaultValue")
ModelT = TypeVar("ModelT", bound=BaseModel)

# T4.1: cap on the number of distinct integer-PRI alternatives that
# ``_exec_syslog_pri`` will materialize as concrete-label lineages. Past the
# cap the source is treated as dynamic so the symbolic path runs and we don't
# emit hundreds of lineages from a pathological add_field/elif chain.
MAX_SYSLOG_PRI_BRANCHES = 32


class _TransformContext(Protocol):
    def _resolve_token(self, token: str, state: AnalyzerState, loc: str) -> list[Lineage]: ...

    def _store_destination(
        self, dest: str, lineages: list[Lineage], loc: str, state: AnalyzerState, *, append: bool = False
    ) -> None: ...


class TransformPluginMixin:
    def _first_transform_config_value(
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

    def _validate_transform_config_model(
        self, stmt: Plugin, state: AnalyzerState, model_cls: type[ModelT], data: dict[str, object]
    ) -> ModelT | None:
        validation_data = dict(data)
        for key, value in stmt.config:
            if str(key) == "on_error":
                continue
            if str(key) not in validation_data:
                if config_key_is_ignored(stmt.name, str(key)):
                    continue
                validation_data[str(key)] = value
        try:
            return model_cls.model_validate(validation_data)
        except ValidationError as exc:
            extra_errors = [err for err in exc.errors() if err.get("type") == "extra_forbidden"]
            for err in extra_errors:
                key = ".".join(str(part) for part in err.get("loc", ())) or "config"
                if config_key_is_ignored(stmt.name, key):
                    continue
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

    def _exec_date(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        context = cast(_TransformContext, self)
        match_raw = self._first_transform_config_value(stmt, state, "match")
        target_raw = self._first_transform_config_value(
            stmt, state, "target", "event.idm.read_only_udm.metadata.event_timestamp"
        )
        timezone_raw = self._first_transform_config_value(stmt, state, "timezone")
        locale_raw = self._first_transform_config_value(stmt, state, "locale")
        config = self._validate_transform_config_model(
            stmt,
            state,
            DatePluginConfig,
            {"match": match_raw, "target": target_raw, "timezone": timezone_raw, "locale": locale_raw},
        )
        match_is_map = isinstance(match_raw, list) and bool(as_pairs(match_raw))
        match = (
            None
            if match_is_map
            else (config.match if config is not None else (match_raw if isinstance(match_raw, list) else None))
        )
        target = (
            config.target
            if config is not None
            else (target_raw if isinstance(target_raw, str) else "event.idm.read_only_udm.metadata.event_timestamp")
        )
        timezone = config.timezone if config is not None else (timezone_raw if isinstance(timezone_raw, str) else None)
        locale = config.locale if config is not None else (locale_raw if isinstance(locale_raw, str) else None)
        loc = _location(stmt.line, "date", f"target={target}")
        if "%{" in str(target):
            warning = static_limit_warning(loc, f"dynamic date target {target}")
            state.add_warning(warning, code="dynamic_date_target", message=warning, parser_location=loc)
            state.add_taint("dynamic_date_target", f"date target {target!r} is runtime-dependent", loc)
        if timezone is not None and "%{" in str(timezone):
            warning = static_limit_warning(loc, f"dynamic date timezone {timezone}")
            state.add_warning(warning, code="dynamic_date_timezone", message=warning, parser_location=loc)
            state.add_taint("dynamic_date_timezone", f"date timezone {timezone!r} is runtime-dependent", loc)
        if isinstance(match, list) and match:
            source_token = str(match[0])
            formats = [str(x) for x in _flatten_scalars(match[1:])]
            transforms = [f"date({', '.join(formats)})"]
            if timezone is not None:
                transforms.append(f"timezone({timezone})")
            if locale is not None:
                transforms.append(f"locale({locale})")
            lins = [
                lin.with_transform(" ".join(transforms), loc)
                for lin in context._resolve_token(source_token, state, loc)
            ]
            lins = _add_conditions(lins, conditions)
            context._store_destination(_normalize_field_ref(target), lins, loc, state)
        else:
            warning = no_match_array_warning(loc)
            state.add_warning(warning, code="missing_match_array", message=warning, parser_location=loc)

    def _exec_base64(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Symbolically propagate base64 decode lineage.

        The analyzer records that a value was transformed by base64
        decoding while preserving the original source provenance.
        """
        context = cast(_TransformContext, self)
        source_cfg = self._first_transform_config_value(stmt, state, "source")
        field_cfg = self._first_transform_config_value(stmt, state, "field")
        fields_cfg = self._first_transform_config_value(stmt, state, "fields")
        target_cfg = self._first_transform_config_value(stmt, state, "target")
        encoding_cfg = self._first_transform_config_value(stmt, state, "encoding", "Standard")
        config = self._validate_transform_config_model(
            stmt,
            state,
            Base64PluginConfig,
            {
                "source": source_cfg,
                "field": field_cfg,
                "fields": fields_cfg,
                "target": target_cfg,
                "encoding": encoding_cfg,
            },
        )
        if config is not None:
            source_cfg = config.source
            field_cfg = config.field
            fields_cfg = cast(ConfigValue | None, config.fields)
            target_cfg = config.target
            default_encoding = config.encoding
        else:
            source_cfg = source_cfg if isinstance(source_cfg, str) else None
            field_cfg = field_cfg if isinstance(field_cfg, str) else None
            fields_cfg = fields_cfg if isinstance(fields_cfg, (list, str)) else None
            target_cfg = target_cfg if isinstance(target_cfg, str) else None
            default_encoding = encoding_cfg if isinstance(encoding_cfg, str) else "Standard"
        operations: list[tuple[str, str, str]] = []
        loc = _location(stmt.line, "base64")
        if source_cfg is not None:
            if field_cfg is not None or fields_cfg is not None:
                warning = static_limit_warning(loc, "base64 source takes precedence over field/fields")
                state.add_warning(warning, code="base64_conflicting_fields", message=warning, parser_location=loc)
            source = str(source_cfg)
            operations.append((source, str(target_cfg) if target_cfg is not None else source, default_encoding))
        else:
            field_values: list[ConfigValue] = []
            if fields_cfg is not None and as_pairs(fields_cfg):
                for field_name, field_encoding in as_pairs(fields_cfg):
                    operations.append((str(field_name), str(field_name), str(field_encoding)))
            elif isinstance(fields_cfg, list):
                field_values.extend(cast(list[ConfigValue], fields_cfg))
            elif fields_cfg is not None:
                field_values.append(fields_cfg)
            if field_cfg is not None:
                field_values.append(field_cfg)
            operations.extend((str(f), str(f), default_encoding) for f in field_values)

        if not operations:
            warning = no_source_field_warning(loc)
            state.add_warning(warning, code="missing_source_field", message=warning, parser_location=loc)
            return
        for source, target, encoding in operations:
            op_loc = _location(stmt.line, "base64", f"{source} -> {target}")
            lins = [
                lin.with_transform(f"base64_decode(encoding={encoding})", op_loc)
                for lin in context._resolve_token(source, state, op_loc)
            ]
            context._store_destination(_normalize_field_ref(target), _add_conditions(lins, conditions), op_loc, state)

    def _exec_syslog_pri(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Resolve syslog PRI integer into severity & facility derived fields.

        Logstash's ``syslog_pri`` plugin reads ``syslog_pri_field_name`` (the
        token holding the integer PRI value) and writes two derived fields,
        ``<source>_severity`` and ``<source>_facility``. The labels come from
        configured ``severity_labels`` / ``facility_labels`` arrays.

        When the source PRI token resolves to a literal integer constant,
        the analyzer can compute the concrete severity/facility labels at
        analysis time (`facility = pri >> 3`, `severity = pri & 7`). When
        the PRI source is dynamic, the lineage stays symbolic but the
        configured label arrays are surfaced in source details so consumers
        can see the candidate label set.
        """
        context = cast(_TransformContext, self)
        source_raw = self._first_transform_config_value(stmt, state, "syslog_pri_field_name", "syslog_pri")
        source = str(source_raw) if source_raw is not None else "syslog_pri"
        sev_labels_raw = self._first_transform_config_value(stmt, state, "severity_labels")
        fac_labels_raw = self._first_transform_config_value(stmt, state, "facility_labels")
        sev_labels = [str(x) for x in sev_labels_raw] if isinstance(sev_labels_raw, list) else None
        fac_labels = [str(x) for x in fac_labels_raw] if isinstance(fac_labels_raw, list) else None
        loc = _location(stmt.line, "syslog_pri", source)
        # R4.2: validate label-array lengths. Per RFC 3164 / 5424 the syslog
        # PRI integer is 5 bits of facility (24 standard values, indices 0-23)
        # plus 3 bits of severity (8 values, indices 0-7). When configured
        # arrays don't match, out-of-bounds PRI values silently fall through
        # to the symbolic path; surface that as an explicit warning so
        # mis-configurations are caught at analysis time.
        if sev_labels is not None and len(sev_labels) != 8:
            warning = (
                f"{loc}: severity_labels has {len(sev_labels)} entries; "
                "syslog severity is a 3-bit value with exactly 8 labels. "
                "Out-of-range PRI values will produce symbolic lineage instead "
                "of concrete labels."
            )
            # "severity_labels" is the syslog plugin config-key name, not a credential.
            state.add_warning(
                warning,
                code="syslog_pri_label_count_mismatch",
                message=warning,
                parser_location=loc,
                source_token="severity_labels",  # nosec B106
            )
        if fac_labels is not None and len(fac_labels) != 24:
            warning = (
                f"{loc}: facility_labels has {len(fac_labels)} entries; "
                "syslog facility is a 5-bit value with 24 standard labels "
                "(0-23). Out-of-range PRI values will produce symbolic "
                "lineage instead of concrete labels."
            )
            # "facility_labels" is the syslog plugin config-key name, not a credential.
            state.add_warning(
                warning,
                code="syslog_pri_label_count_mismatch",
                message=warning,
                parser_location=loc,
                source_token="facility_labels",  # nosec B106
            )
        # Try to resolve the source to a literal integer for concrete-label
        # output. If the source has at least one constant lineage with an
        # integer-parseable expression, use it. Multiple constant alternatives
        # (e.g. ``if [x] { add_field => syslog_pri => "13" } else { ... "14" }``)
        # produce multiple concrete label lineages, deduplicated by integer
        # value so two branches that resolve to the same PRI don't double-emit.
        # T4.1: cap the alternatives to keep an adversarial fixture from
        # producing thousands of label lineages — beyond the cap we fall back
        # to symbolic.
        source_lineages = context._resolve_token(source, state, loc)
        literal_pris: list[int] = []
        seen_pris: set[int] = set()
        has_dynamic = False
        for lin in source_lineages:
            for src in lin.sources:
                # C5: PRI is unsigned per RFC 3164 / 5424 — facility 0-23 (5
                # bits) + severity 0-7 (3 bits) gives a valid range of 0-191.
                # The previous test ``lstrip("-").isdigit()`` accepted negative
                # literals like ``-13``, after which Python's signed bitwise
                # ops produced wrong concrete labels (e.g. ``(-13) & 7 == 3``
                # mislabeled as severity "err"). Reject anything that isn't a
                # plain non-negative integer literal in the valid range; out-of
                # -range values fall through to the symbolic path along with
                # dynamic sources.
                expression = src.expression.strip() if src.expression else ""
                if src.kind == "constant" and expression.isdigit():
                    pri = int(expression)
                    if 0 <= pri <= 191:
                        if pri not in seen_pris:
                            seen_pris.add(pri)
                            literal_pris.append(pri)
                    else:
                        has_dynamic = True
                else:
                    has_dynamic = True
        if not source_lineages:
            has_dynamic = True
        if len(literal_pris) > MAX_SYSLOG_PRI_BRANCHES:
            # Bail out conservatively: treat the source as dynamic so the
            # symbolic path runs and a single derived lineage is emitted.
            literal_pris = []
            has_dynamic = True
        for suffix, labels in (("severity", sev_labels), ("facility", fac_labels)):
            dest = f"{source}_{suffix}"
            dest_loc = _location(stmt.line, "syslog_pri", f"{source} -> {dest}")
            concrete_lins: list[Lineage] = []
            for pri in literal_pris:
                if labels is None:
                    break
                idx = (pri & 7) if suffix == "severity" else (pri >> 3)
                if 0 <= idx < len(labels):
                    label = labels[idx]
                    concrete_lins.append(
                        Lineage(
                            status="constant",
                            sources=[SourceRef(kind="constant", expression=label)],
                            expression=label,
                            transformations=[f"syslog_pri({suffix})"],
                            conditions=list(conditions),
                            parser_locations=[dest_loc],
                        )
                    )
            symbolic_lins: list[Lineage] = []
            if has_dynamic or not concrete_lins:
                symbolic_lins = [lin.with_transform(f"syslog_pri({suffix})", dest_loc) for lin in source_lineages]
                if not symbolic_lins:
                    # No source lineage at all — emit a single symbolic
                    # lineage so downstream queries see something.
                    symbolic_lins = [
                        Lineage(
                            status="derived",
                            sources=[
                                SourceRef(
                                    kind="syslog_pri",
                                    source_token=source,
                                    expression=source,
                                )
                            ],
                            expression=source,
                            transformations=[f"syslog_pri({suffix})"],
                            conditions=list(conditions),
                            parser_locations=[dest_loc],
                        )
                    ]
            context._store_destination(
                _normalize_field_ref(dest),
                _add_conditions([*concrete_lins, *symbolic_lins], conditions),
                dest_loc,
                state,
            )

    def _exec_url_decode(self, stmt: Plugin, state: AnalyzerState, conditions: list[str]) -> None:
        """Symbolically propagate URL-decoding lineage.

        SecOps parser snippets typically use ``source`` and ``target`` for this
        plugin. If ``fields`` or ``field`` is present instead, treat it as an
        in-place transform for each listed token.
        """
        context = cast(_TransformContext, self)
        loc = _location(stmt.line, "url_decode")
        source = self._first_transform_config_value(stmt, state, "source")
        target = self._first_transform_config_value(stmt, state, "target")
        fields = self._first_transform_config_value(stmt, state, "fields")
        field = self._first_transform_config_value(stmt, state, "field")
        config = self._validate_transform_config_model(
            stmt,
            state,
            UrlDecodePluginConfig,
            {"source": source, "target": target, "fields": fields, "field": field},
        )
        if config is not None:
            source = config.source
            target = config.target
            fields = cast(ConfigValue | None, config.fields)
            field = config.field
        else:
            source = source if isinstance(source, str) else None
            target = target if isinstance(target, str) else None
            fields = fields if isinstance(fields, (list, str)) else None
            field = field if isinstance(field, str) else None

        operations: list[tuple[str, str]] = []
        if source is not None:
            src = str(source)
            operations.append((src, str(target) if target is not None else src))
        else:
            field_values: list[ConfigValue] = []
            if isinstance(fields, list):
                field_values.extend(cast(list[ConfigValue], fields))
            elif fields is not None:
                field_values.append(fields)
            if field is not None:
                field_values.append(field)
            operations.extend((str(f), str(f)) for f in field_values)

        if not operations:
            warning = no_source_field_warning(loc)
            state.add_warning(warning, code="missing_source_field", message=warning, parser_location=loc)
            return

        for src, dst in operations:
            op_loc = _location(stmt.line, "url_decode", f"{src} -> {dst}")
            lins = [lin.with_transform("url_decode", op_loc) for lin in context._resolve_token(src, state, op_loc)]
            context._store_destination(_normalize_field_ref(dst), _add_conditions(lins, conditions), op_loc, state)
