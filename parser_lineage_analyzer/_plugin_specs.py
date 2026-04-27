"""Compatibility metadata for built-in parser plugins."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, cast

from ._plugin_config_models import (
    Base64PluginConfig,
    CsvPluginConfig,
    DatePluginConfig,
    DissectPluginConfig,
    GrokPluginConfig,
    JsonPluginConfig,
    KvPluginConfig,
    UrlDecodePluginConfig,
    XmlPluginConfig,
)

ParserDialect = Literal["secops", "logstash"]
PluginSemanticClass = Literal["extractor", "enricher", "transform", "mutate_like", "passthrough"]
DestinationValueKind = Literal["scalar", "map", "list"]
TaintHint = Literal["none", "derived", "dynamic"]
GENERIC_TRANSFORM_SOURCE_KEYS = ("source", "field", "fields")
GENERIC_TRANSFORM_DEST_KEYS = ("target",)


@dataclass(frozen=True, slots=True)
class DialectProfile:
    name: ParserDialect
    mutate_canonical_order_default: bool
    supports_on_error_blocks: bool
    default_failure_tags_enabled: bool
    warn_unknown_config_keys: bool
    statedump_is_terminal: bool
    io_anchor_mode: Literal["secops", "logstash"]


DIALECT_PROFILES: dict[ParserDialect, DialectProfile] = {
    "secops": DialectProfile(
        name="secops",
        mutate_canonical_order_default=False,
        supports_on_error_blocks=True,
        default_failure_tags_enabled=False,
        warn_unknown_config_keys=True,
        statedump_is_terminal=True,
        io_anchor_mode="secops",
    ),
    "logstash": DialectProfile(
        name="logstash",
        mutate_canonical_order_default=True,
        supports_on_error_blocks=False,
        default_failure_tags_enabled=True,
        warn_unknown_config_keys=True,
        statedump_is_terminal=False,
        io_anchor_mode="logstash",
    ),
}

COMMON_IGNORED_CONFIG_KEYS = frozenset(
    {
        "add_field",
        "add_tag",
        "enable_metric",
        "id",
        "on_error",
        "periodic_flush",
        "remove_field",
        "remove_tag",
        "tag_on_failure",
        "tag_on_timeout",
        "timeout_millis",
    }
)


@dataclass(frozen=True, slots=True)
class PluginSpec:
    handler_name: str
    dialects: tuple[ParserDialect, ...] = ("secops", "logstash")
    config_model: type[object] | None = None
    semantic_class: PluginSemanticClass = "passthrough"
    source_keys: tuple[str, ...] = ()
    dest_keys: tuple[str, ...] = ()
    dest_value_kind: DestinationValueKind = "scalar"
    taint_hint: TaintHint = "none"
    runtime_notes: tuple[str, ...] = ()
    ignored_config_keys: frozenset[str] = field(default_factory=frozenset)
    default_failure_tags: tuple[str, ...] = ()
    default_timeout_tags: tuple[str, ...] = ()
    apply_decorators: bool = False
    symbolic_failure_routing: bool = False

    def ignores_config_key(self, key: str) -> bool:
        return key in COMMON_IGNORED_CONFIG_KEYS or key in self.ignored_config_keys


PLUGIN_SPECS: dict[str, PluginSpec] = {
    "mutate": PluginSpec("_exec_mutate", semantic_class="mutate_like"),
    "json": PluginSpec(
        "_exec_json",
        config_model=JsonPluginConfig,
        semantic_class="extractor",
        source_keys=("source",),
        dest_keys=("target",),
        ignored_config_keys=frozenset({"fallback", "skip_on_invalid_json"}),
        default_failure_tags=("_jsonparsefailure",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "xml": PluginSpec(
        "_exec_xml",
        config_model=XmlPluginConfig,
        semantic_class="extractor",
        source_keys=("source",),
        dest_keys=("target",),
        ignored_config_keys=frozenset({"force_array", "parse_options", "remove_namespaces", "store_xml", "target"}),
        default_failure_tags=("_xmlparsefailure",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "kv": PluginSpec(
        "_exec_kv",
        config_model=KvPluginConfig,
        semantic_class="extractor",
        source_keys=("source",),
        dest_keys=("target",),
        ignored_config_keys=frozenset(
            {
                "allow_empty_values",
                "default_keys",
                "exclude_keys",
                "field_split_pattern",
                "include_brackets",
                "include_keys",
                "recursive",
                "target",
                "transform_key",
                "transform_value",
                "value_split_pattern",
                "whitespace_strict",
            }
        ),
        default_failure_tags=("_kvparsefailure",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "csv": PluginSpec(
        "_exec_csv",
        config_model=CsvPluginConfig,
        semantic_class="extractor",
        source_keys=("source",),
        dest_keys=("target",),
        ignored_config_keys=frozenset(
            {
                "autodetect_column_names",
                "autogenerate_column_names",
                "convert",
                "quote_char",
                "skip_empty_columns",
                "skip_empty_rows",
                "skip_header",
                "target",
            }
        ),
        default_failure_tags=("_csvparsefailure",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "grok": PluginSpec(
        "_exec_grok",
        config_model=GrokPluginConfig,
        semantic_class="extractor",
        source_keys=("match", "source"),
        dest_keys=("target",),
        ignored_config_keys=frozenset(
            {
                "break_on_match",
                "keep_empty_captures",
                "named_captures_only",
                "overwrite",
                "source",
                "target",
            }
        ),
        default_failure_tags=("_grokparsefailure",),
        default_timeout_tags=("_groktimeout",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "date": PluginSpec(
        "_exec_date",
        config_model=DatePluginConfig,
        semantic_class="transform",
        source_keys=("match", "timezone"),
        dest_keys=("target",),
        ignored_config_keys=frozenset({"locale", "match", "target", "timezone"}),
        default_failure_tags=("_dateparsefailure",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "base64": PluginSpec(
        "_exec_base64",
        config_model=Base64PluginConfig,
        semantic_class="transform",
        source_keys=("source", "field", "fields"),
        dest_keys=("target",),
        ignored_config_keys=frozenset({"action"}),
        apply_decorators=True,
    ),
    "url_decode": PluginSpec(
        "_exec_url_decode",
        config_model=UrlDecodePluginConfig,
        semantic_class="transform",
        source_keys=("source", "field", "fields"),
        dest_keys=("target",),
        apply_decorators=True,
    ),
    "syslog_pri": PluginSpec(
        "_exec_syslog_pri",
        semantic_class="transform",
        source_keys=("source",),
        apply_decorators=True,
    ),
    "dissect": PluginSpec(
        "_exec_dissect",
        config_model=DissectPluginConfig,
        semantic_class="extractor",
        source_keys=("mapping", "match"),
        ignored_config_keys=frozenset({"append_separator", "convert_datatype"}),
        default_failure_tags=("_dissectfailure",),
        apply_decorators=True,
        symbolic_failure_routing=True,
    ),
    "on_error": PluginSpec(
        "_exec_on_error_block",
        dialects=("secops",),
        runtime_notes=("SecOps-only fallback block",),
    ),
    "ruby": PluginSpec(
        "_exec_ruby",
        semantic_class="transform",
        taint_hint="dynamic",
        ignored_config_keys=frozenset({"code", "init", "path", "script_params"}),
        runtime_notes=("Ruby is modeled by conservative event API patterns only",),
    ),
    "translate": PluginSpec(
        "_exec_translate",
        semantic_class="transform",
        source_keys=("field", "source"),
        dest_keys=("destination", "target"),
        ignored_config_keys=frozenset(
            {
                "destination",
                "dictionary",
                "dictionary_path",
                "exact",
                "fallback",
                "field",
                "iterate_on",
                "override",
                "refresh_behaviour",
                "refresh_interval",
                "regex",
                "source",
                "target",
                "yaml_dictionary_code_point_limit",
            }
        ),
    ),
    "aggregate": PluginSpec(
        "_exec_aggregate",
        semantic_class="transform",
        source_keys=("task_id",),
        taint_hint="dynamic",
        ignored_config_keys=frozenset(
            {
                "aggregate_maps_path",
                "code",
                "end_of_task",
                "inactivity_timeout",
                "map_action",
                "push_map_as_event_on_timeout",
                "push_previous_map_as_event",
                "task_id",
                "timeout",
                "timeout_code",
                "timeout_tags",
            }
        ),
    ),
    "clone": PluginSpec("_exec_clone", semantic_class="mutate_like", dest_keys=("clones",)),
    "useragent": PluginSpec(
        "_exec_useragent",
        semantic_class="enricher",
        source_keys=("source",),
        dest_keys=("target", "prefix"),
        ignored_config_keys=frozenset(
            {"cache_size", "ecs_compatibility", "lru_cache_size", "prefix", "source", "target"}
        ),
    ),
    "geoip": PluginSpec(
        "_exec_geoip",
        semantic_class="enricher",
        source_keys=("source",),
        dest_keys=("target",),
        ignored_config_keys=frozenset(
            {"database", "default_database_type", "ecs_compatibility", "fields", "source", "target"}
        ),
    ),
    "cidr": PluginSpec("_exec_generic_plugin", semantic_class="enricher", taint_hint="dynamic"),
    "mac": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "math": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "extractnumbers": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "tld": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "cipher": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "anonymize": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "fingerprint": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "urldecode": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "bytes": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "i18n": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "alter": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "truncate": PluginSpec(
        "_exec_generic_transform",
        semantic_class="transform",
        source_keys=GENERIC_TRANSFORM_SOURCE_KEYS,
        dest_keys=GENERIC_TRANSFORM_DEST_KEYS,
    ),
    "elapsed": PluginSpec("_exec_elapsed", semantic_class="transform"),
    "uuid": PluginSpec("_exec_uuid", semantic_class="transform"),
    "dns": PluginSpec("_exec_dns", semantic_class="enricher", taint_hint="dynamic"),
    "prune": PluginSpec("_exec_prune", semantic_class="mutate_like", taint_hint="dynamic"),
    "split": PluginSpec(
        "_exec_split",
        semantic_class="mutate_like",
        source_keys=("field",),
        dest_keys=("target",),
    ),
    "elasticsearch": PluginSpec(
        "_exec_external_lookup",
        dialects=("logstash",),
        semantic_class="enricher",
        source_keys=("query", "statement", "url"),
        dest_keys=("target", "get", "fields"),
        dest_value_kind="map",
        taint_hint="dynamic",
        ignored_config_keys=frozenset(
            {
                "aggregation_fields",
                "docinfo_fields",
                "enable_sort",
                "fields",
                "get",
                "hosts",
                "index",
                "query",
                "result_size",
                "sort",
                "target",
                "user",
            }
        ),
    ),
    "memcached": PluginSpec(
        "_exec_external_lookup",
        dialects=("logstash",),
        semantic_class="enricher",
        dest_keys=("target", "get"),
        dest_value_kind="map",
        taint_hint="dynamic",
        ignored_config_keys=frozenset({"get", "hosts", "namespace", "target", "ttl"}),
    ),
    "jdbc_streaming": PluginSpec(
        "_exec_external_lookup",
        dialects=("logstash",),
        semantic_class="enricher",
        source_keys=("statement",),
        dest_keys=("target",),
        taint_hint="dynamic",
        ignored_config_keys=frozenset(
            {
                "jdbc_driver_class",
                "jdbc_driver_library",
                "jdbc_password",
                "jdbc_user",
                "parameters",
                "statement",
                "target",
                "use_cache",
            }
        ),
    ),
    "http": PluginSpec(
        "_exec_external_lookup",
        dialects=("logstash",),
        semantic_class="enricher",
        source_keys=("url",),
        dest_keys=("target",),
        taint_hint="dynamic",
        ignored_config_keys=frozenset({"body", "headers", "method", "target", "url", "verb"}),
    ),
    "rest": PluginSpec(
        "_exec_external_lookup",
        dialects=("logstash",),
        semantic_class="enricher",
        source_keys=("url",),
        dest_keys=("target",),
        taint_hint="dynamic",
        ignored_config_keys=frozenset({"body", "headers", "method", "target", "url", "verb"}),
    ),
    "acme_threat_lookup": PluginSpec(
        "_exec_external_lookup",
        dialects=("logstash",),
        semantic_class="enricher",
        dest_keys=("target",),
        taint_hint="dynamic",
    ),
}


def normalize_dialect(dialect: str) -> ParserDialect:
    if dialect not in {"secops", "logstash"}:
        raise ValueError(f"dialect must be 'secops' or 'logstash', got {dialect!r}")
    return cast(ParserDialect, dialect)


def dialect_profile_for(dialect: str) -> DialectProfile:
    return DIALECT_PROFILES[normalize_dialect(dialect)]


def plugin_spec_for(name: str) -> PluginSpec | None:
    return PLUGIN_SPECS.get(name)


def config_key_is_ignored(plugin_name: str, key: str) -> bool:
    spec = plugin_spec_for(plugin_name)
    if spec is not None:
        return spec.ignores_config_key(key)
    return key in COMMON_IGNORED_CONFIG_KEYS


__all__ = [
    "COMMON_IGNORED_CONFIG_KEYS",
    "DIALECT_PROFILES",
    "DestinationValueKind",
    "DialectProfile",
    "PLUGIN_SPECS",
    "ParserDialect",
    "PluginSemanticClass",
    "PluginSpec",
    "TaintHint",
    "config_key_is_ignored",
    "dialect_profile_for",
    "normalize_dialect",
    "plugin_spec_for",
]
