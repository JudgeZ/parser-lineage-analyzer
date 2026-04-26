"""Internal diagnostic message helpers.

These helpers intentionally preserve the exact public warning/unsupported
strings emitted by the analyzer while giving call sites a single place to build
them.
"""

from __future__ import annotations

from ._analysis_helpers import _location
from .model import SyntaxDiagnostic


def unparsed_statement(line: int, text: str) -> str:
    return f"line {line}: unparsed statement: {text[:80]}"


def unsupported_plugin(line: int, name: str) -> str:
    return _location(line, f"unsupported plugin {name}")


def unsupported_mutate_operation(line: int, op: object) -> str:
    return _location(line, f"unsupported mutate operation {op}")


def drop_warning(line: int) -> str:
    return _location(line, "drop", "parser may drop events on this path")


def on_error_parse_warning(loc: str, diag: SyntaxDiagnostic) -> str:
    return (
        f"{loc}: could not parse fallback body at line {getattr(diag, 'line', '?')}, "
        f"column {getattr(diag, 'column', '?')}: {getattr(diag, 'message', diag)}"
    )


def config_parse_warning(line: int, plugin: str, diag: SyntaxDiagnostic) -> str:
    return (
        f"line {line}: {plugin} config parse failure at line {getattr(diag, 'line', '?')}, "
        f"column {getattr(diag, 'column', '?')}: {getattr(diag, 'message', diag)}"
    )


def config_validation_warning(line: int, plugin: str, detail: str) -> str:
    return f"line {line}: {plugin} config validation failure: {detail}"


def duplicate_config_key_warning(line: int, plugin: str, key: str, count: int) -> str:
    """Warning text for extractor/transform singleton config keys (use first value)."""
    return _location(
        line, plugin, f"duplicate singleton config key {key!r} appears {count} times; using the first value"
    )


def duplicate_mutate_map_key_warning(line: int, plugin: str, key: str, count: int) -> str:
    """Warning text for mutate map ops where duplicate keys are NOT first-wins.

    Mutate operations follow Logstash semantics: ``replace``/``update``/
    ``add_field``/``copy``/``rename``/``convert`` are last-write-wins on
    duplicate destination keys, while ``merge`` appends every source value.
    The previous helper (``duplicate_config_key_warning``) said "using the
    first value", which only matches singleton extractor/transform options.
    """
    return _location(
        line,
        plugin,
        (
            f"duplicate map key {key!r} appears {count} times; keeping the last value "
            f"(replace/update/add_field/copy/rename/convert) or appending all values (merge)"
        ),
    )


def noop_remove_field_warning(loc: str, field: str) -> str:
    """Warning text for ``mutate.remove_field`` targeting a token never written.

    Logstash silently ignores a remove_field for a name that the pipeline
    never wrote. The analyzer used to insert a phantom ``removed`` tombstone
    for such fields (causing the name to surface in ``list_udm_fields()`` and
    ``analysis_summary()['udm_fields']``); now the no-op is recorded as a
    structured diagnostic instead so consumers can still see it without
    polluting the UDM-field set.
    """
    return f"{loc}: remove_field target {field!r} was never written; nothing to remove"


def unknown_config_key_warning(line: int, plugin: str, key: str) -> str:
    return _location(line, plugin, f"unknown config key {key!r} ignored by static analyzer")


def dynamic_destination_warning(loc: str, dest: str) -> str:
    return (
        f"{loc}: dynamic destination field name {dest!r} cannot be resolved to concrete UDM paths without a raw event"
    )


def dynamic_output_anchor_warning(loc: str, anchor: str) -> str:
    return f"{loc}: dynamic @output anchor {anchor!r} cannot be resolved to concrete output events without a raw event"


def dynamic_field_removal_warning(loc: str) -> str:
    return f"{loc}: dynamic field removal not resolved statically"


def empty_destination_warning(loc: str) -> str:
    return f"{loc}: empty destination field name ignored"


def unresolved_bare_token_warning(loc: str, token: str) -> str:
    return f"{loc}: bare token {token!r} was not resolved; treating it as unresolved instead of a literal constant"


def malformed_gsub_warning(line: int, length: int) -> str:
    return _location(line, "mutate.gsub", f"malformed gsub array has {length} element(s); expected triples")


def loop_variables_warning(loc: str, count: int) -> str:
    return f"{loc}: loop declares {count} variables; treating variables after the first as symbolic loop items"


def json_target_warning(loc: str, target: object) -> str:
    return f"{loc}: json target must be a scalar token name; ignoring unsupported target={target!r}"


def json_source_unresolved_warning(loc: str) -> str:
    return f"{loc}: source token was not resolved; fields from this json block are not inferred as exact raw paths"


def extractor_source_unresolved_warning(loc: str) -> str:
    return f"{loc}: source token was not resolved; fields from this extractor are not inferred as exact raw paths"


def template_fanout_warning(loc: str, count: int, limit: int) -> str:
    return f"{loc}: template interpolation has {count} possible combinations; summarized as dynamic after limit {limit}"


def runtime_condition_warning(loc: str, condition: str) -> str:
    return f"{loc}: condition {condition!r} contains runtime interpolation or dynamic regex; branch lineage is symbolic"


def unreachable_branch_warning(loc: str, condition: str) -> str:
    return f"{loc}: condition {condition!r} contradicts prior literal branch facts; branch skipped"


def static_limit_warning(loc: str, feature: str) -> str:
    return f"{loc}: {feature} is not fully modeled statically; lineage is symbolic"


def no_xpath_mappings_warning(loc: str) -> str:
    return f"{loc}: no xpath mappings discovered"


def no_grok_match_warning(loc: str) -> str:
    return f"{loc}: no match mappings discovered"


def dissect_indirect_warning(loc: str, key_token: str) -> str:
    return f"{loc}: dissect indirect field &{{{key_token}}} is runtime-named; no literal token was created"


def no_dissect_mapping_warning(loc: str) -> str:
    return f"{loc}: no mapping/match pairs discovered"


def no_match_array_warning(loc: str) -> str:
    return f"{loc}: no match array discovered"


def no_source_field_warning(loc: str) -> str:
    return f"{loc}: no source/field discovered"


def long_elif_chain_warning(line: int, count: int, threshold: int) -> str:
    return (
        f"line {line}: if/else-if chain has {count} elif clauses (threshold {threshold}); "
        f"long chains are a maintenance smell — consider hash table dispatch or splitting the chain"
    )


def large_array_literal_warning(line: int, count: int, threshold: int) -> str:
    return (
        f"line {line}: array literal has {count} elements (threshold {threshold}); large literals slow lineage analysis"
    )


def regex_over_escape_warning(loc: str, pattern: str, escape: str) -> str:
    return (
        f"{loc}: regex literal {pattern!r} contains {escape!r} which matches a literal "
        f"backslash followed by '{escape[-1]}', not the metacharacter — did you mean '\\{escape[-1]}'?"
    )


def non_canonical_on_error_placement_warning(line: int, plugin: str) -> str:
    return _location(
        line,
        plugin,
        "on_error appears as a config-map key; the canonical placement is the statement-level "
        "form 'plugin { ... } on_error { ... }' — nested configs are not interpreted as fallback bodies",
    )


def ruby_concurrency_risk_warning(loc: str, var_name: str) -> str:
    return (
        f"{loc}: ruby block uses global/class variable {var_name!r}; "
        "this poses a concurrency risk in multi-worker environments"
    )


def ruby_event_split_warning(loc: str) -> str:
    return f"{loc}: ruby block contains yield or event.clone, splitting one input event into multiple output events"
