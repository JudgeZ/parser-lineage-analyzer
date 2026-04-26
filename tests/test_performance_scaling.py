import os
import time
from pathlib import Path
from typing import cast

import pytest

from parser_lineage_analyzer import CompactAnalysisSummaryDict, ReverseParser
from parser_lineage_analyzer._analysis_assignment import MAX_LITERAL_COLLECTION_LINEAGES
from parser_lineage_analyzer._analysis_state import AnalyzerState, ExtractionHint
from parser_lineage_analyzer._scanner import strip_comments_keep_offsets
from parser_lineage_analyzer.config_parser import (
    MAX_CONFIG_NESTING_DEPTH,
    clear_config_parse_cache,
    config_parse_cache_info,
    parse_config,
    parse_config_with_diagnostics,
)
from parser_lineage_analyzer.model import Lineage, QueryResult, SourceRef, TaintReason, _freeze_details
from parser_lineage_analyzer.render import render_compact_json, render_text

_NATIVE_DISABLED = os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() in {"1", "true", "yes", "on"}


def _independent_if_parser(count: int) -> str:
    lines = ["filter {", '  json { source => "message" }']
    for i in range(count):
        lines.append(f'  if [f{i}] == "1" {{')
        lines.append(
            f'    mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.k{i}" => "%{{v{i}}}" }} }}'
        )
        lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _mutate_only_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.k{i}" => "%{{v{i}}}" }} }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _dynamic_mutate_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.%{{k{i}}}" => "%{{v{i}}}" }} }}'
        )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _drop_guard_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  if [drop{i}] == "1" {{ drop {{ }} }}')
        lines.append(f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.k{i}" => "v" }} }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _else_if_chain_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        prefix = "if" if i == 0 else "} else if"
        lines.append(f'  {prefix} [action] == "{i}" {{')
        lines.append(f'    mutate {{ replace => {{ "event.idm.read_only_udm.security_result.action" => "A{i}" }} }}')
    lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _analysis_seconds(code: str) -> tuple[float, ReverseParser]:
    parser = ReverseParser(code)
    start = time.perf_counter()
    parser.analyze()
    return time.perf_counter() - start, parser


def _parse_and_analysis_seconds(code: str) -> tuple[float, ReverseParser]:
    start = time.perf_counter()
    parser = ReverseParser(code)
    parser.analyze()
    return time.perf_counter() - start, parser


def _standalone_on_error_parser(count: int, seed_count: int = 1_000) -> str:
    lines = ["filter {"]
    for i in range(seed_count):
        lines.append(f'  mutate {{ replace => {{ "seed.{i}" => "v{i}" }} }}')
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.err{i}" => "ok" }} }}')
    for i in range(count):
        lines.append("  on_error {")
        lines.append(f'    mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.err{i}" => "v" }} }}')
        lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _branch_local_metadata_parser(count: int, seed_count: int = 2_000) -> str:
    lines = ["filter {"]
    for i in range(seed_count):
        lines.append(f'  mutate {{ replace => {{ "seed.{i}" => "v{i}" }} }}')
    for i in range(count):
        lines.append(f'  if [extract{i}] == "1" {{')
        lines.append(f'    json {{ source => "message" target => "payload{i}" }}')
        lines.append('    mutate { merge => { "@output" => "event" } }')
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def _dynamic_loop_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f"  for item{i} in %{{items{i}}} {{")
        for j in range(5):
            lines.append(
                f'    mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.loop{i}_{j}" => "%{{item{i}.v{j}}}" }} }}'
            )
        lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _object_merge_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "obj{i}.child" => "v{i}" }} }}')
        lines.append(f'  mutate {{ merge => {{ "event.idm.read_only_udm.additional.fields.obj{i}" => "obj{i}" }} }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _parent_remove_rename_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "root{i}.child" => "v{i}" "keep{i}.child" => "v{i}" }} }}')
        lines.append(f'  mutate {{ remove_field => ["root{i}"] }}')
        lines.append(f'  mutate {{ rename => {{ "keep{i}" => "renamed{i}" }} }}')
    lines.append("}")
    return "\n".join(lines)


def _json_hint_reference_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  json {{ source => "message" target => "payload{i}" }}')
    for i in range(count):
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.hint{i}" => "%{{payload{i}.field}}" }} }}'
        )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _duplicate_anchor_dynamic_parser(anchor_count: int, dynamic_count: int) -> str:
    lines = ["filter {"]
    for _ in range(anchor_count):
        lines.append('  mutate { merge => { "@output" => "event" } }')
    for i in range(dynamic_count):
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.%{{k{i}}}" => "%{{v{i}}}" }} }}'
        )
    lines.append("}")
    return "\n".join(lines)


def _repeated_append_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ add_field => {{ "event.idm.read_only_udm.additional.fields.repeat" => "v{i}" }} }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _interleaved_json_hint_reference_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  json {{ source => "message" target => "payload{i}" }}')
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.hint{i}" => "%{{payload{i}.field}}" }} }}'
        )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _root_dynamic_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "%{{root{i}}}.tail{i}" => "v{i}" }} }}')
    lines.append("}")
    return "\n".join(lines)


def _unique_anchor_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ merge => {{ "@output" => "event{i}" }} }}')
    lines.append("}")
    return "\n".join(lines)


def _hot_branch_append_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  if [flag{i}] == "1" {{')
        lines.append('    mutate { add_field => { "event.idm.read_only_udm.additional.fields.repeat" => "v" } }')
        lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _explicit_else_self_rewrite_parser(count: int) -> str:
    lines = [
        "filter {",
        '  mutate { replace => { "event.idm.read_only_udm.additional.fields.x" => "seed" } }',
    ]
    for i in range(count):
        lines.append(f'  if [flag{i}] == "1" {{')
        lines.append(
            '    mutate { replace => { "event.idm.read_only_udm.additional.fields.x" => "%{event.idm.read_only_udm.additional.fields.x}" } }'
        )
        lines.append("  } else {")
        lines.append(
            '    mutate { replace => { "event.idm.read_only_udm.additional.fields.x" => "%{event.idm.read_only_udm.additional.fields.x}" } }'
        )
        lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _conditional_anchor_dynamic_parser(anchor_count: int, dynamic_count: int) -> str:
    lines = ["filter {"]
    for i in range(anchor_count):
        lines.append(f'  if [out{i}] == "1" {{ mutate {{ merge => {{ "@output" => "event" }} }} }}')
    for i in range(dynamic_count):
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.%{{k{i}}}" => "%{{v{i}}}" }} }}'
        )
    lines.append("}")
    return "\n".join(lines)


def _anchored_direct_dynamic_parser(dynamic_count: int) -> str:
    lines = [
        "filter {",
        '  mutate { replace => { "event.idm.read_only_udm.additional.fields.anything" => "direct" } }',
    ]
    for i in range(dynamic_count):
        lines.append(
            f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.%{{k{i}}}" => "%{{v{i}}}" }} }}'
        )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _comment_like_scanner_body(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        body = f'"url{i}" => "http://example.com/a//b/{i}" "xpath{i}" => {{//node{i}}}'
        lines.append(f"  mutate {{ replace => {{ {body} }} }} // trailing")
    lines.append("}")
    return "\n".join(lines)


def _comment_free_scanner_body(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  mutate {{ replace => {{ "field{i}" => "value{i}" }} }}')
    lines.append("}")
    return "\n".join(lines)


def _destination_template_fanout_parser(branches_per_ref: int) -> str:
    lines = ["filter {"]
    for name in ("a", "b", "c"):
        for i in range(branches_per_ref):
            lines.append(f'  mutate {{ add_field => {{ "{name}" => "{name}{i}" }} }}')
    lines.append('  mutate { replace => { "event.idm.read_only_udm.additional.fields.%{a}.%{b}.%{c}" => "v" } }')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _json_target_chain_parser(count: int) -> str:
    target = "payload"
    lines = ["filter {", '  mutate { replace => { "message" => "raw" } }']
    for i in range(count):
        lines.append(f'  json {{ source => "message" target => "{target}" }}')
        target += f".f{i}"
    lines.append(
        f'  mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.deep" => "%{{{target}.leaf}}" }} }}'
    )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _secops_routing_chain_parser(count: int) -> str:
    lines = [
        "filter {",
        '  json { source => "message" target => "parsed_json" }',
        (
            '  mutate { replace => { "event.idm.read_only_udm.metadata.event_timestamp" '
            '=> "%{parsed_json.timestamp}" } }'
        ),
    ]
    for i in range(count):
        prefix = "if" if i == 0 else "} else if"
        lines.append(f'  {prefix} [parsed_json][vendor_id] == "VND_{i:05d}" {{')
        lines.append(
            f'    mutate {{ replace => {{ "event.idm.read_only_udm.metadata.vendor_name" => "VendorCorp_{i}" }} }}'
        )
        lines.append(
            '    mutate { replace => { "event.idm.read_only_udm.metadata.product_name" '
            f'=> "Enterprise_Suite_{i}" }} }}'
        )
        if i % 3 == 0:
            lines.append(
                '    grok { match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} '
                "%{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: "
                '%{GREEDYDATA:syslog_message}" } }'
            )
            lines.append(
                '    mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{syslog_hostname}" } }'
            )
        elif i % 3 == 1:
            lines.append('    xml { source => "message" target => "parsed_xml" }')
            lines.append(
                '    mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{parsed_xml.destination_ip}" } }'
            )
        else:
            lines.append(
                '    csv { source => "message" separator => "," columns => ["timestamp", "src_ip", "dst_ip", "action"] }'
            )
            lines.append('    mutate { replace => { "event.idm.read_only_udm.principal.ip" => "%{src_ip}" } }')
            lines.append('    mutate { replace => { "event.idm.read_only_udm.target.ip" => "%{dst_ip}" } }')
        lines.append(
            "    mutate { replace => { "
            f'"event.idm.read_only_udm.additional.fields.%{{parsed_json.key_{i}}}" => "%{{parsed_json.val_{i}}}"'
            " } }"
        )
        lines.append('    if [parsed_json][action] == "ALLOW" or [parsed_json][status] == "SUCCESS" {')
        lines.append('      mutate { replace => { "event.idm.read_only_udm.security_result.action" => "ALLOW" } }')
        lines.append('    } else if [parsed_json][action] == "DENY" {')
        lines.append('      mutate { replace => { "event.idm.read_only_udm.security_result.action" => "BLOCK" } }')
        lines.append("    } else {")
        lines.append(
            '      mutate { replace => { "event.idm.read_only_udm.security_result.action" => "UNKNOWN_ACTION" } }'
        )
        lines.append("    }")
    lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _nested_static_loop_parser(width: int, depth: int) -> str:
    values = "[" + ", ".join(f'"v{i}"' for i in range(width)) + "]"
    lines = ["filter {"]
    for level in range(depth):
        indent = "  " * (level + 1)
        lines.append(f"{indent}for item{level} in {values} {{")
    combo = ".".join(f"%{{item{level}}}" for level in range(depth))
    lines.append(
        "  " * (depth + 1)
        + f'mutate {{ add_field => {{ "event.idm.read_only_udm.additional.fields.combo" => "{combo}" }} }}'
    )
    for level in reversed(range(depth)):
        lines.append("  " * (level + 1) + "}")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _nested_dynamic_loop_parser(width: int) -> str:
    lines = ["filter {"]
    for i in range(width):
        lines.append(f'  mutate {{ add_field => {{ "items_a" => "a{i}" "items_b" => "b{i}" }} }}')
    lines.append("  for item_a in %{items_a} {")
    lines.append("    for item_b in %{items_b} {")
    lines.append(
        '      mutate { replace => { "event.idm.read_only_udm.additional.fields.cross" => "%{item_a}:%{item_b}" } }'
    )
    lines.append("    }")
    lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _real_slow_shape_parser() -> str:
    values = "[" + ", ".join(f'"v{i}"' for i in range(25)) + "]"
    lines = ["filter {"]
    for name in ("event_type", "region", "tenant", "actor", "action"):
        lines.append(f"  for {name} in {values} {{")
    lines.append(
        '    mutate { replace => { "event.idm.read_only_udm.additional.fields.routing_key" '
        '=> "%{tenant}.%{region}.%{event_type}" } }'
    )
    for _ in range(5):
        lines.append("  }")
    lines.append('  mutate { replace => { "sev_part_0" => "SEV" "tgt_part_0" => "TGT" } }')
    for i in range(1, 11):
        lines.append(
            f'  if [log][s{i}] {{ mutate {{ replace => {{ "sev_part_{i}" => "%{{sev_part_{i - 1}}}_S{i}" }} }} }} '
            f'else {{ mutate {{ replace => {{ "sev_part_{i}" => "%{{sev_part_{i - 1}}}_N{i}" }} }} }}'
        )
        lines.append(
            f'  if [target][t{i}] {{ mutate {{ replace => {{ "tgt_part_{i}" => "%{{tgt_part_{i - 1}}}_T{i}" }} }} }} '
            f'else {{ mutate {{ replace => {{ "tgt_part_{i}" => "%{{tgt_part_{i - 1}}}_N{i}" }} }} }}'
        )
    lines.append("  for final_sev in %{sev_part_10} {")
    lines.append("    for final_tgt in %{tgt_part_10} {")
    lines.append(
        '      mutate { replace => { "event.idm.read_only_udm.security_result.description" '
        '=> "%{final_sev}:%{final_tgt}" } }'
    )
    lines.append("    }")
    lines.append("  }")
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _gsub_transform_fanout_parser(replacements: int = 1_000, include_backref: bool = False) -> str:
    lines = ["filter {"]
    for i in range(10):
        lines.append(
            f'  if [compliance][check_{i}] == "PASS" '
            f'{{ mutate {{ replace => {{ "comp_status_{i}" => "COMPLIANT" }} }} }} '
            f'else {{ mutate {{ replace => {{ "comp_status_{i}" => "VIOLATION" }} }} }}'
        )
    signature = "_".join(f"%{{comp_status_{i}}}" for i in range(10))
    lines.append(f'  mutate {{ replace => {{ "posture_signature" => "{signature}" }} }}')
    lines.append("  mutate {")
    lines.append("    gsub => [")
    for i in range(replacements):
        replacement = r"[\1]" if include_backref and i == 0 else "[REDACTED]"
        lines.append(f'      "posture_signature", "DROP TABLE.*{i}", "{replacement}",')
    lines.append('      "posture_signature", "end", "end"')
    lines.append("    ]")
    lines.append("  }")
    lines.append(
        '  mutate { replace => { "event.idm.read_only_udm.additional.fields.posture" => "%{posture_signature}" } }'
    )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _iam_self_referential_context_parser(segments: int = 34) -> str:
    lines = ["filter {", '  mutate { replace => { "iam_context_string" => "arn:aws:iam" } }']
    for i in range(1, segments + 1):
        lines.append(
            f'  if [event][auth_context][role_segment_{i}] != "" '
            f'{{ mutate {{ replace => {{ "iam_context_string" => '
            f'"%{{iam_context_string}}:%{{event.auth_context.role_segment_{i}}}" }} }} }} '
            f'else {{ mutate {{ replace => {{ "iam_context_string" => "%{{iam_context_string}}:unspecified" }} }} }}'
        )
    lines.append("  for mapped_iam_role in %{iam_context_string} {")
    lines.append('    mutate { replace => { "target_taxonomy_role" => "%{mapped_iam_role}" } }')
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def _same_field_port_chain_parser(count: int) -> str:
    lines = ["filter {", '  mutate { replace => { "network_app_proto" => "unknown" } }']
    for i in range(count):
        lines.append(
            f'  if [network][destination][port] == "{i}" '
            f'{{ mutate {{ replace => {{ "network_app_proto" => "%{{network_app_proto}}_APP_{i}" }} }} }}'
        )
    lines.append(
        '  mutate { replace => { "event.idm.read_only_udm.additional.fields.proto" => "%{network_app_proto}" } }'
    )
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _real_slow_2_shape_parser() -> str:
    lines = ["filter {"]
    lines.extend(_iam_self_referential_context_parser().splitlines()[1:-1])
    lines.extend(_gsub_transform_fanout_parser().splitlines()[1:-1])
    lines.extend(_same_field_port_chain_parser(250).splitlines()[1:-1])
    for i in range(8_000):
        lines.append(f'  json {{ source => "vendor_extension_block_{i}" }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


def _literal_collection_merge_parser(count: int) -> str:
    values = ", ".join(f'"10.0.{i // 256}.{i % 256}"' for i in range(count))
    return "\n".join(
        [
            "filter {",
            f'  mutate {{ merge => {{ "global_threat_feed" => [{values}] }} }}',
            "}",
        ]
    )


def _unresolved_json_extractor_parser(count: int) -> str:
    lines = ["filter {"]
    for i in range(count):
        lines.append(f'  json {{ source => "vendor_extension_block_{i}" }}')
    lines.append("}")
    return "\n".join(lines)


def _branched_unresolved_json_extractor_parser(count_per_branch: int) -> str:
    lines = ["filter {", '  if [route] == "a" {']
    for i in range(count_per_branch):
        lines.append(f'    json {{ source => "branch_a_vendor_extension_{i}" }}')
    lines.append("  } else {")
    for i in range(count_per_branch):
        lines.append(f'    json {{ source => "branch_b_vendor_extension_{i}" }}')
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def _real_slow_3_diagnostic_shape_parser() -> str:
    lines = ["filter {"]
    lines.extend(_iam_self_referential_context_parser(48).splitlines()[1:-1])
    lines.extend(_gsub_transform_fanout_parser(replacements=250).splitlines()[1:-1])
    for i in range(12_001):
        lines.append(f'  json {{ source => "vendor_extension_block_{i}" }}')
    lines.append('  mutate { merge => { "@output" => "event" } }')
    lines.append("}")
    return "\n".join(lines)


@pytest.mark.parametrize(("count", "budget"), [(5_000, 5.0), (10_000, 8.0), (20_000, 15.0)])
def test_independent_conditionals_scale_near_linearly(count: int, budget: float):
    elapsed, parser = _analysis_seconds(_independent_if_parser(count))
    assert elapsed < budget
    assert len(parser.analyze().tokens) == (count * 2) + 1


def test_large_mutate_only_parser_avoids_descendant_scan_quadratic_behavior():
    elapsed, parser = _analysis_seconds(_mutate_only_parser(20_000))
    assert elapsed < 8.0
    assert len(parser.analyze().tokens) == 20_001


def test_end_to_end_large_flat_mutates_stays_within_total_budget():
    elapsed, parser = _parse_and_analysis_seconds(_mutate_only_parser(20_000))
    assert elapsed < 15.0
    assert len(parser.analyze().tokens) == 20_001


def test_end_to_end_independent_ifs_stays_within_total_budget():
    elapsed, parser = _parse_and_analysis_seconds(_independent_if_parser(20_000))
    assert elapsed < 22.0
    assert len(parser.analyze().tokens) == 40_001


def test_mega_parser_fixture_stays_fast_end_to_end():
    fixture = Path(__file__).parent / "fixtures" / "test_corpus" / "challenge" / "test_mega_parser_perf_budget.cbn"
    elapsed, parser = _parse_and_analysis_seconds(fixture.read_text(encoding="utf-8"))
    assert elapsed < 3.0
    assert parser.analyze().tokens


def test_scanner_strips_many_trailing_comments_without_mangling_comment_like_bodies():
    code = _comment_like_scanner_body(10_000)

    start = time.perf_counter()
    stripped = strip_comments_keep_offsets(code)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0
    assert len(stripped) == len(code)
    assert stripped.count("http://example.com/a//b/") == 10_000
    assert stripped.count("//node") == 10_000
    assert " // trailing" not in stripped


def test_scanner_comment_free_fast_path_returns_original_text_without_full_scan():
    code = _comment_free_scanner_body(50_000)

    start = time.perf_counter()
    stripped = strip_comments_keep_offsets(code)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.05
    assert stripped is code


@pytest.mark.parametrize(("count", "budget"), [(1_000, 3.0), (2_000, 6.0), (5_000, 20.0)])
def test_drop_guards_scale_with_delta_merge_and_compact_path_conditions(count: int, budget: float):
    elapsed, parser = _analysis_seconds(_drop_guard_parser(count))
    assert elapsed < budget
    result = parser.query(f"additional.fields.k{count - 1}")
    assert any("drop parser may drop events" in warning for warning in result.warnings)
    conditions = list(result.mappings[0].conditions)
    if count <= 32:
        assert conditions == [f'NOT([drop{count - 1}] == "1")']
    else:
        assert conditions == [f"NOT(drop path: any of {count} prior drop conditions matched)"]


def test_standalone_on_error_blocks_use_delta_reconciliation():
    elapsed, parser = _analysis_seconds(_standalone_on_error_parser(1_000))
    assert elapsed < 4.0
    result = parser.query("additional.fields.err999")
    assert any("on_error" in cond for mapping in result.mappings for cond in mapping.conditions)
    assert any("NOT(on_error)" in cond for mapping in result.mappings for cond in mapping.conditions)


@pytest.mark.parametrize(("count", "budget"), [(1_000, 2.0), (2_000, 4.0), (4_000, 8.0)])
def test_branch_local_extractors_and_anchors_do_not_force_full_token_merge(count: int, budget: float):
    elapsed, parser = _analysis_seconds(_branch_local_metadata_parser(count))
    assert elapsed < budget
    summary = cast(CompactAnalysisSummaryDict, parser.analysis_summary(compact=True))
    assert summary["json_extractions_total"] == count
    assert summary["output_anchors_total"] == count


def test_branch_local_metadata_avoids_quadratic_probe_shape():
    elapsed, parser = _analysis_seconds(_branch_local_metadata_parser(4_000, seed_count=0))
    assert elapsed < 5.0
    assert parser.analysis_summary(compact=True)["json_extractions_total"] == 4_000


def test_dynamic_loop_alternatives_merge_only_loop_deltas():
    elapsed, parser = _analysis_seconds(_dynamic_loop_parser(1_000))
    assert elapsed < 8.0
    assert "event.idm.read_only_udm.additional.fields.loop999_4" in parser.analyze().tokens


def test_nested_static_loop_below_cumulative_fanout_remains_exact():
    parser = ReverseParser(_nested_static_loop_parser(3, 3))
    result = parser.query("additional.fields.combo")

    assert len(result.mappings) == 27
    assert not any(warning.code == "loop_fanout" for warning in result.structured_warnings)


def test_flat_static_loop_over_cumulative_cap_remains_exact_under_assignment_cap():
    parser = ReverseParser(_nested_static_loop_parser(1001, 1))
    result = parser.query("additional.fields.combo")

    assert len(result.mappings) == 1001
    assert not any(warning.code == "loop_fanout" for warning in result.structured_warnings)


def test_nested_static_loop_over_cumulative_fanout_is_summarized_fast():
    start = time.perf_counter()
    parser = ReverseParser(_nested_static_loop_parser(6, 4))
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start
    result = parser.query("additional.fields.combo")

    assert elapsed < 1.0
    assert summary["warning_counts"]["loop_fanout"] >= 1
    assert summary["taint_counts"]["loop_fanout"] >= 1
    assert result.status == "dynamic"
    assert result.mappings
    assert any(taint.code == "loop_fanout" for mapping in result.mappings for taint in mapping.taints)


def test_nested_dynamic_loop_over_cumulative_fanout_is_summarized_fast():
    start = time.perf_counter()
    parser = ReverseParser(_nested_dynamic_loop_parser(32))
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start
    result = parser.query("additional.fields.cross")

    assert elapsed < 1.0
    assert summary["warning_counts"]["loop_fanout"] >= 1
    assert summary["taint_counts"]["loop_fanout"] >= 1
    assert result.status == "dynamic"
    assert result.mappings
    assert any(taint.code == "loop_fanout" for mapping in result.mappings for taint in mapping.taints)


def test_real_slow_shape_completes_with_loop_fanout_diagnostics():
    start = time.perf_counter()
    parser = ReverseParser(_real_slow_shape_parser())
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0
    assert summary["warning_counts"]["loop_fanout"] >= 2
    assert summary["taint_counts"]["loop_fanout"] >= 2


def test_gsub_transform_fanout_is_summarized_fast():
    start = time.perf_counter()
    parser = ReverseParser(_gsub_transform_fanout_parser())
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start
    result = parser.query("additional.fields.posture")

    assert elapsed < 2.0
    assert summary["warning_counts"]["gsub_transform_fanout"] >= 1
    assert summary["taint_counts"]["gsub_transform_fanout"] >= 1
    assert any(
        "gsub(1001 replacements summarized)" in tx for mapping in result.mappings for tx in mapping.transformations
    )


def test_small_gsub_preserves_individual_transformations_below_fanout_cap():
    parser = ReverseParser(_gsub_transform_fanout_parser(replacements=2))
    result = parser.query("additional.fields.posture")

    assert not any(diagnostic.code == "gsub_transform_fanout" for diagnostic in result.effective_diagnostics)
    assert any(
        "gsub(pattern=DROP TABLE.*0, replacement=[REDACTED])" in tx for m in result.mappings for tx in m.transformations
    )


def test_gsub_backreference_warning_survives_transform_fanout_summary():
    parser = ReverseParser(_gsub_transform_fanout_parser(include_backref=True))
    result = parser.query("additional.fields.posture")

    assert any(diagnostic.code == "gsub_transform_fanout" for diagnostic in result.effective_diagnostics)
    assert any(diagnostic.code == "gsub_backreference" for diagnostic in result.effective_diagnostics)


def test_self_referential_template_chain_is_summarized_fast():
    elapsed, parser = _analysis_seconds(_iam_self_referential_context_parser())
    summary = parser.analysis_summary(compact=True)
    result = parser.query("target_taxonomy_role")

    assert elapsed < 1.0
    assert summary["warning_counts"]["template_fanout"] >= 1
    assert any(diagnostic.code == "dynamic_loop_iterable" for diagnostic in result.effective_diagnostics)


def test_same_field_independent_branch_chain_uses_cached_condition_facts():
    elapsed, parser = _analysis_seconds(_same_field_port_chain_parser(250))
    result = parser.query("additional.fields.proto")

    assert elapsed < 3.0
    assert any(diagnostic.code == "branch_lineage_fanout" for diagnostic in result.effective_diagnostics)


def test_real_slow_2_shape_completes_with_transform_and_branch_fanout_diagnostics():
    start = time.perf_counter()
    parser = ReverseParser(_real_slow_2_shape_parser())
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start

    assert elapsed < 5.0
    assert summary["warning_counts"]["gsub_transform_fanout"] >= 1
    assert summary["warning_counts"]["branch_lineage_fanout"] >= 1
    assert summary["warning_counts"]["unresolved_extractor_source"] == 8_000


def test_literal_collection_merge_below_cap_remains_exact():
    count = 128
    parser = ReverseParser(_literal_collection_merge_parser(count))
    state = parser.analyze()

    assert len(state.tokens["global_threat_feed"]) == count
    assert not any(warning.code == "literal_collection_fanout" for warning in state.structured_warnings)


def test_literal_collection_merge_over_cap_is_summarized_fast():
    elapsed, parser = _analysis_seconds(_literal_collection_merge_parser(MAX_LITERAL_COLLECTION_LINEAGES + 1))
    summary = parser.analysis_summary(compact=True)
    lineages = parser.analyze().tokens["global_threat_feed"]

    assert elapsed < 1.0
    assert len(lineages) == 1
    assert lineages[0].status == "dynamic"
    assert summary["warning_counts"]["literal_collection_fanout"] == 1
    assert summary["taint_counts"]["literal_collection_fanout"] == 1


def test_unresolved_json_extractor_diagnostics_are_coalesced_with_logical_counts():
    count = 12_001
    elapsed, parser = _analysis_seconds(_unresolved_json_extractor_parser(count))
    summary = parser.analysis_summary(compact=True)
    warnings = [
        warning for warning in parser.analyze().structured_warnings if warning.code == "unresolved_extractor_source"
    ]

    assert elapsed < 2.0
    assert len(warnings) <= 129
    assert summary["warning_counts"]["unresolved_extractor_source"] == count
    assert summary["taint_counts"]["unresolved_extractor_source"] == count
    assert any("additional unresolved sources summarized" in warning.message for warning in warnings)


def test_coalesced_extractor_counts_survive_branch_merges():
    count_per_branch = 150
    elapsed, parser = _analysis_seconds(_branched_unresolved_json_extractor_parser(count_per_branch))
    summary = parser.analysis_summary(compact=True)

    assert elapsed < 1.0
    assert summary["warning_counts"]["unresolved_extractor_source"] == count_per_branch * 2
    assert summary["taint_counts"]["unresolved_extractor_source"] == count_per_branch * 2


def test_small_unresolved_json_extractor_set_keeps_exact_source_warnings():
    parser = ReverseParser(_unresolved_json_extractor_parser(3))
    warnings = [
        warning for warning in parser.analyze().structured_warnings if warning.code == "unresolved_extractor_source"
    ]

    assert [warning.source_token for warning in warnings] == [
        "vendor_extension_block_0",
        "vendor_extension_block_1",
        "vendor_extension_block_2",
    ]


def test_real_slow_3_shape_combines_template_and_extractor_summarization():
    elapsed, parser = _analysis_seconds(_real_slow_3_diagnostic_shape_parser())
    summary = parser.analysis_summary(compact=True)
    unresolved_warnings = [
        warning for warning in parser.analyze().structured_warnings if warning.code == "unresolved_extractor_source"
    ]

    assert elapsed < 5.0
    assert len(unresolved_warnings) <= 129
    assert summary["warning_counts"]["template_fanout"] >= 1
    assert summary["warning_counts"]["gsub_transform_fanout"] >= 1
    assert summary["warning_counts"]["unresolved_extractor_source"] == 12_001


def test_object_merge_and_parent_remove_rename_use_descendant_indexes():
    elapsed, parser = _analysis_seconds(_object_merge_parser(2_000))
    assert elapsed < 5.0
    assert "event.idm.read_only_udm.additional.fields.obj1999.child" in parser.analyze().tokens

    elapsed, parser = _analysis_seconds(_parent_remove_rename_parser(4_000))
    assert elapsed < 8.0
    state = parser.analyze()
    assert state.tokens["root3999.child"][0].status == "removed"
    assert "keep3999.child" not in state.tokens


def test_large_extractor_hint_reference_lookup_uses_target_index():
    elapsed, parser = _analysis_seconds(_json_hint_reference_parser(10_000))
    assert elapsed < 12.0
    result = parser.query("additional.fields.hint9999")
    assert result.mappings


def test_interleaved_extractor_hint_index_updates_incrementally():
    elapsed, parser = _analysis_seconds(_interleaved_json_hint_reference_parser(5_000))
    assert elapsed < 8.0
    assert parser.query("additional.fields.hint4999").mappings


def test_deep_extractor_target_hint_chains_are_indexed_by_prefix():
    elapsed, parser = _analysis_seconds(_json_target_chain_parser(1_000))
    assert elapsed < 2.0

    start = time.perf_counter()
    result = parser.query("additional.fields.deep")
    query_elapsed = time.perf_counter() - start

    assert query_elapsed < 0.25
    assert len(result.mappings) == 1_000
    # C1 fix: chained json extractions all flow through a single
    # `mutate.replace` (overwrite), so these 1000 mappings represent
    # multi-source derivation, not append/merge semantics. Status should be
    # `derived`, not `repeated` — the prior assertion only passed because
    # `_status_from_aggregate` misclassified any 2+ unconditional exact
    # mappings as `repeated`.
    assert result.status == "derived"


def test_untargeted_extractor_hints_are_coalesced_before_token_inference_fanout():
    state = AnalyzerState()
    for i in range(5_000):
        state.add_extraction_hint(
            "json",
            ExtractionHint(
                "json",
                "message",
                {},
                parser_locations=[f"line {i}: json source=message"],
                source_resolved=True,
            ),
        )

    start = time.perf_counter()
    hints = state.extractor_hints_for_token("json", "deep.field")
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert len(state.json_extractions) == 5_000
    assert len(hints) == 1
    assert len(tuple(hints[0].parser_locations)) == 128


def test_repeated_appends_to_same_token_are_incremental():
    elapsed, parser = _analysis_seconds(_repeated_append_parser(20_000))
    assert elapsed < 10.0
    result = parser.query("additional.fields.repeat")
    assert len(result.mappings) == 20_000


def test_dynamic_destination_query_uses_template_index_for_unrelated_prefixes():
    parser = ReverseParser(_dynamic_mutate_parser(20_000))
    parser.analyze()

    start = time.perf_counter()
    miss = parser.query("principal.ip")
    unrelated_elapsed = time.perf_counter() - start
    assert unrelated_elapsed < 0.25
    assert miss.status == "unresolved"

    hit = parser.query("additional.fields.anything")
    assert len(hit.mappings) == 20_000


def test_duplicate_anchors_do_not_multiply_dynamic_query_work():
    parser = ReverseParser(_duplicate_anchor_dynamic_parser(1_000, 1_000))
    parser.analyze()

    start = time.perf_counter()
    result = parser.query("additional.fields.anything")
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0
    assert len(result.output_anchors) == 1
    assert len(result.mappings) == 1_000


def test_root_dynamic_templates_use_literal_guard_for_unrelated_query_misses():
    parser = ReverseParser(_root_dynamic_parser(10_000))
    parser.analyze()

    start = time.perf_counter()
    result = parser.query("event.idm.read_only_udm.principal.ip")
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert result.status == "unresolved"


def test_destination_template_static_fanout_is_capped_before_materializing_tokens():
    elapsed, parser = _analysis_seconds(_destination_template_fanout_parser(11))
    state = parser.analyze()

    assert elapsed < 1.0
    assert len(state.tokens) < 100
    assert any(diagnostic.code == "template_fanout" for diagnostic in state.diagnostics)
    assert any(warning.code == "dynamic_destination" for warning in state.structured_warnings)


# Budgets give ~50% headroom over the typical local elapsed; recent shared
# Linux runners on PRs #6 and #7 measured 0.305s and 0.32s for count=1000
# under a previous 0.3s gate, so the gate was set too tight for noisy CI.
@pytest.mark.parametrize(("count", "budget"), [(500, 0.3), (1_000, 0.45), (2_000, 0.75), (3_000, 1.2)])
def test_unique_output_anchor_queries_use_prefix_index(count: int, budget: float):
    parser = ReverseParser(_unique_anchor_parser(count))
    parser.analyze()

    start = time.perf_counter()
    result = parser.query("principal.ip")
    elapsed = time.perf_counter() - start

    assert elapsed < budget
    assert len(result.output_anchors) == count


def test_hot_repeated_branch_appends_do_not_reclone_existing_lineages():
    elapsed, parser = _analysis_seconds(_hot_branch_append_parser(10_000))
    assert elapsed < 12.0
    result = parser.query("additional.fields.repeat")
    assert len(result.mappings) <= 4_097
    assert any(diagnostic.code == "branch_lineage_fanout" for diagnostic in result.effective_diagnostics)


def test_explicit_else_self_rewrite_lineage_doubling_is_capped():
    elapsed, parser = _analysis_seconds(_explicit_else_self_rewrite_parser(16))
    assert elapsed < 3.0
    result = parser.query("additional.fields.x")
    assert len(result.mappings) == 1
    assert result.mappings[0].status == "conditional"
    assert any(diagnostic.code == "branch_lineage_fanout" for diagnostic in result.effective_diagnostics)


def test_anchor_conditioned_dynamic_query_is_sampled_in_compact_output():
    parser = ReverseParser(_conditional_anchor_dynamic_parser(1_000, 2_000))
    parser.analyze()

    start = time.perf_counter()
    result = parser.query("additional.fields.anything")
    elapsed = time.perf_counter() - start
    payload = render_compact_json(result)

    assert elapsed < 2.0
    assert result.total_mappings == 2_000_000
    assert len(result.mappings) <= 50
    assert '"mappings_total": 2000000' in payload
    assert any(diagnostic.code == "anchor_conditioned_fanout" for diagnostic in result.effective_diagnostics)


def test_anchor_conditioned_dynamic_query_honors_sample_limit():
    parser = ReverseParser(_conditional_anchor_dynamic_parser(300, 200))
    parser.analyze()

    result = parser.query("additional.fields.anything", sample_limit=7)

    assert result.total_mappings == 60_000
    assert len(result.mappings) == 7


def test_anchor_conditioned_dynamic_query_clamps_oversized_sample_limit():
    parser = ReverseParser(_conditional_anchor_dynamic_parser(300, 200))
    parser.analyze()

    result = parser.query("additional.fields.anything", sample_limit=10_000)

    assert result.total_mappings == 60_000
    assert len(result.mappings) == 50


def test_compact_anchor_conditioned_direct_dynamic_query_does_not_exceed_sample_limit():
    parser = ReverseParser(_anchored_direct_dynamic_parser(20))
    parser.analyze()

    result = parser.query("additional.fields.anything", compact=True, sample_limit=7)

    assert result.total_mappings == 21
    assert len(result.mappings) == 7
    assert result.status == "dynamic"


def test_sampled_hidden_mappings_drive_query_semantics_without_no_assignment():
    parser = ReverseParser(_conditional_anchor_dynamic_parser(300, 200))
    parser.analyze()

    result = parser.query("additional.fields.anything", sample_limit=-1)
    diagnostic = next(d for d in result.effective_diagnostics if d.code == "anchor_conditioned_fanout")

    assert result.total_mappings == 60_000
    assert result.mappings == []
    assert result.status == "dynamic"
    assert result.is_conditional
    assert result.has_dynamic
    assert not result.has_unresolved
    assert not any(warning.code == "no_assignment" for warning in result.structured_warnings)
    assert "query result is sampled" in diagnostic.message
    assert "compact result" not in diagnostic.message


def test_compact_summary_bounds_high_volume_diagnostics_but_keeps_counts():
    parser = ReverseParser(_dynamic_mutate_parser(200))
    summary = parser.analysis_summary(compact=True)
    full_udm_fields = parser.list_udm_fields()

    assert summary["warnings_total"] == 200
    assert summary["taints_total"] >= 200
    assert summary["warning_counts"]["dynamic_destination"] == 200
    assert summary["udm_fields_total"] == len(full_udm_fields)
    assert summary["udm_fields"] == full_udm_fields[:50]
    assert len(summary["warnings"]) == 50
    assert len(summary["diagnostics"]) == 50

    compact_meta = summary["compact_summary"]
    assert compact_meta["limit"] == 50
    truncated = set(compact_meta["truncated_keys"])
    assert {"warnings", "diagnostics", "taints"}.issubset(truncated)
    assert "udm_fields" not in truncated or summary["udm_fields_total"] > 50


def test_compact_summary_marks_no_truncation_when_lists_fit_within_limit():
    parser = ReverseParser('filter { mutate { merge => { "@output" => "event" } } }')
    summary = parser.analysis_summary(compact=True)
    assert summary["compact_summary"]["limit"] == 50
    assert summary["compact_summary"]["truncated_keys"] == []


def test_compact_summary_many_static_fields_samples_without_scanning_full_payloads():
    parser = ReverseParser(_mutate_only_parser(20_000))
    parser.analyze()

    start = time.perf_counter()
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert summary["udm_fields_total"] == 20_000
    assert len(summary["udm_fields"]) == 50
    assert summary["token_count"] == 20_001


def test_compact_summary_aggregates_high_volume_taints_without_full_payload_growth():
    parser = ReverseParser(_dynamic_mutate_parser(2_000))
    parser.analyze()

    start = time.perf_counter()
    summary = parser.analysis_summary(compact=True)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert summary["taints_total"] == 6_000
    assert summary["taint_counts"]["dynamic_destination"] == 2_000
    assert summary["taint_counts"]["unresolved_token"] == 4_000
    assert len(summary["taints"]) == 50


def test_compact_query_json_bounds_high_cardinality_output():
    parser = ReverseParser(_dynamic_mutate_parser(200))
    result = parser.query("additional.fields.anything")
    payload = render_compact_json(result)
    assert '"mappings_total": 200' in payload
    assert '"normalized_candidates_total"' in payload
    assert payload.count('"status"') < 80


def test_compact_query_json_bounds_normalized_candidates_for_many_anchors():
    parser = ReverseParser(_unique_anchor_parser(200))
    result = parser.query("principal.ip")
    payload = render_compact_json(result, limit=20)
    assert '"normalized_candidates_total": 403' in payload
    assert payload.count('"event') < 40


def test_text_render_limits_mapping_taints_without_unbounded_output():
    mapping = Lineage(
        status="dynamic",
        expression="x",
        taints=[
            TaintReason(code="dynamic_destination", message=f"taint {i}", parser_location=f"line {i}: mutate")
            for i in range(2_000)
        ],
    )
    result = QueryResult(
        udm_field="additional.fields.x",
        normalized_candidates=["event.idm.read_only_udm.additional.fields.x"],
        mappings=[mapping],
    )

    start = time.perf_counter()
    text = render_text(result, verbose=True, limit=5)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert text.count("dynamic_destination: taint") == 5
    assert "... 1995 more taints omitted" in text


def test_large_else_if_chain_remains_fast():
    elapsed, parser = _analysis_seconds(_else_if_chain_parser(4_000))
    assert elapsed < 5.0
    result = parser.query("security_result.action")
    assert len(result.mappings) == 4_000


@pytest.mark.parametrize(("count", "budget"), [(1_000, 4.0), (2_000, 8.0), (4_000, 16.0)])
def test_secops_routing_else_if_chain_uses_sparse_branch_merge(count: int, budget: float):
    if _NATIVE_DISABLED:
        pytest.skip("strict parse+analysis budget requires native scanner/config acceleration")
    elapsed, parser = _parse_and_analysis_seconds(_secops_routing_chain_parser(count))
    assert elapsed < budget
    summary = cast(CompactAnalysisSummaryDict, parser.analysis_summary(compact=True))
    assert summary["token_count"] == (count * 3) + 18
    assert summary["json_extractions_total"] == 1
    assert summary["xml_extractions_total"] == count // 3 + (1 if count % 3 >= 2 else 0)


def test_secops_routing_else_if_chain_diagnostics_merge_is_not_quadratic():
    """The diagnostics merge must scale linearly, not quadratically, in elif count.

    Before the alias guard in ``_merge_branch_diagnostics_delta``, sibling
    branches whose state still aliased the parent's ``diagnostics`` list
    re-iterated the entire shared list — which kept growing as each earlier
    sibling's records were appended. That made the merge ~0.225 * N**2 per 1k
    elifs (≈225k iterations vs an expected delta of ≈666). After the fix the
    quadratic blow-up is gone; we assert a linear-ish ratio (<8x for 4x
    branches) with budget loose enough for noisy CI runners. Pure linear is
    4x; quadratic would be 16x.
    """
    if _NATIVE_DISABLED:
        pytest.skip("perf ratio assertion requires native scanner/config acceleration")

    small_count = 1_000
    large_count = 4_000

    # Warm up Python's import/jit caches so the first run isn't unfairly slow.
    ReverseParser(_secops_routing_chain_parser(50)).analyze()

    small_elapsed, _ = _analysis_seconds(_secops_routing_chain_parser(small_count))
    large_elapsed, _ = _analysis_seconds(_secops_routing_chain_parser(large_count))

    ratio = large_elapsed / max(small_elapsed, 1e-3)
    # Ratio budget of 8x: linear is 4x, quadratic 16x. 8x absorbs CI variance
    # while still flagging a regression to the quadratic shape.
    assert ratio < 8.0, (
        f"diagnostics merge looks super-linear: "
        f"{small_count} elifs took {small_elapsed:.3f}s, "
        f"{large_count} elifs took {large_elapsed:.3f}s "
        f"(ratio {ratio:.2f}x; expected <8x)"
    )


def test_branch_seed_diagnostic_sync_scales_linearly_per_elif():
    """Long elif chains must not pay an O(N) rebuild per elif.

    ``_sync_branch_seed_diagnostics`` is invoked once per elif via the
    ``_exec_if`` chain. When the elif conditions are exact-literal equality
    checks (the common SecOps routing pattern) neither
    ``_warn_condition_limits`` nor ``_branch_is_reachable`` adds any
    diagnostics, so the seed and the parent state stay in lockstep and the
    sync should early-return without touching the seen-set indexes. This test
    asserts that ``_rebuild_diagnostic_indexes`` is called only during the
    initial post-init bootstrap and never from the sync path during the elif
    loop, which is what keeps total work linear in the number of branches.
    """
    from parser_lineage_analyzer._analysis_state import AnalyzerState

    rebuild_calls = 0
    original_rebuild = AnalyzerState._rebuild_diagnostic_indexes

    def counting_rebuild(self: AnalyzerState) -> None:
        nonlocal rebuild_calls
        rebuild_calls += 1
        original_rebuild(self)

    AnalyzerState._rebuild_diagnostic_indexes = counting_rebuild
    try:
        small_count = 200
        small_parser = ReverseParser(_secops_routing_chain_parser(small_count))
        small_parser.analyze()
        small_rebuilds = rebuild_calls

        rebuild_calls = 0
        large_count = 2_000
        large_parser = ReverseParser(_secops_routing_chain_parser(large_count))
        large_parser.analyze()
        large_rebuilds = rebuild_calls
    finally:
        AnalyzerState._rebuild_diagnostic_indexes = original_rebuild

    # Total rebuilds must not scale with the number of elifs. The 10x branch
    # increase should stay within a tiny constant factor — one rebuild per
    # post-init plus a handful of unrelated bootstraps.
    assert small_rebuilds <= 4, f"unexpected baseline rebuild count: {small_rebuilds}"
    assert large_rebuilds <= small_rebuilds + 2, (
        f"_rebuild_diagnostic_indexes grew with elif count: "
        f"{small_count} elifs -> {small_rebuilds} rebuilds, "
        f"{large_count} elifs -> {large_rebuilds} rebuilds"
    )


def test_parent_assignment_clears_descendants_without_touching_similar_prefixes():
    code = r"""
    filter {
      mutate { replace => { "foo.bar" => "child" "foobar.baz" => "similar" } }
      mutate { replace => { "foo" => "parent" } }
    }
    """
    state = ReverseParser(code).analyze()
    assert "foo.bar" not in state.tokens
    assert "foo" in state.tokens
    assert "foobar.baz" in state.tokens


def test_simple_config_fast_path_matches_lark_supported_shapes():
    assert parse_config('replace => { "a" => "b" "c" => "%{d}" }') == [("replace", [("a", "b"), ("c", "%{d}")])]
    assert parse_config('copy => { "dst" => "src" } merge => { "@output" => "event" }') == [
        ("copy", [("dst", "src")]),
        ("merge", [("@output", "event")]),
    ]
    assert parse_config('replace => { "a" => ["b"] }') == [("replace", [("a", ["b"])])]
    assert parse_config('source => "message" target => "payload"') == [("source", "message"), ("target", "payload")]


def test_config_cache_returns_fresh_mutable_results_and_can_be_cleared():
    clear_config_parse_cache()
    first = parse_config('source => "message" target => "payload"')
    first.append(("polluted", "yes"))
    second = parse_config('source => "message" target => "payload"')
    assert second == [("source", "message"), ("target", "payload")]
    clear_config_parse_cache()
    third = parse_config('source => "message" target => "payload"')
    assert third == second


def test_config_parse_cache_info_reports_lark_cache_stats():
    clear_config_parse_cache()
    assert config_parse_cache_info().currsize == 0
    parse_config('{"key" => "value"}')
    after_miss = config_parse_cache_info()
    assert after_miss.misses == 1
    assert after_miss.hits == 0
    assert after_miss.currsize == 1
    parse_config('{"key" => "value"}')
    after_hit = config_parse_cache_info()
    assert after_hit.hits == 1
    assert after_hit.misses == 1


def test_fast_config_rejects_reserved_equals_in_bare_atoms():
    config, diagnostics = parse_config_with_diagnostics("source => a=b")
    assert config[0][0] == "__config_parse_error__"
    assert diagnostics


def test_config_cache_preserves_nested_scalar_array_shape():
    clear_config_parse_cache()
    first = parse_config('x => [["a", "b"]]')
    assert first == [("x", [["a", "b"]])]
    first_value = first[0][1]
    assert isinstance(first_value, list)
    first_value.append(["polluted"])
    second = parse_config('x => [["a", "b"]]')
    assert second == [("x", [["a", "b"]])]


def test_fast_config_handles_nested_scalar_arrays_without_lark_cache():
    clear_config_parse_cache()
    assert parse_config('x => [["a", "b"], ["c", ["d"]]]') == [("x", [["a", "b"], ["c", ["d"]]])]
    assert config_parse_cache_info().hits == 0
    assert config_parse_cache_info().misses == 0
    assert config_parse_cache_info().currsize == 0


def test_nested_array_config_cache_fast_path_scales_and_returns_fresh_values():
    clear_config_parse_cache()
    config = 'x => [["a", "b"], ["c", ["d", "e"]], ["f", ["g", ["h"]]]]'

    start = time.perf_counter()
    for _ in range(5_000):
        parsed = parse_config(config)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
    assert parsed == [("x", [["a", "b"], ["c", ["d", "e"]], ["f", ["g", ["h"]]]])]
    parsed[0][1].append(["polluted"])
    assert parse_config(config) == [("x", [["a", "b"], ["c", ["d", "e"]], ["f", ["g", ["h"]]]])]
    assert config_parse_cache_info().currsize == 0


def test_fast_config_nested_array_depth_guard_falls_back_to_diagnostic():
    text = "x => " + ("[" * (MAX_CONFIG_NESTING_DEPTH + 1)) + '"a"' + ("]" * (MAX_CONFIG_NESTING_DEPTH + 1))
    config, diagnostics = parse_config_with_diagnostics(text)
    assert config[0][0] == "__config_parse_error__"
    assert diagnostics
    assert f"Config nesting depth exceeds limit of {MAX_CONFIG_NESTING_DEPTH}" in diagnostics[0].message


def test_fast_config_counts_map_depth_for_nested_array_guard():
    text = (
        'replace => { "a" => ' + ("[" * MAX_CONFIG_NESTING_DEPTH) + '"value"' + ("]" * MAX_CONFIG_NESTING_DEPTH) + " }"
    )
    config, diagnostics = parse_config_with_diagnostics(text)
    assert config[0][0] == "__config_parse_error__"
    assert diagnostics
    assert f"Config nesting depth exceeds limit of {MAX_CONFIG_NESTING_DEPTH}" in diagnostics[0].message


def test_standalone_on_error_body_is_not_parsed_as_plugin_config():
    summary = ReverseParser("filter { on_error { source => a=b } }").analysis_summary()
    assert all(w["code"] != "malformed_config" for w in summary["structured_warnings"])


def test_frozen_details_are_reused_and_json_skips_empty_details():
    details = _freeze_details({"target": "payload", "nested": {"k": ["v"]}})
    ref = SourceRef(kind="json_path", source_token="message", path="a", details=details)
    clone = SourceRef(kind="json_path", source_token="message", path="b", details=ref.details)

    assert clone.details is ref.details
    assert "details" not in SourceRef(kind="constant", expression="x").to_json()
    assert ref.to_json()["details"] == {"target": "payload", "nested": {"k": ["v"]}}


def test_with_conditions_long_existing_tuple_uses_set_membership_fast_path():
    lineage = Lineage(status="exact", expression="x", conditions=tuple(f"c{i}" for i in range(4_096)))
    incoming = tuple(f"new{i}" for i in range(8))

    start = time.perf_counter()
    for _ in range(2_000):
        lineage.with_conditions(incoming)
    elapsed = time.perf_counter() - start

    # Budget guards against regression to the O(n) tuple scan, which would
    # take many seconds for 2,000 iterations on a 4,096-element tuple. The
    # fast path (cached frozenset, O(1) lookup) finishes in tens of ms on
    # fast hardware; budget is loose to absorb noisy CI runners (Windows
    # py3.11 GHA observed ~0.5s; macOS/Linux observed <0.05s).
    assert elapsed < 1.5


def test_analyzer_state_clone_uses_cow_for_inferred_token_caches():
    # Regression test for the v0.1.0 release-blocker performance fix.
    #
    # Before the copy-on-write rewrite, ``AnalyzerState.clone()`` eagerly
    # deep-copied ``_inferred_token_generations`` and
    # ``_inferred_token_lineage_keys`` on every fork. With ~3,200 clones
    # touching populated inferred-caches that scaled O(N * dict_size) and
    # produced an 8x wall-clock slowdown in profiling (0.99s of 1.59s spent
    # on the dict-of-set comprehension alone). The COW pattern shares the
    # dicts by reference and only copies on first mutation per clone.
    #
    # This is a microbenchmark rather than a parser-driven workload because
    # the caches are populated by ``_cache_inferred_token`` for inferred
    # JSON members, which is hard to drive in bulk via real fixtures without
    # also exercising large amounts of unrelated analysis.
    state = AnalyzerState()
    for i in range(100):
        state._inferred_token_generations[f"token_{i}"] = (i, i + 1, i + 2, i + 3)
        state._inferred_token_lineage_keys[f"token_{i}"] = {(f"k{j}",) for j in range(20)}

    n = 3_200
    start = time.perf_counter()
    clones = []
    for i in range(n):
        c = state.clone()
        # Trigger COW by popping a key from each cache. Use the public
        # ``.pop()`` path (rather than the COW helper) so the budget bound
        # below catches a regression to the eager-copy clone path and
        # not just the absence of a particular helper.
        c._inferred_token_generations.pop(f"token_{i % 100}", None)
        c._inferred_token_lineage_keys.pop(f"token_{i % 100}", None)
        clones.append(c)
    elapsed = time.perf_counter() - start

    # Budget gives ~4x headroom above the post-fix ~0.03s number; the
    # pre-fix code took ~0.35s for the same loop on the same hardware
    # (12x slower). 3.0s leaves ample slack for slow CI hosts while still
    # catching a regression to the unconditional eager-copy path, which
    # would balloon to several seconds at this iteration count once the
    # inferred-cache dicts inflate to realistic sizes.
    assert elapsed < 3.0

    # Sanity-check COW semantics: parent state remains untouched even
    # though every clone mutated its view of the inferred caches.
    assert len(state._inferred_token_generations) == 100
    assert len(state._inferred_token_lineage_keys) == 100
    # Each clone observed exactly one popped entry, leaving 99 keys.
    for clone in clones:
        assert len(clone._inferred_token_generations) == 99
        assert len(clone._inferred_token_lineage_keys) == 99


def test_analyzer_state_clone_uses_per_kind_cow_for_extractor_hint_index():
    # Regression test for the v0.1.0 release-blocker performance fix (gap P2).
    #
    # Before the per-kind COW rewrite, ``_ensure_extractor_hint_index`` reacted
    # to ``_extractor_hint_index_owned == False`` by deep-copying the index
    # buckets for *every* kind unconditionally — even kinds that hadn't grown
    # since the fork. For a 1000-branch parser that adds a fresh ``json``
    # extractor in each branch and immediately references its dotted target,
    # that meant cloning every kind's hint set on every fork; the inner
    # ``set(values)`` copy alone accounted for ~38% of analysis wall time.
    # Wall scaling 500/1000/2000 → 0.13/0.36/1.24 s (~O(N^1.7)).
    #
    # The post-fix path keeps untouched kinds shared by reference and only
    # deep-copies the kind whose ``len()`` actually changed in this branch.
    n = 1_500
    state = AnalyzerState()

    # Pre-populate every kind with a realistic per-kind hint set so that the
    # pre-fix ``set(values)`` deep copy is expensive enough to detect. Each
    # kind gets 1000 hints with distinct dotted targets, so the index has
    # 1000 buckets per kind, each holding a one-element ``set[int]``. At
    # this size the pre-fix all-kinds eager copy is ~4s while the post-fix
    # per-kind COW copies only json (~0.8s), giving a ~5x signal that the
    # 2.5s budget below catches reliably even on slow CI.
    for kind, store in (
        ("json", state.json_extractions),
        ("kv", state.kv_extractions),
        ("csv", state.csv_extractions),
        ("xml", state.xml_extractions),
    ):
        for i in range(1_000):
            store.append(
                ExtractionHint(
                    kind,
                    "message",
                    {"target": f"{kind}_target_{i}"},
                    parser_locations=[f"line {i}: {kind}"],
                    source_resolved=True,
                )
            )
    # Force the index to materialise on the parent so every clone starts with
    # populated buckets that could have been deep-copied by the buggy path.
    state.extractor_hints_for_token("json", "json_target_0")

    start = time.perf_counter()
    clones = []
    for i in range(n):
        c = state.clone()
        # Add a single new ``json`` extractor in this branch — mirrors the
        # 1000-branch dotted-target workload from the perf review. We go
        # through ``add_extraction_hint`` (rather than appending to the list
        # directly) because ``clone()`` shares the per-kind extraction lists
        # by reference; the public path runs ``_ensure_metadata_owned`` to
        # COW the list before mutating it.
        c.add_extraction_hint(
            "json",
            ExtractionHint(
                "json",
                "message",
                {"target": f"branch_target_{i}"},
                parser_locations=[f"branch {i}"],
                source_resolved=True,
            ),
        )
        # Immediately reference the new target — this is the hot call site
        # that triggers ``_ensure_extractor_hint_index`` and (pre-fix) the
        # full deep-copy of every kind's bucket map.
        hits = c.extractor_hints_for_token("json", f"branch_target_{i}")
        assert hits, "new branch-local hint must be reachable via the index"
        clones.append(c)
    elapsed = time.perf_counter() - start

    # Budget tuned for slow shared CI runners: post-fix wall is ~0.8s on a
    # local dev machine and ~3s on macOS / Ubuntu GitHub-hosted runners. The
    # pre-fix path is ~4s locally and would scale to ~15-20s on those CI
    # runners (5x slower than the post-fix path on the same hardware), so an
    # 8s budget still catches a regression with 100% margin while absorbing
    # CI variance. Don't tighten this without re-measuring the pre-fix wall
    # on the slowest runner in the matrix.
    assert elapsed < 8.0

    # Sanity-check COW semantics: parent's index is untouched and still sized
    # to the original 1000 hints per kind, while every clone sees 1001 json
    # hints (1000 inherited + 1 branch-local).
    assert len(state.json_extractions) == 1_000
    for clone in clones:
        assert len(clone.json_extractions) == 1_001
    # Parent's untouched kinds (kv/csv/xml) stayed shared by reference — the
    # whole point of per-kind COW. We can't observe sharing directly without
    # poking at the ``_extractor_hint_owned_kinds`` flag, so verify that
    # path explicitly: the last clone never touched kv/csv/xml, so those
    # kinds must not be in its owned-kinds set, and the underlying buckets
    # must be the same object as the parent's.
    last_clone = clones[-1]
    assert "json" in last_clone._extractor_hint_owned_kinds
    for shared_kind in ("kv", "csv", "xml"):
        assert shared_kind not in last_clone._extractor_hint_owned_kinds
        assert last_clone._extractor_hint_index[shared_kind] is state._extractor_hint_index[shared_kind]
