from __future__ import annotations

import json

from parser_lineage_analyzer._plugin_signatures import load_bundled_registry
from scripts import compat_audit_corpus


def test_compat_audit_writes_json_and_markdown(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "a.cbn").write_text(
        'filter { grok { match => { "message" => "%{IP:src_ip}" } } }\n',
        encoding="utf-8",
    )
    (root / "b.cbn").write_text(
        'filter { custom_lookup { target => "event.idm.read_only_udm.target.ip" } }\n',
        encoding="utf-8",
    )

    audit = compat_audit_corpus.audit_corpus(root, ["secops"])
    json_out = tmp_path / "out" / "compat.json"
    md_out = tmp_path / "out" / "compat.md"
    compat_audit_corpus.write_outputs(audit, json_out, md_out)

    payload = json.loads(json_out.read_text(encoding="utf-8"))
    markdown = md_out.read_text(encoding="utf-8")

    assert payload["parser_count"] == 2
    assert [entry["path"] for entry in payload["reports_by_dialect"]["secops"]] == ["a.cbn", "b.cbn"]
    assert payload["totals_by_dialect"]["secops"]["totals"]["unsupported_plugins"] == 1
    assert payload["totals_by_dialect"]["secops"]["unsupported_plugin_counts"] == {"custom_lookup": 1}
    assert "# Parser Compatibility Audit" in markdown
    assert "Unsupported Plugins" in markdown


def test_compat_audit_main_honors_dialects_and_regression_baseline(tmp_path, capsys):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "a.cbn").write_text('filter { custom_lookup { target => "x" } }\n', encoding="utf-8")

    current_json = tmp_path / "audit.json"
    current_md = tmp_path / "audit.md"
    rc = compat_audit_corpus.main(
        [
            "--root",
            str(root),
            "--dialect",
            "secops",
            "--json-out",
            str(current_json),
            "--md-out",
            str(current_md),
        ]
    )
    assert rc == 0
    payload = json.loads(current_json.read_text(encoding="utf-8"))
    assert payload["dialects"] == ["secops"]

    baseline = payload.copy()
    baseline["totals_by_dialect"] = {
        "secops": {
            **payload["totals_by_dialect"]["secops"],
            "totals": {**payload["totals_by_dialect"]["secops"]["totals"], "unsupported_plugins": 0},
        }
    }
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    rc = compat_audit_corpus.main(
        [
            "--root",
            str(root),
            "--dialect",
            "secops",
            "--json-out",
            str(tmp_path / "audit2.json"),
            "--md-out",
            str(tmp_path / "audit2.md"),
            "--fail-on-regression",
            str(baseline_path),
        ]
    )
    assert rc == 1
    assert "unsupported_plugins regressed from 0 to 1" in capsys.readouterr().err


def test_compat_audit_can_use_bundled_signatures_to_reduce_unsupported_counts(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "a.cbn").write_text('filter { throttle { key => "%{message}" } }\n', encoding="utf-8")

    without_signatures = compat_audit_corpus.audit_corpus(root, ["secops"])
    with_signatures = compat_audit_corpus.audit_corpus(root, ["secops"], plugin_signatures=load_bundled_registry())

    assert without_signatures["totals_by_dialect"]["secops"]["totals"]["unsupported_plugins"] == 1
    assert with_signatures["totals_by_dialect"]["secops"]["totals"].get("unsupported_plugins", 0) == 0
    assert with_signatures["plugin_signatures"]["enabled"] is True
