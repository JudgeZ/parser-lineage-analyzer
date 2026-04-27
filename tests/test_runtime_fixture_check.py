from __future__ import annotations

import json

from scripts import runtime_fixture_check


def test_runtime_fixture_check_passes_checked_in_fixture():
    report = runtime_fixture_check.check_runtime_fixtures(runtime_fixture_check.DEFAULT_ROOT)

    assert report["fixture_count"] >= 1
    assert report["failed"] == 0


def test_runtime_fixture_check_reports_missing_static_coverage(tmp_path, capsys):
    fixture = tmp_path / "runtime" / "bad"
    fixture.mkdir(parents=True)
    (fixture / "parser.cbn").write_text('filter { mutate { replace => { "seen" => "yes" } } }\n', encoding="utf-8")
    (fixture / "input.json").write_text('{"message":"x"}\n', encoding="utf-8")
    (fixture / "expected.json").write_text(
        json.dumps({"touched_fields": ["missing"], "tags": ["missing_tag"], "output_anchors": ["event"]}),
        encoding="utf-8",
    )

    report = runtime_fixture_check.check_runtime_fixtures(tmp_path / "runtime")

    assert report["failed"] == 1
    assert report["results"][0]["failures"]["missing_fields"] == ["missing"]
    assert runtime_fixture_check.main(["--root", str(tmp_path / "runtime")]) == 1
    assert "runtime fixture mismatch" in capsys.readouterr().err


def test_runtime_fixture_check_honors_fixture_dialect(tmp_path):
    fixture = tmp_path / "runtime" / "logstash"
    fixture.mkdir(parents=True)
    (fixture / "parser.cbn").write_text('filter { json { source => "message" } }\n', encoding="utf-8")
    (fixture / "input.json").write_text('{"message":"not-json"}\n', encoding="utf-8")
    (fixture / "expected.json").write_text(
        json.dumps({"dialect": "logstash", "tags": ["_jsonparsefailure"]}),
        encoding="utf-8",
    )

    report = runtime_fixture_check.check_runtime_fixtures(tmp_path / "runtime")

    assert report["failed"] == 0
    assert report["results"][0]["dialect"] == "logstash"
