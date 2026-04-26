"""Integration tests for the corpus promotion script.

Builds a tiny stub corpus + stub test files in a tempdir and runs the
promotion script against them to validate the live `--apply` path. The real
corpus is never touched.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "promote_corpus_fixture.py"


def _load_script_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("promote_corpus_fixture", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["promote_corpus_fixture"] = module
    spec.loader.exec_module(module)
    return module


if TYPE_CHECKING:
    # The script is loaded dynamically at runtime via importlib (so the test
    # exercises the same file the orchestrator invokes). Mypy can't follow
    # that, so we also import it statically under TYPE_CHECKING only — no
    # runtime cost, but the static import lets mypy resolve attribute access
    # on ``_SCRIPT`` (e.g. ``_SCRIPT.PromotionPaths``).
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import promote_corpus_fixture as _SCRIPT
else:
    _SCRIPT = _load_script_module()


_BASELINE_TEST_TEMPLATE = '''
"""Stub baseline test."""
expected = {"baseline": 3, "expected": 5, "misc": 1}
'''.lstrip()


_CHALLENGE_TEST_TEMPLATE = '''
"""Stub challenge test."""

def test_challenge_bucket_size():
    expected = 2
    assert expected >= 0
'''.lstrip()


_BUGS_TEST_TEMPLATE = '''
"""Stub bugs test."""
import pytest


@pytest.mark.xfail(strict=True, reason="not yet fixed")
def test_bug_demo_widget_unwrapping():
    raise AssertionError("nope")


def test_bug_other_thing():
    pass


def test_bug_bucket_size():
    files = list(range(2))
    assert len(files) == 2
'''.lstrip()


def _make_stub_repo(tmp_path: Path) -> _SCRIPT.PromotionPaths:
    """Build a minimal repo layout that the promotion script can operate on."""
    corpus = tmp_path / "tests" / "fixtures" / "test_corpus"
    for bucket in _SCRIPT.BUCKETS:
        (corpus / bucket).mkdir(parents=True, exist_ok=True)
    (corpus / "PROMOTION_LOG.md").write_text("# Log\n\n", encoding="utf-8")
    (corpus / "bugs" / "test_demo_widget.cbn").write_text("filter { mutate {} }\n", encoding="utf-8")
    (corpus / "challenge" / "test_other_challenge.cbn").write_text("filter {}\n", encoding="utf-8")
    (tmp_path / "tests" / "test_corpus_baseline.py").write_text(_BASELINE_TEST_TEMPLATE, encoding="utf-8")
    (tmp_path / "tests" / "test_corpus_challenge.py").write_text(_CHALLENGE_TEST_TEMPLATE, encoding="utf-8")
    (tmp_path / "tests" / "test_corpus_bugs.py").write_text(_BUGS_TEST_TEMPLATE, encoding="utf-8")
    return _SCRIPT.PromotionPaths(repo_root=tmp_path)


def test_promote_bug_to_expected_applies_all_edits(tmp_path: Path) -> None:
    paths = _make_stub_repo(tmp_path)

    rc = _SCRIPT.promote(
        "test_demo_widget",
        "expected",
        reason="fixed in stub commit",
        paths=paths,
        use_git=False,
    )
    assert rc == 0

    # Fixture moved.
    assert not (paths.corpus_root / "bugs" / "test_demo_widget.cbn").exists()
    assert (paths.corpus_root / "expected" / "test_demo_widget.cbn").exists()

    # Baseline-test 'expected' constant bumped from 5 → 6.
    baseline_text = paths.baseline_test.read_text(encoding="utf-8")
    assert '"expected": 6' in baseline_text
    assert '"baseline": 3' in baseline_text  # unchanged

    # Bugs-test bucket count bumped from 2 → 1.
    bugs_text = paths.bugs_test.read_text(encoding="utf-8")
    assert "assert len(files) == 1" in bugs_text

    # The bug function was removed (the demo_widget one), the unrelated one stays.
    assert "def test_bug_demo_widget_unwrapping" not in bugs_text
    assert "def test_bug_other_thing" in bugs_text
    # Its xfail decorator should be gone too.
    assert 'reason="not yet fixed"' not in bugs_text

    # Log appended.
    log_text = paths.log.read_text(encoding="utf-8")
    assert "bugs/test_demo_widget.cbn → expected/" in log_text
    assert "fixed in stub commit" in log_text


def test_promote_challenge_bucket_size_constant_is_adjusted(tmp_path: Path) -> None:
    paths = _make_stub_repo(tmp_path)

    rc = _SCRIPT.promote(
        "test_other_challenge",
        "baseline",
        reason="reclassified",
        paths=paths,
        use_git=False,
    )
    assert rc == 0

    # Challenge constant bumped from 2 → 1.
    challenge_text = paths.challenge_test.read_text(encoding="utf-8")
    assert "expected = 1" in challenge_text

    # Baseline 'baseline' bumped from 3 → 4.
    assert '"baseline": 4' in paths.baseline_test.read_text(encoding="utf-8")


def test_promote_to_bugs_bumps_count_and_warns_about_test_function(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _make_stub_repo(tmp_path)
    # First move challenge to bugs (so the challenge constant is exercised in
    # the demote direction too).
    rc = _SCRIPT.promote(
        "test_other_challenge",
        "bugs",
        paths=paths,
        use_git=False,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "NOTE: add a hand-written test_bug_*" in out

    challenge_text = paths.challenge_test.read_text(encoding="utf-8")
    assert "expected = 1" in challenge_text
    bugs_text = paths.bugs_test.read_text(encoding="utf-8")
    assert "assert len(files) == 3" in bugs_text


def test_promote_dry_run_makes_no_changes(tmp_path: Path) -> None:
    paths = _make_stub_repo(tmp_path)
    baseline_before = paths.baseline_test.read_text(encoding="utf-8")
    bugs_before = paths.bugs_test.read_text(encoding="utf-8")
    log_before = paths.log.read_text(encoding="utf-8")

    rc = _SCRIPT.promote(
        "test_demo_widget",
        "expected",
        dry_run=True,
        paths=paths,
        use_git=False,
    )
    assert rc == 0

    # Nothing moved.
    assert (paths.corpus_root / "bugs" / "test_demo_widget.cbn").exists()
    assert not (paths.corpus_root / "expected" / "test_demo_widget.cbn").exists()
    # Files unchanged.
    assert paths.baseline_test.read_text(encoding="utf-8") == baseline_before
    assert paths.bugs_test.read_text(encoding="utf-8") == bugs_before
    assert paths.log.read_text(encoding="utf-8") == log_before


def test_promote_finds_function_via_fixture_marker(tmp_path: Path) -> None:
    """R5.3: the explicit ``# fixture: <stem>`` marker beats the prefix
    heuristic. Add a stub function whose name does NOT match the prefix
    pattern but DOES carry the marker — promote should still find and
    remove it."""
    paths = _make_stub_repo(tmp_path)
    # Add a function whose name doesn't match the demo_widget prefix but
    # carries the marker.
    extra_function = '''

def test_bug_some_other_renamed_function():
    """Bug test for the demo widget — different name, marker matches."""
    # fixture: test_demo_widget
    pass
'''
    paths.bugs_test.write_text(paths.bugs_test.read_text(encoding="utf-8") + extra_function, encoding="utf-8")

    rc = _SCRIPT.promote(
        "test_demo_widget",
        "expected",
        reason="marker-driven removal",
        paths=paths,
        use_git=False,
    )
    assert rc == 0
    bugs_text = paths.bugs_test.read_text(encoding="utf-8")
    # The marker-tagged function was removed.
    assert "test_bug_some_other_renamed_function" not in bugs_text
    # The unrelated function stays.
    assert "def test_bug_other_thing" in bugs_text


def test_promote_rejects_unknown_fixture(tmp_path: Path) -> None:
    paths = _make_stub_repo(tmp_path)
    with pytest.raises(SystemExit, match="no fixture"):
        _SCRIPT.promote("nonexistent", "baseline", paths=paths, use_git=False)


def test_promote_rejects_same_source_target_bucket(tmp_path: Path) -> None:
    paths = _make_stub_repo(tmp_path)
    with pytest.raises(SystemExit, match="already in bugs/"):
        _SCRIPT.promote("test_demo_widget", "bugs", paths=paths, use_git=False)


@pytest.mark.skipif(shutil.which("git") is None, reason="git binary not on PATH")
def test_promote_real_git_mv_keeps_index_consistent(tmp_path: Path) -> None:
    """R5.1: cover the live `git mv` path against an actual git repo so the
    integration isn't only exercised via subprocess in production. Builds the
    same stub layout as other tests but inside a real `git init`-backed
    tempdir, commits the initial state, then runs `promote(... use_git=True)`
    and verifies git tracks the move (no untracked leftovers, the .cbn shows
    up as 'renamed' in `git status`).
    """
    paths = _make_stub_repo(tmp_path)

    # Initialize a real repo so `git mv` has somewhere to operate.
    def _git(*args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
            env={
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "PATH": __import__("os").environ.get("PATH", ""),
                "HOME": str(tmp_path),
            },
        )
        return result.stdout

    _git("init", "-b", "main")
    _git("add", "-A")
    _git("commit", "-m", "initial corpus stub")

    rc = _SCRIPT.promote(
        "test_demo_widget",
        "expected",
        reason="real-git integration",
        paths=paths,
        use_git=True,
    )
    assert rc == 0

    # Fixture moved on disk.
    assert not (paths.corpus_root / "bugs" / "test_demo_widget.cbn").exists()
    assert (paths.corpus_root / "expected" / "test_demo_widget.cbn").exists()

    # Git index reflects the rename.
    status = _git("status", "--porcelain=v1")
    # `git mv` produces an `R` (renamed) status entry for the .cbn file.
    assert (
        "R  tests/fixtures/test_corpus/bugs/test_demo_widget.cbn -> tests/fixtures/test_corpus/expected/test_demo_widget.cbn"
        in status
    ), status
    # No stray untracked entries from the move itself.
    untracked_lines = [line for line in status.splitlines() if line.startswith("?? ")]
    untracked_paths = {line[3:] for line in untracked_lines}
    # The post-promotion log update + test file edits ARE legitimate untracked/
    # modified entries from the script — but the .cbn must not appear as
    # untracked at the destination.
    assert "tests/fixtures/test_corpus/expected/test_demo_widget.cbn" not in untracked_paths
