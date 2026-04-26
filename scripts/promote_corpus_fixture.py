#!/usr/bin/env python3
"""Promote / demote a fixture between test_corpus buckets.

Usage:
    promote_corpus_fixture.py <fixture_stem> <target_bucket> [--reason TEXT] [--dry-run]

Where:
    fixture_stem    The fixture file name without the `.cbn` suffix
                    (e.g. `test_array_index`).
    target_bucket   One of: baseline, expected, challenge, bugs, misc.

The script performs the `git mv`, adjusts the bucket-size constants in
``tests/test_corpus_baseline.py`` and ``tests/test_corpus_challenge.py``,
removes the corresponding hand-written test from ``tests/test_corpus_bugs.py``
when promoting out of ``bugs/``, and appends a one-line entry to
``tests/fixtures/test_corpus/PROMOTION_LOG.md``.

Use ``--dry-run`` to preview the planned moves and edits without applying them.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re

# Dev-only fixture promotion script; only invokes `git mv` with literal args.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path

BUCKETS = ("baseline", "expected", "challenge", "bugs", "misc")
SMOKE_BUCKETS = ("baseline", "expected", "misc")


@dataclass(frozen=True)
class PromotionPaths:
    """Path bundle so the script is testable against a tempdir."""

    repo_root: Path

    @property
    def corpus_root(self) -> Path:
        return self.repo_root / "tests" / "fixtures" / "test_corpus"

    @property
    def baseline_test(self) -> Path:
        return self.repo_root / "tests" / "test_corpus_baseline.py"

    @property
    def challenge_test(self) -> Path:
        return self.repo_root / "tests" / "test_corpus_challenge.py"

    @property
    def bugs_test(self) -> Path:
        return self.repo_root / "tests" / "test_corpus_bugs.py"

    @property
    def log(self) -> Path:
        return self.corpus_root / "PROMOTION_LOG.md"


_DEFAULT_PATHS = PromotionPaths(Path(__file__).resolve().parent.parent)


def _find_fixture(stem: str, paths: PromotionPaths) -> Path:
    matches: list[Path] = []
    for bucket in BUCKETS:
        candidate = paths.corpus_root / bucket / f"{stem}.cbn"
        if candidate.exists():
            matches.append(candidate)
    if not matches:
        raise SystemExit(f"error: no fixture {stem}.cbn found in any bucket")
    if len(matches) > 1:
        raise SystemExit(f"error: fixture {stem}.cbn exists in multiple buckets: {matches}")
    return matches[0]


def _git_mv(src: Path, dst: Path, paths: PromotionPaths, dry_run: bool, *, use_git: bool) -> None:
    rel_src = src.relative_to(paths.repo_root)
    rel_dst = dst.relative_to(paths.repo_root)
    if dry_run:
        print(f"[dry-run] git mv {rel_src} {rel_dst}")
        return
    if use_git:
        # Dev-only `git mv` with list-form args; `git` is resolved via PATH by design.
        subprocess.run(  # nosec B607, B603
            ["git", "mv", str(src), str(dst)],
            cwd=paths.repo_root,
            check=True,
        )
    else:
        # Test path: tempdirs aren't git repos. Plain rename keeps the
        # integration test self-contained.
        dst.parent.mkdir(parents=True, exist_ok=True)
        src.rename(dst)


def _adjust_smoke_bucket_size(test_file: Path, bucket: str, delta: int, dry_run: bool) -> None:
    """Bump the integer in `expected = {"<bucket>": N, ...}` mapping."""
    text = test_file.read_text(encoding="utf-8")
    pattern = re.compile(rf'("{bucket}":\s*)(\d+)')
    new_text, n = pattern.subn(
        lambda m: f"{m.group(1)}{int(m.group(2)) + delta}",
        text,
        count=1,
    )
    if n == 0:
        return  # no constant to adjust in this test file
    if dry_run:
        print(f"[dry-run] {test_file.name}: bump {bucket!r} constant by {delta:+d}")
        return
    test_file.write_text(new_text, encoding="utf-8")


def _adjust_challenge_bucket_size(test_file: Path, delta: int, dry_run: bool) -> None:
    """Bump the bare integer in `expected = N` inside `test_challenge_bucket_size`.

    The challenge test file uses a single integer constant rather than the
    smoke-bucket dict shape, so the smoke regex never matched it. Match the
    `expected = <int>` line scoped to the `def test_challenge_bucket_size()`
    function body.
    """
    text = test_file.read_text(encoding="utf-8")
    func_re = re.compile(
        r"(def test_challenge_bucket_size\(.*?\n)(.*?)(?=^def |\Z)",
        re.DOTALL | re.MULTILINE,
    )
    match = func_re.search(text)
    if not match:
        if dry_run:
            print(f"[dry-run] {test_file.name}: no test_challenge_bucket_size to adjust")
        return
    body = match.group(2)
    new_body, n = re.subn(
        r"(expected\s*=\s*)(\d+)",
        lambda m: f"{m.group(1)}{int(m.group(2)) + delta}",
        body,
        count=1,
    )
    if n == 0:
        return
    if dry_run:
        print(f"[dry-run] {test_file.name}: bump challenge bucket constant by {delta:+d}")
        return
    test_file.write_text(text[: match.start(2)] + new_body + text[match.end(2) :], encoding="utf-8")


def _adjust_bug_count(test_file: Path, delta: int, dry_run: bool) -> None:
    text = test_file.read_text(encoding="utf-8")
    pattern = re.compile(r"(assert len\(files\) == )(\d+)")
    new_text, n = pattern.subn(lambda m: f"{m.group(1)}{int(m.group(2)) + delta}", text, count=1)
    if n == 0:
        return
    if dry_run:
        print(f"[dry-run] {test_file.name}: bump bug-bucket count by {delta:+d}")
        return
    test_file.write_text(new_text, encoding="utf-8")


def _remove_bug_test(test_file: Path, stem: str, dry_run: bool) -> bool:
    """Remove a test_bug_<stem...> function from the bugs test file.

    Two ways to find the function:

    1. **Explicit metadata (R5.3, preferred):** the function carries a
       ``# fixture: <stem>`` line in its body or docstring. This is the
       reliable mechanism — names can drift from fixture stems, but the
       metadata marker doesn't.
    2. **Prefix heuristic (fallback):** the function name begins with
       ``test_bug_<short>`` where ``<short>`` is ``stem`` minus the leading
       ``test_``. Used when no metadata marker exists yet (legacy tests).

    Returns True if a test was removed.
    """
    text = test_file.read_text(encoding="utf-8")
    # First pass: look for an explicit `# fixture: <stem>` marker. The marker
    # may live anywhere inside the function body (including the docstring),
    # so we walk every `def test_bug_*` block and inspect its body.
    func_block_re = re.compile(
        r"(?ms)^(?:@pytest\.mark\.[^\n]+\n)*def (test_bug_\w+)\(.*?(?=^(?:@pytest|def )|^# ----|\Z)"
    )
    marker = re.compile(rf"#\s*fixture:\s*{re.escape(stem)}\b")
    for func_match in func_block_re.finditer(text):
        if marker.search(func_match.group(0)):
            func_name = func_match.group(1)
            if dry_run:
                print(f"[dry-run] {test_file.name}: remove function {func_name}() (matched via fixture-marker)")
                return True
            test_file.write_text(text[: func_match.start()] + text[func_match.end() :], encoding="utf-8")
            return True
    # Fallback: prefix heuristic.
    short = stem[len("test_") :] if stem.startswith("test_") else stem
    func_prefix = f"test_bug_{short}"
    pattern = re.compile(
        rf"(?ms)^(?:@pytest\.mark\.[^\n]+\n)*def ({re.escape(func_prefix)}\w*)\(.*?(?=^(?:@pytest|def )|^# ----|\Z)"
    )
    match = pattern.search(text)
    if not match:
        return False
    func_name = match.group(1)
    if dry_run:
        print(f"[dry-run] {test_file.name}: remove function {func_name}()")
        return True
    test_file.write_text(text[: match.start()] + text[match.end() :], encoding="utf-8")
    return True


def _append_log(log_file: Path, src_bucket: str, stem: str, dst_bucket: str, reason: str, dry_run: bool) -> None:
    today = _dt.date.today().isoformat()
    entry = f"{today} {src_bucket}/{stem}.cbn → {dst_bucket}/ ({reason})\n"
    if dry_run:
        print(f"[dry-run] append to {log_file.name}: {entry.rstrip()}")
        return
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(entry)


def promote(
    fixture_stem: str,
    target_bucket: str,
    *,
    reason: str = "",
    dry_run: bool = False,
    paths: PromotionPaths | None = None,
    use_git: bool = True,
) -> int:
    """Programmatic entry point — used by the CLI and the integration test."""
    paths = paths or _DEFAULT_PATHS
    if target_bucket not in BUCKETS:
        raise SystemExit(f"error: target_bucket must be one of {BUCKETS}; got {target_bucket!r}")
    src = _find_fixture(fixture_stem, paths)
    src_bucket = src.parent.name
    if src_bucket == target_bucket:
        raise SystemExit(f"error: fixture is already in {target_bucket}/")
    dst = paths.corpus_root / target_bucket / src.name

    print(f"Promoting {fixture_stem}.cbn: {src_bucket}/ → {target_bucket}/")
    _git_mv(src, dst, paths, dry_run, use_git=use_git)

    # Adjust bucket-size constants.
    if src_bucket in SMOKE_BUCKETS:
        _adjust_smoke_bucket_size(paths.baseline_test, src_bucket, -1, dry_run)
    if target_bucket in SMOKE_BUCKETS:
        _adjust_smoke_bucket_size(paths.baseline_test, target_bucket, +1, dry_run)
    if src_bucket == "challenge":
        _adjust_challenge_bucket_size(paths.challenge_test, -1, dry_run)
    if target_bucket == "challenge":
        _adjust_challenge_bucket_size(paths.challenge_test, +1, dry_run)
    if src_bucket == "bugs":
        _adjust_bug_count(paths.bugs_test, -1, dry_run)
        removed = _remove_bug_test(paths.bugs_test, fixture_stem, dry_run)
        if not removed:
            print(
                f"warning: no test_bug_* function for {fixture_stem} found in "
                f"{paths.bugs_test.name}; you may need to remove it manually"
            )
    if target_bucket == "bugs":
        _adjust_bug_count(paths.bugs_test, +1, dry_run)
        print(f"NOTE: add a hand-written test_bug_* function for {fixture_stem} to {paths.bugs_test.name}")

    _append_log(paths.log, src_bucket, fixture_stem, target_bucket, reason or "promotion", dry_run)

    if dry_run:
        print("\n[dry-run complete — re-run without --dry-run to apply]")
    else:
        print("\nDone. Run `pytest tests/test_corpus_baseline.py tests/test_corpus_bugs.py -q` to verify.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_stem", help="fixture file name without .cbn suffix")
    parser.add_argument("target_bucket", choices=BUCKETS)
    parser.add_argument("--reason", default="", help="reason text for the log entry")
    parser.add_argument("--dry-run", action="store_true", help="preview without applying")
    args = parser.parse_args(argv)
    return promote(
        args.fixture_stem,
        args.target_bucket,
        reason=args.reason,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
