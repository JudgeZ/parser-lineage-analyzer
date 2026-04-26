# Contributing

Thanks for your interest in `parser-lineage-analyzer`. This project is small,
opinionated, and aims for a high test/lint/security bar; please keep that in
mind when proposing changes.

## Reporting bugs

Open a GitHub issue: https://github.com/JudgeZ/parser-lineage-analyzer/issues

Include the `parser-lineage-analyzer --version` output, a minimal parser file
(or fragment), the exact command you ran, and the observed vs. expected
behavior. Note whether the native extension is enabled (default) or disabled
(`PARSER_LINEAGE_ANALYZER_NO_EXT=1`); if you can, reproduce both ways.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. Follow the private
disclosure process in [`SECURITY.md`](SECURITY.md), which routes through
GitHub Security Advisories.

## Local development setup

Requires Python 3.10+. Cython is needed at install time when building the
native extensions (default).

```bash
git clone https://github.com/JudgeZ/parser-lineage-analyzer.git
cd parser-lineage-analyzer
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Environment toggles for the native build:

- `PARSER_LINEAGE_ANALYZER_NO_EXT=1` — skip building the C extensions and
  use the pure-Python fallbacks. Useful when Cython or a C toolchain is
  unavailable.
- `PARSER_LINEAGE_ANALYZER_REQUIRE_EXT=1` — fail the build if any native
  extension cannot be compiled (instead of silently falling back).

## Running tests

```bash
python -m pytest -q
```

Toggle the native modules off for the entire run:

```bash
PARSER_LINEAGE_ANALYZER_NO_EXT=1 python -m pytest
```

Per-extension toggles let you isolate the pure-Python path for a single
component while leaving the others native:

- `PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE=0`
- `PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE=0`

## Lint and type-check

The CI bar is the same set of commands a contributor runs locally:

```bash
ruff format --check parser_lineage_analyzer scripts tests fuzz setup.py
ruff check parser_lineage_analyzer scripts tests fuzz setup.py
mypy parser_lineage_analyzer
bandit -c pyproject.toml -r parser_lineage_analyzer scripts -ll
```

`bandit` is configured to fail on medium-or-higher severity findings.

## Building wheels

Local sdist + abi3 wheel:

```bash
python -m build
```

This produces a single CPython abi3 wheel that works on CPython 3.10+ on the
host platform. For cross-platform / cross-arch builds, the project uses
[cibuildwheel](https://cibuildwheel.readthedocs.io/) — see
`.github/workflows/wheels.yml` for the matrix.

## Pull request process

- Open the PR against `main`.
- Ensure the full CI matrix is green: pure-Python tests across all supported
  Python/OS combinations, abi3 wheel tests, lint, mypy, bandit, and
  pip-audit. PRs are not merged on red CI.
- Commit messages follow the conventional-commit-ish style visible in
  `git log --oneline` (`feat:`, `fix:`, `ci:`, `docs:`, `release:`, etc.).
  Imperative mood, lowercase scope, no trailing period.
- Keep PRs focused. Refactors and unrelated cleanups belong in separate PRs
  from feature work or fixes.
- New behavior needs tests. New external-input surface area should ideally
  also get a fuzz harness in `fuzz/`.

## Architecture notes

For the parser/IR model, the analyzer pipeline, the native-extension layout,
and the dedupe/branch-merge invariants, see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
