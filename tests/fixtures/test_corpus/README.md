# Test Corpus

580 `.cbn` fixtures adopted from a curated set under `examples/test_*.cbn`.
Each fixture's top-of-file comment describes its claim about analyzer
behavior. Fixtures live in topical buckets:

| Bucket | Count | Contract |
|--------|-------|----------|
| `baseline/` | 126 | Validates a parser feature today. Smoke test asserts no crash + no parse-recovery diagnostics. |
| `expected/` | 195 | Asserts what the analyzer *should* produce. Smoke test asserts no crash + no parse-recovery. |
| `misc/` | 3 | Free-form description; same smoke contract as baseline. |
| `challenge/` | 224 | Stress / pathological input. Asserts the analyzer terminates within 60s. |
| `bugs/` | 32 | Real analyzer bugs (or claims of bugs). Each has a hand-written test in `tests/test_corpus_bugs.py`; unfixed bugs are `@pytest.mark.xfail(strict=True)`. |

## Test files that consume this corpus

- [tests/test_corpus_baseline.py](../../test_corpus_baseline.py) — parametrized smoke for `baseline`/`expected`/`misc`.
- [tests/test_corpus_challenge.py](../../test_corpus_challenge.py) — parametrized stress for `challenge`.
- [tests/test_corpus_bugs.py](../../test_corpus_bugs.py) — hand-written per-bug assertions.

## Promoting / demoting fixtures

When the analyzer fix for a bug lands, **promote** the fixture from `bugs/` to
`expected/` (or `baseline/` if appropriate) so it's exercised by the
smoke-coverage parametrized test instead of the hand-written xfail test.

When you discover a regression in a fixture currently under `baseline/` or
`expected/`, **demote** it to `bugs/` and write a per-fixture test in
`tests/test_corpus_bugs.py` that documents the new gap.

Use the helper script — it does the `git mv`, updates the bucket-size
assertions, removes the corresponding hand-written test (if promoting), and
appends to `PROMOTION_LOG.md`:

```bash
# Dry-run preview
venv/bin/python scripts/promote_corpus_fixture.py test_array_index expected --dry-run

# Apply
venv/bin/python scripts/promote_corpus_fixture.py test_array_index expected --reason "fixed in commit abc123"
```

The script will fail loudly if the fixture name is ambiguous, the destination
bucket doesn't exist, or the resulting state would break the bucket-size
assertions in the test files.

## Sidecar assertions (Phase C)

Beyond the smoke contract, fixtures may carry a sibling
`<name>.expected.json` file with structured claims:

```json
{
  "must_have_warning_codes": ["dynamic_destination"],
  "must_resolve_fields": ["target.ip"],
  "must_have_unsupported": ["http"]
}
```

If a sidecar exists, `tests/test_corpus_baseline.py` asserts each declared
contract in addition to the smoke checks. See the test file for the full
sidecar schema.

## Layout

```
tests/fixtures/test_corpus/
├── README.md              ← this file
├── PROMOTION_LOG.md       ← append-only changelog
├── baseline/              ← 126 BASELINE fixtures
├── expected/              ← 195 EXPECTED BEHAVIOR fixtures (some with sidecars)
├── challenge/             ← 224 stress fixtures
├── bugs/                  ← 32 bug fixtures (each with a hand-written test)
└── misc/                  ← 3 free-form fixtures
```
