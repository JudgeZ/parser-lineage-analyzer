# Test Corpus Promotion Log

Append-only log of fixture promotions / demotions across the
`tests/fixtures/test_corpus/{baseline,expected,challenge,bugs,misc}/` buckets.

Format: `YYYY-MM-DD <from>/<name> → <to>/ (<reason>)`.

When you move a fixture, run `scripts/promote_corpus_fixture.py <name> <to>`
which performs the move, adjusts bucket-size assertions in
`tests/test_corpus_baseline.py` and `tests/test_corpus_bugs.py`, and appends an
entry here.

## History

2026-04-25 examples/ → tests/fixtures/test_corpus/{baseline,expected,challenge,bugs,misc}/ (initial 580-fixture adoption — see `/Users/gamer/.claude/plans/test-corpus-adoption.md`)
