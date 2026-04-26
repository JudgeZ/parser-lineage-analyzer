"""Round-trip parity between ``TokenStore.get`` and ``TokenStore.__getitem__``.

The fast-path ``get`` skips the ``MutableMapping`` fallback's ``__getitem__``
+ ``KeyError``-catch cycle. It must stay observationally identical to the
default behavior across every overlay state (fresh, fork+override, append,
delete) and for both present and missing keys.
"""

from __future__ import annotations

from typing import cast

from parser_lineage_analyzer._analysis_state import TokenStore
from parser_lineage_analyzer.model import Lineage, SourceRef


def _lineage(token: str) -> Lineage:
    return Lineage(status="exact", sources=[SourceRef(kind="exact", source_token=token)])


_SENTINEL = object()


def _assert_get_matches_getitem(store: TokenStore, key: str) -> None:
    """Assert ``store.get`` matches what ``Mapping.get`` would return.

    ``Mapping.get`` is defined as ``try: self[key]; except KeyError: default``.
    Our fast path must preserve that contract: present keys return
    ``__getitem__`` value; absent keys (incl. ``__getitem__`` raising) return
    the default. This helper exercises both branches.
    """
    try:
        expected = store[key]
    except KeyError:
        # Match Mapping.get fallback: return default on KeyError.
        assert store.get(key) is None
        assert store.get(key, _SENTINEL) is _SENTINEL
    else:
        assert store.get(key) == expected
        assert store.get(key, _SENTINEL) == expected


def test_fresh_empty_store_get_matches_getitem() -> None:
    store: TokenStore = TokenStore()
    _assert_get_matches_getitem(store, "missing")


def test_populated_store_get_matches_getitem() -> None:
    store = TokenStore(data={"a": [_lineage("a")], "b": [_lineage("b")]})
    _assert_get_matches_getitem(store, "a")
    _assert_get_matches_getitem(store, "b")
    _assert_get_matches_getitem(store, "missing")


def test_forked_store_with_override_get_matches_getitem() -> None:
    base = TokenStore(data={"a": [_lineage("a-base")], "b": [_lineage("b-base")]})
    fork = base.fork(owner=None)
    fork["a"] = [_lineage("a-fork")]
    _assert_get_matches_getitem(fork, "a")  # overridden in fork
    _assert_get_matches_getitem(fork, "b")  # falls through to base
    _assert_get_matches_getitem(fork, "missing")


def test_append_only_get_matches_getitem() -> None:
    base = TokenStore(data={"a": [_lineage("a-base")]})
    fork = base.fork(owner=None)
    fork.append_values("a", [_lineage("a-appended")], existed=True)
    fork.append_values("c", [_lineage("c-only-appended")], existed=False)
    _assert_get_matches_getitem(fork, "a")  # base + appended
    _assert_get_matches_getitem(fork, "c")  # appended-only, no base/data
    _assert_get_matches_getitem(fork, "missing")


def test_delete_in_fork_get_returns_default() -> None:
    base = TokenStore(data={"a": [_lineage("a-base")], "b": [_lineage("b-base")]})
    fork = base.fork(owner=None)
    del fork["a"]
    # `a` is shadowed in fork; both get and __getitem__ must agree.
    _assert_get_matches_getitem(fork, "a")
    assert fork.get("a", _SENTINEL) is _SENTINEL
    _assert_get_matches_getitem(fork, "b")  # untouched
    _assert_get_matches_getitem(fork, "missing")


def test_combined_overlay_states_round_trip() -> None:
    base = TokenStore(
        data={"keep": [_lineage("keep")], "drop": [_lineage("drop")], "shadow": [_lineage("shadow-base")]}
    )
    fork = base.fork(owner=None)
    fork["shadow"] = [_lineage("shadow-fork")]
    fork.append_values("keep", [_lineage("keep-extra")], existed=True)
    fork.append_values("appended-only", [_lineage("appended-only")], existed=False)
    del fork["drop"]

    for key in ("keep", "drop", "shadow", "appended-only", "missing"):
        _assert_get_matches_getitem(fork, key)


def test_get_handles_non_string_keys_safely() -> None:
    store = TokenStore(data={"a": [_lineage("a")]})
    # __contains__ rejects non-str keys; get must mirror that and return default.
    # ``cast`` bypasses the typed overloads so we can exercise the runtime
    # safety net without sprinkling ``# type: ignore`` — the test deliberately
    # violates the ``str`` contract to verify the no-op fallback.
    assert store.get(cast(str, 123)) is None
    assert store.get(cast(str, None), _SENTINEL) is _SENTINEL
