"""Runtime-checked narrowing helpers for ``analysis_summary()`` payloads.

``analysis_summary()`` returns a ``JSONDict`` (i.e. ``Mapping[str, JSONValue]``).
Values are typed as the recursive ``JSONValue`` union, which mypy refuses to
index, iterate, or treat as comparable. Tests know — by construction of the
underlying dataclasses — that specific summary keys are always lists, dicts,
or strings, but that knowledge is not expressed in the public type.

These helpers narrow a ``JSONValue`` (or any object) to the form the test
expects. They double as runtime guards: if the analyzer ever drifts and a
summary key starts holding a different shape, the assertion fires before the
test produces a misleading downstream failure.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from parser_lineage_analyzer._types import JSONValue


def expect_list(value: object) -> Sequence[JSONValue]:
    """Narrow a ``JSONValue`` to its ``Sequence`` form for test assertions."""
    assert isinstance(value, list), f"expected list, got {type(value).__name__}"
    return value


def expect_mapping(value: object) -> Mapping[str, JSONValue]:
    """Narrow a ``JSONValue`` to its ``Mapping`` form for test assertions."""
    assert isinstance(value, dict), f"expected dict, got {type(value).__name__}"
    return value


def expect_str(value: object) -> str:
    """Narrow a ``JSONValue`` to ``str`` for test assertions."""
    assert isinstance(value, str), f"expected str, got {type(value).__name__}"
    return value


def expect_str_list(value: object) -> list[str]:
    """Narrow a ``JSONValue`` to ``list[str]`` for test assertions.

    Used when the test joins/iterates a list whose elements are known to be
    strings (e.g. ``summary["unsupported"]`` is always ``list[str]`` even
    though the public type is ``JSONValue``).
    """
    assert isinstance(value, list), f"expected list, got {type(value).__name__}"
    out: list[str] = []
    for item in value:
        assert isinstance(item, str), f"expected str element, got {type(item).__name__}"
        out.append(item)
    return out


def expect_mapping_list(value: object) -> list[Mapping[str, JSONValue]]:
    """Narrow a ``JSONValue`` to ``list[Mapping[str, JSONValue]]``.

    Used for ``summary["structured_warnings"]`` whose elements are always
    dict-like ``WarningReason.to_json()`` payloads.
    """
    assert isinstance(value, list), f"expected list, got {type(value).__name__}"
    out: list[Mapping[str, JSONValue]] = []
    for item in value:
        assert isinstance(item, dict), f"expected dict element, got {type(item).__name__}"
        out.append(item)
    return out
