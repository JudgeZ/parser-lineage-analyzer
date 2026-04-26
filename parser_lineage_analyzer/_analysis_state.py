"""Mutable analysis state for the reverse-lineage executor."""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, MutableMapping, Set as AbstractSet
from dataclasses import dataclass, field
from re import Pattern
from typing import Protocol, TypeVar, cast, overload

from ._analysis_dedupe import Key, _freeze_value
from ._analysis_helpers import (
    _anchor_key,
    _dedupe_lineages,
    _dedupe_sources,
    _dedupe_strings,
    _diagnostic_key,
    _hint_key,
    _lineage_key,
    _looks_like_udm_field,
    _taint_key,
    _warning_key,
)
from ._analysis_templates import (
    dynamic_template_bucket_literal,
    dynamic_template_literals,
    dynamic_template_matches,
    dynamic_template_pattern_text,
)
from ._types import FrozenJSONDict, JSONDict
from .model import (
    DiagnosticRecord,
    IOAnchor,
    Lineage,
    OutputAnchor,
    SourceRef,
    TaintReason,
    WarningReason,
    _details_to_json,
    _freeze_details,
    _freeze_for_key,
)

MAX_EXACT_DROP_CONDITIONS = 32
MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES = 128
MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES = 4096
MIN_TOKEN_LINEAGE_KEY_CACHE_VALUES = 8
MAX_UNTARGETED_EXTRACTOR_HINTS = 128
_EXTRACTOR_HINT_KINDS: tuple[str, str, str, str] = ("json", "kv", "csv", "xml")
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class TagState:
    """T2/R2: structured tag-membership tracking for ``mutate { add_tag/remove_tag }``.

    Per-branch the analyzer wants to know:

    * ``definitely``: literal tags that have been added on EVERY path leading
      to the current point (no remove_tag has touched them since). A tag in
      ``definitely`` answers "is X always present?" with yes.
    * ``possibly``: literal tags that *might* be present — the union of
      additions across paths, minus tags whose removal is certain.
    * ``has_dynamic``: True iff any prior ``add_tag`` or ``remove_tag`` carried
      a templated value (``%{field}``). When True, ``possibly`` is widened to
      "anything could match" because we can't enumerate runtime tag values.

    Branch-merge intersects ``definitely`` and unions ``possibly`` across
    survivors so the post-merge state honors both "always present" and "might
    be present" semantics.
    """

    definitely: frozenset[str] = frozenset()
    possibly: frozenset[str] = frozenset()
    has_dynamic: bool = False

    def with_added(self, literals: Iterable[str], *, has_dynamic: bool) -> TagState:
        lits = frozenset(literals)
        return TagState(
            definitely=self.definitely | lits,
            possibly=self.possibly | lits,
            has_dynamic=self.has_dynamic or has_dynamic,
        )

    def with_removed(self, literals: Iterable[str], *, has_dynamic: bool) -> TagState:
        lits = frozenset(literals)
        # Definitely-removed: drop from definitely. If the remove is purely
        # literal (no dynamic), drop from possibly too — we know exactly
        # which tag was removed. If dynamic, leave possibly alone (the
        # runtime tag may match something we don't know).
        new_possibly = self.possibly if has_dynamic else (self.possibly - lits)
        return TagState(
            definitely=self.definitely - lits,
            possibly=new_possibly,
            has_dynamic=self.has_dynamic or has_dynamic,
        )

    @staticmethod
    def merge(states: Iterable[TagState]) -> TagState:
        """Merge tag states across branch outputs.

        ``definitely`` = intersection (true on every branch),
        ``possibly`` = union (true on at least one),
        ``has_dynamic`` = OR (any branch widened).
        """
        states = list(states)
        if not states:
            return TagState()
        defin = states[0].definitely
        for st in states[1:]:
            defin = defin & st.definitely
        poss: frozenset[str] = frozenset()
        dyn = False
        for st in states:
            poss = poss | st.possibly
            dyn = dyn or st.has_dynamic
        return TagState(definitely=defin, possibly=poss, has_dynamic=dyn)


_PROMOTABLE_TO_CONDITIONAL_STATUSES: frozenset[str] = frozenset(
    {"exact", "exact_capture", "constant", "derived", "repeated"}
)
DROP_CONDITION_SUMMARY_RE = re.compile(r"^NOT\(drop path: any of (?P<count>\d+) prior drop conditions matched\)$")


class _BranchMergeExt(Protocol):
    def merge_appended_only(
        self,
        lineage_key_func: Callable[[Lineage], Key],
        initial_merged: list[Lineage],
        initial_keys: set[Key],
        appended_lists: list[list[Lineage]],
        fanout_limit: int,
    ) -> tuple[list[Lineage], set[Key], bool]: ...

    def merge_with_unchanged_fallback(
        self,
        lineage_key_func: Callable[[Lineage], Key],
        unchanged_pre_conditioned: list[Lineage],
        effective_record_vals: list[list[Lineage]],
        missing_lineages: list[Lineage],
        fanout_limit: int,
    ) -> tuple[list[Lineage], set[Key], bool, int]: ...


_NATIVE_BRANCH_MERGE: _BranchMergeExt | None = None
if os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() not in {
    "1",
    "true",
    "yes",
    "on",
} and os.environ.get("PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE", "").lower() not in {
    "0",
    "false",
    "no",
    "off",
}:
    try:  # pragma: no cover - exercised only when the optional extension is built.
        _NATIVE_BRANCH_MERGE = cast(
            _BranchMergeExt,
            importlib.import_module("parser_lineage_analyzer._native._branch_merge_ext"),
        )
    except ImportError:
        _NATIVE_BRANCH_MERGE = None


def _merge_appended_only_python(
    lineage_key_func: Callable[[Lineage], Key],
    initial_merged: list[Lineage],
    initial_keys: set[Key],
    appended_lists: list[list[Lineage]],
    fanout_limit: int,
) -> tuple[list[Lineage], set[Key], bool]:
    """Append-only branch merge (pure-Python kernel).

    ``initial_merged`` MUST be treated as read-only — callers (notably
    ``_merge_changed_token_lineages``) may pass an alias of
    ``original.tokens[token]`` to skip an eager copy, and we mutate only the
    fresh ``merged`` list created by ``list(initial_merged)`` below.
    """
    merged: list[Lineage] = list(initial_merged)
    keys: set[Key] = set(initial_keys)
    for appended in appended_lists:
        for lin in appended:
            key = lineage_key_func(lin)
            if key in keys:
                continue
            keys.add(key)
            merged.append(lin)
            if len(merged) > fanout_limit:
                return merged, keys, True
    return merged, keys, False


def _merge_with_unchanged_fallback_python(
    lineage_key_func: Callable[[Lineage], Key],
    unchanged_pre_conditioned: list[Lineage],
    effective_record_vals: list[list[Lineage]],
    missing_lineages: list[Lineage],
    fanout_limit: int,
) -> tuple[list[Lineage], set[Key], bool, int]:
    merged: list[Lineage] = []
    keys: set[Key] = set()
    total_seen = 0
    for lin in unchanged_pre_conditioned:
        total_seen += 1
        key = lineage_key_func(lin)
        if key in keys:
            continue
        keys.add(key)
        merged.append(lin)
    for vals in effective_record_vals:
        for lin in vals:
            total_seen += 1
            key = lineage_key_func(lin)
            if key in keys:
                continue
            keys.add(key)
            merged.append(lin)
            if len(merged) > fanout_limit:
                return merged, keys, True, total_seen
    for lin in missing_lineages:
        total_seen += 1
        key = lineage_key_func(lin)
        if key in keys:
            continue
        keys.add(key)
        merged.append(lin)
        if len(merged) > fanout_limit:
            return merged, keys, True, total_seen
    return merged, keys, False, total_seen


def _merge_appended_only(
    initial_merged: list[Lineage],
    initial_keys: set[Key],
    appended_lists: list[list[Lineage]],
) -> tuple[list[Lineage], set[Key], bool]:
    if _NATIVE_BRANCH_MERGE is not None:
        return _NATIVE_BRANCH_MERGE.merge_appended_only(
            _lineage_key,
            initial_merged,
            initial_keys,
            appended_lists,
            MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES,
        )
    return _merge_appended_only_python(
        _lineage_key,
        initial_merged,
        initial_keys,
        appended_lists,
        MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES,
    )


def _merge_with_unchanged_fallback(
    unchanged_pre_conditioned: list[Lineage],
    effective_record_vals: list[list[Lineage]],
    missing_lineages: list[Lineage],
) -> tuple[list[Lineage], set[Key], bool, int]:
    if _NATIVE_BRANCH_MERGE is not None:
        return _NATIVE_BRANCH_MERGE.merge_with_unchanged_fallback(
            _lineage_key,
            unchanged_pre_conditioned,
            effective_record_vals,
            missing_lineages,
            MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES,
        )
    return _merge_with_unchanged_fallback_python(
        _lineage_key,
        unchanged_pre_conditioned,
        effective_record_vals,
        missing_lineages,
        MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES,
    )


def _token_parent_prefixes(token: str) -> Iterator[str]:
    start = 0
    while True:
        dot = token.find(".", start)
        if dot == -1:
            return
        yield token[:dot]
        start = dot + 1


def _dynamic_template_prefix(token: str) -> str | None:
    marker = token.find("%{")
    return token[:marker] if marker != -1 else None


def _dynamic_template_literals(token: str) -> tuple[str, ...]:
    return dynamic_template_literals(token)


def _dynamic_template_bucket_literal(token: str) -> str:
    return dynamic_template_bucket_literal(token)


def _untargeted_hint_key(hint: ExtractionHint) -> Key:
    return (
        hint.kind,
        hint.source_token,
        _freeze_value(hint.details),
        tuple(hint.conditions),
        hint.source_resolved,
    )


def _compact_drop_path_conditions(conditions: Iterable[str]) -> list[str]:
    exact: list[str] = []
    summarized = 0
    for condition in conditions:
        match = DROP_CONDITION_SUMMARY_RE.match(condition)
        if match:
            summarized += int(match.group("count"))
        elif condition:
            exact.append(condition)
    total = summarized + len(exact)
    if total <= MAX_EXACT_DROP_CONDITIONS:
        return _dedupe_strings(exact)
    return [f"NOT(drop path: any of {total} prior drop conditions matched)"]


def _compact_branch_conditions(conditions: Iterable[str]) -> list[str]:
    exact = _dedupe_strings(condition for condition in conditions if condition)
    if len(exact) <= MAX_EXACT_DROP_CONDITIONS:
        return exact
    return [f"branch lineage fanout: {len(exact)} distinct branch conditions summarized"]


def _add_count_delta(target: dict[str, int], delta: Mapping[str, int]) -> None:
    for code, count in delta.items():
        target[code] = target.get(code, 0) + count


class TokenStore(MutableMapping[str, list[Lineage]]):
    """Token mapping with cheap branch forks.

    Forked stores keep local writes/deletes in an overlay and read unchanged
    tokens from the base store. This avoids copying the full token map for every
    branch in large parsers.
    """

    def __init__(
        self,
        owner: AnalyzerState | None = None,
        data: Iterable[tuple[str, list[Lineage]]] | Mapping[str, list[Lineage]] | None = None,
        *,
        base: TokenStore | None = None,
    ) -> None:
        self._owner = owner
        self._data = dict(data or {})
        self._base = base
        self._deleted: set[str] = set()
        self._appends: dict[str, list[Lineage]] = {}
        self._append_keys: dict[str, set[Key]] = {}

    def bind(self, owner: AnalyzerState) -> None:
        self._owner = owner

    def fork(self, owner: AnalyzerState | None) -> TokenStore:
        # ``__init__`` already permits a ``None`` owner (used by tests that
        # exercise the overlay logic without a back-reference). Match that
        # signature so call sites don't need ``# type: ignore`` to pass
        # ``None``.
        return TokenStore(owner, base=self)

    def has_local_value(self, key: str) -> bool:
        return key in self._data and key not in self._deleted

    def has_replacement(self, key: str) -> bool:
        return key in self._data

    def is_deleted(self, key: str) -> bool:
        return key in self._deleted

    def appended_values(self, key: str) -> list[Lineage]:
        return self._appends.get(key, [])

    def appended_keys(self, key: str) -> set[Key]:
        return self._append_keys.get(key, set())

    def base_values(self, key: str) -> list[Lineage]:
        if self._base is not None and key not in self._deleted:
            return self._base[key]
        if key in self._data:
            return self._data[key]
        raise KeyError(key)

    def append_values(
        self, key: str, values: list[Lineage], *, existed: bool, invalidate_inferred: bool = True
    ) -> None:
        if not values:
            return
        self._appends.setdefault(key, []).extend(values)
        self._append_keys.setdefault(key, set()).update(_lineage_key(value) for value in values)
        self._deleted.discard(key)
        if self._owner is not None:
            self._owner._mark_token_changed(key, existed=existed, invalidate_inferred=invalidate_inferred)

    def mark_local_value_changed(self, key: str, *, invalidate_inferred: bool = True) -> None:
        if self._owner is not None:
            self._owner._mark_token_changed(key, existed=True, invalidate_inferred=invalidate_inferred)

    def materialize(self) -> dict[str, list[Lineage]]:
        return {key: self[key] for key in self}

    def __getitem__(self, key: str) -> list[Lineage]:
        appended = self._appends.get(key)
        if key in self._data:
            value = self._data[key]
            return [*value, *appended] if appended else value
        if key in self._deleted:
            raise KeyError(key)
        if self._base is not None:
            base = self._base[key]
            return [*base, *appended] if appended else base
        if appended:
            return appended
        raise KeyError(key)

    @overload
    def get(self, key: str) -> list[Lineage] | None: ...
    @overload
    def get(self, key: str, default: list[Lineage]) -> list[Lineage]: ...
    @overload
    def get(self, key: str, default: _T) -> list[Lineage] | _T: ...

    def get(self, key: object, default: list[Lineage] | _T | None = None) -> list[Lineage] | _T | None:
        # Fast path that avoids ``MutableMapping.get``'s ``self[key]`` +
        # ``KeyError``-catch round-trip on the common "key present" path —
        # hot on the routing-chain analyze workload (TokenStore.get accounts
        # for ~313k calls there). Wrap the existing ``__getitem__`` so we
        # preserve overlay precedence and don't introduce semantic drift if
        # ``__getitem__`` itself raises (e.g. the pre-existing append-only-
        # on-fork edge case where ``__contains__`` is True but ``__getitem__``
        # raises) — falling back to ``default`` matches what
        # ``Mapping.get`` did before this fast path landed.
        #
        # ``key`` is typed ``object`` (not ``str``) so the contains-rejection
        # branch below stays observable: ``MutableMapping.get`` historically
        # accepts any hashable, and a non-str key is a defined no-op that
        # returns ``default`` rather than raising ``TypeError``.
        if not isinstance(key, str):
            return default
        if key in self._deleted:
            return default
        if key in self:
            try:
                return self[key]
            except KeyError:
                return default
        return default

    def __setitem__(self, key: str, value: list[Lineage]) -> None:
        existed = key in self
        old = self.get(key)
        self._data[key] = value
        self._appends.pop(key, None)
        self._append_keys.pop(key, None)
        self._deleted.discard(key)
        if self._owner is not None:
            self._owner._inferred_token_generations.pop(key, None)
            self._owner._inferred_token_lineage_keys.pop(key, None)
        if self._owner is not None and (not existed or old != value):
            self._owner._mark_token_changed(key, existed=existed)

    def __delitem__(self, key: str) -> None:
        if key not in self:
            raise KeyError(key)
        self._data.pop(key, None)
        self._appends.pop(key, None)
        self._append_keys.pop(key, None)
        if self._base is not None and key in self._base:
            self._deleted.add(key)
        else:
            self._deleted.discard(key)
        if self._owner is not None:
            self._owner._mark_token_removed(key)

    def __iter__(self) -> Iterator[str]:
        yielded: set[str] = set()
        for key in self._data:
            if key not in self._deleted:
                yielded.add(key)
                yield key
        for key in self._appends:
            if key not in yielded and key not in self._deleted:
                yielded.add(key)
                yield key
        if self._base is not None:
            for key in self._base:
                if key not in yielded and key not in self._deleted:
                    yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        if key in self._data:
            return key not in self._deleted
        if key in self._appends:
            return key not in self._deleted
        if key in self._deleted:
            return False
        return self._base is not None and key in self._base


@dataclass(slots=True)
class BranchRecord:
    state: AnalyzerState
    conditions: list[str] = field(default_factory=list)
    is_no_op: bool = False


@dataclass(frozen=True, slots=True)
class ExtractionHint:
    kind: str
    source_token: str
    details: FrozenJSONDict = field(default_factory=lambda: cast(FrozenJSONDict, _freeze_details({})))
    conditions: Iterable[str] = field(default_factory=tuple)
    parser_locations: Iterable[str] = field(default_factory=tuple)
    source_resolved: bool = True
    _analysis_key: tuple[object, ...] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", _freeze_details(self.details))
        object.__setattr__(self, "conditions", tuple(self.conditions))
        object.__setattr__(self, "parser_locations", tuple(self.parser_locations))
        object.__setattr__(
            self,
            "_analysis_key",
            (
                self.kind,
                self.source_token,
                _freeze_for_key(self.details),
                self.conditions,
                self.parser_locations,
                self.source_resolved,
            ),
        )

    def __hash__(self) -> int:
        return hash(self._analysis_key)

    def __eq__(self, other: object) -> bool:
        if other.__class__ is not ExtractionHint:
            return NotImplemented
        return self._analysis_key == other._analysis_key

    def to_json(self) -> JSONDict:
        return {
            "kind": self.kind,
            "source_token": self.source_token,
            "details": _details_to_json(self.details),
            "conditions": list(self.conditions),
            "parser_locations": list(self.parser_locations),
            "source_resolved": self.source_resolved,
        }


@dataclass
class AnalyzerState:
    tokens: MutableMapping[str, list[Lineage]] = field(default_factory=dict)
    output_anchors: list[OutputAnchor] = field(default_factory=list)
    io_anchors: list[IOAnchor] = field(default_factory=list)
    # Phase 4A: opt-in flag — when True, mutate operations within a single
    # mutate{} block are dispatched in Logstash's canonical order rather than
    # source order. False matches the analyzer's historical behavior.
    mutate_canonical_order: bool = False
    # T2: structured tag-membership tracking — see TagState docstring. The
    # field is itself immutable; updates produce a new TagState assigned back.
    tag_state: TagState = field(default_factory=TagState)
    json_extractions: list[ExtractionHint] = field(default_factory=list)
    kv_extractions: list[ExtractionHint] = field(default_factory=list)
    csv_extractions: list[ExtractionHint] = field(default_factory=list)
    xml_extractions: list[ExtractionHint] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    structured_warnings: list[WarningReason] = field(default_factory=list)
    taints: list[TaintReason] = field(default_factory=list)
    diagnostics: list[DiagnosticRecord] = field(default_factory=list)
    dropped: bool = False
    path_conditions: list[str] = field(default_factory=list)
    _defer_token_index: bool = field(default=False, repr=False, compare=False)
    _unsupported_seen: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _warning_seen: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _structured_warning_seen: set[Key] = field(default_factory=set, init=False, repr=False, compare=False)
    _taint_seen: set[Key] = field(default_factory=set, init=False, repr=False, compare=False)
    _diagnostic_seen: set[Key] = field(default_factory=set, init=False, repr=False, compare=False)
    _dirty_tokens: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _removed_tokens: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _token_parent_index: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False, compare=False)
    _token_parent_index_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _token_parent_index_additions: dict[str, set[str]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _token_parent_index_removals: dict[str, set[str]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _dynamic_token_index: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False, compare=False)
    _dynamic_token_literal_index: dict[str, dict[str, set[str]]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _dynamic_token_index_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _dynamic_token_index_additions: dict[str, set[str]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _dynamic_token_index_removals: dict[str, set[str]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _dynamic_template_regex_cache: dict[str, Pattern[str]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _extractor_hint_index: dict[str, dict[str, set[int]]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _untargeted_extractor_hints: dict[str, list[ExtractionHint]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _untargeted_extractor_hint_keys: dict[str, dict[Key, int]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _extractor_hint_index_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _extractor_hint_index_sizes: tuple[int, int, int, int] = field(
        default=(0, 0, 0, 0), init=False, repr=False, compare=False
    )
    _diagnostic_base_counts: tuple[int, int, int, int, int] = field(
        default=(0, 0, 0, 0, 0), init=False, repr=False, compare=False
    )
    _metadata_base_counts: tuple[int, int, int, int, int] = field(
        default=(0, 0, 0, 0, 0), init=False, repr=False, compare=False
    )
    _metadata_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _metadata_seen_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _diagnostics_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _suppressed_warning_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False, compare=False)
    _suppressed_taint_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False, compare=False)
    _diagnostic_base_suppressed_warning_counts: dict[str, int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _diagnostic_base_suppressed_taint_counts: dict[str, int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _unresolved_extractor_source_counts: dict[str, int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _unresolved_extractor_source_summary_taints: dict[str, TaintReason] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _output_anchor_seen: set[Key] = field(default_factory=set, init=False, repr=False, compare=False)
    _hint_seen_by_kind: dict[str, set[Key]] = field(default_factory=dict, init=False, repr=False, compare=False)
    _token_lineage_key_cache: dict[str, AbstractSet[Key]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _token_lineage_key_cache_owned: bool = field(default=True, init=False, repr=False, compare=False)
    _token_lineage_key_cache_evictions: set[str] = field(default_factory=set, init=False, repr=False, compare=False)
    _extractor_hint_generation: int = field(default=0, init=False, repr=False, compare=False)
    _extractor_hint_generation_by_kind: dict[str, int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _inference_miss_cache: dict[str, tuple[int, int, int, int]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _inferred_token_generations: dict[str, tuple[int, int, int, int]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _inferred_token_lineage_keys: dict[str, set[Key]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _has_resolved_extractor: dict[str, bool] = field(default_factory=dict, init=False, repr=False, compare=False)
    _dynamic_template_literals_cache: dict[str, tuple[str, ...]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _member_inference_cache: dict[tuple[str, str, tuple[Key, ...]], list[Lineage]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _static_destination_total_tokens: int = field(default=0, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.tokens, TokenStore):
            self.tokens.bind(self)
        else:
            self.tokens = TokenStore(self, self.tokens)
        if not self._defer_token_index:
            self._rebuild_token_parent_index()
            self._rebuild_diagnostic_indexes()
            self._rebuild_metadata_indexes()

    def _rebuild_token_parent_index(self) -> None:
        index: dict[str, set[str]] = {}
        for token in self.tokens:
            for parent in _token_parent_prefixes(token):
                index.setdefault(parent, set()).add(token)
        self._token_parent_index = index
        self._token_parent_index_owned = True
        self._token_parent_index_additions = {}
        self._token_parent_index_removals = {}
        self._rebuild_dynamic_token_index()

    def _rebuild_dynamic_token_index(self) -> None:
        index: dict[str, set[str]] = {}
        literal_index: dict[str, dict[str, set[str]]] = {}
        for token in self.tokens:
            prefix = _dynamic_template_prefix(token)
            if prefix is not None:
                index.setdefault(prefix, set()).add(token)
                literal = _dynamic_template_bucket_literal(token)
                literal_index.setdefault(prefix, {}).setdefault(literal, set()).add(token)
        self._dynamic_token_index = index
        self._dynamic_token_literal_index = literal_index
        self._dynamic_token_index_owned = True
        self._dynamic_token_index_additions = {}
        self._dynamic_token_index_removals = {}
        self._dynamic_template_regex_cache = {}
        self._dynamic_template_literals_cache = {}

    def _add_token_to_parent_index(self, token: str) -> None:
        for parent in _token_parent_prefixes(token):
            if self._token_parent_index_owned:
                self._token_parent_index.setdefault(parent, set()).add(token)
            else:
                self._token_parent_index_removals.get(parent, set()).discard(token)
                self._token_parent_index_additions.setdefault(parent, set()).add(token)

    def _remove_token_from_parent_index(self, token: str) -> None:
        for parent in _token_parent_prefixes(token):
            if self._token_parent_index_owned:
                children = self._token_parent_index.get(parent)
                if children is not None:
                    children.discard(token)
                    if not children:
                        self._token_parent_index.pop(parent, None)
            else:
                self._token_parent_index_additions.get(parent, set()).discard(token)
                self._token_parent_index_removals.setdefault(parent, set()).add(token)

    def _mark_token_changed(self, token: str, *, existed: bool, invalidate_inferred: bool = True) -> None:
        self._dirty_tokens.add(token)
        self._removed_tokens.discard(token)
        self._discard_token_lineage_key_cache(token)
        if invalidate_inferred:
            self._inferred_token_generations.pop(token, None)
            self._inferred_token_lineage_keys.pop(token, None)
        self._inference_miss_cache = {}
        self._member_inference_cache = {}
        if not existed:
            self._add_token_to_parent_index(token)
            self._add_token_to_dynamic_index(token)

    def _mark_token_removed(self, token: str) -> None:
        self._dirty_tokens.add(token)
        self._removed_tokens.add(token)
        self._discard_token_lineage_key_cache(token)
        self._inferred_token_generations.pop(token, None)
        self._inferred_token_lineage_keys.pop(token, None)
        self._inference_miss_cache = {}
        self._member_inference_cache = {}
        self._remove_token_from_parent_index(token)
        self._remove_token_from_dynamic_index(token)

    def _ensure_token_lineage_key_cache_owned(self) -> None:
        if self._token_lineage_key_cache_owned:
            return
        evictions = self._token_lineage_key_cache_evictions
        if evictions:
            self._token_lineage_key_cache = {
                token: set(keys) if isinstance(keys, set) else keys
                for token, keys in self._token_lineage_key_cache.items()
                if token not in evictions
            }
            self._token_lineage_key_cache_evictions = set()
        else:
            self._token_lineage_key_cache = {
                token: set(keys) if isinstance(keys, set) else keys
                for token, keys in self._token_lineage_key_cache.items()
            }
        self._token_lineage_key_cache_owned = True

    def _peek_token_lineage_key_cache(self, token: str) -> AbstractSet[Key] | None:
        if not self._token_lineage_key_cache_owned and token in self._token_lineage_key_cache_evictions:
            return None
        return self._token_lineage_key_cache.get(token)

    def _discard_token_lineage_key_cache(self, token: str) -> None:
        if self._token_lineage_key_cache_owned:
            if token in self._token_lineage_key_cache:
                self._token_lineage_key_cache.pop(token, None)
            return
        if token in self._token_lineage_key_cache and token not in self._token_lineage_key_cache_evictions:
            self._token_lineage_key_cache_evictions.add(token)

    def _clear_token_lineage_key_cache(self) -> None:
        self._token_lineage_key_cache = {}
        if self._token_lineage_key_cache_evictions:
            self._token_lineage_key_cache_evictions = set()
        self._token_lineage_key_cache_owned = True

    def _cache_token_lineage_keys(
        self, token: str, keys: Iterable[Key], *, value_count: int | None = None, mutable: bool = False
    ) -> AbstractSet[Key]:
        if mutable:
            cached: AbstractSet[Key] = keys if isinstance(keys, set) else set(keys)
        else:
            cached = frozenset(keys)
        if value_count is None:
            value_count = len(cached)
        if value_count >= MIN_TOKEN_LINEAGE_KEY_CACHE_VALUES:
            self._ensure_token_lineage_key_cache_owned()
            self._token_lineage_key_cache[token] = cached
        else:
            self._discard_token_lineage_key_cache(token)
        return cached

    def _cached_token_lineage_keys(self, token: str, lineages: Iterable[Lineage]) -> AbstractSet[Key]:
        cached = self._peek_token_lineage_key_cache(token)
        if cached is not None:
            return cached
        value_count = len(lineages) if isinstance(lineages, list) else None
        return self._cache_token_lineage_keys(token, (_lineage_key(lin) for lin in lineages), value_count=value_count)

    def _add_token_to_dynamic_index(self, token: str) -> None:
        prefix = _dynamic_template_prefix(token)
        if prefix is None:
            return
        if self._dynamic_token_index_owned:
            self._dynamic_token_index.setdefault(prefix, set()).add(token)
            literal = _dynamic_template_bucket_literal(token)
            self._dynamic_token_literal_index.setdefault(prefix, {}).setdefault(literal, set()).add(token)
        else:
            self._dynamic_token_index_removals.get(prefix, set()).discard(token)
            self._dynamic_token_index_additions.setdefault(prefix, set()).add(token)

    def _remove_token_from_dynamic_index(self, token: str) -> None:
        prefix = _dynamic_template_prefix(token)
        if prefix is None:
            return
        self._dynamic_template_regex_cache.pop(token, None)
        self._dynamic_template_literals_cache.pop(token, None)
        if self._dynamic_token_index_owned:
            tokens = self._dynamic_token_index.get(prefix)
            if tokens is not None:
                tokens.discard(token)
                if not tokens:
                    self._dynamic_token_index.pop(prefix, None)
            literal = _dynamic_template_bucket_literal(token)
            literal_tokens = self._dynamic_token_literal_index.get(prefix, {}).get(literal)
            if literal_tokens is not None:
                literal_tokens.discard(token)
                if not literal_tokens:
                    self._dynamic_token_literal_index.get(prefix, {}).pop(literal, None)
                if not self._dynamic_token_literal_index.get(prefix):
                    self._dynamic_token_literal_index.pop(prefix, None)
        else:
            self._dynamic_token_index_additions.get(prefix, set()).discard(token)
            self._dynamic_token_index_removals.setdefault(prefix, set()).add(token)

    def descendant_tokens(self, token: str) -> list[str]:
        descendants = set(self._token_parent_index.get(token, set()))
        descendants.update(self._token_parent_index_additions.get(token, set()))
        descendants.difference_update(self._token_parent_index_removals.get(token, set()))
        return [candidate for candidate in descendants if candidate in self.tokens]

    def dynamic_template_tokens(self, candidate: str) -> list[str]:
        out: set[str] = set()
        for end in range(len(candidate) + 1):
            prefix = candidate[:end]
            removed = self._dynamic_token_index_removals.get(prefix, set())
            base_candidates: set[str] = set()
            literal_buckets = self._dynamic_token_literal_index.get(prefix, {})
            for literal, tokens in literal_buckets.items():
                if not literal or literal in candidate:
                    base_candidates.update(tokens)
            for token in base_candidates:
                if (
                    token not in removed
                    and token in self.tokens
                    and self.dynamic_template_literals_match(token, candidate)
                ):
                    out.add(token)
            for token in self._dynamic_token_index_additions.get(prefix, set()):
                if token in self.tokens and self.dynamic_template_literals_match(token, candidate):
                    out.add(token)
        return sorted(out)

    def dynamic_template_pattern(self, token: str) -> Pattern[str]:
        cached = self._dynamic_template_regex_cache.get(token)
        if cached is not None:
            return cached
        pattern = re.compile(dynamic_template_pattern_text(token))
        self._dynamic_template_regex_cache[token] = pattern
        return pattern

    def dynamic_template_literals_match(self, token: str, candidate: str) -> bool:
        literals = self._dynamic_template_literals_cache.get(token)
        if literals is None:
            literals = _dynamic_template_literals(token)
            self._dynamic_template_literals_cache[token] = literals
        return all(not literal or literal in candidate for literal in literals)

    def dynamic_template_matches(self, token: str, candidate: str) -> bool:
        if type(self).dynamic_template_pattern is not _DEFAULT_DYNAMIC_TEMPLATE_PATTERN:
            return bool(self.dynamic_template_pattern(token).match(candidate))
        return dynamic_template_matches(token, candidate)

    def extractor_hints_for_token(self, kind: str, token: str) -> list[ExtractionHint]:
        self._ensure_extractor_hint_index()
        hints = self._hints_for_kind(kind)
        index = self._extractor_hint_index.get(kind, {})
        positions: set[int] = set()
        if kind in {"json", "xml"}:
            for end in range(1, len(token) + 1):
                positions.update(index.get(token[:end], set()))
        else:
            positions.update(index.get(token, set()))
        untargeted = self._untargeted_extractor_hints.get(kind, [])
        return [*untargeted, *(hints[pos] for pos in sorted(positions) if pos < len(hints))]

    def _hints_for_kind(self, kind: str) -> list[ExtractionHint]:
        if kind == "json":
            return self.json_extractions
        if kind == "kv":
            return self.kv_extractions
        if kind == "csv":
            return self.csv_extractions
        if kind == "xml":
            return self.xml_extractions
        return []

    def _ensure_extractor_hint_index(self) -> None:
        sizes = (
            len(self.json_extractions),
            len(self.kv_extractions),
            len(self.csv_extractions),
            len(self.xml_extractions),
        )
        if sizes == self._extractor_hint_index_sizes:
            return
        if any(indexed < 0 for indexed in self._extractor_hint_index_sizes) or any(
            size < indexed for size, indexed in zip(sizes, self._extractor_hint_index_sizes, strict=True)
        ):
            self._extractor_hint_index = {}
            self._untargeted_extractor_hints = {}
            self._untargeted_extractor_hint_keys = {}
            self._extractor_hint_index_owned = True
            self._extractor_hint_index_sizes = (0, 0, 0, 0)
        if not self._extractor_hint_index_owned:
            self._extractor_hint_index = {
                kind: {key: set(values) for key, values in self._extractor_hint_index.get(kind, {}).items()}
                for kind in _EXTRACTOR_HINT_KINDS
            }
            self._untargeted_extractor_hints = {
                kind: list(hints) for kind, hints in self._untargeted_extractor_hints.items()
            }
            self._untargeted_extractor_hint_keys = {
                kind: dict(keys) for kind, keys in self._untargeted_extractor_hint_keys.items()
            }
            self._extractor_hint_index_owned = True
        indexes = self._extractor_hint_index
        old_sizes = self._extractor_hint_index_sizes
        for kind_idx, kind in enumerate(_EXTRACTOR_HINT_KINDS):
            kind_index = indexes.setdefault(kind, {})
            start = old_sizes[kind_idx]
            for pos, hint in enumerate(self._hints_for_kind(kind)[start:], start=start):
                target = hint.details.get("target") if hint.details else None
                if target:
                    kind_index.setdefault(str(target), set()).add(pos)
                else:
                    self._add_untargeted_extractor_hint(kind, hint)
        self._extractor_hint_index = indexes
        self._extractor_hint_index_sizes = sizes

    def _add_untargeted_extractor_hint(self, kind: str, hint: ExtractionHint) -> None:
        grouped = self._untargeted_extractor_hints.setdefault(kind, [])
        keys = self._untargeted_extractor_hint_keys.setdefault(kind, {})
        key = _untargeted_hint_key(hint)
        pos = keys.get(key)
        if pos is None:
            keys[key] = len(grouped)
            grouped.append(
                ExtractionHint(
                    hint.kind,
                    hint.source_token,
                    hint.details,
                    conditions=hint.conditions,
                    parser_locations=_dedupe_strings(str(loc) for loc in hint.parser_locations)[
                        :MAX_UNTARGETED_EXTRACTOR_HINTS
                    ],
                    source_resolved=hint.source_resolved,
                )
            )
            return
        if pos >= len(grouped):
            return
        existing = grouped[pos]
        if len(tuple(existing.parser_locations)) >= MAX_UNTARGETED_EXTRACTOR_HINTS:
            return
        locations = _dedupe_strings([*existing.parser_locations, *(str(loc) for loc in hint.parser_locations)])[
            :MAX_UNTARGETED_EXTRACTOR_HINTS
        ]
        if tuple(locations) == tuple(existing.parser_locations):
            return
        grouped[pos] = ExtractionHint(
            existing.kind,
            existing.source_token,
            existing.details,
            conditions=existing.conditions,
            parser_locations=locations,
            source_resolved=existing.source_resolved,
        )

    def has_resolved_extractor(self, kind: str) -> bool:
        cached = self._has_resolved_extractor.get(kind)
        if cached is not None:
            return cached
        value = any(hint.source_resolved for hint in self._hints_for_kind(kind))
        self._has_resolved_extractor[kind] = value
        return value

    def add_output_anchor(self, anchor: OutputAnchor) -> None:
        key = _anchor_key(anchor)
        if key in self._output_anchor_seen:
            return
        self._ensure_metadata_owned()
        self._output_anchor_seen.add(key)
        self.output_anchors.append(anchor)

    def add_extraction_hint(self, kind: str, hint: ExtractionHint) -> None:
        self.add_extraction_hints(kind, [hint])

    def add_extraction_hints(self, kind: str, hints: Iterable[ExtractionHint]) -> None:
        pending: list[tuple[Key, ExtractionHint]] = []
        seen = self._hint_seen_by_kind.get(kind)
        pending_keys: set[Key] = set()
        for hint in hints:
            key = _hint_key(hint)
            if (seen is not None and key in seen) or key in pending_keys:
                continue
            pending_keys.add(key)
            pending.append((key, hint))
        if not pending:
            return
        self._ensure_metadata_owned()
        seen = self._hint_seen_by_kind.setdefault(kind, set())
        target = self._hints_for_kind(kind)
        added = 0
        for key, hint in pending:
            if key in seen:
                continue
            seen.add(key)
            target.append(hint)
            added += 1
        if not added:
            return
        self._extractor_hint_generation += added
        self._extractor_hint_generation_by_kind[kind] = self._extractor_hint_generation_by_kind.get(kind, 0) + added
        self._has_resolved_extractor.pop(kind, None)

    def inference_generation_key(self) -> tuple[int, int, int, int]:
        return (
            self._extractor_hint_generation_by_kind.get("json", 0),
            self._extractor_hint_generation_by_kind.get("kv", 0),
            self._extractor_hint_generation_by_kind.get("csv", 0),
            self._extractor_hint_generation_by_kind.get("xml", 0),
        )

    def append_token_lineages(self, token: str, lineages: list[Lineage]) -> None:
        store = self.tokens if isinstance(self.tokens, TokenStore) else None
        preserve_inferred = (
            store is not None
            and token in self._inferred_token_generations
            and token in store
            and not store.is_deleted(token)
        )
        append_in_overlay = (
            store is not None
            and not store.has_replacement(token)
            and bool(store._base)
            and token in store
            and not store.is_deleted(token)
        )
        append_in_store = append_in_overlay or preserve_inferred
        state_existing = (
            store.base_values(token) if append_in_overlay and store is not None else self.tokens.get(token, [])
        )
        existing = state_existing
        if (
            existing
            and all(lin.status == "removed" for lin in existing)
            and any(lin.status != "removed" for lin in lineages)
        ):
            existing = []
            append_in_overlay = False
            append_in_store = False
            preserve_inferred = False
        cached_keys = self._peek_token_lineage_key_cache(token) if existing is state_existing else None
        keys = cached_keys if isinstance(cached_keys, set) and self._token_lineage_key_cache_owned else None
        if keys is None and cached_keys is not None:
            keys = set(cached_keys)
        if existing and keys is None:
            keys = {_lineage_key(lin) for lin in existing}
            if existing is state_existing:
                keys = cast(
                    set[Key],
                    self._cache_token_lineage_keys(token, keys, value_count=len(existing), mutable=True),
                )
        if keys is None:
            keys = set()
        mutate_local = store is not None and store.has_local_value(token) and existing is state_existing
        merged = existing if mutate_local else list(existing)
        changed = existing is not state_existing
        appended: list[Lineage] = []
        appended_keys = set(store.appended_keys(token)) if store is not None else set()
        for lin in lineages:
            key = _lineage_key(lin)
            if key in keys or key in appended_keys:
                continue
            appended_keys.add(key)
            keys.add(key)
            if append_in_store:
                appended.append(lin)
            else:
                merged.append(lin)
            changed = True
        if changed:
            if append_in_store and store is not None:
                store.append_values(
                    token,
                    appended,
                    existed=token in store,
                    invalidate_inferred=not preserve_inferred,
                )
                self._cache_token_lineage_keys(token, keys, value_count=len(keys), mutable=True)
            elif mutate_local:
                cast_store = self.tokens
                if isinstance(cast_store, TokenStore):
                    cast_store.mark_local_value_changed(token)
            else:
                self.tokens[token] = merged
        if not append_in_store:
            self._cache_token_lineage_keys(token, keys, value_count=len(merged), mutable=True)

    def _replace_tokens(
        self,
        tokens: dict[str, list[Lineage]],
        inferred_generations: dict[str, tuple[int, int, int, int]] | None = None,
        inferred_lineage_keys: dict[str, set[Key]] | None = None,
    ) -> None:
        old = self.tokens.materialize() if isinstance(self.tokens, TokenStore) else dict(self.tokens)
        self.tokens = TokenStore(self, tokens)
        changed = {token for token, vals in tokens.items() if old.get(token) != vals}
        removed = {token for token in old if token not in tokens}
        self._dirty_tokens.update(changed)
        self._dirty_tokens.update(removed)
        self._removed_tokens.update(removed)
        self._removed_tokens.difference_update(changed)
        self._clear_token_lineage_key_cache()
        self._inferred_token_generations = dict(inferred_generations or {})
        self._inferred_token_lineage_keys = {token: set(keys) for token, keys in (inferred_lineage_keys or {}).items()}
        self._member_inference_cache = {}
        self._rebuild_token_parent_index()

    def _rebuild_diagnostic_indexes(self) -> None:
        self._unsupported_seen = set(self.unsupported)
        self._warning_seen = set(self.warnings)
        self._structured_warning_seen = {_warning_key(warning) for warning in self.structured_warnings}
        self._taint_seen = {_taint_key(taint) for taint in self.taints}
        self._diagnostic_seen = {_diagnostic_key(diagnostic) for diagnostic in self.diagnostics}

    def _rebuild_metadata_indexes(self) -> None:
        self._output_anchor_seen = {_anchor_key(anchor) for anchor in self.output_anchors}
        self._hint_seen_by_kind = {
            kind: {_hint_key(hint) for hint in self._hints_for_kind(kind)} for kind in ("json", "kv", "csv", "xml")
        }
        self._metadata_seen_owned = True
        self._extractor_hint_generation += 1
        self._extractor_hint_generation_by_kind = {
            kind: self._extractor_hint_generation_by_kind.get(kind, 0) + 1 for kind in ("json", "kv", "csv", "xml")
        }
        self._has_resolved_extractor = {}
        self._inference_miss_cache = {}
        self._member_inference_cache = {}

    def _ensure_metadata_owned(self) -> None:
        if self._metadata_owned and self._metadata_seen_owned:
            return
        if not self._metadata_owned:
            self.output_anchors = list(self.output_anchors)
            self.json_extractions = list(self.json_extractions)
            self.kv_extractions = list(self.kv_extractions)
            self.csv_extractions = list(self.csv_extractions)
            self.xml_extractions = list(self.xml_extractions)
            self._metadata_owned = True
        if not self._metadata_seen_owned:
            self._output_anchor_seen = set(self._output_anchor_seen)
            self._hint_seen_by_kind = {kind: set(keys) for kind, keys in self._hint_seen_by_kind.items()}
            self._metadata_seen_owned = True

    def _ensure_diagnostics_owned(self) -> None:
        if self._diagnostics_owned:
            return
        self.unsupported = list(self.unsupported)
        self.warnings = list(self.warnings)
        self.structured_warnings = list(self.structured_warnings)
        self.taints = list(self.taints)
        self.diagnostics = list(self.diagnostics)
        self._suppressed_warning_counts = dict(self._suppressed_warning_counts)
        self._suppressed_taint_counts = dict(self._suppressed_taint_counts)
        self._unresolved_extractor_source_counts = dict(self._unresolved_extractor_source_counts)
        self._unresolved_extractor_source_summary_taints = dict(self._unresolved_extractor_source_summary_taints)
        self._diagnostics_owned = True
        # ``clone()`` aliases the diagnostic lists to the parent without
        # propagating the seen-sets (which are reset to empty per-instance
        # by ``default_factory=set``). If the first writer on the clone is
        # ``_ensure_diagnostics_owned`` (rather than going through
        # ``_sync_branch_seed_diagnostics`` first), the now-owned lists carry
        # the parent's existing entries but the seen-sets remain empty,
        # so a duplicate of any pre-existing parent diagnostic would slip
        # past the dedup check in ``_add_diagnostic_record`` and be appended
        # twice. Hydrate the seen-sets to match the freshly owned lists when
        # any list has content but its corresponding seen-set is empty;
        # already-synced seeds (where the seen-sets reflect the lists) take
        # the cheap no-op path through these short-circuit checks.
        seen_initialized = (
            (not self.unsupported or self._unsupported_seen)
            and (not self.warnings or self._warning_seen)
            and (not self.structured_warnings or self._structured_warning_seen)
            and (not self.taints or self._taint_seen)
            and (not self.diagnostics or self._diagnostic_seen)
        )
        if not seen_initialized:
            self._rebuild_diagnostic_indexes()

    def clone(self) -> AnalyzerState:
        # Shallow structural clone. Lineage and SourceRef objects are treated as
        # immutable by the analyzer; assignment/append operations replace token
        # lists rather than mutating shared lineage objects. Avoiding deepcopy is
        # critical for large parser corpora with hundreds of independent
        # conditionals, where deepcopy causes quadratic-to-cubic behavior.
        clone = AnalyzerState(
            tokens={},
            output_anchors=self.output_anchors,
            mutate_canonical_order=self.mutate_canonical_order,
            tag_state=self.tag_state,
            json_extractions=self.json_extractions,
            kv_extractions=self.kv_extractions,
            csv_extractions=self.csv_extractions,
            xml_extractions=self.xml_extractions,
            unsupported=self.unsupported,
            warnings=self.warnings,
            structured_warnings=self.structured_warnings,
            taints=self.taints,
            diagnostics=self.diagnostics,
            dropped=self.dropped,
            path_conditions=list(self.path_conditions),
            _defer_token_index=True,
        )
        clone.tokens = (
            self.tokens.fork(clone) if isinstance(self.tokens, TokenStore) else TokenStore(clone, self.tokens)
        )
        clone._token_parent_index = self._token_parent_index
        clone._token_parent_index_owned = False
        clone._token_parent_index_additions = {
            parent: set(children) for parent, children in self._token_parent_index_additions.items()
        }
        clone._token_parent_index_removals = {
            parent: set(children) for parent, children in self._token_parent_index_removals.items()
        }
        clone._dynamic_token_index = self._dynamic_token_index
        clone._dynamic_token_literal_index = self._dynamic_token_literal_index
        clone._dynamic_token_index_owned = False
        clone._dynamic_token_index_additions = {
            prefix: set(tokens) for prefix, tokens in self._dynamic_token_index_additions.items()
        }
        clone._dynamic_token_index_removals = {
            prefix: set(tokens) for prefix, tokens in self._dynamic_token_index_removals.items()
        }
        clone._dynamic_template_regex_cache = self._dynamic_template_regex_cache
        clone._dynamic_template_literals_cache = self._dynamic_template_literals_cache
        clone._member_inference_cache = dict(self._member_inference_cache)
        self._token_lineage_key_cache_owned = False
        clone._token_lineage_key_cache = self._token_lineage_key_cache
        clone._token_lineage_key_cache_owned = False
        clone._token_lineage_key_cache_evictions = (
            set(self._token_lineage_key_cache_evictions) if self._token_lineage_key_cache_evictions else set()
        )
        clone._static_destination_total_tokens = self._static_destination_total_tokens
        clone._output_anchor_seen = self._output_anchor_seen
        clone._hint_seen_by_kind = self._hint_seen_by_kind
        clone._extractor_hint_index = self._extractor_hint_index
        clone._untargeted_extractor_hints = self._untargeted_extractor_hints
        clone._untargeted_extractor_hint_keys = self._untargeted_extractor_hint_keys
        clone._extractor_hint_index_owned = False
        clone._extractor_hint_index_sizes = self._extractor_hint_index_sizes
        clone._extractor_hint_generation = self._extractor_hint_generation
        clone._extractor_hint_generation_by_kind = dict(self._extractor_hint_generation_by_kind)
        clone._inferred_token_generations = dict(self._inferred_token_generations)
        clone._inferred_token_lineage_keys = {
            token: set(keys) for token, keys in self._inferred_token_lineage_keys.items()
        }
        clone._has_resolved_extractor = dict(self._has_resolved_extractor)
        clone._metadata_owned = False
        clone._metadata_seen_owned = False
        clone._diagnostics_owned = False
        clone._suppressed_warning_counts = self._suppressed_warning_counts
        clone._suppressed_taint_counts = self._suppressed_taint_counts
        clone._diagnostic_base_suppressed_warning_counts = dict(self._suppressed_warning_counts)
        clone._diagnostic_base_suppressed_taint_counts = dict(self._suppressed_taint_counts)
        clone._unresolved_extractor_source_counts = self._unresolved_extractor_source_counts
        clone._unresolved_extractor_source_summary_taints = self._unresolved_extractor_source_summary_taints
        clone._metadata_base_counts = (
            len(self.output_anchors),
            len(self.json_extractions),
            len(self.kv_extractions),
            len(self.csv_extractions),
            len(self.xml_extractions),
        )
        clone._diagnostic_base_counts = (
            len(self.unsupported),
            len(self.warnings),
            len(self.structured_warnings),
            len(self.taints),
            len(self.diagnostics),
        )
        return clone

    def add_taint(
        self, code: str, message: str, parser_location: str | None = None, source_token: str | None = None
    ) -> TaintReason:
        taint = TaintReason(code=code, message=message, parser_location=parser_location, source_token=source_token)
        self._add_diagnostic_record(
            DiagnosticRecord(
                code=code,
                kind="taint",
                message=message,
                parser_location=parser_location,
                source_token=source_token,
                taint=taint,
            )
        )
        return taint

    def add_suppressed_diagnostic_counts(
        self, *, warning_code: str | None = None, taint_code: str | None = None
    ) -> None:
        self._ensure_diagnostics_owned()
        if warning_code is not None:
            self._suppressed_warning_counts[warning_code] = self._suppressed_warning_counts.get(warning_code, 0) + 1
        if taint_code is not None:
            self._suppressed_taint_counts[taint_code] = self._suppressed_taint_counts.get(taint_code, 0) + 1

    def add_warning(
        self,
        warning: str,
        *,
        code: str,
        message: str | None = None,
        parser_location: str | None = None,
        source_token: str | None = None,
    ) -> WarningReason:
        reason = WarningReason(
            code=code,
            message=message if message is not None else warning,
            parser_location=parser_location,
            source_token=source_token,
            warning=warning,
        )
        self._add_diagnostic_record(
            DiagnosticRecord(
                code=code,
                kind="warning",
                message=reason.message,
                parser_location=parser_location,
                source_token=source_token,
                warning=warning,
            )
        )
        return reason

    def add_unsupported(
        self,
        unsupported: str,
        *,
        code: str,
        message: str | None = None,
        parser_location: str | None = None,
        source_token: str | None = None,
    ) -> DiagnosticRecord:
        record = DiagnosticRecord(
            code=code,
            kind="unsupported",
            message=message if message is not None else unsupported,
            parser_location=parser_location,
            source_token=source_token,
            warning=unsupported,
            unsupported=unsupported,
        )
        self._add_diagnostic_record(record)
        return record

    def _add_diagnostic_record(self, record: DiagnosticRecord) -> None:
        # ``_ensure_diagnostics_owned`` is responsible for both copying the
        # diagnostic lists out of the parent's storage AND hydrating the
        # seen-sets to reflect those lists. The dedup checks below rely on
        # the seen-sets already mirroring the lists, so call it once up
        # front rather than lazily inside each branch — otherwise a fresh
        # clone (whose seen-sets default to empty) would short-circuit the
        # ``key not in self._diagnostic_seen`` check on the first emission
        # and append a duplicate of any pre-existing parent diagnostic.
        # The early-return guard inside ``_ensure_diagnostics_owned`` keeps
        # this a single bool check on the hot path once ownership is set.
        self._ensure_diagnostics_owned()
        key = _diagnostic_key(record)
        if key not in self._diagnostic_seen:
            self._diagnostic_seen.add(key)
            self.diagnostics.append(record)
        if record.kind == "warning":
            if record.warning and record.warning not in self._warning_seen:
                self._warning_seen.add(record.warning)
                self.warnings.append(record.warning)
            reason = WarningReason(
                code=record.code,
                message=record.message,
                parser_location=record.parser_location,
                source_token=record.source_token,
                warning=record.warning,
            )
            warning_key = _warning_key(reason)
            if warning_key not in self._structured_warning_seen:
                self._structured_warning_seen.add(warning_key)
                self.structured_warnings.append(reason)
        elif record.kind == "unsupported":
            unsupported = record.unsupported or record.warning
            if unsupported and unsupported not in self._unsupported_seen:
                self._unsupported_seen.add(unsupported)
                self.unsupported.append(unsupported)
            reason = WarningReason(
                code=record.code,
                message=record.message,
                parser_location=record.parser_location,
                source_token=record.source_token,
                warning=unsupported,
            )
            warning_key = _warning_key(reason)
            if warning_key not in self._structured_warning_seen:
                self._structured_warning_seen.add(warning_key)
                self.structured_warnings.append(reason)
        elif record.kind == "taint" and record.taint:
            taint_key = _taint_key(record.taint)
            if taint_key not in self._taint_seen:
                self._taint_seen.add(taint_key)
                self.taints.append(record.taint)

    def merge_branch_records(self, original: AnalyzerState, records: list[BranchRecord]) -> None:
        self._merge_branch_diagnostics_delta(records)
        changed_token_records = self._changed_branch_token_records(original, records)
        changed_tokens = set(changed_token_records)
        unchanged_branch_keys = self._unchanged_non_no_op_lineage_keys(original, records, changed_tokens)

        no_op_records = [record for record in records if record.is_no_op and not record.state.dropped]
        for record in records:
            if not record.is_no_op:
                continue
            self._condition_no_op_record(record, changed_tokens, unchanged_branch_keys)

        survivors = [record.state for record in records if not record.state.dropped]
        non_no_op_survivor_count = sum(1 for record in records if not record.is_no_op and not record.state.dropped)
        dropped_records = [record for record in records if record.state.dropped]
        if not survivors:
            self.dropped = True
            return
        self._apply_dropped_path_conditions(survivors, dropped_records, records)
        self._merge_branch_metadata_delta([record for record in records if not record.state.dropped])

        for token in sorted(changed_tokens):
            token_records = changed_token_records[token]
            unchanged_records = (
                self._unchanged_non_no_op_records(records, token, token_records)
                if token in original.tokens and non_no_op_survivor_count > len(token_records)
                else []
            )
            missing_lineages = (
                self._missing_branch_lineages(records, token, token_records)
                if token not in original.tokens
                and "%{" not in token
                and "." not in token
                and not _looks_like_udm_field(token)
                and self._should_mark_missing_branch_token(token_records, token)
                else []
            )
            merged, merged_keys = self._merge_changed_token_lineages(
                original,
                token_records,
                token,
                unchanged_records=unchanged_records,
                missing_lineages=missing_lineages,
                no_op_records=no_op_records,
            )
            if merged:
                self.tokens[token] = merged
                self._cache_token_lineage_keys(token, merged_keys, value_count=len(merged), mutable=True)
            else:
                self.tokens.pop(token, None)

        self.dropped = False
        path_condition_sets = [tuple(st.path_conditions) for st in survivors]
        self.path_conditions = (
            list(path_condition_sets[0])
            if path_condition_sets and all(p == path_condition_sets[0] for p in path_condition_sets)
            else []
        )
        # T2: merge per-branch tag_state so post-merge `definitely` keeps only
        # tags added on every surviving path, while `possibly` is the union.
        # Branches that dropped (drop {}) don't constrain the merge.
        self.tag_state = TagState.merge(st.tag_state for st in survivors)

    def _merge_branch_metadata_delta(self, records: list[BranchRecord]) -> None:
        for record in records:
            state = record.state
            a0, j0, k0, c0, x0 = state._metadata_base_counts
            # If the branch never took ownership of a metadata container, the
            # branch's reference is still aliased to the parent's list. The
            # branch-local delta is by definition empty in that case (any new
            # entries the branch tries to record would have triggered
            # ``_ensure_metadata_owned`` first, breaking the alias). Iterating
            # the parent's tail here would re-merge entries that were appended
            # to the parent by other branches in the same merge — which is
            # both wasteful and quadratic when many sibling branches share the
            # alias (e.g. long elif chains over diagnostic-heavy bodies).
            if state.output_anchors is not self.output_anchors:
                for anchor in state.output_anchors[a0:]:
                    self.add_output_anchor(anchor)
            if state.json_extractions is not self.json_extractions and len(state.json_extractions) > j0:
                self.add_extraction_hints("json", state.json_extractions[j0:])
            if state.kv_extractions is not self.kv_extractions and len(state.kv_extractions) > k0:
                self.add_extraction_hints("kv", state.kv_extractions[k0:])
            if state.csv_extractions is not self.csv_extractions and len(state.csv_extractions) > c0:
                self.add_extraction_hints("csv", state.csv_extractions[c0:])
            if state.xml_extractions is not self.xml_extractions and len(state.xml_extractions) > x0:
                self.add_extraction_hints("xml", state.xml_extractions[x0:])

    def _apply_dropped_path_conditions(
        self, survivors: list[AnalyzerState], dropped_records: list[BranchRecord], records: list[BranchRecord]
    ) -> None:
        if not dropped_records:
            return
        if len(survivors) == 1:
            survivor = survivors[0]
            survivor_record = next(record for record in records if record.state is survivor)
            survivor.path_conditions = _compact_drop_path_conditions(
                list(survivor.path_conditions) + survivor_record.conditions
            )
            return
        if len(dropped_records) > MAX_EXACT_DROP_CONDITIONS:
            dropped_desc = f"any of {len(dropped_records)} prior drop conditions matched"
        else:
            dropped_desc = " OR ".join(" AND ".join(record.conditions) for record in dropped_records)
        for survivor in survivors:
            survivor.path_conditions = _compact_drop_path_conditions(
                list(survivor.path_conditions) + [f"NOT(drop path: {dropped_desc})"]
            )

    def _merge_branch_diagnostics_delta(self, records: list[BranchRecord]) -> None:
        for record in records:
            state = record.state
            # If the branch never took ownership of its diagnostic list, its
            # reference is still aliased to ``self.diagnostics``. The branch
            # delta is by definition empty in that case — any branch-local
            # diagnostic emission would have routed through
            # ``_ensure_diagnostics_owned`` first, breaking the alias. Without
            # this guard, every shared-alias branch re-iterates everything
            # ``_add_diagnostic_record`` has appended to the shared list since
            # the clone, making sibling-branch merges quadratic in elif-chain
            # length (the diagnostics list keeps growing as we merge each
            # earlier sibling). Suppressed-warning/taint counters below remain
            # safe to merge because they read per-state base counts captured
            # at clone time, not list slices.
            if state.diagnostics is not self.diagnostics:
                _u0, _w0, _sw0, _t0, d0 = state._diagnostic_base_counts
                for diagnostic in state.diagnostics[d0:]:
                    self._add_diagnostic_record(diagnostic)
            for code, count in state._suppressed_warning_counts.items():
                base_count = state._diagnostic_base_suppressed_warning_counts.get(code, 0)
                if count > base_count:
                    self._suppressed_warning_counts[code] = self._suppressed_warning_counts.get(code, 0) + (
                        count - base_count
                    )
            for code, count in state._suppressed_taint_counts.items():
                base_count = state._diagnostic_base_suppressed_taint_counts.get(code, 0)
                if count > base_count:
                    self._suppressed_taint_counts[code] = self._suppressed_taint_counts.get(code, 0) + (
                        count - base_count
                    )

    def _changed_branch_token_records(
        self, original: AnalyzerState, records: list[BranchRecord]
    ) -> dict[str, list[BranchRecord]]:
        changed_tokens: dict[str, list[BranchRecord]] = {}
        for record in records:
            branch_state = record.state
            if record.is_no_op or branch_state.dropped:
                continue
            candidates = sorted(branch_state._dirty_tokens | branch_state._removed_tokens)
            for token in candidates:
                store = branch_state.tokens if isinstance(branch_state.tokens, TokenStore) else None
                if store is not None and store.appended_values(token):
                    changed_tokens.setdefault(token, []).append(record)
                    continue
                if branch_state.tokens.get(token) != original.tokens.get(token):
                    changed_tokens.setdefault(token, []).append(record)
        return changed_tokens

    def _unchanged_non_no_op_lineage_keys(
        self, original: AnalyzerState, records: list[BranchRecord], changed_tokens: set[str]
    ) -> dict[str, AbstractSet[Key]]:
        keys_by_token: dict[str, AbstractSet[Key]] = {}
        borrowed_keys: set[str] = set()
        for record in records:
            if record.is_no_op or record.state.dropped:
                continue
            dirty = (record.state._dirty_tokens | record.state._removed_tokens) & changed_tokens
            for token in dirty:
                store = record.state.tokens if isinstance(record.state.tokens, TokenStore) else None
                if store is not None and not store.has_replacement(token) and not store.is_deleted(token):
                    original_vals = original.tokens.get(token)
                    if original_vals and token not in keys_by_token:
                        keys_by_token[token] = original._cached_token_lineage_keys(token, original_vals)
                        borrowed_keys.add(token)
                    continue
                vals = record.state.tokens.get(token)
                if vals:
                    keys = keys_by_token.get(token)
                    if keys is None:
                        mutable_keys: set[Key] = set()
                        keys_by_token[token] = mutable_keys
                    elif token in borrowed_keys or not isinstance(keys, set):
                        mutable_keys = set(keys)
                        keys_by_token[token] = mutable_keys
                        borrowed_keys.discard(token)
                    else:
                        mutable_keys = keys
                    cached = record.state._peek_token_lineage_key_cache(token)
                    if cached is not None:
                        mutable_keys.update(cached)
                    else:
                        mutable_keys.update(_lineage_key(lin) for lin in vals)
        return keys_by_token

    def _unchanged_non_no_op_records(
        self, records: list[BranchRecord], token: str, changed_records: list[BranchRecord]
    ) -> list[BranchRecord]:
        changed_record_ids = {id(record) for record in changed_records}
        return [
            record
            for record in records
            if not record.is_no_op
            and not record.state.dropped
            and id(record) not in changed_record_ids
            and token in record.state.tokens
        ]

    def _missing_branch_lineages(
        self, records: list[BranchRecord], token: str, changed_records: list[BranchRecord]
    ) -> list[Lineage]:
        changed_record_ids = {id(record) for record in changed_records}
        lineages: list[Lineage] = []
        compact_conditions: list[str] = []
        missing_count = 0
        for record in records:
            if (
                record.is_no_op
                or record.state.dropped
                or id(record) in changed_record_ids
                or token in record.state.tokens
            ):
                continue
            missing_count += 1
            if missing_count <= MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES:
                lineages.append(self._missing_branch_lineage(token, record.conditions))
                compact_conditions.extend(record.conditions)
        if missing_count <= MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES:
            return lineages
        return [self._missing_branch_summary_lineage(token, compact_conditions, missing_count)]

    def _should_mark_missing_branch_token(self, records: list[BranchRecord], token: str) -> bool:
        for record in records:
            for lin in record.state.tokens.get(token, []):
                if any(": mutate." in loc for loc in lin.parser_locations):
                    return True
        return False

    def _merge_changed_token_lineages(
        self,
        original: AnalyzerState,
        records: list[BranchRecord],
        token: str,
        *,
        unchanged_records: list[BranchRecord] | None = None,
        missing_lineages: list[Lineage] | None = None,
        no_op_records: list[BranchRecord] | None = None,
    ) -> tuple[list[Lineage], set[Key]]:
        unchanged_records = unchanged_records or []
        missing_lineages = missing_lineages or []
        no_op_records = no_op_records or []
        effective_records = list(records)
        for record in no_op_records:
            if token in record.state.tokens:
                effective_records.append(record)
        if all(
            isinstance(record.state.tokens, TokenStore)
            and not record.state.tokens.has_replacement(token)
            and not record.state.tokens.is_deleted(token)
            for record in effective_records
        ):
            original_vals = original.tokens.get(token, [])
            if original_vals:
                initial_keys: set[Key] = set(original._cached_token_lineage_keys(token, original_vals))
                # ``initial_merged`` aliases ``original.tokens[token]``;
                # ``_merge_appended_only`` (and any other consumer) must treat
                # it as read-only — both the Python and native kernels copy via
                # ``list(initial_merged)`` before mutating, so we avoid an
                # eager copy here. Do NOT append to ``initial_merged`` directly
                # or ``original.tokens`` will be silently corrupted.
                initial_merged: list[Lineage] = original_vals
            else:
                initial_keys = set()
                initial_merged = []
            appended_lists: list[list[Lineage]] = [
                record.state.tokens.appended_values(token)
                for record in effective_records
                if isinstance(record.state.tokens, TokenStore)
            ]
            merged, keys, hit_limit = _merge_appended_only(initial_merged, initial_keys, appended_lists)
            if hit_limit:
                summary = self._summarize_token_lineage_fanout(token, merged, len(merged))
                return summary, {_lineage_key(summary[0])}
            return merged, keys

        unchanged_pre_conditioned: list[Lineage] = []
        for record in unchanged_records:
            unchanged_pre_conditioned.extend(
                self._lineages_with_record_conditions(record.state.tokens.get(token, []), record.conditions)
            )
        effective_record_vals: list[list[Lineage]] = [
            record.state.tokens.get(token, []) for record in effective_records
        ]
        merged, keys, hit_limit, total_seen = _merge_with_unchanged_fallback(
            unchanged_pre_conditioned, effective_record_vals, missing_lineages
        )
        if hit_limit:
            summary = self._summarize_token_lineage_fanout(token, merged, total_seen)
            return summary, {_lineage_key(summary[0])}
        return merged, keys

    def _missing_branch_lineage(self, token: str, conditions: list[str]) -> Lineage:
        return Lineage(
            status="unresolved",
            sources=[SourceRef(kind="unknown", source_token=token, expression=token)],
            expression=token,
            conditions=list(conditions),
            notes=["Token is not assigned on this branch path."],
        )

    def _missing_branch_summary_lineage(self, token: str, conditions: list[str], missing_count: int) -> Lineage:
        return Lineage(
            status="unresolved",
            sources=[SourceRef(kind="unknown", source_token=token, expression=token)],
            expression=token,
            conditions=_compact_branch_conditions(conditions),
            notes=[f"Token is not assigned on {missing_count} branch paths; missing branch alternatives summarized."],
        )

    def _lineages_with_record_conditions(self, lineages: list[Lineage], conditions: list[str]) -> list[Lineage]:
        if not conditions:
            return list(lineages)
        conditioned: list[Lineage] = []
        for lin in lineages:
            clone = lin.with_conditions(conditions)
            if clone.conditions and clone.status in _PROMOTABLE_TO_CONDITIONAL_STATUSES:
                clone = clone.with_status("conditional")
            conditioned.append(clone)
        return conditioned

    def _summarize_token_lineage_fanout(self, token: str, lineages: list[Lineage], total_seen: int) -> list[Lineage]:
        loc = next((loc for lin in lineages for loc in lin.parser_locations), None)
        warning = (
            f"{loc or 'branch merge'}: token {token!r} exceeded "
            f"{MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES} branch lineage alternatives; summarized"
        )
        self.add_warning(
            warning,
            code="branch_lineage_fanout",
            message=warning,
            parser_location=loc,
            source_token=token,
        )
        taint = self.add_taint(
            "branch_lineage_fanout",
            f"Token {token!r} exceeded {MAX_TOKEN_LINEAGE_MERGE_ALTERNATIVES} branch lineage alternatives",
            loc,
            token,
        )
        sources = _dedupe_sources(
            src for lin in lineages[:MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES] for src in lin.sources
        )
        conditions = _compact_branch_conditions(
            cond for lin in lineages[:MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES] for cond in lin.conditions
        )
        locations = _dedupe_strings(
            loc_value
            for lin in lineages[:MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES]
            for loc_value in lin.parser_locations
        )[:MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES]
        notes = _dedupe_strings(
            [
                f"{total_seen} branch lineage alternatives were summarized after fanout threshold.",
                *(note for lin in lineages[:MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES] for note in lin.notes),
            ]
        )
        return [
            Lineage(
                status="conditional",
                sources=sources,
                expression=token,
                conditions=conditions,
                parser_locations=locations,
                notes=notes,
                taints=[taint],
            )
        ]

    def _condition_no_op_record(
        self, record: BranchRecord, changed_tokens: set[str], unchanged_branch_keys: dict[str, AbstractSet[Key]]
    ) -> None:
        for token in sorted(changed_tokens):
            if token not in record.state.tokens:
                continue
            shared_keys = unchanged_branch_keys.get(token, set())
            existing_values = record.state.tokens[token]
            if shared_keys and shared_keys is record.state._peek_token_lineage_key_cache(token):
                continue
            conditionable_count = sum(1 for lin in existing_values if _lineage_key(lin) not in shared_keys)
            if conditionable_count > MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES:
                retained = [lin for lin in existing_values if _lineage_key(lin) in shared_keys]
                loc = next((loc for lin in existing_values for loc in lin.parser_locations), None)
                warning = (
                    f"{loc or 'branch merge'}: branch no-op path has {conditionable_count} prior lineage "
                    "alternatives; summarized to avoid quadratic conditioning"
                )
                self.add_warning(
                    warning,
                    code="branch_lineage_fanout",
                    message=warning,
                    parser_location=loc,
                    source_token=token,
                )
                taint = self.add_taint(
                    "branch_lineage_fanout",
                    f"Branch no-op path for {token!r} exceeded "
                    f"{MAX_BRANCH_LINEAGE_CONDITIONING_ALTERNATIVES} lineage alternatives",
                    loc,
                    token,
                )
                retained.append(
                    Lineage(
                        status="conditional",
                        expression=token,
                        conditions=list(record.conditions),
                        parser_locations=[loc] if loc else [],
                        notes=["Prior branch alternatives were summarized after fanout threshold."],
                        taints=[taint],
                    )
                )
                record.state.tokens[token] = _dedupe_lineages(retained)
                continue
            conditioned: list[Lineage] = []
            for lin in existing_values:
                if _lineage_key(lin) in shared_keys:
                    conditioned.append(lin)
                    continue
                clone = lin.with_conditions(record.conditions)
                if clone.conditions and clone.status in _PROMOTABLE_TO_CONDITIONAL_STATUSES:
                    clone = clone.with_status("conditional")
                conditioned.append(clone)
            record.state.tokens[token] = _dedupe_lineages(conditioned)


_DEFAULT_DYNAMIC_TEMPLATE_PATTERN = AnalyzerState.dynamic_template_pattern
