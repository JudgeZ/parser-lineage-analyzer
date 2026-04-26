"""Data model for SecOps parser reverse-lineage results."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal, TypedDict, TypeVar

from ._types import FrozenJSONDict, FrozenJSONValue, JSONDict, JSONValue

# Word-boundary match for the ``merge``/``add_tag``/``add_field`` evidence
# tokens that promote a multi-mapping ``QueryResult`` to ``repeated`` status.
# Compiled once at module import to avoid the per-call cost in the hot
# ``_status_from_aggregate`` path. The ``\b`` boundaries prevent
# false-positives on substring-collisions like ``remerge``, ``merger``,
# ``premerge``, ``add_field_validator`` — none exist in the current code
# corpus, but the substring form was a sharp edge for any future analyzer
# extension that introduces such names.
_MERGE_EVIDENCE_PATTERN = re.compile(r"\b(?:merge|add_tag|add_field)\b", re.IGNORECASE)

# Per-mapping lineage status assigned to a single ``Lineage`` row.
#
# Values (kept consistent with the README "Output statuses" section):
#   - ``exact``: one direct raw source field, JSON path, XML XPath, KV key,
#     CSV column, loop item, or map key/value.
#   - ``exact_capture``: Grok or named-regex capture from a source token.
#   - ``conditional``: one or more branch predicates are required for this
#     mapping to fire.
#   - ``derived``: value is transformed or built from multiple
#     tokens/constants.
#   - ``constant``: parser assigns a literal value.
#   - ``repeated``: parser uses ``merge``/append-style semantics.
#   - ``dynamic``: at least one path depends on runtime data such as a
#     destination template.
#   - ``removed``: parser removed the field.
#   - ``unresolved``: source could not be inferred from the implemented
#     subset.
LineageStatus = Literal[
    "exact",
    "exact_capture",
    "conditional",
    "derived",
    "constant",
    "repeated",
    "dynamic",
    "removed",
    "unresolved",
]

# Aggregate status reported by ``QueryResult.status`` for a whole query.
#
# Includes every ``LineageStatus`` value, plus:
#   - ``partial``: the query has mixed resolved/removed/unresolved paths.
#
# Dynamic or unresolved uncertainty takes precedence over conditionality
# when collapsing per-mapping statuses; use ``QueryResult.is_conditional``,
# ``has_dynamic``, ``has_unresolved``, and ``has_taints`` for orthogonal
# gates.
QueryStatus = Literal[
    "exact",
    "exact_capture",
    "conditional",
    "derived",
    "constant",
    "repeated",
    "dynamic",
    "removed",
    "partial",
    "unresolved",
]

LINEAGE_STATUS_ORDER: tuple[LineageStatus, ...] = (
    "exact",
    "exact_capture",
    "conditional",
    "derived",
    "constant",
    "repeated",
    "dynamic",
    "removed",
    "unresolved",
)
QUERY_STATUS_ORDER: tuple[QueryStatus, ...] = (
    "exact",
    "exact_capture",
    "conditional",
    "derived",
    "constant",
    "repeated",
    "dynamic",
    "removed",
    "partial",
    "unresolved",
)
LINEAGE_STATUS_VALUES: frozenset[str] = frozenset(LINEAGE_STATUS_ORDER)
QUERY_STATUS_VALUES: frozenset[str] = frozenset(QUERY_STATUS_ORDER)
HashableValue = TypeVar("HashableValue")


MAX_LINEAGE_TRANSFORMATIONS = 128
MAX_PARSER_LOCATIONS_PER_LINEAGE = 128


@dataclass(frozen=True, slots=True, eq=False)
class _FrozenDetails(Mapping[str, FrozenJSONValue]):
    items_tuple: tuple[tuple[str, FrozenJSONValue], ...] = ()
    _key_tuple: tuple[tuple[str, object], ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "_key_tuple", tuple(sorted((key, _frozen_details_key(value)) for key, value in self.items_tuple))
        )

    def __getitem__(self, key: str) -> FrozenJSONValue:
        for item_key, value in self.items_tuple:
            if item_key == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        for key, _value in self.items_tuple:
            yield key

    def __len__(self) -> int:
        return len(self.items_tuple)

    def __eq__(self, other: object) -> bool:
        # Compare by the order-insensitive _key_tuple so equality matches the
        # contract used by SourceRef._analysis_key (which calls
        # _freeze_for_key/_frozen_details_key — both sort by key). Without this,
        # the auto-generated __eq__ over items_tuple would treat
        # _FrozenDetails((('a',1),('b',2))) as != _FrozenDetails((('b',2),('a',1)))
        # while the dedupe key would treat them as equal — a latent divergence.
        if not isinstance(other, _FrozenDetails):
            return NotImplemented
        return self._key_tuple == other._key_tuple

    def __hash__(self) -> int:
        return hash(self._key_tuple)

    @property
    def key_tuple(self) -> tuple[tuple[str, object], ...]:
        return self._key_tuple


def _frozen_details_key(value: FrozenJSONValue) -> object:
    if isinstance(value, _FrozenDetails):
        return value.key_tuple
    if isinstance(value, tuple):
        return tuple(_frozen_details_key(item) for item in value)
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), _frozen_details_key(item)) for key, item in value.items()))
    return value


_EMPTY_DETAILS: FrozenJSONDict = _FrozenDetails()


def _freeze_details(value: JSONValue | FrozenJSONValue) -> FrozenJSONValue:
    if isinstance(value, _FrozenDetails):
        return value
    if isinstance(value, Mapping):
        if not value:
            return _EMPTY_DETAILS
        return _FrozenDetails(tuple((str(k), _freeze_details(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_details(v) for v in value)
    return value


def _details_to_json(value: FrozenJSONValue) -> JSONValue:
    if isinstance(value, Mapping):
        if not value:
            return {}
        return {str(k): _details_to_json(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_details_to_json(v) for v in value]
    return value


def _freeze_for_key(value: object) -> object:
    """Mirror of ``_analysis_dedupe._freeze_value_python`` available without an
    upward import. Used by model dataclasses to populate ``_analysis_key`` at
    construction time."""

    if isinstance(value, _FrozenDetails):
        return value.key_tuple
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _freeze_for_key(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_for_key(v) for v in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze_for_key(v) for v in value), key=repr))
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def _tuple_unique(values: Iterable[HashableValue]) -> tuple[HashableValue, ...]:
    # Fast path: ``dict.fromkeys`` preserves insertion order and is ~2.6x
    # faster than the per-element try/except fallback when every element is
    # hashable (the common case in Lineage.with_updates and friends). Falls
    # through to the slow path on any unhashable value. Materialize once so
    # iterator inputs aren't exhausted before the fallback runs.
    materialized = tuple(values)
    try:
        return tuple(dict.fromkeys(materialized))
    except TypeError:
        pass
    out: list[HashableValue] = []
    seen_hashable: set[HashableValue] = set()
    for value in materialized:
        try:
            if value in seen_hashable:
                continue
            seen_hashable.add(value)
            out.append(value)
        except TypeError:
            if value in out:
                continue
            out.append(value)
    return tuple(out)


def _first_query_status(statuses: Iterable[str]) -> QueryStatus:
    for status in QUERY_STATUS_ORDER:
        if status in statuses:
            return status
    return "unresolved"


@dataclass(frozen=True, slots=True)
class SyntaxDiagnostic:
    """Structured syntax diagnostic produced by statement/config parsing."""

    line: int
    column: int
    message: str

    def to_json(self) -> JSONDict:
        return {"line": self.line, "column": self.column, "message": self.message}


@dataclass(frozen=True, slots=True)
class SourceRef:
    """A symbolic source location in the original log or parser runtime state.

    This intentionally does not contain field values. It describes where a value
    would come from if the parser took a path that assigns it.
    """

    kind: str
    source_token: str | None = None
    path: str | None = None
    capture_name: str | None = None
    column: int | None = None
    pattern: str | None = None
    expression: str | None = None
    details: FrozenJSONDict = field(default_factory=lambda: _EMPTY_DETAILS)
    _analysis_key: tuple[object, ...] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", _freeze_details(self.details))
        object.__setattr__(
            self,
            "_analysis_key",
            (
                self.kind,
                self.source_token,
                self.path,
                self.capture_name,
                self.column,
                self.pattern,
                self.expression,
                _freeze_for_key(self.details),
            ),
        )

    def __hash__(self) -> int:
        return hash(self._analysis_key)

    def __eq__(self, other: object) -> bool:
        if other.__class__ is not SourceRef:
            return NotImplemented
        return self._analysis_key == other._analysis_key

    def short(self) -> str:
        if self.kind == "json_path":
            return f"json:{self.source_token}.{self.path}" if self.source_token else f"json:{self.path}"
        if self.kind == "xml_xpath":
            return f"xml:{self.source_token}:{self.path}"
        if self.kind == "kv_key":
            return f"kv:{self.source_token}:{self.path}"
        if self.kind == "csv_column":
            return f"csv:{self.source_token}:column{self.column}"
        if self.kind in {"grok_capture", "regex_capture", "dissect_field"}:
            return f"{self.kind}:{self.source_token}:{self.capture_name}"
        if self.kind == "constant":
            return f"constant:{self.expression!r}"
        if self.kind in {"loop_item", "map_key", "map_value"}:
            return f"{self.kind}:{self.path or self.source_token}"
        if self.path:
            return f"{self.kind}:{self.path}"
        if self.source_token:
            return f"{self.kind}:{self.source_token}"
        return self.kind

    def to_json(self) -> JSONDict:
        data: JSONDict = {"kind": self.kind}
        if self.source_token is not None:
            data["source_token"] = self.source_token
        if self.path is not None:
            data["path"] = self.path
        if self.capture_name is not None:
            data["capture_name"] = self.capture_name
        if self.column is not None:
            data["column"] = self.column
        if self.pattern is not None:
            data["pattern"] = self.pattern
        if self.expression is not None:
            data["expression"] = self.expression
        if self.details:
            data["details"] = _details_to_json(self.details)
        return data


@dataclass(frozen=True, slots=True)
class TaintReason:
    """Structured reason why a lineage became dynamic or unresolved."""

    code: str
    message: str
    parser_location: str | None = None
    source_token: str | None = None
    _analysis_key: tuple[object, ...] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_analysis_key",
            (self.code, self.parser_location, self.source_token, self.message),
        )

    def __hash__(self) -> int:
        return hash(self._analysis_key)

    def __eq__(self, other: object) -> bool:
        if other.__class__ is not TaintReason:
            return NotImplemented
        return self._analysis_key == other._analysis_key

    def to_json(self) -> JSONDict:
        data: JSONDict = {
            "code": self.code,
            "message": self.message,
            "parser_location": self.parser_location,
            "source_token": self.source_token,
        }
        return {k: v for k, v in data.items() if v is not None}


@dataclass(frozen=True, slots=True)
class WarningReason:
    """Structured companion to the public warning string."""

    code: str
    message: str
    parser_location: str | None = None
    source_token: str | None = None
    warning: str | None = None
    _analysis_key: tuple[object, ...] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_analysis_key",
            (self.code, self.parser_location, self.source_token, self.message, self.warning),
        )

    def __hash__(self) -> int:
        return hash(self._analysis_key)

    def __eq__(self, other: object) -> bool:
        if other.__class__ is not WarningReason:
            return NotImplemented
        return self._analysis_key == other._analysis_key

    def to_json(self) -> JSONDict:
        data: JSONDict = {
            "code": self.code,
            "message": self.message,
            "parser_location": self.parser_location,
            "source_token": self.source_token,
            "warning": self.warning,
        }
        return {k: v for k, v in data.items() if v not in (None, {}, [])}


@dataclass(frozen=True, slots=True)
class DiagnosticRecord:
    """Single diagnostic sink used to derive warnings, unsupported items, and taints."""

    code: str
    message: str
    kind: Literal["warning", "unsupported", "taint"] = "warning"
    parser_location: str | None = None
    source_token: str | None = None
    warning: str | None = None
    unsupported: str | None = None
    taint: TaintReason | None = None
    strict: bool = True
    _analysis_key: tuple[object, ...] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        taint_key = self.taint._analysis_key if self.taint is not None else None
        object.__setattr__(
            self,
            "_analysis_key",
            (
                self.code,
                self.kind,
                self.parser_location,
                self.source_token,
                self.message,
                self.warning,
                self.unsupported,
                taint_key,
                self.strict,
            ),
        )

    def __hash__(self) -> int:
        return hash(self._analysis_key)

    def __eq__(self, other: object) -> bool:
        if other.__class__ is not DiagnosticRecord:
            return NotImplemented
        return self._analysis_key == other._analysis_key

    def to_json(self) -> JSONDict:
        data: JSONDict = {
            "code": self.code,
            "kind": self.kind,
            "message": self.message,
            "parser_location": self.parser_location,
            "source_token": self.source_token,
            "warning": self.warning,
            "unsupported": self.unsupported,
            "taint": self.taint.to_json() if self.taint else None,
            "strict": self.strict,
        }
        return {k: v for k, v in data.items() if v is not None}


@dataclass(frozen=True, slots=True)
class Lineage:
    """Symbolic provenance for one assignment into one token/UDM field."""

    status: LineageStatus
    sources: Sequence[SourceRef] = field(default_factory=tuple)
    expression: str | None = None
    transformations: Sequence[str] = field(default_factory=tuple)
    conditions: Sequence[str] = field(default_factory=tuple)
    parser_locations: Sequence[str] = field(default_factory=tuple)
    notes: Sequence[str] = field(default_factory=tuple)
    taints: Sequence[TaintReason] = field(default_factory=tuple)
    # Phase 4C: tracked runtime type when known. "unknown" by default so all
    # existing lineages produced before the type-promotion handlers landed
    # remain equality-equivalent. Values: "string" | "array" | "object" |
    # "unknown".
    value_type: str = "unknown"
    _analysis_key: tuple[object, ...] | None = field(default=None, init=False, repr=False, compare=False)
    _condition_set_cache: frozenset[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", tuple(self.sources))
        object.__setattr__(self, "transformations", tuple(self.transformations))
        object.__setattr__(self, "conditions", tuple(self.conditions))
        object.__setattr__(self, "parser_locations", tuple(self.parser_locations))
        object.__setattr__(self, "notes", tuple(self.notes))
        object.__setattr__(self, "taints", tuple(self.taints))
        object.__setattr__(
            self,
            "_analysis_key",
            (
                self.status,
                tuple(src._analysis_key for src in self.sources),
                self.expression,
                self.transformations,
                self.conditions,
                self.parser_locations,
                self.notes,
                tuple(taint._analysis_key for taint in self.taints),
                self.value_type,
            ),
        )

    def __hash__(self) -> int:
        return hash(self._analysis_key)

    def __eq__(self, other: object) -> bool:
        if other.__class__ is not Lineage:
            return NotImplemented
        return self._analysis_key == other._analysis_key

    def clone(self) -> Lineage:
        return self

    def with_status(self, status: LineageStatus) -> Lineage:
        if status == self.status:
            return self
        return replace(self, status=status)

    def with_sources(self, sources: Iterable[SourceRef]) -> Lineage:
        source_tuple = tuple(sources)
        if source_tuple == self.sources:
            return self
        return replace(self, sources=source_tuple)

    def with_updates(
        self,
        *,
        status: LineageStatus | None = None,
        sources: Iterable[SourceRef] | None = None,
        conditions: Iterable[str] = (),
        parser_locations: Iterable[str] = (),
        notes: Iterable[str] = (),
        taints: Iterable[TaintReason] = (),
        transformations: Iterable[str] = (),
    ) -> Lineage:
        next_status = status or self.status
        next_sources = tuple(sources) if sources is not None else self.sources
        next_conditions = _tuple_unique((*self.conditions, *(condition for condition in conditions if condition)))
        next_locations = _tuple_unique((*self.parser_locations, *parser_locations))
        next_notes = _tuple_unique((*self.notes, *notes))
        next_taints = _tuple_unique((*self.taints, *taints))
        next_transformations = _tuple_unique((*self.transformations, *transformations))
        if len(next_locations) > MAX_PARSER_LOCATIONS_PER_LINEAGE:
            omitted = len(next_locations) - MAX_PARSER_LOCATIONS_PER_LINEAGE
            next_locations = next_locations[:MAX_PARSER_LOCATIONS_PER_LINEAGE]
            next_notes = _tuple_unique((*next_notes, f"{omitted} additional parser locations omitted after compaction"))
        if len(next_transformations) > MAX_LINEAGE_TRANSFORMATIONS:
            omitted = len(next_transformations) - MAX_LINEAGE_TRANSFORMATIONS
            next_transformations = next_transformations[:MAX_LINEAGE_TRANSFORMATIONS]
            next_notes = _tuple_unique((*next_notes, f"{omitted} additional transformations omitted after compaction"))
        if (
            next_status == self.status
            and next_sources == self.sources
            and next_conditions == self.conditions
            and next_locations == self.parser_locations
            and next_notes == self.notes
            and next_taints == self.taints
            and next_transformations == self.transformations
        ):
            return self
        return replace(
            self,
            status=next_status,
            sources=next_sources,
            transformations=next_transformations,
            conditions=next_conditions,
            parser_locations=next_locations,
            notes=next_notes,
            taints=next_taints,
        )

    def with_value_type(self, value_type: str) -> Lineage:
        """Phase 4C: tag the runtime type. Returns self if unchanged."""
        if value_type == self.value_type:
            return self
        return replace(self, value_type=value_type)

    @staticmethod
    def union_value_types(lineages: Iterable[Lineage]) -> str:
        """R1.2: collapse a list of lineages' value_types into a single tag.

        - All entries "unknown" → "unknown"
        - All non-unknown entries equal → that single type
        - Mixed non-unknown entries → "mixed"
        - "unknown" entries are ignored when forming the union, since the
          analyzer simply hasn't determined the type yet — they shouldn't
          pollute a definite type from another branch.
        """
        seen: set[str] = set()
        for lin in lineages:
            vt = lin.value_type
            if vt and vt != "unknown":
                seen.add(vt)
        if not seen:
            return "unknown"
        if len(seen) == 1:
            return next(iter(seen))
        return "mixed"

    def with_conditions(self, conditions: Iterable[str]) -> Lineage:
        incoming = tuple(condition for condition in conditions if condition)
        if not incoming:
            return self
        if len(incoming) <= 8:
            extra: list[str] = []
            if len(self.conditions) > 32:
                existing = self._condition_set_cache
                if existing is None:
                    existing = frozenset(self.conditions)
                    object.__setattr__(self, "_condition_set_cache", existing)
                for condition in incoming:
                    if condition not in existing and condition not in extra:
                        extra.append(condition)
            else:
                for condition in incoming:
                    if condition not in self.conditions and condition not in extra:
                        extra.append(condition)
            if not extra:
                return self
            return self._with_condition_tuple((*self.conditions, *extra))
        return self._with_condition_tuple(_tuple_unique([*self.conditions, *incoming]))

    def _with_condition_tuple(self, conditions: Sequence[str]) -> Lineage:
        return replace(self, conditions=conditions)

    def with_parser_locations(self, locations: Iterable[str]) -> Lineage:
        return self.with_updates(parser_locations=locations)

    def with_notes(self, notes: Iterable[str]) -> Lineage:
        return self.with_updates(notes=notes)

    def with_taints(self, taints: Iterable[TaintReason]) -> Lineage:
        return self.with_updates(taints=taints)

    def with_transformations(self, transformations: Iterable[str]) -> Lineage:
        return self.with_updates(transformations=transformations)

    def with_taint(
        self,
        code: str,
        message: str,
        parser_location: str | None = None,
        source_token: str | None = None,
    ) -> Lineage:
        taint = TaintReason(code=code, message=message, parser_location=parser_location, source_token=source_token)
        return self.with_taints([taint])

    def with_transform(self, transform: str, location: str | None = None) -> Lineage:
        clone = self.with_transformations([transform] if transform else [])
        if location:
            clone = clone.with_parser_locations([location])
        if clone.status in {"exact", "exact_capture", "constant"}:
            clone = clone.with_status("derived")
        return clone

    def to_json(self) -> JSONDict:
        out: JSONDict = {
            "status": self.status,
            "sources": [s.to_json() for s in self.sources],
        }
        if self.expression is not None:
            out["expression"] = self.expression
        if self.transformations:
            out["transformations"] = list(self.transformations)
        if self.conditions:
            out["conditions"] = list(self.conditions)
        if self.parser_locations:
            out["parser_locations"] = list(self.parser_locations)
        if self.notes:
            out["notes"] = list(self.notes)
        if self.taints:
            out["taints"] = [
                taint.to_json()
                for taint in sorted(
                    set(self.taints),
                    key=lambda t: (t.code, t.parser_location or "", t.source_token or "", t.message),
                )
            ]
        # Phase 4C: only emit value_type when the analyzer has tagged it,
        # so existing JSON snapshots produced before type tracking landed
        # don't drift.
        if self.value_type and self.value_type != "unknown":
            out["value_type"] = self.value_type
        return out


@dataclass(frozen=True, slots=True)
class OutputAnchor:
    anchor: str
    conditions: Iterable[str] = field(default_factory=tuple)
    parser_locations: Iterable[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "conditions", tuple(self.conditions))
        object.__setattr__(self, "parser_locations", tuple(self.parser_locations))

    def to_json(self) -> JSONDict:
        data: JSONDict = {"anchor": self.anchor}
        if self.conditions:
            data["conditions"] = list(self.conditions)
        if self.parser_locations:
            data["parser_locations"] = list(self.parser_locations)
        return data


@dataclass(frozen=True, slots=True)
class IOAnchor:
    """A top-level input{}/output{} block plugin instance.

    Where ``OutputAnchor`` represents an event sink named via ``@output``,
    ``IOAnchor`` represents the Logstash-style ``input { kafka { ... } }``
    or ``output { elasticsearch { ... } }`` block plugin invocation. The
    analyzer doesn't model these plugins' lineage, but it records that
    they exist so downstream tooling can answer "where do my events come
    from / go to" without re-parsing the source.
    """

    kind: str  # "input" or "output"
    plugin: str
    conditions: Iterable[str] = field(default_factory=tuple)
    parser_locations: Iterable[str] = field(default_factory=tuple)
    # T3.2: optional config-key/value pairs for human-readable plugin
    # provenance (e.g. ``("topics", "['events']")``). Captured per a
    # per-plugin allowlist so the I/O anchor is enough to answer "what
    # topic does this kafka input read" without re-parsing the source.
    config_summary: Iterable[tuple[str, str]] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "conditions", tuple(self.conditions))
        object.__setattr__(self, "parser_locations", tuple(self.parser_locations))
        object.__setattr__(self, "config_summary", tuple(self.config_summary))

    def to_json(self) -> JSONDict:
        data: JSONDict = {"kind": self.kind, "plugin": self.plugin}
        if self.conditions:
            data["conditions"] = list(self.conditions)
        if self.parser_locations:
            data["parser_locations"] = list(self.parser_locations)
        if self.config_summary:
            data["config_summary"] = [list(pair) for pair in self.config_summary]
        return data


@dataclass(frozen=True, slots=True)
class QuerySemanticSummary:
    """Compact semantics for mappings omitted from sampled query results."""

    statuses: tuple[str, ...] = ()
    is_conditional: bool = False
    has_taints: bool = False

    def with_lineages(
        self,
        lineages: Iterable[Lineage],
        *,
        statuses: Iterable[str] = (),
        conditions: Iterable[str] = (),
    ) -> QuerySemanticSummary:
        lineages_tuple = tuple(lineages)
        statuses_tuple = tuple(statuses)
        lineage_statuses = () if statuses_tuple else tuple(lineage.status for lineage in lineages_tuple)
        next_statuses = _tuple_unique((*self.statuses, *statuses_tuple, *lineage_statuses))
        next_is_conditional = (
            self.is_conditional or any(conditions) or any(lineage.conditions for lineage in lineages_tuple)
        )
        next_has_taints = self.has_taints or any(lineage.taints for lineage in lineages_tuple)
        if (
            next_statuses == self.statuses
            and next_is_conditional == self.is_conditional
            and next_has_taints == self.has_taints
        ):
            return self
        return QuerySemanticSummary(
            statuses=next_statuses,
            is_conditional=next_is_conditional,
            has_taints=next_has_taints,
        )

    def with_summary(self, summary: QuerySemanticSummary, *, conditions: Iterable[str] = ()) -> QuerySemanticSummary:
        next_statuses = _tuple_unique((*self.statuses, *summary.statuses))
        next_is_conditional = self.is_conditional or summary.is_conditional or any(conditions)
        next_has_taints = self.has_taints or summary.has_taints
        if (
            next_statuses == self.statuses
            and next_is_conditional == self.is_conditional
            and next_has_taints == self.has_taints
        ):
            return self
        return QuerySemanticSummary(
            statuses=next_statuses,
            is_conditional=next_is_conditional,
            has_taints=next_has_taints,
        )


@dataclass(frozen=True, slots=True)
class QueryResultAggregate:
    """Computed-once snapshot of every cross-mapping property of a ``QueryResult``.

    Returned by :meth:`QueryResult.aggregate`. Renderers and consumers that
    need more than one of the derived fields (``status``,
    ``is_conditional``, ``has_dynamic``, etc.) can call ``.aggregate()``
    once and read multiple fields off the result instead of paying the
    derivation cost per property access. The individual ``QueryResult``
    properties (``status``, ``is_conditional``, ...) wrap exactly this and
    remain the recommended path for one-off reads.
    """

    statuses: frozenset[str]
    status: QueryStatus
    invalid_lineage_statuses: tuple[str, ...]
    is_conditional: bool
    has_dynamic: bool
    has_unresolved: bool
    has_taints: bool


@dataclass(slots=True)
class QueryResult:
    udm_field: str
    normalized_candidates: list[str]
    mappings: list[Lineage]
    normalized_candidates_total: int | None = None
    mappings_total: int | None = None
    output_anchors: list[OutputAnchor] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    structured_warnings: list[WarningReason] = field(default_factory=list)
    diagnostics: list[DiagnosticRecord] = field(default_factory=list)
    semantic_summary: QuerySemanticSummary = field(default_factory=QuerySemanticSummary)

    @property
    def status(self) -> QueryStatus:
        return self.aggregate().status

    def aggregate(self) -> QueryResultAggregate:
        """Compute every cross-mapping derived property in a single pass.

        Returns a :class:`QueryResultAggregate` snapshot. Callers that need
        more than one of ``status``/``is_conditional``/``has_dynamic``/
        ``has_unresolved``/``has_taints``/``invalid_lineage_statuses``
        should use this method once and read fields off the result rather
        than going through the per-property accessors, which each call
        ``aggregate()`` themselves.
        """
        mapping_statuses = set(self.semantic_summary.statuses)
        has_conditions = self.semantic_summary.is_conditional
        has_taints = self.semantic_summary.has_taints
        for mapping in self.mappings:
            mapping_statuses.add(mapping.status)
            has_conditions = has_conditions or bool(mapping.conditions)
            has_taints = has_taints or bool(mapping.taints)
        invalid_statuses = tuple(sorted(str(status) for status in mapping_statuses - LINEAGE_STATUS_VALUES))
        has_unresolved = not mapping_statuses or any(
            status == "unresolved" or status not in LINEAGE_STATUS_VALUES for status in mapping_statuses
        )
        return QueryResultAggregate(
            statuses=frozenset(mapping_statuses),
            status=self._status_from_aggregate(mapping_statuses, has_conditions),
            invalid_lineage_statuses=invalid_statuses,
            is_conditional=has_conditions,
            has_dynamic="dynamic" in mapping_statuses,
            has_unresolved=has_unresolved,
            has_taints=has_taints,
        )

    def _status_from_aggregate(self, mapping_statuses: set[str], is_conditional: bool) -> QueryStatus:
        if not mapping_statuses:
            return "unresolved"
        valid_statuses = mapping_statuses & LINEAGE_STATUS_VALUES
        unknown = mapping_statuses - LINEAGE_STATUS_VALUES
        if unknown:
            return "partial" if valid_statuses else "unresolved"
        if valid_statuses == {"unresolved"}:
            return "unresolved"
        if "unresolved" in valid_statuses or ("removed" in valid_statuses and valid_statuses != {"removed"}):
            return "partial"
        if "dynamic" in valid_statuses:
            return "dynamic"
        if valid_statuses == {"removed"}:
            return "removed"
        if is_conditional:
            return "conditional"
        if self.total_mappings > 1:
            # Multiple unconditional mappings are usually append/merge output,
            # not branch logic. Do not label these as conditional unless branch
            # predicates are actually present.
            #
            # Bug C1: gate `repeated` on actual evidence of merge/append
            # semantics rather than the mere presence of >=2 unconditional
            # mappings. Conservative signals that qualify:
            #   1. any mapping's status is literally `repeated`
            #   2. any mapping carries a transformation OR parser_location
            #      whose tokens include a merge/append-style operation
            #      (`merge`, `add_tag`, `add_field`) — matched by
            #      ``_MERGE_EVIDENCE_PATTERN`` with word boundaries to avoid
            #      false-positives on substring-collisions like ``remerge``
            #      or ``add_field_validator``.
            # Otherwise, fall back to `derived` — multiple mappings with no
            # merge/append evidence are derived from multiple sources, not a
            # repeated/append-style write.
            if "repeated" in valid_statuses:
                return "repeated"
            for mapping in self.mappings:
                for marker in (*mapping.transformations, *mapping.parser_locations):
                    if _MERGE_EVIDENCE_PATTERN.search(str(marker)):
                        return "repeated"
            return "derived"
        return _first_query_status(valid_statuses)

    @property
    def total_mappings(self) -> int:
        return self.mappings_total if self.mappings_total is not None else len(self.mappings)

    @property
    def total_normalized_candidates(self) -> int:
        return (
            self.normalized_candidates_total
            if self.normalized_candidates_total is not None
            else len(self.normalized_candidates)
        )

    @property
    def _semantic_statuses(self) -> set[str]:
        return set(self.aggregate().statuses)

    @property
    def invalid_lineage_statuses(self) -> list[str]:
        return list(self.aggregate().invalid_lineage_statuses)

    @property
    def effective_diagnostics(self) -> list[DiagnosticRecord]:
        return self.compute_effective_diagnostics(self.aggregate())

    def compute_effective_diagnostics(self, aggregate: QueryResultAggregate) -> list[DiagnosticRecord]:
        """Return diagnostics including any synthesized from invalid statuses.

        Takes a precomputed :class:`QueryResultAggregate` so renderers that
        already called :meth:`aggregate` don't have to recompute it. The
        no-args :attr:`effective_diagnostics` property is the convenience
        equivalent for one-off reads.
        """
        diagnostics = list(self.diagnostics)
        invalid_statuses = aggregate.invalid_lineage_statuses
        if invalid_statuses:
            diagnostics.append(
                DiagnosticRecord(
                    code="invalid_lineage_status",
                    kind="warning",
                    message=f"Unknown lineage status values: {', '.join(invalid_statuses)}",
                    warning=f"Unknown lineage status values: {', '.join(invalid_statuses)}",
                    strict=True,
                )
            )
        return diagnostics

    @property
    def is_conditional(self) -> bool:
        return self.aggregate().is_conditional

    @property
    def has_dynamic(self) -> bool:
        return self.aggregate().has_dynamic

    @property
    def has_unresolved(self) -> bool:
        return self.aggregate().has_unresolved

    @property
    def has_taints(self) -> bool:
        return self.aggregate().has_taints

    def to_json(self) -> JSONDict:
        aggregate = self.aggregate()
        diagnostics = self.compute_effective_diagnostics(aggregate)
        data: JSONDict = {
            "udm_field": self.udm_field,
            "status": aggregate.status,
            "is_conditional": aggregate.is_conditional,
            "has_dynamic": aggregate.has_dynamic,
            "has_unresolved": aggregate.has_unresolved,
            "has_taints": aggregate.has_taints,
            "normalized_candidates": self.normalized_candidates,
            "mappings": [m.to_json() for m in self.mappings],
        }
        if self.normalized_candidates_total is not None:
            data["normalized_candidates_total"] = self.normalized_candidates_total
        if self.mappings_total is not None:
            data["mappings_total"] = self.mappings_total
        if self.output_anchors:
            data["output_anchors"] = [a.to_json() for a in self.output_anchors]
        if self.unsupported:
            data["unsupported"] = self.unsupported
        if self.warnings:
            data["warnings"] = self.warnings
        if self.structured_warnings:
            data["structured_warnings"] = [warning.to_json() for warning in self.structured_warnings]
        if diagnostics:
            data["diagnostics"] = [diagnostic.to_json() for diagnostic in diagnostics]
        return data


class AnalysisSummaryDict(TypedDict, total=False):
    """Static shape of :meth:`ReverseParser.analysis_summary` (non-compact).

    Every key is optional (``total=False``) because some entries — notably
    ``value_type_summary`` — are only emitted when the underlying analyzer
    state has anything to report. The runtime values follow the same
    JSON-compatible semantics as ``JSONDict`` (see ``_types.JSONValue``); this
    TypedDict simply pins the per-key types so static consumers don't need to
    rediscover them via ``isinstance`` guards on every read.
    """

    udm_fields: list[str]
    output_anchors: list[JSONDict]
    unsupported: list[str]
    warnings: list[str]
    structured_warnings: list[JSONDict]
    diagnostics: list[JSONDict]
    taints: list[JSONDict]
    token_count: int
    json_extractions: list[JSONDict]
    csv_extractions: list[JSONDict]
    kv_extractions: list[JSONDict]
    xml_extractions: list[JSONDict]
    value_type_summary: dict[str, JSONValue]


class CompactAnalysisSummaryDict(TypedDict, total=False):
    """Static shape of :meth:`ReverseParser.analysis_summary` (compact).

    Mirrors :class:`AnalysisSummaryDict` and adds the ``*_total`` counters,
    the ``compact_summary`` envelope, and the per-code count maps emitted only
    by the bounded summary path. ``total=False`` keeps the contract honest:
    not every counter is present in every payload (the implementation only
    emits the keys it actually populates), so callers should still go through
    ``.get()`` / the CLI ``_summary_*`` helpers.
    """

    compact_summary: dict[str, JSONValue]
    udm_fields: list[str]
    udm_fields_total: int
    output_anchors: list[JSONDict]
    unsupported: list[str]
    warnings: list[str]
    structured_warnings: list[JSONDict]
    diagnostics: list[JSONDict]
    taints: list[JSONDict]
    token_count: int
    json_extractions: list[JSONDict]
    csv_extractions: list[JSONDict]
    kv_extractions: list[JSONDict]
    xml_extractions: list[JSONDict]
    warning_counts: dict[str, int]
    taint_counts: dict[str, int]
    diagnostic_counts: dict[str, int]
    unsupported_total: int
    warnings_total: int
    structured_warnings_total: int
    diagnostics_total: int
    taints_total: int
    output_anchors_total: int
    json_extractions_total: int
    csv_extractions_total: int
    kv_extractions_total: int
    xml_extractions_total: int
