"""Small AST for a useful subset of Google SecOps / Chronicle parser code."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._types import ConfigPair
from .model import SyntaxDiagnostic


@dataclass
class Statement:
    line: int


@dataclass
class Plugin(Statement):
    name: str
    body: str
    config: list[ConfigPair] = field(default_factory=list)
    config_diagnostics: list[SyntaxDiagnostic] = field(default_factory=list)
    body_line: int | None = None


@dataclass
class ElifBlock(Statement):
    condition: str
    body: list[Statement]


@dataclass
class IfBlock(Statement):
    condition: str
    then_body: list[Statement]
    elifs: list[ElifBlock] = field(default_factory=list)
    else_body: list[Statement] | None = None


@dataclass
class ForBlock(Statement):
    variables: list[str]
    iterable: str
    is_map: bool
    body: list[Statement]
    header: str


@dataclass
class Unknown(Statement):
    text: str


@dataclass
class IOBlock(Statement):
    """Top-level ``input { ... }`` or ``output { ... }`` block.

    Logstash pipelines have three top-level block kinds: ``input`` defines
    where events come from, ``filter`` transforms them, ``output`` decides
    where they go. The analyzer's primary job is filter-stage lineage, but
    surfacing input/output anchors gives users a complete picture of an
    event's path through the pipeline.

    Children are the inner plugin statements (and nested if/for blocks) the
    analyzer would otherwise have walked at top level.
    """

    kind: str  # "input" or "output"
    body: list[Statement] = field(default_factory=list)
