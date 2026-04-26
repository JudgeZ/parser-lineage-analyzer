"""Parser Lineage Analyzer for Google SecOps / Chronicle parser code."""

from __future__ import annotations

from typing import TYPE_CHECKING

_PUBLIC_EXPORTS = (
    "ReverseParser",
    "QueryResult",
    "QueryResultAggregate",
    "Lineage",
    "LineageStatus",
    "QueryStatus",
    "SourceRef",
    "OutputAnchor",
    "IOAnchor",
    "TaintReason",
    "WarningReason",
    "DiagnosticRecord",
    "SyntaxDiagnostic",
)
if not TYPE_CHECKING:
    for _export in _PUBLIC_EXPORTS:
        globals().pop(_export, None)
    del _export

if TYPE_CHECKING:
    from .analyzer import ReverseParser as ReverseParser
    from .model import (
        DiagnosticRecord as DiagnosticRecord,
        IOAnchor as IOAnchor,
        Lineage as Lineage,
        LineageStatus as LineageStatus,
        OutputAnchor as OutputAnchor,
        QueryResult as QueryResult,
        QueryResultAggregate as QueryResultAggregate,
        QueryStatus as QueryStatus,
        SourceRef as SourceRef,
        SyntaxDiagnostic as SyntaxDiagnostic,
        TaintReason as TaintReason,
        WarningReason as WarningReason,
    )

__all__ = list(_PUBLIC_EXPORTS)
__version__ = "0.1.0"

_MODEL_EXPORTS = {
    "QueryResult",
    "QueryResultAggregate",
    "Lineage",
    "LineageStatus",
    "QueryStatus",
    "SourceRef",
    "OutputAnchor",
    "IOAnchor",
    "TaintReason",
    "WarningReason",
    "DiagnosticRecord",
    "SyntaxDiagnostic",
}


def __getattr__(name: str) -> object:
    if name == "ReverseParser":
        from .analyzer import ReverseParser

        globals()[name] = ReverseParser
        return ReverseParser
    if name in _MODEL_EXPORTS:
        from . import model

        export = getattr(model, name)
        globals()[name] = export
        return export
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
