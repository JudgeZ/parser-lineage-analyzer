"""Condition propagation helpers."""

from __future__ import annotations

from ._analysis_condition_facts import _normalize_condition
from .model import Lineage, OutputAnchor

MAX_EXACT_PRIOR_NEGATIONS = 32


def _lineages_with_anchor_conditions(lineages: list[Lineage], anchor: OutputAnchor | None) -> list[Lineage]:
    if anchor is None or not anchor.conditions:
        return [lin.clone() for lin in lineages]
    out: list[Lineage] = []
    for lin in lineages:
        clone = lin.with_conditions(anchor.conditions).with_parser_locations(anchor.parser_locations)
        if clone.status in {"exact", "exact_capture", "constant", "derived", "repeated"}:
            clone = clone.with_status("conditional")
        out.append(clone)
    return out


def _add_conditions(lineages: list[Lineage], conditions: list[str]) -> list[Lineage]:
    out: list[Lineage] = []
    for lin in lineages:
        clone = lin.with_conditions([cond for cond in conditions if cond])
        if clone.conditions and clone.status in {"exact", "exact_capture", "constant", "derived", "repeated"}:
            clone = clone.with_status("conditional")
        out.append(clone)
    return out


def _clean_condition(condition: str) -> str:
    return _normalize_condition(condition)


def _prior_negation_conditions(prior_negations: list[str]) -> list[str]:
    if len(prior_negations) <= MAX_EXACT_PRIOR_NEGATIONS:
        return list(prior_negations)
    return [f"NOT(any of {len(prior_negations)} prior if/else-if conditions matched)"]
