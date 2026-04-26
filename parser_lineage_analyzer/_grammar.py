"""Packaged grammar loading helpers."""

from __future__ import annotations

from importlib import resources


def load_grammar(filename: str) -> str:
    """Load a bundled Lark grammar file as UTF-8 text."""
    return (resources.files(__package__) / "grammar" / filename).read_text(encoding="utf-8")
