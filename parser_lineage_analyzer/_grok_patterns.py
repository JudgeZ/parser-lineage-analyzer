"""Grok pattern resolver.

The vendored Logstash legacy pattern library (under ``grok_patterns/``)
is parsed into a :class:`GrokLibrary` and exposed via
:func:`bundled_library`. :func:`expand_pattern` recursively inlines
``%{NAME}`` / ``%{NAME:capture}`` / ``%{NAME:capture:type}`` references
to a flat regex body that downstream analyzer code can hand to the
regex algebra in PR-C.

Soundness contract: every public function returns ``None`` rather than a
partial expansion when *anything* about the pattern is uncertain
(missing name, reference cycle, depth bound hit, byte bound hit). The
analyzer treats ``None`` as "no implicit constraint" — i.e. UNKNOWN —
which propagates through the algebra as compatible-by-default.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable, Mapping
from functools import lru_cache
from importlib import resources
from pathlib import Path

# Pattern recursion depth — guards against self-references that slip
# through cycle detection (e.g. mutual recursion through ≥ 33 layers).
# Set well above the deepest chain in the upstream legacy library
# (`URI` → `URIPROTO`/`USER`/`URIHOST`/`URIPATH`/... ≈ 5 layers).
MAX_GROK_RECURSION_DEPTH = 32

# Per-pattern expansion size cap. Some upstream patterns (e.g. ``IP``
# expanding to the full ``IPV6``+``IPV4`` alternation) reach ~1.5 KB on
# their own; an 8 KB cap leaves headroom for nested user patterns while
# bounding worst-case memory and aligning with the regex algebra's
# ``MAX_REGEX_BODY_BYTES`` threshold downstream.
MAX_EXPANDED_BODY_BYTES = 8192

# Matches a Logstash grok reference exactly as the upstream preprocessor
# does: ``%{NAME}``, ``%{NAME:capture}``, or ``%{NAME:capture:type}``.
# CAPTURE and TYPE are intentionally stripped during expansion — the
# resolver returns the *regex body* that determines L(pattern); capture
# metadata is the analyzer's concern, handled separately by
# ``_extract_grok_captures``.
_GROK_REF_RE = re.compile(r"%\{(?P<name>[A-Za-z0-9_]+)(?::[^}]*)?\}")


class GrokLibrary:
    """An immutable name→body mapping with a stable identity for caching.

    Two libraries built from identical pattern sets compare equal and
    hash equal regardless of construction order, so the LRU cache on
    :func:`expand_pattern` shares slots across logically-equivalent
    instances.
    """

    __slots__ = ("_patterns", "_identity")

    def __init__(self, patterns: Mapping[str, str]) -> None:
        self._patterns: dict[str, str] = dict(patterns)
        # Canonical-form hash: sorted (name, body) pairs joined into a
        # single string. Python's ``hash`` over the canonical string gives
        # a stable in-process identity; the ``__eq__`` cross-check below
        # resolves any hash collision.
        canon = "\n".join(f"{name}={body}" for name, body in sorted(self._patterns.items()))
        self._identity: int = hash(canon)

    def get(self, name: str) -> str | None:
        return self._patterns.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._patterns

    def __len__(self) -> int:
        return len(self._patterns)

    def __hash__(self) -> int:
        return self._identity

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GrokLibrary):
            return NotImplemented
        return self._identity == other._identity and self._patterns == other._patterns

    def names(self) -> list[str]:
        return list(self._patterns)

    def merge(self, other: GrokLibrary) -> GrokLibrary:
        """Return a new library containing the union of both, with
        ``other`` winning on duplicate names."""
        merged = dict(self._patterns)
        merged.update(other._patterns)
        return GrokLibrary(merged)


# -- Bundled library --------------------------------------------------

_BUNDLED_LIBRARY_CACHE: GrokLibrary | None = None
_BUNDLED_LIBRARY_LOCK = threading.Lock()


def bundled_library() -> GrokLibrary:
    """Return the lazily-constructed singleton library built from the
    vendored ``parser_lineage_analyzer/grok_patterns/`` data files.

    The bundle is parsed exactly once per process; concurrent first-call
    races are serialized by a module-level lock.
    """
    global _BUNDLED_LIBRARY_CACHE
    if _BUNDLED_LIBRARY_CACHE is not None:
        return _BUNDLED_LIBRARY_CACHE
    with _BUNDLED_LIBRARY_LOCK:
        if _BUNDLED_LIBRARY_CACHE is None:
            _BUNDLED_LIBRARY_CACHE = GrokLibrary(_load_bundled_patterns())
    return _BUNDLED_LIBRARY_CACHE


def _load_bundled_patterns() -> dict[str, str]:
    """Parse every data file under ``grok_patterns/`` (skipping NOTICE,
    LICENSE, hidden files, and any non-data resources). Returns a
    name→body mapping with deterministic last-write-wins on duplicates
    (sorted file iteration order)."""
    pkg = resources.files("parser_lineage_analyzer.grok_patterns")
    entries = sorted(pkg.iterdir(), key=lambda p: p.name)
    out: dict[str, str] = {}
    for entry in entries:
        name = entry.name
        if name in {"NOTICE", "LICENSE", "__init__.py"} or name.startswith("."):
            continue
        if not entry.is_file():
            continue
        out.update(_parse_pattern_file_text(entry.read_text(encoding="utf-8")))
    return out


def _parse_pattern_file_text(text: str) -> dict[str, str]:
    """Parse a single Logstash grok pattern file's contents.

    Format: each non-empty, non-comment line is ``NAME (whitespace) BODY``.
    Returns a name→body mapping; later definitions in the file overwrite
    earlier ones (matches upstream behavior).
    """
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        # First whitespace separates NAME from BODY.
        sep = re.search(r"\s", line)
        if sep is None:
            continue  # malformed: NAME with no body
        pat_name = line[: sep.start()].strip()
        pat_body = line[sep.end() :].strip()
        if pat_name and pat_body:
            out[pat_name] = pat_body
    return out


def load_library_from_paths(paths: Iterable[Path]) -> GrokLibrary:
    """Build a library from one or more user-supplied pattern files or
    directories. Files are merged in argument order with last-write-wins;
    inside a directory, files are merged in sorted-name order."""
    merged: dict[str, str] = {}
    for path in paths:
        if path.is_dir():
            for entry in sorted(path.iterdir(), key=lambda p: p.name):
                if entry.is_file() and not entry.name.startswith("."):
                    merged.update(_parse_pattern_file_text(entry.read_text(encoding="utf-8")))
        elif path.is_file():
            merged.update(_parse_pattern_file_text(path.read_text(encoding="utf-8")))
        # Silently skip non-existent paths — caller validates if it cares.
    return GrokLibrary(merged)


# -- Expansion --------------------------------------------------------


def expand_pattern(name: str, library: GrokLibrary | None = None) -> str | None:
    """Recursively expand a grok pattern name to its flat regex body.

    Returns ``None`` when:
      * the name is not in the library
      * a reference cycle is detected
      * the recursion depth exceeds :data:`MAX_GROK_RECURSION_DEPTH`
      * the expanded body would exceed :data:`MAX_EXPANDED_BODY_BYTES`

    A ``None`` return is always sound — callers must treat it as "no
    implicit constraint" rather than "definitely unconstrained".
    """
    if library is None:
        library = bundled_library()
    return _expand_pattern_cached(name, library)


@lru_cache(maxsize=4096)
def _expand_pattern_cached(name: str, library: GrokLibrary) -> str | None:
    return _expand(name, library, 0, frozenset())


def _expand(name: str, library: GrokLibrary, depth: int, visited: frozenset[str]) -> str | None:
    if depth > MAX_GROK_RECURSION_DEPTH:
        return None
    if name in visited:
        return None
    body = library.get(name)
    if body is None:
        return None

    next_visited = visited | {name}
    failed = False

    def _replace(match: re.Match[str]) -> str:
        nonlocal failed
        if failed:
            return ""
        ref_name = match.group("name")
        replacement = _expand(ref_name, library, depth + 1, next_visited)
        if replacement is None:
            failed = True
            return ""
        return replacement

    expanded = _GROK_REF_RE.sub(_replace, body)
    if failed:
        return None
    if len(expanded.encode("utf-8")) > MAX_EXPANDED_BODY_BYTES:
        return None
    return expanded
