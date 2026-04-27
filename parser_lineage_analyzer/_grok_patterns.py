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

Loader robustness: per-file size cap (``MAX_PATTERN_FILE_BYTES``)
defends against accidentally pointing the loader at a multi-megabyte
log/dump. Symlinks whose resolved target sits outside the loaded
directory are skipped to avoid auto-walking pulling pattern data from
elsewhere on the filesystem when a directory is enumerated. This
mirrors the loader policy in ``_plugin_signatures.py`` and is the same
soundness/safety bar.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Iterable, Mapping
from functools import lru_cache
from importlib import resources
from pathlib import Path

from ._path_safety import path_is_within

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

# Per-file size cap for the pattern data loader. A real pattern file
# tops out in the low tens of KB (the bundled Logstash legacy bundle's
# largest file is well under 32 KB); 1 MiB is a sanity guard against
# accidentally enumerating a multi-megabyte log or dump that happens to
# live in a configured ``--grok-patterns-dir``. Enforced before
# ``read_text`` so we never pin memory on a hostile or accidental huge
# file. The bundled-loader and explicit-file paths raise ``ValueError``;
# the directory-walk path silently skips oversize files (matching the
# loader's existing silent-drop policy for malformed entries).
MAX_PATTERN_FILE_BYTES = 1024 * 1024

# Matches a Logstash grok reference exactly as the upstream preprocessor
# does: ``%{NAME}``, ``%{NAME:capture}``, or ``%{NAME:capture:type}``.
# CAPTURE and TYPE are intentionally stripped during expansion — the
# resolver returns the *regex body* that determines L(pattern); capture
# metadata is the analyzer's concern, handled separately by
# ``_extract_grok_captures``.
_GROK_REF_RE = re.compile(r"%\{(?P<name>[A-Za-z0-9_]+)(?::[^}]*)?\}")


class GrokLibrary:
    """A name→body mapping with a stable identity for caching.

    The ``__hash__`` is computed once at construction from the canonical
    sorted ``(name, body)`` pairs, so two libraries built from
    identical pattern sets compare equal and hash equal regardless of
    insertion order — letting the LRU cache on :func:`expand_pattern`
    share slots across logically-equivalent instances.

    **Immutability invariant.** ``_patterns`` is a private attribute
    and MUST NOT be mutated after construction. ``__hash__`` reads the
    cached identity, so post-construction mutation through internal
    attribute access (which the slot doesn't prevent) silently
    corrupts cache lookups. Use :meth:`merge` to derive a new library
    rather than mutating an existing one.
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


# Files that ship alongside the pattern data but must not be parsed as
# patterns. Hidden files (``.DS_Store``, ``.gitkeep``, etc.) are filtered
# separately by the leading-dot check.
_NON_PATTERN_FILENAMES = frozenset({"NOTICE", "LICENSE", "__init__.py", "__pycache__"})

# File extensions that obviously aren't pattern data. Upstream Logstash
# patterns are extensionless (``aws``, ``bind``, ``grok-patterns``, etc.),
# so any file with a recognizable extension is non-pattern. Defends
# against future maintainers dropping a stray ``README.md`` or
# ``CHANGELOG.txt`` into the bundle.
_NON_PATTERN_EXTENSIONS = frozenset({".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".py", ".pyc"})


def _is_pattern_data_file(name: str) -> bool:
    """Return True if ``name`` looks like a Logstash grok data file."""
    if not name or name.startswith("."):
        return False
    if name in _NON_PATTERN_FILENAMES:
        return False
    # ``Path("aws").suffix`` is ``""`` for extensionless files; only
    # filter on a known non-pattern extension.
    suffix = Path(name).suffix.lower()
    return not (suffix and suffix in _NON_PATTERN_EXTENSIONS)


def _read_pattern_file_text(path: Path) -> str:
    """Read a pattern file enforcing :data:`MAX_PATTERN_FILE_BYTES`.

    Sizes the file via ``os.fstat`` on the open handle before reading
    its contents so the cap check and the read see the same file (no
    stat-then-open TOCTOU window). Raises ``ValueError`` when the cap
    is exceeded; callers that want silent-drop semantics (e.g.
    directory walks) handle the ``ValueError`` and continue.
    """
    with path.open("rb") as handle:
        try:
            size = os.fstat(handle.fileno()).st_size
        except OSError:  # pragma: no cover - defensive (fstat almost never fails on an open fd)
            size = -1
        if size >= 0 and size > MAX_PATTERN_FILE_BYTES:
            raise ValueError(f"{path}: grok pattern file exceeds {MAX_PATTERN_FILE_BYTES} bytes")
        return handle.read().decode("utf-8")


def _load_bundled_patterns() -> dict[str, str]:
    """Parse every data file under ``grok_patterns/`` (skipping NOTICE,
    LICENSE, ``__init__.py``, hidden files, and any file with an
    extension that obviously isn't pattern data — see
    :data:`_NON_PATTERN_FILENAMES` and :data:`_NON_PATTERN_EXTENSIONS`).
    Returns a name→body mapping with deterministic last-write-wins on
    duplicates (sorted file iteration order)."""
    pkg = resources.files("parser_lineage_analyzer.grok_patterns")
    entries = sorted(pkg.iterdir(), key=lambda p: p.name)
    out: dict[str, str] = {}
    for entry in entries:
        if not _is_pattern_data_file(entry.name):
            continue
        if not entry.is_file():
            continue
        # ``importlib.resources.abc.Traversable.read_text`` doesn't expose
        # a ``stat``; the bundled directory is a known-finite checked-in
        # asset, so we trust the existing read here and rely on the byte
        # cap on user-supplied paths (``load_library_from_paths``).
        out.update(_parse_pattern_file_text(entry.read_text(encoding="utf-8")))
    return out


def _parse_pattern_file_text(text: str) -> dict[str, str]:
    """Parse a single Logstash grok pattern file's contents.

    Format: each non-empty, non-comment line is ``NAME (whitespace) BODY``.
    Lines with leading whitespace are tolerated — the leading whitespace
    is stripped before the NAME/BODY split, matching upstream Logstash
    behavior for indented pattern lines. Returns a name→body mapping;
    later definitions in the file overwrite earlier ones.
    """
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        # Strip both ends so leading-whitespace lines parse the NAME
        # correctly. (A previous version only ``rstrip``'d, which made
        # ``re.search(r"\s", line)`` find the *leading* whitespace as
        # the separator and silently drop the entry.)
        line = raw_line.strip()
        if not line or line.startswith("#"):
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
    inside a directory, files are merged in sorted-name order.

    Per-file safety: the byte cap (:data:`MAX_PATTERN_FILE_BYTES`) is
    enforced on every read. Inside a directory walk, oversize files and
    symlinks pointing outside the directory are silently skipped (the
    same drop-on-uncertainty policy this module's malformed-line parser
    uses). When ``path`` is itself an explicit file argument, an oversize
    file raises ``ValueError`` so the caller's typo or wrong path
    surfaces as a loud failure rather than an empty library.
    """
    merged: dict[str, str] = {}
    for path in paths:
        if path.is_dir():
            try:
                resolved_directory = path.resolve()
            except (OSError, RuntimeError):  # pragma: no cover - defensive
                # ``Path.resolve()`` raises ``RuntimeError`` on infinite
                # symlink loops — drop back to the unresolved directory
                # rather than leaking a traceback.
                resolved_directory = path
            for entry in sorted(path.iterdir(), key=lambda p: p.name):
                if entry.name.startswith("."):
                    continue
                # Default to reading ``entry`` directly. Symlinks that
                # pass the containment check are loaded via
                # ``resolved_target`` so a retarget between
                # ``resolve()`` and the read can't bypass containment.
                load_path = entry
                if entry.is_symlink():
                    # Skip symlinks that escape the configured directory.
                    # ``resolve()`` walks the chain; ``path_is_within``
                    # checks containment via ``os.path.normcase`` so
                    # case-insensitive filesystems (macOS APFS, Windows
                    # NTFS) don't false-positive on a case-mismatched
                    # directory argument. In-dir symlinks (sibling
                    # links) are still followed. ``resolve()`` raises
                    # ``RuntimeError`` on cyclic symlink chains — also
                    # skip those.
                    try:
                        resolved_target = entry.resolve()
                    except (OSError, RuntimeError):
                        continue
                    if not path_is_within(resolved_target, resolved_directory):
                        continue
                    load_path = resolved_target
                if not load_path.is_file():
                    continue
                # Directory walk: silently drop oversize files (matches
                # the silent-drop convention for malformed pattern lines
                # in ``_parse_pattern_file_text``).
                try:
                    text = _read_pattern_file_text(load_path)
                except ValueError:
                    continue
                merged.update(_parse_pattern_file_text(text))
        elif path.is_file():
            # Explicit file argument: oversize is a loud ValueError
            # (caller pointed at this file deliberately).
            merged.update(_parse_pattern_file_text(_read_pattern_file_text(path)))
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
    return _expand(name, library, 0, frozenset(), inner_cache=None)


def _expand(
    name: str,
    library: GrokLibrary,
    depth: int,
    visited: frozenset[str],
    inner_cache: dict[str, str | None] | None,
) -> str | None:
    """Recursive expansion core.

    Streams the substitution segment-by-segment via
    :func:`re.Pattern.finditer` so the byte budget is enforced
    *before* materializing the final string. A pathological user
    pattern like ``BIG => "%{CHUNK} %{CHUNK} ..."`` (with a 1 KB
    ``CHUNK``) fails fast at ``MAX_EXPANDED_BODY_BYTES`` rather than
    allocating the full multi-megabyte expansion only to discard it
    afterwards.

    ``inner_cache`` shares per-name results across recursive
    sub-calls within a single :func:`_expand_pattern_cached` invocation
    so a body referencing the same pattern many times pays its
    expansion cost once (the outer ``lru_cache`` shares across calls;
    this shares within one call).
    """
    if depth > MAX_GROK_RECURSION_DEPTH:
        return None
    if name in visited:
        return None
    if inner_cache is None:
        inner_cache = {}
    if name in inner_cache:
        return inner_cache[name]
    body = library.get(name)
    if body is None:
        return None

    next_visited = visited | {name}

    parts: list[str] = []
    bytes_so_far = 0
    last_end = 0
    for match in _GROK_REF_RE.finditer(body):
        between = body[last_end : match.start()]
        bytes_so_far += len(between.encode("utf-8"))
        if bytes_so_far > MAX_EXPANDED_BODY_BYTES:
            inner_cache[name] = None
            return None
        parts.append(between)
        replacement = _expand(match.group("name"), library, depth + 1, next_visited, inner_cache)
        if replacement is None:
            inner_cache[name] = None
            return None
        bytes_so_far += len(replacement.encode("utf-8"))
        if bytes_so_far > MAX_EXPANDED_BODY_BYTES:
            inner_cache[name] = None
            return None
        parts.append(replacement)
        last_end = match.end()
    tail = body[last_end:]
    bytes_so_far += len(tail.encode("utf-8"))
    if bytes_so_far > MAX_EXPANDED_BODY_BYTES:
        inner_cache[name] = None
        return None
    parts.append(tail)

    expanded = "".join(parts)
    inner_cache[name] = expanded
    return expanded
