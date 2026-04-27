"""Plugin signature registry (F3, PR-D).

A :class:`PluginSignatureRegistry` is a thin wrapper over
``dict[str, PluginSignature]`` that lets users teach the analyzer about
custom (e.g. org-specific) plugins via declarative TOML files. Without
a registered signature, an unknown plugin hits the
``_taint_unsupported_plugin_destinations`` path in ``_analysis_flow.py``
and produces a hard ``unsupported_plugin`` taint. With one, the
dispatcher in ``_analysis_flow.FlowExecutorMixin._exec_plugin`` hands
off to ``_plugins_signature.SignaturePluginMixin._exec_signature_dispatched``,
which produces generic but sound lineage that respects the plugin's
declared source/destination shape.

TOML format
-----------

Each top-level table maps to a :class:`PluginSignature`. The table key
is used as the default ``name`` if the table omits one, so users can
write::

    [example_extractor]
    semantic_class = "extractor"
    source_keys = ["source"]
    dest_keys = ["target"]
    lineage_status = "derived"
    taint_hint = "derived"

If a table provides an explicit ``name`` field, it MUST equal the table
key. A divergent ``name`` is rejected at load time with a
``ValueError`` — silently registering under the explicit ``name`` would
make ``lookup(<table-key>)`` a confusing miss for the user.

See ``docs/plugin-signatures.md`` for the full schema and per-class
examples.

Soundness
---------

Lookup miss MUST fall through to the existing ``unsupported_plugin``
taint path — the dispatcher checks for ``None`` explicitly. Validation
errors from a malformed TOML table raise ``ValueError`` at load time
rather than silently registering a partial signature.

Loader robustness: malformed TOML, oversize files, and outward-pointing
symlinks all raise ``ValueError`` (the CLI catches ``OSError``/
``ValueError`` and emits a deterministic diagnostic, never a traceback).
A 1 MiB cap protects against accidental huge files; symlinks resolving
outside the loaded directory are skipped to avoid unintentionally
loading TOML from elsewhere on the filesystem when a directory is
auto-walked.

Determinism
-----------

Tables within a TOML file load in sorted-key order. Files within a
directory load in sorted-name order. Inputs to ``from_paths`` (and
``--plugin-signatures-dir`` / ``--plugin-signatures``) merge in argv
order with last-write-wins.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from ._plugin_config_models import PluginSignature, compact_validation_error

# Standard 3.10-compatible tomllib idiom. ``tomli`` is a runtime dep on
# 3.10 (see pyproject.toml); 3.11+ ships ``tomllib`` in the stdlib.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

# Hard cap on a single plugin-signature TOML file. A real registry with
# hundreds of plugins lands in the tens of KB; 1 MiB is a sanity guard
# against accidentally pointing the loader at a multi-megabyte log/dump
# file. Enforced before ``tomllib.load`` so a malicious or accidental
# huge file can't pin memory or stall the parser.
_MAX_TOML_BYTES = 1024 * 1024


def _path_is_within(target: Path, base: Path) -> bool:
    """Return True if ``target`` lies within ``base``, normalising case where
    ``os.path.normcase`` does (Windows NTFS).

    ``Path.is_relative_to`` compares path strings byte-for-byte and stays
    case-sensitive even when the underlying filesystem is not. On Windows
    that mis-classifies an in-dir symlink whose configured directory
    differs only in case (``C:\\Foo`` vs ``c:\\foo``) as outward-pointing.
    Routing both sides through ``os.path.normcase`` closes that gap on
    Windows; on POSIX (Linux, macOS — both case-sensitive at the
    Python-path-string level) ``normcase`` is identity so behaviour is
    unchanged. The check is fail-safe: if a case-insensitive volume is
    ever encountered with case-mismatched arguments, an in-dir symlink is
    conservatively rejected rather than falsely accepted.
    """
    try:
        target_norm = os.path.normcase(os.fspath(target))
        base_norm = os.path.normcase(os.fspath(base))
    except (OSError, ValueError):
        return False
    # Ensure ``base`` ends in a separator so ``/foo/bar`` isn't accepted
    # as inside ``/foo/barbecue``.
    base_norm_with_sep = base_norm if base_norm.endswith(os.sep) else base_norm + os.sep
    return target_norm == base_norm_with_sep.rstrip(os.sep) or target_norm.startswith(base_norm_with_sep)


class PluginSignatureRegistry:
    """Mapping of plugin name → :class:`PluginSignature`."""

    __slots__ = ("_signatures",)

    def __init__(self, signatures: Mapping[str, PluginSignature] | None = None) -> None:
        self._signatures: dict[str, PluginSignature] = dict(signatures) if signatures else {}

    def register(self, sig: PluginSignature) -> None:
        """Insert or overwrite a single signature keyed by ``sig.name``."""
        self._signatures[sig.name] = sig

    def lookup(self, name: str) -> PluginSignature | None:
        """Return the signature for ``name`` or ``None`` if unregistered."""
        return self._signatures.get(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._signatures

    def __len__(self) -> int:
        return len(self._signatures)

    def names(self) -> list[str]:
        """Return registered plugin names sorted for determinism."""
        return sorted(self._signatures)

    def load_toml(self, path: Path) -> None:
        """Load signatures from a single TOML file.

        Each top-level table becomes a :class:`PluginSignature` keyed by
        its ``name`` field (defaulting to the table key if omitted).
        An explicit ``name`` that differs from the table key is rejected
        with ``ValueError`` to prevent silent ``lookup`` misses.

        Tables that fail validation raise ``ValueError`` with a compact
        diagnostic so the user sees the bad table immediately. Malformed
        TOML, oversize files, and IO errors all surface as ``ValueError``
        (or ``OSError`` for the latter) so the CLI's
        ``(OSError, ValueError)`` catch can produce a deterministic
        diagnostic instead of leaking a ``TOMLDecodeError`` traceback.
        """
        path = Path(path)
        with path.open("rb") as handle:
            # Enforce the byte cap before invoking the TOML parser so a
            # huge file can't pin memory or trigger a slow parse before
            # we reject it. ``fstat`` on the open handle is the canonical
            # way to size a file we already opened (avoids a separate
            # stat-then-open TOCTOU race against the file content).
            try:
                size = os.fstat(handle.fileno()).st_size
            except OSError:  # pragma: no cover - defensive (fstat almost never fails on an open fd)
                size = -1
            if size >= 0 and size > _MAX_TOML_BYTES:
                raise ValueError(f"{path}: plugin-signature TOML exceeds {_MAX_TOML_BYTES} bytes")
            try:
                data = tomllib.load(handle)
            except tomllib.TOMLDecodeError as exc:
                # CLI catches ``(OSError, ValueError)``; re-raising as
                # ValueError keeps the failure mode deterministic
                # ("invalid TOML: <reason>") instead of letting the
                # traceback escape.
                raise ValueError(f"{path}: invalid TOML: {exc}") from exc
        if not isinstance(data, dict):  # pragma: no cover - defensive
            raise ValueError(f"{path}: expected a TOML mapping, got {type(data).__name__}")
        # Sort table keys for deterministic load order across platforms.
        for table_name in sorted(data):
            payload = data[table_name]
            if not isinstance(payload, dict):
                raise ValueError(
                    f"{path}: top-level entry {table_name!r} must be a TOML table, got {type(payload).__name__}"
                )
            payload_dict = cast(dict[str, object], dict(payload))
            explicit_name = payload_dict.get("name")
            if explicit_name is not None and explicit_name != table_name:
                # Silently registering under ``explicit_name`` would make
                # ``lookup(<table_key>)`` miss — a confusing failure
                # mode. Reject loudly so the user fixes the TOML.
                raise ValueError(
                    f"{path}: table [{table_name}] has explicit name={explicit_name!r} which differs from table key"
                )
            payload_dict.setdefault("name", table_name)
            try:
                sig = PluginSignature.model_validate(payload_dict)
            except ValidationError as exc:
                detail = compact_validation_error(exc)
                raise ValueError(f"{path}: invalid plugin signature {table_name!r}: {detail}") from exc
            self.register(sig)

    def load_directory(self, directory: Path) -> None:
        """Load every ``*.toml`` file in ``directory`` (non-recursive).

        Files are loaded in sorted order so two directories with the
        same files produce the same registry state. Missing or non-
        directory paths are silently ignored — the bundled
        ``plugin_signatures/`` directory ships empty in v0.2 so callers
        can opt into "load bundled if present" without guarding.

        Symlinks whose resolved target sits outside the loaded directory
        are skipped: a configured signatures directory shouldn't
        unexpectedly pull TOML from elsewhere on the filesystem just
        because someone dropped a symlink in. Symlinks pointing at
        siblings inside the same directory are still followed.
        """
        directory = Path(directory)
        if not directory.is_dir():
            return
        try:
            resolved_directory = directory.resolve()
        except OSError:  # pragma: no cover - defensive
            resolved_directory = directory
        for entry in sorted(directory.iterdir()):
            if entry.is_symlink():
                # Reject symlinks that escape the configured directory.
                # ``resolve()`` walks the chain; ``_path_is_within``
                # checks containment via ``os.path.normcase`` so a
                # case-mismatched directory argument on Windows doesn't
                # false-positive (POSIX is byte-equal — see helper
                # docstring for the fail-safe rationale).
                try:
                    resolved_target = entry.resolve()
                except OSError:
                    continue
                if not _path_is_within(resolved_target, resolved_directory):
                    continue
            if entry.is_file() and entry.suffix == ".toml":
                self.load_toml(entry)

    def merge(self, other: PluginSignatureRegistry) -> PluginSignatureRegistry:
        """Return a new registry combining ``self`` and ``other``.

        Later writes win: any name present in ``other`` overrides the
        same name in ``self``. Both inputs are left unmodified.
        """
        merged: dict[str, PluginSignature] = dict(self._signatures)
        merged.update(other._signatures)
        return PluginSignatureRegistry(merged)

    @classmethod
    def from_paths(
        cls,
        files: Iterable[Path] | None = None,
        directories: Iterable[Path] | None = None,
    ) -> PluginSignatureRegistry:
        """Construct a registry from explicit file and directory paths.

        Directories are processed first (in argv order), then individual
        files (in argv order). Later sources override earlier ones
        (last-write-wins) — this matches users' mental model of
        ``--plugin-signatures-dir defaults --plugin-signatures override.toml``.
        """
        registry = cls()
        for directory in directories or ():
            registry.load_directory(directory)
        for file_path in files or ():
            registry.load_toml(file_path)
        return registry


def load_bundled_registry() -> PluginSignatureRegistry:
    """Load any signatures bundled with the package.

    v0.2 ships the ``plugin_signatures/`` directory empty (see
    ``docs/plugin-signatures.md`` for examples that are deliberately
    docs-only). The loader still consults the directory so future
    bundled additions need no code change.
    """
    registry = PluginSignatureRegistry()
    bundled_dir = Path(__file__).parent / "plugin_signatures"
    registry.load_directory(bundled_dir)
    return registry


__all__ = ["PluginSignatureRegistry", "load_bundled_registry"]
