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

See ``docs/plugin-signatures.md`` for the full schema and per-class
examples.

Soundness
---------

Lookup miss MUST fall through to the existing ``unsupported_plugin``
taint path — the dispatcher checks for ``None`` explicitly. Validation
errors from a malformed TOML table raise ``ValueError`` at load time
rather than silently registering a partial signature.

Determinism
-----------

Tables within a TOML file load in sorted-key order. Files within a
directory load in sorted-name order. Inputs to ``from_paths`` (and
``--plugin-signatures-dir`` / ``--plugin-signatures``) merge in argv
order with last-write-wins.
"""

from __future__ import annotations

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
        Tables that fail validation raise ``ValueError`` with a compact
        diagnostic so the user sees the bad table immediately.
        """
        path = Path(path)
        with path.open("rb") as handle:
            data = tomllib.load(handle)
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
        """
        directory = Path(directory)
        if not directory.is_dir():
            return
        for entry in sorted(directory.iterdir()):
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
