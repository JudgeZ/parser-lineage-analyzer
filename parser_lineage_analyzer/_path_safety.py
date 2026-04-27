"""Path-containment helpers shared by loader-side symlink-escape checks.

The plugin-signature (:mod:`._plugin_signatures`) and grok-pattern
(:mod:`._grok_patterns`) loaders both need to decide whether a symlink
inside a user-supplied directory escapes that directory. Keeping a
single implementation here removes the must-not-drift hazard the two
inline copies previously carried.
"""

from __future__ import annotations

import os
from pathlib import Path


def path_is_within(target: Path, base: Path) -> bool:
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
