"""Cython kernels for branch-merge inner loops.

These kernels are pure dedupe-and-cap loops; the surrounding Python code in
``_analysis_state._merge_changed_token_lineages`` owns all decisions about
which input shape applies (append-only fast path vs replacement/deletion
fallback) and is responsible for summarizing past the fanout limit.
"""


def merge_appended_only(
    object lineage_key_func,
    list initial_merged,
    set initial_keys,
    list appended_lists,
    Py_ssize_t fanout_limit,
):
    """Append-only branch merge.

    Walks ``appended_lists`` in iteration order, deduping by ``lineage_key_func``
    against ``initial_keys`` and any keys observed during the walk. Stops as soon
    as ``len(merged) > fanout_limit`` and returns the partial merge with
    ``hit_limit=True`` so the caller can summarize.

    Returns ``(merged, keys, hit_limit)`` where ``merged`` is a fresh list,
    ``keys`` is a fresh set, and ``hit_limit`` is True iff the limit was
    exceeded.
    """
    cdef list merged = list(initial_merged)
    cdef set keys = set(initial_keys)
    cdef Py_ssize_t merged_len = len(merged)
    cdef list appended
    cdef object lin
    cdef object key
    for appended in appended_lists:
        for lin in appended:
            key = lineage_key_func(lin)
            if key in keys:
                continue
            keys.add(key)
            merged.append(lin)
            merged_len += 1
            if merged_len > fanout_limit:
                return merged, keys, True
    return merged, keys, False


def merge_with_unchanged_fallback(
    object lineage_key_func,
    list unchanged_pre_conditioned,
    list effective_record_vals,
    list missing_lineages,
    Py_ssize_t fanout_limit,
):
    """Replacement/deletion-aware branch merge.

    The Python caller passes:
      - ``unchanged_pre_conditioned``: a flat list of Lineages already
        rebuilt with their record's path conditions applied.
      - ``effective_record_vals``: list[list[Lineage]], one inner list per
        effective record's token values (or empty for records that don't
        define the token).
      - ``missing_lineages``: any synthetic "missing on this branch"
        lineages the caller pre-computed.

    Returns ``(merged, keys, hit_limit, total_seen)``. ``total_seen`` mirrors
    the Python reference's ``total_seen`` accumulator (count of every lineage
    visited, before dedupe).
    """
    cdef list merged = []
    cdef set keys = set()
    cdef Py_ssize_t merged_len = 0
    cdef Py_ssize_t total_seen = 0
    cdef list vals
    cdef object lin
    cdef object key

    for lin in unchanged_pre_conditioned:
        total_seen += 1
        key = lineage_key_func(lin)
        if key in keys:
            continue
        keys.add(key)
        merged.append(lin)
        merged_len += 1

    for vals in effective_record_vals:
        for lin in vals:
            total_seen += 1
            key = lineage_key_func(lin)
            if key in keys:
                continue
            keys.add(key)
            merged.append(lin)
            merged_len += 1
            if merged_len > fanout_limit:
                return merged, keys, True, total_seen

    for lin in missing_lineages:
        total_seen += 1
        key = lineage_key_func(lin)
        if key in keys:
            continue
        keys.add(key)
        merged.append(lin)
        merged_len += 1
        if merged_len > fanout_limit:
            return merged, keys, True, total_seen

    return merged, keys, False, total_seen
