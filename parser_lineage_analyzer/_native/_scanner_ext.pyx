# cython: language_level=3

"""Cython acceleration for parser text scanning.

The implementation intentionally mirrors ``parser_lineage_analyzer._scanner``.
It returns plain Python containers so the public ScannerIndex object and all
fallback semantics stay owned by the Python module.
"""


cdef bint _is_linebreak(str ch):
    return ch == "\r" or ch == "\n"


cdef bint _is_unquoted_slash_mapping_key(str text, Py_ssize_t pos):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t i = pos + 2
    cdef Py_ssize_t key_start
    if i >= n or text[i].isspace():
        return False
    key_start = i
    while i < n and not _is_linebreak(text[i]) and text[i] not in "{}[]," and not text[i].isspace() and text[i] != "=":
        i += 1
    while i < n and not _is_linebreak(text[i]) and text[i].isspace():
        i += 1
    if i == key_start:
        return False
    if text.startswith("=>", i):
        i += 2
    elif i < n and text[i] == "=":
        i += 1
    else:
        return False
    while i < n and not _is_linebreak(text[i]) and text[i].isspace():
        i += 1
    return i < n and text[i] in {'"', "'"}


cdef bint _is_line_comment_start(str text, Py_ssize_t pos):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t j
    if pos + 1 >= n or text[pos + 1] != "/":
        return False
    if _is_unquoted_slash_mapping_key(text, pos):
        return False
    j = pos - 1
    while j >= 0 and not _is_linebreak(text[j]):
        if not text[j].isspace():
            break
        j -= 1
    if j < 0 or _is_linebreak(text[j]):
        return True
    if pos > 0 and not text[pos - 1].isspace() and text[pos - 1] != "}":
        return False
    if text[j] in {",", "(", "[", "=", "~", "!"}:
        return False
    return True


cdef bint _is_regex_literal_start(str text, Py_ssize_t pos):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t j
    cdef Py_ssize_t k
    cdef str ch
    cdef bint in_class
    cdef bint escape
    if pos + 1 < n and text[pos + 1] == "*":
        return False
    j = pos - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    if j >= 1 and text[j - 1 : j + 1] in {"=~", "!~"}:
        return True
    if pos + 1 < n and text[pos + 1] == "/":
        return False
    if j >= 0 and text[j] == ">":
        # `=> /pattern/` form. Walk forward looking for the closing `/`. An
        # unescaped `{` outside a character class is almost never a real
        # regex (`\{n,m\}` quantifiers escape them), so its presence is
        # evidence the `/...` was actually a path-style bareword. Mirrors
        # the Python heuristic in _scanner._is_regex_literal_start so the
        # native scanner can handle path barewords too.
        k = pos + 1
        in_class = False
        escape = False
        while k < n and not _is_linebreak(text[k]):
            ch = text[k]
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif in_class:
                if ch == "]":
                    in_class = False
            elif ch == "[":
                in_class = True
            elif ch == "{":
                return False
            elif ch == "/":
                return True
            elif ch.isspace() or ch in {",", "}", "]"}:
                return False
            k += 1
        return False
    return j >= 0 and text[j] in {"[", "{", ",", "="}


cdef bint _is_path_bareword_start(str text, Py_ssize_t pos):
    """Cython mirror of _scanner._is_path_bareword_start.

    `/` after `=>` that is NOT a regex (per `_is_regex_literal_start`) and
    contains an unescaped `{` or `}` before end-of-line. The brace inside
    such barewords (e.g. `=> /var_{/logs/}`) must NOT count toward the
    surrounding brace depth, so the scanner skips the bareword as opaque.
    """
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t j = pos - 1
    cdef Py_ssize_t k
    cdef bint saw_brace = False
    while j >= 0 and text[j].isspace():
        j -= 1
    if j < 0 or text[j] != ">":
        return False
    if _is_regex_literal_start(text, pos):
        return False
    k = pos + 1
    while k < n and not _is_linebreak(text[k]):
        if text[k] == "\\" and k + 1 < n:
            k += 2
            continue
        if text[k] == "{" or text[k] == "}":
            saw_brace = True
            break
        if text[k] == " " or text[k] == "\t" or text[k] == ",":
            return False
        k += 1
    return saw_brace


def strip_comments_keep_offsets(str text):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t i = 0
    cdef Py_ssize_t start
    cdef list out = list(text)
    cdef str c
    cdef str quote = ""
    cdef bint regex = False
    cdef bint escape = False

    while i < n:
        c = text[i]
        if regex:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "/":
                regex = False
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = ""
            i += 1
            continue
        if c in {'"', "'"}:
            quote = c
            i += 1
            continue
        if c == "/" and _is_regex_literal_start(text, i):
            regex = True
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/" and _is_line_comment_start(text, i):
            start = i
            while i < n and text[i] != "\n":
                i += 1
            while start < i:
                if out[start] != "\n":
                    out[start] = " "
                start += 1
            continue
        if c == "/" and _is_path_bareword_start(text, i):
            # Path-style bareword (`=> /var_{/logs/}`); inner braces must
            # not count toward the surrounding brace depth tracker. Skip
            # opaque content until end-of-line, whitespace, or comma.
            i += 1
            while i < n and text[i] not in " \t\r\n,":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            start = i
            i += 2
            while i < n:
                if i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            while start < i:
                if out[start] != "\n":
                    out[start] = " "
                start += 1
            continue
        if c == "#":
            start = i
            while i < n and text[i] != "\n":
                i += 1
            while start < i:
                if out[start] != "\n":
                    out[start] = " "
                start += 1
            continue
        i += 1
    return "".join(out)


def build_scanner_index_parts(str text):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t i = 0
    cdef int depth_square = 0
    cdef int ref_depth = 0
    cdef Py_ssize_t skip_ref_open_at = -1
    cdef int fallback_close = -1
    cdef str c
    cdef str quote = ""
    cdef bint regex = False
    cdef bint escape = False
    cdef list square_positions = []
    cdef list square_depths = []
    cdef dict mutable_targets = {}
    cdef dict matching_close = {}
    cdef list stack = []
    cdef tuple key

    while i < n:
        c = text[i]
        if regex:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "/":
                regex = False
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = ""
            i += 1
            continue
        if c in {'"', "'"}:
            quote = c
            i += 1
            continue
        if c == "/" and _is_regex_literal_start(text, i):
            regex = True
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/" and _is_line_comment_start(text, i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and _is_path_bareword_start(text, i):
            # Skip path-style bareword opaquely so its inner `{`/`}` don't
            # desync the surrounding brace tracker.
            i += 1
            while i < n and text[i] not in " \t\r\n,":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n:
                if i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "[":
            depth_square += 1
            square_positions.append(i)
            square_depths.append(depth_square)
        elif c == "]" and depth_square:
            depth_square -= 1
            square_positions.append(i)
            square_depths.append(depth_square)
        if c == "%" and i + 1 < n and text[i + 1] == "{":
            ref_depth += 1
            skip_ref_open_at = i + 1
            i += 1
            continue
        if ref_depth:
            if i == skip_ref_open_at:
                skip_ref_open_at = -1
            elif c == "{":
                ref_depth += 1
            elif c == "}":
                ref_depth -= 1
            i += 1
            continue
        if c in "{}":
            key = (c, depth_square)
            mutable_targets.setdefault(key, []).append(i)
        if c == "{":
            stack.append(i)
        elif c == "}":
            fallback_close = i
            if stack:
                matching_close[stack.pop()] = i
        i += 1

    return (
        tuple(square_positions),
        tuple(square_depths),
        {key: tuple(value) for key, value in mutable_targets.items()},
        matching_close,
        fallback_close,
    )


def target_positions_for(str text, str target, int square_depth):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t i = 0
    cdef int depth_square = 0
    cdef int ref_depth = 0
    cdef Py_ssize_t skip_ref_open_at = -1
    cdef str c
    cdef str quote = ""
    cdef bint regex = False
    cdef bint escape = False
    cdef list positions = []

    while i < n:
        c = text[i]
        if regex:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == "/":
                regex = False
            i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = ""
            i += 1
            continue
        if c in {'"', "'"}:
            quote = c
            i += 1
            continue
        if c == "/" and _is_regex_literal_start(text, i):
            regex = True
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/" and _is_line_comment_start(text, i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and _is_path_bareword_start(text, i):
            i += 1
            while i < n and text[i] not in " \t\r\n,":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n:
                if i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    break
                i += 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "[":
            depth_square += 1
        elif c == "]" and depth_square:
            depth_square -= 1
        if c == "%" and i + 1 < n and text[i + 1] == "{":
            ref_depth += 1
            skip_ref_open_at = i + 1
            i += 1
            continue
        if ref_depth:
            if i == skip_ref_open_at:
                skip_ref_open_at = -1
            elif c == "{":
                ref_depth += 1
            elif c == "}":
                ref_depth -= 1
            i += 1
            continue
        if c == target and depth_square == square_depth:
            positions.append(i)
        i += 1
    return tuple(positions)

