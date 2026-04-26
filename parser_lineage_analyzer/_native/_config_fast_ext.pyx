# cython: language_level=3

"""Cython acceleration for the common plugin-config fast path."""


cdef bint _is_ident_start(str ch):
    if ch == "_":
        return True
    return ("A" <= ch <= "Z") or ("a" <= ch <= "z")


cdef bint _is_ident_part(str ch):
    if ch == "_" or ch == "@" or ch == "." or ch == "-":
        return True
    return ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ("0" <= ch <= "9")


cdef Py_ssize_t _skip_ws(str text, Py_ssize_t pos):
    cdef Py_ssize_t n = len(text)
    while pos < n and text[pos].isspace():
        pos += 1
    return pos


def decode_string(str token_text):
    cdef Py_ssize_t n = len(token_text)
    cdef Py_ssize_t i = 0
    cdef str quote
    cdef str body
    cdef str ch
    cdef str nxt
    cdef str raw
    cdef list out

    if n < 2:
        return token_text
    quote = token_text[0]
    body = token_text[1:-1] if token_text[-1] == quote else token_text[1:]
    out = []
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "t":
                out.append("\t")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "f":
                out.append("\f")
            elif nxt == "b":
                out.append("\b")
            elif nxt == "v":
                out.append("\v")
            elif nxt == quote:
                out.append(quote)
            elif nxt == "x" and i + 3 < len(body):
                raw = body[i + 2 : i + 4]
                try:
                    out.append(chr(int(raw, 16)))
                    i += 4
                    continue
                except ValueError:
                    out.append("\\x")
            elif nxt == "u" and i + 5 < len(body):
                raw = body[i + 2 : i + 6]
                try:
                    out.append(chr(int(raw, 16)))
                    i += 6
                    continue
                except ValueError:
                    out.append("\\u")
            elif nxt == "\\":
                out.append("\\")
            else:
                out.append("\\" + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


cdef tuple _read_fast_quoted(str text, Py_ssize_t pos):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t i
    cdef str quote
    cdef str ch
    cdef bint escape = False
    if pos >= n or text[pos] not in {'"', "'"}:
        return None, pos
    quote = text[pos]
    i = pos + 1
    while i < n:
        ch = text[i]
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == quote:
            return decode_string(text[pos : i + 1]), i + 1
        i += 1
    return None, pos


cdef tuple _read_fast_atom(str text, Py_ssize_t pos):
    cdef object quoted
    cdef Py_ssize_t after_quoted
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t end
    quoted, after_quoted = _read_fast_quoted(text, pos)
    if quoted is not None:
        return quoted, after_quoted
    end = pos
    while end < n and not text[end].isspace() and text[end] not in "{}[],=>":
        if text[end] == "#":
            return None, pos
        if text[end] == "/":
            if end == pos:
                return None, pos
            if end + 1 < n and text[end + 1] == "*":
                break
            if end + 1 < n and text[end + 1] == "/" and text[end - 1] != ":":
                break
        end += 1
    if end == pos:
        return None, pos
    return text[pos:end], end


cdef tuple _read_fast_value(str text, Py_ssize_t pos, int nesting_depth, int max_depth):
    cdef object array
    cdef Py_ssize_t after_array
    array, after_array = _read_fast_array(text, pos, nesting_depth + 1, max_depth)
    if array is not None:
        return array, after_array
    return _read_fast_atom(text, pos)


cdef tuple _read_fast_array(str text, Py_ssize_t pos, int depth, int max_depth):
    cdef Py_ssize_t n = len(text)
    cdef list values
    cdef object value
    if depth > max_depth:
        return None, pos
    if pos >= n or text[pos] != "[":
        return None, pos
    pos += 1
    values = []
    while True:
        pos = _skip_ws(text, pos)
        if pos >= n:
            return None, pos
        if text[pos] == "]":
            return values, pos + 1
        value, pos = _read_fast_value(text, pos, depth, max_depth)
        if value is None:
            return None, pos
        values.append(value)
        pos = _skip_ws(text, pos)
        if pos < n and text[pos] == ",":
            pos += 1


cdef tuple _read_op(str text, Py_ssize_t pos):
    cdef Py_ssize_t n = len(text)
    cdef Py_ssize_t start = pos
    if pos >= n or not _is_ident_start(text[pos]):
        return None, pos
    pos += 1
    while pos < n and _is_ident_part(text[pos]):
        pos += 1
    return text[start:pos], pos


def parse_simple_config_fast(str text, int max_depth):
    cdef Py_ssize_t pos = 0
    cdef Py_ssize_t end = len(text)
    cdef object op
    cdef object key
    cdef object value
    cdef list pairs = []
    cdef list map_values

    while True:
        pos = _skip_ws(text, pos)
        if pos >= end:
            return pairs if pairs else None
        op, pos = _read_op(text, pos)
        if op is None:
            return None
        pos = _skip_ws(text, pos)
        if not text.startswith("=>", pos):
            return None
        pos = _skip_ws(text, pos + 2)
        if pos >= end:
            return None
        if text[pos] == "[":
            value, pos = _read_fast_array(text, pos, 1, max_depth)
            if value is None:
                return None
            pairs.append((op, value))
            continue
        if text[pos] == "{":
            pos += 1
            map_values = []
            while True:
                pos = _skip_ws(text, pos)
                if pos >= end:
                    return None
                if text[pos] == "}":
                    pos += 1
                    break
                key, pos = _read_fast_atom(text, pos)
                if key is None:
                    return None
                pos = _skip_ws(text, pos)
                if not text.startswith("=>", pos):
                    return None
                pos = _skip_ws(text, pos + 2)
                value, pos = _read_fast_value(text, pos, 1, max_depth)
                if value is None:
                    return None
                map_values.append((key, value))
            pairs.append((op, map_values))
            continue
        value, pos = _read_fast_atom(text, pos)
        if value is None:
            return None
        pairs.append((op, value))

