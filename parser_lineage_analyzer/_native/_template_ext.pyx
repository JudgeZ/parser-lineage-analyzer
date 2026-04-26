"""Cython template-string helper kernels."""

import re


cdef list _template_spans(str text):
    cdef list spans = []
    cdef Py_ssize_t start = 0
    cdef Py_ssize_t marker
    cdef Py_ssize_t close
    while True:
        marker = text.find("%{", start)
        if marker == -1:
            return spans
        close = text.find("}", marker + 2)
        if close == -1:
            start = marker + 2
            continue
        if close > marker + 2:
            spans.append((marker, close + 1, text[marker + 2:close]))
        start = close + 1


def template_refs(str text):
    cdef list refs = []
    cdef object span
    for span in _template_spans(text):
        refs.append(span[2])
    return refs


def dynamic_template_literals(str text):
    cdef list literals = []
    cdef Py_ssize_t last = 0
    cdef Py_ssize_t start
    cdef Py_ssize_t end
    cdef object span
    cdef str literal
    for span in _template_spans(text):
        start = span[0]
        end = span[1]
        literal = text[last:start]
        if literal:
            literals.append(literal)
        last = end
    literal = text[last:]
    if literal:
        literals.append(literal)
    return tuple(literals)


def dynamic_template_bucket_literal(str text):
    cdef tuple literals = dynamic_template_literals(text)
    if literals:
        return max(literals, key=len)
    return ""


def dynamic_template_pattern_text(str text):
    cdef list parts = ["^"]
    cdef Py_ssize_t last = 0
    cdef Py_ssize_t start
    cdef Py_ssize_t end
    cdef object span
    for span in _template_spans(text):
        start = span[0]
        end = span[1]
        parts.append(re.escape(text[last:start]))
        parts.append(r".*?")
        last = end
    parts.append(re.escape(text[last:]))
    parts.append("$")
    return "".join(parts)


def dynamic_template_matches(str template, str candidate):
    cdef list spans = _template_spans(template)
    cdef Py_ssize_t first_start
    cdef Py_ssize_t last
    cdef Py_ssize_t pos = 0
    cdef Py_ssize_t start
    cdef Py_ssize_t end
    cdef Py_ssize_t found
    cdef object span
    cdef str literal
    cdef str leading
    cdef str trailing
    if not spans:
        return template == candidate
    first_start = spans[0][0]
    if first_start:
        leading = template[:first_start]
        if not candidate.startswith(leading):
            return False
        pos = len(leading)
    last = spans[0][1]
    for span in spans[1:]:
        start = span[0]
        end = span[1]
        literal = template[last:start]
        if literal:
            found = candidate.find(literal, pos)
            if found == -1:
                return False
            pos = found + len(literal)
        last = end
    trailing = template[last:]
    if trailing:
        found = candidate.find(trailing, pos)
        return found != -1 and candidate.endswith(trailing)
    return True
