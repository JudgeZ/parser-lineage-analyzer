"""Path, token-reference, and plausibility helpers."""

from __future__ import annotations

import re

from ._analysis_dedupe import _dedupe_strings


def _looks_like_udm_field(token: str) -> bool:
    return (
        token.startswith("event.idm.read_only_udm.")
        or re.match(r"^event\d+\.idm\.read_only_udm\.", token) is not None
        or token.startswith("idm.read_only_udm.")
    )


def _strip_ref(expr: str) -> str:
    expr = str(expr).strip()
    m = re.fullmatch(r"%\{([^}]+)\}", expr)
    if m:
        return _normalize_field_ref(m.group(1).strip())
    return _normalize_field_ref(expr)


def _normalize_field_ref(expr: str) -> str:
    expr = str(expr).strip()
    if not expr:
        return expr
    parts = re.findall(r"\[([^\]]+)\]", expr)
    if parts:
        joined = "".join(f"[{p}]" for p in parts)
        prefix = ""
        if joined == expr:
            pass  # standard `[a][b]` form
        elif expr.endswith(joined) and re.fullmatch(r"[A-Za-z_@][A-Za-z0-9_@.:-]*", expr[: len(expr) - len(joined)]):
            # Mixed `ident[a][b]` form (Logstash array index syntax). Treat
            # the leading identifier as the first segment.
            prefix = expr[: len(expr) - len(joined)] + "."
        else:
            return expr
        clean: list[str] = []
        for part in parts:
            p = part.strip()
            if len(p) >= 2 and p[0] == p[-1] and p[0] in {'"', "'"}:
                p = p[1:-1]
            clean.append(p)
        return prefix + ".".join(p for p in clean if p)
    return expr


def _has_nested_token_reference(expr: str) -> bool:
    if "%{" not in expr:
        return False
    depth = 0
    i = 0
    while i < len(expr):
        if expr.startswith("%{", i):
            if depth > 0:
                return True
            depth += 1
            i += 2
            continue
        if expr[i] == "}" and depth:
            depth -= 1
        i += 1
    return False


def _starts_identifier(token: str) -> bool:
    if not token:
        return False
    first = token[0]
    return first == "_" or "A" <= first <= "Z" or "a" <= first <= "z"


def _is_path_char(ch: str) -> bool:
    return (
        ch == "_"
        or ch == "."
        or ch == ":"
        or ch == "-"
        or ("0" <= ch <= "9")
        or ("A" <= ch <= "Z")
        or ("a" <= ch <= "z")
    )


def _is_plausible_data_path(token: str) -> bool:
    if not token or token.startswith("event") or token.startswith("@"):
        return False
    if token in {"true", "false", "null"}:
        return False
    return _starts_identifier(token) and all(_is_path_char(ch) for ch in token[1:])


def _looks_like_enum_constant(expr: str) -> bool:
    return re.fullmatch(r"[A-Z][A-Z0-9_]*", str(expr)) is not None


def _is_plausible_kv_key(token: str) -> bool:
    if not token or token.startswith("event") or token.startswith("@"):
        return False
    return _starts_identifier(token) and all(_is_path_char(ch) for ch in token[1:])


def _udm_suffixes(q: str) -> list[str]:
    q = q.strip()
    suffixes = [q]
    if q.startswith("event.idm.read_only_udm."):
        suffixes.append(q[len("event.") :])
    elif not q.startswith("event") and not q.startswith("idm.read_only_udm."):
        suffixes.append("idm.read_only_udm." + q)
    if q.startswith("idm.read_only_udm."):
        suffixes.append(q)
    return _dedupe_strings(suffixes)
