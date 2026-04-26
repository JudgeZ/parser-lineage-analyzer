from __future__ import annotations

import os

from setuptools import Extension, setup

try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # pragma: no cover - wheel is a build-time dep
    _bdist_wheel = None


_EXTENSIONS = (
    ("parser_lineage_analyzer._native._scanner_ext", "parser_lineage_analyzer/_native/_scanner_ext"),
    ("parser_lineage_analyzer._native._config_fast_ext", "parser_lineage_analyzer/_native/_config_fast_ext"),
    ("parser_lineage_analyzer._native._dedupe_ext", "parser_lineage_analyzer/_native/_dedupe_ext"),
    ("parser_lineage_analyzer._native._template_ext", "parser_lineage_analyzer/_native/_template_ext"),
    ("parser_lineage_analyzer._native._branch_merge_ext", "parser_lineage_analyzer/_native/_branch_merge_ext"),
)


def _native_disabled() -> bool:
    return os.environ.get("PARSER_LINEAGE_ANALYZER_NO_EXT", "").lower() in {"1", "true", "yes", "on"}


def _native_required() -> bool:
    return os.environ.get("PARSER_LINEAGE_ANALYZER_REQUIRE_EXT", "").lower() in {"1", "true", "yes", "on"}


_ABI3_DEFINE_MACROS: list[tuple[str, str]] = [("Py_LIMITED_API", "0x030A0000")]
_ABI3_KWARGS = {
    "py_limited_api": True,
    "define_macros": _ABI3_DEFINE_MACROS,
}


def _extensions() -> list[Extension]:
    if _native_disabled():
        if _native_required():
            raise RuntimeError("PARSER_LINEAGE_ANALYZER_NO_EXT conflicts with PARSER_LINEAGE_ANALYZER_REQUIRE_EXT")
        return []
    required = _native_required()
    try:
        from Cython.Build import cythonize
    except ImportError:
        extensions = []
        missing = []
        for name, stem in _EXTENSIONS:
            c_source = f"{stem}.c"
            if os.path.exists(c_source):
                extensions.append(Extension(name, [c_source], optional=not required, **_ABI3_KWARGS))
            else:
                missing.append(c_source)
        if required and missing:
            missing_sources = ", ".join(missing)
            raise RuntimeError(
                "PARSER_LINEAGE_ANALYZER_REQUIRE_EXT requires Cython or generated C sources for every "
                f"native extension; missing: {missing_sources}"
            ) from None
        if extensions or not required:
            return extensions
        raise RuntimeError("Cython is required to build native extensions from .pyx sources") from None

    extensions = [Extension(name, [f"{stem}.pyx"], optional=not required, **_ABI3_KWARGS) for name, stem in _EXTENSIONS]
    return cythonize(extensions, compiler_directives={"language_level": "3"})


_cmdclass: dict[str, type] = {}
if _bdist_wheel is not None and not _native_disabled():

    class _Abi3BdistWheel(_bdist_wheel):
        def get_tag(self) -> tuple[str, str, str]:
            python, abi, plat = super().get_tag()
            if python.startswith("cp"):
                return "cp310", "abi3", plat
            return python, abi, plat

    _cmdclass["bdist_wheel"] = _Abi3BdistWheel


setup(ext_modules=_extensions(), cmdclass=_cmdclass)
