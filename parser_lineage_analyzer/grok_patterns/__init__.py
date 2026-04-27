"""Vendored upstream Logstash grok pattern library.

The data files alongside this module are byte-identical copies of the
``patterns/legacy/`` directory from logstash-plugins/logstash-patterns-core
(Apache-2.0). See ``NOTICE`` for upstream attribution and the pinned
revision; ``LICENSE`` carries the verbatim upstream license text.

This file exists solely to make the directory a regular Python package
so ``importlib.resources.files("parser_lineage_analyzer.grok_patterns")``
works under every wheel installer (regular, zipapp, embedded). The
resolver code lives in ``parser_lineage_analyzer/_grok_patterns.py``.
"""
