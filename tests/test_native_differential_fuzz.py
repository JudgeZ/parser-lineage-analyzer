"""Differential fuzz: deterministic seeded parser shapes must produce byte-identical
analysis output across native, pure-Python, and opt-out-dedupe modes."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

NUM_SHAPES = 60
SEED_BASE = 0xC0DEC0DE
REPO_ROOT = Path(__file__).resolve().parent.parent


def _make_parser(seed: int) -> tuple[str, str]:
    rng = random.Random(SEED_BASE ^ seed)

    fields = [f"f{i}" for i in range(rng.randint(2, 4))]
    tokens = [f"t{i}" for i in range(rng.randint(2, 4))]
    target_token = rng.choice(tokens)

    branches: list[str] = []
    for i in range(rng.randint(2, 5)):
        guard_field = rng.choice(fields)
        guard_value = rng.choice(["alpha", "beta", "gamma", "1", "2"])
        op = rng.choice(["==", "!="])

        body_parts: list[str] = []
        for _ in range(rng.randint(1, 3)):
            kind = rng.choice(["replace", "dynamic_replace", "rename", "merge"])
            tok = rng.choice(tokens)
            if kind == "replace":
                source = rng.choice(tokens + fields)
                literal = rng.choice(["lit_a", "lit_b", "lit_c", f"%{{{source}}}"])
                body_parts.append(f'mutate {{ replace => {{ "{tok}" => "{literal}" }} }}')
            elif kind == "dynamic_replace":
                tmpl_field = rng.choice(fields + tokens)
                src = rng.choice(tokens + fields)
                body_parts.append(f'mutate {{ replace => {{ "out.%{{{tmpl_field}}}.suffix" => "%{{{src}}}" }} }}')
            elif kind == "rename":
                src = rng.choice(tokens)
                if src != tok:
                    body_parts.append(f'mutate {{ rename => {{ "{src}" => "{tok}" }} }}')
            elif kind == "merge":
                src = rng.choice(tokens)
                body_parts.append(f'mutate {{ merge => {{ "{tok}" => "{src}" }} }}')

        if rng.random() < 0.15:
            body_parts.append("drop {}")

        if not body_parts:
            body_parts.append('mutate { replace => { "noop" => "noop" } }')

        body = "\n    ".join(body_parts)
        prefix = "if" if i == 0 else "else if"
        branches.append(f'{prefix} [{guard_field}] {op} "{guard_value}" {{\n    {body}\n  }}')

    if rng.random() < 0.6:
        else_body = f'mutate {{ replace => {{ "{rng.choice(tokens)}" => "fallthrough" }} }}'
        branches.append(f"else {{\n    {else_body}\n  }}")

    branch_block = " ".join(branches)
    output = (
        f'mutate {{ replace => {{ "event.idm.read_only_udm.additional.fields.{target_token}" '
        f'=> "%{{{target_token}}}" }} }}'
    )
    parser_text = (
        f'filter {{\n  mutate {{ replace => {{ "{target_token}" => "base" }} }}\n  {branch_block}\n  {output}\n}}'
    )
    udm_field = f"additional.fields.{target_token}"
    return parser_text, udm_field


_DRIVER_SCRIPT = r"""
import json
import sys

from parser_lineage_analyzer import ReverseParser

shapes = json.loads(sys.stdin.read())
out = []
for parser_text, udm_field in shapes:
    parser = ReverseParser(parser_text)
    parser.analyze()
    out.append({
        "summary": parser.analysis_summary(compact=True),
        "query": parser.query(udm_field).to_json(),
    })
print(json.dumps(out, sort_keys=True))
"""


_NATIVE_ENV_FLAGS = (
    "PARSER_LINEAGE_ANALYZER_NO_EXT",
    "PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE",
    "PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE",
)


def _run_mode(shapes: list[tuple[str, str]], env_overrides: dict[str, str]) -> str:
    env = dict(os.environ)
    for key in _NATIVE_ENV_FLAGS:
        env.pop(key, None)
    env.update(env_overrides)
    payload = json.dumps([list(shape) for shape in shapes])
    result = subprocess.run(
        [sys.executable, "-c", _DRIVER_SCRIPT],
        check=True,
        env=env,
        input=payload,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    return result.stdout


@pytest.fixture(scope="module")
def fuzz_baseline() -> tuple[list[tuple[str, str]], str]:
    shapes = [_make_parser(seed) for seed in range(NUM_SHAPES)]
    return shapes, _run_mode(shapes, {})


@pytest.mark.parametrize(
    "env_overrides",
    [
        pytest.param({"PARSER_LINEAGE_ANALYZER_NO_EXT": "1"}, id="no-ext"),
        pytest.param({"PARSER_LINEAGE_ANALYZER_USE_NATIVE_DEDUPE": "0"}, id="no-native-dedupe"),
        pytest.param({"PARSER_LINEAGE_ANALYZER_USE_NATIVE_BRANCH_MERGE": "0"}, id="no-native-branch-merge"),
    ],
)
def test_differential_fuzz_generated_parsers_match_across_modes(
    fuzz_baseline: tuple[list[tuple[str, str]], str],
    env_overrides: dict[str, str],
) -> None:
    shapes, baseline = fuzz_baseline
    other = _run_mode(shapes, env_overrides)
    assert other == baseline
