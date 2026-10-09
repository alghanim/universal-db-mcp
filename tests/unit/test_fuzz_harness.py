"""The fuzz harness (tests/fuzz/fuzz_sql_guard.py) stays runnable: its
property holds on every seed, and on inputs no seed covers."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

FUZZ = Path(__file__).resolve().parents[1] / "fuzz"


def _harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fuzz_sql_guard", FUZZ / "fuzz_sql_guard.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HARNESS = _harness()
SEEDS = sorted((FUZZ / "corpus").iterdir())


def test_the_corpus_has_seeds_for_every_engine_and_both_modes() -> None:
    decoded = [HARNESS.decode(seed.read_bytes()) for seed in SEEDS]
    assert {engine for engine, _, _ in decoded} == set(HARNESS.ENGINES)
    assert {explain for _, explain, _ in decoded} == {True, False}


@pytest.mark.parametrize("seed", SEEDS, ids=[seed.name for seed in SEEDS])
def test_the_guard_accepts_or_refuses_every_seed(seed: Path) -> None:
    HARNESS.check(seed.read_bytes())


@pytest.mark.parametrize(
    "data",
    [b"", b"\x00", b"\x05\x01", b"\x02\x00\xff\xfe", b"\x03\x00" + b"(" * 5000, b"\x04\x01" + "é".encode() * 3000],
)
def test_the_guard_accepts_or_refuses_odd_inputs(data: bytes) -> None:
    HARNESS.check(data)
