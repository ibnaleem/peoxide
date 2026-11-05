"""The committed fixtures must be exactly what scripts/gen_fixtures.py generates."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def test_fixtures_match_the_generator():
    spec = importlib.util.spec_from_file_location("gen_fixtures", ROOT / "scripts" / "gen_fixtures.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    expected = generator.fixtures()
    assert sorted(p.name for p in FIXTURES.iterdir()) == sorted(expected)
    for name, data in expected.items():
        assert (FIXTURES / name).read_bytes() == data, f"rerun scripts/gen_fixtures.py ({name})"
