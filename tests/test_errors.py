"""Bad input must raise a Python exception, never crash or panic."""

import os
import random
from pathlib import Path

import pytest

import peoxide

KERNEL32 = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "kernel32.dll"
needs_kernel32 = pytest.mark.skipif(not KERNEL32.exists(), reason="needs kernel32.dll")


@pytest.mark.parametrize("data", [b"", b"MZ", b"not a pe file", b"\x00" * 4096])
def test_garbage_raises_pe_format_error(data):
    with pytest.raises(peoxide.PEFormatError):
        peoxide.PE(data=data)


def test_missing_file_raises_os_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        peoxide.PE(str(tmp_path / "missing.exe"))


@pytest.mark.parametrize("kwargs", [{}, {"name": "a.exe", "data": b"MZ"}])
def test_needs_exactly_one_source(kwargs):
    with pytest.raises(TypeError):
        peoxide.PE(**kwargs)


@needs_kernel32
def test_name_and_data_agree():
    by_path = peoxide.PE(str(KERNEL32))
    by_data = peoxide.PE(data=KERNEL32.read_bytes())
    assert by_path.OPTIONAL_HEADER.CheckSum == by_data.OPTIONAL_HEADER.CheckSum


@needs_kernel32
@pytest.mark.parametrize("length", [2, 0x40, 0x100, 0x200, 0x400, 0x1000, 0x10000])
def test_truncated_file_raises(length):
    with pytest.raises(peoxide.PEFormatError):
        peoxide.PE(data=KERNEL32.read_bytes()[:length])


@needs_kernel32
def test_random_corruption_never_crashes():
    original = KERNEL32.read_bytes()
    rng = random.Random(0)
    for _ in range(2000):
        data = bytearray(original)
        hot = rng.random() < 0.7
        for _ in range(rng.randint(1, 16)):
            pos = rng.randrange(0x1000 if hot else len(data))
            data[pos] = rng.randrange(256)
        try:
            peoxide.PE(data=bytes(data))
        except peoxide.PEFormatError:
            pass
