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


I64_MAX = 2**63 - 1
I64_MIN = -(2**63)


@needs_kernel32
def test_extreme_lengths_read_to_the_end_like_pefile():
    import pefile

    data = KERNEL32.read_bytes()
    ours, theirs = peoxide.PE(data=data), pefile.PE(data=data)
    text, ref_text = ours.sections[0], theirs.sections[0]
    assert ours.get_data(text.VirtualAddress, I64_MAX) == theirs.get_data(
        ref_text.VirtualAddress, I64_MAX
    )
    assert text.get_data(None, I64_MAX) == ref_text.get_data(None, I64_MAX)
    assert ours.get_data(0x40, I64_MAX) == theirs.get_data(0x40, I64_MAX)


@needs_kernel32
@pytest.mark.parametrize("value", [I64_MAX, I64_MIN])
def test_extreme_addresses_never_panic(value):
    pe = peoxide.PE(data=KERNEL32.read_bytes())
    section = pe.sections[0]
    section.get_data(value, I64_MAX)
    section.get_data(value, None, True)
    section.get_offset_from_rva(value)
    section.get_rva_from_offset(value)
    pe.get_rva_from_offset(value)
    try:
        pe.get_data(value, I64_MAX)
        pe.get_offset_from_rva(value)
    except peoxide.PEFormatError:
        pass


FIXTURE_BYTES = [
    p.read_bytes()
    for p in sorted((Path(__file__).parent / "fixtures").rglob("*"))
    if p.is_file()
]


def test_random_corruption_never_crashes():
    rng = random.Random(0)
    for _ in range(2000):
        data = bytearray(rng.choice(FIXTURE_BYTES))
        hot = rng.random() < 0.7
        for _ in range(rng.randint(1, 16)):
            # The hot region holds the headers and the section table.
            pos = rng.randrange(0x400 if hot else len(data))
            data[pos] = rng.randrange(256)
        try:
            pe = peoxide.PE(data=bytes(data))
        except peoxide.PEFormatError:
            continue
        # Built on first access, so PE() alone never parses them.
        pe.DIRECTORY_ENTRY_BOUND_IMPORT
        read_lazy_directories(pe)
        read_exceptions(pe)


def read_exceptions(pe):
    """Builds the lazy exception directory and reads every unwind code."""
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        info = entry.unwindinfo
        if info is not None:
            info.get_chained_function_entry()
            [str(code) for code in getattr(info, "UnwindCodes", [])]


def test_crafted_exception_directory_never_crashes():
    data = (Path(__file__).parent / "fixtures" / "crafted" / "exceptions.dll").read_bytes()
    rng = random.Random(0)
    for _ in range(500):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 16)):
            # Past the headers, so the edits land in the unwind records and the table.
            mutated[rng.randrange(0x400, len(mutated))] = rng.randrange(256)
        read_exceptions(peoxide.PE(data=bytes(mutated)))


def read_lazy_directories(pe):
    """Builds the directories `PE()` leaves for first access, down to each relocation entry."""
    blocks = list(pe.DIRECTORY_ENTRY_BASERELOC)
    config = pe.DIRECTORY_ENTRY_LOAD_CONFIG
    for dynamic in (config and config.dynamic_relocations) or []:
        blocks += getattr(dynamic, "relocations", [])
        for function in getattr(dynamic, "func_relocs", []):
            blocks += function.relocations
    for block in blocks:
        for entry in block.entries:
            entry.struct
