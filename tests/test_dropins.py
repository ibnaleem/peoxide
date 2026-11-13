"""pefile methods that peoxide offers so pefile code runs unchanged, checked against pefile."""

import os
from pathlib import Path

import pefile
import pytest

import peoxide

SYSTEM32 = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
FIXTURES = Path(__file__).parent / "fixtures"
FILES = [FIXTURES / name for name in ("sample64.dll", "sample32.exe", "driver.sys")] + [
    path for path in (SYSTEM32 / "kernel32.dll", SYSTEM32 / "notepad.exe") if path.exists()
]


@pytest.fixture(params=FILES, ids=lambda p: p.name, scope="module")
def pair(request):
    data = request.param.read_bytes()
    return peoxide.PE(data=data), pefile.PE(data=data)


def probes(pe):
    """RVAs and offsets at the edges of the headers, each section and the file."""
    size = len(pe.__data__)
    points = {0, 1, 0x3C, pe.OPTIONAL_HEADER.AddressOfEntryPoint, size - 8, size - 1, size, size + 64}
    for section in pe.sections:
        start, raw = section.VirtualAddress, section.SizeOfRawData
        points |= {start, start + 1, start + raw - 8, start + raw - 1, start + raw}
        points |= {section.PointerToRawData, section.PointerToRawData + raw - 2}
    return sorted(p for p in points if p >= 0)


@pytest.mark.parametrize("width", ["word", "dword", "qword"])
def test_integer_readers_match_pefile(pair, width):
    ours, theirs = pair
    for point in probes(theirs):
        for kind in ("at_rva", "from_offset"):
            method = f"get_{width}_{kind}"
            assert getattr(ours, method)(point) == getattr(theirs, method)(point), (method, point)


def test_integer_readers_return_none_for_a_negative_offset():
    pe = peoxide.PE(str(FILES[0]))
    assert pe.get_dword_from_offset(-8) is None


def test_get_string_at_rva_matches_pefile(pair):
    ours, theirs = pair
    for point in probes(theirs):
        for max_length in (None, 5):
            args = (point,) if max_length is None else (point, max_length)
            assert ours.get_string_at_rva(*args) == theirs.get_string_at_rva(*args), args
    assert ours.get_string_at_rva(None) is None


def test_import_names_can_be_read_back_as_strings(pair):
    ours, theirs = pair
    for entry in theirs.DIRECTORY_ENTRY_IMPORT if hasattr(theirs, "DIRECTORY_ENTRY_IMPORT") else []:
        assert ours.get_string_at_rva(entry.struct.Name) == entry.dll


def test_checksum_matches_pefile(pair):
    ours, theirs = pair
    assert ours.generate_checksum() == theirs.generate_checksum()
    assert ours.verify_checksum() == theirs.verify_checksum()


def test_checksum_of_a_file_with_a_trailing_partial_dword():
    data = FILES[0].read_bytes() + b"\x01\x02\x03"
    assert peoxide.PE(data=data).generate_checksum() == pefile.PE(data=data).generate_checksum()


def test_data_is_the_whole_file(pair):
    ours, theirs = pair
    assert ours.__data__ == bytes(theirs.__data__)


def test_pefile_loading_idiom_runs_unchanged():
    with peoxide.PE(str(FILES[0]), fast_load=True) as pe:
        pe.parse_data_directories(directories=[1, 0])
        pe.full_load()
        imports = [entry.dll for entry in pe.DIRECTORY_ENTRY_IMPORT]
    pe.close()
    assert imports == [entry.dll for entry in peoxide.PE(str(FILES[0])).DIRECTORY_ENTRY_IMPORT]


def test_fast_load_is_accepted_positionally():
    assert peoxide.PE(None, FILES[0].read_bytes(), True).sections
