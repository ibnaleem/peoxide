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


READERS = [
    f"get_{width}_{kind}"
    for width in ("word", "dword", "qword")
    for kind in ("at_rva", "from_offset")
]


@pytest.mark.parametrize("method", READERS + ["get_string_at_rva"])
@pytest.mark.parametrize("address", [-1, -8, -(2**70)])
def test_readers_return_none_for_a_negative_address(method, address):
    """pefile reads from the end of the headers or the file here, by accident of slicing."""
    pe = peoxide.PE(str(FILES[0]))
    assert getattr(pe, method)(address) is None


@pytest.mark.parametrize("method", READERS)
@pytest.mark.parametrize("address", [2**63, 2**64, 2**70])
def test_integer_readers_return_none_for_an_address_too_large_for_any_file(pair, method, address):
    ours, theirs = pair
    assert getattr(ours, method)(address) is None
    assert getattr(theirs, method)(address) is None


def test_get_string_at_rva_takes_values_too_large_for_any_file(pair):
    ours, theirs = pair
    assert ours.get_string_at_rva(2**70) == theirs.get_string_at_rva(2**70) == b""
    assert ours.get_string_at_rva(0x40, 2**70) == theirs.get_string_at_rva(0x40, 2**70)
    assert ours.get_string_at_rva(0x40, -1) == theirs.get_string_at_rva(0x40, -1)
    assert ours.get_string_at_rva(0x40, 0) == theirs.get_string_at_rva(0x40, 0) == b""


@pytest.mark.parametrize("method", READERS + ["get_string_at_rva"])
def test_readers_reject_an_address_that_is_not_an_integer(method):
    with pytest.raises(TypeError):
        getattr(peoxide.PE(str(FILES[0])), method)("0x10")


def test_parse_data_directories_takes_only_the_arguments_pefile_takes():
    pe = peoxide.PE(str(FILES[0]))
    pe.parse_data_directories([1], forwarded_exports_only=True, import_dllnames_only=True)
    with pytest.raises(TypeError):
        pe.parse_data_directories(directorys=[1])


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


SYSWOW64 = SYSTEM32.parent / "SysWOW64"
STRING_TABLE_FILES = [FIXTURES / "strings.dll"] + [
    path for path in (SYSTEM32 / "nddeapi.dll", SYSTEM32 / "spwizres.dll") if path.exists()
]
MAPPED_FILES = FILES + [
    FIXTURES / "strings.dll",
] + [
    path
    for path in (
        SYSTEM32 / "ntdll.dll",
        SYSTEM32 / "drivers" / "tcpip.sys",
        SYSWOW64 / "kernel32.dll",
        SYSWOW64 / "ntdll.dll",
        SYSWOW64 / "notepad.exe",
    )
    if path.exists()
]


def raises_same(call_ours, call_theirs):
    """Both calls return equal values, or both raise an exception of the same type name."""
    try:
        theirs = ("ok", call_theirs())
    except Exception as e:
        theirs = ("raise", type(e).__name__)
    try:
        ours = ("ok", call_ours())
    except Exception as e:
        ours = ("raise", type(e).__name__)
    assert ours == theirs


def utf16_rvas(pe):
    """RVAs of real UTF-16 text: resource names, and strings inside version and string data."""
    rvas = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return rvas
    base = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress

    def walk(directory):
        for entry in directory.entries:
            if entry.struct.Name & 0x80000000:
                rvas.add(base + (entry.struct.Name & 0x7FFFFFFF) + 2)
            if hasattr(entry, "directory"):
                walk(entry.directory)
            elif hasattr(entry, "data"):
                start = entry.data.struct.OffsetToData
                rvas.update({start + 2, start + 6, start + 0x26})

    walk(pe.DIRECTORY_ENTRY_RESOURCE)
    return rvas


UNICODE_FILES = FILES + STRING_TABLE_FILES


@pytest.fixture(params=UNICODE_FILES, ids=lambda p: p.name, scope="module")
def unicode_pair(request):
    data = request.param.read_bytes()
    return peoxide.PE(data=data), pefile.PE(data=data)


def test_corpus_has_utf16_strings():
    assert any(utf16_rvas(pefile.PE(str(path))) for path in UNICODE_FILES)


@pytest.mark.parametrize("encoding", [None, "", "utf-16-le", "ascii", "latin-1"])
def test_get_string_u_at_rva_matches_pefile(unicode_pair, encoding):
    ours, theirs = unicode_pair
    points = utf16_rvas(theirs) | set(probes(theirs))
    for rva in sorted(points):
        for max_length in (0, 1, 2, 127, 128, 129, 2**16, 2**70):
            raises_same(
                lambda: ours.get_string_u_at_rva(rva, max_length, encoding),
                lambda: theirs.get_string_u_at_rva(rva, max_length, encoding),
            )
        raises_same(
            lambda: ours.get_string_u_at_rva(rva, encoding=encoding),
            lambda: theirs.get_string_u_at_rva(rva, encoding=encoding),
        )


def test_get_string_u_at_rva_keeps_surrogate_pairs_apart():
    data = bytearray(FILES[0].read_bytes())
    # Header padding, past the section table and before the first section's data.
    at = 0x3E0
    data[at : at + 8] = "\U0001f600\xe9".encode("utf-16-le") + b"\0\0"
    ours, theirs = peoxide.PE(data=bytes(data)), pefile.PE(data=bytes(data))
    assert theirs.get_string_u_at_rva(at) == b"\\ud83d\\ude00\xc3\xa9"
    for encoding in (None, "utf-8", "utf-16-le", "ascii"):
        assert ours.get_string_u_at_rva(at, encoding=encoding) == theirs.get_string_u_at_rva(
            at, encoding=encoding
        )


def test_get_string_u_at_rva_raises_where_pefile_cannot_read(pair):
    ours, theirs = pair
    for rva in (2**32, 2**63, 2**70):
        with pytest.raises(pefile.PEFormatError):
            theirs.get_string_u_at_rva(rva)
        with pytest.raises(peoxide.PEFormatError):
            ours.get_string_u_at_rva(rva)
    assert ours.get_string_u_at_rva(2**70, 0) == theirs.get_string_u_at_rva(2**70, 0) == b""


def test_get_string_u_at_rva_rejects_what_pefile_mishandles():
    """pefile slices from the end for a negative RVA, and never returns for a negative length."""
    pe = peoxide.PE(str(FILES[0]))
    with pytest.raises(peoxide.PEFormatError):
        pe.get_string_u_at_rva(-2)
    with pytest.raises(ValueError):
        pe.get_string_u_at_rva(0x40, -1)


def test_get_physical_by_rva_matches_pefile(pair):
    ours, theirs = pair
    points = probes(theirs) + [-1, -(2**70), 2**63, 2**70]
    for rva in points:
        assert ours.get_physical_by_rva(rva) == theirs.get_physical_by_rva(rva), rva
    assert ours.get_physical_by_rva("0x10") is theirs.get_physical_by_rva("0x10") is None


@pytest.fixture(params=MAPPED_FILES, ids=lambda p: f"{p.parent.name}/{p.name}", scope="module")
def mapped_pair(request):
    return request.param.read_bytes()


def test_get_memory_mapped_image_matches_pefile(mapped_pair):
    ours = peoxide.PE(data=mapped_pair)
    # pefile caches state per call, so each comparison uses a fresh object.
    for args in ((), (0x2000,), (0,), (-1,), (2**70,)):
        assert ours.get_memory_mapped_image(*args) == pefile.PE(
            data=mapped_pair
        ).get_memory_mapped_image(*args), args
    base = ours.OPTIONAL_HEADER.ImageBase
    assert ours.get_memory_mapped_image(ImageBase=base) == pefile.PE(
        data=mapped_pair
    ).get_memory_mapped_image(ImageBase=base)


def test_get_memory_mapped_image_does_not_relocate():
    pe = peoxide.PE(str(FILES[0]))
    with pytest.raises(NotImplementedError):
        pe.get_memory_mapped_image(ImageBase=pe.OPTIONAL_HEADER.ImageBase + 0x10000)


def test_get_memory_mapped_image_pads_and_cuts_like_pefile():
    """Sections that overlap or leave gaps, which the system files never do."""
    data = bytearray(FILES[0].read_bytes())
    last = pefile.PE(data=bytes(data)).sections[-1]
    # Move the last section into the middle of the one before it, then past a gap.
    for address in (last.VirtualAddress - 0xF00, last.VirtualAddress + 0x3000):
        patched = bytearray(data)
        offset = last.get_file_offset() + 12
        patched[offset : offset + 4] = address.to_bytes(4, "little")
        assert peoxide.PE(data=bytes(patched)).get_memory_mapped_image() == pefile.PE(
            data=bytes(patched)
        ).get_memory_mapped_image(), hex(address)
    # A first section with more raw data than fits before the second, so the second cuts it.
    first = pefile.PE(data=bytes(data)).sections[0]
    patched = bytearray(data) + bytes(0x2000)
    offset = first.get_file_offset() + 16
    patched[offset : offset + 4] = (0x1200).to_bytes(4, "little")
    ours = peoxide.PE(data=bytes(patched)).get_memory_mapped_image()
    assert ours == pefile.PE(data=bytes(patched)).get_memory_mapped_image()
    assert ours[0x1000:0x2000] == bytes(patched[0x400:0x1400])


def test_pe_type_matches_pefile(pair):
    ours, theirs = pair
    assert ours.PE_TYPE == theirs.PE_TYPE


def test_corpus_has_pe32_and_pe32_plus():
    assert {peoxide.PE(str(path)).PE_TYPE for path in FILES} == {0x10B, 0x20B}


def test_has_relocs_matches_pefile(mapped_pair):
    assert peoxide.PE(data=mapped_pair).has_relocs() == pefile.PE(data=mapped_pair).has_relocs()


def test_corpus_has_files_with_and_without_relocs():
    found = {peoxide.PE(data=data).has_relocs() for data in map(Path.read_bytes, MAPPED_FILES)}
    assert found == {False, True}


def test_get_resources_strings_matches_pefile(unicode_pair):
    ours, theirs = unicode_pair
    assert ours.get_resources_strings() == theirs.get_resources_strings()


def test_corpus_has_resource_strings():
    assert peoxide.PE(str(FIXTURES / "strings.dll")).get_resources_strings() == ["Hello", "caf\xe9"]


def test_normalize_import_va_matches_pefile(pair):
    ours, theirs = pair
    base, size = theirs.OPTIONAL_HEADER.ImageBase, theirs.OPTIONAL_HEADER.SizeOfImage
    for va in (0, 1, base - 1, base, base + 0x1000, base + size - 1, base + size, 2**70, -1):
        assert ours.normalize_import_va(va) == theirs.normalize_import_va(va), va


BYTES_SAMPLES = [b"", b"\x01", b"\x01\x02\x03", bytes(range(1, 10)), bytearray(b"\x00ab\x00cd")]
OFFSETS = [0, 1, 2, 3, 8, 9, 10, -1, -2, -3, -(2**70), 2**70]


@pytest.mark.parametrize("width", ["word", "dword", "qword"])
def test_integer_from_data_matches_pefile(width):
    ours, theirs = peoxide.PE(str(FILES[0])), pefile.PE(str(FILES[0]))
    method = f"get_{width}_from_data"
    for data in BYTES_SAMPLES + [memoryview(bytes(range(16)))]:
        for offset in OFFSETS:
            raises_same(
                lambda: getattr(ours, method)(data, offset),
                lambda: getattr(theirs, method)(data, offset),
            )


@pytest.mark.parametrize("method", ["get_bytes_from_data", "get_string_from_data"])
def test_bytes_and_strings_from_data_match_pefile(method):
    ours, theirs = peoxide.PE(str(FILES[0])), pefile.PE(str(FILES[0]))
    for data in BYTES_SAMPLES + [memoryview(b"ab\x00c"), "ab\x00c"]:
        for offset in OFFSETS:
            try:
                expected = getattr(theirs, method)(offset, data)
            except Exception as e:
                with pytest.raises(type(e)):
                    getattr(ours, method)(offset, data)
                continue
            got = getattr(ours, method)(offset, data)
            assert type(got) is type(expected)
            assert bytes(got) == bytes(expected) if not isinstance(got, str) else got == expected


@pytest.mark.parametrize("width", ["word", "dword", "qword"])
def test_data_from_integer_matches_pefile(width):
    ours, theirs = peoxide.PE(str(FILES[0])), pefile.PE(str(FILES[0]))
    method = f"get_data_from_{width}"
    for value in (0, 1, 0xFFFF, 0x10000, 0xFFFFFFFF, 2**32, 2**64 - 1, 2**64, -1, -(2**70), 1.5):
        raises_same(lambda: getattr(ours, method)(value), lambda: getattr(theirs, method)(value))


def test_dword_align_matches_pefile():
    ours, theirs = peoxide.PE(str(FILES[0])), pefile.PE(str(FILES[0]))
    for offset in (0, 1, 3, 4, 5, -1, 2**40, -(2**70)):
        for base in (0, 1, 2, 3, 0xFFFFFFFF, 2**70, -5):
            assert ours.dword_align(offset, base) == theirs.dword_align(offset, base)
