"""Field-by-field comparison of peoxide against pefile on real Windows binaries."""

import os
from pathlib import Path

import pefile
import pytest

import peoxide

WINDIR = Path(os.environ.get("WINDIR", r"C:\Windows"))
CORPUS = [
    WINDIR / "System32" / "kernel32.dll",
    WINDIR / "System32" / "ntdll.dll",
    WINDIR / "System32" / "user32.dll",
    WINDIR / "System32" / "notepad.exe",
    WINDIR / "SysWOW64" / "kernel32.dll",
]
CORPUS = [p for p in CORPUS if p.exists()]

DOS_FIELDS = [
    "e_magic",
    "e_cblp",
    "e_cp",
    "e_crlc",
    "e_cparhdr",
    "e_minalloc",
    "e_maxalloc",
    "e_ss",
    "e_sp",
    "e_csum",
    "e_ip",
    "e_cs",
    "e_lfarlc",
    "e_ovno",
    "e_res",
    "e_oemid",
    "e_oeminfo",
    "e_res2",
    "e_lfanew",
]
FILE_FIELDS = [
    "Machine",
    "NumberOfSections",
    "TimeDateStamp",
    "PointerToSymbolTable",
    "NumberOfSymbols",
    "SizeOfOptionalHeader",
    "Characteristics",
]
OPTIONAL_FIELDS = [
    "Magic",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "SizeOfCode",
    "SizeOfInitializedData",
    "SizeOfUninitializedData",
    "AddressOfEntryPoint",
    "BaseOfCode",
    "ImageBase",
    "SectionAlignment",
    "FileAlignment",
    "MajorOperatingSystemVersion",
    "MinorOperatingSystemVersion",
    "MajorImageVersion",
    "MinorImageVersion",
    "MajorSubsystemVersion",
    "MinorSubsystemVersion",
    "Reserved1",
    "SizeOfImage",
    "SizeOfHeaders",
    "CheckSum",
    "Subsystem",
    "DllCharacteristics",
    "SizeOfStackReserve",
    "SizeOfStackCommit",
    "SizeOfHeapReserve",
    "SizeOfHeapCommit",
    "LoaderFlags",
    "NumberOfRvaAndSizes",
]
SECTION_FIELDS = [
    "Name",
    "Misc_VirtualSize",
    "VirtualAddress",
    "SizeOfRawData",
    "PointerToRawData",
    "PointerToRelocations",
    "PointerToLinenumbers",
    "NumberOfRelocations",
    "NumberOfLinenumbers",
    "Characteristics",
]

pytestmark = pytest.mark.skipif(not CORPUS, reason="needs Windows system binaries")


@pytest.fixture(params=CORPUS, ids=lambda p: f"{p.parent.name}/{p.name}", scope="module")
def pair(request):
    return peoxide.PE(str(request.param)), pefile.PE(str(request.param))


def assert_fields_match(ours, theirs, fields):
    for field in fields:
        assert getattr(ours, field) == getattr(theirs, field), field


def test_dos_header(pair):
    ours, theirs = pair
    assert_fields_match(ours.DOS_HEADER, theirs.DOS_HEADER, DOS_FIELDS)


def test_nt_headers(pair):
    ours, theirs = pair
    assert ours.NT_HEADERS.Signature == theirs.NT_HEADERS.Signature


def test_file_header(pair):
    ours, theirs = pair
    assert_fields_match(ours.FILE_HEADER, theirs.FILE_HEADER, FILE_FIELDS)


def test_optional_header(pair):
    ours, theirs = pair
    assert_fields_match(ours.OPTIONAL_HEADER, theirs.OPTIONAL_HEADER, OPTIONAL_FIELDS)
    assert ours.OPTIONAL_HEADER.BaseOfData == getattr(theirs.OPTIONAL_HEADER, "BaseOfData", None)


def test_data_directory(pair):
    ours, theirs = pair
    assert [(d.name, d.VirtualAddress, d.Size) for d in ours.OPTIONAL_HEADER.DATA_DIRECTORY] == [
        (d.name, d.VirtualAddress, d.Size) for d in theirs.OPTIONAL_HEADER.DATA_DIRECTORY
    ]


FILE_FLAGS = [name for name, _ in pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, "IMAGE_FILE_")]
DLL_FLAGS = [
    name
    for name, _ in pefile.retrieve_flags(pefile.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_")
]
SECTION_FLAGS = [
    name for name, _ in pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, "IMAGE_SCN_")
]


def test_flags(pair):
    ours, theirs = pair
    assert_fields_match(ours.FILE_HEADER, theirs.FILE_HEADER, FILE_FLAGS)
    assert_fields_match(ours.OPTIONAL_HEADER, theirs.OPTIONAL_HEADER, DLL_FLAGS)
    for mine, ref in zip(ours.sections, theirs.sections):
        assert_fields_match(mine, ref, SECTION_FLAGS)


def test_unknown_attribute_raises(pair):
    ours, _ = pair
    with pytest.raises(AttributeError):
        ours.FILE_HEADER.IMAGE_FILE_NOT_A_FLAG


def test_sections(pair):
    ours, theirs = pair
    assert len(ours.sections) == len(theirs.sections)
    for mine, ref in zip(ours.sections, theirs.sections):
        assert_fields_match(mine, ref, SECTION_FIELDS)


def test_imports(pair):
    ours, theirs = pair
    expected = getattr(theirs, "DIRECTORY_ENTRY_IMPORT", [])
    assert [d.dll for d in ours.DIRECTORY_ENTRY_IMPORT] == [d.dll for d in expected]
    for mine, ref in zip(ours.DIRECTORY_ENTRY_IMPORT, expected):
        assert len(mine.imports) == len(ref.imports), mine.dll
        for a, b in zip(mine.imports, ref.imports):
            assert (a.name, a.ordinal, a.address, a.import_by_ordinal) == (
                b.name,
                b.ordinal,
                b.address,
                b.import_by_ordinal,
            )
            if a.name is not None:
                assert a.hint == b.hint


def test_exports(pair):
    ours, theirs = pair
    export_dir = getattr(theirs, "DIRECTORY_ENTRY_EXPORT", None)
    expected = export_dir.symbols if export_dir else []

    def key(s):
        return (s.name, s.ordinal, s.address, s.forwarder)

    assert [key(s) for s in ours.DIRECTORY_ENTRY_EXPORT.symbols] == [key(s) for s in expected]
