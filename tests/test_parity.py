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

DOS_FIELDS = ["e_magic", "e_lfanew"]
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


def test_sections(pair):
    ours, theirs = pair
    assert len(ours.sections) == len(theirs.sections)
    for mine, ref in zip(ours.sections, theirs.sections):
        assert_fields_match(mine, ref, SECTION_FIELDS)
