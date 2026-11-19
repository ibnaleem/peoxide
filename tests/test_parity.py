"""Field-by-field comparison of peoxide against pefile on Windows binaries and tests/fixtures."""

import os
from pathlib import Path

import pefile
import pytest

import peoxide

WINDIR = Path(os.environ.get("WINDIR", r"C:\Windows"))
SYSTEM = [
    WINDIR / "System32" / "kernel32.dll",
    WINDIR / "System32" / "ntdll.dll",
    WINDIR / "System32" / "user32.dll",
    WINDIR / "System32" / "notepad.exe",
    WINDIR / "System32" / "drivers" / "ntfs.sys",
    WINDIR / "SysWOW64" / "kernel32.dll",
    # The only file in System32, SysWOW64 or Program Files found with bound imports.
    WINDIR / "SysWOW64" / "mfc40u.dll",
    # The ones above have no TLS directory.
    WINDIR / "System32" / "msvcrt.dll",
    WINDIR / "SysWOW64" / "msvcrt.dll",
]
SYSTEM = [p for p in SYSTEM if p.exists()]
CORPUS = SYSTEM + sorted(p for p in (Path(__file__).parent / "fixtures").iterdir() if p.is_file())

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

pytestmark = pytest.mark.skipif(not SYSTEM, reason="needs Windows system binaries")


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


def test_classification(pair):
    ours, theirs = pair
    assert (ours.is_exe(), ours.is_dll(), ours.is_driver()) == (
        theirs.is_exe(),
        theirs.is_dll(),
        theirs.is_driver(),
    )


def test_unknown_attribute_raises(pair):
    ours, _ = pair
    with pytest.raises(AttributeError):
        ours.FILE_HEADER.IMAGE_FILE_NOT_A_FLAG


def test_field_reads_return_the_stored_object(pair):
    # `is`, not `==`: a field stored as a Rust integer builds a new int on every read, which
    # makes attribute access several times slower than pefile's.
    ours, _ = pair
    reads = [(ours.OPTIONAL_HEADER, "ImageBase")]
    reads += [(section, "VirtualAddress") for section in ours.sections]
    reads += [(symbol, "address") for symbol in ours.DIRECTORY_ENTRY_EXPORT.symbols]
    reads += [(i, "address") for dll in ours.DIRECTORY_ENTRY_IMPORT for i in dll.imports]
    assert all(getattr(obj, name) is getattr(obj, name) for obj, name in reads)


def test_sections(pair):
    ours, theirs = pair
    assert len(ours.sections) == len(theirs.sections)
    for mine, ref in zip(ours.sections, theirs.sections):
        assert_fields_match(mine, ref, SECTION_FIELDS)


def outcome(method, *args):
    try:
        return method(*args)
    except (pefile.PEFormatError, peoxide.PEFormatError):
        return "raised"


def probe_rvas(pe):
    rvas = {0, 2, 0x40, 0x3FF, len(pe.__data__) - 1, len(pe.__data__) + 0x100000}
    for s in pe.sections:
        end = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        rvas |= {s.VirtualAddress, s.VirtualAddress + 0x10, end - 1, end, end + 0x10}
    return sorted(rvas)


def probe_offsets(pe):
    offsets = {0, 0x40, len(pe.__data__) - 1, len(pe.__data__) + 0x100000}
    for s in pe.sections:
        end = s.PointerToRawData + s.SizeOfRawData
        offsets |= {s.PointerToRawData, s.PointerToRawData + 0x10, end - 1, end}
    return sorted(offsets)


def test_get_data(pair):
    ours, theirs = pair
    for rva in probe_rvas(theirs):
        for length in (None, 1, 16):
            assert outcome(ours.get_data, rva, length) == outcome(theirs.get_data, rva, length), (
                hex(rva),
                length,
            )


def test_rva_offset_mapping(pair):
    ours, theirs = pair
    for rva in probe_rvas(theirs):
        assert outcome(ours.get_offset_from_rva, rva) == outcome(
            theirs.get_offset_from_rva, rva
        ), hex(rva)
        mine, ref = ours.get_section_by_rva(rva), theirs.get_section_by_rva(rva)
        assert (mine and mine.Name) == (ref and ref.Name), hex(rva)
    for offset in probe_offsets(theirs):
        assert ours.get_rva_from_offset(offset) == theirs.get_rva_from_offset(offset), hex(offset)
        mine, ref = ours.get_section_by_offset(offset), theirs.get_section_by_offset(offset)
        assert (mine and mine.Name) == (ref and ref.Name), hex(offset)


def test_section_data(pair):
    ours, theirs = pair
    for mine, ref in zip(ours.sections, theirs.sections):
        va = ref.VirtualAddress
        for args in [(), (va + 0x10,), (va, 0x20), (va + 4, None, True), (None, None, True)]:
            assert mine.get_data(*args) == ref.get_data(*args), (mine.Name, args)
        assert mine.get_entropy() == pytest.approx(ref.get_entropy(), abs=1e-9), mine.Name
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            method = f"get_hash_{algorithm}"
            assert getattr(mine, method)() == getattr(ref, method)(), (mine.Name, algorithm)


def test_section_contains(pair):
    ours, theirs = pair
    for mine, ref in zip(ours.sections, theirs.sections):
        for rva in probe_rvas(theirs):
            assert mine.contains_rva(rva) == ref.contains_rva(rva), (mine.Name, hex(rva))
        for offset in probe_offsets(theirs):
            assert mine.contains_offset(offset) == ref.contains_offset(offset), (mine.Name, hex(offset))


@pytest.mark.parametrize("value", [2**64, 2**70, -(2**64)])
def test_addresses_beyond_64_bits_follow_pefile(pair, value):
    ours, theirs = pair
    for method in ("get_data", "get_offset_from_rva", "get_rva_from_offset"):
        mine, ref = outcome(getattr(ours, method), value), outcome(getattr(theirs, method), value)
        assert mine == ref, method
    assert ours.get_data(0x40, value) == theirs.get_data(0x40, value)
    for method in ("get_section_by_rva", "get_section_by_offset"):
        assert getattr(ours, method)(value) is getattr(theirs, method)(value) is None, method
    for mine, ref in zip(ours.sections, theirs.sections):
        assert mine.get_data(value) == ref.get_data(value), mine.Name
        va = ref.VirtualAddress
        assert mine.get_data(va, value) == ref.get_data(va, value), mine.Name
        for method in ("contains_rva", "contains", "contains_offset"):
            assert getattr(mine, method)(value) == getattr(ref, method)(value), (mine.Name, method)
        for method in ("get_offset_from_rva", "get_rva_from_offset"):
            assert getattr(mine, method)(value) == getattr(ref, method)(value), (mine.Name, method)


@pytest.mark.parametrize("rva, length", [(-5, 10), (-5, None), (-16, 8), (-1, 1)])
def test_negative_rvas_slice_the_header_like_pefile(pair, rva, length):
    ours, theirs = pair
    assert ours.get_data(rva, length) == theirs.get_data(rva, length)


def test_overlay(pair):
    ours, theirs = pair
    assert ours.get_overlay_data_start_offset() == theirs.get_overlay_data_start_offset()
    assert ours.get_overlay() == theirs.get_overlay()


def test_appended_data_is_overlay():
    data = CORPUS[0].read_bytes() + b"appended overlay"
    ours, theirs = peoxide.PE(data=data), pefile.PE(data=data)
    assert ours.get_overlay() == theirs.get_overlay()
    assert ours.get_overlay().endswith(b"appended overlay")


def test_imphash_and_exphash(pair):
    ours, theirs = pair
    assert ours.get_imphash() == theirs.get_imphash()
    assert ours.get_exphash() == theirs.get_exphash()


def test_hash_algorithm_is_selectable():
    pe = peoxide.PE(str(CORPUS[0]))
    assert len(pe.get_imphash("sha256")) == 64
    assert pe.get_imphash("sha256") != pe.get_imphash()
    assert len(pe.get_exphash("sha256")) == 64
    with pytest.raises(ValueError):
        pe.get_imphash("not-a-hash")


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


def import_entries(entries):
    return [
        (
            d.dll,
            [
                (None if i.import_by_ordinal else i.name, i.ordinal, i.hint, i.address)
                for i in d.imports
            ],
        )
        for d in entries
    ]


def test_delay_imports(pair):
    ours, theirs = pair
    expected = getattr(theirs, "DIRECTORY_ENTRY_DELAY_IMPORT", [])
    assert import_entries(ours.DIRECTORY_ENTRY_DELAY_IMPORT) == import_entries(expected)


def test_corpus_has_delay_imports():
    assert any(peoxide.PE(str(p)).DIRECTORY_ENTRY_DELAY_IMPORT for p in CORPUS)


@pytest.mark.parametrize("name", ["shared_thunks.dll", "shared_delay_thunks.dll"])
def test_import_symbol_cap_matches_pefile(name):
    path = str(Path(__file__).parent / "fixtures" / "crafted" / name)
    ours, theirs = peoxide.PE(path), pefile.PE(path)
    for directory in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        expected = getattr(theirs, directory, [])
        assert import_entries(getattr(ours, directory)) == import_entries(expected)


DEBUG_FIELDS = [
    "Characteristics",
    "TimeDateStamp",
    "MajorVersion",
    "MinorVersion",
    "Type",
    "SizeOfData",
    "AddressOfRawData",
    "PointerToRawData",
]
DEBUG_ENTRY_FIELDS = {
    "CvInfoPdb70": [
        "CvSignature",
        "Signature_Data1",
        "Signature_Data2",
        "Signature_Data3",
        "Signature_Data4",
        "Signature_Data5",
        "Signature_Data6",
        "Signature_Data6_value",
        "Signature_String",
        "Age",
        "PdbFileName",
    ],
    "CvInfoPdb20": ["CvHeaderSignature", "CvHeaderOffset", "Signature", "Age", "PdbFileName"],
    "ExDllCharacteristics": ["ExDllCharacteristics", "IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT"],
}


def debug_entries(pe):
    entries = []
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        struct = [getattr(d.struct, f) for f in DEBUG_FIELDS]
        kind = next((k for k, fields in DEBUG_ENTRY_FIELDS.items() if hasattr(d.entry, fields[0])), None)
        values = [getattr(d.entry, f, None) for f in DEBUG_ENTRY_FIELDS[kind]] if kind else None
        entries.append((struct, kind, values))
    return entries


def test_debug_directory(pair):
    ours, theirs = pair
    assert debug_entries(ours) == debug_entries(theirs)


def test_corpus_has_codeview_records():
    kinds = {kind for p in CORPUS for _, kind, _ in debug_entries(peoxide.PE(str(p)))}
    assert "CvInfoPdb70" in kinds


RICH_FIELDS = ["checksum", "values", "key", "raw_data", "clear_data"]


def rich_header(pe):
    rich = getattr(pe, "RICH_HEADER", None)
    return rich and [getattr(rich, f) for f in RICH_FIELDS]


def test_rich_header(pair):
    ours, theirs = pair
    assert rich_header(ours) == rich_header(theirs)
    for algorithm in ("md5", "sha256"):
        assert ours.get_rich_header_hash(algorithm) == theirs.get_rich_header_hash(algorithm)


def test_corpus_has_rich_headers():
    assert any(peoxide.PE(str(p)).RICH_HEADER for p in CORPUS)


MISSING = "missing"
RELOCATION_ENTRY_FIELDS = [
    "Data",
    "PageRelativeOffset",
    "IndirectCall",
    "IATIndex",
    "RexWPrefix",
    "CfgCheck",
    "Reserved",
    "RegisterNumber",
]


def fields(struct, names):
    return [getattr(struct, name, MISSING) for name in names]


def relocation_blocks(blocks):
    return [
        (
            b.struct.VirtualAddress,
            b.struct.SizeOfBlock,
            [
                (getattr(e, "type", MISSING), e.rva, e.base_rva, fields(e.struct, RELOCATION_ENTRY_FIELDS))
                for e in b.entries
            ],
        )
        for b in blocks
    ]


def relocations(pe):
    return relocation_blocks(getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []))


def test_relocations(pair):
    ours, theirs = pair
    assert relocations(ours) == relocations(theirs)


def test_corpus_has_relocations():
    assert any(peoxide.PE(str(p)).DIRECTORY_ENTRY_BASERELOC for p in CORPUS)


MISSING = "missing"
UNWIND_FIELDS = [
    "Version",
    "Flags",
    "SizeOfProlog",
    "CountOfCodes",
    "FrameRegister",
    "FrameOffset",
    "UNW_FLAG_EHANDLER",
    "UNW_FLAG_UHANDLER",
    "UNW_FLAG_CHAININFO",
]
# pefile sets these only on some records.
OPTIONAL_UNWIND_FIELDS = ["ExceptionHandler", "FunctionEntry", "SizeOfEpilog"]
CODE_METHODS = ["get_offset", "get_alloc_size"]


def unwind_code(code, reference):
    """A code's class, text, methods and every `.struct` field pefile's matching code has."""
    names = [name for names in reference.struct.__keys_ext__ for name in names]
    return (
        type(code).__name__,
        str(code),
        code.is_valid(),
        [getattr(code, m)() if hasattr(code, m) else MISSING for m in CODE_METHODS],
        [getattr(code.struct, name, MISSING) for name in names],
    )


def exception_entries(pe, reference):
    """Every entry, with sharing and chaining as indexes into the list. Field names come from
    `reference`, the pefile.PE of the same file."""
    entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
    references = getattr(reference, "DIRECTORY_ENTRY_EXCEPTION", [])
    index = {id(e): i for i, e in enumerate(entries)}
    first_user = {}
    rows = []
    for i, (entry, ref) in enumerate(zip(entries, references)):
        info = entry.unwindinfo
        row = [entry.struct.BeginAddress, entry.struct.EndAddress, entry.struct.UnwindData]
        if info is not None:
            chained = info.get_chained_function_entry()
            codes = getattr(info, "UnwindCodes", None)
            row += [
                first_user.setdefault(id(info), i),
                [getattr(info, f) for f in UNWIND_FIELDS],
                [getattr(info, f, MISSING) for f in OPTIONAL_UNWIND_FIELDS],
                # A KeyError here means the chained entry is not the list's own object.
                None if chained is None else index[id(chained)],
                None
                if codes is None
                else [len(codes)]
                + [unwind_code(c, r) for c, r in zip(codes, ref.unwindinfo.UnwindCodes)],
            ]
        rows.append(row)
    return len(entries), rows


def test_exceptions(pair):
    ours, theirs = pair
    assert exception_entries(ours, theirs) == exception_entries(theirs, theirs)


def test_corpus_has_exception_entries():
    pes = [peoxide.PE(str(p)) for p in CORPUS]
    entries = [e for pe in pes for e in pe.DIRECTORY_ENTRY_EXCEPTION]
    assert entries
    assert any(hasattr(e.unwindinfo, "FunctionEntry") for e in entries)
    assert any(e.unwindinfo is None for e in entries)
    kinds = {type(c).__name__ for e in entries if e.unwindinfo for c in e.unwindinfo.UnwindCodes}
    assert len(kinds) == 10, kinds


def test_x86_files_have_no_exception_entries():
    x86 = [p for p in CORPUS if pefile.PE(str(p), fast_load=True).FILE_HEADER.Machine == 0x14C]
    assert x86
    assert all(peoxide.PE(str(p)).DIRECTORY_ENTRY_EXCEPTION == [] for p in x86)


def test_crafted_exceptions_match_pefile():
    path = str(Path(__file__).parent / "fixtures" / "crafted" / "exceptions.dll")
    ours, theirs = peoxide.PE(path), pefile.PE(path)
    assert exception_entries(ours, theirs) == exception_entries(theirs, theirs)
    assert len(ours.DIRECTORY_ENTRY_EXCEPTION) == 5


def test_entries_share_and_chain_the_same_objects():
    pe = peoxide.PE(str(Path(__file__).parent / "fixtures" / "exceptions64.dll"))
    entries = pe.DIRECTORY_ENTRY_EXCEPTION
    assert entries is pe.DIRECTORY_ENTRY_EXCEPTION
    assert entries[0].unwindinfo is entries[1].unwindinfo
    assert entries[8].unwindinfo.get_chained_function_entry() is entries[7]
BOUND_FIELDS = ["TimeDateStamp", "OffsetModuleName", "NumberOfModuleForwarderRefs"]
BOUND_REF_FIELDS = ["TimeDateStamp", "OffsetModuleName", "Reserved"]


def bound_imports(pe):
    return [
        (
            [getattr(d.struct, f) for f in BOUND_FIELDS],
            d.name,
            [([getattr(r.struct, f) for f in BOUND_REF_FIELDS], r.name) for r in d.entries],
        )
        for d in getattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT", [])
    ]


def test_bound_imports(pair):
    ours, theirs = pair
    assert bound_imports(ours) == bound_imports(theirs)


def test_corpus_has_bound_imports():
    assert any(
        d.entries for p in CORPUS for d in peoxide.PE(str(p)).DIRECTORY_ENTRY_BOUND_IMPORT
    )


@pytest.mark.parametrize(
    "name",
    ["bound_huge_count.dll", "bound_bad_names.dll", "bound_name_outside.dll", "bound_truncated.dll", "bound_in_section.dll"],
)
def test_malformed_bound_imports_match_pefile(name):
    path = str(Path(__file__).parent / "fixtures" / "crafted" / name)
    assert bound_imports(peoxide.PE(path)) == bound_imports(pefile.PE(path))


def test_bound_imports_need_fourteen_directories_like_pefile():
    # pefile reaches the delay-import directory (13) first and stops when it is missing.
    data = bytearray((Path(__file__).parent / "fixtures" / "bound_imports.dll").read_bytes())
    count = peoxide.PE(data=bytes(data)).DOS_HEADER.e_lfanew + 24 + 108
    data[count : count + 4] = (13).to_bytes(4, "little")
    ours, theirs = peoxide.PE(data=bytes(data)), pefile.PE(data=bytes(data))
    assert len(ours.OPTIONAL_HEADER.DATA_DIRECTORY) == len(theirs.OPTIONAL_HEADER.DATA_DIRECTORY) == 13
    assert ours.DIRECTORY_ENTRY_BOUND_IMPORT == bound_imports(theirs) == []
TLS_FIELDS = [
    "StartAddressOfRawData",
    "EndAddressOfRawData",
    "AddressOfIndex",
    "AddressOfCallBacks",
    "SizeOfZeroFill",
    "Characteristics",
]


def tls(pe):
    entry = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    return entry and [getattr(entry.struct, f) for f in TLS_FIELDS]


def test_tls(pair):
    ours, theirs = pair
    assert tls(ours) == tls(theirs)


def test_corpus_has_tls():
    system = [peoxide.PE(str(p)) for p in SYSTEM]
    assert {pe.OPTIONAL_HEADER.Magic for pe in system if tls(pe)} == {0x10B, 0x20B}


@pytest.mark.parametrize("name", ["tls_size_zero.dll", "tls_outside_sections.dll"])
def test_crafted_tls_matches_pefile(name):
    path = str(Path(__file__).parent / "fixtures" / "crafted" / name)
    assert tls(peoxide.PE(path)) == tls(pefile.PE(path))
    assert tls(peoxide.PE(path))


RESOURCE_DIR_FIELDS = ["Characteristics", "TimeDateStamp", "MajorVersion", "MinorVersion", "NumberOfNamedEntries", "NumberOfIdEntries"]
RESOURCE_ENTRY_FIELDS = ["Name", "OffsetToData", "NameOffset", "Id", "DataIsDirectory", "OffsetToDirectory"]
RESOURCE_DATA_FIELDS = ["OffsetToData", "Size", "CodePage", "Reserved"]


def resource_tree(directory):
    if directory is None:
        return None
    entries = []
    for e in directory.entries:
        child = (
            resource_tree(e.directory)
            if hasattr(e, "directory")
            else ([getattr(e.data.struct, f) for f in RESOURCE_DATA_FIELDS], e.data.lang, e.data.sublang)
        )
        name = e.name and (e.name.string, str(e.name))
        entries.append(([getattr(e.struct, f) for f in RESOURCE_ENTRY_FIELDS], name, e.id, child))
    strings = list(directory.strings.items()) if hasattr(directory, "strings") else None
    return [getattr(directory.struct, f) for f in RESOURCE_DIR_FIELDS], entries, strings


def test_resources(pair):
    ours, theirs = pair
    assert resource_tree(ours.DIRECTORY_ENTRY_RESOURCE) == resource_tree(
        getattr(theirs, "DIRECTORY_ENTRY_RESOURCE", None)
    )


def test_corpus_has_string_tables():
    def has_strings(directory):
        return hasattr(directory, "strings") and bool(directory.strings) or any(
            has_strings(e.directory) for e in directory.entries if hasattr(e, "directory")
        )

    assert any(has_strings(peoxide.PE(str(p)).DIRECTORY_ENTRY_RESOURCE) for p in CORPUS)


def test_self_referencing_resource_directory_stops_like_pefile():
    data = bytearray(CORPUS[0].read_bytes())
    pe = peoxide.PE(data=bytes(data))
    first_entry = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress + 16)
    data[first_entry + 4 : first_entry + 8] = (0x80000000).to_bytes(4, "little")
    ours, theirs = peoxide.PE(data=bytes(data)), pefile.PE(data=bytes(data))
    assert ours.DIRECTORY_ENTRY_RESOURCE.entries == []
    assert resource_tree(ours.DIRECTORY_ENTRY_RESOURCE) == resource_tree(theirs.DIRECTORY_ENTRY_RESOURCE)


def test_resource_entries_have_directory_or_data():
    root = peoxide.PE(str(CORPUS[0])).DIRECTORY_ENTRY_RESOURCE
    entry = root.entries[0]
    assert hasattr(entry, "directory") and not hasattr(entry, "data")
    leaf = entry.directory.entries[0].directory.entries[0]
    assert hasattr(leaf, "data") and not hasattr(leaf, "directory")


VERSION_HEADER_FIELDS = ["Length", "ValueLength", "Type"]
FIXED_FILE_INFO_FIELDS = [
    "Signature", "StrucVersion", "FileVersionMS", "FileVersionLS", "ProductVersionMS",
    "ProductVersionLS", "FileFlagsMask", "FileFlags", "FileOS", "FileType", "FileSubtype",
    "FileDateMS", "FileDateLS",
]


def version_info(pe):
    """Every version field peoxide exposes; None for an attribute the object lacks."""

    def fields(s, names):
        return [getattr(s, f) for f in names]

    def each(obj, attr, convert):
        return [convert(item) for item in getattr(obj, attr)] if hasattr(obj, attr) else None

    def table(t):
        return fields(t, VERSION_HEADER_FIELDS), t.LangID, list(t.entries.items())

    def var(v):
        return fields(v, VERSION_HEADER_FIELDS), getattr(v, "entry", None)

    def block(b):
        return fields(b, VERSION_HEADER_FIELDS), b.Key, each(b, "StringTable", table), each(b, "Var", var)

    return (
        each(pe, "VS_VERSIONINFO", lambda v: fields(v, VERSION_HEADER_FIELDS + ["Key"])),
        each(pe, "VS_FIXEDFILEINFO", lambda f: fields(f, FIXED_FILE_INFO_FIELDS)),
        each(pe, "FileInfo", lambda blocks: [block(b) for b in blocks]),
    )


def test_version_info(pair):
    ours, theirs = pair
    assert version_info(ours) == version_info(theirs)


def test_corpus_has_version_strings_and_vars():
    infos = [getattr(peoxide.PE(str(p)), "FileInfo", []) for p in CORPUS]
    blocks = [b for info in infos for blocks in info for b in blocks]
    assert any(t.entries for b in blocks if hasattr(b, "StringTable") for t in b.StringTable)
    assert any(hasattr(v, "entry") for b in blocks if hasattr(b, "Var") for v in b.Var)


def test_missing_version_info_raises_like_pefile():
    data = bytearray(CORPUS[0].read_bytes())
    pe = peoxide.PE(data=bytes(data))
    version = next(e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == 16)
    leaf = version.directory.entries[0].directory.entries[0].data.struct
    key = pe.get_offset_from_rva(leaf.OffsetToData) + 6  # past Length, ValueLength, Type
    assert data[key : key + 30] == "VS_VERSION_INFO".encode("utf-16-le")
    data[key] = ord("X")
    ours, theirs = peoxide.PE(data=bytes(data)), pefile.PE(data=bytes(data))
    for attr in ["VS_VERSIONINFO", "VS_FIXEDFILEINFO", "FileInfo"]:
        assert not hasattr(theirs, attr)
        with pytest.raises(AttributeError):
            getattr(ours, attr)


def test_exports(pair):
    ours, theirs = pair
    export_dir = getattr(theirs, "DIRECTORY_ENTRY_EXPORT", None)
    expected = export_dir.symbols if export_dir else []

    def key(s):
        return (s.name, s.ordinal, s.address, s.forwarder)

    assert [key(s) for s in ours.DIRECTORY_ENTRY_EXPORT.symbols] == [key(s) for s in expected]


LOAD_CONFIG_FIELDS = [f.split(",")[1] for f in pefile.PE.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__[1]]


def dynamic_relocation(d):
    header = (d.struct.Symbol, d.struct.BaseRelocSize, d.symbol)
    if not hasattr(d, "func_relocs"):
        return header, relocation_blocks(d.relocations)
    functions = [
        (
            fields(f.struct, ["OriginalRva", "BDDOffset", "RvaSize", "BaseRelocSize"]),
            f.func_rva,
            f.override_rvas,
            relocation_blocks(f.relocations),
        )
        for f in d.func_relocs
    ]
    return header, functions, [fields(b.struct, ["Left", "Right", "Value"]) for b in d.bdd_relocs]


def load_config(pe):
    """The structure's fields, `MISSING` where it stops short, and its dynamic relocations."""
    config = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if config is None:
        return None
    dynamic = config.dynamic_relocations
    return fields(config.struct, LOAD_CONFIG_FIELDS), dynamic and [dynamic_relocation(d) for d in dynamic]


def test_load_config(pair):
    ours, theirs = pair
    assert load_config(ours) == load_config(theirs)


def dynamic_symbols(pe):
    config = pe.DIRECTORY_ENTRY_LOAD_CONFIG
    return {d.symbol for d in (config and config.dynamic_relocations or [])}


def test_corpus_has_load_config():
    configs = [load_config(peoxide.PE(str(p))) for p in CORPUS]
    assert any(c and MISSING not in c[0] for c in configs)


def test_corpus_has_dynamic_relocations():
    symbols = set().union(*(dynamic_symbols(peoxide.PE(str(p))) for p in CORPUS))
    assert {3, 4, 5, 6, 7} <= symbols and max(symbols) > 2**32


KERNEL_IMAGES = [WINDIR / "System32" / name for name in ("ntoskrnl.exe", "win32kfull.sys")]


@pytest.mark.parametrize("path", [p for p in KERNEL_IMAGES if p.exists()], ids=lambda p: p.name)
def test_kernel_dynamic_relocations(path):
    """Kernel images hold the most dynamic relocations, often in the bitfield formats."""
    theirs = pefile.PE(str(path), fast_load=True)
    theirs.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]])
    ours = peoxide.PE(str(path))
    assert dynamic_symbols(ours)
    assert load_config(ours) == load_config(theirs)


CRAFTED = Path(__file__).parent / "fixtures" / "crafted"


@pytest.mark.parametrize(
    "name",
    ["load_config_short_size.dll", "load_config_odd_size.dll", "load_config_long_table.dll"],
)
def test_crafted_load_config_matches_pefile(name):
    path = str(CRAFTED / name)
    assert load_config(peoxide.PE(path)) == load_config(pefile.PE(path))
