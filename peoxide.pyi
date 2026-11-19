"""Type stubs for peoxide. Classes with a leading underscore are not importable from
peoxide; they name the types of PE's attributes."""

import os
from collections.abc import Iterable
from types import TracebackType
from typing import Any, final

from typing_extensions import Self

__all__ = ["PE", "PEFormatError"]

class PEFormatError(Exception): ...

@final
class _DosHeader:
    e_magic: int
    e_cblp: int
    e_cp: int
    e_crlc: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_csum: int
    e_ip: int
    e_cs: int
    e_lfarlc: int
    e_ovno: int
    e_res: bytes
    e_oemid: int
    e_oeminfo: int
    e_res2: bytes
    e_lfanew: int

@final
class _NtHeaders:
    Signature: int

@final
class _FileHeader:
    Machine: int
    NumberOfSections: int
    TimeDateStamp: int
    PointerToSymbolTable: int
    NumberOfSymbols: int
    SizeOfOptionalHeader: int
    Characteristics: int
    IMAGE_FILE_RELOCS_STRIPPED: bool
    IMAGE_FILE_EXECUTABLE_IMAGE: bool
    IMAGE_FILE_LINE_NUMS_STRIPPED: bool
    IMAGE_FILE_LOCAL_SYMS_STRIPPED: bool
    IMAGE_FILE_AGGRESIVE_WS_TRIM: bool
    IMAGE_FILE_LARGE_ADDRESS_AWARE: bool
    IMAGE_FILE_16BIT_MACHINE: bool
    IMAGE_FILE_BYTES_REVERSED_LO: bool
    IMAGE_FILE_32BIT_MACHINE: bool
    IMAGE_FILE_DEBUG_STRIPPED: bool
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: bool
    IMAGE_FILE_NET_RUN_FROM_SWAP: bool
    IMAGE_FILE_SYSTEM: bool
    IMAGE_FILE_DLL: bool
    IMAGE_FILE_UP_SYSTEM_ONLY: bool
    IMAGE_FILE_BYTES_REVERSED_HI: bool

@final
class _DataDirectory:
    name: str
    VirtualAddress: int
    Size: int

@final
class _OptionalHeader:
    Magic: int
    MajorLinkerVersion: int
    MinorLinkerVersion: int
    SizeOfCode: int
    SizeOfInitializedData: int
    SizeOfUninitializedData: int
    AddressOfEntryPoint: int
    BaseOfCode: int
    BaseOfData: int | None
    ImageBase: int
    SectionAlignment: int
    FileAlignment: int
    MajorOperatingSystemVersion: int
    MinorOperatingSystemVersion: int
    MajorImageVersion: int
    MinorImageVersion: int
    MajorSubsystemVersion: int
    MinorSubsystemVersion: int
    Reserved1: int
    SizeOfImage: int
    SizeOfHeaders: int
    CheckSum: int
    Subsystem: int
    DllCharacteristics: int
    SizeOfStackReserve: int
    SizeOfStackCommit: int
    SizeOfHeapReserve: int
    SizeOfHeapCommit: int
    LoaderFlags: int
    NumberOfRvaAndSizes: int
    DATA_DIRECTORY: list[_DataDirectory]
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: bool
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: bool
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: bool
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT: bool
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: bool
    IMAGE_DLLCHARACTERISTICS_NO_SEH: bool
    IMAGE_DLLCHARACTERISTICS_NO_BIND: bool
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER: bool
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: bool
    IMAGE_DLLCHARACTERISTICS_GUARD_CF: bool
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: bool

@final
class _Section:
    Name: bytes
    Misc_VirtualSize: int
    VirtualAddress: int
    SizeOfRawData: int
    PointerToRawData: int
    PointerToRelocations: int
    PointerToLinenumbers: int
    NumberOfRelocations: int
    NumberOfLinenumbers: int
    Characteristics: int
    IMAGE_SCN_TYPE_REG: bool
    IMAGE_SCN_TYPE_DSECT: bool
    IMAGE_SCN_TYPE_NOLOAD: bool
    IMAGE_SCN_TYPE_GROUP: bool
    IMAGE_SCN_TYPE_NO_PAD: bool
    IMAGE_SCN_TYPE_COPY: bool
    IMAGE_SCN_CNT_CODE: bool
    IMAGE_SCN_CNT_INITIALIZED_DATA: bool
    IMAGE_SCN_CNT_UNINITIALIZED_DATA: bool
    IMAGE_SCN_LNK_OTHER: bool
    IMAGE_SCN_LNK_INFO: bool
    IMAGE_SCN_LNK_OVER: bool
    IMAGE_SCN_LNK_REMOVE: bool
    IMAGE_SCN_LNK_COMDAT: bool
    IMAGE_SCN_MEM_PROTECTED: bool
    IMAGE_SCN_NO_DEFER_SPEC_EXC: bool
    IMAGE_SCN_GPREL: bool
    IMAGE_SCN_MEM_FARDATA: bool
    IMAGE_SCN_MEM_SYSHEAP: bool
    IMAGE_SCN_MEM_PURGEABLE: bool
    IMAGE_SCN_MEM_16BIT: bool
    IMAGE_SCN_MEM_LOCKED: bool
    IMAGE_SCN_MEM_PRELOAD: bool
    IMAGE_SCN_ALIGN_1BYTES: bool
    IMAGE_SCN_ALIGN_2BYTES: bool
    IMAGE_SCN_ALIGN_4BYTES: bool
    IMAGE_SCN_ALIGN_8BYTES: bool
    IMAGE_SCN_ALIGN_16BYTES: bool
    IMAGE_SCN_ALIGN_32BYTES: bool
    IMAGE_SCN_ALIGN_64BYTES: bool
    IMAGE_SCN_ALIGN_128BYTES: bool
    IMAGE_SCN_ALIGN_256BYTES: bool
    IMAGE_SCN_ALIGN_512BYTES: bool
    IMAGE_SCN_ALIGN_1024BYTES: bool
    IMAGE_SCN_ALIGN_2048BYTES: bool
    IMAGE_SCN_ALIGN_4096BYTES: bool
    IMAGE_SCN_ALIGN_8192BYTES: bool
    IMAGE_SCN_ALIGN_MASK: bool
    IMAGE_SCN_LNK_NRELOC_OVFL: bool
    IMAGE_SCN_MEM_DISCARDABLE: bool
    IMAGE_SCN_MEM_NOT_CACHED: bool
    IMAGE_SCN_MEM_NOT_PAGED: bool
    IMAGE_SCN_MEM_SHARED: bool
    IMAGE_SCN_MEM_EXECUTE: bool
    IMAGE_SCN_MEM_READ: bool
    IMAGE_SCN_MEM_WRITE: bool
    def get_data(
        self, start: int | None = None, length: int | None = None, ignore_padding: bool = False
    ) -> bytes: ...
    def get_entropy(self) -> float: ...
    def get_hash_md5(self) -> str: ...
    def get_hash_sha1(self) -> str: ...
    def get_hash_sha256(self) -> str: ...
    def get_hash_sha512(self) -> str: ...
    def contains_rva(self, rva: int) -> bool: ...
    def contains(self, rva: int) -> bool: ...
    def contains_offset(self, offset: int) -> bool: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    def get_rva_from_offset(self, offset: int) -> int: ...

@final
class _ImportData:
    name: bytes | None
    hint: int | None
    ordinal: int | None
    import_by_ordinal: bool
    address: int

@final
class _ImportDescData:
    dll: bytes
    imports: list[_ImportData]

@final
class _ExportData:
    name: bytes | None
    ordinal: int
    address: int
    forwarder: bytes | None

@final
class _ExportDirData:
    symbols: list[_ExportData]

@final
class _DebugDirectory:
    Characteristics: int
    TimeDateStamp: int
    MajorVersion: int
    MinorVersion: int
    Type: int
    SizeOfData: int
    AddressOfRawData: int
    PointerToRawData: int

@final
class _CvInfoPdb70:
    CvSignature: bytes
    Signature_Data1: int
    Signature_Data2: int
    Signature_Data3: int
    Signature_Data4: int
    Signature_Data5: int
    Signature_Data6: bytes
    Signature_Data6_value: int
    Signature_String: str
    Age: int
    PdbFileName: bytes

@final
class _ExDllCharacteristics:
    ExDllCharacteristics: int
    IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT: bool
    IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE: bool
    IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE: bool
    IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC: bool
    IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1: bool
    IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2: bool

@final
class _DebugData:
    struct: _DebugDirectory
    entry: _CvInfoPdb70 | _ExDllCharacteristics | None

@final
class _RichHeader:
    checksum: int
    values: list[int]
    key: bytes
    raw_data: bytes
    clear_data: bytes

@final
class _TlsDirectory:
    StartAddressOfRawData: int
    EndAddressOfRawData: int
    AddressOfIndex: int
    AddressOfCallBacks: int
    SizeOfZeroFill: int
    Characteristics: int

@final
class _TlsData:
    struct: _TlsDirectory

@final
class _BaseRelocation:
    VirtualAddress: int
    SizeOfBlock: int

@final
class _RelocationData:
    type: int
    rva: int
    base_rva: int

@final
class _BaseRelocationData:
    struct: _BaseRelocation
    entries: list[_RelocationData]

@final
class _BoundImportDescriptor:
    TimeDateStamp: int
    OffsetModuleName: int
    NumberOfModuleForwarderRefs: int

@final
class _BoundForwarderRef:
    TimeDateStamp: int
    OffsetModuleName: int
    Reserved: int

@final
class _BoundImportRefData:
    struct: _BoundForwarderRef
    name: bytes

@final
class _BoundImportDescData:
    struct: _BoundImportDescriptor
    name: bytes
    entries: list[_BoundImportRefData]

@final
class _ResourceDirectoryStruct:
    Characteristics: int
    TimeDateStamp: int
    MajorVersion: int
    MinorVersion: int
    NumberOfNamedEntries: int
    NumberOfIdEntries: int

@final
class _ResourceEntryStruct:
    Name: int
    OffsetToData: int
    NameOffset: int
    Id: int
    DataIsDirectory: int
    OffsetToDirectory: int

@final
class _ResourceDataStruct:
    OffsetToData: int
    Size: int
    CodePage: int
    Reserved: int

@final
class _ResourceName:
    string: bytes | None
    def decode(self, *args: Any) -> str: ...

@final
class _ResourceDataEntryData:
    struct: _ResourceDataStruct
    lang: int
    sublang: int

@final
class _ResourceDirEntryData:
    struct: _ResourceEntryStruct
    id: int | None
    name: _ResourceName | None
    # Exactly one of these is set; the other raises AttributeError.
    directory: _ResourceDirData
    data: _ResourceDataEntryData

@final
class _ResourceDirData:
    struct: _ResourceDirectoryStruct
    entries: list[_ResourceDirEntryData]
    # Only on RT_STRING directories; elsewhere it raises AttributeError.
    strings: dict[int, str]

@final
class _VersionInfoStruct:
    Length: int
    ValueLength: int
    Type: int
    Key: bytes

@final
class _FixedFileInfoStruct:
    Signature: int
    StrucVersion: int
    FileVersionMS: int
    FileVersionLS: int
    ProductVersionMS: int
    ProductVersionLS: int
    FileFlagsMask: int
    FileFlags: int
    FileOS: int
    FileType: int
    FileSubtype: int
    FileDateMS: int
    FileDateLS: int

@final
class _StringTableStruct:
    Length: int
    ValueLength: int
    Type: int
    LangID: bytes
    entries: dict[bytes, bytes]

@final
class _VarStruct:
    Length: int
    ValueLength: int
    Type: int
    entry: dict[bytes, str]

@final
class _FileInfoStruct:
    Length: int
    ValueLength: int
    Type: int
    Key: bytes
    # StringFileInfo has StringTable and VarFileInfo has Var; the other raises AttributeError.
    StringTable: list[_StringTableStruct]
    Var: list[_VarStruct]

@final
class PE:
    """A parsed PE file. Everything is parsed once, up front, in Rust."""

    DOS_HEADER: _DosHeader
    NT_HEADERS: _NtHeaders
    FILE_HEADER: _FileHeader
    OPTIONAL_HEADER: _OptionalHeader
    sections: list[_Section]
    DIRECTORY_ENTRY_DEBUG: list[_DebugData]
    RICH_HEADER: _RichHeader | None
    DIRECTORY_ENTRY_TLS: _TlsData | None
    def __new__(
        cls,
        name: str | os.PathLike[str] | None = None,
        data: bytes | bytearray | memoryview | None = None,
        fast_load: object = None,
    ) -> Self: ...
    @property
    def DIRECTORY_ENTRY_IMPORT(self) -> list[_ImportDescData]: ...
    @property
    def DIRECTORY_ENTRY_EXPORT(self) -> _ExportDirData: ...
    @property
    def DIRECTORY_ENTRY_DELAY_IMPORT(self) -> list[_ImportDescData]: ...
    @property
    def DIRECTORY_ENTRY_BASERELOC(self) -> list[_BaseRelocationData]: ...
    @property
    def DIRECTORY_ENTRY_BOUND_IMPORT(self) -> list[_BoundImportDescData]: ...
    @property
    def DIRECTORY_ENTRY_RESOURCE(self) -> _ResourceDirData | None: ...
    # The version attributes raise AttributeError when the file has no version information.
    @property
    def VS_VERSIONINFO(self) -> list[_VersionInfoStruct]: ...
    @property
    def VS_FIXEDFILEINFO(self) -> list[_FixedFileInfoStruct]: ...
    @property
    def FileInfo(self) -> list[list[_FileInfoStruct]]: ...
    @property
    def __data__(self) -> bytes: ...
    def get_data(self, rva: int = 0, length: int | None = None) -> bytes: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    def get_rva_from_offset(self, offset: int) -> int | None: ...
    def get_section_by_rva(self, rva: int) -> _Section | None: ...
    def get_section_by_offset(self, offset: int) -> _Section | None: ...
    def get_overlay_data_start_offset(self) -> int | None: ...
    def get_overlay(self) -> bytes | None: ...
    def get_imphash(self, algorithm: str = "md5") -> str: ...
    def get_exphash(self, algorithm: str = "md5") -> str: ...
    def get_rich_header_hash(self, algorithm: str = "md5") -> str: ...
    def parse_data_directories(
        self,
        directories: Iterable[int] | None = None,
        forwarded_exports_only: object = None,
        import_dllnames_only: object = None,
    ) -> None: ...
    def full_load(self) -> None: ...
    def close(self) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
    def get_word_at_rva(self, rva: int) -> int | None: ...
    def get_dword_at_rva(self, rva: int) -> int | None: ...
    def get_qword_at_rva(self, rva: int) -> int | None: ...
    def get_word_from_offset(self, offset: int) -> int | None: ...
    def get_dword_from_offset(self, offset: int) -> int | None: ...
    def get_qword_from_offset(self, offset: int) -> int | None: ...
    def get_string_at_rva(self, rva: int | None, max_length: int | None = None) -> bytes | None: ...
    def generate_checksum(self) -> int: ...
    def verify_checksum(self) -> bool: ...
    def is_exe(self) -> bool: ...
    def is_dll(self) -> bool: ...
    def is_driver(self) -> bool: ...
