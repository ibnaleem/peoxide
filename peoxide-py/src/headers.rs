use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use crate::{bytes, list};

py_class!(DosHeader from peoxide_core::DosHeader as (py, c) {
    e_magic: u16 = c.e_magic,
    e_cblp: u16 = c.e_cblp,
    e_cp: u16 = c.e_cp,
    e_crlc: u16 = c.e_crlc,
    e_cparhdr: u16 = c.e_cparhdr,
    e_minalloc: u16 = c.e_minalloc,
    e_maxalloc: u16 = c.e_maxalloc,
    e_ss: u16 = c.e_ss,
    e_sp: u16 = c.e_sp,
    e_csum: u16 = c.e_csum,
    e_ip: u16 = c.e_ip,
    e_cs: u16 = c.e_cs,
    e_lfarlc: u16 = c.e_lfarlc,
    e_ovno: u16 = c.e_ovno,
    e_res: Py<PyBytes> = bytes(py, &c.e_res),
    e_oemid: u16 = c.e_oemid,
    e_oeminfo: u16 = c.e_oeminfo,
    e_res2: Py<PyBytes> = bytes(py, &c.e_res2),
    e_lfanew: u32 = c.e_lfanew,
});

py_class!(NtHeaders from peoxide_core::Headers as (py, c) {
    Signature: u32 = c.signature,
});

py_class!(FileHeader [dict] from peoxide_core::FileHeader as (py, c) {
    Machine: u16 = c.machine,
    NumberOfSections: u16 = c.number_of_sections,
    TimeDateStamp: u32 = c.time_date_stamp,
    PointerToSymbolTable: u32 = c.pointer_to_symbol_table,
    NumberOfSymbols: u32 = c.number_of_symbols,
    SizeOfOptionalHeader: u16 = c.size_of_optional_header,
    Characteristics: u16 = c.characteristics,
});

const DIRECTORY_NAMES: [&str; 16] = [
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_TLS",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
    "IMAGE_DIRECTORY_ENTRY_RESERVED",
];

py_class!(DataDirectory from (usize, peoxide_core::DataDirectory) as (py, c) {
    name: &'static str = DIRECTORY_NAMES[c.0],
    VirtualAddress: u32 = c.1.virtual_address,
    Size: u32 = c.1.size,
});

py_class!(OptionalHeader [dict] from peoxide_core::OptionalHeader as (py, c) {
    Magic: u16 = c.magic,
    MajorLinkerVersion: u8 = c.major_linker_version,
    MinorLinkerVersion: u8 = c.minor_linker_version,
    SizeOfCode: u64 = c.size_of_code,
    SizeOfInitializedData: u64 = c.size_of_initialized_data,
    SizeOfUninitializedData: u64 = c.size_of_uninitialized_data,
    AddressOfEntryPoint: u32 = c.address_of_entry_point,
    BaseOfCode: u64 = c.base_of_code,
    BaseOfData: Option<u32> = c.base_of_data,
    ImageBase: u64 = c.image_base,
    SectionAlignment: u32 = c.section_alignment,
    FileAlignment: u32 = c.file_alignment,
    MajorOperatingSystemVersion: u16 = c.major_operating_system_version,
    MinorOperatingSystemVersion: u16 = c.minor_operating_system_version,
    MajorImageVersion: u16 = c.major_image_version,
    MinorImageVersion: u16 = c.minor_image_version,
    MajorSubsystemVersion: u16 = c.major_subsystem_version,
    MinorSubsystemVersion: u16 = c.minor_subsystem_version,
    Reserved1: u32 = c.win32_version_value,
    SizeOfImage: u32 = c.size_of_image,
    SizeOfHeaders: u32 = c.size_of_headers,
    CheckSum: u32 = c.checksum,
    Subsystem: u16 = c.subsystem,
    DllCharacteristics: u16 = c.dll_characteristics,
    SizeOfStackReserve: u64 = c.size_of_stack_reserve,
    SizeOfStackCommit: u64 = c.size_of_stack_commit,
    SizeOfHeapReserve: u64 = c.size_of_heap_reserve,
    SizeOfHeapCommit: u64 = c.size_of_heap_commit,
    LoaderFlags: u32 = c.loader_flags,
    NumberOfRvaAndSizes: u32 = c.number_of_rva_and_sizes,
    DATA_DIRECTORY: Py<PyList> = list(
        py,
        &c.data_directory.iter().copied().enumerate().collect::<Vec<_>>(),
        DataDirectory::new,
    )?,
});
