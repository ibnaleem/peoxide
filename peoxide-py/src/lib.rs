#![allow(non_snake_case)] // Python attribute names follow pefile (e_lfanew, NumberOfSections, ...)

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

create_exception!(
    peoxide,
    PEFormatError,
    PyException,
    "The data is not a valid PE file."
);

/// Defines a frozen, read-only Python class plus `new(py, core)`, which builds every field
/// from the given expression. The caller names the `py` and core bindings the expressions use.
macro_rules! py_class {
    (
        $(#[$meta:meta])*
        $name:ident from $core:ty as ($py:ident, $c:ident) {
            $($field:ident: $ty:ty = $value:expr),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[pyclass(frozen, get_all, module = "peoxide")]
        struct $name { $($field: $ty),* }

        impl $name {
            #[allow(unused_variables)]
            fn new($py: Python<'_>, $c: &$core) -> PyResult<Self> {
                Ok(Self { $($field: $value),* })
            }
        }
    };
}

fn bytes(py: Python<'_>, b: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, b).unbind()
}

fn list<'py, T, C: IntoPyObject<'py>>(
    py: Python<'py>,
    items: &[T],
    new: impl Fn(Python<'py>, &T) -> PyResult<C>,
) -> PyResult<Py<PyList>> {
    let objects = items
        .iter()
        .map(|i| new(py, i))
        .collect::<PyResult<Vec<_>>>()?;
    Ok(PyList::new(py, objects)?.unbind())
}

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

py_class!(FileHeader from peoxide_core::FileHeader as (py, c) {
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

py_class!(OptionalHeader from peoxide_core::OptionalHeader as (py, c) {
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

py_class!(Section from peoxide_core::Section as (py, c) {
    Name: Py<PyBytes> = bytes(py, &c.name),
    Misc_VirtualSize: u32 = c.virtual_size,
    VirtualAddress: u32 = c.virtual_address,
    SizeOfRawData: u32 = c.size_of_raw_data,
    PointerToRawData: u32 = c.pointer_to_raw_data,
    PointerToRelocations: u32 = c.pointer_to_relocations,
    PointerToLinenumbers: u32 = c.pointer_to_linenumbers,
    NumberOfRelocations: u16 = c.number_of_relocations,
    NumberOfLinenumbers: u16 = c.number_of_linenumbers,
    Characteristics: u32 = c.characteristics,
});

py_class!(ImportData from peoxide_core::ImportSymbol as (py, c) {
    name: Option<Py<PyBytes>> = c.name.as_deref().map(|n| bytes(py, n)),
    hint: Option<u16> = c.hint,
    ordinal: Option<u16> = c.ordinal,
    import_by_ordinal: bool = c.ordinal.is_some(),
    address: u64 = c.address,
});

py_class!(ImportDescData from peoxide_core::ImportDll as (py, c) {
    dll: Py<PyBytes> = bytes(py, &c.dll),
    imports: Py<PyList> = list(py, &c.imports, ImportData::new)?,
});

py_class!(ExportData from peoxide_core::ExportSymbol as (py, c) {
    name: Option<Py<PyBytes>> = c.name.as_deref().map(|n| bytes(py, n)),
    ordinal: u32 = c.ordinal,
    address: u32 = c.address,
    forwarder: Option<Py<PyBytes>> = c.forwarder.as_deref().map(|f| bytes(py, f)),
});

py_class!(
    /// Always present; `symbols` is empty when the file exports nothing.
    ExportDirData from [peoxide_core::ExportSymbol] as (py, c) {
        symbols: Py<PyList> = list(py, c, ExportData::new)?,
    }
);

/// A parsed PE file. Everything is parsed once, up front, in Rust.
#[pyclass(frozen, module = "peoxide")]
struct PE {
    #[pyo3(get)]
    DOS_HEADER: Py<DosHeader>,
    #[pyo3(get)]
    NT_HEADERS: Py<NtHeaders>,
    #[pyo3(get)]
    FILE_HEADER: Py<FileHeader>,
    #[pyo3(get)]
    OPTIONAL_HEADER: Py<OptionalHeader>,
    #[pyo3(get)]
    sections: Py<PyList>,
    #[pyo3(get)]
    DIRECTORY_ENTRY_IMPORT: Py<PyList>,
    #[pyo3(get)]
    DIRECTORY_ENTRY_EXPORT: Py<ExportDirData>,
}

#[pymethods]
impl PE {
    /// Parse a PE file from a path (`name`) or from in-memory bytes (`data`).
    #[new]
    #[pyo3(signature = (name=None, data=None))]
    fn new(
        py: Python<'_>,
        name: Option<std::path::PathBuf>,
        data: Option<&[u8]>,
    ) -> PyResult<Self> {
        let owned;
        let data = match (name, data) {
            (Some(path), None) => {
                owned = std::fs::read(path)?;
                &owned[..]
            }
            (None, Some(data)) => data,
            _ => {
                return Err(PyTypeError::new_err(
                    "PE() takes exactly one of name or data",
                ));
            }
        };
        let pe = peoxide_core::parse(data).map_err(|e| PEFormatError::new_err(e.to_string()))?;
        let h = &pe.headers;

        Ok(PE {
            DOS_HEADER: Py::new(py, DosHeader::new(py, &h.dos_header)?)?,
            NT_HEADERS: Py::new(py, NtHeaders::new(py, h)?)?,
            FILE_HEADER: Py::new(py, FileHeader::new(py, &h.file_header)?)?,
            OPTIONAL_HEADER: Py::new(py, OptionalHeader::new(py, &h.optional_header)?)?,
            sections: list(py, &pe.sections, Section::new)?,
            DIRECTORY_ENTRY_IMPORT: list(py, &pe.imports, ImportDescData::new)?,
            DIRECTORY_ENTRY_EXPORT: Py::new(py, ExportDirData::new(py, &pe.exports)?)?,
        })
    }
}

#[pymodule]
fn peoxide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    m.add("PEFormatError", m.py().get_type::<PEFormatError>())?;
    Ok(())
}
