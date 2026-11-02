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

/// A read-only Python class whose integer fields are copied from a peoxide-core struct.
macro_rules! int_struct {
    ($name:ident from $core:ty { $($field:ident: $ty:ty = $src:ident),* $(,)? }) => {
        #[pyclass(frozen, get_all, module = "peoxide")]
        struct $name { $($field: $ty),* }

        impl From<&$core> for $name {
            fn from(c: &$core) -> Self {
                Self { $($field: c.$src),* }
            }
        }
    };
}

int_struct!(NtHeaders from peoxide_core::Headers {
    Signature: u32 = signature,
});

int_struct!(FileHeader from peoxide_core::FileHeader {
    Machine: u16 = machine,
    NumberOfSections: u16 = number_of_sections,
    TimeDateStamp: u32 = time_date_stamp,
    PointerToSymbolTable: u32 = pointer_to_symbol_table,
    NumberOfSymbols: u32 = number_of_symbols,
    SizeOfOptionalHeader: u16 = size_of_optional_header,
    Characteristics: u16 = characteristics,
});

int_struct!(OptionalHeader from peoxide_core::OptionalHeader {
    Magic: u16 = magic,
    MajorLinkerVersion: u8 = major_linker_version,
    MinorLinkerVersion: u8 = minor_linker_version,
    SizeOfCode: u64 = size_of_code,
    SizeOfInitializedData: u64 = size_of_initialized_data,
    SizeOfUninitializedData: u64 = size_of_uninitialized_data,
    AddressOfEntryPoint: u32 = address_of_entry_point,
    BaseOfCode: u64 = base_of_code,
    BaseOfData: Option<u32> = base_of_data,
    ImageBase: u64 = image_base,
    SectionAlignment: u32 = section_alignment,
    FileAlignment: u32 = file_alignment,
    MajorOperatingSystemVersion: u16 = major_operating_system_version,
    MinorOperatingSystemVersion: u16 = minor_operating_system_version,
    MajorImageVersion: u16 = major_image_version,
    MinorImageVersion: u16 = minor_image_version,
    MajorSubsystemVersion: u16 = major_subsystem_version,
    MinorSubsystemVersion: u16 = minor_subsystem_version,
    Reserved1: u32 = win32_version_value,
    SizeOfImage: u32 = size_of_image,
    SizeOfHeaders: u32 = size_of_headers,
    CheckSum: u32 = checksum,
    Subsystem: u16 = subsystem,
    DllCharacteristics: u16 = dll_characteristics,
    SizeOfStackReserve: u64 = size_of_stack_reserve,
    SizeOfStackCommit: u64 = size_of_stack_commit,
    SizeOfHeapReserve: u64 = size_of_heap_reserve,
    SizeOfHeapCommit: u64 = size_of_heap_commit,
    LoaderFlags: u32 = loader_flags,
    NumberOfRvaAndSizes: u32 = number_of_rva_and_sizes,
});

fn bytes(py: Python<'_>, b: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, b).unbind()
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct DosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: Py<PyBytes>,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: Py<PyBytes>,
    e_lfanew: u32,
}

impl DosHeader {
    fn new(py: Python<'_>, d: &peoxide_core::DosHeader) -> Self {
        DosHeader {
            e_magic: d.e_magic,
            e_cblp: d.e_cblp,
            e_cp: d.e_cp,
            e_crlc: d.e_crlc,
            e_cparhdr: d.e_cparhdr,
            e_minalloc: d.e_minalloc,
            e_maxalloc: d.e_maxalloc,
            e_ss: d.e_ss,
            e_sp: d.e_sp,
            e_csum: d.e_csum,
            e_ip: d.e_ip,
            e_cs: d.e_cs,
            e_lfarlc: d.e_lfarlc,
            e_ovno: d.e_ovno,
            e_res: bytes(py, &d.e_res),
            e_oemid: d.e_oemid,
            e_oeminfo: d.e_oeminfo,
            e_res2: bytes(py, &d.e_res2),
            e_lfanew: d.e_lfanew,
        }
    }
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct Section {
    Name: Py<PyBytes>,
    Misc_VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

impl Section {
    fn new(py: Python<'_>, s: &peoxide_core::Section) -> Self {
        Section {
            Name: bytes(py, &s.name),
            Misc_VirtualSize: s.virtual_size,
            VirtualAddress: s.virtual_address,
            SizeOfRawData: s.size_of_raw_data,
            PointerToRawData: s.pointer_to_raw_data,
            PointerToRelocations: s.pointer_to_relocations,
            PointerToLinenumbers: s.pointer_to_linenumbers,
            NumberOfRelocations: s.number_of_relocations,
            NumberOfLinenumbers: s.number_of_linenumbers,
            Characteristics: s.characteristics,
        }
    }
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct ImportData {
    name: Option<Py<PyBytes>>,
    hint: Option<u16>,
    ordinal: Option<u16>,
    import_by_ordinal: bool,
    address: u64,
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct ImportDescData {
    dll: Py<PyBytes>,
    imports: Py<PyList>,
}

impl ImportDescData {
    fn new(py: Python<'_>, d: &peoxide_core::ImportDll) -> PyResult<Self> {
        let imports = d.imports.iter().map(|i| ImportData {
            name: i.name.as_deref().map(|n| bytes(py, n)),
            hint: i.hint,
            ordinal: i.ordinal,
            import_by_ordinal: i.ordinal.is_some(),
            address: i.address,
        });
        Ok(ImportDescData {
            dll: bytes(py, &d.dll),
            imports: PyList::new(py, imports)?.unbind(),
        })
    }
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct ExportData {
    name: Option<Py<PyBytes>>,
    ordinal: u32,
    address: u32,
    forwarder: Option<Py<PyBytes>>,
}

/// Always present; `symbols` is empty when the file exports nothing.
#[pyclass(frozen, get_all, module = "peoxide")]
struct ExportDirData {
    symbols: Py<PyList>,
}

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
        let sections = pe.sections.iter().map(|s| Section::new(py, s));
        let imports = pe
            .imports
            .iter()
            .map(|d| ImportDescData::new(py, d))
            .collect::<PyResult<Vec<_>>>()?;
        let symbols = pe.exports.iter().map(|e| ExportData {
            name: e.name.as_deref().map(|n| bytes(py, n)),
            ordinal: e.ordinal,
            address: e.address,
            forwarder: e.forwarder.as_deref().map(|f| bytes(py, f)),
        });

        Ok(PE {
            DOS_HEADER: Py::new(py, DosHeader::new(py, &h.dos_header))?,
            NT_HEADERS: Py::new(py, NtHeaders::from(h))?,
            FILE_HEADER: Py::new(py, FileHeader::from(&h.file_header))?,
            OPTIONAL_HEADER: Py::new(py, OptionalHeader::from(&h.optional_header))?,
            sections: PyList::new(py, sections)?.unbind(),
            DIRECTORY_ENTRY_IMPORT: PyList::new(py, imports)?.unbind(),
            DIRECTORY_ENTRY_EXPORT: Py::new(
                py,
                ExportDirData {
                    symbols: PyList::new(py, symbols)?.unbind(),
                },
            )?,
        })
    }
}

#[pymodule]
fn peoxide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    m.add("PEFormatError", m.py().get_type::<PEFormatError>())?;
    Ok(())
}
