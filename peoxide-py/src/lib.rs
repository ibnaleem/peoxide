#![allow(non_snake_case)] // Python attribute names follow pefile (e_lfanew, NumberOfSections, ...)

use pyo3::create_exception;
use pyo3::exceptions::{PyAttributeError, PyException, PyTypeError};
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

type Flags = &'static [(&'static str, u32)];

/// pefile's flag tables: each name reads as `bool(field & mask)`.
const IMAGE_FILE_FLAGS: Flags = &[
    ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001),
    ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002),
    ("IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004),
    ("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008),
    ("IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010),
    ("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020),
    ("IMAGE_FILE_16BIT_MACHINE", 0x0040),
    ("IMAGE_FILE_BYTES_REVERSED_LO", 0x0080),
    ("IMAGE_FILE_32BIT_MACHINE", 0x0100),
    ("IMAGE_FILE_DEBUG_STRIPPED", 0x0200),
    ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400),
    ("IMAGE_FILE_NET_RUN_FROM_SWAP", 0x0800),
    ("IMAGE_FILE_SYSTEM", 0x1000),
    ("IMAGE_FILE_DLL", 0x2000),
    ("IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000),
    ("IMAGE_FILE_BYTES_REVERSED_HI", 0x8000),
];

const DLL_CHARACTERISTICS_FLAGS: Flags = &[
    ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 0x0020),
    ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 0x0040),
    ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 0x0080),
    ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 0x0100),
    ("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 0x0200),
    ("IMAGE_DLLCHARACTERISTICS_NO_SEH", 0x0400),
    ("IMAGE_DLLCHARACTERISTICS_NO_BIND", 0x0800),
    ("IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 0x1000),
    ("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 0x2000),
    ("IMAGE_DLLCHARACTERISTICS_GUARD_CF", 0x4000),
    ("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 0x8000),
];

const SECTION_FLAGS: Flags = &[
    ("IMAGE_SCN_TYPE_REG", 0x00000000),
    ("IMAGE_SCN_TYPE_DSECT", 0x00000001),
    ("IMAGE_SCN_TYPE_NOLOAD", 0x00000002),
    ("IMAGE_SCN_TYPE_GROUP", 0x00000004),
    ("IMAGE_SCN_TYPE_NO_PAD", 0x00000008),
    ("IMAGE_SCN_TYPE_COPY", 0x00000010),
    ("IMAGE_SCN_CNT_CODE", 0x00000020),
    ("IMAGE_SCN_CNT_INITIALIZED_DATA", 0x00000040),
    ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080),
    ("IMAGE_SCN_LNK_OTHER", 0x00000100),
    ("IMAGE_SCN_LNK_INFO", 0x00000200),
    ("IMAGE_SCN_LNK_OVER", 0x00000400),
    ("IMAGE_SCN_LNK_REMOVE", 0x00000800),
    ("IMAGE_SCN_LNK_COMDAT", 0x00001000),
    ("IMAGE_SCN_MEM_PROTECTED", 0x00004000),
    ("IMAGE_SCN_NO_DEFER_SPEC_EXC", 0x00004000),
    ("IMAGE_SCN_GPREL", 0x00008000),
    ("IMAGE_SCN_MEM_FARDATA", 0x00008000),
    ("IMAGE_SCN_MEM_SYSHEAP", 0x00010000),
    ("IMAGE_SCN_MEM_PURGEABLE", 0x00020000),
    ("IMAGE_SCN_MEM_16BIT", 0x00020000),
    ("IMAGE_SCN_MEM_LOCKED", 0x00040000),
    ("IMAGE_SCN_MEM_PRELOAD", 0x00080000),
    ("IMAGE_SCN_ALIGN_1BYTES", 0x00100000),
    ("IMAGE_SCN_ALIGN_2BYTES", 0x00200000),
    ("IMAGE_SCN_ALIGN_4BYTES", 0x00300000),
    ("IMAGE_SCN_ALIGN_8BYTES", 0x00400000),
    ("IMAGE_SCN_ALIGN_16BYTES", 0x00500000),
    ("IMAGE_SCN_ALIGN_32BYTES", 0x00600000),
    ("IMAGE_SCN_ALIGN_64BYTES", 0x00700000),
    ("IMAGE_SCN_ALIGN_128BYTES", 0x00800000),
    ("IMAGE_SCN_ALIGN_256BYTES", 0x00900000),
    ("IMAGE_SCN_ALIGN_512BYTES", 0x00A00000),
    ("IMAGE_SCN_ALIGN_1024BYTES", 0x00B00000),
    ("IMAGE_SCN_ALIGN_2048BYTES", 0x00C00000),
    ("IMAGE_SCN_ALIGN_4096BYTES", 0x00D00000),
    ("IMAGE_SCN_ALIGN_8192BYTES", 0x00E00000),
    ("IMAGE_SCN_ALIGN_MASK", 0x00F00000),
    ("IMAGE_SCN_LNK_NRELOC_OVFL", 0x01000000),
    ("IMAGE_SCN_MEM_DISCARDABLE", 0x02000000),
    ("IMAGE_SCN_MEM_NOT_CACHED", 0x04000000),
    ("IMAGE_SCN_MEM_NOT_PAGED", 0x08000000),
    ("IMAGE_SCN_MEM_SHARED", 0x10000000),
    ("IMAGE_SCN_MEM_EXECUTE", 0x20000000),
    ("IMAGE_SCN_MEM_READ", 0x40000000),
    ("IMAGE_SCN_MEM_WRITE", 0x80000000),
];

fn flag(flags: Flags, field: u32, class: &str, name: &str) -> PyResult<bool> {
    flags
        .iter()
        .find(|(flag, _)| *flag == name)
        .map(|(_, mask)| field & mask != 0)
        .ok_or_else(|| {
            PyAttributeError::new_err(format!("'{class}' object has no attribute '{name}'"))
        })
}

#[pymethods]
impl FileHeader {
    fn __getattr__(&self, name: &str) -> PyResult<bool> {
        flag(
            IMAGE_FILE_FLAGS,
            self.Characteristics.into(),
            "FileHeader",
            name,
        )
    }
}

#[pymethods]
impl OptionalHeader {
    fn __getattr__(&self, name: &str) -> PyResult<bool> {
        let field = self.DllCharacteristics.into();
        flag(DLL_CHARACTERISTICS_FLAGS, field, "OptionalHeader", name)
    }
}

#[pymethods]
impl Section {
    fn __getattr__(&self, name: &str) -> PyResult<bool> {
        flag(SECTION_FLAGS, self.Characteristics, "Section", name)
    }
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
    pe: peoxide_core::Pe,
    data: Py<PyBytes>,
}

#[pymethods]
impl PE {
    /// Parse a PE file from a path (`name`) or from in-memory bytes (`data`).
    #[new]
    #[pyo3(signature = (name=None, data=None))]
    fn new(
        py: Python<'_>,
        name: Option<std::path::PathBuf>,
        data: Option<Bound<'_, PyBytes>>,
    ) -> PyResult<Self> {
        let data = match (name, data) {
            (Some(path), None) => PyBytes::new(py, &std::fs::read(path)?),
            (None, Some(data)) => data,
            _ => {
                return Err(PyTypeError::new_err(
                    "PE() takes exactly one of name or data",
                ));
            }
        };
        let pe = peoxide_core::parse(data.as_bytes())
            .map_err(|e| PEFormatError::new_err(e.to_string()))?;
        let h = &pe.headers;

        Ok(PE {
            DOS_HEADER: Py::new(py, DosHeader::new(py, &h.dos_header)?)?,
            NT_HEADERS: Py::new(py, NtHeaders::new(py, h)?)?,
            FILE_HEADER: Py::new(py, FileHeader::new(py, &h.file_header)?)?,
            OPTIONAL_HEADER: Py::new(py, OptionalHeader::new(py, &h.optional_header)?)?,
            sections: list(py, &pe.sections, Section::new)?,
            DIRECTORY_ENTRY_IMPORT: list(py, &pe.imports, ImportDescData::new)?,
            DIRECTORY_ENTRY_EXPORT: Py::new(py, ExportDirData::new(py, &pe.exports)?)?,
            pe,
            data: data.unbind(),
        })
    }

    /// Bytes at an RVA, read from whichever section holds it (or the headers, or the raw file).
    #[pyo3(signature = (rva=0, length=None))]
    fn get_data<'py>(
        &self,
        py: Python<'py>,
        rva: i64,
        length: Option<i64>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let range = self.pe.data_range(rva, length).ok_or_else(|| {
            PEFormatError::new_err("data at RVA can't be fetched. Corrupt header?")
        })?;
        Ok(PyBytes::new(py, &self.data.as_bytes(py)[range]))
    }

    fn get_offset_from_rva(&self, rva: i64) -> PyResult<i64> {
        self.pe.offset_from_rva(rva).ok_or_else(|| {
            PEFormatError::new_err(format!("data at RVA 0x{rva:x} can't be fetched"))
        })
    }

    /// `None` when the offset is past the start of the first section but in none of them.
    fn get_rva_from_offset(&self, offset: i64) -> Option<i64> {
        self.pe.rva_from_offset(offset)
    }

    fn get_section_by_rva<'py>(
        &self,
        py: Python<'py>,
        rva: i64,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let index = self.pe.section_by_rva(rva);
        index
            .map(|i| self.sections.bind(py).get_item(i))
            .transpose()
    }

    fn get_section_by_offset<'py>(
        &self,
        py: Python<'py>,
        offset: i64,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let index = self.pe.section_by_offset(offset);
        index
            .map(|i| self.sections.bind(py).get_item(i))
            .transpose()
    }

    /// Offset of data appended past everything the headers describe, or `None`.
    fn get_overlay_data_start_offset(&self) -> Option<usize> {
        self.pe.overlay_offset()
    }

    /// The appended data itself, or `None`.
    fn get_overlay<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        let offset = self.pe.overlay_offset()?;
        Some(PyBytes::new(py, &self.data.as_bytes(py)[offset..]))
    }

    /// True for a standard executable: not a DLL, not a driver, and marked executable.
    fn is_exe(&self) -> bool {
        self.pe.is_exe()
    }

    /// True when FILE_HEADER has IMAGE_FILE_DLL set.
    fn is_dll(&self) -> bool {
        self.pe.is_dll()
    }

    /// True when the image imports a kernel DLL, or has a PAGE section and a native subsystem.
    fn is_driver(&self) -> bool {
        self.pe.is_driver()
    }
}

#[pymodule]
fn peoxide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    m.add("PEFormatError", m.py().get_type::<PEFormatError>())?;
    Ok(())
}
