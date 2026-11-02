#![allow(non_snake_case)] // Python attribute names follow pefile (e_lfanew, NumberOfSections, ...)

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

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

int_struct!(DosHeader from peoxide_core::DosHeader {
    e_magic: u16 = e_magic,
    e_lfanew: u32 = e_lfanew,
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

/// A parsed PE file. Everything is parsed once, up front, in Rust.
#[pyclass(frozen, module = "peoxide")]
struct PE {
    #[pyo3(get)]
    DOS_HEADER: Py<DosHeader>,
    #[pyo3(get)]
    FILE_HEADER: Py<FileHeader>,
}

#[pymethods]
impl PE {
    #[new]
    fn new(py: Python<'_>, name: std::path::PathBuf) -> PyResult<Self> {
        let data = std::fs::read(name)?;
        let pe = peoxide_core::parse(&data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let h = &pe.headers;

        Ok(PE {
            DOS_HEADER: Py::new(py, DosHeader::from(&h.dos_header))?,
            FILE_HEADER: Py::new(py, FileHeader::from(&h.file_header))?,
        })
    }
}

#[pymodule]
fn peoxide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    Ok(())
}
