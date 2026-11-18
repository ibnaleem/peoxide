use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::{SaturatingI64, bytes, hexdigest, no_panic};

/// Exposed fields are Python objects for the reason given on `py_class!`.
#[pyclass(frozen, dict, module = "peoxide")]
pub(crate) struct Section {
    #[pyo3(get)]
    Name: Py<PyBytes>,
    #[pyo3(get)]
    Misc_VirtualSize: Py<PyAny>,
    #[pyo3(get)]
    VirtualAddress: Py<PyAny>,
    #[pyo3(get)]
    SizeOfRawData: Py<PyAny>,
    #[pyo3(get)]
    PointerToRawData: Py<PyAny>,
    #[pyo3(get)]
    PointerToRelocations: Py<PyAny>,
    #[pyo3(get)]
    PointerToLinenumbers: Py<PyAny>,
    #[pyo3(get)]
    NumberOfRelocations: Py<PyAny>,
    #[pyo3(get)]
    NumberOfLinenumbers: Py<PyAny>,
    #[pyo3(get)]
    Characteristics: Py<PyAny>,
    table: peoxide_core::Section,
    layout: peoxide_core::SectionLayout,
    /// The whole file, shared with `PE` and every other section.
    file: Py<PyBytes>,
}

impl Section {
    pub(crate) fn new(
        py: Python<'_>,
        table: &peoxide_core::Section,
        layout: peoxide_core::SectionLayout,
        file: &Bound<'_, PyBytes>,
    ) -> PyResult<Self> {
        Ok(Section {
            Name: bytes(py, &table.name),
            Misc_VirtualSize: table.virtual_size.into_py_any(py)?,
            VirtualAddress: table.virtual_address.into_py_any(py)?,
            SizeOfRawData: table.size_of_raw_data.into_py_any(py)?,
            PointerToRawData: table.pointer_to_raw_data.into_py_any(py)?,
            PointerToRelocations: table.pointer_to_relocations.into_py_any(py)?,
            PointerToLinenumbers: table.pointer_to_linenumbers.into_py_any(py)?,
            NumberOfRelocations: table.number_of_relocations.into_py_any(py)?,
            NumberOfLinenumbers: table.number_of_linenumbers.into_py_any(py)?,
            Characteristics: table.characteristics.into_py_any(py)?,
            table: table.clone(),
            layout,
            file: file.clone().unbind(),
        })
    }

    fn data<'a>(
        &'a self,
        py: Python<'_>,
        start: Option<i64>,
        length: Option<i64>,
        ignore_padding: bool,
    ) -> PyResult<&'a [u8]> {
        let file = self.file.as_bytes(py);
        no_panic(|| {
            let range = self
                .layout
                .data_range(&self.table, start, length, ignore_padding);
            &file[peoxide_core::clamp(range, file.len())]
        })
    }
}

#[pymethods]
impl Section {
    /// The section's bytes, or a slice of them starting at RVA `start`.
    #[pyo3(signature = (start=None, length=None, ignore_padding=false))]
    fn get_data<'py>(
        &self,
        py: Python<'py>,
        start: Option<SaturatingI64>,
        length: Option<SaturatingI64>,
        ignore_padding: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let (start, length) = (start.map(|start| start.0), length.map(|length| length.0));
        Ok(PyBytes::new(
            py,
            self.data(py, start, length, ignore_padding)?,
        ))
    }

    /// Shannon entropy of `get_data()`, in bits per byte.
    fn get_entropy(&self, py: Python<'_>) -> PyResult<f64> {
        let data = self.data(py, None, None, false)?;
        no_panic(|| peoxide_core::entropy(data))
    }

    fn get_hash_md5(&self, py: Python<'_>) -> PyResult<String> {
        hexdigest(py, "md5", self.data(py, None, None, false)?)
    }

    fn get_hash_sha1(&self, py: Python<'_>) -> PyResult<String> {
        hexdigest(py, "sha1", self.data(py, None, None, false)?)
    }

    fn get_hash_sha256(&self, py: Python<'_>) -> PyResult<String> {
        hexdigest(py, "sha256", self.data(py, None, None, false)?)
    }

    fn get_hash_sha512(&self, py: Python<'_>) -> PyResult<String> {
        hexdigest(py, "sha512", self.data(py, None, None, false)?)
    }

    fn contains_rva(&self, rva: SaturatingI64) -> PyResult<bool> {
        no_panic(|| self.layout.contains_rva(rva.0))
    }

    fn contains(&self, rva: SaturatingI64) -> PyResult<bool> {
        no_panic(|| self.layout.contains_rva(rva.0))
    }

    fn contains_offset(&self, offset: SaturatingI64) -> PyResult<bool> {
        no_panic(|| self.layout.contains_offset(&self.table, offset.0))
    }

    fn get_offset_from_rva(&self, rva: i64) -> PyResult<i64> {
        no_panic(|| self.layout.offset_from_rva(rva))
    }

    fn get_rva_from_offset(&self, offset: i64) -> PyResult<i64> {
        no_panic(|| self.layout.rva_from_offset(offset))
    }
}
