use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::{bytes, list, missing};

py_class!(VersionInfoStruct from peoxide_core::VersionInfo as (py, c) {
    Length: u16 = c.header.length,
    ValueLength: u16 = c.header.value_length,
    Type: u16 = c.header.type_,
    Key: Py<PyBytes> = bytes(py, &c.key),
});

py_class!(FixedFileInfoStruct from peoxide_core::FixedFileInfo as (py, c) {
    Signature: u32 = c.signature,
    StrucVersion: u32 = c.struc_version,
    FileVersionMS: u32 = c.file_version_ms,
    FileVersionLS: u32 = c.file_version_ls,
    ProductVersionMS: u32 = c.product_version_ms,
    ProductVersionLS: u32 = c.product_version_ls,
    FileFlagsMask: u32 = c.file_flags_mask,
    FileFlags: u32 = c.file_flags,
    FileOS: u32 = c.file_os,
    FileType: u32 = c.file_type,
    FileSubtype: u32 = c.file_subtype,
    FileDateMS: u32 = c.file_date_ms,
    FileDateLS: u32 = c.file_date_ls,
});

fn bytes_dict<'a>(
    py: Python<'_>,
    pairs: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in pairs {
        dict.set_item(PyBytes::new(py, key), PyBytes::new(py, value))?;
    }
    Ok(dict.unbind())
}

py_class!(StringTableStruct from peoxide_core::StringTable as (py, c) {
    Length: u16 = c.header.length,
    ValueLength: u16 = c.header.value_length,
    Type: u16 = c.header.type_,
    LangID: Py<PyBytes> = bytes(py, &c.lang_id),
    entries: Py<PyDict> = bytes_dict(py, c.entries.iter().map(|(k, v)| (&k[..], &v[..])))?,
});

/// `entry` is missing, as in pefile, when the Var holds no complete word pair.
#[pyclass(frozen, module = "peoxide")]
struct VarStruct {
    #[pyo3(get)]
    Length: u16,
    #[pyo3(get)]
    ValueLength: u16,
    #[pyo3(get)]
    Type: u16,
    entry: Option<Py<PyDict>>,
}

impl VarStruct {
    fn new(py: Python<'_>, v: &peoxide_core::Var) -> PyResult<Self> {
        let entry = v
            .entry
            .as_ref()
            .map(|(name, words)| -> PyResult<_> {
                let dict = PyDict::new(py);
                dict.set_item(PyBytes::new(py, name), words)?;
                Ok(dict.unbind())
            })
            .transpose()?;
        Ok(VarStruct {
            Length: v.header.length,
            ValueLength: v.header.value_length,
            Type: v.header.type_,
            entry,
        })
    }
}

#[pymethods]
impl VarStruct {
    #[getter]
    fn entry(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        missing(&self.entry, py, "entry")
    }
}

/// A StringFileInfo or VarFileInfo block. `StringTable` and `Var` exist only where pefile
/// sets them.
#[pyclass(frozen, module = "peoxide")]
struct FileInfoStruct {
    #[pyo3(get)]
    Length: u16,
    #[pyo3(get)]
    ValueLength: u16,
    #[pyo3(get)]
    Type: u16,
    #[pyo3(get)]
    Key: Py<PyBytes>,
    string_table: Option<Py<PyList>>,
    var: Option<Py<PyList>>,
}

impl FileInfoStruct {
    fn new(py: Python<'_>, f: &peoxide_core::FileInfo) -> PyResult<Self> {
        Ok(FileInfoStruct {
            Length: f.header.length,
            ValueLength: f.header.value_length,
            Type: f.header.type_,
            Key: bytes(py, &f.key),
            string_table: f
                .string_table
                .as_ref()
                .map(|t| list(py, t, StringTableStruct::new))
                .transpose()?,
            var: f
                .var
                .as_ref()
                .map(|v| list(py, v, VarStruct::new))
                .transpose()?,
        })
    }
}

#[pymethods]
impl FileInfoStruct {
    #[getter]
    fn StringTable(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        missing(&self.string_table, py, "StringTable")
    }

    #[getter]
    fn Var(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        missing(&self.var, py, "Var")
    }
}

/// pefile's three version attributes, each `None` where pefile leaves it undefined.
pub(crate) struct VersionLists {
    pub(crate) vs_versioninfo: Option<Py<PyList>>,
    pub(crate) vs_fixedfileinfo: Option<Py<PyList>>,
    pub(crate) file_info: Option<Py<PyList>>,
}

impl VersionLists {
    pub(crate) fn new(py: Python<'_>, v: &peoxide_core::Version) -> PyResult<Self> {
        let file_info = v
            .file_info
            .as_ref()
            .map(|lists| {
                let inner = lists
                    .iter()
                    .map(|blocks| list(py, blocks, FileInfoStruct::new))
                    .collect::<PyResult<Vec<_>>>()?;
                Ok::<_, PyErr>(PyList::new(py, inner)?.unbind())
            })
            .transpose()?;
        Ok(VersionLists {
            vs_versioninfo: v
                .vs_versioninfo
                .as_ref()
                .map(|l| list(py, l, VersionInfoStruct::new))
                .transpose()?,
            vs_fixedfileinfo: v
                .vs_fixedfileinfo
                .as_ref()
                .map(|l| list(py, l, FixedFileInfoStruct::new))
                .transpose()?,
            file_info,
        })
    }
}
