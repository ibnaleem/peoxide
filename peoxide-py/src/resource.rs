use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

use crate::{bytes, list, missing};

py_class!(ResourceDirectoryStruct from peoxide_core::ResourceDirectory as (py, c) {
    Characteristics: u32 = c.characteristics,
    TimeDateStamp: u32 = c.time_date_stamp,
    MajorVersion: u16 = c.major_version,
    MinorVersion: u16 = c.minor_version,
    NumberOfNamedEntries: u16 = c.number_of_named_entries,
    NumberOfIdEntries: u16 = c.number_of_id_entries,
});

py_class!(ResourceEntryStruct from peoxide_core::ResourceEntry as (py, c) {
    Name: u32 = c.name_field,
    OffsetToData: u32 = c.offset_to_data,
    NameOffset: u32 = c.name_field & 0x7FFF_FFFF,
    Id: u32 = c.name_field & 0xFFFF,
    DataIsDirectory: u32 = c.offset_to_data >> 31,
    OffsetToDirectory: u32 = c.offset_to_data & 0x7FFF_FFFF,
});

py_class!(ResourceDataStruct from peoxide_core::ResourceData as (py, c) {
    OffsetToData: u32 = c.offset_to_data,
    Size: u32 = c.size,
    CodePage: u32 = c.code_page,
    Reserved: u32 = c.reserved,
});

/// A resource name. `string` is UTF-8, or `None` where pefile leaves the name unread.
#[pyclass(frozen, get_all, module = "peoxide")]
struct ResourceName {
    string: Option<Py<PyBytes>>,
}

#[pymethods]
impl ResourceName {
    #[pyo3(signature = (*args))]
    fn decode(&self, py: Python<'_>, args: &Bound<'_, PyTuple>) -> PyResult<Py<PyAny>> {
        match &self.string {
            Some(s) if !s.as_bytes(py).is_empty() => Ok(s.call_method1(py, "decode", args)?),
            _ => Ok("".into_pyobject(py)?.into_any().unbind()),
        }
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        self.decode(py, &PyTuple::new(py, ["utf-8", "backslashreplace"])?)?
            .extract(py)
    }
}

#[pyclass(frozen, module = "peoxide")]
struct ResourceDataEntryData {
    #[pyo3(get, name = "struct")]
    structure: Py<ResourceDataStruct>,
    #[pyo3(get)]
    lang: u32,
    #[pyo3(get)]
    sublang: u32,
}

/// Has `directory` or `data`, never both, as in pefile.
#[pyclass(frozen, module = "peoxide")]
struct ResourceDirEntryData {
    #[pyo3(get, name = "struct")]
    structure: Py<ResourceEntryStruct>,
    #[pyo3(get)]
    name: Option<Py<ResourceName>>,
    #[pyo3(get)]
    id: Option<u32>,
    directory: Option<Py<ResourceDirData>>,
    data: Option<Py<ResourceDataEntryData>>,
}

#[pymethods]
impl ResourceDirEntryData {
    #[getter]
    fn directory(&self, py: Python<'_>) -> PyResult<Py<ResourceDirData>> {
        missing(&self.directory, py, "directory")
    }

    #[getter]
    fn data(&self, py: Python<'_>) -> PyResult<Py<ResourceDataEntryData>> {
        missing(&self.data, py, "data")
    }
}

#[pyclass(frozen, module = "peoxide")]
pub(crate) struct ResourceDirData {
    #[pyo3(get, name = "struct")]
    structure: Py<ResourceDirectoryStruct>,
    #[pyo3(get)]
    entries: Py<PyList>,
    strings: Option<Py<PyDict>>,
}

impl ResourceDirData {
    pub(crate) fn new(py: Python<'_>, d: &peoxide_core::ResourceDirectory) -> PyResult<Self> {
        let strings = d
            .strings
            .as_ref()
            .map(|table| -> PyResult<_> {
                let dict = PyDict::new(py);
                for (key, value) in table {
                    dict.set_item(key, value)?;
                }
                Ok(dict.unbind())
            })
            .transpose()?;
        Ok(ResourceDirData {
            structure: Py::new(py, ResourceDirectoryStruct::new(py, d)?)?,
            entries: list(py, &d.entries, ResourceDirEntryData::new)?,
            strings,
        })
    }
}

#[pymethods]
impl ResourceDirData {
    /// The decoded string table, only on the per-block directories under RT_STRING.
    #[getter]
    fn strings(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        missing(&self.strings, py, "strings")
    }
}

impl ResourceDirEntryData {
    fn new(py: Python<'_>, e: &peoxide_core::ResourceEntry) -> PyResult<Self> {
        let (directory, data) = match &e.child {
            peoxide_core::ResourceChild::Directory(d) => {
                (Some(Py::new(py, ResourceDirData::new(py, d)?)?), None)
            }
            peoxide_core::ResourceChild::Data(d) => {
                let entry = ResourceDataEntryData {
                    structure: Py::new(py, ResourceDataStruct::new(py, d)?)?,
                    lang: e.name_field & 0x3FF,
                    sublang: e.name_field >> 10,
                };
                (None, Some(Py::new(py, entry)?))
            }
        };
        let name = e
            .name
            .as_ref()
            .map(|s| {
                let string = s.as_deref().map(|s| bytes(py, s));
                Py::new(py, ResourceName { string })
            })
            .transpose()?;
        Ok(ResourceDirEntryData {
            structure: Py::new(py, ResourceEntryStruct::new(py, e)?)?,
            id: e.name.is_none().then_some(e.name_field),
            name,
            directory,
            data,
        })
    }
}
