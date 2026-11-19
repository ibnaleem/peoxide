use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use crate::flags::{EX_DLL_CHARACTERISTICS_FLAGS, with_flags};
use crate::{bytes, list};

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
    ordinal: u64 = c.ordinal,
    address: u32 = c.address,
    forwarder: Option<Py<PyBytes>> = c.forwarder.as_deref().map(|f| bytes(py, f)),
});

py_class!(
    /// Always present; `symbols` is empty when the file exports nothing.
    ExportDirData from [peoxide_core::ExportSymbol] as (py, c) {
        symbols: Py<PyList> = list(py, c, ExportData::new)?,
    }
);

py_class!(DebugDirectory from peoxide_core::DebugDirectory as (py, c) {
    Characteristics: u32 = c.characteristics,
    TimeDateStamp: u32 = c.time_date_stamp,
    MajorVersion: u16 = c.major_version,
    MinorVersion: u16 = c.minor_version,
    Type: u32 = c.debug_type,
    SizeOfData: u32 = c.size_of_data,
    AddressOfRawData: u32 = c.address_of_raw_data,
    PointerToRawData: u32 = c.pointer_to_raw_data,
});

#[pyclass(frozen, get_all, module = "peoxide")]
struct CvInfoPdb70 {
    CvSignature: Py<PyBytes>,
    Signature_Data1: u32,
    Signature_Data2: u16,
    Signature_Data3: u16,
    Signature_Data4: u8,
    Signature_Data5: u8,
    Signature_Data6: Py<PyBytes>,
    Signature_Data6_value: u64,
    Signature_String: String,
    Age: u32,
    PdbFileName: Option<Py<PyBytes>>,
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct CvInfoPdb20 {
    CvHeaderSignature: u32,
    CvHeaderOffset: u32,
    Signature: u32,
    Age: u32,
    PdbFileName: Option<Py<PyBytes>>,
}

#[pyclass(frozen, dict, get_all, module = "peoxide")]
struct ExDllCharacteristics {
    ExDllCharacteristics: u32,
}

fn debug_entry(py: Python<'_>, entry: &peoxide_core::DebugEntry) -> PyResult<Py<PyAny>> {
    use peoxide_core::DebugEntry as E;
    let name = |n: &Option<Vec<u8>>| n.as_deref().map(|n| bytes(py, n));
    Ok(match entry {
        E::Pdb70 {
            cv_signature,
            guid_data1,
            guid_data2,
            guid_data3,
            guid_data4,
            guid_data5,
            guid_data6,
            age,
            pdb_file_name,
        } => Py::new(
            py,
            CvInfoPdb70 {
                CvSignature: bytes(py, cv_signature),
                Signature_Data1: *guid_data1,
                Signature_Data2: *guid_data2,
                Signature_Data3: *guid_data3,
                Signature_Data4: *guid_data4,
                Signature_Data5: *guid_data5,
                Signature_Data6: bytes(py, guid_data6),
                Signature_Data6_value: guid_data6.iter().fold(0, |v, &b| (v << 8) | b as u64),
                Signature_String: entry.pdb70_signature_string().unwrap_or_default(),
                Age: *age,
                PdbFileName: name(pdb_file_name),
            },
        )?
        .into_any(),
        E::Pdb20 {
            cv_header_signature,
            cv_header_offset,
            signature,
            age,
            pdb_file_name,
        } => Py::new(
            py,
            CvInfoPdb20 {
                CvHeaderSignature: *cv_header_signature,
                CvHeaderOffset: *cv_header_offset,
                Signature: *signature,
                Age: *age,
                PdbFileName: name(pdb_file_name),
            },
        )?
        .into_any(),
        E::ExDllCharacteristics(value) => with_flags(
            py,
            ExDllCharacteristics {
                ExDllCharacteristics: *value,
            },
            EX_DLL_CHARACTERISTICS_FLAGS,
            *value,
        )?
        .into_any(),
    })
}

#[pyclass(frozen, module = "peoxide")]
pub(crate) struct DebugData {
    #[pyo3(get, name = "struct")]
    structure: Py<DebugDirectory>,
    /// `None` for debug types peoxide does not decode.
    #[pyo3(get)]
    entry: Option<Py<PyAny>>,
}

impl DebugData {
    pub(crate) fn new(py: Python<'_>, d: &peoxide_core::DebugDirectory) -> PyResult<Self> {
        Ok(DebugData {
            structure: Py::new(py, DebugDirectory::new(py, d)?)?,
            entry: d.entry.as_ref().map(|e| debug_entry(py, e)).transpose()?,
        })
    }
}

py_class!(RichHeader from peoxide_core::RichHeader as (py, c) {
    checksum: u32 = c.checksum,
    values: Py<PyList> = PyList::new(py, &c.values)?.unbind(),
    key: Py<PyBytes> = bytes(py, &c.key),
    raw_data: Py<PyBytes> = bytes(py, &c.raw_data),
    clear_data: Py<PyBytes> = bytes(py, &c.clear_data),
});

py_class!(TlsDirectory from peoxide_core::TlsDirectory as (py, c) {
    StartAddressOfRawData: u64 = c.start_address_of_raw_data,
    EndAddressOfRawData: u64 = c.end_address_of_raw_data,
    AddressOfIndex: u64 = c.address_of_index,
    AddressOfCallBacks: u64 = c.address_of_callbacks,
    SizeOfZeroFill: u32 = c.size_of_zero_fill,
    Characteristics: u32 = c.characteristics,
});

py_class!(TlsData from peoxide_core::TlsDirectory as (py, c) {
    r#struct: Py<TlsDirectory> = Py::new(py, TlsDirectory::new(py, c)?)?,
});

py_class!(BaseRelocation from peoxide_core::RelocationBlock as (py, c) {
    VirtualAddress: u32 = c.virtual_address,
    SizeOfBlock: u32 = c.size_of_block,
});

#[pyclass(frozen, get_all, module = "peoxide")]
struct RelocationData {
    r#type: u16,
    rva: u64,
    base_rva: u32,
}

py_class!(BaseRelocationData from peoxide_core::RelocationBlock as (py, c) {
    r#struct: Py<BaseRelocation> = Py::new(py, BaseRelocation::new(py, c)?)?,
    entries: Py<PyList> = PyList::new(
        py,
        c.entries
            .iter()
            .map(|e| RelocationData { r#type: e.reloc_type, rva: e.rva, base_rva: c.virtual_address }),
    )?
    .unbind(),
});
