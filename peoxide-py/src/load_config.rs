use peoxide_core::{DynamicRelocationKind, LoadConfig};
use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyList;

use crate::directories::BaseRelocationData;
use crate::list;

/// pefile's IMAGE_LOAD_CONFIG_DIRECTORY. Its fields are plain attributes because, as in
/// pefile, a structure whose `Size` stops early lacks the later ones.
#[pyclass(frozen, dict, module = "peoxide")]
pub(crate) struct LoadConfigDirectory {}

py_class!(DynamicRelocation from peoxide_core::DynamicRelocation as (py, c) {
    Symbol: u64 = c.symbol,
    BaseRelocSize: u32 = c.base_reloc_size,
});

#[pyclass(frozen, get_all, module = "peoxide")]
struct DynamicRelocationData {
    r#struct: Py<PyAny>,
    symbol: Py<PyAny>,
    relocations: Py<PyAny>,
}

#[pyclass(frozen, get_all, module = "peoxide")]
struct FunctionOverrideData {
    r#struct: Py<PyAny>,
    symbol: Py<PyAny>,
    bdd_relocs: Py<PyAny>,
    func_relocs: Py<PyAny>,
}

py_class!(FunctionOverrideDynamicRelocation from peoxide_core::FunctionOverride as (py, c) {
    OriginalRva: u32 = c.original_rva,
    BDDOffset: u32 = c.bdd_offset,
    RvaSize: u32 = c.rva_size,
    BaseRelocSize: u32 = c.base_reloc_size,
});

py_class!(FunctionOverrideDynamicRelocationData from peoxide_core::FunctionOverride as (py, c) {
    r#struct: Py<FunctionOverrideDynamicRelocation> =
        Py::new(py, FunctionOverrideDynamicRelocation::new(py, c)?)?,
    func_rva: u32 = c.original_rva,
    override_rvas: Py<PyList> = PyList::new(py, &c.override_rvas)?.unbind(),
    relocations: Py<PyList> = list(py, &c.relocations, BaseRelocationData::new)?,
});

py_class!(BddDynamicRelocation from peoxide_core::BddRelocation as (py, c) {
    Left: u16 = c.left,
    Right: u16 = c.right,
    Value: u32 = c.value,
});

py_class!(BddDynamicRelocationData from peoxide_core::BddRelocation as (py, c) {
    r#struct: Py<BddDynamicRelocation> = Py::new(py, BddDynamicRelocation::new(py, c)?)?,
});

fn dynamic_relocation(py: Python<'_>, d: &peoxide_core::DynamicRelocation) -> PyResult<Py<PyAny>> {
    let r#struct = Py::new(py, DynamicRelocation::new(py, d)?)?.into_any();
    let symbol = d.symbol.into_py_any(py)?;
    match &d.kind {
        DynamicRelocationKind::Relocations(blocks) => DynamicRelocationData {
            r#struct,
            symbol,
            relocations: list(py, blocks, BaseRelocationData::new)?.into_any(),
        }
        .into_py_any(py),
        DynamicRelocationKind::FunctionOverride {
            func_relocs,
            bdd_relocs,
        } => FunctionOverrideData {
            r#struct,
            symbol,
            bdd_relocs: list(py, bdd_relocs, BddDynamicRelocationData::new)?.into_any(),
            func_relocs: list(py, func_relocs, FunctionOverrideDynamicRelocationData::new)?
                .into_any(),
        }
        .into_py_any(py),
    }
}

#[pyclass(frozen, module = "peoxide")]
pub(crate) struct LoadConfigData {
    #[pyo3(get, name = "struct")]
    structure: Py<LoadConfigDirectory>,
    load_config: LoadConfig,
    /// Built on first access: kernel images have tens of thousands of entries.
    dynamic_relocations: PyOnceLock<Option<Py<PyList>>>,
}

impl LoadConfigData {
    pub(crate) fn new(py: Python<'_>, load_config: LoadConfig) -> PyResult<Self> {
        let structure = Bound::new(py, LoadConfigDirectory {})?;
        for &(name, value) in &load_config.fields {
            structure.as_any().setattr(name, value)?;
        }
        Ok(LoadConfigData {
            structure: structure.unbind(),
            load_config,
            dynamic_relocations: PyOnceLock::new(),
        })
    }
}

#[pymethods]
impl LoadConfigData {
    /// `None` when the structure is too short to point at dynamic relocations, or they
    /// can't be read.
    #[getter]
    fn dynamic_relocations(&self, py: Python<'_>) -> PyResult<Option<Py<PyList>>> {
        self.dynamic_relocations
            .get_or_try_init(py, || {
                self.load_config
                    .dynamic_relocations
                    .as_ref()
                    .map(|d| list(py, d, dynamic_relocation))
                    .transpose()
            })
            .map(|d| d.as_ref().map(|d| d.clone_ref(py)))
    }
}
