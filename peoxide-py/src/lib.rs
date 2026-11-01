use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
mod peoxide {
    use pyo3::prelude::*;

    #[pyclass(frozen, get_all, skip_from_py_object)] // frozen = read-only, get_all = a getter per field
    #[derive(Clone)]
    struct DosHeader { e_magic: u16, e_lfanew: u32 }

    #[pyclass(frozen)]
    struct PE {
        #[pyo3(get, name= "DOS_HEADER")]
        dos_header: DosHeader,
    }

    #[pymethods]
    impl PE {
        #[new]
        fn new(path: &str) -> PyResult<Self> {
            let data = std::fs::read(path)?;
            let core = peoxide_core::parse(&data).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            Ok(PE {
                dos_header: DosHeader {
                    e_magic: core.dos_header.e_magic,
                    e_lfanew: core.dos_header.e_lfanew,
                }
            })
            
        }
    }

}
