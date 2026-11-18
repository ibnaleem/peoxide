#![allow(non_snake_case)] // Python attribute names follow pefile (e_lfanew, NumberOfSections, ...)

use pyo3::create_exception;
use pyo3::exceptions::{PyAttributeError, PyException};
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
///
/// Fields hold finished Python objects, so PyO3 exposes them as struct members, which CPython
/// reads without calling into Rust or allocating. A `u32` field would build a new `int` on
/// every read.
macro_rules! py_class {
    (
        $(#[$meta:meta])*
        $name:ident $([$($option:ident),*])? from $core:ty as ($py:ident, $c:ident) {
            $($field:ident: $ty:ty = $value:expr),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[pyclass(frozen, get_all, module = "peoxide" $($(, $option)*)?)]
        pub(crate) struct $name { $($field: Py<PyAny>),* }

        impl $name {
            #[allow(unused_variables)]
            pub(crate) fn new($py: Python<'_>, $c: &$core) -> PyResult<Self> {
                Ok(Self { $($field: { let value: $ty = $value; value.into_py_any($py)? }),* })
            }
        }
    };
}

mod directories;
mod flags;
mod headers;
mod load_config;
mod pe;
mod resource;
mod section;
mod version;

use pe::PE;

/// Runs code that calls into the core parser, turning a panic into `PEFormatError`. A panic
/// would reach Python as PanicException, which slips past `except Exception`.
fn no_panic<T>(f: impl FnOnce() -> T) -> PyResult<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        PEFormatError::new_err(
            "internal peoxide error while reading this file; please report it, \
             with the file, at https://github.com/ibnaleem/peoxide/issues",
        )
    })
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

fn missing<T>(value: &Option<Py<T>>, py: Python<'_>, name: &str) -> PyResult<Py<T>> {
    value
        .as_ref()
        .map(|v| v.clone_ref(py))
        .ok_or_else(|| PyAttributeError::new_err(name.to_owned()))
}

fn hexdigest(py: Python<'_>, algorithm: &str, data: &[u8]) -> PyResult<String> {
    py.import("hashlib")?
        .call_method1("new", (algorithm, PyBytes::new(py, data)))?
        .call_method0("hexdigest")?
        .extract()
}

#[pymodule]
fn peoxide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    m.add("PEFormatError", m.py().get_type::<PEFormatError>())?;
    Ok(())
}
