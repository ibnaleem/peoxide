//! pefile's byte helpers on caller-supplied data: `get_*_from_data` and friends.

use pyo3::buffer::PyBuffer;
use pyo3::conversion::FromPyObjectOwned;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PySlice, PyType};

use crate::SaturatingI64;

/// `value` as an `i64`, pinned to the nearest end of the range like `SaturatingI64`.
pub(crate) fn saturating_i64(value: &Bound<'_, PyAny>) -> PyResult<i64> {
    value.extract::<SaturatingI64>().map(|SaturatingI64(v)| v)
}

/// pefile's `get_{word,dword,qword}_from_data`, with Python's slicing and `struct.unpack`
/// behaviour for negative indices: counted from the end, or `struct.error` on a short slice.
pub(crate) fn uint_from_data(
    data: &Bound<'_, PyAny>,
    offset: &Bound<'_, PyAny>,
    size: usize,
) -> PyResult<Option<u64>> {
    let len = data.len()? as i128;
    let index = i128::from(saturating_i64(offset)?);
    let size_i = size as i128;
    if (index + 1) * size_i > len {
        return Ok(None);
    }
    let python_index = |i: i128| (if i < 0 { i + len } else { i }).clamp(0, len) as usize;
    let (start, end) = (
        python_index(index * size_i),
        python_index((index + 1) * size_i),
    );
    let end = end.max(start);
    let read = |chunk: &[u8]| {
        (chunk.len() == size).then(|| {
            chunk
                .iter()
                .rev()
                .fold(0, |value, &byte| (value << 8) | u64::from(byte))
        })
    };
    let value = match data.cast::<PyBytes>() {
        Ok(bytes) => read(bytes.as_bytes().get(start..end).unwrap_or_default()),
        Err(_) => {
            PyBuffer::<u8>::get(data)
                .map_err(|_| PyTypeError::new_err("a bytes-like object is required"))?;
            // Copy only the slice read: a whole-buffer copy made each call O(len).
            let py = data.py();
            let slice = data.get_item(PySlice::new(py, start as isize, end as isize, 1))?;
            let chunk = py
                .get_type::<PyBytes>()
                .call1((slice,))?
                .cast_into::<PyBytes>()?;
            read(chunk.as_bytes())
        }
    };
    match value {
        Some(value) => Ok(Some(value)),
        None => Err(struct_error(
            data.py(),
            format!("unpack requires a buffer of {size} bytes"),
        )),
    }
}

/// pefile's `get_bytes_from_data`, through Python's own comparison and slicing.
pub(crate) fn bytes_from_data<'py>(
    offset: &Bound<'py, PyAny>,
    data: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let py = data.py();
    if offset.gt(data.len()?)? {
        return Ok(PyBytes::new(py, b"").into_any());
    }
    let tail = data.get_item(slice(py, offset, py.None().bind(py))?)?;
    if tail.is_instance_of::<PyByteArray>() {
        return py.get_type::<PyBytes>().call1((tail,));
    }
    Ok(tail)
}

/// `slice(start, stop)` for any Python objects, so big integers keep their meaning.
pub(crate) fn slice<'py>(
    py: Python<'py>,
    start: &Bound<'py, PyAny>,
    stop: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    py.get_type::<PySlice>().call1((start, stop))
}

/// `value` as `T`, raising `struct.error` as `struct.pack` does when it does not fit.
pub(crate) fn extract_packable<'py, T: FromPyObjectOwned<'py>>(
    value: &Bound<'py, PyAny>,
) -> PyResult<T> {
    value
        .extract::<T>()
        .map_err(|e| struct_error(value.py(), Into::<PyErr>::into(e).to_string()))
}

pub(crate) fn struct_error(py: Python<'_>, message: String) -> PyErr {
    match py
        .import("struct")
        .and_then(|module| module.getattr("error"))
        .and_then(|error| error.cast_into::<PyType>().map_err(Into::into))
    {
        Ok(error) => PyErr::from_type(error, message),
        Err(e) => e,
    }
}
