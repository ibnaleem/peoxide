#![allow(non_snake_case)] // Python attribute names follow pefile (e_lfanew, NumberOfSections, ...)

use pyo3::IntoPyObjectExt;
use pyo3::buffer::PyBuffer;
use pyo3::create_exception;
use pyo3::exceptions::{PyAttributeError, PyException, PyOSError, PyOverflowError, PyTypeError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

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
mod resource;
mod section;

use directories::{BaseRelocationData, DebugData, ExportDirData, ImportDescData, RichHeader};
use flags::{DLL_CHARACTERISTICS_FLAGS, IMAGE_FILE_FLAGS, SECTION_FLAGS, with_flags};
use headers::{DosHeader, FileHeader, NtHeaders, OptionalHeader};
use resource::ResourceDirData;
use section::Section;

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

/// The file's contents, read into the `bytes` object itself so the file is held only once.
fn read_file<'py>(py: Python<'py>, path: &std::path::Path) -> PyResult<Bound<'py, PyBytes>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        // A pipe or device reports no length, so it is read to its end instead.
        let mut contents = Vec::new();
        py.detach(|| file.read_to_end(&mut contents))?;
        return Ok(PyBytes::new(py, &contents));
    }
    let len = usize::try_from(metadata.len())
        .map_err(|_| PyOSError::new_err("file is too large to load"))?;
    PyBytes::new_with(py, len, |buffer| {
        py.detach(|| file.read_exact(buffer))?;
        Ok(())
    })
}

/// `data` as `bytes`. Other bytes-like objects (`bytearray`, `mmap`, `memoryview`) are copied
/// once, because the parser runs without the GIL and they could change or shrink under it.
fn immutable_bytes(data: Bound<'_, PyAny>) -> PyResult<Bound<'_, PyBytes>> {
    let data = match data.cast_into::<PyBytes>() {
        Ok(bytes) => return Ok(bytes),
        Err(e) => e.into_inner(),
    };
    PyBuffer::<u8>::get(&data)
        .map_err(|_| PyTypeError::new_err("data must be bytes or another bytes-like object"))?;
    data.py()
        .get_type::<PyBytes>()
        .call1((data,))?
        .cast_into()
        .map_err(Into::into)
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
struct VersionLists {
    vs_versioninfo: Option<Py<PyList>>,
    vs_fixedfileinfo: Option<Py<PyList>>,
    file_info: Option<Py<PyList>>,
}

impl VersionLists {
    fn new(py: Python<'_>, v: &peoxide_core::Version) -> PyResult<Self> {
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
    /// Built on first access, like everything below held in a `PyOnceLock`. A large DLL has
    /// thousands of imports and exports, and building their Python objects took about a third
    /// of `PE()`, all of it with the GIL held.
    imports: PyOnceLock<Py<PyList>>,
    exports: PyOnceLock<Py<ExportDirData>>,
    delay_imports: PyOnceLock<Py<PyList>>,
    #[pyo3(get)]
    DIRECTORY_ENTRY_DEBUG: Py<PyList>,
    #[pyo3(get)]
    RICH_HEADER: Option<Py<RichHeader>>,
    relocations: PyOnceLock<Py<PyList>>,
    resources: PyOnceLock<Option<Py<ResourceDirData>>>,
    version: VersionLists,
    pe: peoxide_core::Pe,
    data: Py<PyBytes>,
}

#[pymethods]
impl PE {
    /// Parse a PE file from a path (`name`) or from in-memory bytes (`data`).
    ///
    /// `fast_load` is accepted so pefile code runs unchanged, and ignored: nothing is gained by
    /// skipping directories that are parsed this quickly or built only when first read.
    #[new]
    #[pyo3(signature = (name=None, data=None, fast_load=None))]
    fn new(
        py: Python<'_>,
        name: Option<std::path::PathBuf>,
        data: Option<Bound<'_, PyAny>>,
        fast_load: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let _ = fast_load;
        let data = match (name, data) {
            (Some(path), None) => read_file(py, &path)?,
            (None, Some(data)) => immutable_bytes(data)?,
            _ => {
                return Err(PyTypeError::new_err(
                    "PE() takes exactly one of name or data",
                ));
            }
        };
        // A panic would reach Python as PanicException, which slips past `except Exception`.
        let bytes = data.as_bytes();
        // `bytes` cannot change under the parser, so other Python threads may run meanwhile.
        let pe = py
            .detach(|| std::panic::catch_unwind(|| peoxide_core::parse(bytes)))
            .map_err(|_| {
                PEFormatError::new_err(
                    "internal peoxide error while parsing this file; please report it, \
                     with the file, at https://github.com/ibnaleem/peoxide/issues",
                )
            })?
            .map_err(|e| PEFormatError::new_err(e.to_string()))?;
        let h = &pe.headers;

        Ok(PE {
            DOS_HEADER: Py::new(py, DosHeader::new(py, &h.dos_header)?)?,
            NT_HEADERS: Py::new(py, NtHeaders::new(py, h)?)?,
            FILE_HEADER: with_flags(
                py,
                FileHeader::new(py, &h.file_header)?,
                IMAGE_FILE_FLAGS,
                h.file_header.characteristics.into(),
            )?,
            OPTIONAL_HEADER: with_flags(
                py,
                OptionalHeader::new(py, &h.optional_header)?,
                DLL_CHARACTERISTICS_FLAGS,
                h.optional_header.dll_characteristics.into(),
            )?,
            sections: PyList::new(
                py,
                pe.sections
                    .iter()
                    .zip(&pe.layouts)
                    .map(|(table, layout)| {
                        let section = Section::new(py, table, *layout, &data)?;
                        with_flags(py, section, SECTION_FLAGS, table.characteristics)
                    })
                    .collect::<PyResult<Vec<_>>>()?,
            )?
            .unbind(),
            imports: PyOnceLock::new(),
            exports: PyOnceLock::new(),
            delay_imports: PyOnceLock::new(),
            DIRECTORY_ENTRY_DEBUG: list(py, &pe.debug, DebugData::new)?,
            RICH_HEADER: pe
                .rich_header
                .as_ref()
                .map(|r| Py::new(py, RichHeader::new(py, r)?))
                .transpose()?,
            relocations: PyOnceLock::new(),
            resources: PyOnceLock::new(),
            version: VersionLists::new(py, &pe.version)?,
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
        let file = self.data.as_bytes(py);
        let data = no_panic(|| self.pe.data_range(rva, length).map(|range| &file[range]))?
            .ok_or_else(|| {
                PEFormatError::new_err("data at RVA can't be fetched. Corrupt header?")
            })?;
        Ok(PyBytes::new(py, data))
    }

    fn get_offset_from_rva(&self, rva: i64) -> PyResult<i64> {
        no_panic(|| self.pe.offset_from_rva(rva))?.ok_or_else(|| {
            PEFormatError::new_err(format!("data at RVA 0x{rva:x} can't be fetched"))
        })
    }

    /// `None` when the offset is past the start of the first section but in none of them.
    fn get_rva_from_offset(&self, offset: i64) -> PyResult<Option<i64>> {
        no_panic(|| self.pe.rva_from_offset(offset))
    }

    fn get_section_by_rva<'py>(
        &self,
        py: Python<'py>,
        rva: i64,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let index = no_panic(|| self.pe.section_by_rva(rva))?;
        index
            .map(|i| self.sections.bind(py).get_item(i))
            .transpose()
    }

    fn get_section_by_offset<'py>(
        &self,
        py: Python<'py>,
        offset: i64,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let index = no_panic(|| self.pe.section_by_offset(offset))?;
        index
            .map(|i| self.sections.bind(py).get_item(i))
            .transpose()
    }

    /// Offset of data appended past everything the headers describe, or `None`.
    fn get_overlay_data_start_offset(&self) -> PyResult<Option<usize>> {
        no_panic(|| self.pe.overlay_offset())
    }

    /// The appended data itself, or `None`.
    fn get_overlay<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let file = self.data.as_bytes(py);
        let overlay = no_panic(|| self.pe.overlay_offset().map(|offset| &file[offset..]))?;
        Ok(overlay.map(|data| PyBytes::new(py, data)))
    }

    /// pefile's imphash: a hash of the lowercase `dll.function` import list, or `""` when
    /// nothing is imported. MD5 by default, which is what other tools exchange; pass any
    /// `hashlib` algorithm name, such as `"sha256"`, for a different digest of the same input.
    #[pyo3(signature = (algorithm="md5"))]
    fn get_imphash(&self, py: Python<'_>, algorithm: &str) -> PyResult<String> {
        no_panic(|| self.pe.imphash_input())?.map_or(Ok(String::new()), |input| {
            hexdigest(py, algorithm, input.as_bytes())
        })
    }

    /// Like `get_imphash`, over the lowercase names of the named exports.
    #[pyo3(signature = (algorithm="md5"))]
    fn get_exphash(&self, py: Python<'_>, algorithm: &str) -> PyResult<String> {
        no_panic(|| self.pe.exphash_input())?.map_or(Ok(String::new()), |input| {
            hexdigest(py, algorithm, input.as_bytes())
        })
    }

    /// A hash of `RICH_HEADER.clear_data`, or `""` when the file has no Rich header.
    #[pyo3(signature = (algorithm="md5"))]
    fn get_rich_header_hash(&self, py: Python<'_>, algorithm: &str) -> PyResult<String> {
        self.pe.rich_header.as_ref().map_or(Ok(String::new()), |r| {
            hexdigest(py, algorithm, &r.clear_data)
        })
    }

    /// Imported DLLs, empty when the file imports nothing.
    #[getter]
    fn DIRECTORY_ENTRY_IMPORT(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        self.imports
            .get_or_try_init(py, || list(py, &self.pe.imports, ImportDescData::new))
            .map(|l| l.clone_ref(py))
    }

    /// The export directory, with an empty `symbols` list when the file exports nothing.
    #[getter]
    fn DIRECTORY_ENTRY_EXPORT(&self, py: Python<'_>) -> PyResult<Py<ExportDirData>> {
        self.exports
            .get_or_try_init(py, || {
                Py::new(py, ExportDirData::new(py, &self.pe.exports)?)
            })
            .map(|e| e.clone_ref(py))
    }

    /// Delay-loaded DLLs, empty when the file has none.
    #[getter]
    fn DIRECTORY_ENTRY_DELAY_IMPORT(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        self.delay_imports
            .get_or_try_init(py, || list(py, &self.pe.delay_imports, ImportDescData::new))
            .map(|l| l.clone_ref(py))
    }

    /// Base relocation blocks, empty when the file has none.
    #[getter]
    fn DIRECTORY_ENTRY_BASERELOC(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        self.relocations
            .get_or_try_init(py, || {
                let blocks = no_panic(|| self.pe.parse_relocations(self.data.as_bytes(py)))?;
                list(py, &blocks, BaseRelocationData::new)
            })
            .map(|l| l.clone_ref(py))
    }

    /// The resource tree's root, or `None` when the file has no readable resource directory.
    /// Built on first access.
    #[getter]
    fn DIRECTORY_ENTRY_RESOURCE(&self, py: Python<'_>) -> PyResult<Option<Py<ResourceDirData>>> {
        self.resources
            .get_or_try_init(py, || {
                no_panic(|| {
                    self.pe
                        .resources
                        .as_ref()
                        .map(|r| Py::new(py, ResourceDirData::new(py, r)?))
                        .transpose()
                })?
            })
            .map(|r| r.as_ref().map(|r| r.clone_ref(py)))
    }

    /// Missing, as in pefile, when the file has no readable version information.
    #[getter]
    fn VS_VERSIONINFO(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        missing(&self.version.vs_versioninfo, py, "VS_VERSIONINFO")
    }

    #[getter]
    fn VS_FIXEDFILEINFO(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        missing(&self.version.vs_fixedfileinfo, py, "VS_FIXEDFILEINFO")
    }

    /// One list of StringFileInfo/VarFileInfo blocks per version resource.
    #[getter]
    fn FileInfo(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        missing(&self.version.file_info, py, "FileInfo")
    }

    /// Does nothing: the directories are already parsed. Here for pefile code that loads
    /// with `fast_load=True` and then asks for the directories it wants.
    #[pyo3(signature = (directories=None, forwarded_exports_only=None, import_dllnames_only=None))]
    fn parse_data_directories(
        &self,
        directories: Option<&Bound<'_, PyAny>>,
        forwarded_exports_only: Option<&Bound<'_, PyAny>>,
        import_dllnames_only: Option<&Bound<'_, PyAny>>,
    ) {
        let _ = (directories, forwarded_exports_only, import_dllnames_only);
    }

    /// Does nothing, for the same reason as `parse_data_directories`.
    fn full_load(&self) {}

    /// Does nothing: no file handle or mapping is kept open. Here for pefile code that closes
    /// its PE objects, directly or through `with`.
    fn close(&self) {}

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, _args: &Bound<'_, PyTuple>) {}

    /// The whole file, as `bytes`.
    #[getter]
    fn __data__(&self, py: Python<'_>) -> Py<PyBytes> {
        self.data.clone_ref(py)
    }

    /// The little-endian 16-bit value at an RVA, or `None` when it can't be read
    /// or the RVA is negative.
    fn get_word_at_rva(&self, rva: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
        self.uint_at_rva(rva, 2)
    }

    /// The little-endian 32-bit value at an RVA, or `None` when it can't be read
    /// or the RVA is negative.
    fn get_dword_at_rva(&self, rva: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
        self.uint_at_rva(rva, 4)
    }

    /// The little-endian 64-bit value at an RVA, or `None` when it can't be read
    /// or the RVA is negative.
    fn get_qword_at_rva(&self, rva: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
        self.uint_at_rva(rva, 8)
    }

    /// The little-endian 16-bit value at a file offset, or `None` past the end of the file
    /// or for a negative offset.
    fn get_word_from_offset(&self, offset: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
        self.uint_at_offset(offset, 2)
    }

    /// The little-endian 32-bit value at a file offset, or `None` past the end of the file
    /// or for a negative offset.
    fn get_dword_from_offset(&self, offset: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
        self.uint_at_offset(offset, 4)
    }

    /// The little-endian 64-bit value at a file offset, or `None` past the end of the file
    /// or for a negative offset.
    fn get_qword_from_offset(&self, offset: &Bound<'_, PyAny>) -> PyResult<Option<u64>> {
        self.uint_at_offset(offset, 8)
    }

    /// The bytes at an RVA up to the first NUL, reading at most `max_length` bytes (pefile's
    /// `MAX_STRING_LENGTH` when omitted). An RVA outside every section is read as a file
    /// offset, as pefile does. `None` for a negative RVA, or when `rva` is `None`.
    #[pyo3(signature = (rva, max_length=None))]
    fn get_string_at_rva<'py>(
        &self,
        py: Python<'py>,
        rva: Option<&Bound<'py, PyAny>>,
        max_length: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let rva = rva.map(saturating_i64).transpose()?;
        let Some(rva) = rva.filter(|&rva| rva >= 0) else {
            return Ok(None);
        };
        let max_length = max_length.map_or(Ok(MAX_STRING_LENGTH), saturating_i64)?;
        let file = self.data.as_bytes(py);
        let string = no_panic(|| self.pe.string_at_rva(file, rva, max_length))?;
        Ok(Some(PyBytes::new(py, string)))
    }

    /// The checksum Windows expects in `OPTIONAL_HEADER.CheckSum` for this file.
    fn generate_checksum(&self, py: Python<'_>) -> PyResult<u64> {
        let file = self.data.as_bytes(py);
        no_panic(|| py.detach(|| self.pe.checksum(file)))
    }

    /// True when `OPTIONAL_HEADER.CheckSum` holds the checksum of this file.
    fn verify_checksum(&self, py: Python<'_>) -> PyResult<bool> {
        let stored = u64::from(self.pe.headers.optional_header.checksum);
        Ok(self.generate_checksum(py)? == stored)
    }

    /// True for a standard executable: not a DLL, not a driver, and marked executable.
    fn is_exe(&self) -> PyResult<bool> {
        no_panic(|| self.pe.is_exe())
    }

    /// True when FILE_HEADER has IMAGE_FILE_DLL set.
    fn is_dll(&self) -> PyResult<bool> {
        no_panic(|| self.pe.is_dll())
    }

    /// True when the image imports a kernel DLL, or has a PAGE section and a native subsystem.
    fn is_driver(&self) -> PyResult<bool> {
        no_panic(|| self.pe.is_driver())
    }
}

/// pefile's `MAX_STRING_LENGTH`.
const MAX_STRING_LENGTH: i64 = 0x100000;

impl PE {
    /// `None` for a negative RVA. pefile would read from the end of the headers or the file.
    fn uint_at_rva(&self, rva: &Bound<'_, PyAny>, size: usize) -> PyResult<Option<u64>> {
        let file = self.data.as_bytes(rva.py());
        let rva = saturating_i64(rva)?;
        if rva < 0 {
            return Ok(None);
        }
        no_panic(|| self.pe.uint_at_rva(file, rva, size))
    }

    /// `None` for a negative offset. pefile would count that from the end of the file.
    fn uint_at_offset(&self, offset: &Bound<'_, PyAny>, size: usize) -> PyResult<Option<u64>> {
        let file = self.data.as_bytes(offset.py());
        let Ok(start) = usize::try_from(saturating_i64(offset)?) else {
            return Ok(None);
        };
        Ok(peoxide_core::uint_at_offset(file, start, size))
    }
}

/// A Python integer as an `i64`, pinned to the nearest end of the range when it does not fit.
/// No address or length that large can be inside a file, so the caller treats it as out of
/// range, where an `OverflowError` would surprise code written for pefile.
fn saturating_i64(value: &Bound<'_, PyAny>) -> PyResult<i64> {
    match value.extract::<i64>() {
        Err(e) if e.is_instance_of::<PyOverflowError>(value.py()) => {
            Ok(if value.lt(0)? { i64::MIN } else { i64::MAX })
        }
        other => other,
    }
}

#[pymodule]
fn peoxide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    m.add("PEFormatError", m.py().get_type::<PEFormatError>())?;
    Ok(())
}
