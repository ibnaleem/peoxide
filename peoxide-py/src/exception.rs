use peoxide_core::{
    AllocLarge, Epilog, Exceptions, Trailer, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER,
    UNW_FLAG_UHANDLER, UnwindCode as Code, UnwindOp,
};
use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyList, PyWeakrefMethods, PyWeakrefReference};

use crate::missing;

#[pyclass(frozen, get_all, module = "peoxide")]
struct RuntimeFunction {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindData: u32,
}

/// Weak-referenceable so a chained `UnwindInfo` can point back at an entry without a
/// reference cycle: crafted files can chain an entry to itself.
#[pyclass(frozen, weakref, module = "peoxide")]
pub(crate) struct ExceptionsDirEntryData {
    #[pyo3(get, name = "struct")]
    structure: Py<RuntimeFunction>,
    #[pyo3(get)]
    unwindinfo: Option<Py<UnwindInfo>>,
}

#[pyclass(frozen, module = "peoxide")]
struct UnwindInfo {
    #[pyo3(get)]
    Version: u8,
    #[pyo3(get)]
    Flags: u8,
    #[pyo3(get)]
    SizeOfProlog: u8,
    #[pyo3(get)]
    CountOfCodes: u8,
    #[pyo3(get)]
    FrameRegister: u8,
    #[pyo3(get)]
    FrameOffset: u8,
    #[pyo3(get)]
    UNW_FLAG_EHANDLER: bool,
    #[pyo3(get)]
    UNW_FLAG_UHANDLER: bool,
    #[pyo3(get)]
    UNW_FLAG_CHAININFO: bool,
    codes: Option<Py<PyList>>,
    size_of_epilog: Option<u8>,
    exception_handler: Option<u32>,
    function_entry: Option<u32>,
    chained: PyOnceLock<Py<PyWeakrefReference>>,
}

fn defined<T>(value: Option<T>, name: &str) -> PyResult<T> {
    value.ok_or_else(|| PyAttributeError::new_err(name.to_owned()))
}

/// pefile sets these only on a record it read in full; elsewhere they raise AttributeError.
#[pymethods]
impl UnwindInfo {
    #[getter]
    fn UnwindCodes(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        missing(&self.codes, py, "UnwindCodes")
    }

    #[getter]
    fn SizeOfEpilog(&self) -> PyResult<u8> {
        defined(self.size_of_epilog, "SizeOfEpilog")
    }

    #[getter]
    fn ExceptionHandler(&self) -> PyResult<u32> {
        defined(self.exception_handler, "ExceptionHandler")
    }

    #[getter]
    fn FunctionEntry(&self) -> PyResult<u32> {
        defined(self.function_entry, "FunctionEntry")
    }

    /// The entry whose `BeginAddress` is `FunctionEntry`, or `None`. It is the same object as
    /// in `DIRECTORY_ENTRY_EXCEPTION`, and reads as `None` once that list is gone.
    fn get_chained_function_entry(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        let entry = self.chained.get(py)?.bind(py).upgrade()?;
        Some(entry.unbind())
    }
}

impl UnwindInfo {
    fn new(py: Python<'_>, info: &peoxide_core::UnwindInfo) -> PyResult<Self> {
        let body = info.body.as_ref();
        let trailer = body.and_then(|b| b.trailer.as_ref());
        Ok(UnwindInfo {
            Version: info.version,
            Flags: info.flags,
            SizeOfProlog: info.size_of_prolog,
            CountOfCodes: info.count_of_codes,
            FrameRegister: info.frame_register,
            FrameOffset: info.frame_offset,
            UNW_FLAG_EHANDLER: info.flags & UNW_FLAG_EHANDLER != 0,
            UNW_FLAG_UHANDLER: info.flags & UNW_FLAG_UHANDLER != 0,
            UNW_FLAG_CHAININFO: info.flags & UNW_FLAG_CHAININFO != 0,
            codes: body
                .map(|b| {
                    let codes = b
                        .codes
                        .iter()
                        .map(|c| unwind_code(py, c))
                        .collect::<PyResult<Vec<_>>>()?;
                    PyList::new(py, codes).map(Bound::unbind)
                })
                .transpose()?,
            size_of_epilog: body.and_then(|b| b.size_of_epilog),
            exception_handler: match trailer {
                Some(Trailer::ExceptionHandler(handler)) => Some(*handler),
                _ => None,
            },
            function_entry: match trailer {
                Some(Trailer::FunctionEntry { begin_address, .. }) => Some(*begin_address),
                _ => None,
            },
            chained: PyOnceLock::new(),
        })
    }
}

/// One Python class per pefile `PrologEpilogOp*` subclass, with its methods.
macro_rules! unwind_op {
    ($name:ident $(, $method:ident = $value:ident)?) => {
        #[pyclass(frozen, module = "peoxide")]
        struct $name {
            #[pyo3(get, name = "struct")]
            structure: Py<PyAny>,
            code: Code,
        }

        #[pymethods]
        impl $name {
            fn is_valid(&self) -> bool {
                self.code.is_valid()
            }

            fn __str__(&self) -> String {
                self.code.to_string()
            }

            $(fn $method(&self) -> u32 {
                self.code.$value().unwrap_or_default()
            })?
        }
    };
}

unwind_op!(PrologEpilogOpPushReg);
unwind_op!(PrologEpilogOpAllocLarge, get_alloc_size = alloc_size);
unwind_op!(PrologEpilogOpAllocSmall, get_alloc_size = alloc_size);
unwind_op!(PrologEpilogOpSetFP);
unwind_op!(PrologEpilogOpSaveReg, get_offset = offset);
unwind_op!(PrologEpilogOpSaveRegFar, get_offset = offset);
unwind_op!(PrologEpilogOpSaveXMM, get_offset = offset);
unwind_op!(PrologEpilogOpSaveXMMFar, get_offset = offset);
unwind_op!(PrologEpilogOpPushFrame);
unwind_op!(PrologEpilogOpEpilogMarker, get_offset = offset);

/// The `.struct` layouts, one per distinct set of pefile field names.
macro_rules! code_struct {
    ($($name:ident { $($field:ident: $ty:ty),* })*) => {
        $(
            #[pyclass(frozen, get_all, module = "peoxide")]
            struct $name { $($field: $ty),* }
        )*
    };
}

code_struct! {
    UnwindCodeStruct { CodeOffset: u8, UnwindOp: u8, OpInfo: u8 }
    UnwindCodeRegStruct { CodeOffset: u8, UnwindOp: u8, Reg: u8 }
    AllocLargeQwordsStruct { CodeOffset: u8, UnwindOp: u8, OpInfo: u8, AllocSizeInQwords: u16 }
    AllocLargeStruct { CodeOffset: u8, UnwindOp: u8, OpInfo: u8, AllocSize: u32 }
    AllocSmallStruct { CodeOffset: u8, UnwindOp: u8, AllocSizeInQwordsMinus8: u8 }
    SaveNonvolStruct { CodeOffset: u8, UnwindOp: u8, Reg: u8, OffsetInQwords: u16 }
    SaveXmm128Struct { CodeOffset: u8, UnwindOp: u8, Reg: u8, OffsetIn2Qwords: u16 }
    SaveFarStruct { CodeOffset: u8, UnwindOp: u8, Reg: u8, Offset: u32 }
    EpilogFirstStruct { OffsetLow: u8, Size: u8, UnwindOp: u8, Flags: u8 }
    EpilogFirstLongStruct {
        Size: u8, UnwindOp: u8, Flags: u8, OffsetLow: u8, Unused: u8, OffsetHigh: u8
    }
    EpilogStruct { OffsetLow: u8, UnwindOp: u8, OffsetHigh: u8 }
}

fn unwind_code(py: Python<'_>, c: &Code) -> PyResult<Py<PyAny>> {
    let code = *c;
    let (CodeOffset, UnwindOp, OpInfo) = (c.code_offset, c.unwind_op, c.op_info);
    macro_rules! build {
        ($class:ident, $structure:expr) => {{
            let structure = Py::new(py, $structure)?.into_any();
            Ok(Py::new(py, $class { structure, code })?.into_any())
        }};
    }
    let reg = UnwindCodeRegStruct {
        CodeOffset,
        UnwindOp,
        Reg: OpInfo,
    };
    let plain = UnwindCodeStruct {
        CodeOffset,
        UnwindOp,
        OpInfo,
    };
    let far = |Offset| SaveFarStruct {
        CodeOffset,
        UnwindOp,
        Reg: OpInfo,
        Offset,
    };
    match c.op {
        UnwindOp::PushNonvol => build!(PrologEpilogOpPushReg, reg),
        UnwindOp::AllocLarge(AllocLarge::Qwords(AllocSizeInQwords)) => build!(
            PrologEpilogOpAllocLarge,
            AllocLargeQwordsStruct {
                CodeOffset,
                UnwindOp,
                OpInfo,
                AllocSizeInQwords
            }
        ),
        UnwindOp::AllocLarge(AllocLarge::Bytes(AllocSize)) => build!(
            PrologEpilogOpAllocLarge,
            AllocLargeStruct {
                CodeOffset,
                UnwindOp,
                OpInfo,
                AllocSize
            }
        ),
        UnwindOp::AllocSmall => build!(
            PrologEpilogOpAllocSmall,
            AllocSmallStruct {
                CodeOffset,
                UnwindOp,
                AllocSizeInQwordsMinus8: OpInfo
            }
        ),
        UnwindOp::SetFpreg { .. } => build!(PrologEpilogOpSetFP, plain),
        UnwindOp::SaveNonvol { offset_in_qwords } => build!(
            PrologEpilogOpSaveReg,
            SaveNonvolStruct {
                CodeOffset,
                UnwindOp,
                Reg: OpInfo,
                OffsetInQwords: offset_in_qwords
            }
        ),
        UnwindOp::SaveNonvolFar { offset } => build!(PrologEpilogOpSaveRegFar, far(offset)),
        UnwindOp::SaveXmm128 { offset_in_2qwords } => build!(
            PrologEpilogOpSaveXMM,
            SaveXmm128Struct {
                CodeOffset,
                UnwindOp,
                Reg: OpInfo,
                OffsetIn2Qwords: offset_in_2qwords
            }
        ),
        UnwindOp::SaveXmm128Far { offset } => build!(PrologEpilogOpSaveXMMFar, far(offset)),
        UnwindOp::PushMachframe => build!(PrologEpilogOpPushFrame, plain),
        UnwindOp::Epilog { layout, .. } => match layout {
            Epilog::FirstShort => build!(
                PrologEpilogOpEpilogMarker,
                EpilogFirstStruct {
                    OffsetLow: CodeOffset,
                    Size: CodeOffset,
                    UnwindOp,
                    Flags: OpInfo
                }
            ),
            Epilog::FirstLong {
                offset_low,
                unused,
                offset_high,
            } => build!(
                PrologEpilogOpEpilogMarker,
                EpilogFirstLongStruct {
                    Size: CodeOffset,
                    UnwindOp,
                    Flags: OpInfo,
                    OffsetLow: offset_low,
                    Unused: unused,
                    OffsetHigh: offset_high
                }
            ),
            Epilog::Later => build!(
                PrologEpilogOpEpilogMarker,
                EpilogStruct {
                    OffsetLow: CodeOffset,
                    UnwindOp,
                    OffsetHigh: OpInfo
                }
            ),
        },
    }
}

/// `DIRECTORY_ENTRY_EXCEPTION`: entries sharing an unwind record share one `UnwindInfo`.
pub(crate) fn exception_entries(py: Python<'_>, e: &Exceptions) -> PyResult<Py<PyList>> {
    let infos = e
        .unwind_infos
        .iter()
        .map(|i| Py::new(py, UnwindInfo::new(py, i)?))
        .collect::<PyResult<Vec<_>>>()?;
    let entries = e
        .entries
        .iter()
        .map(|r| {
            let structure = RuntimeFunction {
                BeginAddress: r.begin_address,
                EndAddress: r.end_address,
                UnwindData: r.unwind_data,
            };
            Bound::new(
                py,
                ExceptionsDirEntryData {
                    structure: Py::new(py, structure)?,
                    unwindinfo: r.unwind_info.map(|i| infos[i].clone_ref(py)),
                },
            )
        })
        .collect::<PyResult<Vec<_>>>()?;
    for (info, core) in infos.iter().zip(&e.unwind_infos) {
        let chained = core.body.as_ref().and_then(|b| match b.trailer {
            Some(Trailer::FunctionEntry { chained, .. }) => chained,
            _ => None,
        });
        if let Some(i) = chained {
            let link = PyWeakrefReference::new(&entries[i])?.unbind();
            let _ = info.get().chained.set(py, link);
        }
    }
    Ok(PyList::new(py, entries)?.unbind())
}
