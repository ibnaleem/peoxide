//! The exception directory: RUNTIME_FUNCTIONs and their UNWIND_INFO, following pefile's
//! `parse_exceptions_directory` and its `UnwindInfo` and `PrologEpilogOp*` classes.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

use crate::Pe;

const EXCEPTION_DIRECTORY: usize = 3;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_IA64: u16 = 0x200;
const RUNTIME_FUNCTION_SIZE: u32 = 12;
const UNWIND_HEADER_SIZE: usize = 4;
const UNWIND_CODE_SIZE: usize = 2;
const HANDLER_SIZE: usize = 4;
/// pefile reads `Size // 12` entries with no limit. Real images stay far below this: shell32,
/// one of the largest system DLLs, has about 23,000.
const MAX_RUNTIME_FUNCTIONS: u32 = 1 << 20;
/// Unwind codes across all records, where pefile has no limit either. Each record holds at
/// most 255, but a few MB of crafted records can be shared out to millions of entries. The
/// most in System32 is about 193,000 (nvidia-pcc.exe).
const MAX_UNWIND_CODES: usize = 1 << 21;

pub const UNW_FLAG_EHANDLER: u8 = 0x01;
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

const REGISTERS: [&str; 16] = [
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13",
    "R14", "R15",
];

#[derive(Default)]
pub struct Exceptions {
    pub entries: Vec<RuntimeFunction>,
    /// One per distinct `UnwindData` RVA: pefile shares an `UnwindInfo` between the entries
    /// that point at the same record.
    pub unwind_infos: Vec<UnwindInfo>,
}

pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
    /// Index into `Exceptions::unwind_infos`. `None` when bit 0 of `unwind_data` is set.
    pub unwind_info: Option<usize>,
}

pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    /// `None` when the record runs past the readable data. pefile then keeps only the header,
    /// without checking its version.
    pub body: Option<UnwindBody>,
}

pub struct UnwindBody {
    pub codes: Vec<UnwindCode>,
    /// The first epilog code's size, which pefile stores on the `UnwindInfo`.
    pub size_of_epilog: Option<u8>,
    pub trailer: Option<Trailer>,
}

/// The DWORD after the codes. pefile names it after the flags, chained info winning.
pub enum Trailer {
    ExceptionHandler(u32),
    FunctionEntry {
        /// The chained RUNTIME_FUNCTION's `BeginAddress`.
        begin_address: u32,
        /// The last entry with that `BeginAddress`, the one pefile links.
        chained: Option<usize>,
    },
}

/// One decoded unwind code. Every layout starts with the same two bytes: `code_offset`, then
/// `unwind_op` in the low nibble and `op_info` in the high one. pefile names those fields
/// differently per operation (an epilog's first byte is `OffsetLow` or `Size`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnwindCode {
    pub code_offset: u8,
    pub unwind_op: u8,
    pub op_info: u8,
    pub op: UnwindOp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindOp {
    PushNonvol,
    AllocLarge(AllocLarge),
    AllocSmall,
    SetFpreg {
        frame_register: u8,
        /// The header's FrameOffset times 16.
        frame_offset: u32,
    },
    SaveNonvol {
        offset_in_qwords: u16,
    },
    SaveNonvolFar {
        offset: u32,
    },
    SaveXmm128 {
        offset_in_2qwords: u16,
    },
    SaveXmm128Far {
        offset: u32,
    },
    PushMachframe,
    Epilog {
        layout: Epilog,
        /// The record's `SizeOfEpilog`, taken from its first epilog code.
        epilog_size: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocLarge {
    /// OpInfo 0: a 16-bit count of quadwords.
    Qwords(u16),
    /// Any other OpInfo: a 32-bit byte count.
    Bytes(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epilog {
    /// The record's first epilog, OpInfo odd: `code_offset` is both `Size` and `OffsetLow`.
    FirstShort,
    /// The record's first epilog, OpInfo even: `code_offset` is `Size`, and a second slot
    /// holds the offset.
    FirstLong {
        offset_low: u8,
        unused: u8,
        offset_high: u8,
    },
    /// A later epilog: `code_offset` is `OffsetLow`, `op_info` is `OffsetHigh`.
    Later,
}

impl UnwindCode {
    /// pefile's `get_alloc_size()`, for the two ALLOC operations.
    pub fn alloc_size(&self) -> Option<u32> {
        match self.op {
            UnwindOp::AllocLarge(AllocLarge::Qwords(qwords)) => Some(u32::from(qwords) * 8),
            UnwindOp::AllocLarge(AllocLarge::Bytes(bytes)) => Some(bytes),
            UnwindOp::AllocSmall => Some(u32::from(self.op_info) * 8 + 8),
            _ => None,
        }
    }

    /// pefile's `get_offset()`, for the SAVE operations and epilogs.
    pub fn offset(&self) -> Option<u32> {
        match self.op {
            UnwindOp::SaveNonvol { offset_in_qwords } => Some(u32::from(offset_in_qwords) * 8),
            UnwindOp::SaveXmm128 { offset_in_2qwords } => Some(u32::from(offset_in_2qwords) * 16),
            UnwindOp::SaveNonvolFar { offset } | UnwindOp::SaveXmm128Far { offset } => Some(offset),
            UnwindOp::Epilog { layout, .. } => Some(match layout {
                Epilog::FirstShort => u32::from(self.code_offset),
                Epilog::FirstLong {
                    offset_low,
                    offset_high,
                    ..
                } => u32::from(offset_low) | u32::from(offset_high) << 8,
                Epilog::Later => u32::from(self.code_offset) | u32::from(self.op_info) << 8,
            }),
            _ => None,
        }
    }

    /// pefile's `is_valid()`: false only for an epilog with offset 0, which ends the list.
    pub fn is_valid(&self) -> bool {
        !matches!(self.op, UnwindOp::Epilog { .. }) || self.offset().is_some_and(|o| o > 0)
    }
}

/// pefile's `str()` of the operation.
impl fmt::Display for UnwindCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let register = REGISTERS[usize::from(self.op_info & 0xF)];
        let offset = self.offset().unwrap_or_default();
        match self.op {
            UnwindOp::PushNonvol => write!(f, ".PUSHREG {register}"),
            UnwindOp::AllocLarge(_) | UnwindOp::AllocSmall => {
                write!(
                    f,
                    ".ALLOCSTACK {:#x}",
                    self.alloc_size().unwrap_or_default()
                )
            }
            UnwindOp::SetFpreg {
                frame_register,
                frame_offset,
            } => write!(
                f,
                ".SETFRAME {}, {frame_offset:#x}",
                REGISTERS[usize::from(frame_register & 0xF)]
            ),
            UnwindOp::SaveNonvol { .. } | UnwindOp::SaveNonvolFar { .. } => {
                write!(f, ".SAVEREG {register}, {offset:#x}")
            }
            UnwindOp::SaveXmm128 { .. } | UnwindOp::SaveXmm128Far { .. } => {
                write!(f, ".SAVEXMM128 XMM{}, {offset:#x}", self.op_info)
            }
            UnwindOp::PushMachframe => {
                let code = if self.op_info != 0 { " <code>" } else { "" };
                write!(f, ".PUSHFRAME{code}")
            }
            UnwindOp::Epilog { epilog_size, .. } if offset > 0 => write!(
                f,
                "EPILOG: size={epilog_size:#x}, offset from the end=-{offset:#x}"
            ),
            UnwindOp::Epilog { .. } => Ok(()),
        }
    }
}

/// Why pefile stopped reading the directory.
enum Stop {
    /// It raised `PEFormatError`, which leaves `DIRECTORY_ENTRY_EXCEPTION` undefined.
    Raise,
    /// It broke out of the loop, keeping the entries read so far.
    Break,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The codes of a record whose bytes, header included, are all in `record`.
fn unwind_codes(record: &[u8], header: &UnwindInfo) -> Result<(Vec<UnwindCode>, Option<u8>), Stop> {
    let mut codes = Vec::with_capacity(usize::from(header.count_of_codes));
    let mut size_of_epilog = None;
    let mut at = UNWIND_HEADER_SIZE;
    let mut left = usize::from(header.count_of_codes);
    // Each code takes at least one slot, so this runs at most 255 times.
    while left > 0 {
        let slot = record.get(at..at + UNWIND_CODE_SIZE).ok_or(Stop::Raise)?;
        let (code_offset, unwind_op, op_info) = (slot[0], slot[1] & 0xF, slot[1] >> 4);
        let slots = match unwind_op {
            1 if op_info == 0 => 2,
            1 | 5 | 9 => 3,
            4 | 8 => 2,
            6 if size_of_epilog.is_none() && op_info & 1 == 0 => 2,
            0 | 2 | 3 | 6 | 10 => 1,
            _ => return Err(Stop::Break),
        };
        let bytes = record
            .get(at..at + slots * UNWIND_CODE_SIZE)
            .ok_or(Stop::Raise)?;
        let op = match unwind_op {
            0 => UnwindOp::PushNonvol,
            1 if op_info == 0 => UnwindOp::AllocLarge(AllocLarge::Qwords(u16_at(bytes, 2))),
            1 => UnwindOp::AllocLarge(AllocLarge::Bytes(u32_at(bytes, 2))),
            2 => UnwindOp::AllocSmall,
            3 => UnwindOp::SetFpreg {
                frame_register: header.frame_register,
                frame_offset: u32::from(header.frame_offset) * 16,
            },
            4 => UnwindOp::SaveNonvol {
                offset_in_qwords: u16_at(bytes, 2),
            },
            5 => UnwindOp::SaveNonvolFar {
                offset: u32_at(bytes, 2),
            },
            8 => UnwindOp::SaveXmm128 {
                offset_in_2qwords: u16_at(bytes, 2),
            },
            9 => UnwindOp::SaveXmm128Far {
                offset: u32_at(bytes, 2),
            },
            10 => UnwindOp::PushMachframe,
            _ => {
                let layout = match size_of_epilog {
                    Some(_) => Epilog::Later,
                    None if op_info & 1 == 1 => Epilog::FirstShort,
                    None => Epilog::FirstLong {
                        offset_low: bytes[2],
                        unused: bytes[3] & 0xF,
                        offset_high: bytes[3] >> 4,
                    },
                };
                let epilog_size = *size_of_epilog.get_or_insert(code_offset);
                UnwindOp::Epilog {
                    layout,
                    epilog_size,
                }
            }
        };
        codes.push(UnwindCode {
            code_offset,
            unwind_op,
            op_info,
            op,
        });
        at += slots * UNWIND_CODE_SIZE;
        left = left.saturating_sub(slots);
    }
    Ok((codes, size_of_epilog))
}

impl Pe {
    /// pefile's `get_data` (`None` where it raises), after checking that pefile's
    /// `get_offset_from_rva` of the same RVA would not raise either.
    fn read_with_offset<'a>(&self, data: &'a [u8], rva: i64, length: i64) -> Option<&'a [u8]> {
        self.offset_from_rva(rva)?;
        self.read(data, rva, length)
    }

    /// pefile's `UnwindInfo.unpack_in_stages`, called twice on a new record.
    fn unwind_info(&self, data: &[u8], rva: u32) -> Result<UnwindInfo, Stop> {
        let rva = i64::from(rva);
        let header = self
            .read_with_offset(data, rva, UNWIND_HEADER_SIZE as i64)
            .filter(|h| h.len() == UNWIND_HEADER_SIZE)
            .ok_or(Stop::Raise)?;
        let mut info = UnwindInfo {
            version: header[0] & 0x7,
            flags: header[0] >> 3,
            size_of_prolog: header[1],
            count_of_codes: header[2],
            frame_register: header[3] & 0xF,
            frame_offset: header[3] >> 4,
            body: None,
        };
        let handler_at = UNWIND_HEADER_SIZE
            + usize::from(info.count_of_codes).div_ceil(2) * 2 * UNWIND_CODE_SIZE;
        let full_size = handler_at + if info.flags == 0 { 0 } else { HANDLER_SIZE };
        let record = self.read(data, rva, full_size as i64).ok_or(Stop::Raise)?;
        if record.len() < full_size {
            return Ok(info);
        }
        if info.version != 1 && info.version != 2 {
            return Err(Stop::Break);
        }
        let (codes, size_of_epilog) = unwind_codes(record, &info)?;
        let handler = || u32_at(record, handler_at);
        let trailer = if info.flags & UNW_FLAG_CHAININFO != 0 {
            Some(Trailer::FunctionEntry {
                begin_address: handler(),
                chained: None,
            })
        } else if info.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            Some(Trailer::ExceptionHandler(handler()))
        } else {
            None
        };
        info.body = Some(UnwindBody {
            codes,
            size_of_epilog,
            trailer,
        });
        Ok(info)
    }

    /// The exception directory of `data`, the file this `Pe` was parsed from. Empty where
    /// pefile leaves `DIRECTORY_ENTRY_EXCEPTION` undefined: machines other than AMD64 and
    /// IA64, no directory, or a read that makes pefile raise.
    ///
    /// `parse` leaves this out. A large x64 DLL has tens of thousands of entries.
    pub fn parse_exceptions(&self, data: &[u8]) -> Exceptions {
        let machine = self.headers.file_header.machine;
        let directory = self
            .headers
            .optional_header
            .data_directory
            .get(EXCEPTION_DIRECTORY);
        match directory {
            Some(d)
                if d.virtual_address != 0 && [MACHINE_AMD64, MACHINE_IA64].contains(&machine) =>
            {
                self.read_exceptions(data, d.virtual_address, d.size, MAX_UNWIND_CODES)
                    .unwrap_or_default()
            }
            _ => Exceptions::default(),
        }
    }

    /// Stops, keeping what it has read, at the record that would pass `max_codes`.
    fn read_exceptions(
        &self,
        data: &[u8],
        start: u32,
        size: u32,
        max_codes: usize,
    ) -> Option<Exceptions> {
        let mut exceptions = Exceptions::default();
        let mut info_by_rva = HashMap::new();
        let mut entry_by_begin = HashMap::new();
        let mut code_count = 0;
        let count = (size / RUNTIME_FUNCTION_SIZE).min(MAX_RUNTIME_FUNCTIONS);
        let mut rva = i64::from(start);
        for _ in 0..count {
            let bytes = self.read_with_offset(data, rva, RUNTIME_FUNCTION_SIZE.into())?;
            if bytes.len() < RUNTIME_FUNCTION_SIZE as usize {
                break;
            }
            let (begin_address, unwind_data) = (u32_at(bytes, 0), u32_at(bytes, 8));
            let unwind_info = if unwind_data & 1 == 0 {
                // A record pefile has already read reads the same again, so it is reused.
                match info_by_rva.entry(unwind_data) {
                    Entry::Occupied(e) => Some(*e.get()),
                    Entry::Vacant(e) => match self.unwind_info(data, unwind_data) {
                        Ok(info) => {
                            code_count += info.body.as_ref().map_or(0, |b| b.codes.len());
                            if code_count > max_codes {
                                break;
                            }
                            exceptions.unwind_infos.push(info);
                            Some(*e.insert(exceptions.unwind_infos.len() - 1))
                        }
                        Err(Stop::Break) => break,
                        Err(Stop::Raise) => return None,
                    },
                }
            } else {
                None
            };
            entry_by_begin.insert(begin_address, exceptions.entries.len());
            exceptions.entries.push(RuntimeFunction {
                begin_address,
                end_address: u32_at(bytes, 4),
                unwind_data,
                unwind_info,
            });
            rva += i64::from(RUNTIME_FUNCTION_SIZE);
        }
        for info in &mut exceptions.unwind_infos {
            if let Some(UnwindBody {
                trailer:
                    Some(Trailer::FunctionEntry {
                        begin_address,
                        chained,
                    }),
                ..
            }) = &mut info.body
            {
                *chained = entry_by_begin.get(begin_address).copied();
            }
        }
        Some(exceptions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    const VALID: &[u8] = include_bytes!("../../tests/fixtures/exceptions64.dll");
    const CRAFTED: &[u8] = include_bytes!("../../tests/fixtures/crafted/exceptions.dll");

    fn exceptions(data: &[u8]) -> Exceptions {
        parse(data).unwrap().parse_exceptions(data)
    }

    fn info(e: &Exceptions, entry: usize) -> &UnwindInfo {
        &e.unwind_infos[e.entries[entry].unwind_info.unwrap()]
    }

    fn body(e: &Exceptions, entry: usize) -> &UnwindBody {
        info(e, entry).body.as_ref().unwrap()
    }

    fn strings(e: &Exceptions, entry: usize) -> Vec<String> {
        body(e, entry).codes.iter().map(|c| c.to_string()).collect()
    }

    fn chained(e: &Exceptions, entry: usize) -> Option<usize> {
        match body(e, entry).trailer {
            Some(Trailer::FunctionEntry { chained, .. }) => chained,
            _ => panic!("entry {entry} is not chained"),
        }
    }

    /// `data` with the bytes at `rva` replaced.
    fn patched(data: &[u8], rva: u32, bytes: &[u8]) -> Vec<u8> {
        let offset = parse(data).unwrap().offset_from_rva(rva.into()).unwrap() as usize;
        let mut data = data.to_vec();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        data
    }

    fn unwind_data(entry: usize) -> u32 {
        exceptions(VALID).entries[entry].unwind_data
    }

    #[test]
    fn decodes_every_unwind_code_layout_as_pefile_prints_it() {
        // pefile 2024.8.26's str() of each code in tests/fixtures/exceptions64.dll.
        let e = exceptions(VALID);
        assert_eq!(e.entries.len(), 11);
        assert_eq!(
            strings(&e, 0),
            [".ALLOCSTACK 0xd0", ".ALLOCSTACK 0x20", ".PUSHREG RBP"]
        );
        assert_eq!(
            strings(&e, 2),
            [".SETFRAME RBP, 0x30", ".ALLOCSTACK 0x12345", ".PUSHFRAME"]
        );
        assert_eq!(
            strings(&e, 3),
            [
                ".SAVEREG RBX, 0x180",
                ".SAVEREG R12, 0x10008",
                ".SAVEXMM128 XMM6, 0x20",
                ".PUSHFRAME <code>"
            ]
        );
        assert_eq!(
            strings(&e, 4),
            [".SAVEXMM128 XMM15, 0x20010", ".ALLOCSTACK 0x8"]
        );
        assert_eq!(
            strings(&e, 5),
            [
                "EPILOG: size=0x5, offset from the end=-0x5",
                "EPILOG: size=0x5, offset from the end=-0x320",
                "",
                ".PUSHREG RSI"
            ]
        );
        assert_eq!(
            strings(&e, 6),
            ["EPILOG: size=0x7, offset from the end=-0x234"]
        );
        let validity: Vec<_> = body(&e, 5).codes.iter().map(UnwindCode::is_valid).collect();
        assert_eq!(validity, [true, true, false, true]);
        assert_eq!(body(&e, 5).size_of_epilog, Some(5));
        assert_eq!(body(&e, 0).size_of_epilog, None);
    }

    #[test]
    fn reads_header_fields_and_the_trailing_dword() {
        let e = exceptions(VALID);
        let first = info(&e, 0);
        assert_eq!(
            (
                first.version,
                first.flags,
                first.size_of_prolog,
                first.count_of_codes
            ),
            (1, 3, 0x10, 4)
        );
        assert!(matches!(
            body(&e, 0).trailer,
            Some(Trailer::ExceptionHandler(0x103C))
        ));
        let frame = info(&e, 2);
        assert_eq!((frame.frame_register, frame.frame_offset), (5, 3));
        // An undefined flag reserves the DWORD, but names no field.
        assert_eq!(info(&e, 4).flags, 8);
        assert!(body(&e, 4).trailer.is_none());
    }

    #[test]
    fn entries_pointing_at_one_record_share_it() {
        let e = exceptions(VALID);
        assert_eq!(e.entries[0].unwind_info, e.entries[1].unwind_info);
        assert_eq!(e.unwind_infos.len(), 9);
    }

    #[test]
    fn chained_entries_link_to_the_entry_their_function_entry_begins() {
        let e = exceptions(VALID);
        assert_eq!(chained(&e, 8), Some(7));
        assert_eq!(chained(&e, 9), None, "no entry begins at the FunctionEntry");
        assert_eq!(
            e.entries[10].unwind_info, None,
            "bit 0 of UnwindData is set"
        );
    }

    #[test]
    fn chain_cycles_and_self_references_are_plain_links() {
        let e = exceptions(CRAFTED);
        assert_eq!(e.entries.len(), 5);
        assert_eq!(chained(&e, 1), Some(1));
        assert_eq!((chained(&e, 2), chained(&e, 3)), (Some(3), Some(2)));
    }

    #[test]
    fn reads_all_255_codes_of_a_record() {
        let e = exceptions(CRAFTED);
        assert_eq!(info(&e, 0).count_of_codes, 255);
        assert_eq!(body(&e, 0).codes.len(), 255);
    }

    #[test]
    fn a_record_cut_off_by_the_section_end_keeps_only_its_header() {
        let e = exceptions(CRAFTED);
        let truncated = info(&e, 4);
        assert_eq!((truncated.version, truncated.count_of_codes), (1, 4));
        assert!(truncated.body.is_none());
    }

    #[test]
    fn stops_before_an_unsupported_version_or_unknown_code() {
        let bad_version = patched(VALID, unwind_data(3), &[3]);
        assert_eq!(exceptions(&bad_version).entries.len(), 3);
        // The second record's first code becomes op 7, which pefile does not know.
        let unknown_op = patched(VALID, unwind_data(2) + 5, &[0x07]);
        assert_eq!(exceptions(&unknown_op).entries.len(), 2);
    }

    #[test]
    fn a_read_pefile_raises_on_leaves_the_directory_empty() {
        let pe = parse(VALID).unwrap();
        let table = pe.headers.optional_header.data_directory[EXCEPTION_DIRECTORY].virtual_address;
        // The fourth entry's UnwindData points past the end of the file.
        let past_end = patched(VALID, table + 3 * 12 + 8, &0x7FFF_0000u32.to_le_bytes());
        assert!(exceptions(&past_end).entries.is_empty());
        // A one-slot ALLOC_LARGE in the last slot of a 1-code record overruns the record.
        let overrun = patched(VALID, unwind_data(7) + 5, &[0x11]);
        assert!(exceptions(&overrun).entries.is_empty());
    }

    #[test]
    fn stops_at_the_record_that_passes_the_code_budget() {
        let pe = parse(VALID).unwrap();
        let d = &pe.headers.optional_header.data_directory[EXCEPTION_DIRECTORY];
        let read = |budget| {
            let e = pe.read_exceptions(VALID, d.virtual_address, d.size, budget);
            e.unwrap().entries.len()
        };
        // The first record has 3 codes, shared by two entries; the second has 3 more.
        assert_eq!(read(5), 2);
        assert_eq!(read(6), 3);
        assert_eq!(read(18), 11, "the fixture has 18 codes");
    }

    #[test]
    fn other_machines_have_no_exception_directory() {
        let pe = parse(VALID).unwrap();
        let machine = pe.headers.dos_header.e_lfanew as usize + 4;
        let mut x86 = VALID.to_vec();
        x86[machine..machine + 2].copy_from_slice(&0x14Cu16.to_le_bytes());
        assert!(exceptions(&x86).entries.is_empty());
        let mut ia64 = VALID.to_vec();
        ia64[machine..machine + 2].copy_from_slice(&MACHINE_IA64.to_le_bytes());
        assert_eq!(exceptions(&ia64).entries.len(), 11);
    }
}
