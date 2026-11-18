//! Bound imports, following pefile's `parse_directory_bound_imports`.
//!
//! pefile reads this directory's address as a file offset, not as an RVA. Linkers put it in
//! the headers, where the two are equal, so that is also where it is usually found.

use crate::{Pe, clamp};

const BOUND_IMPORT_DIRECTORY: usize = 11;
/// pefile walks its directory table in a fixed order and stops at the first index the table
/// lacks. The delay-import directory (13) comes before this one in that order.
const DIRECTORIES_PEFILE_NEEDS: usize = 14;
/// IMAGE_BOUND_IMPORT_DESCRIPTOR and IMAGE_BOUND_FORWARDER_REF are both 8 bytes.
const ENTRY_SIZE: usize = 8;
/// pefile stops at a module name longer than this.
const MAX_NAME_LENGTH: usize = 256;

pub struct BoundImportDescriptor {
    pub time_date_stamp: u32,
    pub offset_module_name: u16,
    pub number_of_module_forwarder_refs: u16,
    pub name: Vec<u8>,
    /// The forwarder refs pefile reads, which can be fewer than the count above.
    pub entries: Vec<BoundForwarderRef>,
}

pub struct BoundForwarderRef {
    pub time_date_stamp: u32,
    pub offset_module_name: u16,
    pub reserved: u16,
    pub name: Vec<u8>,
}

/// The 8-byte entry at file offset `at`, as its three fields, or `None` past the file end.
fn entry(data: &[u8], at: usize) -> Option<(u32, u16, u16)> {
    let raw = data.get(at..at.checked_add(ENTRY_SIZE)?)?;
    Some((
        u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        u16::from_le_bytes([raw[4], raw[5]]),
        u16::from_le_bytes([raw[6], raw[7]]),
    ))
}

/// The NUL-terminated module name at `offset`, or `None` when pefile would reject it: longer
/// than 256 bytes, or holding a byte outside Python's `string.printable`. Only 257 bytes are
/// read, which is enough to tell a name that is too long.
fn module_name(data: &[u8], offset: usize) -> Option<Vec<u8>> {
    let start = offset.min(data.len());
    let window = &data[start..offset.saturating_add(MAX_NAME_LENGTH + 1).min(data.len())];
    let name = &window[..window.iter().position(|&b| b == 0).unwrap_or(window.len())];
    let printable = |b: &u8| matches!(b, 0x20..=0x7E | 0x09..=0x0D);
    (name.len() <= MAX_NAME_LENGTH && name.iter().all(printable)).then(|| name.to_vec())
}

impl Pe {
    /// The bound import descriptors of `data`, the file this `Pe` was parsed from. Empty
    /// wherever pefile leaves `DIRECTORY_ENTRY_BOUND_IMPORT` undefined, including when it
    /// gives up partway and drops what it had read.
    ///
    /// Every descriptor and forwarder ref read moves 8 bytes further through the file, and a
    /// read past its end ends the walk, so neither loop runs more than `data.len() / 8` times.
    pub fn parse_bound_imports(&self, data: &[u8]) -> Vec<BoundImportDescriptor> {
        self.bound_imports(data).unwrap_or_default()
    }

    fn bound_imports(&self, data: &[u8]) -> Option<Vec<BoundImportDescriptor>> {
        let directories = &self.headers.optional_header.data_directory;
        if directories.len() < DIRECTORIES_PEFILE_NEEDS {
            return None;
        }
        let start = directories[BOUND_IMPORT_DIRECTORY].virtual_address as usize;
        if start == 0 {
            return None;
        }
        let mut at = start;
        let mut descriptors = Vec::new();
        // Descriptors and refs may all name one string, so the copied names are capped at the
        // file size; a real file's names are disjoint and stay under it. pefile has no cap.
        let mut budget = data.len();
        let mut name_at = |offset: u16| {
            let name = module_name(data, start.saturating_add(offset as usize))?;
            budget = budget.checked_sub(name.len())?;
            Some(name)
        };
        loop {
            let (time_date_stamp, offset_module_name, number_of_module_forwarder_refs) =
                entry(data, at)?;
            if (
                time_date_stamp,
                offset_module_name,
                number_of_module_forwarder_refs,
            ) == (0, 0, 0)
            {
                break;
            }
            at += ENTRY_SIZE;
            let room = self.room_after(at as i64)?;
            let mut entries = Vec::new();
            for _ in 0..(number_of_module_forwarder_refs as i64).min(room / ENTRY_SIZE as i64) {
                let (time_date_stamp, offset_module_name, reserved) = entry(data, at)?;
                at += ENTRY_SIZE;
                let Some(name) = name_at(offset_module_name) else {
                    break;
                };
                entries.push(BoundForwarderRef {
                    time_date_stamp,
                    offset_module_name,
                    reserved,
                    name,
                });
            }
            match name_at(offset_module_name) {
                Some(name) if !name.is_empty() => descriptors.push(BoundImportDescriptor {
                    time_date_stamp,
                    offset_module_name,
                    number_of_module_forwarder_refs,
                    name,
                    entries,
                }),
                _ => break,
            }
        }
        Some(descriptors)
    }

    /// pefile's `safety_boundary`: how many bytes from `at` the forwarder refs may span. `None`
    /// where pefile abandons the directory, because `at` is in no section and none starts
    /// after it, or because `at` read as an RVA can't be mapped.
    fn room_after(&self, at: i64) -> Option<i64> {
        let file_offset = self.offset_from_rva(at)?;
        if let Some(i) = self.section_by_offset(at) {
            let (layout, section) = (&self.layouts[i], &self.sections[i]);
            let data = clamp(
                layout.data_range(section, None, None, false),
                self.file_size,
            );
            let end = section.pointer_to_raw_data as i64 + data.len() as i64;
            return Some(end.saturating_sub(file_offset));
        }
        let next = self
            .sections
            .iter()
            .map(|s| s.pointer_to_raw_data as i64)
            .filter(|&pointer| pointer > file_offset)
            .min()?;
        let i = self.section_by_offset(next)?;
        Some((self.sections[i].pointer_to_raw_data as i64).saturating_sub(file_offset))
    }
}
