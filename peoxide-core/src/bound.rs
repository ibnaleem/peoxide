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

#[cfg(test)]
mod tests {
    use crate::parse;

    fn names(data: &[u8]) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
        parse(data)
            .unwrap()
            .parse_bound_imports(data)
            .into_iter()
            .map(|d| (d.name, d.entries.into_iter().map(|r| r.name).collect()))
            .collect()
    }

    fn owned(expected: &[(&[u8], &[&[u8]])]) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
        expected
            .iter()
            .map(|(name, refs)| (name.to_vec(), refs.iter().map(|r| r.to_vec()).collect()))
            .collect()
    }

    const BOUND64: &[u8] = include_bytes!("../../tests/fixtures/bound_imports.dll");
    const BOUND32: &[u8] = include_bytes!("../../tests/fixtures/bound_imports32.exe");
    const VALID: &[(&[u8], &[&[u8]])] = &[
        (b"KERNEL32.dll", &[b"NTDLL.DLL", b"KERNELBASE.dll"]),
        (b"USER32.dll", &[]),
    ];

    #[test]
    fn reads_descriptors_and_forwarder_refs_in_pe32_plus_and_pe32() {
        for data in [BOUND64, BOUND32] {
            assert_eq!(names(data), owned(VALID));
        }
        let pe = parse(BOUND64).unwrap();
        let first = &pe.parse_bound_imports(BOUND64)[0];
        assert_eq!(first.time_date_stamp, 0x5F00_0001);
        assert_eq!(first.number_of_module_forwarder_refs, 2);
        assert_eq!(first.entries[1].time_date_stamp, 0x5F00_0003);
        assert_eq!(first.entries[1].reserved, 0);
    }

    #[test]
    fn absent_directory_is_empty() {
        let data = include_bytes!("../../tests/fixtures/sample64.dll");
        assert!(names(data).is_empty());
    }

    #[test]
    fn short_directory_tables_are_skipped_like_pefile() {
        // NumberOfRvaAndSizes 13: pefile stops before reaching the bound import directory.
        let mut data = BOUND64.to_vec();
        let count = 0x40 + 24 + 108;
        data[count..count + 4].copy_from_slice(&13u32.to_le_bytes());
        assert!(names(&data).is_empty());
    }

    #[test]
    fn huge_forwarder_count_stops_at_the_next_section() {
        // 0xFFFF refs claimed at 0x300; the headers end at 0x400, so 31 are read.
        let data = include_bytes!("../../tests/fixtures/crafted/bound_huge_count.dll");
        let parsed = names(data);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1.len(), 31);
    }

    #[test]
    fn invalid_names_end_the_walk() {
        let data = include_bytes!("../../tests/fixtures/crafted/bound_bad_names.dll");
        // The bad ref name ends KERNEL32's refs, and the unread ref is taken as a descriptor.
        let expected: &[(&[u8], &[&[u8]])] =
            &[(b"KERNEL32.dll", &[b"NTDLL.DLL"]), (b"KERNELBASE.dll", &[])];
        assert_eq!(names(data), owned(expected));
        let data = include_bytes!("../../tests/fixtures/crafted/bound_name_outside.dll");
        assert_eq!(names(data), owned(&[(b"KERNEL32.dll", &[])]));
    }

    #[test]
    fn shared_names_copy_no_more_than_the_file() {
        let data = include_bytes!("../../tests/fixtures/crafted/bound_shared_names.dll");
        let parsed = names(data);
        assert_eq!(parsed[0].0.len(), 256, "a name is kept whole");
        let copied: usize = parsed.iter().map(|(name, _)| name.len()).sum();
        assert!(
            copied <= data.len(),
            "{copied} name bytes from {}",
            data.len()
        );
        assert!(parsed.len() < 8000, "the walk stops at the budget");
    }

    #[test]
    fn truncated_directory_is_dropped() {
        let data = include_bytes!("../../tests/fixtures/crafted/bound_truncated.dll");
        assert!(names(data).is_empty());
    }

    #[test]
    fn address_is_read_as_a_file_offset() {
        // The address is .text's RVA, and the descriptors sit at that file offset in .data.
        let data = include_bytes!("../../tests/fixtures/crafted/bound_in_section.dll");
        assert_eq!(names(data), owned(VALID));
    }

    #[test]
    fn module_names_follow_pefiles_checks() {
        let long = [b'a'; 300];
        assert_eq!(super::module_name(&long, 0), None);
        assert_eq!(
            super::module_name(&long[..256], 0),
            Some(long[..256].to_vec())
        );
        assert_eq!(super::module_name(b"a\x01b\0", 0), None);
        assert_eq!(super::module_name(b"a\tb\0c", 0), Some(b"a\tb".to_vec()));
        assert_eq!(super::module_name(b"abc", usize::MAX), Some(Vec::new()));
    }
}
