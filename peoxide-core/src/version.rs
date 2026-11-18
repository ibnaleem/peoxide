//! Version information (RT_VERSION), following pefile's `parse_version_information`.
//!
//! Offsets are relative to the resource's data and aligned with pefile's `dword_align`,
//! including its 32-bit mask. Where an offset wraps past 4 GiB, pefile's loops can spin
//! forever; each walk here stops instead once its offset stops moving forward.
//!
//! Blocks in a crafted resource can overlap, so that every block rereads the rest of the
//! resource as its key: gigabytes from a small file. One budget per PE bounds the strings
//! read here, and parsing stops where it runs out, unlike pefile.

use std::cell::Cell;

use crate::{Pe, ResourceChild, ResourceData};

const RT_VERSION: u32 = 16;
const HEADER_SIZE: i64 = 6;
const FIXED_FILE_INFO_SIZE: usize = 52;
const VS_VERSION_INFO: &[u8] = b"VS_VERSION_INFO";
/// pefile's default `max_length` for `get_string_u_at_rva`.
const DEFAULT_MAX_UNITS: i64 = 1 << 16;
/// Bytes of version strings one PE may read, each string charged its length plus
/// `STRING_OVERHEAD`. The largest System32 or SysWOW64 file kept strings charging an
/// estimated 64 KiB.
const VERSION_BUDGET: usize = 16 << 20;
/// What one more string costs beyond its bytes, so that empty keys are not free.
const STRING_OVERHEAD: usize = 64;

/// The `Length`, `ValueLength` and `Type` words that open every version block.
#[derive(Clone, Copy)]
pub struct BlockHeader {
    pub length: u16,
    pub value_length: u16,
    pub type_: u16,
}

/// pefile's `VS_VERSIONINFO` entry.
pub struct VersionInfo {
    pub header: BlockHeader,
    pub key: Vec<u8>,
}

/// pefile's `VS_FIXEDFILEINFO` entry, in field order.
pub struct FixedFileInfo {
    pub signature: u32,
    pub struc_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

/// A StringFileInfo or VarFileInfo block from pefile's `FileInfo`.
pub struct FileInfo {
    pub header: BlockHeader,
    pub key: Vec<u8>,
    /// Set on a StringFileInfo block whose `Type` is 0 or 1 and `ValueLength` is 0.
    pub string_table: Option<Vec<StringTable>>,
    /// Set on a VarFileInfo block under the same condition.
    pub var: Option<Vec<Var>>,
}

pub struct StringTable {
    pub header: BlockHeader,
    pub lang_id: Vec<u8>,
    /// pefile's `entries` dict: insertion order, a repeated key keeps its first place.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct Var {
    pub header: BlockHeader,
    /// pefile's `entry`: the name and its last word pair as `"0x%04x 0x%04x"`, or `None`
    /// where pefile never sets the attribute.
    pub entry: Option<(Vec<u8>, String)>,
}

/// pefile's three version attributes. Each is `None` where pefile leaves it undefined.
#[derive(Default)]
pub struct Version {
    pub vs_versioninfo: Option<Vec<VersionInfo>>,
    pub vs_fixedfileinfo: Option<Vec<FixedFileInfo>>,
    pub file_info: Option<Vec<Vec<FileInfo>>>,
}

fn dword_align(offset: i64, base: i64) -> i64 {
    ((offset + base + 3) & 0xFFFF_FFFC) - (base & 0xFFFF_FFFC)
}

/// `data[start:end]` with Python's slice rules, negative bounds included.
fn py_slice(data: &[u8], start: i64, end: Option<i64>) -> &[u8] {
    let len = data.len() as i64;
    let bound = |i: i64| if i < 0 { (len + i).max(0) } else { i.min(len) };
    let start = bound(start);
    let end = end.map_or(len, bound).max(start);
    &data[start as usize..end as usize]
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn block_header(raw: &[u8], offset: i64) -> Option<BlockHeader> {
    let b = py_slice(raw, offset, None).get(..HEADER_SIZE as usize)?;
    Some(BlockHeader {
        length: u16_at(b, 0),
        value_length: u16_at(b, 2),
        type_: u16_at(b, 4),
    })
}

fn fixed_file_info(raw: &[u8], offset: i64) -> Option<FixedFileInfo> {
    let b = py_slice(raw, offset, None).get(..FIXED_FILE_INFO_SIZE)?;
    let d = |i: usize| u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    Some(FixedFileInfo {
        signature: d(0),
        struc_version: d(1),
        file_version_ms: d(2),
        file_version_ls: d(3),
        product_version_ms: d(4),
        product_version_ls: d(5),
        file_flags_mask: d(6),
        file_flags: d(7),
        file_os: d(8),
        file_type: d(9),
        file_subtype: d(10),
        file_date_ms: d(11),
        file_date_ls: d(12),
    })
}

/// pefile's `get_word_from_data(raw[start:start + 2], 0)`.
fn word(raw: &[u8], start: i64) -> Option<u16> {
    let b = py_slice(raw, start, Some(start + 2));
    (b.len() == 2).then(|| u16_at(b, 0))
}

fn insert(entries: &mut Vec<(Vec<u8>, Vec<u8>)>, key: Vec<u8>, value: Vec<u8>) {
    match entries.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => entries.push((key, value)),
    }
}

/// Where the block after a key string starts: `2 * (len(key) + 1)` counts the key's encoded
/// bytes, not its UTF-16 units, as in pefile.
fn after_key(offset: i64, key: &[u8], base: i64) -> i64 {
    dword_align(offset + HEADER_SIZE + 2 * (key.len() as i64 + 1), base)
}

/// One RT_VERSION resource: the data it is read from, and pefile's `OffsetToData` base.
struct Block<'a> {
    pe: &'a Pe,
    data: &'a [u8],
    raw: &'a [u8],
    base: i64,
    budget: &'a Cell<usize>,
}

impl Block<'_> {
    /// `None` once the PE's budget runs out, which ends every walk that reads strings.
    fn string(&self, offset: i64, max_units: i64) -> Option<Vec<u8>> {
        if self.budget.get() == 0 {
            return None;
        }
        let string = self
            .pe
            .utf16_string_at(self.data, self.base + offset, max_units)?;
        let left = self
            .budget
            .get()
            .checked_sub(string.len() + STRING_OVERHEAD);
        self.budget.set(left.unwrap_or(0));
        left.and(Some(string))
    }

    fn string_tables(&self, mut offset: i64, file_info_length: u16) -> Vec<StringTable> {
        let mut tables = Vec::new();
        while let Some(header) = block_header(self.raw, offset) {
            let Some(lang_id) = self.string(offset + HEADER_SIZE, DEFAULT_MAX_UNITS) else {
                break;
            };
            let entries = self.strings(
                after_key(offset, &lang_id, self.base),
                offset + header.length as i64,
            );
            tables.push(StringTable {
                header,
                lang_id,
                entries,
            });
            let next = dword_align(header.length as i64 + offset, self.base);
            if next <= offset {
                break;
            }
            offset = next;
            // pefile compares the table's offset in the resource with the block's length.
            if offset >= file_info_length as i64 {
                break;
            }
        }
        tables
    }

    fn strings(&self, mut offset: i64, end: i64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut entries = Vec::new();
        while offset < end {
            let Some(header) = block_header(self.raw, offset) else {
                break;
            };
            let key_offset = offset + HEADER_SIZE;
            let Some(key) = self.string(key_offset, DEFAULT_MAX_UNITS) else {
                break;
            };
            if self.pe.offset_from_rva(self.base + key_offset).is_none() {
                break;
            }
            let value_offset = dword_align(2 * (key.len() as i64 + 1) + key_offset, self.base);
            let Some(value) = self.string(value_offset, header.value_length as i64) else {
                break;
            };
            if self.pe.offset_from_rva(self.base + value_offset).is_none() {
                break;
            }
            let next = match header.length {
                0 => end,
                length => dword_align(length as i64 + offset, self.base),
            };
            insert(&mut entries, key, value);
            if next <= offset {
                break;
            }
            offset = next;
        }
        entries
    }

    /// pefile's Var loop ends after its first pass (`var_offset <= var_offset + Length`
    /// always holds), so a VarFileInfo block lists at most one Var.
    fn vars(&self, offset: i64) -> Vec<Var> {
        let Some(header) = block_header(self.raw, offset) else {
            return Vec::new();
        };
        let Some(name) = self.string(offset + HEADER_SIZE, DEFAULT_MAX_UNITS) else {
            return Vec::new();
        };
        let start = dword_align(
            2 * (name.len() as i64 + 1) + offset + HEADER_SIZE,
            self.base,
        );
        let end = start + header.value_length as i64;
        let last_pair = (start..end)
            .step_by(4)
            .filter_map(|at| Some((word(self.raw, at)?, word(self.raw, at + 2)?)))
            .last();
        let entry = last_pair.map(|(a, b)| (name, format!("0x{a:04x} 0x{b:04x}")));
        vec![Var { header, entry }]
    }

    fn file_info(&self, offset: i64, header: BlockHeader, key: Vec<u8>) -> FileInfo {
        let listed = matches!(header.type_, 0 | 1) && header.value_length == 0;
        let children = after_key(offset, &key, self.base);
        let string_table = (listed && key.starts_with(b"StringFileInfo"))
            .then(|| self.string_tables(children, header.length));
        let var = (listed && key.starts_with(b"VarFileInfo")).then(|| self.vars(children));
        FileInfo {
            header,
            key,
            string_table,
            var,
        }
    }
}

impl Pe {
    /// pefile parses version information for every top-level entry whose ID (the low 16
    /// bits of `Name`, even for a named entry) is RT_VERSION.
    pub(crate) fn parse_version(&self, data: &[u8]) -> Version {
        let mut version = Version::default();
        let Some(resources) = &self.resources else {
            return version;
        };
        let budget = Cell::new(VERSION_BUDGET);
        for entry in &resources.entries {
            if entry.name_field & 0xFFFF != RT_VERSION {
                continue;
            }
            let ResourceChild::Directory(names) = &entry.child else {
                continue;
            };
            let Some(ResourceChild::Directory(languages)) = names.entries.first().map(|e| &e.child)
            else {
                continue;
            };
            for language in &languages.entries {
                if let ResourceChild::Data(leaf) = &language.child {
                    self.version_information(data, leaf, &budget, &mut version);
                }
            }
        }
        version
    }

    fn version_information(
        &self,
        data: &[u8],
        leaf: &ResourceData,
        budget: &Cell<usize>,
        out: &mut Version,
    ) {
        let base = leaf.offset_to_data as i64;
        let Some(start) = self.offset_from_rva(base) else {
            return;
        };
        let raw = py_slice(data, start, Some(start + leaf.size as i64));
        let block = Block {
            pe: self,
            data,
            raw,
            base,
            budget,
        };
        let Some(header) = block_header(raw, 0) else {
            return;
        };
        let max_units = self
            .section_by_rva(base + HEADER_SIZE)
            .map_or(DEFAULT_MAX_UNITS, |i| {
                let s = &self.sections[i];
                let end = s.virtual_address as i64 + s.size_of_raw_data.max(s.virtual_size) as i64;
                (end - (base + HEADER_SIZE)) >> 1
            });
        if block.string(HEADER_SIZE, max_units).as_deref() != Some(VS_VERSION_INFO) {
            return;
        }
        out.vs_versioninfo
            .get_or_insert_default()
            .push(VersionInfo {
                header,
                key: VS_VERSION_INFO.to_vec(),
            });
        let fixed_offset = after_key(0, VS_VERSION_INFO, base);
        let Some(fixed) = fixed_file_info(raw, fixed_offset) else {
            return;
        };
        out.vs_fixedfileinfo.get_or_insert_default().push(fixed);
        let file_info = out.file_info.get_or_insert_default();
        let mut blocks = Vec::new();
        let mut offset = dword_align(fixed_offset + FIXED_FILE_INFO_SIZE as i64, base);
        loop {
            // pefile returns here without appending this resource's list.
            let Some(block_info) = block_header(raw, offset) else {
                return;
            };
            let Some(key) = block.string(offset + HEADER_SIZE, DEFAULT_MAX_UNITS) else {
                break;
            };
            blocks.push(block.file_info(offset, block_info, key));
            let next = dword_align(block_info.length as i64 + offset, base);
            if block_info.length == 0 || next >= header.length as i64 || next <= offset {
                break;
            }
            offset = next;
        }
        file_info.push(blocks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dword_align_keeps_pefile_mask() {
        assert_eq!(dword_align(5, 0), 8);
        // Aligns base + offset, not the offset alone.
        assert_eq!(dword_align(4, 2), 8);
        assert_eq!(dword_align(0xFFFF_FFFF, 0), 0);
    }

    #[test]
    fn py_slice_follows_python() {
        let data = b"abcdef";
        assert_eq!(py_slice(data, 2, Some(4)), b"cd");
        assert_eq!(py_slice(data, -2, None), b"ef");
        assert_eq!(py_slice(data, 4, Some(2)), b"");
        assert_eq!(py_slice(data, 10, None), b"");
        assert_eq!(py_slice(data, -10, Some(-4)), b"ab");
    }

    #[test]
    fn short_headers_are_none() {
        assert!(block_header(b"\x01\x00\x02\x00\x03", 0).is_none());
        let header = block_header(b"\x01\x00\x02\x00\x03\x00", 0).unwrap();
        assert_eq!(
            (header.length, header.value_length, header.type_),
            (1, 2, 3)
        );
        assert!(fixed_file_info(&[0; 51], 0).is_none());
    }

    #[test]
    fn repeated_key_keeps_first_place() {
        let mut entries = Vec::new();
        insert(&mut entries, b"a".to_vec(), b"1".to_vec());
        insert(&mut entries, b"b".to_vec(), b"2".to_vec());
        insert(&mut entries, b"a".to_vec(), b"3".to_vec());
        assert_eq!(
            entries,
            vec![
                (b"a".to_vec(), b"3".to_vec()),
                (b"b".to_vec(), b"2".to_vec())
            ]
        );
    }

    #[test]
    fn reads_the_dll_fixture_version_info() {
        let pe = crate::parse(crate::tests::DLL).unwrap();
        let info = &pe.version.vs_versioninfo.as_ref().unwrap()[0];
        assert_eq!(info.key, b"VS_VERSION_INFO");
        assert_eq!((info.header.value_length, info.header.type_), (52, 0));
        assert_eq!(
            pe.version.vs_fixedfileinfo.as_ref().unwrap()[0].signature,
            0xFEEF04BD
        );
        let [strings, vars] = pe.version.file_info.as_ref().unwrap()[0].as_slice() else {
            panic!("expected StringFileInfo and VarFileInfo");
        };
        assert_eq!(strings.key, b"StringFileInfo");
        let table = &strings.string_table.as_ref().unwrap()[0];
        assert_eq!(table.lang_id, b"040904B0");
        assert_eq!(
            table.entries[0],
            (b"CompanyName".to_vec(), b"peoxide".to_vec())
        );
        assert_eq!(vars.key, b"VarFileInfo");
        let entry = vars.var.as_ref().unwrap()[0].entry.as_ref().unwrap();
        assert_eq!(
            entry,
            &(b"Translation".to_vec(), "0x0409 0x04b0".to_string())
        );
    }

    #[test]
    fn overlapping_blocks_keep_within_the_budget() {
        // Kept in full, the fixture's FileInfo keys come to about 64 MiB.
        let data = include_bytes!("../../tests/fixtures/crafted/overlapping_version.dll");
        let pe = crate::parse(data).unwrap();
        let file_info = pe.version.file_info.unwrap();
        assert!(!file_info[0].is_empty());
        let kept: usize = file_info.iter().flatten().map(|b| b.key.len()).sum();
        assert!(kept <= VERSION_BUDGET, "kept {kept} bytes of keys");
    }
}
