//! The resource tree, following pefile's `parse_resources_directory`, with RT_STRING tables.
//! Version information is decoded from the finished tree in `version.rs`.

use crate::Pe;

const RESOURCE_DIRECTORY: usize = 2;
const DIRECTORY_HEADER_SIZE: i64 = 16;
const ENTRY_SIZE: i64 = 8;
const DATA_ENTRY_SIZE: i64 = 16;
const MAX_DEPTH: usize = 32;
const MAX_ENTRIES_PER_DIRECTORY: usize = 4096;
const MAX_ENTRIES: usize = 0x8000;
const FIRST_STRING_READ: i64 = 256;
const RT_STRING: u32 = 6;
const STRINGS_PER_BLOCK: i64 = 16;
const MAX_DECODE_ERRORS: usize = 3;

pub struct ResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
    pub entries: Vec<ResourceEntry>,
    /// pefile's `strings`: set only on the per-block directories under RT_STRING, in
    /// insertion order, where a later language overwrites an earlier one's value.
    pub strings: Option<Vec<(i64, String)>>,
}

pub struct ResourceEntry {
    /// The raw `Name` field: an ID, or a string offset with the high bit set.
    pub name_field: u32,
    pub offset_to_data: u32,
    /// Set for named entries. The inner value is `None` where pefile leaves the string unread.
    pub name: Option<Option<Vec<u8>>>,
    pub child: ResourceChild,
}

pub enum ResourceChild {
    Directory(ResourceDirectory),
    Data(ResourceData),
}

pub struct ResourceData {
    pub offset_to_data: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// UTF-8 with lone surrogates written as `\udXXX`, as pefile's `backslashreplace_` does.
/// pefile decodes each UTF-16 unit on its own, so surrogate pairs are escaped too.
fn encode_units(units: impl Iterator<Item = u16>) -> Vec<u8> {
    let mut out = String::new();
    for unit in units {
        match char::from_u32(unit as u32) {
            Some(c) => out.push(c),
            None => out.push_str(&format!("\\u{unit:04x}")),
        }
    }
    out.into_bytes()
}

fn insert(table: &mut Vec<(i64, String)>, key: i64, value: String) {
    match table.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => table.push((key, value)),
    }
}

/// pefile's `parse_strings`: length-prefixed UTF-16 strings, numbered from `counter`.
fn parse_strings(data: &[u8], mut counter: i64, table: &mut Vec<(i64, String)>) {
    let (mut i, mut errors) = (0, 0);
    while let Some(prefix) = data.get(i..i + 2) {
        let length = i16::from_le_bytes([prefix[0], prefix[1]]) as i64;
        i += 2;
        if length != 0 && (0..=data.len() as i64).contains(&(length * 2)) {
            let bytes = &data[i.min(data.len())..(i + length as usize * 2).min(data.len())];
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&u| u16::from_le_bytes(u))
                .collect();
            match String::from_utf16(&units) {
                Ok(s) if bytes.len().is_multiple_of(2) => insert(table, counter, s),
                _ => errors += 1,
            }
            if errors >= MAX_DECODE_ERRORS {
                break;
            }
            i += length as usize * 2;
        }
        counter += 1;
    }
}

struct Walk<'a> {
    pe: &'a Pe,
    data: &'a [u8],
    base: i64,
    total_entries: usize,
}

impl Walk<'_> {
    fn read(&self, rva: i64, length: i64) -> Option<&[u8]> {
        self.data.get(self.pe.data_range(rva, Some(length))?)
    }

    fn read_exact(&self, rva: i64, length: i64) -> Option<&[u8]> {
        self.read(rva, length)
            .filter(|b| b.len() == length as usize)
    }

    fn word(&self, rva: i64) -> u16 {
        self.read_exact(rva, 2).map_or(0, |b| u16_at(b, 0))
    }

    fn string_at(&self, rva: i64, max_units: u16) -> Option<Vec<u8>> {
        self.pe.utf16_string_at(self.data, rva, max_units as i64)
    }

    /// Decodes every string block under an RT_STRING type directory.
    fn attach_strings(&self, string_type: &mut ResourceDirectory) {
        for block in &mut string_type.entries {
            let block_id = (block.name.is_none()).then_some(block.name_field);
            let ResourceChild::Directory(languages) = &mut block.child else {
                continue;
            };
            let mut table = Vec::new();
            for language in &languages.entries {
                let (ResourceChild::Data(leaf), Some(id)) = (&language.child, block_id) else {
                    continue;
                };
                if let Some(bytes) = self.read(leaf.offset_to_data as i64, leaf.size as i64) {
                    parse_strings(bytes, (id as i64 - 1) * STRINGS_PER_BLOCK, &mut table);
                }
            }
            languages.strings = Some(table);
        }
    }

    fn directory(
        &mut self,
        rva: i64,
        level: usize,
        parents: &mut Vec<i64>,
    ) -> Option<ResourceDirectory> {
        if level > MAX_DEPTH {
            return None;
        }
        let header = self.read_exact(rva, DIRECTORY_HEADER_SIZE)?;
        let mut directory = ResourceDirectory {
            characteristics: u32_at(header, 0),
            time_date_stamp: u32_at(header, 4),
            major_version: u16_at(header, 8),
            minor_version: u16_at(header, 10),
            number_of_named_entries: u16_at(header, 12),
            number_of_id_entries: u16_at(header, 14),
            entries: Vec::new(),
            strings: None,
        };
        let count =
            directory.number_of_named_entries as usize + directory.number_of_id_entries as usize;
        if count > MAX_ENTRIES_PER_DIRECTORY {
            return None;
        }
        self.total_entries += count;
        if self.total_entries > MAX_ENTRIES {
            return None;
        }
        let mut last_name: Option<(i64, i64, usize)> = None;
        for i in 0..count as i64 {
            let Some(raw) =
                self.read_exact(rva + DIRECTORY_HEADER_SIZE + i * ENTRY_SIZE, ENTRY_SIZE)
            else {
                break;
            };
            let (name_field, offset_to_data) = (u32_at(raw, 0), u32_at(raw, 4));
            let target = self.base + (offset_to_data & 0x7FFF_FFFF) as i64;
            let mut name = None;
            if name_field & 0x8000_0000 != 0 {
                let start = self.base + (name_field & 0x7FFF_FFFF) as i64;
                let length = self.word(start);
                if let Some((begin, end, index)) = last_name
                    && begin < start
                    && end >= start
                {
                    if let Some(previous) = directory.entries.get_mut(index) {
                        previous.name = Some(None);
                    }
                    break;
                }
                last_name = Some((start, start + length as i64, directory.entries.len()));
                name = Some(self.string_at(start + 2, length));
            }
            let child = if offset_to_data & 0x8000_0000 != 0 {
                if parents.contains(&target) {
                    break;
                }
                parents.push(target);
                let child = self.directory(target, level + 1, parents);
                parents.pop();
                match child {
                    Some(mut child) => {
                        if name.is_none() && name_field == RT_STRING {
                            self.attach_strings(&mut child);
                        }
                        ResourceChild::Directory(child)
                    }
                    None => break,
                }
            } else {
                let Some(raw) = self.read_exact(target, DATA_ENTRY_SIZE) else {
                    break;
                };
                ResourceChild::Data(ResourceData {
                    offset_to_data: u32_at(raw, 0),
                    size: u32_at(raw, 4),
                    code_page: u32_at(raw, 8),
                    reserved: u32_at(raw, 12),
                })
            };
            directory.entries.push(ResourceEntry {
                name_field,
                offset_to_data,
                name,
                child,
            });
        }
        Some(directory)
    }
}

impl Pe {
    /// pefile's `get_string_u_at_rva`: up to `max_units` UTF-16 units, stopping at a NUL unit.
    /// `None` where pefile raises, and for a negative `max_units`, on which pefile never returns.
    pub(crate) fn utf16_string_at(&self, data: &[u8], rva: i64, max_units: i64) -> Option<Vec<u8>> {
        let read = |rva: i64, length: i64| data.get(self.data_range(rva, Some(length))?);
        if max_units == 0 {
            return Some(Vec::new());
        }
        if max_units < 0 {
            return None;
        }
        read(rva, 2)?;
        let max = max_units.saturating_mul(2);
        let mut bytes = read(rva, max.min(FIRST_STRING_READ))?.to_vec();
        let has_nul = |b: &[u8]| b.as_chunks::<2>().0.contains(&[0, 0]);
        if !has_nul(&bytes) && bytes.len() as i64 == FIRST_STRING_READ && max > FIRST_STRING_READ {
            bytes.extend_from_slice(read(rva + FIRST_STRING_READ, max - FIRST_STRING_READ)?);
        }
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&u| u16::from_le_bytes(u))
            .take_while(|&u| u != 0);
        Some(encode_units(units))
    }

    pub(crate) fn parse_resources(&self, data: &[u8]) -> Option<ResourceDirectory> {
        let directory = self
            .headers
            .optional_header
            .data_directory
            .get(RESOURCE_DIRECTORY)?;
        if directory.virtual_address == 0 {
            return None;
        }
        let base = directory.virtual_address as i64;
        let mut walk = Walk {
            pe: self,
            data,
            base,
            total_entries: 0,
        };
        walk.directory(base, 0, &mut vec![base])
    }
}
