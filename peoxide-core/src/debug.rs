//! The debug directory, following pefile's `parse_debug_directory`.
//!
//! CodeView (PDB 7.0 and 2.0) and extended DLL-characteristics entries are decoded. Other
//! entry types, including the rare IMAGE_DEBUG_TYPE_MISC, carry `entry: None`.

use crate::Pe;

const DEBUG_DIRECTORY: usize = 6;
const DIRECTORY_ENTRY_SIZE: usize = 28;
const TYPE_CODEVIEW: u32 = 2;
const TYPE_EX_DLLCHARACTERISTICS: u32 = 20;
const PDB70_FIXED_SIZE: usize = 24;
const PDB20_FIXED_SIZE: usize = 16;

pub struct DebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub entry: Option<DebugEntry>,
}

pub enum DebugEntry {
    /// An `RSDS` CodeView record.
    Pdb70 {
        cv_signature: [u8; 4],
        guid_data1: u32,
        guid_data2: u16,
        guid_data3: u16,
        guid_data4: u8,
        guid_data5: u8,
        guid_data6: [u8; 6],
        age: u32,
        /// The raw bytes after the fixed fields, trailing NULs included, as pefile keeps them.
        pdb_file_name: Option<Vec<u8>>,
    },
    /// An `NB10` CodeView record.
    Pdb20 {
        cv_header_signature: u32,
        cv_header_offset: u32,
        signature: u32,
        age: u32,
        pdb_file_name: Option<Vec<u8>>,
    },
    ExDllCharacteristics(u32),
}

impl DebugEntry {
    /// pefile's `Signature_String`: the GUID's hex digits without dashes, then the age.
    pub fn pdb70_signature_string(&self) -> Option<String> {
        let DebugEntry::Pdb70 {
            guid_data1,
            guid_data2,
            guid_data3,
            guid_data4,
            guid_data5,
            guid_data6,
            age,
            ..
        } = self
        else {
            return None;
        };
        let node: String = guid_data6.iter().map(|b| format!("{b:02X}")).collect();
        Some(format!(
            "{guid_data1:08X}{guid_data2:04X}{guid_data3:04X}{guid_data4:02X}{guid_data5:02X}{node}{age:X}"
        ))
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The file name pefile expects after the fixed part, or `None` when the data is too short or
/// the name would overdraw `budget`.
fn split_name(
    record: &[u8],
    fixed: usize,
    declared_size: usize,
    budget: &mut usize,
) -> Option<Option<Vec<u8>>> {
    let name_size = declared_size.saturating_sub(fixed);
    if record.len() < fixed + name_size {
        return None;
    }
    *budget = budget.checked_sub(name_size)?;
    Some((name_size > 0).then(|| record[fixed..fixed + name_size].to_vec()))
}

fn decode_entry(
    record: &[u8],
    debug_type: u32,
    declared_size: usize,
    budget: &mut usize,
) -> Option<DebugEntry> {
    match debug_type {
        TYPE_CODEVIEW if record.starts_with(b"RSDS") && record.len() >= PDB70_FIXED_SIZE => {
            let pdb_file_name = split_name(record, PDB70_FIXED_SIZE, declared_size, budget)?;
            Some(DebugEntry::Pdb70 {
                cv_signature: record[0..4].try_into().ok()?,
                guid_data1: u32_at(record, 4),
                guid_data2: u16_at(record, 8),
                guid_data3: u16_at(record, 10),
                guid_data4: record[12],
                guid_data5: record[13],
                guid_data6: record[14..20].try_into().ok()?,
                age: u32_at(record, 20),
                pdb_file_name,
            })
        }
        TYPE_CODEVIEW if record.starts_with(b"NB10") && record.len() >= PDB20_FIXED_SIZE => {
            let pdb_file_name = split_name(record, PDB20_FIXED_SIZE, declared_size, budget)?;
            Some(DebugEntry::Pdb20 {
                cv_header_signature: u32_at(record, 0),
                cv_header_offset: u32_at(record, 4),
                signature: u32_at(record, 8),
                age: u32_at(record, 12),
                pdb_file_name,
            })
        }
        TYPE_EX_DLLCHARACTERISTICS if record.len() >= 4 => {
            Some(DebugEntry::ExDllCharacteristics(u32_at(record, 0)))
        }
        _ => None,
    }
}

impl Pe {
    /// Empty when any directory record is unreadable, as pefile drops the whole list then.
    pub(crate) fn parse_debug_directory(&self, data: &[u8]) -> Vec<DebugDirectory> {
        let Some(directory) = self
            .headers
            .optional_header
            .data_directory
            .get(DEBUG_DIRECTORY)
        else {
            return Vec::new();
        };
        if directory.virtual_address == 0 {
            return Vec::new();
        }
        let count = directory.size as usize / DIRECTORY_ENTRY_SIZE;
        let base = directory.virtual_address as i64;
        // Entries may all point at one record, so the copied PDB names are capped at the file
        // size; a real file's records are disjoint and stay under it. pefile has no cap.
        let mut name_budget = data.len();
        (0..count)
            .map(|i| {
                let rva = base + (i * DIRECTORY_ENTRY_SIZE) as i64;
                let raw = data.get(self.data_range(rva, Some(DIRECTORY_ENTRY_SIZE as i64))?)?;
                (raw.len() == DIRECTORY_ENTRY_SIZE)
                    .then(|| self.debug_entry(data, raw, &mut name_budget))
            })
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default()
    }

    fn debug_entry(&self, data: &[u8], raw: &[u8], name_budget: &mut usize) -> DebugDirectory {
        let debug_type = u32_at(raw, 12);
        let size_of_data = u32_at(raw, 16);
        let pointer_to_raw_data = u32_at(raw, 24);
        let start = pointer_to_raw_data as i64;
        let record = &data[crate::clamp((start, start + size_of_data as i64), data.len())];
        DebugDirectory {
            characteristics: u32_at(raw, 0),
            time_date_stamp: u32_at(raw, 4),
            major_version: u16_at(raw, 8),
            minor_version: u16_at(raw, 10),
            debug_type,
            size_of_data,
            address_of_raw_data: u32_at(raw, 20),
            pointer_to_raw_data,
            entry: decode_entry(record, debug_type, size_of_data as usize, name_budget),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECTION_RVA: u32 = 0x1000;
    const SECTION_OFFSET: usize = 0x200;

    /// A one-section PE32+ whose debug directory holds `count` CodeView entries, all pointing
    /// at the same RSDS record of `record_len` bytes.
    fn pe_with_shared_rsds(count: usize, record_len: usize) -> Vec<u8> {
        let records_len = count * DIRECTORY_ENTRY_SIZE;
        let mut body = Vec::new();
        for _ in 0..count {
            for field in [0u32, 0, 0, TYPE_CODEVIEW, record_len as u32] {
                body.extend(field.to_le_bytes());
            }
            body.extend((SECTION_RVA + records_len as u32).to_le_bytes());
            body.extend(((SECTION_OFFSET + records_len) as u32).to_le_bytes());
        }
        assert_eq!(body.len(), records_len);
        body.extend(b"RSDS");
        body.resize(records_len + PDB70_FIXED_SIZE, 0x11);
        body.resize(records_len + record_len, b'p');
        let raw_size = body.len().next_multiple_of(0x200);
        body.resize(raw_size, 0);

        let mut head = vec![0u8; SECTION_OFFSET];
        head[0..2].copy_from_slice(b"MZ");
        head[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let put = |head: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            head[at..at + bytes.len()].copy_from_slice(bytes)
        };
        put(&mut head, 0x40, b"PE\0\0");
        put(&mut head, 0x44, &0x8664u16.to_le_bytes());
        put(&mut head, 0x46, &1u16.to_le_bytes());
        put(&mut head, 0x54, &240u16.to_le_bytes());
        put(&mut head, 0x56, &0x2022u16.to_le_bytes());
        let opt = 0x58;
        put(&mut head, opt, &0x20Bu16.to_le_bytes());
        put(&mut head, opt + 24, &0x1_8000_0000u64.to_le_bytes());
        put(&mut head, opt + 32, &0x1000u32.to_le_bytes());
        put(&mut head, opt + 36, &0x200u32.to_le_bytes());
        put(&mut head, opt + 40, &6u16.to_le_bytes());
        put(&mut head, opt + 48, &6u16.to_le_bytes());
        let size_of_image = (SECTION_RVA as usize + raw_size).next_multiple_of(0x1000);
        put(&mut head, opt + 56, &(size_of_image as u32).to_le_bytes());
        put(&mut head, opt + 60, &(SECTION_OFFSET as u32).to_le_bytes());
        put(&mut head, opt + 68, &3u16.to_le_bytes());
        put(&mut head, opt + 108, &16u32.to_le_bytes());
        let debug_dir = opt + 112 + 8 * DEBUG_DIRECTORY;
        put(&mut head, debug_dir, &SECTION_RVA.to_le_bytes());
        put(
            &mut head,
            debug_dir + 4,
            &(records_len as u32).to_le_bytes(),
        );
        let section = opt + 240;
        put(&mut head, section, b".rdata");
        for (at, field) in [raw_size, SECTION_RVA as usize, raw_size, SECTION_OFFSET]
            .into_iter()
            .enumerate()
        {
            put(
                &mut head,
                section + 8 + 4 * at,
                &(field as u32).to_le_bytes(),
            );
        }
        put(&mut head, section + 36, &0x4000_0040u32.to_le_bytes());
        [head, body].concat()
    }

    fn name_len(directory: &DebugDirectory) -> usize {
        match &directory.entry {
            Some(DebugEntry::Pdb70 {
                pdb_file_name: Some(name),
                ..
            }) => name.len(),
            _ => 0,
        }
    }

    #[test]
    fn shared_codeview_records_copy_no_more_than_the_file() {
        let (count, record_len) = (300, 4096);
        let data = pe_with_shared_rsds(count, record_len);
        let debug = crate::parse(&data).unwrap().debug;

        assert_eq!(debug.len(), count);
        assert_eq!(name_len(&debug[0]), record_len - PDB70_FIXED_SIZE);
        let copied: usize = debug.iter().map(name_len).sum();
        assert!(
            copied <= data.len(),
            "{copied} name bytes copied from a {}-byte file",
            data.len()
        );
    }
}
