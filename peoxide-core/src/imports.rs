//! Thunk tables, shared by the import and delay-import walks. Follows pefile's
//! `get_import_table` and `parse_imports`.
//!
//! Not ported: pefile's repeated-address and address-spread heuristics for bogus thunk
//! tables. Clean binaries never reach them.

use crate::{ImportSymbol, Pe};

const MAX_NAME_LENGTH: i64 = 0x200;
const MAGIC_PE32_PLUS: u16 = 0x20b;
const ORDINAL_FLAG_32: u64 = 0x8000_0000;
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;
/// pefile drops a whole thunk table when an "ordinal" does not fit in 16 bits.
const MAX_ORDINAL: u64 = 0xFFFF;

const DOS_FILENAME_EXTRA: &[u8] = b"!#$%&'()-@^_`{}~+,.;=[]:\\/";
const FUNCTION_NAME_EXTRA: &[u8] = b"._?@$()<>";

pub(crate) fn is_valid_dos_filename(name: &[u8]) -> bool {
    name.iter()
        .all(|b| b.is_ascii_alphanumeric() || DOS_FILENAME_EXTRA.contains(b))
}

fn is_valid_function_name(name: &[u8]) -> bool {
    name.iter()
        .all(|b| b.is_ascii_alphanumeric() || FUNCTION_NAME_EXTRA.contains(b))
}

/// What a thunk read can yield: pefile treats a failed read and a bogus ordinal differently.
enum ThunkTable {
    Unreadable,
    Entries(Vec<u64>),
}

impl Pe {
    fn bytes_at<'a>(&self, data: &'a [u8], rva: i64, len: i64) -> Option<&'a [u8]> {
        data.get(self.data_range(rva, Some(len))?)
    }

    pub(crate) fn uint_at(&self, data: &[u8], rva: i64, size: usize) -> Option<u64> {
        let bytes = self.bytes_at(data, rva, size as i64)?;
        (bytes.len() == size).then(|| {
            bytes
                .iter()
                .rev()
                .fold(0u64, |value, &b| (value << 8) | b as u64)
        })
    }

    pub(crate) fn c_string_at(&self, data: &[u8], rva: i64) -> Vec<u8> {
        let bytes = self
            .bytes_at(data, rva, MAX_NAME_LENGTH)
            .unwrap_or_default();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        bytes[..end].to_vec()
    }

    /// pefile's `normalize_import_va`: turn an in-image VA into an RVA, leave anything else.
    pub(crate) fn normalize_va(&self, va: i64) -> i64 {
        // i128 holds every u64 ImageBase and its end, so the range matches pefile's ints.
        let base = i128::from(self.headers.optional_header.image_base);
        let end = base + i128::from(self.headers.optional_header.size_of_image);
        if (base..end).contains(&i128::from(va)) {
            // va lies in [base, end) and base >= 0, so the difference fits an i64.
            (i128::from(va) - base) as i64
        } else {
            va
        }
    }

    fn thunk_size(&self) -> usize {
        if self.headers.optional_header.magic == MAGIC_PE32_PLUS {
            8
        } else {
            4
        }
    }

    fn ordinal_flag(&self) -> u64 {
        if self.thunk_size() == 8 {
            ORDINAL_FLAG_64
        } else {
            ORDINAL_FLAG_32
        }
    }

    /// pefile's `get_import_table`.
    fn thunk_table(&self, data: &[u8], start: i64, max_length: i64, vas: bool) -> ThunkTable {
        let size = self.thunk_size();
        let mut entries = Vec::new();
        let mut rva = start;
        while rva != 0 && rva < start.saturating_add(max_length) {
            let Some(raw) = self.uint_at(data, rva, size) else {
                return ThunkTable::Unreadable;
            };
            let value = if vas {
                self.normalize_va(raw as i64) as u64
            } else {
                raw
            };
            if (start..=rva).contains(&(value as i64)) {
                break;
            }
            if value & self.ordinal_flag() != 0 && value & 0x7FFF_FFFF > MAX_ORDINAL {
                return ThunkTable::Entries(Vec::new());
            }
            if value == 0 {
                break;
            }
            entries.push(value);
            rva += size as i64;
        }
        ThunkTable::Entries(entries)
    }

    /// pefile's `parse_imports` for the lookup table at `int` and the address table at
    /// `iat`; `None` where it raises and the descriptor is dropped.
    pub(crate) fn import_symbols(
        &self,
        data: &[u8],
        int: i64,
        iat: i64,
        max_length: i64,
        vas: bool,
    ) -> Option<Vec<ImportSymbol>> {
        let entries = |rva| match self.thunk_table(data, rva, max_length, vas) {
            ThunkTable::Entries(entries) if !entries.is_empty() => Some(entries),
            _ => None,
        };
        let table = entries(int).or_else(|| entries(iat))?;
        let address_mask = self.ordinal_flag() - 1;
        let image_base = self.headers.optional_header.image_base;
        let mut symbols = Vec::new();
        for (index, value) in table.into_iter().enumerate() {
            let address = crate::iat_slot_address(image_base, iat as u64, index, self.thunk_size());
            if value & self.ordinal_flag() != 0 {
                let ordinal = (value & 0xFFFF) as u16;
                if ordinal != 0 {
                    symbols.push(ImportSymbol {
                        name: None,
                        hint: None,
                        ordinal: Some(ordinal),
                        address,
                    });
                }
                continue;
            }
            let hint_rva = (value & address_mask) as i64;
            let hint = self.uint_at(data, hint_rva, 2)? as u16;
            let name = self.c_string_at(data, (value as i64).saturating_add(2));
            if !name.is_empty() && is_valid_function_name(&name) {
                symbols.push(ImportSymbol {
                    name: Some(name),
                    hint: Some(hint),
                    ordinal: None,
                    address,
                });
            }
        }
        Some(symbols)
    }
}
