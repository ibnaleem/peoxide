//! The delay-load import table, which goblin does not parse. Follows pefile's
//! `parse_delay_import_directory` and `parse_imports`.
//!
//! Not ported: pefile's repeated-address and address-spread heuristics for bogus thunk
//! tables, and its global import-symbol cap. Clean binaries never reach them.

use crate::{ImportDll, ImportSymbol, Pe};

const DELAY_IMPORT_DIRECTORY: usize = 13;
const DESCRIPTOR_SIZE: i64 = 32;
const MAX_NAME_LENGTH: i64 = 0x200;
const MAX_EMPTY_DESCRIPTORS: u32 = 5;
const MACHINE_I386: u16 = 0x14c;
const MAGIC_PE32_PLUS: u16 = 0x20b;
const ORDINAL_FLAG_32: u64 = 0x8000_0000;
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;
/// pefile drops a whole thunk table when an "ordinal" does not fit in 16 bits.
const MAX_ORDINAL: u64 = 0xFFFF;

const DOS_FILENAME_EXTRA: &[u8] = b"!#$%&'()-@^_`{}~+,.;=[]:\\/";
const FUNCTION_NAME_EXTRA: &[u8] = b"._?@$()<>";

fn is_valid_dos_filename(name: &[u8]) -> bool {
    name.iter()
        .all(|b| b.is_ascii_alphanumeric() || DOS_FILENAME_EXTRA.contains(b))
}

fn is_valid_function_name(name: &[u8]) -> bool {
    name.iter()
        .all(|b| b.is_ascii_alphanumeric() || FUNCTION_NAME_EXTRA.contains(b))
}

struct Descriptor {
    attributes: u32,
    name: i64,
    iat: i64,
    int: i64,
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

    fn uint_at(&self, data: &[u8], rva: i64, size: usize) -> Option<u64> {
        let bytes = self.bytes_at(data, rva, size as i64)?;
        (bytes.len() == size).then(|| {
            bytes
                .iter()
                .rev()
                .fold(0u64, |value, &b| (value << 8) | b as u64)
        })
    }

    fn c_string_at(&self, data: &[u8], rva: i64) -> Vec<u8> {
        let bytes = self
            .bytes_at(data, rva, MAX_NAME_LENGTH)
            .unwrap_or_default();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        bytes[..end].to_vec()
    }

    /// pefile's `normalize_import_va`: turn an in-image VA into an RVA, leave anything else.
    fn normalize_va(&self, va: i64) -> i64 {
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

    /// pefile's `parse_imports`; `None` where it raises and the descriptor is dropped.
    fn import_symbols(
        &self,
        data: &[u8],
        descriptor: &Descriptor,
        max_length: i64,
        vas: bool,
    ) -> Option<Vec<ImportSymbol>> {
        let entries = |rva| match self.thunk_table(data, rva, max_length, vas) {
            ThunkTable::Entries(entries) if !entries.is_empty() => Some(entries),
            _ => None,
        };
        let table = entries(descriptor.int).or_else(|| entries(descriptor.iat))?;
        let address_mask = self.ordinal_flag() - 1;
        let image_base = self.headers.optional_header.image_base;
        let iat_va = image_base.saturating_add(descriptor.iat as u64);
        let mut symbols = Vec::new();
        for (index, value) in table.into_iter().enumerate() {
            let address = iat_va.saturating_add((index * self.thunk_size()) as u64);
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

    fn descriptor_at(&self, data: &[u8], rva: i64) -> Option<Descriptor> {
        let field = |i: i64| self.uint_at(data, rva + 4 * i, 4).map(|v| v as i64);
        let fields: Vec<i64> = (0..8).map(field).collect::<Option<_>>()?;
        if fields.iter().all(|&f| f == 0) {
            return None;
        }
        Some(Descriptor {
            attributes: fields[0] as u32,
            name: fields[1],
            iat: fields[3],
            int: fields[4],
        })
    }

    pub(crate) fn parse_delay_imports(&self, data: &[u8]) -> Vec<ImportDll> {
        let Some(directory) = self
            .headers
            .optional_header
            .data_directory
            .get(DELAY_IMPORT_DIRECTORY)
        else {
            return Vec::new();
        };
        let mut rva = directory.virtual_address as i64;
        let mut dlls = Vec::new();
        let mut empty_descriptors = 0;
        // Each descriptor is read from the file, so the walk never spans more than the file.
        let end = rva.saturating_add(self.file_size as i64);
        while rva != 0 && rva < end {
            let Some(file_offset) = self.offset_from_rva(rva) else {
                break;
            };
            let Some(mut descriptor) = self.descriptor_at(data, rva) else {
                break;
            };
            let vas =
                descriptor.attributes == 0 && self.headers.file_header.machine == MACHINE_I386;
            if vas {
                descriptor.name = self.normalize_va(descriptor.name);
                descriptor.iat = self.normalize_va(descriptor.iat);
                descriptor.int = self.normalize_va(descriptor.int);
            }
            rva += DESCRIPTOR_SIZE;
            let max_length = if rva > descriptor.int || rva > descriptor.iat {
                (rva - descriptor.int).max(rva - descriptor.iat)
            } else {
                self.file_size as i64 - file_offset
            }
            .min(self.file_size as i64);
            if empty_descriptors > MAX_EMPTY_DESCRIPTORS {
                break;
            }
            let symbols = self
                .import_symbols(data, &descriptor, max_length, vas)
                .unwrap_or_default();
            if symbols.is_empty() {
                empty_descriptors += 1;
                continue;
            }
            let dll = self.c_string_at(data, descriptor.name);
            let dll = if is_valid_dos_filename(&dll) {
                dll
            } else {
                b"*invalid*".to_vec()
            };
            if !dll.is_empty() {
                dlls.push(ImportDll {
                    dll,
                    imports: symbols,
                });
            }
        }
        dlls
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn normalize_va_leaves_small_values_below_a_huge_image_base() {
        // ImageBase 0xFFFFFFFFFFFFF000 is negative as an i64.
        let pe = crate::parse(include_bytes!(
            "../../tests/fixtures/crafted/top_image_base.dll"
        ))
        .unwrap();
        assert_eq!(pe.normalize_va(0x1000), 0x1000);
    }
}
