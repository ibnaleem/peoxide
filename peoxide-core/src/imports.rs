//! The import and delay-import directories, walked by one loop. Follows pefile's
//! `parse_import_directory`, `parse_delay_import_directory`, `get_import_table` and
//! `parse_imports`. goblin parses imports too, but it reads every table in full and skips
//! delay imports, so peoxide does not use it.
//!
//! Not ported: pefile's repeated-address and address-spread heuristics for bogus thunk
//! tables. Clean binaries never reach them.

use crate::{ImportDll, ImportSymbol, Pe};

/// pefile's cap on thunk-table entries read per file, across imports and delay imports.
/// Without it, many descriptors sharing one long table cost descriptors x entries.
const MAX_IMPORT_SYMBOLS: u32 = 0x2000;
const MAX_EMPTY_DESCRIPTORS: u32 = 5;
const MACHINE_I386: u16 = 0x14c;

/// Where the two directories differ. Field positions count 4-byte words.
struct DirectoryKind {
    index: usize,
    descriptor_size: i64,
    attributes: Option<usize>,
    name: usize,
    int: usize,
    iat: usize,
    /// pefile keeps the partly read table that passed the cap in the import directory, but
    /// drops it from the delay-import directory.
    drops_descriptor_over_cap: bool,
}

/// `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORTS: DirectoryKind = DirectoryKind {
    index: 1,
    descriptor_size: 20,
    attributes: None,
    name: 3,
    int: 0,
    iat: 4,
    drops_descriptor_over_cap: false,
};

/// `IMAGE_DELAYLOAD_DESCRIPTOR`.
const DELAY_IMPORTS: DirectoryKind = DirectoryKind {
    index: 13,
    descriptor_size: 32,
    attributes: Some(0),
    name: 1,
    int: 4,
    iat: 3,
    drops_descriptor_over_cap: true,
};

/// A descriptor's name and tables as RVAs. `vas` marks tables whose entries are VAs.
struct Descriptor {
    name: i64,
    int: i64,
    iat: i64,
    vas: bool,
}
const MAX_NAME_LENGTH: i64 = 0x200;
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

    /// pefile's `get_import_table`. `symbols_read` counts every entry read in the file, the
    /// terminator included, and the table stops short once it passes `MAX_IMPORT_SYMBOLS`.
    fn thunk_table(
        &self,
        data: &[u8],
        start: i64,
        max_length: i64,
        vas: bool,
        symbols_read: &mut u32,
    ) -> ThunkTable {
        let size = self.thunk_size();
        let mut entries = Vec::new();
        let mut rva = start;
        while rva != 0 && rva < start.saturating_add(max_length) {
            if *symbols_read > MAX_IMPORT_SYMBOLS {
                break;
            }
            *symbols_read += 1;
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

    /// pefile's `parse_imports` for a descriptor's lookup and address tables; `None` where
    /// it raises and the descriptor is dropped.
    fn import_symbols(
        &self,
        data: &[u8],
        descriptor: &Descriptor,
        max_length: i64,
        symbols_read: &mut u32,
    ) -> Option<Vec<ImportSymbol>> {
        let entries = |table| match table {
            ThunkTable::Entries(entries) if !entries.is_empty() => Some(entries),
            _ => None,
        };
        let vas = descriptor.vas;
        // pefile reads both tables, so both count towards the cap.
        let lookup = self.thunk_table(data, descriptor.int, max_length, vas, symbols_read);
        let addresses = self.thunk_table(data, descriptor.iat, max_length, vas, symbols_read);
        let table = entries(lookup).or_else(|| entries(addresses))?;
        let address_mask = self.ordinal_flag() - 1;
        let image_base = self.headers.optional_header.image_base;
        let iat = descriptor.iat as u64;
        let mut symbols = Vec::new();
        for (index, value) in table.into_iter().enumerate() {
            let address = crate::iat_slot_address(image_base, iat, index, self.thunk_size());
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

    /// The import and delay-import tables, with pefile's one `MAX_IMPORT_SYMBOLS` counter
    /// carried from the first into the second.
    pub(crate) fn parse_import_directories(&self, data: &[u8]) -> (Vec<ImportDll>, Vec<ImportDll>) {
        let mut symbols_read = 0;
        let imports = self.import_directory(data, &IMPORTS, &mut symbols_read);
        let delay_imports = self.import_directory(data, &DELAY_IMPORTS, &mut symbols_read);
        (imports, delay_imports)
    }

    /// A descriptor's fields; `None` at the all-zero terminator or where it cannot be read.
    fn descriptor_at(&self, data: &[u8], rva: i64, kind: &DirectoryKind) -> Option<Descriptor> {
        let field = |i: i64| self.uint_at(data, rva + 4 * i, 4).map(|v| v as i64);
        let fields: Vec<i64> = (0..kind.descriptor_size / 4)
            .map(field)
            .collect::<Option<_>>()?;
        if fields.iter().all(|&f| f == 0) {
            return None;
        }
        // Old delay descriptors (attributes 0, x86 only) hold VAs instead of RVAs.
        let vas = kind.attributes.is_some_and(|i| fields[i] == 0)
            && self.headers.file_header.machine == MACHINE_I386;
        let address = |i: usize| {
            if vas {
                self.normalize_va(fields[i])
            } else {
                fields[i]
            }
        };
        Some(Descriptor {
            name: address(kind.name),
            int: address(kind.int),
            iat: address(kind.iat),
            vas,
        })
    }

    /// pefile's bound on a descriptor's thunk tables. `next` is the RVA after the descriptor.
    fn table_max_length(&self, descriptor: &Descriptor, next: i64, file_offset: i64) -> i64 {
        let (int, iat) = (descriptor.int, descriptor.iat);
        let max_length = if next > int || next > iat {
            (next - int).max(next - iat)
        } else {
            self.file_size as i64 - file_offset
        };
        max_length.min(self.file_size as i64)
    }

    fn dll_name(&self, data: &[u8], rva: i64) -> Vec<u8> {
        let name = self.c_string_at(data, rva);
        if is_valid_dos_filename(&name) {
            name
        } else {
            b"*invalid*".to_vec()
        }
    }

    /// pefile's `parse_import_directory` and `parse_delay_import_directory`.
    fn import_directory(
        &self,
        data: &[u8],
        kind: &DirectoryKind,
        symbols_read: &mut u32,
    ) -> Vec<ImportDll> {
        let Some(directory) = self.headers.optional_header.data_directory.get(kind.index) else {
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
            let Some(descriptor) = self.descriptor_at(data, rva, kind) else {
                break;
            };
            rva += kind.descriptor_size;
            let max_length = self.table_max_length(&descriptor, rva, file_offset);
            // pefile reads the tables before it checks the error count.
            let symbols = self
                .import_symbols(data, &descriptor, max_length, symbols_read)
                .unwrap_or_default();
            if empty_descriptors > MAX_EMPTY_DESCRIPTORS {
                break;
            }
            if symbols.is_empty() {
                empty_descriptors += 1;
                continue;
            }
            if kind.drops_descriptor_over_cap && *symbols_read > MAX_IMPORT_SYMBOLS {
                break;
            }
            let dll = self.dll_name(data, descriptor.name);
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
