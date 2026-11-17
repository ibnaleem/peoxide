//! The delay-load import table, which goblin does not parse. Follows pefile's
//! `parse_delay_import_directory`.

use crate::imports::is_valid_dos_filename;
use crate::{ImportDll, Pe};

const DELAY_IMPORT_DIRECTORY: usize = 13;
const DESCRIPTOR_SIZE: i64 = 32;
const MAX_EMPTY_DESCRIPTORS: u32 = 5;
const MACHINE_I386: u16 = 0x14c;

struct Descriptor {
    attributes: u32,
    name: i64,
    iat: i64,
    int: i64,
}

impl Pe {
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
                .import_symbols(data, descriptor.int, descriptor.iat, max_length, vas)
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
