//! The TLS directory, following pefile's `parse_directory_tls`.

use crate::Pe;

const TLS_DIRECTORY: usize = 9;
const MAGIC_PE32_PLUS: u16 = 0x20b;
const TLS_DIRECTORY_SIZE: usize = 24;
const TLS_DIRECTORY64_SIZE: usize = 40;

/// IMAGE_TLS_DIRECTORY. The four address fields are 32 bits wide in a PE32 image and 64 bits
/// in a PE32+ one.
#[derive(Debug, PartialEq, Eq)]
pub struct TlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

fn uint(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, &byte| (value << 8) | u64::from(byte))
}

impl TlsDirectory {
    /// `raw` holds exactly the struct: 24 bytes, or 40 when `wide`.
    fn read(raw: &[u8], wide: bool) -> Self {
        let width = if wide { 8 } else { 4 };
        let field = |i: usize| uint(&raw[i * width..(i + 1) * width]);
        let tail = 4 * width;
        TlsDirectory {
            start_address_of_raw_data: field(0),
            end_address_of_raw_data: field(1),
            address_of_index: field(2),
            address_of_callbacks: field(3),
            size_of_zero_fill: uint(&raw[tail..tail + 4]) as u32,
            characteristics: uint(&raw[tail + 4..tail + 8]) as u32,
        }
    }
}

impl Pe {
    /// `None` where pefile leaves `DIRECTORY_ENTRY_TLS` undefined: no directory entry, a zero
    /// RVA, or fewer bytes at the RVA than the struct needs. pefile ignores the entry's size.
    pub(crate) fn parse_tls(&self, data: &[u8]) -> Option<TlsDirectory> {
        let directory = self
            .headers
            .optional_header
            .data_directory
            .get(TLS_DIRECTORY)?;
        if directory.virtual_address == 0 {
            return None;
        }
        let wide = self.headers.optional_header.magic == MAGIC_PE32_PLUS;
        let size = if wide {
            TLS_DIRECTORY64_SIZE
        } else {
            TLS_DIRECTORY_SIZE
        };
        let range = self.data_range(directory.virtual_address as i64, Some(size as i64))?;
        let raw = data.get(range).filter(|raw| raw.len() == size)?;
        Some(TlsDirectory::read(raw, wide))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    const DLL: &[u8] = include_bytes!("../../tests/fixtures/sample64.dll");
    const EXE: &[u8] = include_bytes!("../../tests/fixtures/sample32.exe");
    const DRIVER: &[u8] = include_bytes!("../../tests/fixtures/driver.sys");
    const SIZE_ZERO: &[u8] = include_bytes!("../../tests/fixtures/crafted/tls_size_zero.dll");
    const OUTSIDE_SECTIONS: &[u8] =
        include_bytes!("../../tests/fixtures/crafted/tls_outside_sections.dll");

    /// `data` with the TLS data directory entry set to `rva` and `size`.
    fn with_tls_entry(data: &[u8], rva: u32, size: u32) -> Vec<u8> {
        let pe = parse(data).unwrap();
        let wide = pe.headers.optional_header.magic == MAGIC_PE32_PLUS;
        let directories =
            pe.headers.dos_header.e_lfanew as usize + 24 + if wide { 112 } else { 96 };
        let at = directories + TLS_DIRECTORY * 8;
        let mut out = data.to_vec();
        out[at..at + 4].copy_from_slice(&rva.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        out
    }

    fn tls(data: &[u8]) -> Option<TlsDirectory> {
        parse(data).unwrap().parse_tls(data)
    }

    #[test]
    fn reads_the_pe32_plus_struct_with_64_bit_addresses() {
        let tls = tls(DLL).expect("the DLL fixture has a TLS directory");
        assert!(tls.start_address_of_raw_data > u64::from(u32::MAX));
        assert_eq!(
            tls.end_address_of_raw_data - tls.start_address_of_raw_data,
            0x10
        );
        assert_eq!(tls.size_of_zero_fill, 0x20);
        assert_eq!(tls.characteristics, 0x0030_0000);
    }

    #[test]
    fn reads_the_pe32_struct_with_32_bit_addresses() {
        let tls = tls(EXE).expect("the EXE fixture has a TLS directory");
        assert!(tls.start_address_of_raw_data >= 0x40_0000);
        assert!(tls.address_of_callbacks <= u64::from(u32::MAX));
        assert_eq!(tls.size_of_zero_fill, 0x20);
        assert_eq!(tls.characteristics, 0x0030_0000);
    }

    #[test]
    fn is_absent_without_a_directory_rva() {
        assert_eq!(tls(DRIVER), None);
        let entry = parse(DLL).unwrap().headers.optional_header.data_directory[TLS_DIRECTORY];
        assert_eq!(tls(&with_tls_entry(DLL, 0, entry.size)), None);
    }

    #[test]
    fn ignores_the_directory_size() {
        assert!(tls(SIZE_ZERO).is_some());
    }

    #[test]
    fn reads_an_rva_outside_every_section_as_a_file_offset() {
        let pe = parse(OUTSIDE_SECTIONS).unwrap();
        let rva = pe.headers.optional_header.data_directory[TLS_DIRECTORY].virtual_address;
        assert_eq!(pe.section_by_rva(rva as i64), None);
        let tls = pe
            .parse_tls(OUTSIDE_SECTIONS)
            .expect("read from the file offset");
        let at = rva as usize;
        assert_eq!(
            tls.start_address_of_raw_data,
            uint(&OUTSIDE_SECTIONS[at..at + 8])
        );
    }

    #[test]
    fn is_absent_when_the_struct_is_cut_short() {
        // The last 24 bytes of the file: a whole PE32 struct, but short of a PE32+ one.
        let rva = parse(DLL)
            .unwrap()
            .sections
            .last()
            .map(|s| s.virtual_address + s.size_of_raw_data - TLS_DIRECTORY_SIZE as u32);
        assert_eq!(tls(&with_tls_entry(DLL, rva.unwrap(), 40)), None);
        let last = parse(EXE)
            .unwrap()
            .sections
            .last()
            .map(|s| s.virtual_address + s.size_of_raw_data - TLS_DIRECTORY_SIZE as u32);
        assert!(tls(&with_tls_entry(EXE, last.unwrap(), 24)).is_some());
    }

    #[test]
    fn is_absent_for_an_rva_past_the_file() {
        assert_eq!(
            tls(&with_tls_entry(DLL, DLL.len() as u32 + 0x10_0000, 40)),
            None
        );
        assert_eq!(tls(&with_tls_entry(DLL, u32::MAX - 3, 40)), None);
        assert_eq!(tls(&with_tls_entry(EXE, u32::MAX, 24)), None);
    }
}
