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
