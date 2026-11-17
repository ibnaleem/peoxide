//! The image checksum, following pefile's `generate_checksum`.

use crate::Pe;

/// From the start of the optional header to its `CheckSum` field, in PE32 and PE32+ alike.
const CHECKSUM_FIELD: u64 = 0x40;
/// The PE signature and the file header, which sit between `e_lfanew` and the optional header.
const BEFORE_OPTIONAL_HEADER: u64 = 24;

impl Pe {
    /// The checksum Windows expects in `OPTIONAL_HEADER.CheckSum` for `data`, the file this
    /// `Pe` was parsed from: the file's little-endian dwords summed with end-around carry,
    /// leaving out the dword that holds the checksum field, folded to 16 bits, plus the length.
    pub fn checksum(&self, data: &[u8]) -> u64 {
        // In u64, because `e_lfanew` can sit at the top of a 32-bit `usize`.
        let field = u64::from(self.headers.dos_header.e_lfanew) + BEFORE_OPTIONAL_HEADER;
        let skipped = (field + CHECKSUM_FIELD) / 4;
        let (dwords, tail) = data.as_chunks::<4>();
        let mut padded = [0; 4];
        padded[..tail.len()].copy_from_slice(tail);
        let last = (!tail.is_empty()).then_some(padded);

        let mut sum = dwords
            .iter()
            .copied()
            .chain(last)
            .enumerate()
            .filter(|&(index, _)| index as u64 != skipped)
            .fold(0u64, |sum, (_, dword)| {
                let sum = sum + u32::from_le_bytes(dword) as u64;
                (sum & 0xFFFF_FFFF) + (sum >> 32)
            });
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum += sum >> 16;
        (sum & 0xFFFF) + data.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use crate::parse;
    use crate::tests::DLL;

    #[test]
    fn checksum_ignores_the_stored_checksum_field() {
        let pe = parse(DLL).unwrap();
        let field = pe.headers.dos_header.e_lfanew as usize + 24 + 0x40;
        let mut changed = DLL.to_vec();
        changed[field..field + 4].copy_from_slice(&[0xAA; 4]);
        assert_eq!(pe.checksum(&changed), pe.checksum(DLL));
    }

    #[test]
    fn checksum_pads_a_file_that_is_not_a_whole_number_of_dwords() {
        let pe = parse(DLL).unwrap();
        let mut longer = DLL.to_vec();
        longer.push(1);
        assert_eq!(pe.checksum(&longer), pe.checksum(DLL) + 2);
    }
}
