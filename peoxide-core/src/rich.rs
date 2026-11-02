//! The Rich header, following pefile's `parse_rich_header`.

const RICH: u32 = 0x6863_6952;
const RICH_SEARCH_START: usize = 0x80;

pub struct RichHeader {
    pub checksum: u32,
    /// `(comp_id, count)` pairs, flattened and decrypted, as pefile lists them.
    pub values: Vec<u32>,
    pub key: [u8; 4],
    pub raw_data: Vec<u8>,
    pub clear_data: Vec<u8>,
}

/// `None` when no `Rich` marker sits between offset 0x80 and the optional header.
pub(crate) fn parse(data: &[u8], optional_header_offset: usize) -> Option<RichHeader> {
    let search = data.get(RICH_SEARCH_START..optional_header_offset.min(data.len()))?;
    let rich_index = RICH_SEARCH_START + search.windows(4).position(|w| w == b"Rich")?;
    let block = &data[RICH_SEARCH_START..(rich_index + 8).min(data.len())];
    let dwords: Vec<u32> = block
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&c| u32::from_le_bytes(c))
        .collect();
    let checksum = *dwords.get(dwords.iter().position(|&d| d == RICH)? + 1)?;
    let key = checksum.to_le_bytes();
    let raw_data = data[RICH_SEARCH_START..rich_index].to_vec();
    let clear_data = raw_data
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect();
    let values = dwords
        .get(4..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .take_while(|&&[id, _]| id != RICH)
        .flat_map(|&[id, count]| [id ^ checksum, count ^ checksum])
        .collect();
    Some(RichHeader {
        checksum,
        values,
        key,
        raw_data,
        clear_data,
    })
}
