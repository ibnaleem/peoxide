//! Base relocations, following pefile's `parse_relocations_directory`.

use crate::Pe;

const BASERELOC_DIRECTORY: usize = 5;
const BLOCK_HEADER_SIZE: i64 = 8;

pub struct RelocationBlock {
    pub virtual_address: u32,
    pub size_of_block: u32,
    pub entries: Vec<Relocation>,
}

pub struct Relocation {
    pub data: u16,
    pub reloc_type: u16,
    /// The block's `virtual_address` plus the entry's 12-bit offset.
    pub rva: u64,
}

/// Which block last held each 16-bit entry value. An entry is its `(offset, type)` pair, so
/// one slot per value finds a repeat without hashing, and one table serves every block.
struct Seen {
    block_of: Vec<u32>,
    block: u32,
}

impl Seen {
    fn new() -> Self {
        Self {
            block_of: vec![0; 1 << 16],
            block: 0,
        }
    }

    /// Call once per block, before its entries. A block is at least 8 bytes of a file whose
    /// length fits in memory, so the counter cannot wrap round to a number still in the table.
    fn next_block(&mut self) {
        self.block += 1;
    }

    /// True the first time `entry` appears in the current block.
    fn insert(&mut self, entry: u16) -> bool {
        let slot = &mut self.block_of[entry as usize];
        let first = *slot != self.block;
        *slot = self.block;
        first
    }
}

/// Entries up to the first repeated `(offset, type)` pair, where pefile stops.
fn entries(bytes: &[u8], base: u32, seen: &mut Seen) -> Vec<Relocation> {
    seen.next_block();
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .map_while(|data| {
            let (reloc_type, offset) = (data >> 12, data & 0x0FFF);
            seen.insert(data).then_some(Relocation {
                data,
                reloc_type,
                rva: base as u64 + offset as u64,
            })
        })
        .collect()
}

impl Pe {
    fn read<'a>(&self, data: &'a [u8], rva: i64, length: i64) -> Option<&'a [u8]> {
        data.get(self.data_range(rva, Some(length))?)
    }

    pub(crate) fn parse_relocations(&self, data: &[u8]) -> Vec<RelocationBlock> {
        let Some(directory) = self
            .headers
            .optional_header
            .data_directory
            .get(BASERELOC_DIRECTORY)
        else {
            return Vec::new();
        };
        if directory.virtual_address == 0 {
            return Vec::new();
        }
        let size_of_image = self.headers.optional_header.size_of_image;
        let mut rva = directory.virtual_address as i64;
        let end = rva + directory.size as i64;
        let mut blocks = Vec::new();
        let mut seen = Seen::new();
        while rva < end {
            let Some(header) = self
                .read(data, rva, BLOCK_HEADER_SIZE)
                .filter(|h| h.len() == BLOCK_HEADER_SIZE as usize)
            else {
                break;
            };
            let virtual_address = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let size_of_block = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if virtual_address > size_of_image || size_of_block > size_of_image {
                break;
            }
            let body = self.read(
                data,
                rva + BLOCK_HEADER_SIZE,
                size_of_block as i64 - BLOCK_HEADER_SIZE,
            );
            blocks.push(RelocationBlock {
                virtual_address,
                size_of_block,
                entries: body.map_or_else(Vec::new, |b| entries(b, virtual_address, &mut seen)),
            });
            if size_of_block == 0 {
                break;
            }
            rva += size_of_block as i64;
        }
        blocks
    }
}
