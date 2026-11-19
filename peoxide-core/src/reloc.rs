//! Base relocations, following pefile's `parse_relocations_directory`, and the relocation
//! lists inside dynamic relocations, following its `parse_image_base_relocation_list`.

use crate::Pe;

const BASERELOC_DIRECTORY: usize = 5;
const BLOCK_HEADER_SIZE: i64 = 8;
const PAGE_OFFSET_MASK: u32 = 0x0FFF;

/// How a block lays out its entries: pefile's `IMAGE_BASE_RELOCATION_ENTRY`, or one of the
/// bitfield formats it reads for dynamic relocation symbols 3 to 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationFormat {
    /// 16 bits: a 4-bit type above a 12-bit page offset.
    Base,
    /// Symbol 3, 32 bits: PageRelativeOffset:12, IndirectCall:1, IATIndex:19.
    ImportControlTransfer,
    /// Symbol 4, 16 bits: PageRelativeOffset:12, IndirectCall:1, RexWPrefix:1, CfgCheck:1,
    /// Reserved:1.
    IndirControlTransfer,
    /// Symbol 5, 16 bits: PageRelativeOffset:12, RegisterNumber:4.
    SwitchtableBranch,
}

impl RelocationFormat {
    /// What pefile compares to find a repeated entry: the whole entry for base relocations,
    /// only the page offset for the bitfield formats.
    fn key(self, data: u32) -> u16 {
        match self {
            Self::Base => data as u16,
            _ => (data & PAGE_OFFSET_MASK) as u16,
        }
    }
}

pub struct RelocationBlock {
    pub virtual_address: u32,
    pub size_of_block: u32,
    pub format: RelocationFormat,
    pub entries: Vec<Relocation>,
}

pub struct Relocation {
    /// The raw entry: 32 bits for `ImportControlTransfer`, 16 for the other formats.
    pub data: u32,
    /// The block's `virtual_address` plus the entry's 12-bit page offset.
    pub rva: u64,
}

impl Relocation {
    /// The type of a `Base` entry, its top 4 bits.
    pub fn reloc_type(&self) -> u16 {
        (self.data >> 12) as u16
    }
}

/// Which block last held each 16-bit entry key, so one slot per key finds a repeat without
/// hashing, and one table serves every block of every list read with it.
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

    /// Call once per block, before its entries. Each block either moves at least one byte
    /// through a directory whose size is a `u32` or uses up one item of a `Reader`'s smaller
    /// budget, so the counter cannot wrap round to a number still in the table.
    fn next_block(&mut self) {
        self.block += 1;
    }

    /// True the first time `key` appears in the current block.
    fn insert(&mut self, key: u16) -> bool {
        let slot = &mut self.block_of[key as usize];
        let first = *slot != self.block;
        *slot = self.block;
        first
    }
}

/// State shared by every relocation list one parse reads: the repeat table, and how many more
/// blocks and entries it may build.
pub(crate) struct Reader {
    seen: Seen,
    budget: usize,
}

impl Reader {
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            seen: Seen::new(),
            budget,
        }
    }

    /// Uses up one item of the budget, or returns false when none is left.
    pub(crate) fn take(&mut self) -> bool {
        let left = self.budget > 0;
        self.budget = self.budget.saturating_sub(1);
        left
    }

    /// Entries up to the first repeated key, where pefile stops.
    fn entries(
        &mut self,
        words: impl Iterator<Item = u32>,
        base: u32,
        format: RelocationFormat,
    ) -> Vec<Relocation> {
        self.seen.next_block();
        let seen = &mut self.seen;
        let entries: Vec<_> = words
            .take(self.budget)
            .map_while(|data| {
                seen.insert(format.key(data)).then_some(Relocation {
                    data,
                    rva: base as u64 + (data & PAGE_OFFSET_MASK) as u64,
                })
            })
            .collect();
        self.budget -= entries.len();
        entries
    }
}

impl Pe {
    /// pefile's `get_data(rva, length)`: `None` where it raises, else the bytes, which may be
    /// fewer than `length`.
    pub(crate) fn read<'a>(&self, data: &'a [u8], rva: i64, length: i64) -> Option<&'a [u8]> {
        data.get(self.data_range(rva, Some(length))?)
    }

    /// The base relocation blocks of `data`, the file this `Pe` was parsed from.
    ///
    /// `parse` leaves these out. A large image has tens of thousands of entries, most callers
    /// never read them, and building them took about a third of the parse.
    pub fn parse_relocations(&self, data: &[u8]) -> Vec<RelocationBlock> {
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
        self.relocation_list(
            data,
            directory.virtual_address as i64,
            directory.size as i64,
            RelocationFormat::Base,
            &mut Reader::new(usize::MAX),
        )
    }

    /// pefile's `parse_image_base_relocation_list`: the blocks in `size` bytes from `rva`.
    pub(crate) fn relocation_list(
        &self,
        data: &[u8],
        mut rva: i64,
        size: i64,
        format: RelocationFormat,
        reader: &mut Reader,
    ) -> Vec<RelocationBlock> {
        let size_of_image = self.headers.optional_header.size_of_image;
        let end = rva.saturating_add(size);
        let mut blocks = Vec::new();
        while rva < end && reader.take() {
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
                rva.saturating_add(BLOCK_HEADER_SIZE),
                size_of_block as i64 - BLOCK_HEADER_SIZE,
            );
            blocks.push(RelocationBlock {
                virtual_address,
                size_of_block,
                format,
                entries: match (body, format) {
                    (None, _) => Vec::new(),
                    (Some(b), RelocationFormat::ImportControlTransfer) => {
                        let words = b.as_chunks::<4>().0.iter().map(|&c| u32::from_le_bytes(c));
                        reader.entries(words, virtual_address, format)
                    }
                    (Some(b), _) => {
                        let words = b.as_chunks::<2>().0.iter();
                        let words = words.map(|&c| u16::from_le_bytes(c).into());
                        reader.entries(words, virtual_address, format)
                    }
                },
            });
            if size_of_block == 0 {
                break;
            }
            rva = rva.saturating_add(size_of_block as i64);
        }
        blocks
    }
}
