//! RVA and file-offset mapping, following pefile's alignment rules exactly.
//!
//! Offsets are `i64` because pefile's arithmetic is unbounded Python integers: a start RVA
//! below a section's address yields a negative offset, which `clamp` turns into an empty or
//! truncated range instead of wrapping.

use std::ops::Range;

use crate::{Headers, Pe, Section};

const SECTOR_MASK: u32 = !0x1FF;
const PAGE_SIZE: u32 = 0x1000;
const SECTION_HEADER_SIZE: i64 = 40;
const NT_SIGNATURE_AND_FILE_HEADER_SIZE: i64 = 4 + 20;

/// Where a section lives once pefile's alignment rules are applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionLayout {
    /// `PointerToRawData` rounded down to 512 bytes (or equal to the address when
    /// SectionAlignment is below a page and the two match).
    pub pointer_to_raw_data: i64,
    /// `VirtualAddress` rounded down to the section alignment.
    pub virtual_address: i64,
    /// RVAs in `rva_start..rva_end` belong to this section.
    pub rva_start: i64,
    pub rva_end: i64,
}

impl SectionLayout {
    /// The unclamped file range `section.get_data(start, length, ignore_padding)` reads.
    pub fn data_range(
        &self,
        section: &Section,
        start: Option<i64>,
        length: Option<i64>,
        ignore_padding: bool,
    ) -> (i64, i64) {
        let offset = start.map_or(self.pointer_to_raw_data, |rva| self.offset_from_rva(rva));
        let end = offset + length.unwrap_or(section.size_of_raw_data as i64);
        let end = if ignore_padding {
            end.min(offset + section.virtual_size as i64)
        } else {
            end
        };
        let section_end = section.pointer_to_raw_data as i64 + section.size_of_raw_data as i64;
        (offset, end.min(section_end))
    }

    pub fn contains_rva(&self, rva: i64) -> bool {
        (self.rva_start..self.rva_end).contains(&rva)
    }

    pub fn contains_offset(&self, section: &Section, offset: i64) -> bool {
        let start = self.pointer_to_raw_data;
        (start..start + section.size_of_raw_data as i64).contains(&offset)
    }

    pub fn offset_from_rva(&self, rva: i64) -> i64 {
        rva - self.virtual_address + self.pointer_to_raw_data
    }

    pub fn rva_from_offset(&self, offset: i64) -> i64 {
        offset - self.pointer_to_raw_data + self.virtual_address
    }
}

/// Python-slice semantics for non-negative bounds: `data[start:end]` never panics.
pub fn clamp((start, end): (i64, i64), len: usize) -> Range<usize> {
    let len = len as i64;
    let start = start.clamp(0, len);
    start as usize..end.clamp(start, len) as usize
}

fn align_down(value: u32, alignment: u32) -> u32 {
    if alignment != 0 && !value.is_multiple_of(alignment) {
        alignment * (value / alignment)
    } else {
        value
    }
}

/// `sections` must already be sorted by `virtual_address`.
pub(crate) fn section_layouts(
    sections: &[Section],
    headers: &Headers,
    file_size: usize,
) -> Vec<SectionLayout> {
    let section_alignment = headers.optional_header.section_alignment;
    let alignment = if section_alignment < PAGE_SIZE {
        headers.optional_header.file_alignment
    } else {
        section_alignment
    };
    sections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let pointer_to_raw_data =
                if section_alignment < PAGE_SIZE && s.pointer_to_raw_data == s.virtual_address {
                    s.virtual_address
                } else {
                    s.pointer_to_raw_data & SECTOR_MASK
                } as i64;
            let virtual_address = align_down(s.virtual_address, alignment) as i64;
            let raw_size = s.size_of_raw_data as i64;
            let virtual_size = s.virtual_size as i64;
            // A raw size running past the end of the file is not trusted.
            let size = if file_size as i64 - pointer_to_raw_data < raw_size {
                virtual_size
            } else {
                raw_size.max(virtual_size)
            };
            let next = sections.get(i + 1).map(|n| n.virtual_address as i64);
            let size = match next {
                Some(next) if next > s.virtual_address as i64 && virtual_address + size > next => {
                    next - virtual_address
                }
                _ => size,
            };
            SectionLayout {
                pointer_to_raw_data,
                virtual_address,
                rva_start: virtual_address,
                rva_end: virtual_address + size,
            }
        })
        .collect()
}

/// pefile's `len(pe.header)`: up to the lowest section data, but at least the section table.
pub(crate) fn header_size(headers: &Headers, sections: &[Section]) -> i64 {
    let table_end = headers.dos_header.e_lfanew as i64
        + NT_SIGNATURE_AND_FILE_HEADER_SIZE
        + headers.file_header.size_of_optional_header as i64
        + SECTION_HEADER_SIZE * sections.len() as i64;
    let lowest_data = sections
        .iter()
        .filter(|s| s.pointer_to_raw_data > 0)
        .map(|s| (s.pointer_to_raw_data & SECTOR_MASK) as i64)
        .min();
    match lowest_data {
        Some(lowest) if lowest != 0 && lowest >= table_end => lowest,
        _ => table_end,
    }
}

impl Pe {
    pub fn section_by_rva(&self, rva: i64) -> Option<usize> {
        self.layouts.iter().position(|l| l.contains_rva(rva))
    }

    pub fn section_by_offset(&self, offset: i64) -> Option<usize> {
        self.layouts
            .iter()
            .zip(&self.sections)
            .position(|(l, s)| l.contains_offset(s, offset))
    }

    /// `None` where pefile raises: the RVA is outside every section and past the file end.
    pub fn offset_from_rva(&self, rva: i64) -> Option<i64> {
        match self.section_by_rva(rva) {
            Some(i) => Some(self.layouts[i].offset_from_rva(rva)),
            None => (rva < self.file_size as i64).then_some(rva),
        }
    }

    /// `None` where pefile returns `None`: an offset outside every section and past the
    /// start of the lowest one.
    pub fn rva_from_offset(&self, offset: i64) -> Option<i64> {
        if let Some(i) = self.section_by_offset(offset) {
            return Some(self.layouts[i].rva_from_offset(offset));
        }
        match self.layouts.iter().map(|l| l.virtual_address).min() {
            Some(lowest) => (offset < lowest).then_some(offset),
            None => Some(offset),
        }
    }

    /// The file range `pe.get_data(rva, length)` reads, or `None` where pefile raises.
    pub fn data_range(&self, rva: i64, length: Option<i64>) -> Option<Range<usize>> {
        if let Some(i) = self.section_by_rva(rva) {
            let range = self.layouts[i].data_range(&self.sections[i], Some(rva), length, false);
            return Some(clamp(range, self.file_size));
        }
        let end = length.map_or(i64::MAX, |length| rva + length);
        if rva < self.header_size {
            return Some(clamp((rva, end.min(self.header_size)), self.file_size));
        }
        (rva < self.file_size as i64).then(|| clamp((rva, end), self.file_size))
    }
}
