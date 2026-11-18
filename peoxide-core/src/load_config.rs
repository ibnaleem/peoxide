//! The load config directory, following pefile's `parse_directory_load_config`, and the
//! dynamic relocations it points to, following `parse_dynamic_relocations`.

use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};

use crate::Pe;
use crate::reloc::{Reader, RelocationBlock, RelocationFormat};

const LOAD_CONFIG_DIRECTORY: usize = 10;
/// pefile parses dynamic relocations only once the structure has more than this many fields.
const DYNAMIC_RELOCATION_FIELDS: usize = 35;
const DYNAMIC_RELOCATION_TABLE_SIZE: i64 = 8;
const FUNCTION_OVERRIDE_HEADER_SIZE: i64 = 4;
const FUNCTION_OVERRIDE_SIZE: i64 = 16;
const BDD_INFO_SIZE: i64 = 8;
const BDD_RELOCATION_SIZE: i64 = 8;
const SYMBOL_FUNCTION_OVERRIDE: u64 = 7;
/// Most headers, blocks, entries, override RVAs and BDD entries one file's dynamic relocations
/// may build. The largest System32 file has about 30,000. Crafted sizes can make the function
/// override lists of successive headers overlap, so without a cap the work grows with the
/// square of the file size.
const MAX_DYNAMIC_RELOCATION_ITEMS: usize = 1 << 20;

/// pefile's `__IMAGE_LOAD_CONFIG_DIRECTORY_format__`: each field's name and width in bytes.
const FIELDS_32: [(&str, usize); 52] = [
    ("Size", 4),
    ("TimeDateStamp", 4),
    ("MajorVersion", 2),
    ("MinorVersion", 2),
    ("GlobalFlagsClear", 4),
    ("GlobalFlagsSet", 4),
    ("CriticalSectionDefaultTimeout", 4),
    ("DeCommitFreeBlockThreshold", 4),
    ("DeCommitTotalFreeThreshold", 4),
    ("LockPrefixTable", 4),
    ("MaximumAllocationSize", 4),
    ("VirtualMemoryThreshold", 4),
    ("ProcessHeapFlags", 4),
    ("ProcessAffinityMask", 4),
    ("CSDVersion", 2),
    ("DependentLoadFlags", 2),
    ("EditList", 4),
    ("SecurityCookie", 4),
    ("SEHandlerTable", 4),
    ("SEHandlerCount", 4),
    ("GuardCFCheckFunctionPointer", 4),
    ("GuardCFDispatchFunctionPointer", 4),
    ("GuardCFFunctionTable", 4),
    ("GuardCFFunctionCount", 4),
    ("GuardFlags", 4),
    ("CodeIntegrityFlags", 2),
    ("CodeIntegrityCatalog", 2),
    ("CodeIntegrityCatalogOffset", 4),
    ("CodeIntegrityReserved", 4),
    ("GuardAddressTakenIatEntryTable", 4),
    ("GuardAddressTakenIatEntryCount", 4),
    ("GuardLongJumpTargetTable", 4),
    ("GuardLongJumpTargetCount", 4),
    ("DynamicValueRelocTable", 4),
    ("CHPEMetadataPointer", 4),
    ("GuardRFFailureRoutine", 4),
    ("GuardRFFailureRoutineFunctionPointer", 4),
    ("DynamicValueRelocTableOffset", 4),
    ("DynamicValueRelocTableSection", 2),
    ("Reserved2", 2),
    ("GuardRFVerifyStackPointerFunctionPointer", 4),
    ("HotPatchTableOffset", 4),
    ("Reserved3", 4),
    ("EnclaveConfigurationPointer", 4),
    ("VolatileMetadataPointer", 4),
    ("GuardEHContinuationTable", 4),
    ("GuardEHContinuationCount", 4),
    ("GuardXFGCheckFunctionPointer", 4),
    ("GuardXFGDispatchFunctionPointer", 4),
    ("GuardXFGTableDispatchFunctionPointer", 4),
    ("CastGuardOsDeterminedFailureMode", 4),
    ("GuardMemcpyFunctionPointer", 4),
];

/// pefile's `__IMAGE_LOAD_CONFIG_DIRECTORY64_format__`.
const FIELDS_64: [(&str, usize); 52] = [
    ("Size", 4),
    ("TimeDateStamp", 4),
    ("MajorVersion", 2),
    ("MinorVersion", 2),
    ("GlobalFlagsClear", 4),
    ("GlobalFlagsSet", 4),
    ("CriticalSectionDefaultTimeout", 4),
    ("DeCommitFreeBlockThreshold", 8),
    ("DeCommitTotalFreeThreshold", 8),
    ("LockPrefixTable", 8),
    ("MaximumAllocationSize", 8),
    ("VirtualMemoryThreshold", 8),
    ("ProcessAffinityMask", 8),
    ("ProcessHeapFlags", 4),
    ("CSDVersion", 2),
    ("DependentLoadFlags", 2),
    ("EditList", 8),
    ("SecurityCookie", 8),
    ("SEHandlerTable", 8),
    ("SEHandlerCount", 8),
    ("GuardCFCheckFunctionPointer", 8),
    ("GuardCFDispatchFunctionPointer", 8),
    ("GuardCFFunctionTable", 8),
    ("GuardCFFunctionCount", 8),
    ("GuardFlags", 4),
    ("CodeIntegrityFlags", 2),
    ("CodeIntegrityCatalog", 2),
    ("CodeIntegrityCatalogOffset", 4),
    ("CodeIntegrityReserved", 4),
    ("GuardAddressTakenIatEntryTable", 8),
    ("GuardAddressTakenIatEntryCount", 8),
    ("GuardLongJumpTargetTable", 8),
    ("GuardLongJumpTargetCount", 8),
    ("DynamicValueRelocTable", 8),
    ("CHPEMetadataPointer", 8),
    ("GuardRFFailureRoutine", 8),
    ("GuardRFFailureRoutineFunctionPointer", 8),
    ("DynamicValueRelocTableOffset", 4),
    ("DynamicValueRelocTableSection", 2),
    ("Reserved2", 2),
    ("GuardRFVerifyStackPointerFunctionPointer", 8),
    ("HotPatchTableOffset", 4),
    ("Reserved3", 4),
    ("EnclaveConfigurationPointer", 8),
    ("VolatileMetadataPointer", 8),
    ("GuardEHContinuationTable", 8),
    ("GuardEHContinuationCount", 8),
    ("GuardXFGCheckFunctionPointer", 8),
    ("GuardXFGDispatchFunctionPointer", 8),
    ("GuardXFGTableDispatchFunctionPointer", 8),
    ("CastGuardOsDeterminedFailureMode", 8),
    ("GuardMemcpyFunctionPointer", 8),
];

pub struct LoadConfig {
    /// The fields pefile reads, in its order. Their number depends on the structure's `Size`.
    pub fields: Vec<(&'static str, u64)>,
    /// `None` where pefile leaves `dynamic_relocations` as `None`.
    pub dynamic_relocations: Option<Vec<DynamicRelocation>>,
}

/// One `IMAGE_DYNAMIC_RELOCATION` (or `..64`) header and what follows it.
pub struct DynamicRelocation {
    pub symbol: u64,
    pub base_reloc_size: u32,
    pub kind: DynamicRelocationKind,
}

pub enum DynamicRelocationKind {
    /// Every symbol from 3 up except 7. Symbols 3 to 5 use their bitfield formats, the rest
    /// (ARM64X's 6 included, which pefile has no format for) the base relocation format.
    Relocations(Vec<RelocationBlock>),
    /// Symbol 7.
    FunctionOverride {
        func_relocs: Vec<FunctionOverride>,
        bdd_relocs: Vec<BddRelocation>,
    },
}

/// One `IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION` and the lists after it.
pub struct FunctionOverride {
    pub original_rva: u32,
    pub bdd_offset: u32,
    pub rva_size: u32,
    pub base_reloc_size: u32,
    pub override_rvas: Vec<u32>,
    pub relocations: Vec<RelocationBlock>,
}

/// One `IMAGE_BDD_DYNAMIC_RELOCATION`.
pub struct BddRelocation {
    pub left: u16,
    pub right: u16,
    pub value: u32,
}

/// pefile raised out of the whole directory parse, so it leaves the directory undefined.
struct Unreadable;

fn uint(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, &byte| (value << 8) | u64::from(byte))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    uint(&bytes[at..at + 4]) as u32
}

/// pefile's truncation: the fields up to the one where the widths add up to `declared`, or
/// all of them when no prefix does.
fn field_count(format: &[(&str, usize)], declared: Option<u64>) -> usize {
    let mut size = 0;
    format
        .iter()
        .position(|&(_, width)| {
            size += width as u64;
            Some(size) == declared
        })
        .map_or(format.len(), |i| i + 1)
}

impl Pe {
    /// `None` where pefile leaves `DIRECTORY_ENTRY_LOAD_CONFIG` undefined.
    ///
    /// `parse` leaves this out, because the dynamic relocations run to tens of thousands of
    /// entries in kernel images.
    pub fn parse_load_config(&self, data: &[u8]) -> Option<LoadConfig> {
        let directory = self
            .headers
            .optional_header
            .data_directory
            .get(LOAD_CONFIG_DIRECTORY)?;
        if directory.virtual_address == 0 {
            return None;
        }
        let format: &[(&'static str, usize)] = match self.headers.optional_header.magic {
            MAGIC_32 => &FIELDS_32,
            MAGIC_64 => &FIELDS_64,
            _ => return None,
        };
        let rva = directory.virtual_address as i64;
        // The structure's own first field, not the data directory's size.
        let count = field_count(format, self.uint_at_rva(data, rva, 4));
        let format = &format[..count];
        let size: usize = format.iter().map(|&(_, width)| width).sum();
        let bytes = self.read(data, rva, size as i64)?.get(..size)?;
        let mut offset = 0;
        let fields: Vec<_> = format
            .iter()
            .map(|&(name, width)| {
                offset += width;
                (name, uint(&bytes[offset - width..offset]))
            })
            .collect();
        let dynamic_relocations = if count > DYNAMIC_RELOCATION_FIELDS {
            self.dynamic_relocations(data, &fields).ok()?
        } else {
            None
        };
        Some(LoadConfig {
            fields,
            dynamic_relocations,
        })
    }

    fn dynamic_relocations(
        &self,
        data: &[u8],
        fields: &[(&str, u64)],
    ) -> Result<Option<Vec<DynamicRelocation>>, Unreadable> {
        let field = |name| fields.iter().find(|f| f.0 == name).map(|f| f.1);
        // pefile raises AttributeError, out of `PE()` itself, when a structure of 36 to 38
        // fields lacks these two.
        let (Some(offset), Some(section)) = (
            field("DynamicValueRelocTableOffset"),
            field("DynamicValueRelocTableSection"),
        ) else {
            return Ok(None);
        };
        if offset == 0 || section == 0 || section > self.sections.len() as u64 {
            return Ok(None);
        }
        let mut rva = self.sections[section as usize - 1].virtual_address as i64 + offset as i64;
        // A short table makes pefile raise AttributeError out of `PE()`.
        let Some(table) = self
            .read(data, rva, DYNAMIC_RELOCATION_TABLE_SIZE)
            .and_then(|t| t.get(..DYNAMIC_RELOCATION_TABLE_SIZE as usize))
        else {
            return Ok(None);
        };
        if u32_at(table, 0) != 1 {
            return Ok(None);
        }
        rva += DYNAMIC_RELOCATION_TABLE_SIZE;
        let end = rva + u32_at(table, 4) as i64;
        let wide = self.headers.optional_header.magic == MAGIC_64;
        let (symbol_size, header_size) = if wide { (8, 12) } else { (4, 8) };
        let mut reader = Reader::new(MAX_DYNAMIC_RELOCATION_ITEMS);
        let mut relocations = Vec::new();
        while rva < end && reader.take() {
            let Some(header) = self
                .read(data, rva, header_size)
                .and_then(|h| h.get(..header_size as usize))
            else {
                break;
            };
            let symbol = uint(&header[..symbol_size]);
            let base_reloc_size = u32_at(header, symbol_size);
            rva = rva.saturating_add(header_size);
            let size = base_reloc_size as i64;
            let format = match symbol {
                3 => Some(RelocationFormat::ImportControlTransfer),
                4 => Some(RelocationFormat::IndirControlTransfer),
                5 => Some(RelocationFormat::SwitchtableBranch),
                SYMBOL_FUNCTION_OVERRIDE => None,
                s if s > 5 => Some(RelocationFormat::Base),
                _ => {
                    rva = rva.saturating_add(size);
                    continue;
                }
            };
            let kind = match format {
                Some(format) => DynamicRelocationKind::Relocations(self.relocation_list(
                    data,
                    rva,
                    size,
                    format,
                    &mut reader,
                )),
                None => self.function_override(data, rva, &mut reader)?,
            };
            relocations.push(DynamicRelocation {
                symbol,
                base_reloc_size,
                kind,
            });
            rva = rva.saturating_add(size);
        }
        Ok(Some(relocations))
    }

    /// pefile's `__unpack_data__(format, get_data(rva, N))` outside a `try`: `Err` where
    /// `get_data` raises, `None` where the data is short.
    fn unpack<const N: usize>(&self, data: &[u8], rva: i64) -> Result<Option<[u8; N]>, Unreadable> {
        let bytes = self.read(data, rva, N as i64).ok_or(Unreadable)?;
        Ok(bytes.get(..N).and_then(|b| b.try_into().ok()))
    }

    /// pefile's `parse_function_override_data`. A short structure ends the lists early.
    fn function_override(
        &self,
        data: &[u8],
        mut rva: i64,
        reader: &mut Reader,
    ) -> Result<DynamicRelocationKind, Unreadable> {
        let mut func_relocs = Vec::new();
        let mut bdd_relocs = Vec::new();
        let done = |func_relocs, bdd_relocs| {
            Ok(DynamicRelocationKind::FunctionOverride {
                func_relocs,
                bdd_relocs,
            })
        };
        let Some(header) = self.unpack::<{ FUNCTION_OVERRIDE_HEADER_SIZE as usize }>(data, rva)?
        else {
            return done(func_relocs, bdd_relocs);
        };
        rva = rva.saturating_add(FUNCTION_OVERRIDE_HEADER_SIZE);
        let func_end = rva.saturating_add(u32_at(&header, 0) as i64);
        while rva < func_end {
            if !reader.take() {
                return done(func_relocs, bdd_relocs);
            }
            let Some(info) = self.unpack::<{ FUNCTION_OVERRIDE_SIZE as usize }>(data, rva)? else {
                return done(func_relocs, bdd_relocs);
            };
            rva = rva.saturating_add(FUNCTION_OVERRIDE_SIZE);
            let rva_size = u32_at(&info, 8);
            let base_reloc_size = u32_at(&info, 12);
            let mut override_rvas = Vec::new();
            for _ in 0..rva_size / 4 {
                if !reader.take() {
                    return done(func_relocs, bdd_relocs);
                }
                // A short read here makes pefile raise struct.error out of `PE()`.
                let bytes = self.read(data, rva, 4).ok_or(Unreadable)?;
                override_rvas.push(u32::from_le_bytes(
                    bytes.try_into().map_err(|_| Unreadable)?,
                ));
                rva = rva.saturating_add(4);
            }
            let relocations = self.relocation_list(
                data,
                rva,
                base_reloc_size as i64,
                RelocationFormat::Base,
                reader,
            );
            rva = rva.saturating_add(base_reloc_size as i64);
            func_relocs.push(FunctionOverride {
                original_rva: u32_at(&info, 0),
                bdd_offset: u32_at(&info, 4),
                rva_size,
                base_reloc_size,
                override_rvas,
                relocations,
            });
        }
        let Some(bdd_info) = self.unpack::<{ BDD_INFO_SIZE as usize }>(data, rva)? else {
            return done(func_relocs, bdd_relocs);
        };
        rva = rva.saturating_add(BDD_INFO_SIZE);
        for _ in 0..u32_at(&bdd_info, 4) / BDD_RELOCATION_SIZE as u32 {
            if !reader.take() {
                break;
            }
            let Some(bdd) = self.unpack::<{ BDD_RELOCATION_SIZE as usize }>(data, rva)? else {
                break;
            };
            rva = rva.saturating_add(BDD_RELOCATION_SIZE);
            bdd_relocs.push(BddRelocation {
                left: u16::from_le_bytes([bdd[0], bdd[1]]),
                right: u16::from_le_bytes([bdd[2], bdd[3]]),
                value: u32_at(&bdd, 4),
            });
        }
        done(func_relocs, bdd_relocs)
    }
}
