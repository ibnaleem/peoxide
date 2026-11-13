mod address;
mod debug;
mod delay;
pub use debug::{DebugDirectory, DebugEntry};
mod headers;
mod imphash;
mod ordinals;
mod reloc;
mod resource;
pub use reloc::{Relocation, RelocationBlock};
pub use resource::{ResourceChild, ResourceData, ResourceDirectory, ResourceEntry};
mod rich;
mod version;
pub use address::{SectionLayout, clamp, entropy};
pub use goblin::error::Error;
pub use goblin::pe::data_directories::DataDirectory;
pub use goblin::pe::section_table::SectionTable as Section;
pub use headers::*;
pub use imphash::ordinal_name;
pub use rich::RichHeader;
pub use version::{BlockHeader, FileInfo, FixedFileInfo, StringTable, Var, Version, VersionInfo};

use goblin::container::Container;
use goblin::pe::export::{ExportAddressTableEntry, ExportData};
use goblin::pe::header::{Header, SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
use goblin::pe::import::{ImportData, SyntheticImportLookupTableEntry};
use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};
use goblin::pe::options::ParseOptions;
use goblin::pe::{characteristic, subsystem};

pub struct Pe {
    pub headers: Headers,
    /// Sorted by `virtual_address`.
    pub sections: Vec<Section>,
    /// One per entry of `sections`, in the same order.
    pub layouts: Vec<SectionLayout>,
    pub file_size: usize,
    pub header_size: i64,
    pub imports: Vec<ImportDll>,
    pub delay_imports: Vec<ImportDll>,
    pub exports: Vec<ExportSymbol>,
    pub debug: Vec<DebugDirectory>,
    pub rich_header: Option<RichHeader>,
    pub relocations: Vec<RelocationBlock>,
    /// `None` where pefile leaves `DIRECTORY_ENTRY_RESOURCE` undefined.
    pub resources: Option<ResourceDirectory>,
    pub version: Version,
}

pub struct ImportDll {
    pub dll: Vec<u8>,
    pub imports: Vec<ImportSymbol>,
}

/// Exactly one of `name` (with `hint`) or `ordinal` is set.
pub struct ImportSymbol {
    pub name: Option<Vec<u8>>,
    pub hint: Option<u16>,
    pub ordinal: Option<u16>,
    /// Virtual address of the symbol's IAT slot (image base + RVA), as pefile reports it.
    pub address: u64,
}

pub struct ExportSymbol {
    pub name: Option<Vec<u8>>,
    /// OrdinalBase + index, which pefile does not wrap at 2**32.
    pub ordinal: u64,
    /// RVA of the exported code/data, or of the forwarder string.
    pub address: u32,
    pub forwarder: Option<Vec<u8>>,
}

/// Imports that mark an image as a kernel-mode driver (pefile's heuristic).
const KERNEL_DLLS: [&[u8]; 5] = [
    b"ntoskrnl.exe",
    b"hal.dll",
    b"ndis.sys",
    b"bootvid.dll",
    b"kdcom.dll",
];

impl Pe {
    pub fn is_dll(&self) -> bool {
        self.headers.file_header.characteristics & characteristic::IMAGE_FILE_DLL != 0
    }

    /// pefile's heuristic: imports a kernel DLL, or has a PAGE/PAGED section and a native
    /// subsystem. An image with no imports is never a driver, as in pefile.
    pub fn is_driver(&self) -> bool {
        if self.imports.is_empty() {
            return false;
        }
        let imports_kernel = self
            .imports
            .iter()
            .any(|d| KERNEL_DLLS.iter().any(|k| d.dll.eq_ignore_ascii_case(k)));
        let paged_section = self.sections.iter().any(|s| {
            let end = s.name.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            let name = &s.name[..end];
            name.eq_ignore_ascii_case(b"page") || name.eq_ignore_ascii_case(b"paged")
        });
        let native = matches!(
            self.headers.optional_header.subsystem,
            subsystem::IMAGE_SUBSYSTEM_NATIVE | subsystem::IMAGE_SUBSYSTEM_NATIVE_WINDOWS
        );
        imports_kernel || (paged_section && native)
    }

    pub fn is_exe(&self) -> bool {
        let executable = self.headers.file_header.characteristics
            & characteristic::IMAGE_FILE_EXECUTABLE_IMAGE
            != 0;
        executable && !self.is_dll() && !self.is_driver()
    }
}

pub fn parse(data: &[u8]) -> Result<Pe, Error> {
    let opts = ParseOptions::default();
    let header = Header::parse(data)?;
    let pe = Tables::read(data, &header, &opts)?;
    let headers = headers::from_goblin(&header)?;
    let optional_header_offset = headers.dos_header.e_lfanew as usize + 24;
    let imports = imports(&pe, headers.optional_header.image_base);
    let exports = exports(data, &pe, headers.optional_header.file_alignment, &opts);
    let mut sections = pe.sections;
    // pefile orders sections by VirtualAddress, not by section-table position.
    sections.sort_by_key(|s| s.virtual_address);
    let mut pe = Pe {
        layouts: address::section_layouts(&sections, &headers, data.len()),
        header_size: address::header_size(&headers, &sections),
        file_size: data.len(),
        headers,
        sections,
        imports,
        delay_imports: Vec::new(),
        exports,
        debug: Vec::new(),
        rich_header: rich::parse(data, optional_header_offset),
        relocations: Vec::new(),
        resources: None,
        version: Version::default(),
    };
    // These directories are read through RVAs, which need the section layouts above.
    pe.delay_imports = pe.parse_delay_imports(data);
    pe.debug = pe.parse_debug_directory(data);
    pe.relocations = pe.parse_relocations(data);
    pe.resources = pe.parse_resources(data);
    pe.version = pe.parse_version(data);
    Ok(pe)
}

/// pefile's IAT slot address, ImageBase + IAT RVA + index * thunk size, saturated at u64::MAX.
fn iat_slot_address(image_base: u64, iat_rva: u64, index: usize, thunk_size: usize) -> u64 {
    image_base
        .saturating_add(iat_rva)
        .saturating_add((index as u64).saturating_mul(thunk_size as u64))
}

/// The tables peoxide takes from goblin. `goblin::pe::PE::parse` reads these and then also
/// resolves every import and export into lists of its own and parses the debug, exception,
/// relocation, load-config and CLR directories. peoxide rebuilds or reparses all of that, so
/// it asks goblin for the raw tables only.
struct Tables<'a> {
    sections: Vec<Section>,
    is_64: bool,
    import_data: Option<ImportData<'a>>,
    export_data: Option<ExportData<'a>>,
}

impl<'a> Tables<'a> {
    /// Follows the start of `PE::parse_with_opts`: the same reads, in the same order, failing
    /// on the same errors.
    fn read(data: &'a [u8], header: &Header<'a>, opts: &ParseOptions) -> Result<Self, Error> {
        let sections_offset = &mut (header.dos_header.pe_pointer as usize
            + SIZEOF_PE_MAGIC
            + SIZEOF_COFF_HEADER
            + header.coff_header.size_of_optional_header as usize);
        let mut tables = Tables {
            sections: header.coff_header.sections(data, sections_offset)?,
            is_64: false,
            import_data: None,
            export_data: None,
        };
        let Some(optional_header) = &header.optional_header else {
            return Ok(tables);
        };
        let magic = optional_header.standard_fields.magic;
        if magic != MAGIC_32 && magic != MAGIC_64 {
            return Err(Error::Malformed(format!(
                "Unsupported header magic ({magic:#x})"
            )));
        }
        tables.is_64 = optional_header.container()? == Container::Big;
        let alignment = optional_header.windows_fields.file_alignment;
        let directories = &optional_header.data_directories;
        if let Some(&table) = directories.get_export_table() {
            // goblin ignores an export directory it cannot read, and so does pefile.
            tables.export_data =
                ExportData::parse_with_opts(data, table, &tables.sections, alignment, opts).ok();
        }
        if let Some(&table) = directories.get_import_table() {
            let sections = &tables.sections;
            tables.import_data = Some(if tables.is_64 {
                ImportData::parse_with_opts::<u64>(data, table, sections, alignment, opts)?
            } else {
                ImportData::parse_with_opts::<u32>(data, table, sections, alignment, opts)?
            });
        }
        Ok(tables)
    }
}

fn imports(pe: &Tables, image_base: u64) -> Vec<ImportDll> {
    let Some(import_data) = &pe.import_data else {
        return Vec::new();
    };
    let thunk_size = if pe.is_64 { 8 } else { 4 };
    import_data
        .import_data
        .iter()
        .map(|entry| {
            let iat_rva = entry.import_directory_entry.import_address_table_rva as u64;
            let imports = entry
                .import_lookup_table
                .iter()
                .flatten()
                .enumerate()
                .map(|(i, lookup)| {
                    let address = iat_slot_address(image_base, iat_rva, i, thunk_size);
                    match lookup {
                        SyntheticImportLookupTableEntry::OrdinalNumber(ordinal) => ImportSymbol {
                            name: None,
                            hint: None,
                            ordinal: Some(*ordinal),
                            address,
                        },
                        SyntheticImportLookupTableEntry::HintNameTableRVA((_, hint_name)) => {
                            ImportSymbol {
                                name: Some(hint_name.name.as_bytes().to_vec()),
                                hint: Some(hint_name.hint),
                                ordinal: None,
                                address,
                            }
                        }
                    }
                })
                .collect();
            ImportDll {
                dll: entry.name.as_bytes().to_vec(),
                imports,
            }
        })
        .collect()
}

/// Named exports in name-table order, then ordinal-only exports, matching pefile.
fn exports(
    data: &[u8],
    pe: &Tables,
    file_alignment: u32,
    opts: &ParseOptions,
) -> Vec<ExportSymbol> {
    let Some(export_data) = &pe.export_data else {
        return Vec::new();
    };
    let base = export_data.export_directory_table.ordinal_base;
    let addresses = &export_data.export_address_table;
    let c_string_at = |rva: u32| {
        let offset =
            goblin::pe::utils::find_offset(rva as usize, &pe.sections, file_alignment, opts)?;
        let bytes = data.get(offset..)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(bytes[..end].to_vec())
    };
    let symbol = |index: usize, name: Option<Vec<u8>>| {
        let (address, forwarder) = match addresses[index] {
            ExportAddressTableEntry::ExportRVA(rva) => (rva, None),
            ExportAddressTableEntry::ForwarderRVA(rva) => (rva, c_string_at(rva)),
        };
        (address != 0).then(|| ExportSymbol {
            name,
            ordinal: u64::from(base).saturating_add(index as u64),
            address,
            forwarder,
        })
    };

    let mut named = vec![false; addresses.len()];
    let mut symbols: Vec<ExportSymbol> = export_data
        .export_name_pointer_table
        .iter()
        .zip(&export_data.export_ordinal_table)
        .filter_map(|(&name_rva, &index)| {
            let index = index as usize;
            *named.get_mut(index)? = true;
            symbol(index, c_string_at(name_rva))
        })
        .collect();
    symbols.extend(
        (0..addresses.len())
            .filter(|&i| !named[i])
            .filter_map(|i| symbol(i, None)),
    );
    symbols
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::pe::header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64, DOS_MAGIC, PE_MAGIC};
    use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};

    pub(crate) const DLL: &[u8] = include_bytes!("../../tests/fixtures/sample64.dll");
    const EXE: &[u8] = include_bytes!("../../tests/fixtures/sample32.exe");
    const DRIVER: &[u8] = include_bytes!("../../tests/fixtures/driver.sys");

    #[test]
    fn parses_the_pe32_plus_dll() {
        let pe = parse(DLL).unwrap();
        let headers = &pe.headers;

        assert_eq!(headers.dos_header.e_magic, DOS_MAGIC);
        assert_eq!(headers.signature, PE_MAGIC);
        assert_eq!(headers.file_header.machine, COFF_MACHINE_X86_64);
        assert_eq!(headers.optional_header.magic, MAGIC_64);
        assert!(headers.optional_header.base_of_data.is_none());
        assert_eq!(headers.optional_header.data_directory.len(), 16);
        assert!(headers.optional_header.data_directory[0].virtual_address != 0);

        assert_eq!(
            pe.sections.len(),
            headers.file_header.number_of_sections as usize
        );
        assert_eq!(&pe.sections[0].name, b".text\0\0\0");

        assert_eq!(pe.imports.len(), 1);
        assert_eq!(pe.imports[0].dll, b"ntdll.dll");
        let exports: Vec<_> = pe
            .exports
            .iter()
            .map(|e| (e.name.as_deref(), e.ordinal, e.address))
            .collect();
        assert_eq!(
            exports,
            [
                (Some(&b"Alpha"[..]), 1, 0x1000),
                (Some(&b"Gamma"[..]), 3, 0x1008),
                (None, 2, 0x1004)
            ]
        );
    }

    #[test]
    fn parses_the_pe32_exe() {
        let headers = parse(EXE).unwrap().headers;
        assert_eq!(headers.file_header.machine, COFF_MACHINE_X86);
        assert_eq!(headers.optional_header.magic, MAGIC_32);
        assert_eq!(headers.optional_header.base_of_data, Some(0x2000));
    }

    #[test]
    fn maps_rvas_and_offsets_through_sections() {
        let data = DLL;
        let pe = parse(data).unwrap();
        let text = &pe.sections[0];
        let rva = text.virtual_address as i64 + 0x10;
        let offset = pe.offset_from_rva(rva).unwrap();
        assert_eq!(offset, text.pointer_to_raw_data as i64 + 0x10);
        assert_eq!(pe.rva_from_offset(offset), Some(rva));
        assert_eq!(pe.section_by_rva(rva), Some(0));

        let range = pe.data_range(rva, Some(4)).unwrap();
        assert_eq!(range, offset as usize..offset as usize + 4);
        assert_eq!(&data[pe.data_range(0, Some(2)).unwrap()], b"MZ");
        assert!(pe.data_range(data.len() as i64 + 0x10_0000, None).is_none());
    }

    #[test]
    fn finds_overlay_and_entropy() {
        assert_eq!(parse(DLL).unwrap().overlay_offset(), None);
        let with_overlay = [DLL, b"appended"].concat();
        let pe = parse(&with_overlay).unwrap();
        let offset = pe.overlay_offset().expect("appended bytes are an overlay");
        assert!(with_overlay[offset..].ends_with(b"appended"));

        assert_eq!(entropy(b""), 0.0);
        assert_eq!(entropy(b"aaaa"), 0.0);
        assert_eq!(entropy(&[0, 1, 2, 3]), 2.0);
    }

    #[test]
    fn builds_imphash_and_exphash_inputs() {
        assert_eq!(ordinal_name(b"OLEAUT32.dll", 2), b"SysAllocString");
        assert_eq!(ordinal_name(b"oleaut32.dll", 65000), b"ord65000");
        assert_eq!(ordinal_name(b"custom.dll", 7), b"ord7");

        let pe = parse(DLL).unwrap();
        assert_eq!(
            pe.imphash_input().unwrap(),
            "ntdll.rtlallocateheap,ntdll.rtlfreeheap"
        );
        assert_eq!(pe.exphash_input().unwrap(), "alpha,gamma");
    }

    #[test]
    fn decodes_the_codeview_pdb_record() {
        let pe = parse(DLL).unwrap();
        let codeview = pe
            .debug
            .iter()
            .find_map(|d| match &d.entry {
                Some(entry @ DebugEntry::Pdb70 { pdb_file_name, .. }) => {
                    Some((entry, pdb_file_name.clone()))
                }
                _ => None,
            })
            .expect("the DLL fixture has an RSDS record");
        assert!(codeview.1.unwrap().starts_with(b"sample64.pdb"));
        let signature = codeview.0.pdb70_signature_string().unwrap();
        assert!(signature.len() > 32 && signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn classifies_dll_exe_and_driver() {
        let classify = |data| {
            let pe = parse(data).unwrap();
            (pe.is_dll(), pe.is_exe(), pe.is_driver())
        };
        assert_eq!(classify(DLL), (true, false, false));
        assert_eq!(classify(EXE), (false, true, false));
        assert_eq!(classify(DRIVER), (false, false, true));
    }

    #[test]
    fn rejects_garbage_and_truncated_input() {
        assert!(parse(b"not a pe file").is_err());
        assert!(parse(&[]).is_err());
        for len in [2, 64, 0x100, 0x400] {
            assert!(parse(&DLL[..len]).is_err(), "truncated to {len} bytes");
        }
    }

    #[test]
    fn crafted_fixtures_parse_without_panicking() {
        let crafted: [&[u8]; 5] = [
            include_bytes!("../../tests/fixtures/crafted/huge_count.dll"),
            include_bytes!("../../tests/fixtures/crafted/self_reference.dll"),
            include_bytes!("../../tests/fixtures/crafted/top_image_base.dll"),
            include_bytes!("../../tests/fixtures/crafted/signed_image_base.dll"),
            include_bytes!("../../tests/fixtures/crafted/long_relocations.dll"),
        ];
        // Ok or Err are both fine; only a panic fails.
        for data in crafted {
            let _ = parse(data);
        }
    }
}
