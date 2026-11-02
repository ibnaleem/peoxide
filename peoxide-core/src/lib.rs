mod headers;
pub use goblin::error::Error;
pub use goblin::pe::data_directories::DataDirectory;
pub use goblin::pe::section_table::SectionTable as Section;
pub use headers::*;

use goblin::pe::PE;
use goblin::pe::export::ExportAddressTableEntry;
use goblin::pe::import::SyntheticImportLookupTableEntry;
use goblin::pe::options::ParseOptions;
use goblin::pe::{characteristic, subsystem};

pub struct Pe {
    pub headers: Headers,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportDll>,
    pub exports: Vec<ExportSymbol>,
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
    pub ordinal: u32,
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
    let mut opts = ParseOptions::default();
    opts.parse_attribute_certificates = false;
    let opts = opts.with_parse_resources(false).with_parse_tls_data(false);

    let pe = PE::parse_with_opts(data, &opts)?;
    let headers = headers::from_goblin(&pe.header)?;
    let imports = imports(&pe, headers.optional_header.image_base);
    let exports = exports(data, &pe, headers.optional_header.file_alignment, &opts);
    let mut sections = pe.sections;
    // pefile orders sections by VirtualAddress, not by section-table position.
    sections.sort_by_key(|s| s.virtual_address);
    Ok(Pe {
        headers,
        sections,
        imports,
        exports,
    })
}

fn imports(pe: &PE, image_base: u64) -> Vec<ImportDll> {
    let Some(import_data) = &pe.import_data else {
        return Vec::new();
    };
    let thunk_size = if pe.is_64 { 8 } else { 4 };
    import_data
        .import_data
        .iter()
        .map(|entry| {
            let iat = image_base + entry.import_directory_entry.import_address_table_rva as u64;
            let imports = entry
                .import_lookup_table
                .iter()
                .flatten()
                .enumerate()
                .map(|(i, lookup)| {
                    let address = iat + (i * thunk_size) as u64;
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
fn exports(data: &[u8], pe: &PE, file_alignment: u32, opts: &ParseOptions) -> Vec<ExportSymbol> {
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
            ordinal: base.wrapping_add(index as u32),
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
    use goblin::pe::header::{COFF_MACHINE_X86_64, DOS_MAGIC, PE_MAGIC};

    const KERNEL32: &str = r"C:\Windows\System32\kernel32.dll";

    #[test]
    fn parses_kernel32() {
        let data = std::fs::read(KERNEL32).unwrap();
        let pe = parse(&data).unwrap();
        let headers = &pe.headers;

        assert_eq!(headers.dos_header.e_magic, DOS_MAGIC);
        assert_eq!(headers.signature, PE_MAGIC);
        assert_eq!(headers.file_header.machine, COFF_MACHINE_X86_64);
        assert_eq!(
            headers.optional_header.magic,
            goblin::pe::optional_header::MAGIC_64
        );
        assert!(headers.optional_header.base_of_data.is_none());
        assert_eq!(headers.optional_header.data_directory.len(), 16);
        assert!(headers.optional_header.data_directory[0].virtual_address != 0);

        assert_eq!(
            pe.sections.len(),
            headers.file_header.number_of_sections as usize
        );
        assert_eq!(&pe.sections[0].name, b".text\0\0\0");

        assert!(
            pe.imports
                .iter()
                .any(|dll| dll.dll.eq_ignore_ascii_case(b"ntdll.dll"))
        );
        let create_file = pe
            .exports
            .iter()
            .find(|e| e.name.as_deref() == Some(b"CreateFileW"))
            .expect("kernel32 exports CreateFileW");
        assert!(create_file.address != 0);
    }

    #[test]
    fn classifies_dll_exe_and_driver() {
        let system32 = std::path::Path::new(r"C:\Windows\System32");
        let classify = |name: &str| {
            let pe = parse(&std::fs::read(system32.join(name)).unwrap()).unwrap();
            (pe.is_dll(), pe.is_exe(), pe.is_driver())
        };
        assert_eq!(classify("kernel32.dll"), (true, false, false));
        assert_eq!(classify("notepad.exe"), (false, true, false));
        assert_eq!(classify(r"drivers\ntfs.sys"), (false, false, true));
    }

    #[test]
    fn rejects_garbage_and_truncated_input() {
        let data = std::fs::read(KERNEL32).unwrap();
        assert!(parse(b"not a pe file").is_err());
        assert!(parse(&[]).is_err());
        for len in [2, 64, 0x100, 0x400] {
            assert!(parse(&data[..len]).is_err(), "truncated to {len} bytes");
        }
    }
}
