pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: Vec<u8>,
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: Vec<u8>,
    pub e_lfanew: u32,
}

fn le_bytes(words: &[u16]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u64,
    pub size_of_initialized_data: u64,
    pub size_of_uninitialized_data: u64,
    pub address_of_entry_point: u32,
    pub base_of_code: u64,
    pub base_of_data: Option<u32>, // Only present in PE32, not in PE32+
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    /// One entry per `number_of_rva_and_sizes`; unused directories are zero.
    pub data_directory: Vec<goblin::pe::data_directories::DataDirectory>,
}

pub struct Headers {
    pub dos_header: DosHeader,
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

pub(crate) fn from_goblin(
    headers: &goblin::pe::header::Header,
) -> Result<Headers, goblin::error::Error> {
    let dos = &headers.dos_header;
    let dos_header = DosHeader {
        e_magic: dos.signature,
        e_cblp: dos.bytes_on_last_page,
        e_cp: dos.pages_in_file,
        e_crlc: dos.relocations,
        e_cparhdr: dos.size_of_header_in_paragraphs,
        e_minalloc: dos.minimum_extra_paragraphs_needed,
        e_maxalloc: dos.maximum_extra_paragraphs_needed,
        e_ss: dos.initial_relative_ss,
        e_sp: dos.initial_sp,
        e_csum: dos.checksum,
        e_ip: dos.initial_ip,
        e_cs: dos.initial_relative_cs,
        e_lfarlc: dos.file_address_of_relocation_table,
        e_ovno: dos.overlay_number,
        e_res: le_bytes(&dos.reserved),
        e_oemid: dos.oem_id,
        e_oeminfo: dos.oem_info,
        e_res2: le_bytes(&dos.reserved2),
        e_lfanew: dos.pe_pointer,
    };

    let file_header = FileHeader {
        machine: headers.coff_header.machine,
        number_of_sections: headers.coff_header.number_of_sections,
        time_date_stamp: headers.coff_header.time_date_stamp,
        pointer_to_symbol_table: headers.coff_header.pointer_to_symbol_table,
        number_of_symbols: headers.coff_header.number_of_symbol_table,
        size_of_optional_header: headers.coff_header.size_of_optional_header,
        characteristics: headers.coff_header.characteristics,
    };

    let opt = headers
        .optional_header
        .as_ref()
        .ok_or_else(|| goblin::error::Error::Malformed("missing optional header".into()))?;

    let base_of_data = if opt.standard_fields.magic == goblin::pe::optional_header::MAGIC_32 {
        Some(opt.standard_fields.base_of_data)
    } else {
        None
    };

    let optional_header = OptionalHeader {
        magic: opt.standard_fields.magic,
        image_base: opt.windows_fields.image_base,
        major_linker_version: opt.standard_fields.major_linker_version,
        minor_linker_version: opt.standard_fields.minor_linker_version,
        size_of_code: opt.standard_fields.size_of_code,
        size_of_initialized_data: opt.standard_fields.size_of_initialized_data,
        size_of_uninitialized_data: opt.standard_fields.size_of_uninitialized_data,
        address_of_entry_point: opt.standard_fields.address_of_entry_point,
        base_of_code: opt.standard_fields.base_of_code,

        // base_of_data is only present in PE32, not in PE32+
        // We handle this by checking the magic number and conditionally setting it to Some(value) or None
        base_of_data, // clippy::redundant_field_names

        section_alignment: opt.windows_fields.section_alignment,
        file_alignment: opt.windows_fields.file_alignment,
        major_operating_system_version: opt.windows_fields.major_operating_system_version,
        minor_operating_system_version: opt.windows_fields.minor_operating_system_version,
        major_image_version: opt.windows_fields.major_image_version,
        minor_image_version: opt.windows_fields.minor_image_version,
        major_subsystem_version: opt.windows_fields.major_subsystem_version,
        minor_subsystem_version: opt.windows_fields.minor_subsystem_version,
        win32_version_value: opt.windows_fields.win32_version_value,
        size_of_image: opt.windows_fields.size_of_image,
        size_of_headers: opt.windows_fields.size_of_headers,
        checksum: opt.windows_fields.check_sum,
        subsystem: opt.windows_fields.subsystem,
        dll_characteristics: opt.windows_fields.dll_characteristics,
        size_of_stack_reserve: opt.windows_fields.size_of_stack_reserve,
        size_of_stack_commit: opt.windows_fields.size_of_stack_commit,
        size_of_heap_reserve: opt.windows_fields.size_of_heap_reserve,
        size_of_heap_commit: opt.windows_fields.size_of_heap_commit,
        loader_flags: opt.windows_fields.loader_flags,
        number_of_rva_and_sizes: opt.windows_fields.number_of_rva_and_sizes,
        data_directory: opt
            .data_directories
            .data_directories
            .iter()
            .take(opt.windows_fields.number_of_rva_and_sizes as usize)
            .map(|entry| entry.map(|(_, dir)| dir).unwrap_or_default())
            .collect(),
    };

    Ok(Headers {
        dos_header,
        signature: headers.signature,
        file_header,
        optional_header,
    })
}
