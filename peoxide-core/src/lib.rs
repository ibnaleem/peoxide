pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
}

pub struct OptionalHeader {
    pub magic: u16,
    pub image_base: u64,
}

pub struct Headers {
    pub dos_header: DosHeader,
    pub signature : u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

pub fn parse(data: &[u8]) -> Result<Headers, goblin::error::Error> {
    let headers = goblin::pe::header::Header::parse(data).map_err(|e| goblin::error::Error::Malformed(format!("Failed to parse PE headers: {}", e)))?;

    let dos_header = DosHeader {
        e_magic: headers.dos_header.signature,
        e_lfanew: headers.dos_header.pe_pointer,
    };

    let file_header = FileHeader {
        machine: headers.coff_header.machine,
        number_of_sections: headers.coff_header.number_of_sections,
    };

    let opt = headers.optional_header.ok_or_else(|| goblin::error::Error::Malformed("missing optional header".into()))?;

    let optional_header = OptionalHeader {
        magic: opt.standard_fields.magic,
        image_base: opt.windows_fields.image_base,
    };

    Ok(Headers {
        dos_header,
        signature: headers.signature,
        file_header,
        optional_header,
    })

    
}

#[cfg(test)]
mod tests {
    use crate::parse;
    use goblin::pe::header::{COFF_MACHINE_X86_64, DOS_MAGIC, PE_MAGIC};

    const KERNEL32: &str = r"C:\Windows\System32\kernel32.dll";

    #[test]
    fn parses_kernel32_headers() {
        let data = std::fs::read(KERNEL32).unwrap();
        
        let headers = parse(&data).unwrap();
        let off = headers.dos_header.e_lfanew as usize;
        assert_eq!(headers.dos_header.e_magic, DOS_MAGIC);
        assert_eq!(&data[off..off + 4], b"PE\0\0");
        assert_eq!(headers.file_header.machine, COFF_MACHINE_X86_64);
        assert_eq!(headers.signature, PE_MAGIC);
    }
    
}



