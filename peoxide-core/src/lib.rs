pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

pub fn parse(data: &[u8]) -> Result<DosHeader, goblin::error::Error> {
    let dos_header = goblin::pe::header::DosHeader::parse(data)?;
    Ok(DosHeader {
        e_magic: dos_header.signature,
        e_lfanew: dos_header.pe_pointer,
    })
}

#[cfg(test)]
mod tests {
    use crate::parse;

    #[test]

    fn parses_kernel32_dos_header() {
        let data = std::fs::read(r"C:\Windows\System32\kernel32.dll").unwrap();
        let dos = parse(&data).unwrap();
        let off = dos.e_lfanew as usize;
        assert_eq!(dos.e_magic, 0x5A4D);
        assert_eq!(&data[off..off + 4], b"PE\0\0");
    }
    
}



