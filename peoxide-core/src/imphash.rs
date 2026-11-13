//! The exact strings pefile hashes for `get_imphash()` and `get_exphash()`.

use crate::Pe;
use crate::ordinals::TABLES;

const STRIPPED_EXTENSIONS: [&str; 3] = ["ocx", "sys", "dll"];

/// pefile's `ordLookup(dll, ordinal, make_name=True)`: the known name, else `ord<N>`.
pub fn ordinal_name(dll: &[u8], ordinal: u16) -> Vec<u8> {
    let dll = dll.to_ascii_lowercase();
    TABLES
        .iter()
        .find(|(name, _)| *name == dll.as_slice())
        .and_then(|(_, table)| {
            let index = table.binary_search_by_key(&ordinal, |&(o, _)| o).ok()?;
            Some(table[index].1.to_vec())
        })
        .unwrap_or_else(|| format!("ord{ordinal}").into_bytes())
}

/// Appends `bytes` in lowercase. Names are nearly always ASCII, which needs no decoding.
fn push_lower(out: &mut String, bytes: &[u8]) {
    if bytes.is_ascii() {
        out.extend(bytes.iter().map(|b| b.to_ascii_lowercase() as char));
    } else {
        out.push_str(&String::from_utf8_lossy(bytes).to_lowercase());
    }
}

fn lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    push_lower(&mut out, bytes);
    out
}

impl Pe {
    /// `dll.function` pairs joined by commas, or `None` when the file imports nothing.
    pub fn imphash_input(&self) -> Option<String> {
        if self.imports.is_empty() {
            return None;
        }
        let mut input = String::new();
        for entry in &self.imports {
            let dll = lower(&entry.dll);
            let library = match dll.rsplit_once('.') {
                Some((stem, ext)) if STRIPPED_EXTENSIONS.contains(&ext) => stem,
                _ => &dll,
            };
            for import in &entry.imports {
                if !input.is_empty() {
                    input.push(',');
                }
                input.push_str(library);
                input.push('.');
                match (&import.name, import.ordinal) {
                    (Some(name), _) if !name.is_empty() => push_lower(&mut input, name),
                    (_, Some(ordinal)) => {
                        push_lower(&mut input, &ordinal_name(&entry.dll, ordinal))
                    }
                    // pefile formats a missing ordinal as Python's None.
                    _ => input.push_str("ordnone"),
                }
            }
        }
        Some(input)
    }

    /// Lowercase named exports joined by commas, or `None` when nothing is exported by name.
    pub fn exphash_input(&self) -> Option<String> {
        let names: Vec<String> = self
            .exports
            .iter()
            .filter_map(|e| e.name.as_deref().map(lower))
            .collect();
        (!names.is_empty()).then(|| names.join(","))
    }
}
