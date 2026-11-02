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

fn lower(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_lowercase()
}

impl Pe {
    /// `dll.function` pairs joined by commas, or `None` when the file imports nothing.
    pub fn imphash_input(&self) -> Option<String> {
        if self.imports.is_empty() {
            return None;
        }
        let pairs = self.imports.iter().flat_map(|entry| {
            let dll = lower(&entry.dll);
            let library = match dll.rsplit_once('.') {
                Some((stem, ext)) if STRIPPED_EXTENSIONS.contains(&ext) => stem.to_owned(),
                _ => dll,
            };
            entry.imports.iter().map(move |import| {
                let function = match (&import.name, import.ordinal) {
                    (Some(name), _) if !name.is_empty() => lower(name),
                    (_, Some(ordinal)) => lower(&ordinal_name(&entry.dll, ordinal)),
                    // pefile formats a missing ordinal as Python's None.
                    _ => "ordnone".to_owned(),
                };
                format!("{library}.{function}")
            })
        });
        Some(pairs.collect::<Vec<_>>().join(","))
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
