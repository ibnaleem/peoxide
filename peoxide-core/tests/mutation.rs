//! Mutated and truncated fixtures must parse or fail with an error, never panic.
//!
//! The default case count keeps `cargo test` quick; set `PROPTEST_CASES` for a deeper run.

use std::ops::Range;

use peoxide_core::{Pe, clamp, entropy, parse};
use proptest::prelude::*;
use proptest::test_runner::Config;

const FIXTURES: [&[u8]; 3] = [
    include_bytes!("../../tests/fixtures/sample64.dll"),
    include_bytes!("../../tests/fixtures/sample32.exe"),
    include_bytes!("../../tests/fixtures/driver.sys"),
];
/// Share of edits aimed at the headers, section table and data directories.
const HOT_EDIT_SHARE: f64 = 0.7;
const TRUNCATE_SHARE: f64 = 0.25;
/// Most bytes one case overwrites.
const MAX_EDITS: usize = 32;

/// One overwritten byte. `region` and `position` are seeds reduced modulo the target range.
#[derive(Debug)]
struct Edit {
    is_hot: bool,
    region: usize,
    position: usize,
    value: u8,
}

/// The bytes the parser reads structure from: headers with the section table, then each directory.
fn hot_regions(data: &[u8]) -> Vec<Range<usize>> {
    let pe = parse(data).expect("fixtures parse");
    let headers = clamp((0, pe.header_size), data.len());
    let directories = pe
        .headers
        .optional_header
        .data_directory
        .iter()
        .filter_map(|d| pe.data_range(d.virtual_address as i64, Some(d.size as i64)));
    std::iter::once(headers)
        .chain(directories)
        .filter(|range| !range.is_empty())
        .collect()
}

fn mutate(original: &[u8], edits: &[Edit], truncate: Option<usize>) -> Vec<u8> {
    let hot = hot_regions(original);
    let mut data = original.to_vec();
    for edit in edits {
        let range = if edit.is_hot {
            hot[edit.region % hot.len()].clone()
        } else {
            0..data.len()
        };
        data[range.start + edit.position % range.len()] = edit.value;
    }
    if let Some(len) = truncate {
        data.truncate(len % (data.len() + 1));
    }
    data
}

/// Calls the model's helpers on boundary probes: type flags, imphash and exphash inputs, overlay,
/// section entropy, section lookup, RVA and offset conversion, and data ranges.
fn exercise(pe: &Pe, data: &[u8]) {
    let sections: Vec<_> = pe.sections.iter().zip(&pe.layouts).collect();
    let _ = (pe.is_dll(), pe.is_exe(), pe.is_driver());
    let _ = (pe.imphash_input(), pe.exphash_input());
    let _ = pe.parse_relocations(data);
    let _ = pe.checksum(data);
    if let Some(offset) = pe.overlay_offset() {
        let _ = &data[offset..];
    }

    let mut probes = vec![
        -1,
        0,
        1,
        i64::MIN,
        i64::MAX,
        pe.file_size as i64,
        pe.header_size,
    ];
    for d in &pe.headers.optional_header.data_directory {
        probes.extend([d.virtual_address as i64, d.size as i64]);
    }
    for &(section, layout) in &sections {
        probes.extend([
            section.virtual_address as i64,
            section.pointer_to_raw_data as i64,
            layout.rva_start,
            layout.rva_end.saturating_sub(1),
            layout.pointer_to_raw_data,
        ]);
        let _ = entropy(&data[clamp(layout.data_range(section, None, None, false), data.len())]);
    }

    let lengths = [None, Some(0), Some(1), Some(-1), Some(i64::MAX)];
    for &value in &probes {
        let _ = (pe.section_by_rva(value), pe.section_by_offset(value));
        let _ = (pe.offset_from_rva(value), pe.rva_from_offset(value));
        for &(section, layout) in &sections {
            let _ = (
                layout.contains_rva(value),
                layout.contains_offset(section, value),
            );
            let _ = (layout.offset_from_rva(value), layout.rva_from_offset(value));
        }
        for length in lengths {
            if let Some(range) = pe.data_range(value, length) {
                let _ = &data[range];
            }
            for &(section, layout) in &sections {
                for ignore_padding in [false, true] {
                    let range = layout.data_range(section, Some(value), length, ignore_padding);
                    let _ = &data[clamp(range, data.len())];
                }
            }
        }
    }
}

fn edit() -> impl Strategy<Value = Edit> {
    (
        prop::bool::weighted(HOT_EDIT_SHARE),
        any::<usize>(),
        any::<usize>(),
        any::<u8>(),
    )
        .prop_map(|(is_hot, region, position, value)| Edit {
            is_hot,
            region,
            position,
            value,
        })
}

proptest! {
    #![proptest_config(Config { failure_persistence: None, ..Config::default() })]

    #[test]
    fn mutated_fixtures_never_panic(
        fixture in 0..FIXTURES.len(),
        edits in prop::collection::vec(edit(), 1..=MAX_EDITS),
        truncate in prop::option::weighted(TRUNCATE_SHARE, any::<usize>()),
    ) {
        let data = mutate(FIXTURES[fixture], &edits, truncate);
        if let Ok(pe) = parse(&data) {
            exercise(&pe, &data);
        }
    }
}
