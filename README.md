<h1 align="center">peoxide</h1>

<p align="center">
  <b>A fast PE file parser library for Python, written in Rust.</b><br>
  Read the headers, sections, imports and exports of Windows executables,
  with the same attribute names as <a href="https://github.com/erocarrera/pefile">pefile</a>.
</p>

<p align="center">
  <a href="https://github.com/ibnaleem/peoxide/actions/workflows/CI.yml"><img src="https://github.com/ibnaleem/peoxide/actions/workflows/CI.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-GPLv3-green" alt="GPLv3">
</p>

---

```python
import peoxide

pe = peoxide.PE("C:/Windows/System32/kernel32.dll")

print(hex(pe.OPTIONAL_HEADER.ImageBase))
for section in pe.sections:
    print(section.Name.rstrip(b"\0"), hex(section.VirtualAddress))

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll, len(entry.imports))

for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(symbol.ordinal, symbol.name, hex(symbol.address))
```

## Why peoxide

pefile is the standard way to read PE files from Python, and it is written in pure Python.
peoxide parses the file in Rust (on top of [goblin](https://github.com/m4b/goblin)) and hands
Python finished, read-only objects. It makes one call into Rust per file, not one per field,
which is where the speedup comes from.

- **Fast.** See [Benchmark](#benchmark).
- **Familiar.** Attribute names, types and values match pefile, so most read-only pefile code works unchanged.
- **Safe on bad input.** Truncated, corrupted or non-PE data raises `peoxide.PEFormatError`. It never crashes the interpreter.

## Install

peoxide is not on PyPI yet. Build it from source with a Rust toolchain and [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/ibnaleem/peoxide
cd peoxide
uv venv
uv pip install maturin
uv run maturin develop --uv --release
```

## Supported platforms

peoxide needs Python 3.8 or newer. CI builds these wheels:

| OS | Architectures |
| --- | --- |
| Linux (manylinux) | x86_64, x86, aarch64, armv7, s390x, ppc64le |
| Linux (musllinux 1.2) | x86_64, x86, aarch64, armv7 |
| Windows | x64, x86, arm64 |
| macOS | x86_64 |

macOS arm64 wheels are not built right now. Apple Silicon users can build from source, as in [Install](#install). The Rust tests run on Windows and Linux against synthetic PE files in `tests/fixtures`. The pefile parity tests also read Windows system binaries, so they run on Windows only.

## API

`peoxide.PE(name=None, data=None)` parses a file path or a `bytes` object. Pass exactly one.
Everything is parsed up front, and every attribute below is read-only.

| Attribute | Contents |
|---|---|
| `DOS_HEADER` | Every field, from `e_magic` to `e_lfanew`. `e_res` and `e_res2` are raw bytes. |
| `NT_HEADERS` | `Signature` |
| `FILE_HEADER` | `Machine`, `NumberOfSections`, `TimeDateStamp`, `PointerToSymbolTable`, `NumberOfSymbols`, `SizeOfOptionalHeader`, `Characteristics` |
| `OPTIONAL_HEADER` | Every PE32 and PE32+ field, from `Magic` to `NumberOfRvaAndSizes`. `BaseOfData` is `None` on PE32+. `DATA_DIRECTORY` lists each directory's `name`, `VirtualAddress` and `Size`. |
| `sections` | List of sections with `Name` (8 raw bytes), `Misc_VirtualSize`, `VirtualAddress`, `SizeOfRawData`, `PointerToRawData`, `PointerToRelocations`, `PointerToLinenumbers`, `NumberOfRelocations`, `NumberOfLinenumbers`, `Characteristics` |
| `DIRECTORY_ENTRY_IMPORT` | List of imported DLLs, each with `dll` (bytes) and `imports`. Each import has `name` (bytes or `None`), `hint`, `ordinal`, `import_by_ordinal` and `address` (the IAT slot's virtual address). |
| `DIRECTORY_ENTRY_DELAY_IMPORT` | Delay-loaded DLLs, in the same shape as `DIRECTORY_ENTRY_IMPORT`. Empty when the file has none. |
| `DIRECTORY_ENTRY_DEBUG` | Debug records, each with `struct` (`Characteristics`, `TimeDateStamp`, `MajorVersion`, `MinorVersion`, `Type`, `SizeOfData`, `AddressOfRawData`, `PointerToRawData`) and `entry`. CodeView records decode to `entry.PdbFileName`, `entry.Age`, the GUID fields and pefile's `entry.Signature_String`, and type 20 decodes to `entry.ExDllCharacteristics` with its `IMAGE_DLLCHARACTERISTICS_EX_*` flags. Other types have `entry` set to `None`. |
| `DIRECTORY_ENTRY_BASERELOC` | Base relocation blocks, each with `struct` (`VirtualAddress`, `SizeOfBlock`) and `entries`. Each entry has `type`, `rva` and `base_rva`. Built on first access, because large DLLs carry tens of thousands of entries. Empty when the file has none. |
| `DIRECTORY_ENTRY_RESOURCE` | The resource tree's root, or `None` when the file has no readable resource directory. A directory has `struct` (`Characteristics`, `TimeDateStamp`, `MajorVersion`, `MinorVersion`, `NumberOfNamedEntries`, `NumberOfIdEntries`) and `entries`. Each entry has `struct` (`Name`, `OffsetToData`, `NameOffset`, `Id`, `DataIsDirectory`, `OffsetToDirectory`), `name` (with `string`, `decode()` and `str()`, or `None` for ID entries), `id`, and either `directory` or `data`. A `data` leaf has `struct` (`OffsetToData`, `Size`, `CodePage`, `Reserved`), `lang` and `sublang`. Read a leaf's bytes with `pe.get_data(leaf.data.struct.OffsetToData, leaf.data.struct.Size)`. The per-block directories under RT_STRING also have `strings`, a dict from string ID to text, as in pefile. Built on first access. |
| `VS_VERSIONINFO`, `VS_FIXEDFILEINFO`, `FileInfo` | Version information from RT_VERSION, as in pefile. `VS_VERSIONINFO` entries have `Length`, `ValueLength`, `Type` and `Key`. `VS_FIXEDFILEINFO` entries have the 13 fixed fields, from `Signature` to `FileDateLS`. `FileInfo` holds one list per version resource of StringFileInfo and VarFileInfo blocks, each with `Length`, `ValueLength`, `Type` and `Key`. A StringFileInfo block has `StringTable`, whose tables have `LangID` and `entries` (a dict of bytes to bytes). A VarFileInfo block has `Var`, whose entries have `entry` (for example `{b'Translation': '0x0409 0x04b0'}`). Like pefile, these attributes are missing when the file has no readable version information, so check with `hasattr`. |
| `RICH_HEADER` | The decoded Rich header, with `checksum`, `values` (flattened `comp_id, count` pairs), `key`, `raw_data` and `clear_data`, or `None` when the file has none. |
| `DIRECTORY_ENTRY_EXPORT` | Has `symbols`, a list where each symbol has `name` (bytes or `None`), `ordinal`, `address` (RVA) and `forwarder` (bytes or `None`). |

Flags read as booleans, as in pefile. `FILE_HEADER.IMAGE_FILE_DLL`,
`OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT` and `section.IMAGE_SCN_MEM_EXECUTE` are
examples, and every `IMAGE_FILE_*`, `IMAGE_DLLCHARACTERISTICS_*` and `IMAGE_SCN_*` name works.

| Method | Returns |
|---|---|
| `is_dll()` | `True` when `FILE_HEADER` has `IMAGE_FILE_DLL` set. |
| `is_driver()` | `True` when the image imports a kernel module such as `ntoskrnl.exe`, or has a `PAGE` section and a native subsystem. Uses pefile's heuristic. |
| `is_exe()` | `True` when the image is marked executable and is neither a DLL nor a driver. |
| `get_data(rva=0, length=None)` | Bytes at an RVA, read from the section that holds it, or from the headers or raw file when no section does. Raises `PEFormatError` when the RVA is past the end of the file. |
| `get_offset_from_rva(rva)` | The file offset an RVA maps to. Raises `PEFormatError` like `get_data`. |
| `get_rva_from_offset(offset)` | The RVA a file offset maps to, or `None`. |
| `get_section_by_rva(rva)`, `get_section_by_offset(offset)` | The section containing the address, or `None`. |
| `get_overlay()`, `get_overlay_data_start_offset()` | Data appended after everything the headers describe, and where it starts, or `None`. |
| `get_imphash(algorithm="md5")` | pefile's imphash: a hash of the lowercase `dll.function` import list, or `""` when nothing is imported. Ordinal imports from OLEAUT32, WS2_32 and WSOCK32 are named with pefile's tables, so the MD5 matches pefile's. Pass any `hashlib` name, such as `"sha256"`, for a different digest of the same input. |
| `get_exphash(algorithm="md5")` | The same over the lowercase names of the named exports, or `""` when there are none. |
| `get_rich_header_hash(algorithm="md5")` | A hash of `RICH_HEADER.clear_data`, or `""` when the file has no Rich header. |

Sections have methods too:

| Method | Returns |
|---|---|
| `get_data(start=None, length=None, ignore_padding=False)` | The section's bytes, or a slice starting at RVA `start`. `ignore_padding` stops at `Misc_VirtualSize`. |
| `get_entropy()` | Shannon entropy of the section's bytes, in bits per byte. |
| `get_hash_md5()`, `get_hash_sha1()`, `get_hash_sha256()`, `get_hash_sha512()` | Hex digest of the section's bytes. |
| `contains_rva(rva)`, `contains_offset(offset)` | Whether the address falls inside the section. |
| `get_offset_from_rva(rva)`, `get_rva_from_offset(offset)` | Address conversion within this section. |

Address math follows pefile's rules exactly, including its rounding of `PointerToRawData` to
512 bytes and of `VirtualAddress` to the section alignment. Like pefile, `sections` is ordered
by `VirtualAddress`.

Errors:

| Situation | Exception |
|---|---|
| The data is not a valid PE file (truncated, corrupted, wrong magic) | `peoxide.PEFormatError` |
| The path cannot be read | `OSError` (for example `FileNotFoundError`) |
| Neither or both of `name` and `data` given | `TypeError` |

## Differences from pefile

peoxide reports what is in the file. pefile adds a few conveniences and safety limits on top, so
the two disagree in these cases:

- **Ordinal imports from OLEAUT32 and WS2_32.** pefile looks up a name from its built-in table. peoxide leaves `name` as `None`, because the file contains only the ordinal.
- **Very large export tables.** pefile stops after 8192 ordinal-only exports and treats the rest as corrupt. Some real DLLs, such as `mfc100.dll`, export more than that, and peoxide returns all of them.
- **Very long export names.** pefile truncates names longer than `MAX_SYMBOL_NAME_LENGTH`. peoxide returns the full name.
- **`get_exphash()` on those two kinds of file.** It hashes the full export list, so it differs from pefile's wherever pefile capped the table or truncated a name.
- **Files with no imports or exports.** pefile leaves `DIRECTORY_ENTRY_IMPORT` and `DIRECTORY_ENTRY_EXPORT` undefined. peoxide always defines them, as an empty list and an object with an empty `symbols` list, so loops work without a `hasattr` check.
- **Section reads that start before the section.** `section.get_data(start)` with `start` below the section's address gives pefile a negative offset, which Python treats as counting from the end of the file. peoxide clamps it to the start of the file instead.
- **Corrupt delay-import thunk tables.** pefile gives up on a thunk table that repeats one address 15 times or spreads its addresses over more than 128 MB. peoxide does not apply those two heuristics, so on such a table it may return entries where pefile returns none.
- **IMAGE_DEBUG_TYPE_MISC records.** pefile decodes these pre-PDB debug records. peoxide leaves their `entry` as `None`.
- **Relocation entries.** They carry `type`, `rva` and `base_rva` but not pefile's per-entry `struct`. `DIRECTORY_ENTRY_BASERELOC` is an empty list, not undefined, when there are no relocations.
- **No resource directory.** `DIRECTORY_ENTRY_RESOURCE` is `None`, not undefined, when the file has no readable resource directory.
- **Version blocks whose offsets wrap past 4 GiB.** pefile aligns version offsets with a 32-bit mask, and on a crafted resource that wraps it can loop forever. peoxide stops reading that block instead.
- **Scope.** peoxide cannot modify or write PE files.

## Correctness

`tests/test_parity.py` compares every field above against pefile on a set of system binaries,
both 64-bit and 32-bit. `scripts/parity_sweep.py` runs the same comparison over a whole folder,
with the differences listed above normalized away:

| Folder | Files | Match |
|---|---:|---:|
| `C:\Windows\System32` | 4,277 | 4,277 |
| `C:\Windows\SysWOW64` (32-bit) | 2,734 | 2,734 |
| `C:\Windows\System32\drivers` | 500 | 500 |

The sweep skipped 6 more SysWOW64 files because pefile could not parse them.
`tests/test_errors.py` feeds peoxide empty, garbage, truncated and 2,000 randomly corrupted
files, and checks that every one either parses or raises `PEFormatError`.

## Benchmark

`scripts/benchmark.py` times each parser on the same in-memory bytes. The timer covers parsing
and then reading every header, section, import and export back out, so a parser can't look fast
by deferring work. Before timing, it checks that peoxide's results equal pefile's on every file.
Garbage collection is disabled while timing, parser order is shuffled per file, one warm-up round
is discarded, and the median round is reported. pefile is timed twice. Once it is limited to the
work peoxide does (headers, sections, imports, delay imports, exports, debug, relocations and
resources with their string tables and version info), and once it runs its default full parse.

Results for the 75 DLLs in `C:\Windows\System32\wbem` (25 MB, 5 rounds, release build, one Windows 11 machine):

| Parser | Total | Per file | vs peoxide |
|---|---:|---:|---:|
| peoxide | 25.0 ms | 0.334 ms | 1.0x |
| pefile (same work as peoxide) | 1,003.7 ms | 13.383 ms | 40.1x |
| pefile (default full parse) | 3,039.2 ms | 40.523 ms | 121.4x |

The scoped row is the fair comparison. The full-parse row is what you get from a plain
`pefile.PE(path)`, which also parses TLS, load config, bound imports and more.
To reproduce, build in release mode first:

```sh
uv run maturin develop --uv --release
uv run python scripts/benchmark.py C:\Windows\System32
```

## Development

```sh
cargo clippy --all-targets -- -D warnings
cargo test                                     # Rust parser tests (peoxide-core)
uv pip install pefile pytest
uv run maturin develop --uv
uv run pytest -q tests                         # Python parity and error tests
uv run python scripts/parity_sweep.py C:\Windows\System32
```

The repository is a Cargo workspace with two crates:

- `peoxide-core` is the parser. It is plain Rust with no Python dependency, so you can test it with `cargo test`.
- `peoxide-py` holds the PyO3 bindings. maturin builds it into the `peoxide` Python module.

## Versioning

peoxide follows [Semantic Versioning](https://semver.org). Both crates and the Python package share one version, set in `[workspace.package]` in the root `Cargo.toml`. maturin reads it from there, so there is no second place to edit. While the version is 0.x, a minor release may break the API.

## License

[GPL-3.0](LICENSE)
