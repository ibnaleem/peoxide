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
| `DIRECTORY_ENTRY_EXPORT` | Has `symbols`, a list where each symbol has `name` (bytes or `None`), `ordinal`, `address` (RVA) and `forwarder` (bytes or `None`). |

Flags read as booleans, as in pefile. `FILE_HEADER.IMAGE_FILE_DLL`,
`OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT` and `section.IMAGE_SCN_MEM_EXECUTE` are
examples, and every `IMAGE_FILE_*`, `IMAGE_DLLCHARACTERISTICS_*` and `IMAGE_SCN_*` name works.

| Method | Returns |
|---|---|
| `is_dll()` | `True` when `FILE_HEADER` has `IMAGE_FILE_DLL` set. |
| `is_driver()` | `True` when the image imports a kernel module such as `ntoskrnl.exe`, or has a `PAGE` section and a native subsystem. Uses pefile's heuristic. |
| `is_exe()` | `True` when the image is marked executable and is neither a DLL nor a driver. |

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
- **Files with no imports or exports.** pefile leaves `DIRECTORY_ENTRY_IMPORT` and `DIRECTORY_ENTRY_EXPORT` undefined. peoxide always defines them, as an empty list and an object with an empty `symbols` list, so loops work without a `hasattr` check.
- **Scope.** peoxide does not parse resources, the Rich header, relocations, debug data or the delay-import table, and it cannot modify or write PE files.

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
work peoxide does (headers, sections, imports, exports), and once it runs its default full parse.

Results for the 75 DLLs in `C:\Windows\System32\wbem` (25 MB, 3 rounds, release build, one Windows 11 machine):

| Parser | Total | Per file | vs peoxide |
|---|---:|---:|---:|
| peoxide | 13.9 ms | 0.185 ms | 1.0x |
| pefile (headers + imports + exports) | 278.5 ms | 3.713 ms | 20.0x |
| pefile (default full parse) | 2,988.3 ms | 39.844 ms | 215.0x |

The scoped row is the fair comparison. The full-parse row is what you get from a plain
`pefile.PE(path)`, which also parses resources, relocations, debug data and more.
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

## License

[GPL-3.0](LICENSE)
