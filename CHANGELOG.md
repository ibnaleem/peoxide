# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

peoxide has not been released yet. Everything below is on `main`.

### Added

- Headers: every DOS, FILE and OPTIONAL header field, `DATA_DIRECTORY`, flag booleans, and `is_exe()`, `is_dll()` and `is_driver()`.
- Sections: section parsing with `get_data`, `get_entropy`, hashes and `contains_*` helpers.
- Address helpers: `get_data`, RVA and file offset conversion, section lookup and overlay detection.
- Imports: `DIRECTORY_ENTRY_IMPORT`.
- Exports: `DIRECTORY_ENTRY_EXPORT`, rebuilt from the raw export tables so ordinals and ordinal-only exports are kept.
- Hashes: `get_imphash()` and `get_exphash()`, MD5 by default with an `algorithm=` argument.
- Delay imports: `DIRECTORY_ENTRY_DELAY_IMPORT`.
- Debug: `DIRECTORY_ENTRY_DEBUG` with CodeView and EX DLL characteristics entries.
- Rich header: `RICH_HEADER` and `get_rich_header_hash`.
- Relocations: `DIRECTORY_ENTRY_BASERELOC`.
- Resources: `DIRECTORY_ENTRY_RESOURCE`, built on first access.
- Strings: RT_STRING tables in the resource directory.
- Version info: RT_VERSION decoded into `VS_VERSIONINFO`, `VS_FIXEDFILEINFO` and `FileInfo`.
- Input: `PE(data=...)` accepts in-memory bytes.
- Errors: malformed or truncated input raises `PEFormatError`.
- CI: clippy and tests on Windows, plus wheel builds for Linux, musllinux, Windows and macOS x86_64.

[Unreleased]: https://github.com/ibnaleem/peoxide/commits/main
