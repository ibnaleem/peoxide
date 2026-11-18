"""Compare peoxide against pefile on every *.dll / *.exe in a folder.

Usage: python scripts/parity_sweep.py C:\\Windows\\System32

Two deliberate pefile behaviours are normalised away before comparing:
- pefile invents names for ordinal imports from OLEAUT32/WS2_32 (its `ordlookup` table);
  peoxide reports the file's contents, so ordinal imports are compared by ordinal only.
- pefile truncates export names at MAX_SYMBOL_NAME_LENGTH and stops after
  MAX_SYMBOL_EXPORT_COUNT ordinals; peoxide returns the full table.
"""

import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pefile

import peoxide

DIRECTORIES = [
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
]
DEBUG_FIELDS = ["Characteristics", "TimeDateStamp", "Type", "SizeOfData", "PointerToRawData"]
CODEVIEW_FIELDS = ["Signature_String", "Age", "PdbFileName", "CvHeaderSignature", "Signature"]
TLS_FIELDS = [entry.split(",")[1] for entry in pefile.PE.__IMAGE_TLS_DIRECTORY_format__[1]]


def summarize(pe, export_limit=None):
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    exports = [
        (s.name and s.name[: pefile.MAX_SYMBOL_NAME_LENGTH], s.ordinal, s.address, s.forwarder)
        for s in (export_dir.symbols if export_dir else [])
    ]
    return {
        "headers": (
            pe.DOS_HEADER.e_lfanew,
            pe.FILE_HEADER.Machine,
            pe.FILE_HEADER.TimeDateStamp,
            pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.SizeOfImage,
            pe.OPTIONAL_HEADER.CheckSum,
        ),
        "sections": [
            (s.Name, s.Misc_VirtualSize, s.VirtualAddress, s.SizeOfRawData, s.PointerToRawData)
            for s in pe.sections
        ],
        "imports": [
            (d.dll, [(None if i.import_by_ordinal else i.name, i.ordinal, i.address) for i in d.imports])
            for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        ],
        "exports": exports[:export_limit],
    }


DOS_FIELDS = [entry.split(",")[1] for entry in pefile.PE.__IMAGE_DOS_HEADER_format__[1]]


def outcome(method, *args):
    try:
        return method(*args)
    except (pefile.PEFormatError, peoxide.PEFormatError):
        return "raised"


def probes(pe):
    """RVAs and file offsets around every section boundary, the headers and the file end."""
    size = len(pe.__data__)
    rvas, offsets = {0, 0x40, size - 1, size + 0x100000}, {0, 0x40, size - 1, size + 0x100000}
    for s in pe.sections:
        end = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        rvas |= {s.VirtualAddress, s.VirtualAddress + 0x10, end - 1, end}
        raw_end = s.PointerToRawData + s.SizeOfRawData
        offsets |= {s.PointerToRawData, s.PointerToRawData + 0x10, raw_end - 1, raw_end}
    return sorted(rvas), sorted(offsets)


def details(pe, rvas, offsets):
    """Fields checked by the sweep but not read inside the benchmark timer."""
    return {
        "dos header": [getattr(pe.DOS_HEADER, field) for field in DOS_FIELDS],
        "data directories": [
            (d.name, d.VirtualAddress, d.Size) for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY
        ],
        "classification": (pe.is_exe(), pe.is_dll(), pe.is_driver()),
        "overlay": pe.get_overlay_data_start_offset(),
        "section data": [(s.get_hash_md5(), round(s.get_entropy(), 9)) for s in pe.sections],
        "rva mapping": [
            (outcome(pe.get_offset_from_rva, rva), outcome(pe.get_data, rva, 16)) for rva in rvas
        ],
        "offset mapping": [pe.get_rva_from_offset(offset) for offset in offsets],
        "delay imports": [
            (
                d.dll,
                [
                    (None if i.import_by_ordinal else i.name, i.ordinal, i.hint, i.address)
                    for i in d.imports
                ],
            )
            for d in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])
        ],
        "debug": [
            (
                [getattr(d.struct, f) for f in DEBUG_FIELDS],
                [getattr(d.entry, f, None) for f in CODEVIEW_FIELDS] if d.entry else None,
            )
            for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
            if d.struct.Type != 4
        ],
        "relocations": [
            (b.struct.VirtualAddress, b.struct.SizeOfBlock, [(e.type, e.rva) for e in b.entries])
            for b in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
        ],
        "rich header": rich_header(pe),
        "tls": tls(pe),
        "resources": resource_tree(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)),
        "version info": version_info(pe),
    }


def tls(pe):
    entry = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    return entry and [getattr(entry.struct, f) for f in TLS_FIELDS]


def resource_tree(directory):
    if directory is None:
        return None
    return (
        directory.struct.NumberOfNamedEntries,
        directory.struct.NumberOfIdEntries,
        [
            (
                e.struct.Name,
                e.struct.OffsetToData,
                e.name and e.name.string,
                e.id,
                resource_tree(e.directory)
                if hasattr(e, "directory")
                else (e.data.struct.OffsetToData, e.data.struct.Size, e.data.lang, e.data.sublang),
            )
            for e in directory.entries
        ],
        list(directory.strings.items()) if hasattr(directory, "strings") else None,
    )


VERSION_HEADER_FIELDS = ["Length", "ValueLength", "Type"]
FIXED_FILE_INFO_FIELDS = [
    entry.split(",")[1] for entry in pefile.PE.__VS_FIXEDFILEINFO_format__[1]
]


def version_info(pe):
    """VS_VERSIONINFO, VS_FIXEDFILEINFO and FileInfo; None for an attribute the object lacks."""

    def fields(s, names):
        return [getattr(s, f) for f in names]

    def each(obj, attr, convert):
        return [convert(item) for item in getattr(obj, attr)] if hasattr(obj, attr) else None

    def block(b):
        return (
            fields(b, VERSION_HEADER_FIELDS),
            b.Key,
            each(b, "StringTable", lambda t: (fields(t, VERSION_HEADER_FIELDS), t.LangID, list(t.entries.items()))),
            each(b, "Var", lambda v: (fields(v, VERSION_HEADER_FIELDS), getattr(v, "entry", None))),
        )

    return (
        each(pe, "VS_VERSIONINFO", lambda v: fields(v, VERSION_HEADER_FIELDS + ["Key"])),
        each(pe, "VS_FIXEDFILEINFO", lambda f: fields(f, FIXED_FILE_INFO_FIELDS)),
        each(pe, "FileInfo", lambda blocks: [block(b) for b in blocks]),
    )


RICH_FIELDS = ["checksum", "values", "key", "raw_data", "clear_data"]


def rich_header(pe):
    """fast_load skips pefile's Rich header, so ask its parser directly."""
    if isinstance(pe, pefile.PE):
        rich = pe.parse_rich_header()
        return rich and [rich[f] for f in RICH_FIELDS]
    return pe.RICH_HEADER and [getattr(pe.RICH_HEADER, f) for f in RICH_FIELDS]


def differences(ours, reference):
    """Names of the summary parts where a peoxide.PE and a pefile.PE disagree."""
    rvas, offsets = probes(reference)
    theirs_summary = summarize(reference) | details(reference, rvas, offsets)
    capped = any("Assuming corrupt" in w for w in reference.get_warnings())
    ours_summary = summarize(ours, len(theirs_summary["exports"]) if capped else None)
    ours_summary |= details(ours, rvas, offsets)
    theirs_summary["imphash"], ours_summary["imphash"] = reference.get_imphash(), ours.get_imphash()
    export_dir = getattr(reference, "DIRECTORY_ENTRY_EXPORT", None)
    names = [s.name for s in export_dir.symbols] if export_dir else []
    if not capped and all(n is None or len(n) < pefile.MAX_SYMBOL_NAME_LENGTH for n in names):
        theirs_summary["exphash"], ours_summary["exphash"] = reference.get_exphash(), ours.get_exphash()
    return [key for key in ours_summary if ours_summary[key] != theirs_summary[key]]


def check(path):
    """The file's outcome, plus (kind, example) pairs to report under that kind."""
    try:
        reference = pefile.PE(str(path), fast_load=True)
        reference.parse_data_directories(directories=DIRECTORIES)
    except Exception:
        return "skipped (pefile failed)", []
    try:
        ours = peoxide.PE(str(path))
    except peoxide.PEFormatError as error:
        return "peoxide failed", [("peoxide failed", f"{path.name}: {error}")]
    differing = differences(ours, reference)
    return "mismatch" if differing else "match", [(f"{k} differs", path.name) for k in differing]


def main(folder):
    files = sorted(
        p for p in Path(folder).iterdir() if p.suffix.lower() in {".dll", ".exe", ".sys"}
    )
    outcomes = Counter()
    examples = {}
    # pefile is pure Python, so threads would serialise on the GIL; processes run it in parallel.
    with ProcessPoolExecutor() as pool:
        for outcome, found in pool.map(check, files, chunksize=16):
            outcomes[outcome] += 1
            for kind, example in found:
                examples.setdefault(kind, []).append(example)

    print(f"{len(files)} files: {dict(outcomes)}")
    for kind, names in examples.items():
        print(f"  {kind} ({len(names)}): {names[:5]}")
    return 0 if set(outcomes) <= {"match", "skipped (pefile failed)"} else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
