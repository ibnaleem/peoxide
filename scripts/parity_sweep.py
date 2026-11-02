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
from pathlib import Path

import pefile

import peoxide

DIRECTORIES = [
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
]


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


def differences(ours, reference):
    """Names of the summary parts where a peoxide.PE and a pefile.PE disagree."""
    theirs_summary = summarize(reference)
    capped = any("Assuming corrupt" in w for w in reference.get_warnings())
    ours_summary = summarize(ours, len(theirs_summary["exports"]) if capped else None)
    return [key for key in ours_summary if ours_summary[key] != theirs_summary[key]]


def main(folder):
    files = sorted(p for p in Path(folder).iterdir() if p.suffix.lower() in {".dll", ".exe"})
    outcomes = Counter()
    examples = {}
    for path in files:
        try:
            reference = pefile.PE(str(path), fast_load=True)
            reference.parse_data_directories(directories=DIRECTORIES)
        except Exception:
            outcomes["skipped (pefile failed)"] += 1
            continue
        try:
            ours = peoxide.PE(str(path))
        except peoxide.PEFormatError as error:
            outcomes["peoxide failed"] += 1
            examples.setdefault("peoxide failed", []).append(f"{path.name}: {error}")
            continue
        differing = differences(ours, reference)
        outcomes["mismatch" if differing else "match"] += 1
        for key in differing:
            examples.setdefault(f"{key} differs", []).append(path.name)

    print(f"{len(files)} files: {dict(outcomes)}")
    for kind, names in examples.items():
        print(f"  {kind} ({len(names)}): {names[:5]}")
    return 0 if set(outcomes) <= {"match", "skipped (pefile failed)"} else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
