"""Generate the synthetic PE files in tests/fixtures/.

They let the Rust tests run without Windows system files. tests/test_parity.py checks
them against pefile, and tests/test_fixtures.py fails if they drift from this script.

Usage: python scripts/gen_fixtures.py
"""

import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
HEADERS_SIZE = 0x400
E_LFANEW = 0x40
TEXT_RVA = SECTION_ALIGN

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_RELOC, DIR_DEBUG, DIR_DELAY = 0, 1, 2, 5, 6, 13
CODE = 0x60000020
DATA = 0x40000040
AMD64, I386 = 0x8664, 0x14C
NATIVE, GUI, CUI = 1, 2, 3
RT_VERSION = 16
CODEVIEW = 2


def align(value, to):
    return -(-value // to) * to


class Section:
    def __init__(self, name, characteristics, rva, raw):
        self.name, self.characteristics, self.rva, self.raw = name, characteristics, rva, raw
        self.data = bytearray()

    def put(self, blob, alignment=4):
        self.data += bytes(-len(self.data) % alignment)
        rva = self.rva + len(self.data)
        self.data += blob
        return rva

    def offset(self, rva):
        return self.raw + rva - self.rva

    def header(self):
        return struct.pack(
            "<8s6I2HI",
            self.name,
            len(self.data),
            self.rva,
            align(len(self.data), FILE_ALIGN),
            self.raw,
            0,
            0,
            0,
            0,
            self.characteristics,
        )


def code(section):
    section.put(b"\xc3" * 0x40)
    return {}


def imports(section, wide, dlls):
    thunk = "<Q" if wide else "<I"
    descriptors = b""
    for dll, names in dlls:
        hints = [section.put(b"\0\0" + name + b"\0", 2) for name in names]
        table = b"".join(struct.pack(thunk, rva) for rva in hints + [0])
        ilt, iat = section.put(table, 8), section.put(table, 8)
        descriptors += struct.pack("<5I", ilt, 0, 0, section.put(dll + b"\0", 1), iat)
    descriptors += bytes(20)
    return section.put(descriptors), len(descriptors)


def shared_imports(section, dll, names, count):
    """`count` 64-bit import descriptors that all share one pair of thunk tables."""
    hints = [section.put(b"\0\0" + name + b"\0", 2) for name in names]
    table = b"".join(struct.pack("<Q", rva) for rva in hints + [0])
    ilt, iat = section.put(table, 8), section.put(table, 8)
    descriptor = struct.pack("<5I", ilt, 0, 0, section.put(dll + b"\0", 1), iat)
    descriptors = descriptor * count + bytes(20)
    return section.put(descriptors), len(descriptors)


def delay_imports(section, dll, names, count=1):
    """`count` 64-bit delay-load descriptors with RVA-based (attributes 1) tables, all
    sharing one pair of thunk tables."""
    hints = [section.put(b"\0\0" + name + b"\0", 2) for name in names]
    table = b"".join(struct.pack("<Q", rva) for rva in hints + [0])
    names_table, iat = section.put(table, 8), section.put(table, 8)
    name = section.put(dll + b"\0", 1)
    descriptor = struct.pack("<8I", 1, name, 0, iat, names_table, 0, 0, 0)
    descriptors = descriptor * count + bytes(32)
    return section.put(descriptors), len(descriptors)


def exports(section, dll, functions, named, base=1):
    """Ordinals start at `base`. Functions left out of `named` are exported by ordinal only."""
    eat = section.put(b"".join(struct.pack("<I", rva) for rva in functions))
    name_rvas = [section.put(name + b"\0", 1) for name, _ in named]
    names = section.put(b"".join(struct.pack("<I", rva) for rva in name_rvas))
    ordinals = section.put(b"".join(struct.pack("<H", index) for _, index in named))
    dll_name = section.put(dll + b"\0", 1)
    directory = struct.pack(
        "<2I2H7I", 0, 0, 0, 0, dll_name, base, len(functions), len(named), eat, names, ordinals
    )
    return section.put(directory), len(directory)


def debug(section, pdb):
    record = b"RSDS" + bytes(range(16)) + struct.pack("<I", 1) + pdb + b"\0"
    rva = section.put(record)
    entry = struct.pack("<2I2H4I", 0, 0, 0, 0, CODEVIEW, len(record), rva, section.offset(rva))
    return section.put(entry), len(entry)


def shared_debug(section, count, record_size):
    """`count` CodeView entries that all point at one RSDS record of `record_size` bytes."""
    record = b"RSDS" + bytes(20) + b"p" * (record_size - 24)
    rva = section.put(record)
    entry = struct.pack("<2I2H4I", 0, 0, 0, 0, CODEVIEW, record_size, rva, section.offset(rva))
    return section.put(entry * count), len(entry) * count


def version_block(key, value=b"", children=(), text=False, value_length=None):
    """A VS_VERSIONINFO-style node. wLength covers the children but not trailing padding."""
    length = len(value) if value_length is None else value_length
    out = struct.pack("<3H", 0, length, int(text)) + key.encode("utf-16-le") + b"\0\0"
    out += bytes(-len(out) % 4) + value
    for child in children:
        out += bytes(-len(out) % 4) + child
    return struct.pack("<H", len(out)) + out[2:]


def version_info():
    fixed = struct.pack(
        "<13I", 0xFEEF04BD, 0x10000, 0x10000, 0, 0x10000, 0, 0x3F, 0, 0x40004, 2, 0, 0, 0
    )
    company = "peoxide".encode("utf-16-le") + b"\0\0"
    string = version_block("CompanyName", company, text=True, value_length=len(company) // 2)
    table = version_block("040904B0", children=[string], text=True)
    strings = version_block("StringFileInfo", children=[table], text=True)
    translation = version_block("Translation", struct.pack("<2H", 0x0409, 0x04B0))
    variables = version_block("VarFileInfo", children=[translation], text=True)
    return version_block("VS_VERSION_INFO", fixed, [strings, variables])


def resources(section):
    """One RT_VERSION resource: type, name and language levels, then the data entry."""

    def directory(entry_id, target):
        return struct.pack("<2I4H2I", 0, 0, 0, 0, 0, 1, entry_id, target)

    subdirectory = 0x80000000
    tree = directory(RT_VERSION, subdirectory | 24)
    tree += directory(1, subdirectory | 48)
    tree += directory(0x409, 72)
    data = version_info()
    tree += struct.pack("<4I", section.rva + len(tree) + 16, len(data), 0, 0)
    return section.put(tree + data), len(tree) + len(data)


def build(machine, wide, characteristics, subsystem, layout, image_base=None):
    if image_base is None:
        image_base = 0x180000000 if wide else 0x400000
    sections, directories = [], {}
    raw, rva = HEADERS_SIZE, SECTION_ALIGN
    for name, flags, fill in layout:
        section = Section(name, flags, rva, raw)
        directories.update(fill(section))
        sections.append(section)
        raw += align(len(section.data), FILE_ALIGN)
        rva += align(len(section.data), SECTION_ALIGN)

    code_size = align(len(sections[0].data), FILE_ALIGN)
    data_size = sum(align(len(s.data), FILE_ALIGN) for s in sections[1:])
    head = [code_size, data_size, 0, TEXT_RVA, TEXT_RVA]
    tail = [6, 0, 0, 0, 6, 0, 0, rva, HEADERS_SIZE, 0, subsystem, 0x160 if wide else 0x140]
    reserve = [0x100000, 0x1000, 0x100000, 0x1000, 0, 16]
    if wide:
        optional = struct.pack(
            "<HBB5IQ2I6H4I2H4Q2I",
            *[0x20B, 14, 0, *head, image_base, SECTION_ALIGN, FILE_ALIGN, *tail, *reserve],
        )
    else:
        optional = struct.pack(
            "<HBB5I4I6H4I2H6I",
            *[0x10B, 14, 0, *head, sections[1].rva, image_base, SECTION_ALIGN, FILE_ALIGN],
            *[*tail, *reserve],
        )
    optional += b"".join(struct.pack("<2I", *directories.get(i, (0, 0))) for i in range(16))

    coff = struct.pack("<2H3I2H", machine, len(sections), 0, 0, 0, len(optional), characteristics)
    headers = b"MZ" + bytes(E_LFANEW - 6) + struct.pack("<I", E_LFANEW) + b"PE\0\0" + coff
    headers += optional + b"".join(s.header() for s in sections)
    out = headers.ljust(HEADERS_SIZE, b"\0")
    for section in sections:
        out += bytes(section.data).ljust(align(len(section.data), FILE_ALIGN), b"\0")
    return out


def header_imports(image):
    """Moves a 64-bit image's import table into its headers, below SizeOfHeaders."""
    rva = 0x300
    section = Section(b"", 0, rva, rva)
    directory = imports(section, True, [(b"KERNEL32.dll", [b"ExitProcess"])])
    out = bytearray(image)
    out[rva : rva + len(section.data)] = section.data
    struct.pack_into("<2I", out, E_LFANEW + 24 + 112 + 8 * DIR_IMPORT, *directory)
    return bytes(out)


def fixtures():
    dll = [
        (b".text", CODE, code),
        (
            b".rdata",
            DATA,
            lambda s: {
                DIR_IMPORT: imports(s, True, [(b"ntdll.dll", [b"RtlAllocateHeap", b"RtlFreeHeap"])]),
                DIR_EXPORT: exports(
                    s,
                    b"sample64.dll",
                    [TEXT_RVA, TEXT_RVA + 4, TEXT_RVA + 8],
                    [(b"Alpha", 0), (b"Gamma", 2)],
                ),
                DIR_DEBUG: debug(s, b"sample64.pdb"),
            },
        ),
        (b".rsrc", DATA, lambda s: {DIR_RESOURCE: resources(s)}),
    ]
    exe = [
        (b".text", CODE, code),
        (b".rdata", DATA, lambda s: {DIR_IMPORT: imports(s, False, [(b"KERNEL32.dll", [b"ExitProcess"])])}),
    ]
    driver = [
        (b".text", CODE, code),
        (b".rdata", DATA, lambda s: {DIR_IMPORT: imports(s, True, [(b"ntoskrnl.exe", [b"IoCreateDevice"])])}),
    ]
    # The second export's ordinal, OrdinalBase + 1, needs 33 bits.
    high_ordinal_base = [
        (b".text", CODE, code),
        (
            b".rdata",
            DATA,
            lambda s: {
                DIR_EXPORT: exports(
                    s, b"high_ordinal_base.dll", [TEXT_RVA, TEXT_RVA + 4], [(b"Alpha", 0)], 0xFFFFFFFF
                )
            },
        ),
    ]
    return {
        "sample64.dll": build(AMD64, True, 0x2022, GUI, dll),
        "high_ordinal_base.dll": build(AMD64, True, 0x2022, GUI, high_ordinal_base),
        "sample32.exe": build(I386, False, 0x0102, CUI, exe),
        "driver.sys": build(AMD64, True, 0x0022, NATIVE, driver),
        "header_imports.exe": header_imports(build(AMD64, True, 0x0022, CUI, [(b".text", CODE, code)])),
        **{f"crafted/{name}": data for name, data in crafted().items()},
    }


def crafted():
    """Malformed files the parser must get through without panicking. Not compared field by
    field with pefile."""
    ntdll = [(b"ntdll.dll", [b"RtlFreeHeap"])]

    def resource_root(root):
        return [
            (b".text", CODE, code),
            (b".rsrc", DATA, lambda s: {DIR_RESOURCE: (s.put(root), len(root))}),
        ]

    huge_count = resource_root(struct.pack("<2I4H", 0, 0, 0, 0, 0xFFFF, 0xFFFF))
    self_reference = resource_root(struct.pack("<2I4H2I", 0, 0, 0, 0, 0, 1, RT_VERSION, 0x80000000))
    leaf = 16 + 8 * 40
    long_name = struct.pack("<2I4H", 0, 0, 0, 0, 40, 0) + struct.pack("<2I", 0x80000000 | leaf + 16, leaf) * 40
    long_name += struct.pack("<4IH", 0x2000, 4, 0, 0, 0xFFFF) + b"A\0" * 0xFFFF
    shared_resource_names = resource_root(long_name)
    reloc_block = struct.pack("<2I2H", TEXT_RVA, 12, 0xA000, 0)
    long_relocations = [
        (b".text", CODE, code),
        (b".reloc", DATA, lambda s: {DIR_RELOC: (s.put(reloc_block), 0x10000000)}),
    ]
    import_tables = [
        (b".text", CODE, code),
        (
            b".rdata",
            DATA,
            lambda s: {
                DIR_IMPORT: imports(s, True, ntdll),
                DIR_DELAY: delay_imports(s, b"user32.dll", [b"MessageBoxW"]),
            },
        ),
    ]
    # Each descriptor reads 2 x 1,001 thunks, so pefile's 0x2000 cap falls partway through
    # the fifth descriptor's lookup table.
    shared_names = [b"F%03X" % i for i in range(1000)]
    shared_thunks = [
        (b".text", CODE, code),
        (b".rdata", DATA, lambda s: {DIR_IMPORT: shared_imports(s, b"shared.dll", shared_names, 2048)}),
    ]
    shared_delay_thunks = [
        (b".text", CODE, code),
        (
            b".rdata",
            DATA,
            lambda s: {
                DIR_IMPORT: imports(s, True, ntdll),
                DIR_DELAY: delay_imports(s, b"shared.dll", shared_names, 16),
            },
        ),
    ]

    def overlapping_version(section, languages=64):
        subdirectory = 0x80000000
        tree = struct.pack("<2I4H2I", 0, 0, 0, 0, 0, 1, RT_VERSION, subdirectory | 24)
        tree += struct.pack("<2I4H2I", 0, 0, 0, 0, 0, 1, 1, subdirectory | 48)
        tree += struct.pack("<2I4H", 0, 0, 0, 0, 0, languages)
        leaf = len(tree) + 8 * languages
        tree += b"".join(struct.pack("<2I", 0x409 + i, leaf) for i in range(languages))
        fixed = struct.pack("<13I", 0xFEEF04BD, *[0] * 12)
        blob = struct.pack("<3H", 0x1000, len(fixed), 0) + "VS_VERSION_INFO\0".encode("utf-16-le")
        blob += bytes(-len(blob) % 4) + fixed + b"\x01\x00" * 0x800
        tree += struct.pack("<4I", section.rva + leaf + 16, len(blob), 0, 0)
        return {DIR_RESOURCE: (section.put(tree + blob), len(tree) + len(blob))}

    return {
        # 2,048 import descriptors share one table of 1,000 imports.
        "shared_thunks.dll": build(AMD64, True, 0x2022, GUI, shared_thunks),
        # Imports stay under the cap, and 16 delay-import descriptors sharing one table cross it.
        "shared_delay_thunks.dll": build(AMD64, True, 0x2022, GUI, shared_delay_thunks),
        # 300 debug entries share one CodeView record with a 4,072-byte PDB name.
        "shared_codeview.dll": build(
            AMD64, True, 0x2022, GUI, [(b".rdata", DATA, lambda s: {DIR_DEBUG: shared_debug(s, 300, 4096)})]
        ),
        # The resource root claims 131,070 entries in a 16-byte directory.
        "huge_count.dll": build(AMD64, True, 0x2022, GUI, huge_count),
        # The resource root's only entry is the root itself.
        "self_reference.dll": build(AMD64, True, 0x2022, GUI, self_reference),
        # 40 named resource entries share one 65,535-unit name: 5 MiB of names if all kept.
        "shared_resource_names.dll": build(AMD64, True, 0x2022, GUI, shared_resource_names),
        # Import addresses (ImageBase + RVA) run past 2**64 and past 2**63.
        "top_image_base.dll": build(AMD64, True, 0x2022, GUI, import_tables, 0xFFFFFFFFFFFFF000),
        "signed_image_base.dll": build(AMD64, True, 0x2022, GUI, import_tables, 0x7FFFFFFFFFFFF000),
        # The base-relocation directory claims 256 MiB in a 2 KiB file.
        "long_relocations.dll": build(AMD64, True, 0x2022, GUI, long_relocations),
        # 64 languages share one RT_VERSION leaf whose FileInfo walk finds a block every 4 bytes,
        # each key running on through 4 KiB of 0x0001 units: about 64 MiB of keys if all kept.
        "overlapping_version.dll": build(
            AMD64, True, 0x2022, GUI, [(b".text", CODE, code), (b".rsrc", DATA, overlapping_version)]
        ),
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in fixtures().items():
        (OUT / name).parent.mkdir(exist_ok=True)
        (OUT / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
