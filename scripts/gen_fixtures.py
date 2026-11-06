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

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_DEBUG, DIR_DELAY = 0, 1, 2, 6, 13
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


def delay_imports(section, dll, names):
    """One 64-bit delay-load descriptor with RVA-based (attributes 1) tables."""
    hints = [section.put(b"\0\0" + name + b"\0", 2) for name in names]
    table = b"".join(struct.pack("<Q", rva) for rva in hints + [0])
    names_table, iat = section.put(table, 8), section.put(table, 8)
    name = section.put(dll + b"\0", 1)
    descriptor = struct.pack("<8I", 1, name, 0, iat, names_table, 0, 0, 0) + bytes(32)
    return section.put(descriptor), len(descriptor)


def exports(section, dll, functions, named):
    """Ordinals start at 1. Functions left out of `named` are exported by ordinal only."""
    eat = section.put(b"".join(struct.pack("<I", rva) for rva in functions))
    name_rvas = [section.put(name + b"\0", 1) for name, _ in named]
    names = section.put(b"".join(struct.pack("<I", rva) for rva in name_rvas))
    ordinals = section.put(b"".join(struct.pack("<H", index) for _, index in named))
    dll_name = section.put(dll + b"\0", 1)
    directory = struct.pack(
        "<2I2H7I", 0, 0, 0, 0, dll_name, 1, len(functions), len(named), eat, names, ordinals
    )
    return section.put(directory), len(directory)


def debug(section, pdb):
    record = b"RSDS" + bytes(range(16)) + struct.pack("<I", 1) + pdb + b"\0"
    rva = section.put(record)
    entry = struct.pack("<2I2H4I", 0, 0, 0, 0, CODEVIEW, len(record), rva, section.offset(rva))
    return section.put(entry), len(entry)


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
    return {
        "sample64.dll": build(AMD64, True, 0x2022, GUI, dll),
        "sample32.exe": build(I386, False, 0x0102, CUI, exe),
        "driver.sys": build(AMD64, True, 0x0022, NATIVE, driver),
        **{f"crafted/{name}": data for name, data in crafted().items()},
    }


def crafted():
    """Malformed files the parser must get through without panicking. Not compared with pefile."""
    ntdll = [(b"ntdll.dll", [b"RtlFreeHeap"])]

    def resource_root(root):
        return [
            (b".text", CODE, code),
            (b".rsrc", DATA, lambda s: {DIR_RESOURCE: (s.put(root), len(root))}),
        ]

    huge_count = resource_root(struct.pack("<2I4H", 0, 0, 0, 0, 0xFFFF, 0xFFFF))
    self_reference = resource_root(struct.pack("<2I4H2I", 0, 0, 0, 0, 0, 1, RT_VERSION, 0x80000000))
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
    return {
        # The resource root claims 131,070 entries in a 16-byte directory.
        "huge_count.dll": build(AMD64, True, 0x2022, GUI, huge_count),
        # The resource root's only entry is the root itself.
        "self_reference.dll": build(AMD64, True, 0x2022, GUI, self_reference),
        # Import addresses (ImageBase + RVA) run past 2**64 and past 2**63.
        "top_image_base.dll": build(AMD64, True, 0x2022, GUI, import_tables, 0xFFFFFFFFFFFFF000),
        "signed_image_base.dll": build(AMD64, True, 0x2022, GUI, import_tables, 0x7FFFFFFFFFFFF000),
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in fixtures().items():
        (OUT / name).parent.mkdir(exist_ok=True)
        (OUT / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
