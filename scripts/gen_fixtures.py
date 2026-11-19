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

DIR_LOAD_CONFIG = 10
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_RELOC, DIR_DEBUG, DIR_TLS, DIR_BOUND, DIR_DELAY = (
    0, 1, 2, 3, 5, 6, 9, 11, 13,
)
# Linkers put bound imports in the headers, after the section table.
BOUND_OFFSET = 0x300
CODE = 0x60000020
DATA = 0x40000040
AMD64, I386 = 0x8664, 0x14C
IMAGE_BASE_64, IMAGE_BASE_32 = 0x180000000, 0x400000
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


# Byte offsets in IMAGE_LOAD_CONFIG_DIRECTORY (PE32, PE32+): DynamicValueRelocTableOffset,
# then the full structure's size.
LOAD_CONFIG_LAYOUT = {False: (136, 192), True: (224, 320)}


def load_config(section, wide, table, table_section, size=None):
    """A load config structure whose fields hold distinct bytes, pointing at `table` (a
    dynamic relocation table) in the section numbered `table_section`. `size` overrides the
    structure's Size field."""
    # Offset 0 would mean no table.
    section.put(bytes(16))
    table_rva = section.put(table)
    dynamic_offset, full = LOAD_CONFIG_LAYOUT[wide]
    config = bytearray((i * 7 + 1) & 0xFF for i in range(full))
    struct.pack_into("<I", config, 0, full if size is None else size)
    struct.pack_into("<IH", config, dynamic_offset, table_rva - section.rva, table_section)
    return section.put(bytes(config)), full


def dynamic_relocations(wide, entries, size=None):
    """A version-1 IMAGE_DYNAMIC_RELOCATION_TABLE. Each entry is (symbol, payload) or
    (symbol, payload, declared BaseRelocSize)."""
    header = "<QI" if wide else "<2I"
    body = b""
    for symbol, payload, *declared in entries:
        body += struct.pack(header, symbol, declared[0] if declared else len(payload)) + payload
    return struct.pack("<2I", 1, len(body) if size is None else size) + body


def relocation_block(rva, words, word="H"):
    data = b"".join(struct.pack("<" + word, w) for w in words)
    return struct.pack("<2I", rva, 8 + len(data)) + data


def function_override(functions, bdd_entries):
    """Symbol 7's payload: (original RVA, override RVAs, relocation block) functions, then
    (Left, Right, Value) BDD entries."""
    body = b""
    for original, overrides, block in functions:
        rvas = b"".join(struct.pack("<I", rva) for rva in overrides)
        body += struct.pack("<4I", original, 0x10, len(rvas), len(block)) + rvas + block
    bdd = b"".join(struct.pack("<2HI", *entry) for entry in bdd_entries)
    return struct.pack("<I", len(body)) + body + struct.pack("<2I", 1, len(bdd)) + bdd


def every_dynamic_relocation(wide):
    """Each kind pefile parses, plus a skipped symbol 1. Symbol 5's third entry repeats the
    first's page offset, which is where pefile stops reading that block."""
    entries = [
        (1, relocation_block(TEXT_RVA, [0xA010])),
        (3, relocation_block(TEXT_RVA, [0x10 | 1 << 12 | 5 << 13, 0x20 | 7 << 13], "I")),
        (4, relocation_block(TEXT_RVA, [0x30 | 1 << 12 | 1 << 14, 0x40 | 1 << 13 | 1 << 15])),
        (5, relocation_block(TEXT_RVA, [0x50 | 3 << 12, 0x60, 0x50 | 9 << 12])),
        (6, relocation_block(TEXT_RVA, [0xA010, 0xA018])),
        (
            7,
            function_override(
                [(TEXT_RVA, [TEXT_RVA + 4, TEXT_RVA + 8], relocation_block(TEXT_RVA, [0xA020]))],
                [(1, 2, 3), (4, 5, 6)],
            ),
        ),
    ]
    big_symbol = 0xFFFFF78000000000 if wide else 0x80000000
    return dynamic_relocations(wide, entries + [(big_symbol, relocation_block(TEXT_RVA, [0xA028]))])


def overlapping_function_overrides(count, rva_size):
    """`count` symbol-7 entries 32 bytes apart. Each one's override RVA list runs `rva_size`
    bytes on through the entries after it, so reading them all costs count * rva_size / 4."""
    payload = struct.pack("<5I", 16, TEXT_RVA, 0, rva_size, 0)
    table = dynamic_relocations(True, [(7, payload)] * count)
    return table + bytes(rva_size + 16)
def bound_imports(descriptors):
    """IMAGE_BOUND_IMPORT_DESCRIPTORs, each followed by its IMAGE_BOUND_FORWARDER_REFs, then a
    zero terminator and the module names. A descriptor is (stamp, name, refs), or
    (stamp, name, refs, count) to claim a different NumberOfModuleForwarderRefs. A ref is
    (stamp, name). A name given as an int is written as OffsetModuleName unchanged."""
    names_start = 8 * (sum(1 + len(d[2]) for d in descriptors) + 1)
    names, offsets = b"", {}

    def offset(name):
        nonlocal names
        if isinstance(name, int):
            return name
        if name not in offsets:
            offsets[name] = names_start + len(names)
            names += name + b"\0"
        return offsets[name]

    table = b""
    for stamp, name, refs, *count in descriptors:
        table += struct.pack("<I2H", stamp, offset(name), count[0] if count else len(refs))
        table += b"".join(struct.pack("<I2H", s, offset(n), 0) for s, n in refs)
    return table + bytes(8) + names


VALID_BOUND = [
    (0x5F000001, b"KERNEL32.dll", [(0x5F000002, b"NTDLL.DLL"), (0x5F000003, b"KERNELBASE.dll")]),
    (0x5F000004, b"USER32.dll", []),
]
def tls(section, wide, image_base):
    """A TLS directory with a 16-byte template and a one-callback list. Its addresses are VAs."""
    pointer = "Q" if wide else "I"
    template = section.put(bytes(range(0x10)))
    index = section.put(bytes(4))
    callbacks = section.put(struct.pack(f"<2{pointer}", image_base + TEXT_RVA, 0), 8)
    addresses = [template, template + 0x10, index, callbacks]
    directory = struct.pack(f"<4{pointer}2I", *(image_base + a for a in addresses), 0x20, 0x00300000)
    return section.put(directory, 8), len(directory)
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


UWOP_PUSH_NONVOL, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL, UWOP_SET_FPREG = 0, 1, 2, 3
UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR, UWOP_EPILOG = 4, 5, 6
UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR, UWOP_PUSH_MACHFRAME = 8, 9, 10
UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UNW_FLAG_CHAININFO = 1, 2, 4
RBX, RBP, RSI, R12 = 3, 5, 6, 12


def slot(first, op, info, operand=b""):
    """One unwind code: the first byte, the op and info nibbles, then any extra slots."""
    return bytes([first, op | info << 4]) + operand


def unwind_info(version, flags, codes, frame=0, trailer=b""):
    """An UNWIND_INFO record. `codes` is the slot bytes, padded here to an even count."""
    header = bytes([version | flags << 3, 0x10, len(codes) // 2, frame])
    return header + codes + bytes(len(codes) % 4) + trailer


def runtime_functions(section, functions):
    """The RUNTIME_FUNCTION table for `(begin, end, unwind_data)` triples."""
    table = b"".join(struct.pack("<3I", *f) for f in functions)
    return section.put(table), len(table)


def exceptions(section):
    """One record per unwind code layout pefile reads, plus shared, chained and bit-0 entries."""
    t = TEXT_RVA
    handler = struct.pack("<I", t + 0x3C)
    put = lambda *args, **kwargs: section.put(unwind_info(*args, **kwargs))
    shared = put(
        1,
        UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER,
        slot(8, UWOP_ALLOC_LARGE, 0, struct.pack("<H", 0x1A))
        + slot(4, UWOP_ALLOC_SMALL, 3)
        + slot(1, UWOP_PUSH_NONVOL, RBP),
        trailer=handler,
    )
    frame = put(
        1,
        0,
        slot(9, UWOP_SET_FPREG, 0)
        + slot(5, UWOP_ALLOC_LARGE, 1, struct.pack("<I", 0x12345))
        + slot(0, UWOP_PUSH_MACHFRAME, 0),
        frame=RBP | 3 << 4,
    )
    saves = put(
        1,
        0,
        slot(12, UWOP_SAVE_NONVOL, RBX, struct.pack("<H", 0x30))
        + slot(10, UWOP_SAVE_NONVOL_FAR, R12, struct.pack("<I", 0x10008))
        + slot(6, UWOP_SAVE_XMM128, 6, struct.pack("<H", 2))
        + slot(0, UWOP_PUSH_MACHFRAME, 1),
    )
    # Flag 0x08 is undefined: it reserves the trailing DWORD, but pefile names no field for it.
    far_xmm = put(
        1,
        0x08,
        slot(7, UWOP_SAVE_XMM128_FAR, 15, struct.pack("<I", 0x20010)) + slot(2, UWOP_ALLOC_SMALL, 0),
        trailer=handler,
    )
    # The first epilog has an odd OpInfo, so its one slot holds the size and offset. The zero
    # slot ends the epilog list, which pefile marks invalid.
    short_epilogs = put(
        2,
        0,
        slot(5, UWOP_EPILOG, 1)
        + slot(0x20, UWOP_EPILOG, 3)
        + slot(0, UWOP_EPILOG, 0)
        + slot(1, UWOP_PUSH_NONVOL, RSI),
    )
    long_epilog = put(2, 0, slot(7, UWOP_EPILOG, 0) + bytes([0x34, 0x20]))
    parent = put(1, 0, slot(1, UWOP_PUSH_NONVOL, RBX))
    chained = put(1, UNW_FLAG_CHAININFO, b"", trailer=struct.pack("<3I", t + 0x20, t + 0x24, parent))
    orphan = put(1, UNW_FLAG_CHAININFO, b"", trailer=struct.pack("<3I", t + 0x3F, t + 0x40, parent))
    functions = [
        (t, t + 4, shared),
        (t + 4, t + 8, shared),
        (t + 8, t + 0xC, frame),
        (t + 0xC, t + 0x10, saves),
        (t + 0x10, t + 0x14, far_xmm),
        (t + 0x14, t + 0x18, short_epilogs),
        (t + 0x18, t + 0x1C, long_epilog),
        (t + 0x20, t + 0x24, parent),
        (t + 0x24, t + 0x28, chained),
        (t + 0x28, t + 0x2C, orphan),
        # Bit 0 set: pefile reads no unwind information.
        (t + 0x2C, t + 0x30, (t + 0x20) | 1),
    ]
    return {DIR_EXCEPTION: runtime_functions(section, functions)}


def crafted_exceptions(section):
    """A 255-code record, a self-chained entry, a two-entry chain cycle and a record cut off by
    the end of the section, under a directory that claims 256 MiB."""
    t = TEXT_RVA
    put = lambda *args, **kwargs: section.put(unwind_info(*args, **kwargs))
    chain = lambda begin: put(1, UNW_FLAG_CHAININFO, b"", trailer=struct.pack("<3I", begin, begin + 4, 0))
    huge = put(1, 0, b"".join(slot(i, UWOP_ALLOC_SMALL, i % 16) for i in range(255)))
    self_chain, cycle_a, cycle_b = chain(t + 4), chain(t + 0xC), chain(t + 8)
    # The truncated record's header is the section's last 4 bytes; its codes would run past it.
    truncated = section.rva + align(len(section.data) + 0x100, FILE_ALIGN) - 4
    functions = [
        (t, t + 4, huge),
        (t + 4, t + 8, self_chain),
        (t + 8, t + 0xC, cycle_a),
        (t + 0xC, t + 0x10, cycle_b),
        (t + 0x10, t + 0x14, truncated),
    ]
    table, _ = runtime_functions(section, functions)
    section.data += bytes(truncated - section.rva - len(section.data))
    section.put(bytes([1, 0x10, 4, 0]))
    return {DIR_EXCEPTION: (table, 0x10000000)}


def build(machine, wide, characteristics, subsystem, layout, image_base=None, bound=None):
    """`bound` is a bound-import blob for the headers, or (blob, address) to point the
    directory somewhere else."""
    if image_base is None:
        image_base = IMAGE_BASE_64 if wide else IMAGE_BASE_32
    sections, directories = [], {}
    if isinstance(bound, bytes):
        bound = (bound, BOUND_OFFSET)
    if bound:
        directories[DIR_BOUND] = (bound[1], len(bound[0]))
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
    if bound:
        assert len(headers) <= BOUND_OFFSET
        headers = headers.ljust(BOUND_OFFSET, b"\0") + bound[0]
    out = headers.ljust(HEADERS_SIZE, b"\0")
    for section in sections:
        out += bytes(section.data).ljust(align(len(section.data), FILE_ALIGN), b"\0")
    return out


def bound_layout(wide):
    kernel32 = [(b"KERNEL32.dll", [b"ExitProcess"]), (b"USER32.dll", [b"MessageBoxW"])]
    return [(b".text", CODE, code), (b".rdata", DATA, lambda s: {DIR_IMPORT: imports(s, wide, kernel32)})]


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
                DIR_TLS: tls(s, True, IMAGE_BASE_64),
            },
        ),
        (b".rsrc", DATA, lambda s: {DIR_RESOURCE: resources(s)}),
    ]
    exe = [
        (b".text", CODE, code),
        (
            b".rdata",
            DATA,
            lambda s: {
                DIR_IMPORT: imports(s, False, [(b"KERNEL32.dll", [b"ExitProcess"])]),
                DIR_TLS: tls(s, False, IMAGE_BASE_32),
            },
        ),
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
    unwind = [(b".text", CODE, code), (b".pdata", DATA, exceptions)]
    return {
        "sample64.dll": build(AMD64, True, 0x2022, GUI, dll),
        "exceptions64.dll": build(AMD64, True, 0x2022, GUI, unwind),
        "high_ordinal_base.dll": build(AMD64, True, 0x2022, GUI, high_ordinal_base),
        "sample32.exe": build(I386, False, 0x0102, CUI, exe),
        "driver.sys": build(AMD64, True, 0x0022, NATIVE, driver),
        "load_config64.dll": build(AMD64, True, 0x2022, GUI, load_config_layout(True, every_dynamic_relocation(True))),
        "load_config32.dll": build(I386, False, 0x2102, GUI, load_config_layout(False, every_dynamic_relocation(False))),
        "bound_imports.dll": build(
            AMD64, True, 0x2022, GUI, bound_layout(True), bound=bound_imports(VALID_BOUND)
        ),
        "bound_imports32.exe": build(
            I386, False, 0x0102, CUI, bound_layout(False), bound=bound_imports(VALID_BOUND)
        ),
        **{f"crafted/{name}": data for name, data in crafted().items()},
    }


def load_config_layout(wide, table, table_section=2, size=None):
    """A load config in .rdata, the second section, whose dynamic relocation table is `table`."""
    return [
        (b".text", CODE, code),
        (b".rdata", DATA, lambda s: {DIR_LOAD_CONFIG: load_config(s, wide, table, table_section, size)}),
    ]


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
    block = relocation_block(TEXT_RVA, [0x10, 0x20])
    long_table = dynamic_relocations(
        True, [(4, block), (0, b""), (0, b""), (6, block, 0x7FFFFFF0)], size=0xFFFFFFF0
    )
    text_only = [(b".text", CODE, code)]
    huge_refs = [(0, b"KERNEL32.dll", [(1, b"NTDLL.DLL"), (2, b"KERNELBASE.dll")], 0xFFFF)]
    bad_names = [
        (1, b"KERNEL32.dll", [(2, b"NTDLL.DLL"), (3, b"bad\x01.dll"), (4, b"KERNELBASE.dll")]),
        (5, b"USER32\x7f.dll", []),
    ]
    name_outside = [(1, b"KERNEL32.dll", []), (2, 0xFFF0, [])]

    def bound_at_text_rva(section):
        """The descriptors at file offset 0x1000, which is also .text's RVA."""
        section.put(bytes(0x1000 - section.raw))
        blob = bound_imports(VALID_BOUND)
        return {DIR_BOUND: (section.offset(section.put(blob)), len(blob))}
    tls_size_zero = [
        (b".text", CODE, code),
        (b".rdata", DATA, lambda s: {DIR_TLS: (tls(s, True, IMAGE_BASE_64)[0], 0)}),
    ]
    # The directory RVA is the struct's file offset, which falls before the first section.
    tls_outside_sections = [
        (b".text", CODE, code),
        (b".rdata", DATA, lambda s: {DIR_TLS: (s.offset(tls(s, True, IMAGE_BASE_64)[0]), 40)}),
    ]

    bound_in_section = [(b".text", CODE, code), (b".data", DATA, bound_at_text_rva)]
    shared_name = bound_imports([(i + 1, b"a" * 252 + b".dll", []) for i in range(8000)])

    def bound_in_data(section):
        return {DIR_BOUND: (section.offset(section.put(shared_name)), len(shared_name))}

    bound_shared_names = [(b".text", CODE, code), (b".data", DATA, bound_in_data)]
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
        # Size 72 ends the load config after 13 of its 52 fields, before GuardFlags.
        "load_config_short_size.dll": build(
            AMD64, True, 0x2022, GUI, load_config_layout(True, every_dynamic_relocation(True), size=72)
        ),
        # Size 77 falls inside ProcessHeapFlags, so pefile reads all 320 bytes. The dynamic
        # relocation table's section number, 9, is past the two sections the file has.
        "load_config_odd_size.dll": build(
            AMD64, True, 0x2022, GUI, load_config_layout(True, every_dynamic_relocation(True), 9, 77)
        ),
        # The dynamic relocation table claims 4 GiB, and its last entry 2 GiB.
        "load_config_long_table.dll": build(AMD64, True, 0x2022, GUI, load_config_layout(True, long_table)),
        # 1,024 function overrides whose 32 KiB override lists overlap: 8 million RVAs in all.
        "load_config_overlap.dll": build(
            AMD64, True, 0x2022, GUI, load_config_layout(True, overlapping_function_overrides(1024, 0x8000))
        ),
        # NumberOfModuleForwarderRefs is 0xFFFF; the headers have room for 31 refs.
        "bound_huge_count.dll": build(AMD64, True, 0x2022, GUI, text_only, bound=bound_imports(huge_refs)),
        # A forwarder name and a module name hold bytes outside string.printable.
        "bound_bad_names.dll": build(AMD64, True, 0x2022, GUI, text_only, bound=bound_imports(bad_names)),
        # The second module name's offset points past the end of the file.
        "bound_name_outside.dll": build(
            AMD64, True, 0x2022, GUI, text_only, bound=bound_imports(name_outside)
        ),
        # The directory starts 4 bytes before the end of the file.
        "bound_truncated.dll": build(
            AMD64, True, 0x2022, GUI, text_only, bound=(bound_imports(VALID_BOUND), 0x5FC)
        ),
        # Read as an RVA, the directory address would land in .text.
        "bound_in_section.dll": build(AMD64, True, 0x2022, GUI, bound_in_section),
        # 8,000 descriptors share one 256-byte name: 2 MB of names from a 66 KB file.
        "bound_shared_names.dll": build(AMD64, True, 0x2022, GUI, bound_shared_names),
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
        "exceptions.dll": build(
            AMD64, True, 0x2022, GUI, [(b".text", CODE, code), (b".pdata", DATA, crafted_exceptions)]
        ),
        # pefile reads the TLS directory whatever its size, even zero.
        "tls_size_zero.dll": build(AMD64, True, 0x2022, GUI, tls_size_zero),
        # pefile reads an RVA outside every section as a file offset.
        "tls_outside_sections.dll": build(AMD64, True, 0x2022, GUI, tls_outside_sections),
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
