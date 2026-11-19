"""peoxide.pyi lists every attribute of the classes reachable from PE.

mypy.stubtest checks PE and PEFormatError. The other classes are not importable, so it skips
the stub's private `_Name` classes; this test checks those against live objects instead.
"""

import ast
import os
from pathlib import Path

import peoxide

STUB = Path(__file__).parent.parent / "peoxide.pyi"
WINDIR = Path(os.environ.get("WINDIR", r"C:\Windows"))
FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = [
    WINDIR / "System32" / "kernel32.dll",
    WINDIR / "System32" / "user32.dll",
    FIXTURES / "sample64.dll",
    FIXTURES / "sample32.exe",
]


def stub_attributes():
    """`{class name without the underscore: names}` for the stub's private classes."""
    classes = {}
    for node in ast.parse(STUB.read_text()).body:
        if isinstance(node, ast.ClassDef) and node.name.startswith("_"):
            classes[node.name[1:]] = {
                (item.target.id if isinstance(item, ast.AnnAssign) else item.name)
                for item in node.body
                if isinstance(item, (ast.AnnAssign, ast.FunctionDef))
            }
    return classes


def runtime_classes():
    """`{class name: (class, public attribute names)}` for every peoxide object reachable from
    PE."""
    found, seen = {}, set()

    def walk(obj):
        if id(obj) in seen:
            return
        seen.add(id(obj))
        if isinstance(obj, list):
            for item in obj:
                walk(item)
            return
        if type(obj).__module__ != "peoxide":
            return
        _, names = found.setdefault(type(obj).__name__, (type(obj), set()))
        for name in dir(obj):
            if name.startswith("__"):
                continue
            # Some attributes exist on only some instances, such as a resource entry's
            # `directory` or `data`; count them wherever they appear.
            try:
                value = getattr(obj, name)
            except AttributeError:
                continue
            names.add(name)
            walk(value)

    # Held until the walk ends, so a freed object's id cannot be reused and look already seen.
    pes = [peoxide.PE(str(path)) for path in SAMPLES if path.exists()]
    for pe in pes:
        walk(pe)
    found.pop("PE", None)
    return found


def test_private_stub_classes_match_runtime():
    stub, runtime = stub_attributes(), runtime_classes()
    assert set(stub) == set(runtime)
    for name, (cls, names) in runtime.items():
        assert names <= stub[name], f"attributes missing from _{name}"
        # Attributes no sample produced must still be defined on the class.
        extra = {attr for attr in stub[name] - names if not hasattr(cls, attr)}
        assert not extra, f"_{name} lists names peoxide does not define"
