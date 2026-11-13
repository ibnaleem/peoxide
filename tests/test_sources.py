"""Every way of handing a file to `PE()` gives the same result."""

import mmap
import threading
from pathlib import Path

import pytest

import peoxide

FIXTURE = Path(__file__).parent / "fixtures" / "sample64.dll"
DATA = FIXTURE.read_bytes()


def fingerprint(pe):
    return (
        pe.OPTIONAL_HEADER.ImageBase,
        [s.Name for s in pe.sections],
        [(d.dll, [i.name for i in d.imports]) for d in pe.DIRECTORY_ENTRY_IMPORT],
        pe.get_data(pe.sections[0].VirtualAddress, 64),
    )


@pytest.mark.parametrize("wrap", [bytearray, memoryview, lambda d: memoryview(bytearray(d))])
def test_bytes_like_data_parses_like_bytes(wrap):
    assert fingerprint(peoxide.PE(data=wrap(DATA))) == fingerprint(peoxide.PE(data=DATA))


def test_mmap_data_parses_like_bytes():
    with FIXTURE.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        assert fingerprint(peoxide.PE(data=mapped)) == fingerprint(peoxide.PE(data=DATA))


def test_path_parses_like_bytes():
    assert fingerprint(peoxide.PE(str(FIXTURE))) == fingerprint(peoxide.PE(data=DATA))


def test_changing_a_bytearray_afterwards_does_not_change_the_pe():
    source = bytearray(DATA)
    pe = peoxide.PE(data=source)
    before = fingerprint(pe)
    source[:] = b"\x00" * len(source)
    assert fingerprint(pe) == before


@pytest.mark.parametrize("data", ["MZ", 5, [77, 90], None.__class__])
def test_data_that_is_not_bytes_like_raises_type_error(data):
    with pytest.raises(TypeError):
        peoxide.PE(data=data)


def test_parsing_on_many_threads_gives_the_same_result():
    expected = fingerprint(peoxide.PE(data=DATA))
    results = []

    def work():
        results.extend(fingerprint(peoxide.PE(data=DATA)) for _ in range(50))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [expected] * 400
