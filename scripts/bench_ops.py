"""Time single operations of peoxide against pefile, and measure memory and throughput.

Usage: python scripts/bench_ops.py [--json out.json] [--baseline old.json] [--folder DIR] [FILE ...]

`benchmark.py` times one whole parse-and-read pass over a folder. This script times each step
on its own, so a change can be tied to the operation it affects:

- init: building a PE object from bytes already in memory, and from a path.
- operations: one attribute read, walking sections, imports and exports, `get_data`, an RVA
  conversion, a section's entropy and the imphash, each on an already built PE object.
- memory: the Python heap one PE object holds (tracemalloc), and the growth of the process
  working set per PE object, which also counts memory allocated in Rust (Windows only).
- throughput: files and megabytes per second over a folder, on one thread and on several.

pefile is limited to the directories peoxide parses, as in `benchmark.py`. Every operation
returns a value, and the two libraries' values must be equal before anything is timed, so a
library cannot look fast by skipping the work. The libraries take turns inside each repeat,
garbage collection is off while timing, and the reported time is the median repeat.

`--baseline` adds a column comparing peoxide with an earlier `--json` run of this script.
"""

import argparse
import gc
import json
import os
import statistics
import subprocess
import sys
import time
import timeit
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script's folder

import pefile
from parity_sweep import DIRECTORIES

import peoxide

DEFAULT_FILES = [
    "C:/Windows/System32/kernel32.dll",
    "C:/Windows/System32/shell32.dll",
    "C:/Windows/System32/notepad.exe",
    "C:/Windows/SysWOW64/kernel32.dll",
]
DEFAULT_FOLDER = "C:/Windows/System32/wbem"
REPEATS = 7
HELD_OBJECTS = 50
THROUGHPUT_PASSES = {"peoxide": 40, "pefile": 1}


def pefile_scoped(**source):
    pe = pefile.PE(fast_load=True, **source)
    pe.parse_data_directories(directories=DIRECTORIES)
    return pe


def peoxide_scoped(**source):
    return peoxide.PE(**source)


LIBRARIES = {"peoxide": peoxide_scoped, "pefile": pefile_scoped}


def export_symbols(pe):
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    return directory.symbols if directory else []


OPERATIONS = {
    "read ImageBase": lambda pe: pe.OPTIONAL_HEADER.ImageBase,
    "walk sections": lambda pe: sum(s.VirtualAddress + s.SizeOfRawData for s in pe.sections),
    "walk imports": lambda pe: sum(
        i.address for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for i in d.imports
    ),
    "walk exports": lambda pe: sum(s.ordinal + s.address for s in export_symbols(pe)),
    "get_data(256 bytes)": lambda pe: pe.get_data(pe.sections[0].VirtualAddress, 256),
    "get_offset_from_rva": lambda pe: pe.get_offset_from_rva(
        pe.OPTIONAL_HEADER.AddressOfEntryPoint or pe.sections[0].VirtualAddress
    ),
    "section entropy": lambda pe: round(pe.sections[0].get_entropy(), 9),
    "get_imphash": lambda pe: pe.get_imphash(),
}


def time_pair(calls):
    """Median, fastest and slowest seconds per call for each library, taking turns per repeat."""
    timers = {name: timeit.Timer(call) for name, call in calls.items()}
    loops = {name: timer.autorange()[0] for name, timer in timers.items()}
    samples = {name: [] for name in calls}
    gc.collect()
    gc.disable()
    try:
        for _ in range(REPEATS):
            for name, timer in timers.items():
                samples[name].append(timer.timeit(loops[name]) / loops[name])
    finally:
        gc.enable()
    return {
        name: {"median": statistics.median(s), "min": min(s), "max": max(s)}
        for name, s in samples.items()
    }


def python_heap(build):
    """Bytes of Python heap still held by one PE object after it is built."""
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    pe = build()
    held = tracemalloc.get_traced_memory()[0] - before
    tracemalloc.stop()
    del pe
    return held


def working_set():
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (name, ctypes.c_size_t)
            for name in (
                "PeakWorkingSetSize",
                "WorkingSetSize",
                "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage",
                "PagefileUsage",
                "PeakPagefileUsage",
            )
        ]

    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    kernel32.K32GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
    return counters.WorkingSetSize


def held_memory_child(library, path):
    """Runs in a fresh process: working-set growth per PE object while many are kept alive."""
    data = Path(path).read_bytes()
    build = LIBRARIES[library]
    build(data=data)
    gc.collect()
    before = working_set()
    held = [build(data=data) for _ in range(HELD_OBJECTS)]
    print((working_set() - before) // len(held))


def held_memory(library, path):
    if sys.platform != "win32":
        return None
    out = subprocess.run(
        [sys.executable, __file__, "--held-memory", library, path],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(out.stdout)


def bench_file(path):
    data = Path(path).read_bytes()
    built = {name: build(data=data) for name, build in LIBRARIES.items()}
    result = {"size": len(data), "times": {}, "memory": {}}

    result["times"]["init from bytes"] = time_pair(
        {name: (lambda b=build: b(data=data)) for name, build in LIBRARIES.items()}
    )
    result["times"]["init from path"] = time_pair(
        {name: (lambda b=build: b(name=path)) for name, build in LIBRARIES.items()}
    )
    # A library that defers work until first use must pay for it inside this timer.
    walk = OPERATIONS["walk imports"]
    result["times"]["init and walk imports"] = time_pair(
        {name: (lambda b=build: walk(b(data=data))) for name, build in LIBRARIES.items()}
    )
    for label, operation in OPERATIONS.items():
        values = {name: operation(pe) for name, pe in built.items()}
        if values["peoxide"] != values["pefile"]:
            sys.exit(f"{path}: {label} differs: {values}")
        result["times"][label] = time_pair(
            {name: (lambda pe=pe: operation(pe)) for name, pe in built.items()}
        )
    for name, build in LIBRARIES.items():
        result["memory"][name] = {
            "python heap": python_heap(lambda: build(data=data)),
            "working set": held_memory(name, path),
        }
    return result


def bench_throughput(folder, threads):
    """Files and megabytes per second, parsing every DLL in the folder from memory."""
    blobs = [p.read_bytes() for p in sorted(Path(folder).glob("*.dll"))]
    result = {"files": len(blobs), "megabytes": sum(map(len, blobs)) / 1e6, "rates": {}}
    folder_blobs = blobs
    for name, build in LIBRARIES.items():
        # One pass of peoxide ends in milliseconds, which would time the thread pool instead.
        blobs = folder_blobs * THROUGHPUT_PASSES[name]
        megabytes = sum(map(len, blobs)) / 1e6
        for workers in (1, threads):
            best = float("inf")
            with ThreadPoolExecutor(workers) as pool:
                for _ in range(3):
                    start = time.perf_counter()
                    parsed = sum(1 for _ in pool.map(lambda blob: build(data=blob), blobs))
                    best = min(best, time.perf_counter() - start)
            assert parsed == len(blobs)
            result["rates"][f"{name}, {workers} thread(s)"] = {
                "files_per_s": len(blobs) / best,
                "mb_per_s": megabytes / best,
            }
    return result


def show_time(seconds):
    for unit, scale in (("s", 1), ("ms", 1e-3), ("us", 1e-6)):
        if seconds >= scale:
            return f"{seconds / scale:.3g} {unit}"
    return f"{seconds / 1e-9:.3g} ns"


def report(results, baseline):
    for path, result in results["files"].items():
        print(f"\n### {path} ({result['size'] / 1e6:.1f} MB)\n")
        header = "| Operation | peoxide | range | pefile | pefile / peoxide |"
        if baseline:
            header += " vs baseline |"
        print(header)
        print("|---|---:|---:|---:|---:|" + ("---:|" if baseline else ""))
        for label, times in result["times"].items():
            ours, theirs = times["peoxide"], times["pefile"]
            row = (
                f"| {label} | {show_time(ours['median'])} "
                f"| {show_time(ours['min'])} to {show_time(ours['max'])} "
                f"| {show_time(theirs['median'])} | {theirs['median'] / ours['median']:.2f}x |"
            )
            if baseline:
                old = baseline["files"].get(path, {}).get("times", {}).get(label)
                row += f" {ours['median'] / old['peoxide']['median'] - 1:+.0%} |" if old else " |"
            print(row)
        for name, memory in result["memory"].items():
            held = memory["working set"]
            print(
                f"\n{name}: {memory['python heap'] / 1024:.0f} KiB Python heap per object"
                + (f", {held / 1024:.0f} KiB working set per object" if held is not None else "")
            )
    throughput = results["throughput"]
    print(f"\n### Throughput: {throughput['files']} DLLs, {throughput['megabytes']:.0f} MB\n")
    print("| Run | files/s | MB/s |\n|---|---:|---:|")
    for label, rate in throughput["rates"].items():
        print(f"| {label} | {rate['files_per_s']:.0f} | {rate['mb_per_s']:.0f} |")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*", default=DEFAULT_FILES)
    parser.add_argument("--folder", default=DEFAULT_FOLDER)
    parser.add_argument("--threads", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument("--json")
    parser.add_argument("--baseline")
    parser.add_argument("--held-memory", nargs=2, metavar=("LIBRARY", "FILE"))
    args = parser.parse_args()
    if args.held_memory:
        return held_memory_child(*args.held_memory)

    results = {
        "files": {path: bench_file(path) for path in args.files},
        "throughput": bench_throughput(args.folder, args.threads),
    }
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
    report(results, json.loads(Path(args.baseline).read_text()) if args.baseline else None)


if __name__ == "__main__":
    main()
