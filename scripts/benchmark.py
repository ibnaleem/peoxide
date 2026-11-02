"""Time peoxide against pefile on every *.dll in a folder.

Usage: python scripts/benchmark.py C:\\Windows\\System32 [rounds]

File bytes are read outside the timer and handed to every parser via `data=`, so disk I/O
and the OS file cache are not part of the numbers. Each round times every parser on every
file; the reported total is the median round.
"""

import statistics
import sys
import time
from pathlib import Path

import pefile

import peoxide

SCOPED = [
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
]


def pefile_scoped(data):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=SCOPED)


PARSERS = {
    "peoxide": lambda data: peoxide.PE(data=data),
    "pefile (headers + imports + exports)": pefile_scoped,
    "pefile (default full parse)": lambda data: pefile.PE(data=data),
}


def parseable(paths):
    for path in paths:
        data = path.read_bytes()
        try:
            pefile.PE(data=data, fast_load=True)
            peoxide.PE(data=data)
        except Exception:
            continue
        yield path


def main(folder, rounds):
    paths = list(parseable(sorted(Path(folder).glob("*.dll"))))
    megabytes = sum(p.stat().st_size for p in paths) / 1e6
    totals = {name: [] for name in PARSERS}
    for _ in range(rounds):
        elapsed = dict.fromkeys(PARSERS, 0.0)
        for path in paths:
            data = path.read_bytes()
            for name, parse in PARSERS.items():
                start = time.perf_counter()
                parse(data)
                elapsed[name] += time.perf_counter() - start
        for name, seconds in elapsed.items():
            totals[name].append(seconds)

    print(f"{len(paths)} files, {megabytes:,.0f} MB, {rounds} rounds (median shown)\n")
    print("| parser | total | per file | vs peoxide |")
    print("|---|---:|---:|---:|")
    baseline = statistics.median(totals["peoxide"])
    for name, runs in totals.items():
        total = statistics.median(runs)
        print(
            f"| {name} | {total:.2f} s | {total / len(paths) * 1e3:.2f} ms "
            f"| {total / baseline:.1f}x |"
        )


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3)
