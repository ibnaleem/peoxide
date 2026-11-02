"""Time peoxide against pefile on every *.dll in a folder.

Usage: python scripts/benchmark.py C:\\Windows\\System32 [rounds]

What is timed, per file and parser: parsing the bytes and then reading every header,
section, import and export back out through `parity_sweep.summarize`. Reading the results
inside the timer means a parser cannot look fast by deferring work.

Outside the timer, every file is checked once: peoxide's results must equal both pefile
variants (after the documented normalisations in `parity_sweep.differences`). File bytes are
read outside the timer, garbage collection is disabled while timing (as `timeit` does) and run
between files instead, parser order is shuffled per file, and one untimed warm-up round runs
first. The reported number is the median round.
"""

import gc
import random
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I drops the script's folder

import pefile
from parity_sweep import DIRECTORIES, differences, summarize

import peoxide


def pefile_scoped(data):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=DIRECTORIES)
    return pe


PARSERS = {
    "peoxide": lambda data: peoxide.PE(data=data),
    "pefile (headers + imports + exports)": pefile_scoped,
    "pefile (default full parse)": lambda data: pefile.PE(data=data),
}


def checked_files(folder):
    """Files every parser accepts and agrees on, plus counts of what was left out and why."""
    kept, skipped = [], Counter()
    for path in sorted(Path(folder).glob("*.dll")):
        data = path.read_bytes()
        try:
            references = [PARSERS[name](data) for name in list(PARSERS)[1:]]
        except Exception:
            skipped["pefile failed"] += 1
            continue
        try:
            ours = PARSERS["peoxide"](data)
        except peoxide.PEFormatError:
            skipped["peoxide failed"] += 1
            continue
        for reference in references:
            differing = differences(ours, reference)
            if differing:
                sys.exit(f"{path.name}: peoxide and pefile disagree on {differing}")
        kept.append(path)
    return kept, skipped


def timed_round(paths, rng):
    elapsed = dict.fromkeys(PARSERS, 0.0)
    for path in paths:
        data = path.read_bytes()
        order = list(PARSERS.items())
        rng.shuffle(order)
        for name, parse in order:
            start = time.perf_counter()
            summarize(parse(data))
            elapsed[name] += time.perf_counter() - start
        gc.collect()
    return elapsed


def main(folder, rounds):
    paths, skipped = checked_files(folder)
    megabytes = sum(p.stat().st_size for p in paths) / 1e6
    rng = random.Random(0)
    gc.disable()
    try:
        timed_round(paths, rng)
        results = [timed_round(paths, rng) for _ in range(rounds)]
    finally:
        gc.enable()

    print(f"{len(paths)} files, {megabytes:,.0f} MB, {rounds} rounds + 1 warm-up (median shown)")
    print(f"Left out: {dict(skipped) or 'none'}. Results matched pefile on every timed file.\n")
    print("| parser | total | per file | vs peoxide |")
    print("|---|---:|---:|---:|")
    totals = {name: statistics.median(r[name] for r in results) for name in PARSERS}
    for name, total in totals.items():
        print(
            f"| {name} | {total * 1e3:,.1f} ms | {total / len(paths) * 1e3:.3f} ms "
            f"| {total / totals['peoxide']:.1f}x |"
        )


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3)
