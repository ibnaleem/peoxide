//! Times `peoxide_core::parse` alone, without Python, on each file given.
//!
//! Usage: cargo run --release -p peoxide-core --example parse_time -- FILE...
//!
//! Subtract these times from `scripts/bench_ops.py`'s "init from bytes" to see how much of
//! building a Python `PE` object is spent outside the parser.

use std::hint::black_box;
use std::time::{Duration, Instant};

const ROUNDS: usize = 7;
const ITERATIONS: u32 = 50;

fn main() {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).expect("readable file");
        let mut rounds: Vec<Duration> = (0..ROUNDS)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..ITERATIONS {
                    black_box(peoxide_core::parse(black_box(&data)).expect("valid PE"));
                }
                start.elapsed() / ITERATIONS
            })
            .collect();
        rounds.sort();
        println!(
            "{path}: median {:?}, range {:?} to {:?}",
            rounds[ROUNDS / 2],
            rounds[0],
            rounds[ROUNDS - 1]
        );
    }
}
