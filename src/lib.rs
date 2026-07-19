//! Recover and use the secret seed of a Vivint/Honeywell 345 MHz door sensor,
//! working only from `rtl_433` captures. No firmware, no key at runtime.
//!
//!   vivint-decode crack  [captures...]            # recover the 16-bit seed
//!   vivint-decode decode &lt;seed&gt; [captures...]     # interpret packets with it
//!
//! Captures are `rtl_433` output (JSON / CSV / codes / plain hex), given as files
//! (concatenated) or on stdin when no files are named.

mod cipher;
mod frame;

use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;

/// Lowest-counter frames used for the brute force (24 * 4 bits = 96 >> 16).
const WINDOW: usize = 24;
/// Above this start counter the replay-from-entry brute force gets slow.
const SLOW_MIN_COUNTER: u16 = 64;

#[derive(Parser)]
#[command(
    name = "vivint-decode",
    about = "Recover and use the secret seed of a Vivint 345 MHz door sensor from rtl_433 captures"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Brute-force the 16-bit seed from captured frames (files, or stdin).
    Crack {
        /// Capture files to concatenate; omit to read stdin.
        captures: Vec<PathBuf>,
    },
    /// Interpret packets with a known seed (files, or stdin).
    Decode {
        /// The recovered seed, hex (0x....) or decimal.
        seed: String,
        /// Capture files to concatenate; omit to read stdin.
        captures: Vec<PathBuf>,
    },
}

#[must_use]
pub fn run() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Crack { captures } => crack(&captures).into(),
        Cmd::Decode { seed, captures } => {
            if let Some(s) = parse_seed(&seed) {
                decode(s, &captures).into()
            } else {
                eprintln!("invalid seed {seed:?} (expected hex 0x.... or a decimal 0..65535)");
                ExitCode::FAILURE
            }
        }
    }
}

/// Yield input lines from the named files (concatenated) or stdin if none given.
fn input_lines(captures: &[PathBuf]) -> Box<dyn Iterator<Item = String>> {
    if captures.is_empty() {
        return Box::new(std::io::stdin().lock().lines().map_while(Result::ok));
    }
    let mut all = Vec::new();
    for p in captures {
        match std::fs::read_to_string(p) {
            Ok(text) => all.extend(text.lines().map(str::to_string)),
            Err(e) => eprintln!("skipping {}: {e}", p.display()),
        }
    }
    Box::new(all.into_iter())
}

fn parse_seed(s: &str) -> Option<u16> {
    let s = s.trim();
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => s.parse().ok()?,
    };
    u16::try_from(v).ok()
}

fn crack(captures: &[PathBuf]) -> u8 {
    // Deduplicate observations by counter (repeats agree); keep the lowest ones.
    let mut by_counter: BTreeMap<u16, u8> = BTreeMap::new();
    for line in input_lines(captures) {
        for f in frame::frames_in_line(&line) {
            let (counter, byte10_hi) = f.observation();
            by_counter.entry(counter).or_insert(byte10_hi);
        }
    }
    let obs: Vec<(u16, u8)> = by_counter.into_iter().collect();
    eprintln!(
        "collected {} distinct-counter observation(s) (min counter = {:?})",
        obs.len(),
        obs.first().map(|o| o.0)
    );
    if let Some(m) = obs.first().map(|o| o.0)
        && m > SLOW_MIN_COUNTER
    {
        eprintln!(
            "note: lowest counter is {m}; the brute force replays from counter 24, so this\n      \
             will be slow. Power-cycle the sensor (battery pull) so counters restart near 24."
        );
    }

    let used: Vec<(u16, u8)> = obs.into_iter().take(WINDOW).collect();
    match cipher::crack(used).as_slice() {
        [] => {
            println!(
                "no seed matches. Wrong device, corrupt frames, or too few distinct counters?"
            );
            1
        }
        [seed] => {
            println!("recovered seed: {seed:#06x}");
            0
        }
        many => {
            let list: Vec<String> = many.iter().map(|s| format!("{s:#06x}")).collect();
            println!(
                "{} candidate seeds — capture more frames at distinct low counters: [{}]",
                many.len(),
                list.join(", ")
            );
            2
        }
    }
}

fn decode(seed: u16, captures: &[PathBuf]) -> u8 {
    let mut dec = cipher::Decoder::new(seed);
    let mut last_counter: Option<u16> = None;
    let mut n = 0usize;
    for line in input_lines(captures) {
        for f in frame::frames_in_line(&line) {
            if last_counter == Some(f.counter) {
                continue; // collapse repeats of the same event
            }
            last_counter = Some(f.counter);
            match dec.contact_open(f.counter, f.status) {
                Some(open) => {
                    println!(
                        "txid={} counter={:5} type={:02x} contact={}",
                        f.txid(),
                        f.counter,
                        f.subtype,
                        if open { "open" } else { "closed" }
                    );
                    n += 1;
                }
                None => eprintln!(
                    "counter {} unreachable from event entry (sensor power-cycled mid-capture?)",
                    f.counter
                ),
            }
        }
    }
    eprintln!("decoded {n} event(s)");
    u8::from(n == 0)
}
