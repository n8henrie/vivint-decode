//! Recover and use the secret seed of a Vivint/Honeywell 345 MHz door sensor,
//! working only from `rtl_433` captures. No firmware, no key at runtime.
//!
//!   vivint-decode crack  [captures...]            # recover the 16-bit seed
//!   vivint-decode decode \<seed> [captures...]     # interpret packets with it
//!
//! Captures are `rtl_433` output (JSON / CSV / codes / plain hex), given as files
//! (concatenated) or on stdin when no files are named. Every frame carries its
//! transmitter id in the clear, so observations are grouped **per TXID** and each
//! device is cracked independently — a second nearby sensor can't poison the
//! brute force. When reading a live stdin stream, `crack` re-attempts the brute
//! force as frames arrive and stops as soon as one device's seed is pinned.

mod cipher;
mod frame;

use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, HashMap};
use std::io::BufRead;
use std::path::PathBuf;

/// Lowest-counter frames used for the brute force (24 * 4 bits = 96 >> 16).
const WINDOW: usize = 24;
/// Above this start counter the replay-from-entry brute force gets slow.
const SLOW_MIN_COUNTER: u16 = 64;
/// While streaming stdin, re-attempt the brute force after this many new lines.
/// Optimistic: a clean power-on burst reaches enough distinct low counters
/// within a batch or two.
const STREAM_BATCH: usize = 12;
/// Don't sweep a device below this many distinct counters — it can't yet be
/// unique, so a full 65536-seed sweep would only waste time.
const MIN_DISTINCT: usize = 8;

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
        /// Capture files to concatenate; omit to read (and stream) stdin.
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

fn main() {
    std::process::exit(match Cli::parse().cmd {
        Cmd::Crack { captures } => crack(&captures),
        Cmd::Decode { seed, captures } => {
            if let Some(s) = parse_seed(&seed) {
                decode(s, &captures)
            } else {
                eprintln!("invalid seed {seed:?} (expected hex 0x.... or a decimal 0..65535)");
                2
            }
        }
    });
}

fn parse_seed(s: &str) -> Option<u16> {
    let s = s.trim();
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => s.parse().ok()?,
    };
    u16::try_from(v).ok()
}

/// Read every line of the named files (concatenated) into memory.
fn file_lines(captures: &[PathBuf]) -> Vec<String> {
    let mut all = Vec::new();
    for p in captures {
        match std::fs::read_to_string(p) {
            Ok(text) => all.extend(text.lines().map(str::to_string)),
            Err(e) => eprintln!("skipping {}: {e}", p.display()),
        }
    }
    all
}

/// Yield input lines from the named files (concatenated) or stdin if none given.
/// Used by `decode`, which processes the whole stream the same way either way.
fn input_lines(captures: &[PathBuf]) -> Box<dyn Iterator<Item = String>> {
    if captures.is_empty() {
        Box::new(std::io::stdin().lock().lines().map_while(Result::ok))
    } else {
        Box::new(file_lines(captures).into_iter())
    }
}

/// Accumulated on-air observations for a single transmitter (TXID).
#[derive(Default)]
struct Device {
    by_counter: BTreeMap<u16, u8>, // counter -> byte10 high nibble
    packets: usize,                // frames seen, including repeats
    dirty: bool,                   // gained a distinct counter since last sweep
}

impl Device {
    fn record(&mut self, counter: u16, byte10_hi: u8) {
        self.packets += 1;
        if self.by_counter.insert(counter, byte10_hi).is_none() {
            self.dirty = true; // a new distinct counter — worth re-cracking
        }
    }

    fn distinct(&self) -> usize {
        self.by_counter.len()
    }

    fn min_counter(&self) -> Option<u16> {
        self.by_counter.keys().next().copied()
    }

    /// Every seed consistent with this device's lowest-counter observations.
    fn seeds(&self) -> Vec<u16> {
        let used: Vec<(u16, u8)> = self
            .by_counter
            .iter()
            .take(WINDOW)
            .map(|(&c, &h)| (c, h))
            .collect();
        cipher::crack(used)
    }
}

/// Fold every frame in `line` into `devices`, keyed by TXID. Only keystreamed
/// event frames (0x7a/0x74/0x79) carry the crackable byte-10 MAC — heartbeats,
/// seed-announce, and other 0x7x frames would poison the search, so we skip them.
fn ingest(line: &str, devices: &mut HashMap<String, Device>) {
    for f in frame::frames_in_line(line) {
        if !f.is_keyed_event() {
            continue;
        }
        let (counter, byte10_hi) = f.observation();
        devices
            .entry(f.txid())
            .or_default()
            .record(counter, byte10_hi);
    }
}

/// `rtl_433` decoder number for the Vivint 0x7x device. This is the `-R <n>` slot
/// the decoder registers under in your `rtl_433` build; adjust if yours differs.
const RTL433_PROTOCOL: &str = "342";

/// The `-R` mapping arg to hand `rtl_433` so it un-keys this device itself, e.g.
/// `-R 342:0056-0405817=0c5e`. `txid` is our "PPPP-QQQ-RRRR" label; `rtl_433` wants
/// the id un-hyphenated in the middle ("PPPP-QQQRRRR").
fn rtl433_arg(txid: &str, seed: u16) -> String {
    let id = match txid.split_once('-') {
        Some((p1, rest)) => format!("{p1}-{}", rest.replace('-', "")),
        None => txid.to_string(),
    };
    format!("-R {RTL433_PROTOCOL}:{id}={seed:04x}")
}

/// Print a recovered seed. The `recovered seed: 0x....` token is kept first and
/// whitespace-delimited so callers can grep it and feed it straight to `decode`;
/// the ready-to-paste `rtl_433` arg follows on the same line, details below.
fn report_hit(txid: &str, seed: u16, dev: &Device) {
    println!(
        "recovered seed: {seed:#06x}    rtl_433: {}",
        rtl433_arg(txid, seed)
    );
    println!(
        "  txid {txid} — {} packets analyzed, {} distinct counters, earliest counter {}",
        dev.packets,
        dev.distinct(),
        dev.min_counter().unwrap_or(0),
    );
}

/// Sweep each device that is dirty and has at least `min_distinct` counters. On
/// the first device that pins to a single seed, print it and return true.
fn try_devices(devices: &mut HashMap<String, Device>, min_distinct: usize) -> bool {
    let mut txids: Vec<String> = devices.keys().cloned().collect();
    txids.sort();
    for txid in txids {
        let dev = devices.get_mut(&txid).unwrap();
        if !dev.dirty || dev.distinct() < min_distinct {
            continue;
        }
        dev.dirty = false; // don't re-sweep the same observations next batch
        if let [seed] = dev.seeds().as_slice() {
            report_hit(&txid, *seed, dev);
            return true;
        }
    }
    false
}

fn crack(captures: &[PathBuf]) -> i32 {
    if captures.is_empty() {
        crack_stream()
    } else {
        crack_files(captures)
    }
}

/// Stream stdin: accumulate observations and re-attempt the brute force every
/// `STREAM_BATCH` lines, printing a progress line each checkpoint and exiting the
/// moment any device's seed is pinned.
fn crack_stream() -> i32 {
    let mut devices: HashMap<String, Device> = HashMap::new();
    let mut lines = 0usize;
    let mut since = 0usize;
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        ingest(&line, &mut devices);
        lines += 1;
        since += 1;
        if since < STREAM_BATCH {
            continue;
        }
        since = 0;
        if stream_checkpoint(lines, &mut devices) {
            return 0;
        }
    }
    // EOF: one last attempt, lowering the bar to include short-lived devices.
    for dev in devices.values_mut() {
        dev.dirty = true;
    }
    if try_devices(&mut devices, 2) {
        return 0;
    }
    report_no_seed(&devices);
    1
}

/// One streaming checkpoint: print collection status to stderr, then sweep each
/// ready device. Returns true if a unique seed was found (and printed).
fn stream_checkpoint(lines: usize, devices: &mut HashMap<String, Device>) -> bool {
    let frames: usize = devices.values().map(|d| d.packets).sum();
    let tag = format!("[{lines} lines, {frames} frames]");
    if devices.is_empty() {
        eprintln!(
            "{tag} no frame hex parsed yet — is rtl_433 emitting the raw frame? \
             (its JSON needs a data/codes hex field)"
        );
        return false;
    }
    let mut txids: Vec<String> = devices.keys().cloned().collect();
    txids.sort();
    for txid in &txids {
        let dev = devices.get_mut(txid).unwrap();
        let distinct = dev.distinct();
        if distinct < MIN_DISTINCT {
            eprintln!(
                "{tag} txid {txid}: {distinct}/{MIN_DISTINCT} distinct counters (min {:?}) — \
                 toggle the reed for more distinct low counters",
                dev.min_counter()
            );
            continue;
        }
        if !dev.dirty {
            continue; // already swept these exact observations
        }
        dev.dirty = false;
        match dev.seeds().as_slice() {
            [seed] => {
                report_hit(txid, *seed, dev);
                return true;
            }
            [] => eprintln!(
                "{tag} txid {txid}: {distinct} counters but no seed matches — corrupt frames or wrong device?"
            ),
            many => eprintln!(
                "{tag} txid {txid}: {distinct} counters, {} candidate seeds — capture more low counters",
                many.len()
            ),
        }
    }
    false
}

/// Crack a finite set of files: group by TXID, then report every device.
fn crack_files(captures: &[PathBuf]) -> i32 {
    let mut devices: HashMap<String, Device> = HashMap::new();
    for line in file_lines(captures) {
        ingest(&line, &mut devices);
    }
    if devices.is_empty() {
        eprintln!("no CRC-valid 0x7x event frames found in input");
        return 1;
    }
    let mut txids: Vec<&String> = devices.keys().collect();
    txids.sort();
    let mut any = false;
    for txid in txids {
        let dev = &devices[txid];
        if let Some(m) = dev.min_counter()
            && m > SLOW_MIN_COUNTER
        {
            eprintln!(
                "txid {txid}: lowest counter is {m}; the brute force replays from counter 24, so\n  \
                 this is slow. Power-cycle the sensor (battery pull) to restart counters near 24."
            );
        }
        match dev.seeds().as_slice() {
            [seed] => {
                report_hit(txid, *seed, dev);
                any = true;
            }
            [] => println!(
                "txid {txid}: no seed matches ({} distinct counters) — wrong device or corrupt frames?",
                dev.distinct()
            ),
            many => {
                let list: Vec<String> = many.iter().map(|s| format!("{s:#06x}")).collect();
                println!(
                    "txid {txid}: {} candidate seeds — capture more low-counter frames: [{}]",
                    many.len(),
                    list.join(", ")
                );
            }
        }
    }
    i32::from(!any)
}

/// No device resolved to a single seed; summarize what we have and how to help.
fn report_no_seed(devices: &HashMap<String, Device>) {
    if devices.is_empty() {
        eprintln!("no CRC-valid 0x7x event frames seen on stdin");
        return;
    }
    eprintln!("no unique seed recovered yet:");
    let mut txids: Vec<&String> = devices.keys().collect();
    txids.sort();
    for txid in txids {
        let dev = &devices[txid];
        eprintln!(
            "  txid {txid}: {} distinct counters (min {:?}), {} packets",
            dev.distinct(),
            dev.min_counter(),
            dev.packets,
        );
    }
    eprintln!(
        "Capture more frames at distinct low counters. Power-cycle the sensor \
         (battery pull) so its counter restarts near 24."
    );
}

/// Render the un-keyed status byte as the classic Honeywell event-byte fields.
/// Which "loop" is the real door contact depends on the model: the DW21R reports
/// on loop-1 (0x80), the DW11 on loop-2 (0x20) — so we surface both.
fn format_status(plain: u8) -> String {
    let onoff = |bit: u8| if plain & bit != 0 { "open" } else { "closed" };
    let flag = |bit: u8| if plain & bit != 0 { "yes" } else { "no" };
    format!(
        "status={:02x} loop1={} loop2={} tamper={} alarm={} batt={} hb={}",
        plain & 0xfc,
        onoff(0x80),
        onoff(0x20),
        flag(0x40),
        flag(0x10),
        if plain & 0x08 != 0 { "low" } else { "ok" },
        flag(0x04),
    )
}

fn decode(seed: u16, captures: &[PathBuf]) -> i32 {
    let mut dec = cipher::Decoder::new(seed);
    let mut last: Option<(u8, u16)> = None; // (subtype, counter) for repeat collapse
    let mut n = 0usize;
    for line in input_lines(captures) {
        for f in frame::frames_in_line(&line) {
            let key = (f.subtype, f.counter);
            if last == Some(key) {
                continue; // collapse consecutive repeats of the same frame
            }
            last = Some(key);

            if let Some(announced) = f.announced_seed() {
                println!(
                    "txid={} type={:02x} seed={announced:#06x} (announced in the clear)",
                    f.txid(),
                    f.subtype,
                );
                n += 1;
                continue;
            }
            if !f.is_keyed_event() {
                // heartbeat / other 0x7x: counter is real, status is not keyed.
                println!(
                    "txid={} counter={:05} type={:02x} (not a keyed event)",
                    f.txid(),
                    f.counter,
                    f.subtype,
                );
                continue;
            }
            match dec.plain_status(f.counter, f.status) {
                Some(plain) => {
                    println!(
                        "txid={} counter={:05} type={:02x} {}",
                        f.txid(),
                        f.counter,
                        f.subtype,
                        format_status(plain),
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
    i32::from(n == 0)
}
