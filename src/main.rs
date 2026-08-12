//! Recover and use the secret seed of a Vivint/Honeywell 345 MHz door sensor,
//! working only from `rtl_433` captures. No firmware, no key at runtime.
//!
//!   vivint-decode crack  [captures...]            # recover the 16-bit seed
//!   vivint-decode decode <seed> [captures...]     # interpret packets with it
//!
//! Captures are `rtl_433` output (JSON / CSV / codes / plain hex), given as files
//! (concatenated) or on stdin when no files are named. Every frame carries its
//! transmitter id in the clear, so observations are grouped **per TXID** and each
//! device is cracked independently — a second nearby sensor can't poison the
//! brute force. `crack` recovers **every** device present: `cat *.json | vivint-decode
//! crack` cracks all of them at once. When reading a live stdin stream, it re-attempts
//! the brute force as frames arrive, announces each device's seed the moment it is
//! pinned, and prints a combined `-R 342:ID1=s1,ID2=s2,…` mapping covering all of them.

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

/// `rtl_433`'s spelling of our "PPPP-QQQ-RRRR" TXID label: it wants the id
/// un-hyphenated in the middle ("PPPP-QQQRRRR").
fn rtl433_id(txid: &str) -> String {
    match txid.split_once('-') {
        Some((p1, rest)) => format!("{p1}-{}", rest.replace('-', "")),
        None => txid.to_string(),
    }
}

/// The `-R` mapping arg to hand `rtl_433` so it un-keys this device itself, e.g.
/// `-R 342:0056-0405817=0c5e`.
fn rtl433_arg(txid: &str, seed: u16) -> String {
    format!("-R {RTL433_PROTOCOL}:{}={seed:04x}", rtl433_id(txid))
}

/// One `-R` arg mapping *every* solved device at once, e.g.
/// `-R 342:0019-0507743=dda9,0056-0405817=0c5e`. `rtl_433` accepts comma-separated
/// `id=seed` pairs, so a single arg configures a whole house of sensors.
fn rtl433_arg_all(solved: &BTreeMap<String, u16>) -> String {
    let pairs: Vec<String> = solved
        .iter()
        .map(|(txid, seed)| format!("{}={seed:04x}", rtl433_id(txid)))
        .collect();
    format!("-R {RTL433_PROTOCOL}:{}", pairs.join(","))
}

/// Print the combined mapping for all solved devices. Only worth showing once two
/// or more devices are known — for a single device the per-device line already has
/// the same arg.
fn print_combined(solved: &BTreeMap<String, u16>) {
    if solved.len() < 2 {
        return;
    }
    println!(
        "all {} devices    rtl_433: {}",
        solved.len(),
        rtl433_arg_all(solved)
    );
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

/// Sweep every dirty, not-yet-solved device with at least `min_distinct` counters.
/// Each device that pins to a single seed is announced and recorded in `solved`;
/// the sweep does not stop at the first — a whole house of sensors resolves in one
/// pass. When `diag` is `Some(tag)`, ambiguous / no-match devices get a progress
/// note on stderr under that tag (kept quiet at EOF). Each ready device is cracked
/// exactly once. Returns true if any *new* device was solved this call.
fn sweep(
    devices: &mut HashMap<String, Device>,
    min_distinct: usize,
    solved: &mut BTreeMap<String, u16>,
    diag: Option<&str>,
) -> bool {
    let mut txids: Vec<String> = devices.keys().cloned().collect();
    txids.sort();
    let mut progress = false;
    for txid in txids {
        if solved.contains_key(&txid) {
            continue; // already pinned — leave it alone
        }
        let dev = devices.get_mut(&txid).unwrap();
        let distinct = dev.distinct();
        if !dev.dirty || distinct < min_distinct {
            continue;
        }
        dev.dirty = false; // don't re-sweep the same observations until a new counter arrives
        match dev.seeds().as_slice() {
            [seed] => {
                report_hit(&txid, *seed, dev);
                solved.insert(txid, *seed);
                progress = true;
            }
            [] => {
                if let Some(tag) = diag {
                    eprintln!(
                        "{tag} txid {txid}: {distinct} counters but no seed matches — corrupt frames or wrong device?"
                    );
                }
            }
            many => {
                if let Some(tag) = diag {
                    eprintln!(
                        "{tag} txid {txid}: {distinct} counters, {} candidate seeds — capture more low counters",
                        many.len()
                    );
                }
            }
        }
    }
    progress
}

fn crack(captures: &[PathBuf]) -> i32 {
    if captures.is_empty() {
        crack_stream()
    } else {
        crack_files(captures)
    }
}

/// Stream stdin: accumulate observations and re-attempt the brute force every
/// `STREAM_BATCH` lines. Each device is announced the moment it is pinned; a
/// combined `-R` mapping is (re)printed whenever a new device joins the set, and
/// once more at EOF. Runs until the stream ends — every device gets cracked.
fn crack_stream() -> i32 {
    let mut devices: HashMap<String, Device> = HashMap::new();
    let mut solved: BTreeMap<String, u16> = BTreeMap::new();
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
        if stream_checkpoint(lines, &mut devices, &mut solved) {
            print_combined(&solved); // a new device joined — refresh the combined arg
        }
    }
    // EOF: one last attempt, lowering the bar to include short-lived devices.
    for dev in devices.values_mut() {
        dev.dirty = true;
    }
    sweep(&mut devices, 2, &mut solved, None);
    if solved.is_empty() {
        report_no_seed(&devices);
        return 1;
    }
    print_combined(&solved); // authoritative final mapping for everything solved
    0
}

/// One streaming checkpoint: print collection status to stderr, then sweep every
/// ready device into `solved`. Returns true if a new device was solved this call.
fn stream_checkpoint(
    lines: usize,
    devices: &mut HashMap<String, Device>,
    solved: &mut BTreeMap<String, u16>,
) -> bool {
    let frames: usize = devices.values().map(|d| d.packets).sum();
    let tag = format!("[{lines} lines, {frames} frames, {} solved]", solved.len());
    if devices.is_empty() {
        eprintln!(
            "{tag} no frame hex parsed yet — is rtl_433 emitting the raw frame? \
             (its JSON needs a data/codes hex field)"
        );
        return false;
    }
    // Cheap per-device progress for anything still short of the crack threshold
    // (no brute force here). Devices at/above the threshold are handled by sweep(),
    // which cracks each exactly once and reports ambiguous/no-match cases via `diag`.
    let mut txids: Vec<String> = devices.keys().cloned().collect();
    txids.sort();
    for txid in &txids {
        if solved.contains_key(txid) {
            continue;
        }
        let dev = &devices[txid];
        let distinct = dev.distinct();
        if distinct < MIN_DISTINCT {
            eprintln!(
                "{tag} txid {txid}: {distinct}/{MIN_DISTINCT} distinct counters (min {:?}) — \
                 toggle the reed for more distinct low counters",
                dev.min_counter()
            );
        }
    }
    sweep(devices, MIN_DISTINCT, solved, Some(&tag))
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
    let mut solved: BTreeMap<String, u16> = BTreeMap::new();
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
                solved.insert(txid.clone(), *seed);
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
    print_combined(&solved); // one arg mapping every device that resolved
    i32::from(solved.is_empty())
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

#[cfg(test)]
mod tests {
    use super::{BTreeMap, rtl433_arg, rtl433_arg_all, rtl433_id};

    #[test]
    fn id_drops_the_inner_hyphens_only() {
        // "PPPP-QQQ-RRRR" -> "PPPP-QQQRRRR": first hyphen stays, the rest go.
        assert_eq!(rtl433_id("0019-050-7743"), "0019-0507743");
        assert_eq!(rtl433_id("0056-040-5817"), "0056-0405817");
        // no hyphens / single segment: passed through untouched
        assert_eq!(rtl433_id("abcdef"), "abcdef");
    }

    #[test]
    fn single_device_arg() {
        assert_eq!(
            rtl433_arg("0056-040-5817", 0x0c5e),
            "-R 342:0056-0405817=0c5e"
        );
    }

    #[test]
    fn combined_arg_joins_all_devices_with_commas() {
        let solved: BTreeMap<String, u16> = [
            ("0019-050-7610".to_string(), 0x05c9u16),
            ("0019-050-7743".to_string(), 0xdda9u16),
        ]
        .into_iter()
        .collect();
        // BTreeMap keeps TXID order deterministic for a stable, paste-able arg.
        assert_eq!(
            rtl433_arg_all(&solved),
            "-R 342:0019-0507610=05c9,0019-0507743=dda9"
        );
    }
}
