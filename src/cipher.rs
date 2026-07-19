//! Clean-room native implementation of the Vivint/Honeywell 345 MHz door-sensor
//! keystream cipher, used only to **brute-force the 16-bit device seed**.
//!
//! Ported from the MSP430 disassembly and validated byte-exact against an emulator
//! oracle (see ../ notes) over all four primitives and 150+ seeds; no firmware is
//! part of this crate. The only firmware-derived value is the constant
//! `0x4d34d34d` (the ROM's repeating 0x4d,0xd3,0x34 bytes).
//!
//! Per-transmit schedule (firmware 0xeb4c..0xe9aa): entropy is expanded from the
//! seed at event entry (counter 0x17); each transmit increments the counter
//! (wraps 0xfff7->0); counter%12==0 => full regenerate; else counter%4==0 => one
//! diffusion round; every transmit => select the keystream. On air the byte-10
//! high nibble carries `(c3 ^ 0x10) & 0xf0`, which is the only value we match.

const ENTRY_COUNTER: u16 = 0x17;

#[inline]
fn byte10_from_c3(c3: u8) -> u8 {
    (c3 ^ 0x10) & 0xf0
}

fn expand(seed: u16) -> [u16; 8] {
    let base = seed ^ 0x0008;
    [
        base,
        base.wrapping_add(0x25),
        base.wrapping_sub(0x04),
        base.wrapping_add(0x2c),
        base.wrapping_sub(0x09),
        base.wrapping_sub(0x1d),
        base ^ 0x00f9,
        base ^ 0x0022,
    ]
}

const ROMPAT: [u8; 3] = [0x4d, 0xd3, 0x34];
#[inline]
fn rom_word(off: usize) -> u16 {
    u16::from(ROMPAT[off % 3]) | (u16::from(ROMPAT[(off + 1) % 3]) << 8)
}
#[inline]
fn rom_dword(off: usize) -> u32 {
    u32::from(rom_word(off)) | (u32::from(rom_word(off + 2)) << 16)
}

/// Flat little-endian RAM window (0x200..0x2ff), matching the firmware layout.
/// Cloned per thread and reset per seed during the brute force.
#[derive(Clone)]
struct Generator {
    m: [u8; 0x300],
}

impl Generator {
    fn new() -> Self {
        Generator { m: [0u8; 0x300] }
    }
    #[inline]
    fn r16(&self, a: usize) -> u16 {
        u16::from(self.m[a]) | (u16::from(self.m[a + 1]) << 8)
    }
    #[inline]
    fn w16(&mut self, a: usize, v: u16) {
        self.m[a] = v as u8;
        self.m[a + 1] = (v >> 8) as u8;
    }
    #[inline]
    fn r32(&self, a: usize) -> u32 {
        u32::from(self.r16(a)) | (u32::from(self.r16(a + 2)) << 16)
    }
    #[inline]
    fn w32(&mut self, a: usize, v: u32) {
        self.w16(a, v as u16);
        self.w16(a + 2, (v >> 16) as u16);
    }

    fn f294(&mut self) {
        let counter = self.r16(0x206);
        let m = (counter % 7) as usize;
        self.w16(
            0x27a + m * 2,
            self.r16(0x27a + m * 2)
                .wrapping_add(counter)
                .wrapping_add(m as u16),
        );
        self.w16(0x288, self.r16(0x288) ^ m as u16);
        let e: [u16; 8] = std::array::from_fn(|i| self.r16(0x27a + 2 * i));
        let mut s1 = [0u16; 16];
        let mut s2 = [0u16; 16];
        for r in 0..8usize {
            if r % 2 == 0 {
                s1[2 * r] = e[r];
                s1[2 * r + 1] = e[(r + 1) % 8];
                s2[2 * r] = e[(r + 5) % 8];
                s2[2 * r + 1] = e[(r + 4) % 8];
            } else {
                s1[2 * r] = e[(r + 4) % 8];
                s1[2 * r + 1] = e[(r + 5) % 8];
                s2[2 * r] = e[(r + 1) % 8];
                s2[2 * r + 1] = e[r];
            }
        }
        for i in 0..16 {
            self.w16(0x232 + 2 * i, s1[i]);
            self.w16(0x252 + 2 * i, s2[i]);
        }
    }

    fn ed74(&mut self) {
        const SC: usize = 0x294;
        for r8 in 0..8 {
            let lo = self.r16(0x252 + r8 * 4);
            let hi = self.r16(0x254 + r8 * 4);
            self.w16(SC + r8 * 4, lo);
            self.w16(SC + 2 + r8 * 4, hi);
        }
        let lcg = self.r32(0x272).wrapping_add(0x4d34_d34d);
        self.w32(0x252, self.r32(0x252).wrapping_add(lcg));
        for r8 in 1..8 {
            let a = self.r32(0x252 + r8 * 4);
            let b = self.r32(0x24e + r8 * 4);
            let sub = self.r32(SC - 4 + r8 * 4);
            let borrow = u32::from(b < sub);
            self.w32(
                0x252 + r8 * 4,
                a.wrapping_add(rom_dword(r8 * 4)).wrapping_add(borrow),
            );
        }
        let borrow = u16::from(self.r32(0x26e) < self.r32(0x2b0));
        self.w16(0x272, borrow);
        self.w16(0x274, 0);
        for r8 in 0..8 {
            let x = self
                .r32(0x232 + r8 * 4)
                .wrapping_add(self.r32(0x252 + r8 * 4));
            let lo = x & 0xffff;
            let hi = x >> 16;
            let xsq = x.wrapping_mul(x);
            let mut acc = (lo.wrapping_mul(lo) >> 16) >> 1;
            acc = acc.wrapping_add(lo.wrapping_mul(hi));
            acc >>= 15;
            acc = acc.wrapping_add(hi.wrapping_mul(hi));
            acc ^= xsq;
            self.w32(SC + r8 * 4, acc);
        }
        let (mut r11, mut r10) = (7usize, 6usize);
        for r8 in [0usize, 2, 4, 6] {
            let t1 = self.r32(SC + r11 * 4).rotate_left(16);
            let t2 = self.r32(SC + r10 * 4).rotate_left(16);
            self.w32(
                0x232 + r8 * 4,
                t1.wrapping_add(self.r32(SC + r8 * 4)).wrapping_add(t2),
            );
            r11 = (r11 + 1) % 8;
            r10 = (r10 + 1) % 8;
            let t3 = self.r32(SC + r11 * 4).rotate_left(8);
            self.w32(
                0x236 + r8 * 4,
                t3.wrapping_add(self.r32(SC + 4 + r8 * 4))
                    .wrapping_add(self.r32(SC + r10 * 4)),
            );
            r11 = (r11 + 1) % 8;
            r10 = (r10 + 1) % 8;
        }
    }

    fn f986(&mut self) {
        for r10 in 0..8usize {
            let r11 = r10 * 4;
            let r14 = ((r10 + 4) % 8) * 4;
            self.w16(0x252 + r11, self.r16(0x252 + r11) ^ self.r16(0x232 + r14));
            self.w16(0x254 + r11, self.r16(0x254 + r11) ^ self.r16(0x234 + r14));
        }
    }

    fn f386(&mut self) {
        let k = self.r16(0x206) & 3;
        let (r14, r12, r13) = match k {
            0 => (
                self.r16(0x23e),
                self.r16(0x248) ^ self.r16(0x232),
                self.r16(0x234),
            ),
            1 => (
                self.r16(0x246),
                self.r16(0x250) ^ self.r16(0x23a),
                self.r16(0x23c),
            ),
            2 => (
                self.r16(0x24e),
                self.r16(0x238) ^ self.r16(0x242),
                self.r16(0x244),
            ),
            _ => (
                self.r16(0x236),
                self.r16(0x240) ^ self.r16(0x24a),
                self.r16(0x24c),
            ),
        };
        let r13 = r13 ^ r14;
        self.m[0x2c1] = r12 as u8;
        self.m[0x2c2] = (r12 >> 8) as u8;
        self.m[0x2c3] = r13 as u8;
        self.m[0x2c4] = (r13 >> 8) as u8;
    }

    fn f9b0(&mut self) {
        self.w16(0x272, 0);
        self.w16(0x274, 0);
        self.f294();
        for _ in 0..4 {
            self.ed74();
        }
        self.f986();
        self.ed74();
        self.f386();
    }

    fn begin(&mut self, seed: u16) {
        self.m = [0u8; 0x300];
        for (i, v) in expand(seed).iter().enumerate() {
            self.w16(0x27a + 2 * i, *v);
        }
    }

    /// Advance one transmit; returns (counter, c1 status-key, c3 byte-10 key).
    fn tick(&mut self, counter: u16) -> (u16, u8, u8) {
        let counter = if counter == 0xfff7 { 0 } else { counter + 1 };
        self.w16(0x206, counter);
        if counter % 12 == 0 {
            self.f9b0();
        } else if counter % 4 == 0 {
            self.ed74();
            self.f386();
        } else {
            self.f386();
        }
        (counter, self.m[0x2c1], self.m[0x2c3])
    }

    /// Replay from entry, checking each `(counter, byte10_hi)` target as reached;
    /// returns false on the first mismatch. `targets` sorted by counter and unique.
    fn replay_matches(&mut self, seed: u16, targets: &[(u16, u8)]) -> bool {
        if targets.is_empty() {
            return true;
        }
        let max_counter = targets[targets.len() - 1].0;
        self.begin(seed);
        let mut counter = ENTRY_COUNTER;
        let mut ti = 0usize;
        while counter < max_counter && ti < targets.len() {
            let (c, _c1, c3) = self.tick(counter);
            counter = c;
            while ti < targets.len() && targets[ti].0 == counter {
                if byte10_from_c3(c3) != targets[ti].1 {
                    return false;
                }
                ti += 1;
            }
        }
        ti == targets.len()
    }
}

/// Streaming keystream lookup for decoding with a known seed. Advances the
/// per-transmit schedule forward as counters arrive (cheap for monotonic
/// streams), caches results, and re-syncs from event entry if the counter jumps
/// backward (sensor power-cycle).
pub(crate) struct Decoder {
    state: Generator,
    seed: u16,
    counter: u16,
    cache: std::collections::HashMap<u16, u8>, // counter -> c1 (status key)
}

impl Decoder {
    pub(crate) fn new(seed: u16) -> Self {
        let mut state = Generator::new();
        state.begin(seed);
        Decoder {
            state,
            seed,
            counter: ENTRY_COUNTER,
            cache: std::collections::HashMap::new(),
        }
    }

    /// The status-key byte c1 at `counter`, or None if unreachable within one
    /// counter cycle (e.g. a counter from before the last reset that we can't
    /// re-derive).
    fn c1_at(&mut self, target: u16) -> Option<u8> {
        if let Some(&v) = self.cache.get(&target) {
            return Some(v);
        }
        if target < self.counter {
            self.state.begin(self.seed); // backward jump -> re-sync from entry
            self.counter = ENTRY_COUNTER;
        }
        let mut steps = 0u32;
        while self.counter != target {
            let (c, c1, _c3) = self.state.tick(self.counter);
            self.counter = c;
            self.cache.insert(c, c1);
            if c == target {
                return Some(c1);
            }
            steps += 1;
            if steps > 0x1_0000 {
                return None;
            }
        }
        self.cache.get(&target).copied()
    }

    /// True contact state for a 0x7x frame: `Some(true)` = open. `status` is the
    /// frame's byte-5 status byte, which the sensor XORs with the keystream.
    pub(crate) fn contact_open(&mut self, counter: u16, status: u8) -> Option<bool> {
        Some((status ^ self.c1_at(counter)?) & 0x80 != 0)
    }
}

/// Brute-force the 16-bit seed against on-air observations `(counter, byte10)`,
/// parallelized across cores. Only the high nibble of byte10 is significant.
/// Returns every seed consistent with all observations (usually exactly one).
pub(crate) fn crack(mut targets: Vec<(u16, u8)>) -> Vec<u16> {
    for t in &mut targets {
        t.1 &= 0xf0;
    }
    targets.sort_by_key(|t| t.0);
    targets.dedup_by_key(|t| t.0);
    if targets.is_empty() {
        return Vec::new();
    }
    let nthreads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let chunk = 0x10000usize.div_ceil(nthreads);
    let targets_ref = &targets;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..nthreads)
            .map(|t| {
                scope.spawn(move || {
                    let mut g = Generator::new();
                    let lo = t * chunk;
                    let hi = ((t + 1) * chunk).min(0x10000);
                    let mut hits = Vec::new();
                    for s in lo..hi {
                        if g.replay_matches(s as u16, targets_ref) {
                            hits.push(s as u16);
                        }
                    }
                    hits
                })
            })
            .collect();
        let mut all: Vec<u16> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all.sort_unstable();
        all
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic seeds used only to exercise the round trip; not real devices.
    const TEST_SEEDS: &[u16] = &[0x0001, 0x1234, 0xabcd, 0xfffe];
    const COUNTERS: &[u16] = &[24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];

    /// Generate the on-air byte-10 high nibble each counter would carry for `seed`.
    fn observations_for(seed: u16, counters: &[u16]) -> Vec<(u16, u8)> {
        let max = *counters.iter().max().unwrap();
        let mut g = Generator::new();
        g.begin(seed);
        let mut by_counter = std::collections::BTreeMap::new();
        let mut c = ENTRY_COUNTER;
        while c < max {
            let (nc, _c1, c3) = g.tick(c);
            c = nc;
            by_counter.insert(c, byte10_from_c3(c3));
        }
        counters
            .iter()
            .map(|&cnt| (cnt, by_counter[&cnt]))
            .collect()
    }

    #[test]
    fn crack_round_trips_each_seed() {
        // Generate frames from a seed, then recover exactly that seed. This
        // exercises the whole cipher and the brute force without any real secret.
        for &seed in TEST_SEEDS {
            assert_eq!(
                crack(observations_for(seed, COUNTERS)),
                vec![seed],
                "seed {seed:#06x}"
            );
        }
    }

    #[test]
    fn too_few_frames_stays_ambiguous_but_includes_truth() {
        let seed = TEST_SEEDS[1];
        let hits = crack(observations_for(seed, &[24, 25]));
        assert!(hits.len() > 1, "two frames should be ambiguous");
        assert!(hits.contains(&seed));
    }

    #[test]
    fn decoder_round_trips_contact_state() {
        // Craft a status byte with a known contact bit XOR the true keystream,
        // then confirm the decoder recovers it. Uses a synthetic seed.
        let seed = TEST_SEEDS[2];
        let c1 = Decoder::new(seed).c1_at(30).unwrap();
        // status = c1 ^ raw_status; contact bit (0x80) set => open, clear => closed.
        assert_eq!(Decoder::new(seed).contact_open(30, c1 ^ 0x80), Some(true));
        assert_eq!(Decoder::new(seed).contact_open(30, c1), Some(false));
    }
}
