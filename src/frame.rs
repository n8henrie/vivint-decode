//! Format-agnostic extraction of Vivint 0x7x event frames from `rtl_433` output.
//!
//! `rtl_433` JSON (`-F json:-`), CSV (`data` column), the `codes` array
//! (`{96}fffe...`), and plain hex-per-line captures all embed the frame as a hex
//! run beginning with the `fffe` sync. Depending on the receiver's OOK polarity
//! the whole frame may be **bit-inverted**, so the sync arrives as `0001`
//! (`fffe ^ ffff`); we accept both. Only CRC-valid 0x7x event frames are yielded.

/// A CRC-valid 0x7x event frame, with the fields cracking and decoding need.
pub(crate) struct Frame {
    pub(crate) subtype: u8, // frame[2]: 0x7a contact, 0x72 heartbeat, ...
    pub(crate) counter: u16,
    pub(crate) status: u8, // frame[5], keystreamed (XOR c1)
    byte10: u8,            // high nibble carries (c3 ^ 0x10)
    id: [u8; 4],           // frame[6..10]
}

impl Frame {
    /// The on-air observation used for cracking: (counter, byte10 high nibble).
    pub(crate) fn observation(&self) -> (u16, u8) {
        (self.counter, self.byte10 & 0xf0)
    }

    /// The printed device label, e.g. "XXXX-XXX-XXXX", from the id bytes.
    pub(crate) fn txid(&self) -> String {
        let p1 = (u32::from(self.id[0]) << 4) | (u32::from(self.id[1]) >> 4);
        let p2 = (u32::from(self.id[1] & 0x0f) << 16)
            | (u32::from(self.id[2]) << 8)
            | u32::from(self.id[3]);
        format!("{:04}-{:03}-{:04}", p1, p2 / 10000, p2 % 10000)
    }
}

/// CRC-16, MSB-first, poly 0x8050, init 0 (firmware `crc16_8050`).
fn crc16_8050(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x8050
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 24 hex chars -> 12 bytes.
fn hex12(hex: &str) -> Option<[u8; 12]> {
    let b = hex.as_bytes();
    if b.len() < 24 {
        return None;
    }
    let mut raw = [0u8; 12];
    for i in 0..12 {
        raw[i] = (hex_val(b[2 * i])? << 4) | hex_val(b[2 * i + 1])?;
    }
    Some(raw)
}

/// Parse a 12-byte frame if it is a `fffe` + 0x7x event with a valid 12-bit check.
fn parse_frame(raw: &[u8; 12]) -> Option<Frame> {
    if raw[0] != 0xff || raw[1] != 0xfe || raw[2] & 0xf0 != 0x70 {
        return None;
    }
    // 0x7x 12-bit packed check: CRC over bytes 2..10 + (byte10 & 0xf0), top 12 bits.
    let mut crc_input = [0u8; 9];
    crc_input[..8].copy_from_slice(&raw[2..10]);
    crc_input[8] = raw[10] & 0xf0;
    let calc12 = crc16_8050(&crc_input) >> 4;
    let stored12 = (u16::from(raw[10] & 0x0f) << 8) | u16::from(raw[11]);
    if calc12 != stored12 {
        return None; // only surface CRC-valid frames
    }
    Some(Frame {
        subtype: raw[2],
        counter: (u16::from(raw[3]) << 8) | u16::from(raw[4]),
        status: raw[5],
        byte10: raw[10],
        id: [raw[6], raw[7], raw[8], raw[9]],
    })
}

/// Every CRC-valid 0x7x event frame in a line, in order. Handles both normal
/// (`fffe…`) and bit-inverted (`0001…`) polarities.
pub(crate) fn frames_in_line(line: &str) -> Vec<Frame> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if hex_val(b[i]).is_none() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && hex_val(b[i]).is_some() {
            i += 1;
        }
        let run = &line[start..i];
        let hit = run
            .find("fffe")
            .or_else(|| run.find("FFFE"))
            .map(|p| (p, false))
            .or_else(|| run.find("0001").map(|p| (p, true)));
        if let Some((pos, inverted)) = hit
            && let Some(mut raw) = hex12(&run[pos..])
        {
            if inverted {
                for byte in &mut raw {
                    *byte ^= 0xff;
                }
            }
            if let Some(f) = parse_frame(&raw) {
                out.push(f);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public rtl_433 #1504 frame, both polarities (fffe… direct, 0001… inverted).
    const DIRECT: &str = "fffe7a001bec0137bedadb5d"; // counter 27, byte10 0xdb
    const INVERTED: &str = "000185ffe413fec8412524a2"; // == DIRECT ^ 0xff

    #[test]
    fn parses_valid_and_rejects_bad() {
        let f = &frames_in_line(DIRECT)[0];
        assert_eq!(f.counter, 27);
        assert_eq!(f.byte10, 0xdb);
        assert_eq!(f.subtype, 0x7a);
        // flipped last byte -> CRC fails; d0 startup -> not a 0x7x
        assert!(frames_in_line("fffe7a001bec0137bedadb5e").is_empty());
        assert!(frames_in_line("fffed0000000000000000000").is_empty());
    }

    #[test]
    fn extracts_from_json_csv_plain() {
        assert_eq!(
            frames_in_line(&format!(r#"{{"rows":[{{"data":"{DIRECT}"}}]}}"#))[0].counter,
            27
        );
        assert_eq!(
            frames_in_line(&format!("2,1768243657.59,96,{DIRECT},0.08,false,6"))[0].counter,
            27
        );
        assert!(frames_in_line("rtl_433 startup, no frame here").is_empty());
    }

    #[test]
    fn accepts_bit_inverted_frames() {
        // Opposite OOK polarity: `0001…` = `fffe…` ^ 0xff (github rtl_433 #1504).
        let f = &frames_in_line(&format!("{{96}}{INVERTED}"))[0];
        assert_eq!(f.subtype, 0x7a);
        assert_eq!(f.counter, 27);
    }
}
