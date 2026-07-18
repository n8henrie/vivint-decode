# vivint-decode

Recover and use the **16-bit secret seed** of a Vivint 345 MHz door sensor, working only from rtl_433 captures. The seed is the sensor's only root entropy; recover it once and you can interpret the sensor's transmissions.

Vibe-coded by Claude Opus, mostly in June / July 2026.

Validated byte-exact against an emulator oracle over 150+ seeds.

Context: <https://github.com/merbanan/rtl_433/issues/1504>

## Quickstart

```console
$ rtl_433 -f 345M -X 'n=v,m=OOK_MC_ZEROBIT,s=133,l=133,r=500,invert' -F json:capture0.json
$ cargo build --release
$ target/release/vivint-decode crack capture0.json capture1.json capture2.json
#   collected 74 distinct-counter observation(s) (min counter = Some(25))
#   recovered seed: 0x1234
$
$ target/release/vivint-decode decode 0x1234 capture.json
#   txid=XXXX-XXX-XXXX counter=   25 type=7a contact=open
#   txid=XXXX-XXX-XXXX counter=   27 type=7a contact=closed
```

Input is format-agnostic — each line is scanned for a `fffe…` (or bit-inverted
`0001…`) hex run and CRC-checked, so rtl_433 JSON/CSV/codes/plain hex all work,
live or saved. `decode` emits one line per event (contact open/closed, decoded by
un-keying the status byte with the seed) and collapses repeats.

## Capturing for a fast crack

The counter increments per **event** and entropy resets only at power-up, so:

1. **Power-cycle the sensor** (battery pull) — counters restart near 24.
2. **Toggle the reed switch ~10–12 times** (or let heartbeats run) for distinct
   low counters.
3. Feed the capture in.

~8–12 distinct low counters pin the seed (each frame's byte-10 nibble gives 4
bits; the seed is 16). A capture starting at a high counter still works but the
brute force replays from event entry for every candidate (slower — `crack` warns).
If more than one candidate survives, capture more low-counter frames.

## Scope

Validated on the DW21R-family door sensor.
