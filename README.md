# vivint-decode

Recover and use the **16-bit secret seed** of a Vivint 345 MHz door sensor, working only from rtl_433 captures.
The seed is the sensor's only root entropy; recover it once and you can interpret the sensor's transmissions.

Validated byte-exact against an emulator oracle over 150+ seeds.

Context: <https://github.com/merbanan/rtl_433/issues/1504>

## LLM Policy

Caveat emptor: This project was almost entirely vibe-coded with Claude Opus, mostly in June / July 2026.
In spite of this, I generally do not care for LLM-generated or LLM-assisted contributions.
Please divulge LLM involvement in any communication or code, and note that issues, PR, or other contributions may (or may not) be closed on this basis alone, with or without additional feedback from me.

## Quickstart

```console
$ rtl_433 -f 345M -X 'n=v,m=OOK_MC_ZEROBIT,s=133,l=133,r=500,invert' -F json:capture0.json
$ cargo build --release
$ target/release/vivint-decode crack test-series-0019-050-7610.json
recovered seed: 0x05c9    rtl_433: -R 342:0019-0507610=05c9
  txid 0019-050-7610 — 144 packets analyzed, 6 distinct counters, earliest counter 25
$ target/release/vivint-decode decode 342:0019-0507610=05c9 test-series-0019-050-7610.json
txid=0019-050-7610 counter=00025 type=7a status=84 loop1=open loop2=closed tamper=no alarm=no batt=ok hb=yes
txid=0019-050-7610 counter=00026 type=7a status=80 loop1=open loop2=closed tamper=no alarm=no batt=ok hb=no
txid=0019-050-7610 counter=00027 type=7a status=04 loop1=closed loop2=closed tamper=no alarm=no batt=ok hb=yes
txid=0019-050-7610 counter=00028 type=7a status=80 loop1=open loop2=closed tamper=no alarm=no batt=ok hb=no
txid=0019-050-7610 counter=00029 type=7a status=04 loop1=closed loop2=closed tamper=no alarm=no batt=ok hb=yes
txid=0019-050-7610 counter=00030 type=7a status=84 loop1=open loop2=closed tamper=no alarm=no batt=ok hb=yes
decoded 6 event(s)
```

Input is format-agnostic — each line is scanned for a `fffe…` (or bit-inverted `0001…`) hex run and CRC-checked, so rtl_433 JSON/CSV/codes/plain hex all work, live or saved.
`decode` emits one line per event (contact open/closed, decoded by un-keying the status byte with the seed) and collapses repeats.

Multiple devices can be cracked or decoded simultaneously (multiple files as arguments or via stdin):

```console
$ cat *.json | target/release/vivint-decode crack
...
all 4 devices    rtl_433: -R 342:0016-0345744=1e35,0016-0357157=e4d8,0019-0507610=05c9,0019-0507743=dda9
$ cat *.json | target/release/vivint-decode 0016-0345744=1e35,0016-0357157=e4d8,0019-0507610=05c9,0019-0507743=dda9
```

The `rtl_433:` output above is formatted for easy decoding with rtl433 as an alternative.

## Capturing for a fast crack

The counter increments per **event** and entropy resets only at power-up, so:

1. **Power-cycle the sensor** (battery pull) — counters restart near 24.
2. **Toggle the reed switch ~10–12 times** (or let heartbeats run) for distinct low counters.
3. Feed the capture in.

~8–12 distinct low counters pin the seed (each frame's byte-10 nibble gives 4 bits; the seed is 16).
A capture starting at a high counter still works but the brute force replays from event entry for every candidate (slower — `crack` warns).
If more than one candidate survives, capture more low-counter frames.

## Scope

Validated on the DW21R-family door sensor.

Supports cracking and decoding multiple sensors.
