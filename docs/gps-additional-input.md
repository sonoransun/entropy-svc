# GPS Subframe 4/Page 17 additional-input

The `gps` feature folds the GPS LNAV **Subframe 4, Page 17** "Special
Message" field into mixrand's output as a NIST SP 800-90A **additional
input / personalization string**. No compile-time dependencies — the
feature only adds runtime acquisition plumbing in `src/entropy/gps.rs`.

> **This is not an entropy source.** It is a *mix-in*, credited **0 bits**
> of entropy. If you want more *entropy*, add an HSM/TPM/CPU source — see
> [entropy-sources.md](entropy-sources.md). This page is about a defense-in-depth
> personalization value, not an entropy contributor.

## What it is — and what it is NOT

GPS satellites broadcast a navigation message in 1500-bit frames of five
300-bit subframes. Subframes 4 and 5 are subcommutated into 25 pages;
**Subframe 4, Page 17** is the "Special Message" page — 22 eight-bit ASCII
characters (176 bits) the control segment can use for free-text messages.

| Property | Reality |
|---|---|
| Secrecy | **None.** Broadcast in the clear, worldwide. |
| Per-receiver uniqueness | **None.** Every receiver on Earth decodes the *same* 22 bytes. |
| Predictability to an attacker | **Total.** Anyone with a GPS receiver (or online almanac data) has it. |
| Real entropy contributed | **~0 bits.** |

So mixrand never treats it as entropy. It is a **personalization string**:
a public value mixed in for domain separation / defense-in-depth that the
tool relies on for *nothing*.

> ⚠️ If you came here expecting GPS to *add randomness*, it cannot. The
> decoded field is a public constant; only the analog RF/ADC noise of an
> SDR capture would be unpredictable, and that is explicitly **not** what
> this field is. Treating broadcast data as entropy is a classic
> RNG-design trap; mixrand is built to make that mistake impossible here.

## How the fold works (and why it is safe)

After `generate()` selects a strong source and it passes the SP 800-90B
health check, the output becomes:

```
output = primary XOR keystream
keystream = ChaCha20( key = BLAKE2b("gps-sf4p17" ‖ field) )   # public, deterministic
```

Because the keystream is a function of *public* data only:

- **Entropy-neutral.** XOR with a value independent of the primary cannot
  raise or lower the primary's entropy. The output is information-theoretically
  equivalent to the primary and is recoverable as `output XOR mask`.
- **0-bit credit.** In daemon mode, kernel-pool crediting stays based on
  the primary (`batch_size`); the GPS field adds 0 credited bits.
- **Never selectable / never graded.** `gps-sf4p17` is in *no* source
  cascade, never wins selection, and never enters `check`'s FIPS/entropy
  grading or the daemon start-up self-test.
- **Never blocks.** Acquisition has a hard timeout and a byte cap; on
  timeout/short-read/length-mismatch the field is skipped and generation
  proceeds with the primary unchanged.

When the field is folded, the source label reflects it, e.g.
`Hardware RNG (/dev/hwrng) + gps-sf4p17 (0-bit addin)`.

## Requirements

- Build with `--features gps` (no system libraries).
- A GNSS receiver plus a decoder that exposes **raw subframes** —
  Subframe 4/Page 17 is *not* in standard NMEA, so plain `gpsd` will not
  do. Workable sources:
  - **u-blox** receivers via `ubxtool` (UBX-RXM-SFRBX raw subframe words),
  - **gnss-sdr** (software-defined receiver) with raw nav-message output,
  - a **custom RTL-SDR** L1 C/A decoder.
- A small **collector** process that decodes the latest Page 17 and writes
  the 22-byte field to a file/FIFO (recommended) or echoes it on stdout.

Because a *live* Page 17 only repeats once per ~12.5-minute almanac
supercycle, mixrand must read a **cached** value — the collector keeps the
cache fresh out-of-band; mixrand's read is fast and non-blocking.

## Configuration

TOML (`[hsm.gps]` — under `[hsm.*]` only for plumbing reuse; it is not an HSM):

```toml
[hsm.gps]
enabled = false                                 # off by default
# command = "/usr/local/bin/gps-sf4p17-cache"   # stdout = field (run via `sh -c`); takes precedence
# path = "/run/gps/sf4p17"                       # file/FIFO with the field (used if command unset)
timeout_ms = 2000                               # acquisition timeout (never blocks generation)
expected_len = 22                               # 176 bits = 22 bytes; mismatch => skipped
```

Environment variables:

```
MIXRAND_GPS_ENABLED=true
MIXRAND_GPS_COMMAND=/usr/local/bin/gps-sf4p17-cache
MIXRAND_GPS_PATH=/run/gps/sf4p17
MIXRAND_GPS_TIMEOUT_MS=2000
MIXRAND_GPS_EXPECTED_LEN=22
```

CLI flags (on every subcommand): `--enable-gps [BOOL]`, `--gps-command <CMD>`,
`--gps-path <PATH>`.

> The producer must emit **exactly `expected_len` bytes** (22) with **no
> trailing newline**. A longer or shorter read is treated as unavailable.

## Worked examples

### 1. Test the wiring with no hardware (mock)

```bash
cargo build --release --features gps

# A fixed 22-byte "field" (exactly 22 bytes, no newline)
printf 'MIXRAND-GPS-TEST-PAGE7' > /tmp/sf4p17
test "$(wc -c < /tmp/sf4p17)" -eq 22 && echo "ok: 22 bytes"

# It shows up as an informational additional-input (not a graded source)
MIXRAND_GPS_ENABLED=true MIXRAND_GPS_PATH=/tmp/sf4p17 \
  ./target/release/mixrand list-sources | grep gps

# Generation folds it in (note the "+ gps-sf4p17 (0-bit addin)" source label)
MIXRAND_GPS_ENABLED=true MIXRAND_GPS_PATH=/tmp/sf4p17 \
  ./target/release/mixrand -n 32 -f hex -v
```

The repo ships a ready-made collector with a self-test mode:

```bash
# Emits a deterministic 22-byte value (no GNSS hardware needed)
examples/gps-sf4p17-collector.sh --self-test > /tmp/sf4p17
```

### 2. Real receiver feeding a FIFO

```bash
# Create the FIFO mixrand will read
mkfifo /run/gps/sf4p17

# Run your decoder→cache loop in the background (see examples/gps-sf4p17-collector.sh
# for a skeleton you adapt to ubxtool / gnss-sdr / your RTL-SDR decoder)
examples/gps-sf4p17-collector.sh --fifo /run/gps/sf4p17 &

# Point mixrand at the FIFO
MIXRAND_GPS_ENABLED=true MIXRAND_GPS_PATH=/run/gps/sf4p17 \
  mixrand -n 32 -f hex -v
```

### 3. Alongside the daemon (systemd)

Run the collector as its own unit and let `mixrand daemon` consume the cache.
Configure GPS in `/etc/mixrand.toml` (`[hsm.gps]`) so the daemon picks it up,
or pass `MIXRAND_GPS_*` in the unit's `Environment=`:

```ini
# /etc/systemd/system/gps-sf4p17-collector.service
[Unit]
Description=GPS Subframe 4/Page 17 collector for mixrand
Before=mixrand.service

[Service]
ExecStart=/usr/local/bin/gps-sf4p17-collector.sh --fifo /run/gps/sf4p17
Restart=always

[Install]
WantedBy=multi-user.target
```

The daemon credits **0** extra entropy bits for the GPS fold — its
`--credit-ratio` accounting is unchanged.

## Verification

```bash
mixrand list-sources | grep gps          # "available" when the cache is fresh, else "skip"
mixrand check --duration 5s              # GPS shown as "0-bit, not graded", absent from sources=[…]
mixrand -n 32 -f hex -v                  # source log shows "+ gps-sf4p17 (0-bit addin)" when folded
```

Confirm graceful degradation — generation must succeed even with GPS
mis-wired:

```bash
# Writer-less FIFO: generation returns promptly (does not hang) using the primary only
mkfifo /tmp/gps.fifo
MIXRAND_GPS_ENABLED=true MIXRAND_GPS_PATH=/tmp/gps.fifo MIXRAND_GPS_TIMEOUT_MS=300 \
  mixrand -n 16 -f hex -v                # no "addin" in the source label; quick return
```

## Troubleshooting

- **`list-sources` shows `skip` / `unavailable`**: the collector is not
  running, the cache is stale/empty, or the value is not exactly 22 bytes.
  Check the file/FIFO contents (`wc -c`) and that the decoder is producing
  Page 17.
- **`gps field length N != expected 22`**: your producer added a trailing
  newline or emitted the wrong field. Emit exactly 22 raw bytes (e.g.
  `printf '%s' "$field" | head -c 22`).
- **Generation seems slow when GPS is enabled**: lower `timeout_ms`
  (default 2000). Generation never *fails* due to GPS, but it will wait up
  to the timeout for a configured-but-unavailable source.
- **"Is this making my output more random?"**: No — and that is by design.
  It is a 0-bit personalization mix-in. For more entropy, enable a real
  source (TPM2, PKCS#11, hwrng, CPU RNG).
- **Debug logging**: run with `--log-level debug` to see the
  `gps additional-input unavailable: …` reason when the field is skipped.
```
