# mixrand

Secure random byte generator that mixes multiple entropy sources cryptographically before output.

## Features

- **Multi-source entropy**: Tries hardware RNG, CPU instructions (RDSEED/RDRAND/XSTORE), haveged, and a fallback mixer — in priority order
- **Cryptographic mixing**: All entropy is mixed through BLAKE2b-256 with domain separation, then expanded via ChaCha20
- **9 output formats**: hex, hex-upper, raw, base64, base64url, uuencode, text, octal, binary
- **Daemon mode**: Monitors the Linux kernel entropy pool and injects mixed entropy when it runs low
- **Structured logging**: Configurable log level with stderr, file, and syslog backends
- **Security hardened**: Intermediate buffers are volatile-zeroized; unsafe code is limited to inline x86_64 asm, volatile writes, and libc FFI

## Installation

```bash
cargo build --release
sudo cp target/release/mixrand /usr/local/bin/
```

## Usage

### Generate random bytes

```bash
# 32 bytes as hex (default)
mixrand

# 64 bytes as raw binary
mixrand -n 64 -f raw

# 16 bytes as base64
mixrand -n 16 -f base64

# Write to file
mixrand -n 256 -o /tmp/random.bin
```

### Daemon mode

Monitors `/proc/sys/kernel/random/entropy_avail` and injects mixed entropy when the pool drops below threshold. Requires root.

```bash
sudo mixrand daemon
sudo mixrand daemon -t 512 -i 10 -b 128
```

### Logging

```bash
# Default: warn level for one-shot, info level for daemon
mixrand -n 32                                # no info output
mixrand -n 32 --log-level info               # shows entropy source
mixrand -n 32 --log-level debug              # shows fallback cascade details

# Log to file
mixrand -n 32 --log-file /tmp/mixrand.log

# Send to syslog (daemon mode)
sudo mixrand daemon --syslog --log-level debug
```

## Configuration

### TOML file

Default path: `/etc/mixrand.toml` (override with `--config`).

```toml
[cpu_rng]
enable_rdseed = true
enable_rdrand = true
enable_xstore = true
rdrand_retries = 10
rdseed_retries = 10
xstore_quality = 3
prefer = "rdseed"        # rdseed | rdrand | xstore
fallback_mix_bytes = 32  # CPU entropy bytes mixed into fallback (0-1024)
oversample = 2           # standalone CPU RNG oversample ratio (1-16)
```

### Configuration layering

Three layers merged in order — later layers override earlier:

1. **Defaults** — `CpuRngConfig::default()`
2. **TOML file** — `/etc/mixrand.toml` (or `--config <path>`)
3. **CLI flags** — `--enable-rdseed`, `--rdrand-retries`, etc.

## Architecture

```
entropy/mod.rs (source dispatch, priority-ordered)
  ├─ 1. hwrng.rs         → /dev/hwrng
  ├─ 2. cpurng.rs         → RDSEED / RDRAND / XSTORE (x86_64 inline asm, CPUID-gated)
  ├─ 3. haveged.rs        → /dev/random (only if haveged process detected)
  └─ 4. fallback.rs       → urandom + procfs + jitter + cpu-rng
                              ↓
                           mixer.rs (BLAKE2b-256, domain-separated, length-prefixed)
                              ↓
                           csprng.rs (ChaCha20Rng seeded from 32-byte BLAKE2b output)
                              ↓
                           output.rs (9 formats)
```

## Security

- All intermediate entropy buffers are volatile-zeroized with `SeqCst` fence
- Unsafe code is limited to: inline x86_64 asm (CPUID/RDRAND/RDSEED/XSTORE), volatile writes for zeroization, libc FFI (ioctl, clock_gettime, sigaction)
- Entropy mixing uses BLAKE2b-256 with domain separation and length-prefixed inputs to prevent canonicalization attacks
- Output expansion uses ChaCha20, a well-studied stream cipher

## License

See repository for license information.
