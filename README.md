# mixrand

Secure random byte generator that mixes multiple entropy sources cryptographically before output.

## Features

- **Multi-source entropy**: Tries hardware RNG, CPU instructions (RDSEED/RDRAND/XSTORE), haveged, and a fallback mixer — in priority order
- **Cryptographic mixing**: All entropy is mixed through BLAKE2b-256 with domain separation, then expanded via ChaCha20
- **9 output formats**: hex, hex-upper, raw, base64, base64url, uuencode, text, octal, binary
- **Daemon mode**: Monitors the Linux kernel entropy pool and injects mixed entropy when it runs low
- **Statistical validation**: Built-in FIPS 140-2 test suite and entropy metrics via `mixrand check`
- **Structured logging**: Configurable log level with stderr, file, and syslog backends
- **Security hardened**: Intermediate buffers are volatile-zeroized; unsafe code is limited to inline x86_64 asm, volatile writes, and libc FFI

## High-Level Overview

```mermaid
flowchart LR
    subgraph Modes["Operating Modes"]
        A["One-Shot<br/><i>mixrand -n 64</i>"]
        B["Daemon<br/><i>mixrand daemon</i>"]
        C["Check<br/><i>mixrand check</i>"]
    end

    subgraph Core["Core Pipeline"]
        D["Entropy<br/>Sources"]
        E["BLAKE2b-256<br/>Mixer"]
        F["ChaCha20<br/>CSPRNG"]
    end

    A --> D
    B --> D
    C --> D
    D --> E --> F

    A -- "formatted bytes" --> G["stdout / file"]
    B -- "ioctl inject" --> H["Kernel Pool"]
    C -- "FIPS 140-2 +<br/>entropy metrics" --> I["Report"]
```

## Entropy Pipeline

Mixrand tries entropy sources in priority order, falling through to the next if one is unavailable. The first source that succeeds provides the output.

```mermaid
flowchart TD
    Start([Generate Request]) --> HW{"/dev/hwrng<br/>available?"}

    HW -- Yes --> HWOut["Read /dev/hwrng"]
    HW -- No --> CPU{"CPU RNG<br/>available?"}

    CPU -- Yes --> CPUCollect["Collect via<br/>RDSEED / RDRAND / XSTORE"]
    CPUCollect --> Oversample{"Oversample<br/>ratio > 1?"}
    Oversample -- Yes --> CPUMix["Collect N× bytes<br/>→ BLAKE2b → ChaCha20"]
    Oversample -- No --> CPURaw["Raw CPU bytes"]
    CPU -- No --> HAV{"haveged<br/>running?"}

    HAV -- Yes --> HAVCheck{"Kernel entropy<br/>≥ 1024 bits?"}
    HAVCheck -- Yes --> HAVRead["Non-blocking read<br/>/dev/random"]
    HAVCheck -- No --> FB
    HAV -- No --> FB

    FB["Fallback Mixer"] --> FBSources
    subgraph FBSources["Collect & Mix"]
        direction LR
        U["/dev/urandom<br/>32 bytes"]
        P["/proc entropy<br/>interrupts, stat,<br/>diskstats"]
        J["CPU jitter<br/>64 timing samples"]
        CR["CPU RNG<br/>best-effort"]
    end

    FBSources --> Mix["BLAKE2b-256<br/>domain-separated hash"]
    Mix --> CSPRNG["ChaCha20Rng<br/>expand to N bytes"]
    CSPRNG --> Zero["Zeroize all<br/>intermediate buffers"]

    HWOut --> Output
    CPUMix --> Output
    CPURaw --> Output
    HAVRead --> Output
    Zero --> Output([Output Bytes])
```

## Cryptographic Mixing

All entropy — whether from the fallback path or the CPU RNG oversample path — passes through a two-stage construction: compression via BLAKE2b-256, then expansion via ChaCha20.

```mermaid
flowchart LR
    subgraph Inputs["Labeled Inputs"]
        direction TB
        I1["('urandom', 32B)"]
        I2["('interrupts', ~4KB)"]
        I3["('stat', ~2KB)"]
        I4["('diskstats', ~1KB)"]
        I5["('jitter', 512B)"]
        I6["('cpu-rng', 0-1024B)"]
    end

    Inputs --> B2["BLAKE2b-256<br/><br/>Domain tag:<br/>'mixrand-entropy-v1'<br/><br/>Each input:<br/>len(label) ‖ label ‖<br/>len(data) ‖ data"]

    B2 -- "32-byte seed" --> CC["ChaCha20Rng<br/>deterministic<br/>expansion"]

    CC -- "N bytes" --> Out([Output])
```

## Daemon Mode

The daemon monitors the Linux kernel entropy pool and injects freshly mixed entropy when it drops below a configurable threshold.

```mermaid
flowchart TD
    Start([Start Daemon]) --> Validate["Validate /dev/random<br/>write permissions"]
    Validate --> Signals["Install SIGTERM/SIGINT<br/>signal handlers"]
    Signals --> Loop

    Loop{"SHUTDOWN<br/>signal?"}
    Loop -- No --> Read["Read<br/>/proc/sys/kernel/random/<br/>entropy_avail"]
    Read --> Check{"entropy_avail<br/>< threshold?"}

    Check -- Yes --> Gen["Generate entropy<br/>via fallback mixer"]
    Gen --> Inject["ioctl(RNDADDENTROPY)<br/>inject into kernel pool"]
    Inject --> Sleep
    Check -- No --> Sleep["Interruptible sleep<br/>(250ms steps)"]
    Sleep --> Loop

    Loop -- Yes --> Shutdown([Graceful Shutdown])
```

## Statistical Validation (`mixrand check`)

The `check` subcommand probes all available entropy sources and runs continuous statistical tests against each one, then produces a comparative report.

```mermaid
flowchart TD
    Start([mixrand check]) --> Probe["Probe available<br/>entropy sources"]
    Probe --> Filter{"Source filter<br/>specified?"}
    Filter -- Yes --> Select["Keep matching sources"]
    Filter -- No --> All["Use all available"]
    Select --> TestLoop
    All --> TestLoop

    TestLoop["For each source,<br/>collect sample"] --> FIPS{"Sample<br/>≥ 2500 bytes?"}

    FIPS -- Yes --> FIPSTests["FIPS 140-2 Suite<br/>• Monobit<br/>• Poker<br/>• Runs<br/>• Long Runs"]
    FIPS -- No --> Entropy

    FIPSTests --> Entropy["Entropy Metrics<br/>• Shannon entropy<br/>• Min-entropy<br/>• Chi-square<br/>• Mean byte value<br/>• Serial correlation"]

    Entropy --> Progress{"Report interval<br/>elapsed?"}
    Progress -- Yes --> Print["Print progress table"]
    Progress -- No --> TimeCheck
    Print --> TimeCheck

    TimeCheck{"Duration<br/>complete?"}
    TimeCheck -- No --> TestLoop
    TimeCheck -- Yes --> Report(["Final Report<br/>per-source stats +<br/>comparison table"])
```

## Configuration Layering

Three configuration layers merge in order — later layers override earlier ones.

```mermaid
flowchart LR
    D["Defaults<br/><code>CpuRngConfig::default()</code>"] --> T["TOML File<br/><code>/etc/mixrand.toml</code>"]
    T --> C["CLI Flags<br/><code>--enable-rdseed</code>, etc."]
    C --> Final(["Final Config<br/><i>validated & clamped</i>"])
```

CLI fields use `Option<T>` so "not set" is distinguishable from "set to default value". Only explicitly-set fields override earlier layers.

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

### Statistical validation

Run FIPS 140-2 tests and entropy metrics against each available source.

```bash
mixrand check                            # 1 minute, all sources
mixrand check -d 5m                      # 5 minutes
mixrand check --sources=rdseed,rdrand    # specific sources only
mixrand check -d 30s -r 5               # 30s, report every 5s
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

## Security

- All intermediate entropy buffers are volatile-zeroized with `SeqCst` fence
- Unsafe code is limited to: inline x86_64 asm (CPUID/RDRAND/RDSEED/XSTORE), volatile writes for zeroization, libc FFI (ioctl, clock_gettime, sigaction)
- Entropy mixing uses BLAKE2b-256 with domain separation and length-prefixed inputs to prevent canonicalization attacks
- Output expansion uses ChaCha20, a well-studied stream cipher

## License

See repository for license information.
