# mixrand

Secure random byte generator that mixes multiple entropy sources cryptographically before output. Cross-platform (x86_64 + AArch64), security-hardened, with a Linux kernel entropy daemon and comprehensive statistical validation.

## Features

- **Multi-source entropy**: Priority-ordered cascade across hardware RNG, CPU instructions (RDSEED, RDRAND, XSTORE, RNDR, RNDRRS), haveged, getrandom syscall, and a fallback mixer
- **Cross-platform CPU RNG**: x86_64 (RDSEED/RDRAND/XSTORE via inline asm) and AArch64 (RNDR/RNDRRS for Apple Silicon and ARM servers)
- **Dual mixer modes**: BLAKE2b-256 single-pass (default) or HKDF-style two-stage extract-then-expand for low-entropy inputs
- **ChaCha20 CSPRNG**: Deterministic expansion with automatic reseeding every 1 MiB for large requests
- **9 output formats**: hex, hex-upper, raw, base64, base64url, uuencode, text, octal, binary
- **Daemon mode**: Monitors the Linux kernel entropy pool with adaptive injection rate, PID file management, privilege dropping, SIGHUP config reload, and systemd sd_notify support
- **Statistical validation**: FIPS 140-2 suite + NIST SP 800-90B health testing + advanced entropy metrics (ApEn, Lempel-Ziv, block entropy, multi-lag autocorrelation) with JSON/CSV output
- **Security hardened**: Volatile zeroization with `SeqCst` fence, mlock/MADV_DONTDUMP for sensitive buffers, privilege dropping, domain-separated mixing
- **Structured logging**: RFC 3339 timestamps, text or JSON format, stderr + file + syslog outputs
- **Flexible configuration**: Four-layer merge (defaults → TOML → environment variables → CLI flags)

## High-Level Architecture

```mermaid
flowchart LR
    subgraph Modes["Operating Modes"]
        A["<b>Generate</b><br/><code>mixrand -n 64</code>"]
        B["<b>Daemon</b><br/><code>mixrand daemon</code>"]
        C["<b>Check</b><br/><code>mixrand check</code>"]
        D["<b>List Sources</b><br/><code>mixrand list-sources</code>"]
        E["<b>Completions</b><br/><code>mixrand completions bash</code>"]
    end

    subgraph Core["Core Pipeline"]
        F["Entropy Sources<br/><i>trait EntropySource</i>"]
        G["Mixer<br/><i>BLAKE2b or HKDF</i>"]
        H["CSPRNG<br/><i>ChaCha20 + reseed</i>"]
    end

    subgraph Security["Security Layer"]
        I["mlock + MADV_DONTDUMP"]
        J["Volatile zeroization"]
        K["Health testing"]
    end

    A --> F
    B --> F
    C --> F
    F --> G --> H
    Security -.-> Core

    A -- "formatted bytes" --> L["stdout / file"]
    B -- "ioctl inject" --> M["Kernel Pool"]
    C -- "text / json / csv" --> N["Report"]
```

## Entropy Source Cascade

Mixrand tries entropy sources in priority order. The first source that succeeds provides the output. Each source implements the `EntropySource` trait, enabling runtime discovery, filtering, and mock testing.

```mermaid
flowchart TD
    Start([Generate Request]) --> HW{"/dev/hwrng<br/>available?"}

    HW -- Yes --> HWOut["Read /dev/hwrng<br/><i>Priority 10</i>"]
    HW -- No --> CPU{"CPU RNG<br/>available?"}

    CPU -- Yes --> CPUCollect["Collect via preferred instruction<br/><i>Priority 20</i>"]

    subgraph CPUInstructions["CPU Instruction Priority"]
        direction LR
        RS["RDSEED<br/><i>x86_64</i>"]
        RR["RDRAND<br/><i>x86_64</i>"]
        XS["XSTORE<br/><i>VIA PadLock</i>"]
        RN["RNDR<br/><i>AArch64</i>"]
        RNR["RNDRRS<br/><i>AArch64 reseed</i>"]
    end

    CPUCollect --> CPUInstructions
    CPUCollect --> Oversample{"Oversample<br/>ratio > 1?"}
    Oversample -- Yes --> CPUMix["Collect N× bytes<br/>→ BLAKE2b → ChaCha20"]
    Oversample -- No --> CPURaw["Raw CPU bytes"]
    CPU -- No --> HAV{"haveged<br/>running?"}

    HAV -- Yes --> HAVCheck{"Kernel entropy<br/>≥ 1024 bits?"}
    HAVCheck -- Yes --> HAVRead["Non-blocking read<br/>/dev/random<br/><i>Priority 30</i>"]
    HAVCheck -- No --> FB
    HAV -- No --> FB

    FB["Fallback Mixer<br/><i>Priority 40</i>"] --> FBSources
    subgraph FBSources["Collect & Mix All Available"]
        direction LR
        GR["getrandom(2) /<br/>getentropy(3)"]
        U["/dev/urandom<br/>32 bytes"]
        P["/proc entropy<br/>interrupts, stat,<br/>diskstats"]
        J["CPU jitter<br/>64 timing samples"]
        CR["CPU RNG<br/>best-effort"]
    end

    FBSources --> Mix["Mixer<br/><i>BLAKE2b-256 or HKDF</i>"]
    Mix --> CSPRNG["ChaCha20Rng<br/>expand to N bytes<br/><i>reseed every 1 MiB</i>"]
    CSPRNG --> Zero["Zeroize all<br/>intermediate buffers"]

    HWOut --> Output
    CPUMix --> Output
    CPURaw --> Output
    HAVRead --> Output
    Zero --> Output([Output Bytes])
```

## Cryptographic Mixing

All entropy passes through a two-stage construction: compression via a cryptographic hash, then expansion via ChaCha20. Two mixer modes are available.

```mermaid
flowchart LR
    subgraph Inputs["Labeled Inputs"]
        direction TB
        I1["('getrandom', 32B)"]
        I2["('urandom', 32B)"]
        I3["('interrupts', ~4KB)"]
        I4["('stat', ~2KB)"]
        I5["('diskstats', ~1KB)"]
        I6["('jitter', 512B)"]
        I7["('cpu-rng', 0-1024B)"]
    end

    subgraph MixerChoice["Mixer Mode"]
        B2["<b>BLAKE2b-256</b><br/><i>Default</i><br/><br/>Domain tag:<br/>'mixrand-entropy-v1'<br/><br/>Each input:<br/>len(label) ‖ label ‖<br/>len(data) ‖ data"]
        HK["<b>HKDF</b><br/><i>Extract-then-Expand</i><br/><br/>Extract: two-pass<br/>BLAKE2b with counter<br/><br/>Expand: HKDF-Expand<br/>with counter bytes"]
    end

    Inputs --> B2
    Inputs --> HK

    B2 -- "32-byte seed" --> CC["ChaCha20Rng<br/>deterministic expansion<br/><i>reseeds every 1 MiB</i>"]
    HK -- "variable-length key" --> CC

    CC -- "N bytes" --> Out([Output])
```

## Security Model

```mermaid
flowchart TD
    subgraph Threats["Threat Mitigations"]
        direction TB
        T1["<b>Cold Boot / Core Dump</b><br/>mlock prevents swap<br/>MADV_DONTDUMP excludes core<br/>Volatile zeroize + SeqCst fence"]
        T2["<b>Weak Entropy Source</b><br/>Multi-source mixing<br/>Domain-separated hashing<br/>Length-prefixed inputs<br/>SP 800-90B health tests"]
        T3["<b>Large Request Exhaustion</b><br/>ChaCha20 reseeds every 1 MiB<br/>Fresh entropy at each boundary"]
        T4["<b>Privilege Escalation</b><br/>Daemon drops to unprivileged user<br/>after opening /dev/random"]
    end

    subgraph Primitives["Cryptographic Primitives"]
        P1["BLAKE2b-256<br/><i>Compression</i>"]
        P2["HKDF Extract+Expand<br/><i>Low-entropy defense</i>"]
        P3["ChaCha20<br/><i>Expansion</i>"]
    end

    subgraph Unsafe["Unsafe Code Boundaries"]
        U1["Inline asm<br/><i>CPUID, RDRAND, RDSEED,<br/>XSTORE, RNDR, RNDRRS</i>"]
        U2["Volatile writes<br/><i>Zeroization</i>"]
        U3["libc FFI<br/><i>ioctl, mlock, sigaction,<br/>getpwnam, clock_gettime</i>"]
    end
```

## Daemon Mode

The daemon monitors the Linux kernel entropy pool and injects freshly mixed entropy with adaptive rate control, privilege dropping, PID management, and systemd integration.

```mermaid
flowchart TD
    Start([Start Daemon]) --> PID["Write PID file<br/><i>stale PID detection via kill(pid, 0)</i>"]
    PID --> Validate["Validate /dev/random<br/>write permissions"]
    Validate --> Signals["Install signal handlers<br/><i>SIGTERM/SIGINT → shutdown</i><br/><i>SIGHUP → config reload</i>"]
    Signals --> Notify["sd_notify(READY=1)<br/><i>if $NOTIFY_SOCKET set</i>"]
    Notify --> PrivDrop{"--user<br/>specified?"}
    PrivDrop -- Yes --> Drop["Drop privileges<br/><i>setgroups → setgid → setuid</i>"]
    PrivDrop -- No --> Loop
    Drop --> Loop

    Loop{"SHUTDOWN<br/>signal?"}
    Loop -- No --> Reload{"SIGHUP<br/>received?"}
    Reload -- Yes --> ReloadCfg["Re-read TOML config"]
    Reload -- No --> Read
    ReloadCfg --> Read

    Read["Read entropy_avail"] --> Rate{"Adaptive Rate"}

    Rate -- "< threshold/2" --> Fast["100ms sleep<br/><i>critical</i>"]
    Rate -- "< threshold" --> Medium["1s sleep<br/><i>low</i>"]
    Rate -- "≥ threshold" --> Normal["Normal interval<br/><i>healthy</i>"]

    Fast --> Gen
    Medium --> Gen
    Gen["Generate entropy<br/>via best available source"] --> Inject["ioctl(RNDADDENTROPY)<br/>inject into kernel pool"]
    Inject --> Heartbeat["Periodic heartbeat log<br/><i>uptime, injections, entropy level</i>"]
    Heartbeat --> Watchdog["sd_notify(WATCHDOG=1)"]
    Watchdog --> Loop
    Normal --> Loop

    Loop -- Yes --> Cleanup["Remove PID file"] --> Shutdown([Graceful Shutdown])
```

## Statistical Validation (`mixrand check`)

Probes all available entropy sources and runs continuous statistical tests against each one. Results are available as text, JSON, or CSV for CI/CD integration.

```mermaid
flowchart TD
    Start([mixrand check]) --> Probe["Probe entropy sources<br/><i>10 granular sources</i>"]
    Probe --> Filter{"--sources<br/>filter?"}
    Filter -- Yes --> Select["Keep matching sources"]
    Filter -- No --> All["Use all available"]
    Select --> TestLoop
    All --> TestLoop

    TestLoop["For each source,<br/>collect sample"] --> FIPS{"Sample<br/>≥ 2500 bytes?"}

    FIPS -- Yes --> FIPSTests
    FIPS -- No --> Entropy

    subgraph FIPSTests["FIPS 140-2 Suite"]
        direction TB
        F1["Monobit<br/><i>1-bit count in 20k bits</i>"]
        F2["Poker<br/><i>Chi-square on 4-bit nibbles</i>"]
        F3["Runs<br/><i>12 run-length categories</i>"]
        F4["Long Runs<br/><i>max run ≤ 25 bits</i>"]
    end

    FIPSTests --> Entropy

    subgraph Entropy["Entropy & Quality Metrics"]
        direction TB
        E1["Shannon entropy<br/>Min-entropy<br/>Chi-square (+ p-value)<br/>Mean byte value<br/>Serial correlation"]
        E2["<b>Advanced</b><br/>Approx. Entropy (m=2, m=3)<br/>Lempel-Ziv complexity<br/>Block entropy (2B, 4B)<br/>Multi-lag autocorrelation (16 lags)"]
    end

    Entropy --> Progress{"Report interval?"}
    Progress -- Yes --> Print["Print progress table"]
    Progress -- No --> TimeCheck
    Print --> TimeCheck

    TimeCheck{"Duration<br/>complete?"}
    TimeCheck -- No --> TestLoop
    TimeCheck -- Yes --> Format{"--output-format"}

    Format -- text --> TextReport(["Per-source stats +<br/>comparison table +<br/>verdict"])
    Format -- json --> JSONReport(["Structured JSON<br/>with all metrics"])
    Format -- csv --> CSVReport(["CSV header + rows<br/>one per source"])
```

## Configuration Layering

Four configuration layers merge in order — later layers override earlier ones.

```mermaid
flowchart LR
    D["<b>Defaults</b><br/><code>CpuRngConfig::default()</code>"]
    T["<b>TOML File</b><br/><code>/etc/mixrand.toml</code><br/><i>or --config path</i>"]
    E["<b>Environment</b><br/><code>MIXRAND_*</code> vars"]
    C["<b>CLI Flags</b><br/><code>--enable-rdseed</code>, etc."]

    D --> T --> E --> C --> Final(["Final Config<br/><i>validated & clamped</i>"])
```

CLI fields use `Option<T>` so "not set" is distinguishable from "set to default value". Only explicitly-set fields override earlier layers. Out-of-range values are clamped with a logged warning.

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

# 10 independent 32-byte keys
mixrand --count 10

# Write to file
mixrand -n 256 -o /tmp/random.bin

# Show effective merged configuration
mixrand --show-config
```

### Daemon mode

Monitors `/proc/sys/kernel/random/entropy_avail` and injects mixed entropy when the pool drops below threshold. Requires root.

```bash
# Basic usage
sudo mixrand daemon

# Custom thresholds and privilege dropping
sudo mixrand daemon -t 512 -i 10 -b 128 --user nobody

# With PID file and syslog
sudo mixrand daemon --pid-file /var/run/mixrand.pid --syslog
```

### Statistical validation

Run FIPS 140-2 tests and entropy metrics against each available source.

```bash
# 1 minute, all sources (default)
mixrand check

# 5 minutes
mixrand check -d 5m

# Specific sources only
mixrand check --sources=rdseed,rdrand

# 30 seconds, report every 5s, JSON output
mixrand check -d 30s -r 5 --output-format json

# CSV output for spreadsheets / CI pipelines
mixrand check -d 1m --output-format csv
```

### List available sources

```bash
mixrand list-sources
```

### Shell completions

```bash
# Generate completions for your shell
mixrand completions bash > /etc/bash_completion.d/mixrand
mixrand completions zsh > ~/.zfunc/_mixrand
mixrand completions fish > ~/.config/fish/completions/mixrand.fish
```

### Logging

```bash
# Verbose / quiet shortcuts
mixrand -v -n 32                            # debug level
mixrand -q -n 32                            # error level only

# Explicit level
mixrand -n 32 --log-level debug

# Log to file
mixrand -n 32 --log-file /tmp/mixrand.log

# JSON structured logging
mixrand -n 32 --log-format json

# Syslog (daemon mode)
sudo mixrand daemon --syslog --log-level info
```

## Configuration

### TOML file

Default path: `/etc/mixrand.toml` (override with `--config`).

```toml
[cpu_rng]
enable_rdseed = true
enable_rdrand = true
enable_xstore = true
enable_rndr = true
enable_rndrrs = true
rdrand_retries = 10         # 1-100
rdseed_retries = 10         # 1-100
rndr_retries = 10           # 1-100
rndrrs_retries = 10         # 1-100
xstore_quality = 3          # 0-3
prefer = "rdseed"           # rdseed | rdrand | xstore | rndr | rndrrs
fallback_mix_bytes = 32     # CPU entropy bytes mixed into fallback (0-1024)
oversample = 2              # standalone CPU RNG oversample ratio (1-16)
mixer_mode = "blake2b"      # blake2b | hkdf
```

### Environment variables

All settings can be overridden via `MIXRAND_*` environment variables (layer between TOML and CLI):

| Variable | Type | Example |
|---|---|---|
| `MIXRAND_ENABLE_RDSEED` | bool | `true`, `false`, `1`, `0`, `yes`, `no` |
| `MIXRAND_ENABLE_RDRAND` | bool | `true` |
| `MIXRAND_ENABLE_XSTORE` | bool | `false` |
| `MIXRAND_ENABLE_RNDR` | bool | `true` |
| `MIXRAND_ENABLE_RNDRRS` | bool | `true` |
| `MIXRAND_RDRAND_RETRIES` | u32 | `20` |
| `MIXRAND_RDSEED_RETRIES` | u32 | `10` |
| `MIXRAND_RNDR_RETRIES` | u32 | `10` |
| `MIXRAND_RNDRRS_RETRIES` | u32 | `10` |
| `MIXRAND_XSTORE_QUALITY` | u32 | `3` |
| `MIXRAND_PREFER` | string | `rdseed`, `rdrand`, `xstore`, `rndr`, `rndrrs` |
| `MIXRAND_FALLBACK_MIX_BYTES` | usize | `64` |
| `MIXRAND_OVERSAMPLE` | u32 | `4` |
| `MIXRAND_MIXER_MODE` | string | `blake2b`, `hkdf` |

## Platform Support

| Platform | CPU RNG | Syscall | Daemon | Entropy Sources |
|---|---|---|---|---|
| Linux x86_64 | RDSEED, RDRAND, XSTORE | `getrandom(2)` | Full support | All |
| Linux AArch64 | RNDR, RNDRRS | `getrandom(2)` | Full support | All |
| macOS x86_64 | RDSEED, RDRAND | `getentropy(3)` | N/A (no `/proc`) | hwrng, cpurng, getrandom, fallback |
| macOS AArch64 | RNDR, RNDRRS | `getentropy(3)` | N/A (no `/proc`) | hwrng, cpurng, getrandom, fallback |

CPU instruction availability is detected at runtime via CPUID (x86_64) or `getauxval`/`sysctlbyname` (AArch64) and cached in atomic variables.

## Security

- **Zeroization**: All intermediate entropy buffers, CSPRNG state, and mixer output are volatile-zeroized with `SeqCst` fence. RNG state is explicitly forgotten after zeroization to prevent drop-based recovery.
- **Memory protection**: Sensitive buffers are locked into physical memory (`mlock`) and excluded from core dumps (`MADV_DONTDUMP`). Failures are non-fatal (user may lack `CAP_IPC_LOCK`).
- **Cryptographic mixing**: BLAKE2b-256 with domain separation tag and length-prefixed inputs prevents canonicalization attacks. HKDF mode provides two-stage extraction for defense-in-depth.
- **CSPRNG reseeding**: ChaCha20 reseeds from fresh entropy every 1 MiB, preventing long-lived key exposure.
- **Continuous health testing**: NIST SP 800-90B Repetition Count and Adaptive Proportion tests run on every entropy sample, detecting stuck or biased sources at runtime.
- **Privilege dropping**: Daemon mode supports dropping to an unprivileged user after opening `/dev/random`, minimizing attack surface.
- **Atomic ordering**: Signal handler flags use `Release`/`Acquire` ordering for correct visibility on weak memory architectures (ARM, RISC-V).
- **Unsafe code boundaries**: Limited to inline x86_64/AArch64 asm (CPUID, RDRAND, RDSEED, XSTORE, RNDR, RNDRRS), volatile writes for zeroization, and libc FFI (ioctl, mlock, sigaction, getpwnam, clock_gettime).

## License

See repository for license information.
