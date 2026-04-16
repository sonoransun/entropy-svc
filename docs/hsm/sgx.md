# Intel SGX

> **Limitation disclosure.** The current `sgx` feature verifies SGX
> hardware capability via CPUID leaf 7 + `SGX_LC` MSR checks and then
> reads random bytes by calling **RDRAND from the untrusted runtime**.
> It is NOT a true enclave-sealed entropy source. Output quality equals
> RDRAND quality on the host CPU. The `sgx_enclave/` directory contains
> a skeleton for a future trusted-runtime implementation; the switchover
> is tracked upstream and will bump the source's priority when ready.

Implemented in `src/entropy/sgx.rs`. Because the heavy lifting is still
RDRAND, the source exists today primarily as a gating check — it
refuses to produce bytes if SGX hardware is absent, so pipelines that
want "HSM-class" guarantees fail closed.

## Requirements

- Intel CPU with SGX (6th-gen Core and later, most Xeon SP).
- BIOS-level SGX enabled (enumerates as CPUID leaf 12 present).
- Build with `--features sgx`. No compile-time dependencies.
- Runtime: `libsgx_urts.so` from the Intel SGX SDK/PSW, installed via
  your distro's `libsgx-urts` package.

## Setup

1. Confirm CPU support:

   ```
   # Bit 2 of CPUID.(EAX=7,ECX=0).EBX indicates SGX.
   cpuid -1 | grep -i sgx
   ```

2. Enable SGX in BIOS/UEFI.

3. Install the PSW runtime:

   ```
   apt-get install libsgx-urts libsgx-enclave-common        # Debian/Ubuntu
   ```

## Configuration

```toml
[hsm.sgx]
enabled = true
```

```
MIXRAND_SGX_ENABLED=true
```

## Verification

```
mixrand list-sources | grep sgx
mixrand -n 32 -f hex
```

When SGX hardware is absent, `list-sources` reports the source as
unavailable and mixrand falls through to the next source.

## Roadmap

A true enclave implementation in `sgx_enclave/` would:

1. Load a signed enclave via `SGXLoadEnclave`.
2. Invoke an ECALL that executes RDRAND inside the enclave.
3. Seal + OCALL the bytes back to the untrusted runtime.

Until that lands, the current implementation is functionally equivalent
to the `cpurng` source with an SGX-presence precondition.
