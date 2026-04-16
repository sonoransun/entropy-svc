# TPM 2.0

The `tpm2` feature reads random bytes from the platform TPM via
`TPM2_GetRandom` using the [`tss-esapi`](https://crates.io/crates/tss-esapi)
Rust bindings. Output is delivered in 48-byte chunks (`TPM2B_DIGEST`
max-size) and reassembled inside `src/entropy/tpm2.rs`.

## Requirements

- A TPM 2.0 chip or vTPM (e.g., `swtpm`, `libtpms`, QEMU guest TPM).
- Kernel drivers: `tpm_crb` (Intel PTT / fTPM) or `tpm_tis` (discrete
  chip); character device at `/dev/tpmrm0` (resource manager) or
  `/dev/tpm0` (direct).
- `tpm2-tss` 2.4+ with `libtss2-esys` / `libtss2-tcti-*` plugins.
- Build-time dependency on `libtss2-dev` (Debian/Ubuntu) or
  `tpm2-tss-devel` (Fedora/RHEL). `cargo build --features tpm2` fails
  without it.

## Permissions

`/dev/tpmrm0` is owned by `root:tss` by default. Add your service user
to the `tss` group:

```
usermod -aG tss mixrand
```

If your distro does not ship a `tss` group (rare), add a udev rule:

```
# /etc/udev/rules.d/60-tpm.rules
KERNEL=="tpm[0-9]*", GROUP="tss", MODE="0660"
KERNEL=="tpmrm[0-9]*", GROUP="tss", MODE="0660"
```

Then reload: `udevadm control --reload && udevadm trigger`.

## Setup

Most distros run `tpm2-abrmd` (Access Broker / Resource Manager) out of
the box. If not, use the kernel resource manager (`/dev/tpmrm0`) via the
`device` TCTI — simpler and equally safe.

### TCTI string format

Mixrand's `tcti` config field (under `[hsm.tpm2]` in `mixrand.toml`) is
passed verbatim to `tss-esapi`:

```
tcti = "device:/dev/tpmrm0"         # default, uses kernel RM
tcti = "device:/dev/tpm0"           # direct TPM, requires CAP_SYS_ADMIN
tcti = "tabrmd:bus_type=system"     # use tpm2-abrmd D-Bus broker
tcti = "swtpm:host=127.0.0.1,port=2321"   # connect to swtpm simulator
tcti = "mssim:host=127.0.0.1,port=2321"   # Microsoft simulator protocol
```

### Configuration

```toml
[hsm.tpm2]
enabled = true
tcti = "device:/dev/tpmrm0"
```

Equivalent env vars (take precedence over TOML):

```
MIXRAND_TPM2_ENABLED=true
MIXRAND_TPM2_TCTI=device:/dev/tpmrm0
```

## Verification

```
# Known-good TPM read from tpm2-tools
tpm2_getrandom 32 | xxd

# Same via mixrand
mixrand list-sources | grep -i tpm
mixrand -n 32 -f hex
```

Confirm `list-sources` reports the tpm2 source as *available*.

## Troubleshooting

- **`EACCES` on /dev/tpmrm0**: group membership not picked up — log out
  and back in after `usermod -aG`, or reload systemd service with the
  updated `SupplementaryGroups=` directive.
- **`abrmd` / `device` conflict**: one ABRMD instance owns the TPM; pick
  either `device:…` OR `tabrmd:…`, not both in different tools at once.
- **Slow initialization on fTPM**: Intel PTT can take several hundred
  milliseconds to start responding. Mixrand's startup self-test will
  hit this; expect ~1 s slower boot on first start after cold boot.
- **`swtpm` for CI**: start `swtpm socket --tpmstate dir=/tmp/swtpm
  --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --tpm2 --flags
  not-need-init --daemon`, then set `tcti = "swtpm:port=2321"`.
