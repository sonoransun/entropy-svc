# Troubleshooting

Common failure modes and how to diagnose them. Run `mixrand -v` to
unlock debug-level logs for most of these scenarios.

## "no entropy sources configured" / "all entropy sources failed"

Something unusual has happened — the fallback source should always be
available. Check:

```bash
mixrand list-sources
# Are any sources listed as "available"?
mixrand -v -n 32 2>&1 | grep -E 'unavailable|failed'
```

If nothing is available, verify you aren't running in a sandbox that
blocks `clock_gettime`, `/proc`, and `/dev/urandom` simultaneously.

## `/dev/hwrng` reports "not available" as root

Check the kernel driver loaded:

```bash
dmesg | grep -i hwrng
ls /sys/class/misc/hw_random/rng_current
cat /sys/devices/virtual/misc/hw_random/rng_available
```

Modern systems route TPM2 through `tpm-rng`; make sure the TPM is
exposed (`/dev/tpmrm0`) and the kernel has a hwrng driver for it.

## `/dev/hwrng` permission denied for non-root users

By default the node is root:0600. Either run as root, or add a
tmpfiles.d entry or udev rule:

```
# /etc/tmpfiles.d/mixrand.conf
z /dev/hwrng 0644 root root -
```

## haveged source skipped

`haveged` reports "process not found". Install it:

```bash
apt install haveged   # Debian/Ubuntu
dnf install haveged   # Fedora
systemctl enable --now haveged
```

If the process *is* running but the source still reports unavailable,
check `/proc/sys/kernel/random/entropy_avail` — it must be ≥ 1024
bits. On very modern kernels (ChaCha-based pool), the legacy
`entropy_avail` always reports 256; haveged's contribution is no longer
needed and you can disable the source with
`MIXRAND_HAVEGED_DISABLED=1` (or set `haveged.enabled = false` in
config).

## TPM2: "tcti error" or "cannot connect to TPM"

```bash
tpm2_pcrread                 # does any TPM command work?
ls /dev/tpmrm0 /dev/tpm0     # what's the device node?
```

If you see `/dev/tpm0` but not `/dev/tpmrm0`, the in-kernel resource
manager is missing — install `tpm2-abrmd` or use the direct device:

```bash
MIXRAND_TPM2_TCTI='device:/dev/tpm0' mixrand -n 32
```

Software TPM (for testing):

```bash
MIXRAND_TPM2_TCTI='swtpm:path=/tmp/swtpm-sock'
```

## PKCS#11: library not found / slot 0 unavailable

Common library paths:

```
/usr/lib/softhsm/libsofthsm2.so        # SoftHSM (Debian/Ubuntu)
/usr/lib64/pkcs11/libsofthsm2.so       # SoftHSM (Fedora/RHEL)
/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  # OpenSC
/usr/local/lib/libp11.so               # libp11 (auto)
```

List slots:

```bash
pkcs11-tool --module /path/to/lib.so --list-slots
```

Then set:

```bash
export MIXRAND_PKCS11_LIBRARY_PATH=/path/to/lib.so
export MIXRAND_PKCS11_SLOT_ID=0          # from pkcs11-tool output
export MIXRAND_PKCS11_PIN=1234
mixrand -n 32 --enable-pkcs11
```

## YubiKey PIV applet select fails

The PIV applet AID is `A0 00 00 03 08 00 00 10 00 01 00`. If SELECT
fails, the card may have PIV disabled via firmware settings or the
wrong applet may be active. Reset with:

```bash
ykman piv reset          # DESTRUCTIVE: wipes PIV data
```

## PC/SC: "no reader found"

```bash
systemctl start pcscd
pcsc_scan               # lists available readers live
```

If the reader is listed but not detected by mixrand, set
`MIXRAND_PCSC_READER` to a unique substring of the reader name.

## YubiHSM: connector not reachable

YubiHSM 2 talks HTTP over the `yubihsm-connector`:

```bash
yubihsm-connector -c /etc/yubihsm-connector.yaml &
curl http://127.0.0.1:12345/connector/status
```

Set `MIXRAND_YUBIHSM_CONNECTOR_URL` if the connector runs on a different
host or port.

## SGX: all device nodes missing

```bash
ls /dev/sgx_enclave /dev/sgx/enclave /dev/isgx
```

If none exist, SGX is either disabled in BIOS/UEFI or the driver
hasn't loaded. `cpuid -l 7 -s 0 | grep SGX` confirms CPU capability.

## FIPS tests fail during `check`

A FIPS 140-2 monobit/poker/runs/long-runs failure indicates the source
is either stuck, biased, or had its output corrupted between
collection and statistics. Re-run `check` with `-v` for per-sample
diagnostics. A single transient failure on a loaded system may be a
false positive; repeated failures should be treated as a real bug in
the source.

## Daemon fails to drop privileges

```
error: setuid(uid) failed: Operation not permitted
```

The target user doesn't exist:

```bash
id _entropy    # should succeed
useradd --system --no-create-home --shell /usr/sbin/nologin _entropy
```

## systemd daemon keeps restarting

Check `journalctl -u mixrand -n 50`. Common causes:

- `WATCHDOG=1` not being sent frequently enough — increase
  `WatchdogSec=` in the service unit or let mixrand's built-in 5-min
  heartbeat interval suffice.
- `/dev/random` permissions — the daemon needs CAP_SYS_ADMIN before
  privilege drop.
- `/var/run/mixrand.pid` stale — mixrand handles this automatically,
  but bad filesystem permissions will block PID-file write.

## "config file not found"

`--config` with an explicit path errors if the file is missing. If you
want graceful fallback to defaults, just omit `--config` — mixrand
reads `/etc/mixrand.toml` only when it exists.

## Daemon exits immediately with "startup self-test: all entropy sources failed"

Run `mixrand check --duration 5s` with the same config to identify the
failing source(s). A common cause is an HSM feature enabled in config
without the hardware present; disable the unused source or remove the
build feature. For debugging only, pass `--no-self-test` to let the
daemon enter the main loop even when every source currently fails —
the daemon will still skip injects whose samples fail the health check
mid-loop.

## PID file collision

On start the daemon refuses to run if `/run/mixrand/mixrand.pid` holds
the PID of a live process. Check who owns it:

```
cat /run/mixrand/mixrand.pid
ps -p $(cat /run/mixrand/mixrand.pid)
```

If the recorded PID is a live `mixrand daemon`, stop the old instance
first. If the PID belongs to an unrelated process, something
overwrote the file — remove it only after confirming no other mixrand
instance is running.

## systemd service keeps restarting

```
journalctl -u mixrand -p err --since "30 min ago"
```

Most commonly: missing capabilities (`CAP_SYS_ADMIN`, `CAP_IPC_LOCK`),
self-test failure, or a PID-file collision. Verify the unit includes
the expected `CapabilityBoundingSet` from `deploy/systemd/mixrand.service`
and that the daemon was started as root (needed to open `/dev/random`
for writing before privilege drop).

## HKDF output changed between builds (v1 → v2 migration)

As of the most recent release, the HKDF expand-phase counter was
widened from `u8` to `u32` and the domain tag bumped to
`mixrand-hkdf-expand-v2` (CHANGELOG under Security). Identical inputs
now yield different HKDF output than under v1. If you stored v1 output
for reproducibility, pin a v1 build or regenerate against v2. The
plain `mix_entropy` BLAKE2b path is unchanged; only `mix_entropy_hkdf`
(and CLI `--mixer-mode hkdf`) is affected.

## Silent clamping of config values

Mixrand clamps out-of-range tunables (e.g. `rdrand_retries` > 100,
`oversample` > 16) to the documented min/max with a WARN log line:

```
mixrand --log-level warn --show-config
```

If a value in your `mixrand.toml` disagrees with `--show-config` output,
the clamp was applied.

## Reporting issues

Run with `-v --log-format json 2>mixrand.log` to capture debug-level
structured logs, then attach the log alongside:

- Output of `mixrand --show-config`
- Output of `mixrand --version --verbose`
- `uname -a` and `rustc --version`
- Feature flags used at build time (`cargo metadata | jq '.packages[] |
  select(.name=="mixrand") | .features'`)
