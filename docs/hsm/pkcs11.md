# PKCS#11

The `pkcs11` feature calls `C_GenerateRandom` on any PKCS#11 token that
implements it. Uses the [`cryptoki`](https://crates.io/crates/cryptoki)
crate, which `dlopen`s the vendor library at runtime — no compile-time
system dependency beyond a C toolchain.

## Requirements

- A PKCS#11 v2.40+ library (SoftHSM, OpenSC, OpenCryptoki, YubiHSM SDK,
  AWS CloudHSM client, Thales Luna, Utimaco CryptoServer, etc.).
- Read access to the vendor library path.
- A token with an initialized slot and a user PIN for the session.

## Setup: SoftHSM2 (recommended for dev/CI)

```
apt-get install softhsm2          # Debian/Ubuntu
dnf install softhsm               # Fedora/RHEL

softhsm2-util --init-token --slot 0 \
    --label mixrand \
    --pin 1234 \
    --so-pin 5678
```

Confirm slot ID (usually differs from `--slot 0` after init):

```
softhsm2-util --show-slots
```

The `Slot ID` column is what goes into the mixrand config.

### Library paths per distro

| OS | Path |
|---|---|
| Debian/Ubuntu | `/usr/lib/softhsm/libsofthsm2.so` |
| Fedora/RHEL | `/usr/lib64/pkcs11/libsofthsm2.so` |
| Alpine | `/usr/lib/softhsm/libsofthsm2.so` |
| macOS (Homebrew) | `/usr/local/lib/softhsm/libsofthsm2.so` |

## Configuration

```toml
[hsm.pkcs11]
enabled = true
library_path = "/usr/lib/softhsm/libsofthsm2.so"
slot_id = 1234567890
pin = "1234"      # prefer MIXRAND_PKCS11_PIN env var in production
```

Env vars:

```
MIXRAND_PKCS11_ENABLED=true
MIXRAND_PKCS11_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so
MIXRAND_PKCS11_SLOT_ID=1234567890
MIXRAND_PKCS11_PIN=1234
```

## Verification

```
# From pkcs11-tool (part of opensc)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
    --generate-random 32 | xxd

# From mixrand
mixrand list-sources | grep -i pkcs11
```

## Other vendors

| Vendor | Typical library path |
|---|---|
| OpenSC | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| YubiHSM2 | `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |
| Utimaco | `/opt/utimaco/Software/PKCS11/lib/libcs_pkcs11_R2.so` |

Vendor-specific session setup (SO-PIN, user-PIN, operator password) must
be done with the vendor's own tool before mixrand can open a session.

## Troubleshooting

- **`CKR_SLOT_ID_INVALID`**: pass the full 32-bit slot ID from
  `softhsm2-util --show-slots`, not the 0-based index.
- **`CKR_USER_PIN_NOT_INITIALIZED`**: re-run `softhsm2-util --init-pin`.
- **Thread safety**: most vendor libraries serialize internally. Mixrand
  opens one session per source probe; do not share a session across
  threads.
- **`dlopen` failure**: `ldd` the library and install any missing deps
  (e.g., `libstdc++`, vendor-specific runtime).
